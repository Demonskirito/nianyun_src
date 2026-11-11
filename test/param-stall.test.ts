import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { postSurfaceTask } from "../src/blackbox/playbooks.js";

const empty = () => ({
  version: 1,
  tasks: { T1: { status: "running", target: "https://h/api/list" } },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
});

const call = (url: string, body: string, status = 200) => ({
  request: { task_id: "T1", tool: "http.request", reason: "param probe", input: { url } } as never,
  result: { ok: true, data: { status, body } },
});

describe("parameter surface circuit breaker", () => {
  it("reports a param stall without killing the task", () => {
    const progress = new BlackboxProgress(empty());
    for (const value of ["0", "1", "2", "3", "4"]) progress.recordParamWander("T1", call(`https://h/api/list?docType=${value}`, '{"code":10200,"data":[1]}').request, call(`https://h/api/list?docType=${value}`, '{"code":10200,"data":[1]}').result);
    expect(progress.state.param_watch?.["h/api/list"]?.calls).toBe(5);
    expect(progress.state.param_watch?.["h/api/list"]?.stalled_at).toBeTypeOf("number");
    expect(progress.state.tasks.T1?.status).toBe("running");
    expect(progress.state.param_stall_alert?.path).toBe("h/api/list");
    expect((progress.state.interrupts || []).some(item => item.kind === "param_stall")).toBe(true);
  });

  it("keeps working when the responses actually differ", () => {
    const progress = new BlackboxProgress(empty());
    for (const [value, body] of [["0", '{"data":[1]}'], ["1", '{"data":[1,2]}'], ["2", '{"data":[]}'], ["3", '{"data":[9]}'], ["4", '{"data":[7,8]}']] as const) {
      const one = call(`https://h/api/list?docType=${value}`, body);
      progress.recordParamWander("T1", one.request, one.result);
    }
    expect(progress.state.param_watch?.["h/api/list"]?.fingerprints.length).toBe(5);
    expect(progress.state.tasks.T1?.status).toBe("running");
    expect(progress.state.param_stall_alert).toBeUndefined();
  });

  it("stalls the real-world pattern: many calls, slow fingerprint growth", () => {
    const progress = new BlackboxProgress(empty());
    // 本机实测形状：31 次调用、19 种参数、7 种响应体
    for (let index = 0; index < 31; index += 1) {
      const body = `{"code":10200,"data":[${index % 7}]}`;
      const one = call(`https://h/api/list?docType=${index}`, body);
      progress.recordParamWander("T1", one.request, one.result);
    }
    expect(progress.state.param_watch?.["h/api/list"]?.fingerprints.length).toBe(7);
    expect(progress.state.param_stall_alert?.calls).toBeGreaterThan(5);
    expect(progress.state.tasks.T1?.status).toBe("running");
  });
  it("treats different paths as separate surfaces", () => {
    const progress = new BlackboxProgress(empty());
    for (const path of ["/api/a", "/api/b", "/api/c", "/api/d", "/api/e"]) {
      const one = call(`https://h${path}?x=1`, '{"code":10200}');
      progress.recordParamWander("T1", one.request, one.result);
    }
    expect(progress.state.param_stall_alert).toBeUndefined();
    expect(progress.state.tasks.T1?.status).toBe("running");
  });
});

describe("advice backlog cap", () => {
  it("archives the oldest pending advice beyond the limit", () => {
    const progress = new BlackboxProgress(empty());
    progress.advicePendingLimit = 3;
    for (let index = 0; index < 6; index += 1) {
      progress.supplement({ supplemental_tasks: [], suggestions: [`建议 ${index}`] }, `advice-${index}`);
    }
    const entries = Object.entries(progress.state.advice || {});
    const pending = entries.filter(([, item]) => item.status === "pending");
    const superseded = entries.filter(([, item]) => item.status === "superseded");
    expect(pending.length).toBeLessThanOrEqual(3);
    expect(superseded.length).toBeGreaterThanOrEqual(3);
    // newest advice survives
    expect(pending.some(([id]) => id === "advice-5")).toBe(true);
    expect(superseded.some(([id]) => id === "advice-0")).toBe(true);
  });
});

describe("POST surface fallback", () => {
  const state = (overrides: Record<string, unknown> = {}) => ({
    tasks: {}, endpoints: Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`https://h/api/${i}`, { evidence_ids: [], task_ids: [] }])),
    playbook_runs: { unauth_exposure: { calls: 20, ok: 20, failed: 0, steps: {}, last_at: 1 } },
    ...overrides,
  });

  it("asks for a method-surface task when no POST playbook ever ran", () => {
    const spec = postSurfaceTask(state(), "20261024160000");
    expect(spec?.id).toBe("post_surface_20261024160000");
    expect(spec?.purpose).toContain("POST");
    expect(spec?.completion_criteria).toContain("≥3");
  });

  it("stays quiet once a POST playbook ran, a task exists, or the surface is tiny", () => {
    expect(postSurfaceTask(state({ playbook_runs: { logic: { calls: 1, ok: 1, failed: 0, steps: {}, last_at: 1 } } }), "s")).toBeUndefined();
    expect(postSurfaceTask(state({ tasks: { post_surface_x: { status: "pending" } } }), "s")).toBeUndefined();
    expect(postSurfaceTask(state({ endpoints: { "https://h/api/0": {} } }), "s")).toBeUndefined();
  });
});
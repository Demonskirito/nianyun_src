import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { normalizePath, normalizeBody } from "../src/blackbox/urlnorm.js";

const state = () => ({
  version: 1,
  tasks: { T1: { status: "running", target: "https://h/api/doc/1" } },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
});

const hit = (url: string, body: string, status = 200) => ({
  request: { task_id: "T1", tool: "http.request", reason: "id walk", input: { url } } as never,
  result: { ok: true, data: { status, body } },
});

describe("RESTful path normalization", () => {
  it("collapses numeric / uuid / hex segments into placeholders", () => {
    expect(normalizePath("/api/doc/86")).toEqual({ path: "/api/doc/{id}", ids: ["86"], dynamic: true });
    expect(normalizePath("/api/doc/118").path).toBe("/api/doc/{id}");
    expect(normalizePath("/api/user/123e4567-e89b-12d3-a456-426614174000").path).toBe("/api/user/{uuid}");
    expect(normalizePath("/api/blob/deadbeefdeadbeefdeadbeef").path).toBe("/api/blob/{hex}");
    expect(normalizePath("/api/doc/listAll")).toEqual({ path: "/api/doc/listAll", ids: [], dynamic: false });
  });

  it("masks the family id and time noise inside the body", () => {
    const a = normalizeBody('{"code":10200,"data":{"id":86,"name":"x","createTime":"2026-10-24T12:00:00.000Z","sn":1792843296448}}', ["86"]);
    const b = normalizeBody('{"code":10200,"data":{"id":118,"name":"x","createTime":"2026-10-24T12:09:31.000Z","sn":1792843991111}}', ["118"]);
    expect(a).toBe(b);
    expect(a).toContain("{id}");
    expect(a).not.toContain("1792843296448");
  });
});

describe("param stall on path ids", () => {
  it("trips after walking three different ids with identical shape", () => {
    const progress = new BlackboxProgress(state());
    for (const id of [86, 118, 240, 512, 999]) {
      const one = hit(`https://h/api/doc/${id}`, `{"code":10200,"data":{"id":${id},"name":"same"}}`);
      progress.recordParamWander("T1", one.request, one.result);
    }
    const watch = progress.state.param_watch?.["h/api/doc/{id}"];
    expect(watch?.calls).toBe(5);
    expect(watch?.variants?.length).toBe(5);
    expect(watch?.fingerprints.length).toBe(1);
    expect(progress.state.param_stall_alert?.path).toBe("h/api/doc/{id}");
    expect(progress.state.param_stall_alert?.variants).toBe(5);
    // 熔断只是提示：任务继续跑，由模型决定换端点还是继续（盲注/越权遍历本来就该重复）。
    expect(progress.state.tasks.T1?.status).toBe("running");
  });

  it("does not trip while each id returns a genuinely different resource", () => {
    const progress = new BlackboxProgress(state());
    const bodies = [
      '{"code":10200,"data":{"id":86,"owner":"alice","docs":12}}',
      '{"code":10200,"data":{"id":118,"owner":"bob","docs":3}}',
      '{"code":10200,"data":{"id":240,"owner":"carol","docs":99}}',
      '{"code":10200,"data":{"id":512,"owner":"dave","docs":7}}',
      '{"code":10200,"data":{"id":999,"owner":"erin","docs":41}}',
    ];
    for (const [index, id] of [86, 118, 240, 512, 999].entries()) {
      const one = hit(`https://h/api/doc/${id}`, bodies[index]!);
      progress.recordParamWander("T1", one.request, one.result);
    }
    expect(progress.state.param_watch?.["h/api/doc/{id}"]?.fingerprints.length).toBe(5);
    expect(progress.state.param_stall_alert).toBeUndefined();
    expect(progress.state.tasks.T1?.status).toBe("running");
  });

  it("keeps static paths and query fuzzing on their own counters", () => {
    const progress = new BlackboxProgress(state());
    for (const value of ["0", "1", "2"]) {
      const one = hit(`https://h/api/list?docType=${value}`, '{"code":10200,"data":[]}');
      progress.recordParamWander("T1", one.request, one.result);
    }
    expect(progress.state.param_watch?.["h/api/list"]?.variants).toEqual([]);
    for (const id of [1, 2, 3]) {
      const one = hit(`https://h/api/doc/${id}`, '{"code":10200,"data":{"id":0}}');
      progress.recordParamWander("T1", one.request, one.result);
    }
    expect(Object.keys(progress.state.param_watch || {}).sort()).toEqual(["h/api/doc/{id}", "h/api/list"]);
  });

  // 方向 3 的遗留：`/api/users/alice` 与 `/api/users/bob` 属于同一资源族，
  // 归一化在 recordParamWander 里必须走"路由模板学习"，否则熔断照样漏判。
  it("trips on slug-like path params after learning the route template", () => {
    const progress = new BlackboxProgress(state());
    progress.state.tasks.T1 = { status: "running", target: "https://h/api/users/alice" };
    const names = ["alice", "bob", "carol", "dave", "erin"];
    for (const name of names) {
      const one = hit(`https://h/api/users/${name}`, `{"code":10200,"data":{"user":"${name}","email":"x@y.z"}}`);
      progress.recordParamWander("T1", one.request, one.result);
    }
    const keys = Object.keys(progress.state.param_watch || {});
    expect(keys).toEqual(["h/api/users/{p3}"]);
    // 第 4 次就满足属尼阀值（1 种形状 / 4 次调用），属尼阀之后不再重复计入新形状。
    expect(progress.state.param_watch?.["h/api/users/{p3}"]?.calls).toBe(5);
    expect(progress.state.param_watch?.["h/api/users/{p3}"]?.fingerprints.length).toBe(1);
    expect(progress.state.param_stall_alert?.path).toBe("h/api/users/{p3}");
    expect((progress.state.param_stall_alert?.variants || 0)).toBeGreaterThanOrEqual(3);
    expect(progress.state.tasks.T1?.status).toBe("running");
  });

  it("does not fold top-level namespaces into one path", () => {
    const progress = new BlackboxProgress(state());
    for (const path of ["/api/doc/1", "/static/app.js", "/assets/main.js", "/internal/health"]) {
      const one = hit(`https://h${path}`, "same-body-shape");
      progress.recordParamWander("T1", one.request, one.result);
    }
    const keys = Object.keys(progress.state.param_watch || {}).sort();
    expect(keys).toEqual(["h/api/doc/{id}", "h/assets/main.js", "h/internal/health", "h/static/app.js"]);
  });
});

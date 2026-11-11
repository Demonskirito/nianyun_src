import { describe, expect, it } from "vitest";
import { blockedByWall, carriesAuth, completionDenial, denialOf, deniedPrefixes, entryKey, hostOf, trackDenial, type AuthWallState } from "../src/blackbox/authwall.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { externalToolCommand } from "../src/blackbox/tools.js";

const denial = { status: 200, body: '{"code":10403,"msg":"未登录"}' };

describe("auth wall detection", () => {
  it("recognises 401 and business codes", () => {
    expect(denialOf({ status: 401 }).denied).toBe(true);
    expect(denialOf(denial).code).toBe("10403");
    expect(denialOf({ status: 200, body: '{"status":"ok","data":[]}' }).denied).toBe(false);
    // WAF 403/412 is not an auth wall
    expect(denialOf({ status: 412, body: "<html>blocked</html>" }).denied).toBe(false);
  });

  it("trips after N distinct entries on one host", () => {
    const state: { auth_wall?: AuthWallState } = {};
    const urls = ["https://h/api/a?x=1", "https://h/api/b", "https://h/api/c"];
    expect(trackDenial(state, { url: urls[0]!, denied: true, code: "10403" }, 3).tripped).toBe(false);
    expect(trackDenial(state, { url: urls[1]!, denied: true, code: "10403" }, 3).tripped).toBe(false);
    const third = trackDenial(state, { url: urls[2]!, denied: true, code: "10403" }, 3);
    expect(third.tripped).toBe(true);
    expect(third.state?.tripped_at).toBeTypeOf("number");
    // same entry with different parameters is one entry, not three
    const repeated: { auth_wall?: AuthWallState } = {};
    for (const suffix of ["1", "2", "3"]) trackDenial(repeated, { url: `https://h/api/item?id=${suffix}`, denied: true, code: "10403" }, 3);
    expect(repeated.auth_wall?.urls.length).toBe(1);
  });

  it("blocks only the denied prefix and lets token paths through", () => {
    const wall: AuthWallState = { host: "https://h", streak: 3, urls: ["https://h/api/order/list", "https://h/api/order/detail"], tripped_at: Date.now(), code: "10403" };
    const state = { auth_wall: wall };
    expect(deniedPrefixes(wall)).toContain("/api/order/");
    expect(blockedByWall(state, "https://h/api/order/other", {})).toBe(true);
    expect(blockedByWall(state, "https://h/login", {})).toBe(false);
    expect(blockedByWall(state, "https://h/api/order/other", { headers: { Authorization: "Bearer t" } })).toBe(false);
    expect(blockedByWall(state, "https://other/api/order/other", {})).toBe(false);
    expect(carriesAuth({ cookie: "sid=1" })).toBe(true);
    expect(hostOf("https://h/api")).toBe("https://h");
    expect(entryKey("https://h/api/x?a=1")).toBe("h/api/x");
  });

  it("treats denied-only evidence as no completion", () => {
    const evidence = [
      { id: "e1", kind: "tool-result", data: { task_id: "T1", status: 200, body: '{"code":10403}' } },
      { id: "e2", kind: "tool-result", data: { task_id: "T1", status: 401, body: "unauthorized" } },
    ];
    expect(completionDenial(evidence, "T1", ["e1", "e2"]).deniedOnly).toBe(true);
    const mixed = [...evidence, { id: "e3", kind: "tool-result", data: { task_id: "T1", status: 200, body: '{"data":[{"owner":"other"}]}' } }];
    expect(completionDenial(mixed, "T1", ["e1", "e2", "e3"]).deniedOnly).toBe(false);
  });
});

describe("progress enforcement", () => {
  const base = {
    version: 1,
    tasks: { T1: { status: "running", target: "https://h/api/order", playbook: "idor" } },
    usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
  };

  it("auto-blocks the task once the wall trips", () => {
    const progress = new BlackboxProgress(base);
    progress.authWall = { streak_limit: 2, codes: ["10403"] };
    const request = { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/order/list" } } as never;
    progress.recordAuthDenial("T1", request, { ok: true, data: { status: 200, body: '{"code":10403}' } });
    expect(progress.state.auth_wall_alert).toBeUndefined();
    progress.recordAuthDenial("T1", { ...request, input: { url: "https://h/api/order/detail" } }, { ok: true, data: { status: 200, body: '{"code":10403}' } });
    expect(progress.state.auth_wall?.tripped_at).toBeTypeOf("number");
    expect(progress.state.tasks.T1?.status).toBe("blocked");
    expect(progress.state.auth_wall_alert?.kind).toBe("wall");
  });

  it("counts entries by the request url, not the task target", () => {
    const progress = new BlackboxProgress({ version: 1, tasks: { T1: { status: "running", target: "https://h/" } },
      actions: {}, seenResults: [], stalledBatches: 0, usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 } });
    progress.authWall = { streak_limit: 3, codes: ["10403"] };
    for (const path of ["/api/a", "/api/b", "/api/c"]) {
      progress.recordAuthDenial("T1", { task_id: "T1", tool: "http.request", reason: "probe", input: { url: `https://h${path}` } } as never,
        { ok: true, data: { status: 200, body: '{"code":10403}' } });
    }
    expect(progress.state.auth_wall?.urls.length).toBe(3);
    expect(progress.state.auth_wall?.tripped_at).toBeTypeOf("number");
  });
  it("refuses further unauthenticated requests under the blocked prefix", () => {
    const progress = new BlackboxProgress({ ...base, tasks: { T1: { status: "running", target: "https://h/api/order" }, T2: { status: "running", target: "https://h/api/order" }, T3: { status: "running", target: "https://h/login" } }, auth_wall: { host: "https://h", streak: 3, urls: ["https://h/api/order/list"], tripped_at: Date.now() } as never });
    const blocked = progress.begin({ task_id: "T1", tool: "http.request", reason: "again", input: { url: "https://h/api/order/other" } } as never, "https://h/api/order/other", 2, 2);
    expect(blocked.blocked).toBe("auth_wall_requires_token");
    const allowed = progress.begin({ task_id: "T2", tool: "http.request", reason: "with token", input: { url: "https://h/api/order/other", headers: { Authorization: "Bearer t" } } } as never, "https://h/api/order/other", 2, 2);
    expect(allowed.blocked).toBeUndefined();
    const login = progress.begin({ task_id: "T3", tool: "http.request", reason: "login", input: { url: "https://h/login" } } as never, "https://h/login", 2, 2);
    expect(login.blocked).toBeUndefined();
  });

  it("turns a denied-only completion into blocked_by_auth when the playbook expects positive data", () => {
    const progress = new BlackboxProgress({
      version: 1,
      tasks: { T1: { status: "running", target: "https://h/api/order", playbook: "sqli", completion_criteria: "看到他人订单" } },
      usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
      playbook_runs: {},
    });
    const evidence = [
      { id: "e1", kind: "tool-result", actor: "tool", data: { task_id: "T1", tool: "http.request", ok: true, status: 200, body: '{"code":10403}' }, created_at: Date.now() },
    ];
    progress.merge({
      required_tasks: [],
      completed_tasks: ["T1"],
      task_outcomes: [{ task_id: "T1", reason: "probe returned", evidence_ids: ["e1"] }],
      advice_decisions: [],
    }, evidence as never);
    expect(progress.state.tasks.T1?.status).toBe("blocked");
    // 结案码走 outcome_code；`reason` 保留创建意图，不再被收口覆盖（2026-11-05）。
    expect(progress.state.tasks.T1?.outcome_code).toBe("blocked_by_auth");
    expect(progress.state.auth_wall_alert?.kind).toBe("denied_completion");
  });

  it("records a denied-only completion as verified_negative for negative-by-design playbooks", () => {
    const progress = new BlackboxProgress({
      version: 1,
      tasks: { T1: { status: "running", target: "https://h/api/order", playbook: "idor", completion_criteria: "确认不存在越权" } },
      usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
      playbook_runs: {},
    });
    const evidence = [
      { id: "e1", kind: "tool-result", actor: "tool", data: { task_id: "T1", tool: "http.request", ok: true, status: 200, body: '{"code":10403}' }, created_at: Date.now() },
      { id: "e2", kind: "tool-result", actor: "tool", data: { task_id: "T1", tool: "http.diff", ok: true, status: 401, body: "unauthorized" }, created_at: Date.now() },
    ];
    progress.merge({
      required_tasks: [],
      completed_tasks: ["T1"],
      task_outcomes: [{ task_id: "T1", reason: "anonymous and authorized probes both denied", evidence_ids: ["e1", "e2"] }],
      advice_decisions: [],
    }, evidence as never);
    expect(progress.state.tasks.T1?.status).toBe("completed");
    expect(progress.state.tasks.T1?.outcome_reason).toContain("verified_negative");
    expect(progress.state.auth_wall_alert).toBeUndefined();
  });

  it("refuses verified_negative on a single denied probe", () => {
    const progress = new BlackboxProgress({
      version: 1,
      tasks: { T1: { status: "running", target: "https://h/api/order", playbook: "idor" } },
      usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
      playbook_runs: {},
    });
    const evidence = [
      { id: "e1", kind: "tool-result", actor: "tool", data: { task_id: "T1", tool: "http.request", ok: true, status: 401, body: "unauthorized" }, created_at: Date.now() },
    ];
    progress.merge({
      required_tasks: [], completed_tasks: ["T1"],
      task_outcomes: [{ task_id: "T1", reason: "probe returned", evidence_ids: ["e1"] }],
      advice_decisions: [],
    }, evidence as never);
    expect(progress.state.tasks.T1?.status).toBe("blocked");
    // 结案码走 outcome_code；`reason` 保留创建意图，不再被收口覆盖（2026-11-05）。
    expect(progress.state.tasks.T1?.outcome_code).toBe("blocked_by_auth");
  });
});

describe("executor path guard", () => {
  it("rejects a URL where a local path is required", () => {
    const ctx = { values: {}, cfg: { data_dir: "/tmp" } } as never;
    expect(() => externalToolCommand("recon.secrets", "https://h/", { path: "https://h/api" }, ctx)).toThrow(/expected a local path, got URL/);
    expect(() => externalToolCommand("recon.secrets", "https://h/", {}, ctx)).toThrow(/requires input.path/);
    expect(() => externalToolCommand("recon.sast", "https://h/", { path: "http://h/x.zip" }, ctx)).toThrow(/expected a local path/);
  });
});
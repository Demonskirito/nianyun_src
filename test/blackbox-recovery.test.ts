import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { recoverLegacyCheckpoint, recoveredTerminalReason, type RecoveryPlan } from "../src/blackbox/recovery.js";

const target = "http://example.invalid/";
const facts = [
  { id: "req", kind: "tool-request", session_id: "s", project_id: "p", source: "main-agent", data: { tool: "http.request", input: { url: target, method: "GET" } } },
  { id: "res", kind: "tool-result", session_id: "s", project_id: "p", source: "http.request", data: { request_evidence_id: "req", url: target, method: "GET", status: 200, body: "SPA", headers: { "content-type": "text/html" } } },
];
function setup() {
  const p = new BlackboxProgress();
  p.state.tasks.baseline = { status: "blocked", completion_criteria: "record a GET response" };
  p.state.tasks.tls = { status: "blocked", outcome_reason: "outside scope" };
  p.state.advice = { advice: { tasks: ["repair checkpoint"], status: "pending" } };
  p.state.validationErrors = ["old error"];
  p.state.usage.tokens = 715134;
  const plan: RecoveryPlan = { reason: "reviewed original request and response", tasks: [{ task_id: "baseline", status: "completed", reason: "recorded GET only; no vulnerability confirmed", evidence_ids: ["res"], urls: [target] }], advice_decisions: [{ advice_id: "advice", reason: "offline repair done; TLS remains out of scope" }] };
  return { p, plan };
}

describe("offline legacy checkpoint recovery", () => {
  it("adds auditable associations without rewriting evidence, resetting usage, or replaying tools", () => {
    const { p, plan } = setup();
    const original = JSON.stringify({ state: p.state, facts });
    const state = recoverLegacyCheckpoint(p.state, facts, target, plan, "audit");
    expect(state.tasks.baseline).toMatchObject({ status: "completed", evidence_ids: ["res"] });
    expect(state.tasks.tls.status).toBe("blocked");
    expect(state.usage).toMatchObject({ tokens: 715134, toolCalls: 1 });
    expect(state.recovery?.links.res).toEqual({ task_id: "baseline", request_id: "req" });
    expect(state.validationErrors).toEqual([]);
    // 2026-11-05 判据变更：baseline 已给出结论（completed + 证据），tls 因范围外受阻（blocked）。
    // 旧口径把它记成 "blocked"，等于说"这场评估失败"——但它其实是可交付的部分完成。
    expect(recoveredTerminalReason(state, facts)).toBe("partial_completed");
    expect(JSON.stringify({ state: p.state, facts })).toBe(original);
    const restored = new BlackboxProgress(state);
    restored.merge({ completed_tasks: ["baseline"], task_outcomes: [{ task_id: "baseline", reason: "existing response", evidence_ids: ["res"] }] }, facts);
    expect(restored.state.validationErrors).toEqual([]);
    expect(restored.begin({ tool: "http.request", task_id: "baseline", input: { url: target } }, target, 2, 2).blocked).toBe("task_completed");
    expect(() => recoverLegacyCheckpoint(state, facts, target, plan, "again")).toThrow("already_recovered");
  });

  it("rejects failure results, unrelated URLs, wrong methods and missing original requests", () => {
    const { p, plan } = setup();
    for (const change of [{ status: 500 }, { ok: false }, { method: "POST" }, { url: "http://other.invalid/" }, { request_evidence_id: "missing" }, { task_id: "other" }, { body_truncated: true }]) {
      const altered = [facts[0], { ...facts[1], data: { ...facts[1].data, ...change } }];
      expect(() => recoverLegacyCheckpoint(p.state, altered, target, plan, "audit")).toThrow();
    }
    expect(() => recoverLegacyCheckpoint(p.state, facts, "https://example.invalid/", plan, "audit")).toThrow("target_mismatch");
    const crossSession = [facts[0], { ...facts[1], session_id: "other" }];
    expect(() => recoverLegacyCheckpoint(p.state, crossSession, target, plan, "audit")).toThrow("provenance");
  });

  it("does not bypass later new tasks, evidence loss or unresolved advice", () => {
    const { p, plan } = setup();
    expect(() => recoverLegacyCheckpoint(p.state, facts, target, { ...plan, advice_decisions: [] }, "audit")).toThrow("terminal_disposition");
    const state = recoverLegacyCheckpoint(p.state, facts, target, plan, "audit");
    expect(recoveredTerminalReason(state, [])).toBe("");
    state.tasks.new = { status: "pending" };
    expect(recoveredTerminalReason(state, facts)).toBe("");
  });
});

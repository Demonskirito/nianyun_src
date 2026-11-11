import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import type { BlackboxToolRequest, BlackboxToolResult } from "../src/blackbox/tools.js";
import { superviseCheckpoint } from "../src/blackbox/supervision.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { looksLikeCode } from "../src/blackbox/task-outcome.js";

const target = "https://app.example.test/";
const request: BlackboxToolRequest = { tool: "http.request", task_id: "inspect login", reason: "inspect", input: { url: `${target}login` } };
const result = (ok = true, body = "login"): BlackboxToolResult => ({ tool: "http.request", ok, summary: ok ? "200" : "timeout", data: ok ? { body, headers: { date: String(Date.now()) } } : { error: "timeout" }, duration_ms: 10, artifacts: [] });

describe("blackbox progress guards", () => {
  it.each([true, false])("applies advice once and preserves the original disposition across retries: %s", accepted => {
    let p = new BlackboxProgress();
    p.state.tasks.inspect = { status: "blocked", reason: "fixture" };
    p.state.advice = { a: { tasks: [], status: "pending" } };
    const decision = { advice_id: "a", accepted, reason: "original", task_ids: accepted ? ["inspect"] : [] };
    p.merge({ advice_decisions: [decision] });
    expect(p.state.adviceDecisionResults).toEqual([{ advice_id: "a", status: "applied" }]);
    const original = structuredClone(p.state.advice);
    p = new BlackboxProgress(JSON.parse(JSON.stringify(p.state)));
    p.state.transitionErrors = ["invalid_advice_decision:a", "completion_without_valid_task_evidence:other"];
    for (let i = 0; i < 2; i++) {
      expect(p.merge({ advice_decisions: [{ ...decision, reason: "changed", task_ids: ["unknown"] }] })).toBe(false);
      expect(p.state.adviceDecisionResults).toEqual([{ advice_id: "a", status: "already_applied" }]);
      expect(p.state.advice).toEqual(original);
      expect(p.state.transitionErrors).toEqual(["completion_without_valid_task_evidence:other"]);
      expect(p.state.plans).toBeUndefined();
    }
  });

  it.each([true, false])("rejects opposite advice dispositions and attributes the conflict: %s", accepted => {
    let p = new BlackboxProgress();
    p.state.tasks.inspect = { status: "blocked", reason: "fixture" };
    p.state.advice = { a: { tasks: [], status: accepted ? "accepted" : "rejected", reason: "original", task_ids: accepted ? ["inspect"] : [] } };
    const original = structuredClone(p.state.advice);
    const conflict = { advice_id: "a", accepted: !accepted, reason: "opposite", task_ids: ["inspect"] };
    p.merge({ advice_decisions: [conflict, conflict] });
    expect(p.state.adviceDecisionResults?.every(r => r.status === "disposition_conflict")).toBe(true);
    expect(p.state.transitionErrors).toEqual(["disposition_conflict:a"]);
    expect(p.state.advice).toEqual(original);
    p = new BlackboxProgress(JSON.parse(JSON.stringify(p.state)));
    const gate = evaluateAcceptance(p.state, []);
    expect(gate.ready).toBe(false);
    expect(gate.issues).toContainEqual(expect.objectContaining({ code: "disposition_conflict", advice_id: "a" }));
    p.merge({ advice_decisions: [{ ...conflict, accepted }] });
    expect(p.state.advice).toEqual(original);
    expect(evaluateAcceptance(p.state, []).ready).toBe(true);
  });

  it("keeps rejecting unknown advice and invalid pending dispositions", () => {
    const p = new BlackboxProgress();
    p.state.advice = { a: { tasks: [], status: "pending" } };
    const decision = { advice_id: "a", accepted: true, reason: "accept", task_ids: [] };
    expect(p.applyAdviceDecision(decision).status).toBe("invalid_advice_decision");
    expect(p.applyAdviceDecision({ ...decision, task_ids: ["unknown"] }).status).toBe("invalid_advice_decision");
    expect(p.applyAdviceDecision({ ...decision, advice_id: "missing" }).status).toBe("invalid_advice_decision");
    expect(p.state.advice.a.status).toBe("pending");
  });

  it("resolves legacy duplicate errors without accepting an invalid original disposition", () => {
    const p = new BlackboxProgress();
    p.state.tasks.inspect = { status: "blocked", reason: "fixture" };
    p.state.advice = { a: { tasks: [], status: "accepted", reason: "original", task_ids: ["missing"] } };
    p.state.validationErrors = ["invalid_advice_decision:a"];
    const restored = new BlackboxProgress(JSON.parse(JSON.stringify(p.state)));
    restored.merge({ advice_decisions: [{ advice_id: "a", accepted: true, reason: "retry", task_ids: ["inspect"] }] });
    expect(restored.state.adviceDecisionResults?.[0].status).toBe("already_applied");
    expect(restored.state.transitionErrors).toEqual([]);
    expect(restored.state.advice).toEqual(p.state.advice);
    expect(evaluateAcceptance(restored.state, []).issues).toContainEqual(expect.objectContaining({ code: "ADVICE_DISPOSITION_INVALID", advice_id: "a" }));
  });

  it("canonicalizes aliases, parameter order, default method and rewritten reasons", () => {
    const progress = new BlackboxProgress();
    expect(progress.identity(request, target)).toBe(progress.identity({ ...request, tool: "http", reason: "try again", input: { timeout_ms: 60000, method: "get", url: `${target}login#fragment` } }, target));
    expect(progress.identity(request, target)).not.toBe(progress.identity({ ...request, input: { url: `${target}other` } }, target));
    expect(progress.identity({ ...request, input: { headers: { accept: "a", "user-agent": "b" } } }, target)).toBe(progress.identity({ ...request, input: { headers: { "user-agent": "b", accept: "a" } } }, target));
  });

  it("blocks unchanged actions while permitting changed results", () => {
    const progress = new BlackboxProgress();
    for (let n = 0; n < 3; n++) {
      const action = progress.begin(request, target, 2, 2);
      expect(action.blocked).toBeUndefined();
      expect(progress.finish(request, action.key, result(), 2)).toBe(n === 0);
    }
    expect(progress.begin({ ...request, reason: "retry with different wording" }, target, 2, 2).blocked).toBe("repeated_without_new_information");
    const changed = new BlackboxProgress();
    for (let n = 0; n < 5; n++) {
      const action = changed.begin(request, target, 2, 2);
      expect(action.blocked).toBeUndefined();
      expect(changed.finish(request, action.key, result(true, String(n)), 2)).toBe(true);
    }
  });

  it("treats changed tool parameters as new work instead of a repeat", () => {
    const progress = new BlackboxProgress();
    const nuclei = (extra: Record<string, unknown>) => ({ tool: "recon.nuclei", task_id: "scan", input: { url: target, ...extra } }) as BlackboxToolRequest;
    expect(progress.identity(nuclei({ templates: "cves" }), target)).not.toBe(progress.identity(nuclei({ templates: "misconfig" }), target));
    expect(progress.identity(nuclei({ wordlist: "a.txt" }), target)).not.toBe(progress.identity(nuclei({ wordlist: "b.txt" }), target));
    expect(progress.identity(nuclei({ token: "aaa.bbb" }), target)).not.toBe(progress.identity(nuclei({ token: "ccc.ddd" }), target));
    // Tuning a timeout or rewriting the reason is the same work.
    expect(progress.identity(nuclei({ templates: "cves", timeout_ms: 30000 }), target)).toBe(progress.identity({ ...nuclei({ templates: "cves" }), reason: "try again" } as BlackboxToolRequest, target));
  });

  it("does not bill a deadline hit as a failure", () => {
    const progress = new BlackboxProgress();
    for (let n = 0; n < 5; n++) {
      const action = progress.begin(request, target, 2, 2);
      expect(action.blocked).toBeUndefined();
      expect(progress.finish(request, action.key, { ...result(false), data: { error: "stage timeout", timed_out: true } }, 2, { timedOut: true })).toBe(false);
    }
    expect(progress.state.tasks["inspect login"]?.status).toBe("pending");
    expect(progress.state.tasks["inspect login"]?.failures).toBeUndefined();
    const failing = progress.begin(request, target, 2, 2);
    expect(failing.blocked).toBeUndefined();
    progress.finish(request, failing.key, result(false), 2);
    expect(progress.state.tasks["inspect login"]?.failures).toBe(1);
  });

  it("does not bill a rejected request as a failure but still stops repeats", () => {
    const progress = new BlackboxProgress();
    const rejection = { ...result(false), summary: "recon.nuclei rejected: recon.nuclei is not configured (NUCLEI_PATH)", data: { error: "recon.nuclei is not configured (NUCLEI_PATH)", rejected: true } };
    for (let n = 0; n < 3; n++) {
      const action = progress.begin(request, target, 2, 2);
      expect(action.blocked).toBeUndefined();
      expect(progress.finish(request, action.key, rejection, 2, { rejected: true })).toBe(false);
    }
    expect(progress.state.tasks["inspect login"]).toMatchObject({ status: "pending", outcome_reason: expect.stringContaining("not configured") });
    expect(progress.state.tasks["inspect login"]?.failures).toBeUndefined();
    expect(progress.begin(request, target, 2, 2).blocked).toBe("repeated_without_new_information");
  });

  it("treats tool params as part of the action identity, regardless of key order", () => {
    const p = new BlackboxProgress();
    const base: BlackboxToolRequest = { tool: "recon.nuclei", task_id: "scan", reason: "check", input: { url: target, params: { severity: "high,medium", rate_limit: 20 } } };
    const reordered: BlackboxToolRequest = { ...base, input: { url: target, params: { rate_limit: 20, severity: "high,medium" } } };
    const changed: BlackboxToolRequest = { ...base, input: { url: target, params: { severity: "critical", rate_limit: 20 } } };
    expect(p.identity(reordered, target)).toBe(p.identity(base, target));
    expect(p.identity(changed, target)).not.toBe(p.identity(base, target));
    // timeout tuning and prose stay out of the identity; knobs that change the work do not.
    expect(p.identity({ ...base, input: { ...base.input, timeout_ms: 5000 } }, target)).toBe(p.identity(base, target));
  });

  it("defers unstarted work with a readable reason", () => {
    const progress = new BlackboxProgress();
    const key = progress.identity(request, target);
    progress.enqueue([request], target);
    progress.defer(request, key, "stage_timeout");
    const deferred = progress.state.tasks["inspect login"]!;
    expect(deferred).toEqual(expect.objectContaining({ status: "pending", reason: "stage_timeout" }));
    // 2026-11-10：outcome_reason 必须是人话。旧写法把码原样写进去，结案说明的判据
    // 会把纯机器码判成 TASK_OUTCOME_NOT_EXPLAINED——控制面自己写的账，不能算模型的错。
    expect(String(deferred.outcome_reason)).toContain("已登记延后");
    expect(looksLikeCode(String(deferred.outcome_reason))).toBe(false);
    expect(progress.begin(request, target, 2, 2).blocked).toBeUndefined();
  });

  it("caps retries per task even when parameters change", () => {
    const progress = new BlackboxProgress();
    for (let n = 0; n < 3; n++) {
      const req = { ...request, input: { url: `${target}login?attempt=${n}` } };
      const action = progress.begin(req, target, 2, 2);
      expect(action.blocked).toBeUndefined();
      expect(progress.finish(req, action.key, result(false), 2)).toBe(false);
    }
    expect(progress.lists().failed_tasks).toEqual(["inspect login"]);
    expect(progress.begin(request, target, 2, 2).blocked).toBe("task_failed");
    progress.merge({ completed_tasks: ["inspect login"] });
    expect(progress.lists().failed_tasks).toEqual(["inspect login"]);
  });

  it("does not block one tool inspecting 100 distinct endpoints", () => {
    const progress = new BlackboxProgress();
    for (let n = 0; n < 100; n++) {
      const req = { ...request, input: { url: `${target}route-${n}` } };
      const action = progress.begin(req, target, 2, 2);
      expect(action.blocked).toBeUndefined();
      progress.finish(req, action.key, result(true, String(n)), 2);
    }
    expect(Object.keys(progress.state.actions)).toHaveLength(100);
  });

  it("restores failures and prevents replay of unknown interrupted invocations", () => {
    const progress = new BlackboxProgress();
    const action = progress.begin(request, target, 2, 2);
    const restored = new BlackboxProgress(JSON.parse(JSON.stringify(progress.state)));
    expect(restored.begin(request, target, 2, 2).blocked).toBe("interrupted_unknown_outcome");
    progress.finish(request, action.key, result(false), 2);
    const retry = new BlackboxProgress(JSON.parse(JSON.stringify(progress.state)));
    expect(retry.state.actions[action.key]?.failures).toBe(1);
    expect(retry.begin(request, target, 2, 2).blocked).toBeUndefined();
  });

  it("uses mechanical supervision for ordinary batches and deduplicates budget warnings", () => {
    const progress = new BlackboxProgress();
    const budget = { timeMs: 0, toolCalls: 10, agentTurns: 0, tokens: 0, cost: 0, retries: 0 };
    expect(superviseCheckpoint(progress.state, budget, { kind: "tool_batch", madeProgress: true, toolCalls: 1 }).action).toBe("continue");
    progress.state.usage.toolCalls = 8;
    expect(superviseCheckpoint(progress.state, budget, { kind: "tool_batch", madeProgress: true, toolCalls: 1 }).action).toBe("observer");
    progress.state.supervision!.reviewPending = false; // A successful Observer run resolves the required review.
    expect(superviseCheckpoint(progress.state, budget, { kind: "tool_batch", madeProgress: true, toolCalls: 1 }).action).toBe("continue");
  });

  it("reviews new findings before accepting a terminal task set", () => {
    const progress = new BlackboxProgress();
    progress.state.tasks.inspect = { status: "completed", evidence_ids: ["ev-1"] };
    const decision = superviseCheckpoint(progress.state, { timeMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 }, { kind: "analysis", newFinding: true }, [{ id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "inspect" } }]);
    expect(decision.acceptance.ready).toBe(false);
    expect(decision.acceptance.reason_codes).toContain("TERMINAL_REVIEW_PENDING");
    expect(decision.action).toBe("observer");
  });

  it.each(["completed", "blocked", "failed"] as const)("rejects acceptance of %s tasks until state validation succeeds", status => {
    const progress = new BlackboxProgress();
    progress.state.tasks.inspect = { status, reason: "fixture outcome", evidence_ids: ["ev-1"] };
    const facts = [{ id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "inspect" } }];
    const budget = { timeMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 };
    const event = { kind: "analysis" as const };
    expect(superviseCheckpoint(progress.state, budget, event, facts).action).toBe("acceptance");
    progress.state.transitionErrors = ["invalid_advice_decision:ev-advice"];
    const rejected = superviseCheckpoint(progress.state, budget, event, facts);
    expect(rejected.action).toBe("observer");
    expect(rejected.reasons).toContain("state_validation_failed");
    expect(rejected.reasons).toContain("validation_failed");
    expect(rejected.acceptance).toMatchObject({ ready: false, validationErrors: ["invalid_advice_decision:ev-advice"] });
    expect(progress.state.validationErrors).toEqual(["invalid_advice_decision:ev-advice"]);
    const restored = new BlackboxProgress(JSON.parse(JSON.stringify(progress.state)));
    expect(superviseCheckpoint(restored.state, budget, event, facts).acceptance.ready).toBe(false);
    restored.state.transitionErrors = [];
    restored.state.supervision!.reviewPending = false;
    expect(superviseCheckpoint(restored.state, budget, event, facts).action).toBe("acceptance");
    expect(restored.state.supervision?.acceptance).toMatchObject({ ready: true, validationErrors: [] });
  });

  it("同一批阻塞 issues 连续 5 轮只排 1 次 Observer，修好后重现才重排", () => {
    const progress = new BlackboxProgress();
    progress.state.tasks.inspect = { status: "completed", reason: "fixture", evidence_ids: ["ev-1"] };
    progress.state.transitionErrors = ["invalid_advice_decision:a"];
    const facts = [{ id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "inspect" } }];
    const budget = { timeMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 };
    const event = { kind: "analysis" as const };
    const first = superviseCheckpoint(progress.state, budget, event, facts);
    expect(first.action).toBe("observer");
    expect(first.reasons).toContain("validation_failed");
    // 真实路径由 desk 的 CAS 提交写回 reviews，这里直接补上一条已完成的审查。
    progress.state.supervision!.reviews = { r1: {
      id: "r1", reason: "validation_failed", trigger_event_id: "e1", session_id: "s1",
      state_version: "sv2-fixture", status: "completed", created_at: Date.now(), attempts: 0,
      issues: first.acceptance.issues,
    } };
    for (let round = 0; round < 4; round++) {
      const decision = superviseCheckpoint(progress.state, budget, event, facts);
      expect(decision.action).toBe("continue");
      expect(decision.reasons).toContain("review_deduped");
      expect(decision.warnings).toContain("review_deduped");
    }
    progress.state.transitionErrors = [];
    progress.state.supervision!.reviewPending = false;
    const repaired = superviseCheckpoint(progress.state, budget, event, facts);
    expect(repaired.reasons).not.toContain("validation_failed");
    expect(progress.state.supervision?.lastReviewIssueFingerprint).toBeUndefined();
    progress.state.transitionErrors = ["invalid_advice_decision:a"];
    const reappeared = superviseCheckpoint(progress.state, budget, event, facts);
    expect(reappeared.action).toBe("observer");
    expect(reappeared.reasons).toContain("validation_failed");
  });
});

describe("进程内重读账本不能把在飞动作当成未知结果（8fa38aaa1cd6a72d 的 T1）", () => {
  it("resume:false 时在飞动作不算中断，任务不被判死", () => {
    const progress = new BlackboxProgress();
    const action = progress.begin(request, target, 2, 2);
    expect(progress.state.tasks[request.task_id || Object.keys(progress.state.tasks)[0]!]?.status).toBe("running");
    // Observer 每轮都会重读一次账本：此刻工具的调用还没结束（inFlight=true），不是"结果未知"。
    const reread = new BlackboxProgress(JSON.parse(JSON.stringify(progress.state)), { resume: false });
    expect(reread.state.tasks[`action:${action.key}`]).toBeUndefined();
    expect(reread.begin(request, target, 2, 2).blocked).toBeUndefined();
    progress.finish(request, action.key, result(true, "ok"), 2);
  });

  it("默认（会话重新开始）仍然拒绝盲重放", () => {
    const progress = new BlackboxProgress();
    const action = progress.begin(request, target, 2, 2);
    const resumed = new BlackboxProgress(JSON.parse(JSON.stringify(progress.state)));
    expect(resumed.state.tasks[`action:${action.key}`]?.reason).toBe("interrupted_unknown_outcome");
    expect(resumed.begin(request, target, 2, 2).blocked).toBe("interrupted_unknown_outcome");
    progress.finish(request, action.key, result(true, "ok"), 2);
  });
});

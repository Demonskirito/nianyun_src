import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";

const facts = [{ id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "inspect" } }];
function fixture() {
  const p = new BlackboxProgress();
  p.state.tasks.inspect = { status: "completed", evidence_ids: ["ev-1"] };
  return p;
}

describe("unified acceptance gate", () => {
  it("revalidates evidence on every call rather than trusting a cached ready result", () => {
    const p = fixture();
    expect(evaluateAcceptance(p.state, facts).ready).toBe(true);
    p.state.tasks.inspect.evidence_ids = ["ev-missing"];
    const failed = evaluateAcceptance(p.state, facts);
    expect(failed).toMatchObject({ ready: false, all_tasks_terminal: true, validation_passed: false, blocking_error_count: 1 });
    expect(failed.reason_codes).toEqual(["VALIDATION_ERRORS_REMAIN", "EVIDENCE_INTEGRITY_FAILED"]);
    expect(failed.issues[0]).toMatchObject({ severity: "error", task_id: "inspect", evidence_id: "ev-missing", path: "tasks.inspect.evidence_ids" });
    // Fixing the underlying state clears computed errors without clearing a cached array.
    p.state.tasks.inspect.evidence_ids = ["ev-1"];
    expect(evaluateAcceptance(p.state, facts)).toMatchObject({ ready: true, validationErrors: [] });
    expect(evaluateAcceptance(p.state, []).ready).toBe(false);
  });

  it.each([
    { id: "ev-1", kind: "audit", data: { ok: true, task_id: "inspect" } },
    { id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "other" } },
    { id: "ev-1", kind: "tool-result", data: { ok: false, task_id: "inspect" } },
  ])("rejects invalid evidence provenance %#", fact => {
    expect(evaluateAcceptance(fixture().state, [fact])).toMatchObject({ ready: false, evidence_integrity_ok: false });
  });

  it("requires reviews and explicit advice disposition independently of terminal tasks", () => {
    const p = fixture();
    p.state.supervision = { observerRuns: 1, reviewPending: true };
    p.state.advice = { a1: { status: "pending", tasks: [] } };
    const gate = evaluateAcceptance(p.state, facts);
    expect(gate).toMatchObject({ ready: false, validation_passed: true, required_reviews_complete: false, unhandled_advice: 1 });
    expect(gate.reason_codes).toEqual(["TERMINAL_REVIEW_PENDING", "UNHANDLED_ADVICE"]);
    const restored = new BlackboxProgress(JSON.parse(JSON.stringify(p.state)));
    expect(evaluateAcceptance(restored.state, facts).required_reviews_complete).toBe(false);
    p.state.supervision.reviewPending = false;
    p.state.advice.a1 = { status: "accepted", tasks: [], task_ids: ["missing"], reason: "accept" };
    expect(evaluateAcceptance(p.state, facts).issues).toContainEqual(expect.objectContaining({ code: "ADVICE_DISPOSITION_INVALID", advice_id: "a1", severity: "error" }));
    p.state.advice.a1 = { status: "rejected", tasks: [], reason: "not applicable" };
    expect(evaluateAcceptance(p.state, facts).ready).toBe(true);
  });

  it.each(["blocked", "failed"] as const)("allows a valid partial report for %s with warnings, not task success", status => {
    const p = new BlackboxProgress();
    p.state.tasks.inspect = { status, outcome_reason: "outside scope or failed adapter" };
    // issues 里现在不止一条（结案契约上线前的老任务还会带一条 legacy warning），
    // 断言"包含"，不钉死顺序。
    expect(evaluateAcceptance(p.state, [])).toMatchObject({ ready: true, all_tasks_terminal: true, validation_passed: true, blocking_error_count: 0,
      issues: expect.arrayContaining([expect.objectContaining({ severity: "warning", code: "PARTIAL_TASK_OUTCOME" })]) });
    expect(p.state.tasks.inspect.status).toBe(status);
  });

  it("retains rejected transitions across empty output and checkpoint reload", () => {
    const p = fixture();
    p.merge({ completed_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "invalid claim", evidence_ids: ["audit"] }] }, facts);
    p.merge({ summary: "no repair" }, facts);
    const reloaded = new BlackboxProgress(JSON.parse(JSON.stringify(p.state)));
    expect(evaluateAcceptance(reloaded.state, facts).ready).toBe(false);
    reloaded.merge({ completed_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "corrected references", evidence_ids: ["ev-1"] }] }, facts);
    expect(evaluateAcceptance(reloaded.state, facts).ready).toBe(true);
  });

  it("preserves legacy unresolved errors and rejects empty plans", () => {
    const p = fixture();
    p.state.validationErrors = ["invalid_advice_decision:old"];
    const result = evaluateAcceptance(p.state, facts);
    expect(result.issues[0]).toMatchObject({ advice_id: "old", severity: "error" });
    expect(result.ready).toBe(false);
    expect(evaluateAcceptance(new BlackboxProgress().state, []).ready).toBe(false);
    const valid = fixture();
    (valid.state as Record<string, unknown>).approvals = { legacy: { id: "legacy", request: { tool: "http.request" }, status: "pending", created_at: 1 } };
    expect(evaluateAcceptance(valid.state, facts).reason_codes).not.toContain("TOOL_APPROVAL_PENDING");
  });

  it("requires a review record rather than trusting a reviewed status label", () => {
    const p = fixture();
    const target = "https://app.example.test/";
    const evidence = [{ ...facts[0], data: { ...facts[0]!.data, url: target } }];
    p.state.findings = { f1: { id: "f1", title: "candidate", type: "exposure", target, description: "fixture", impact: "unconfirmed", severity: "low", reproduction_steps: ["read fixture"], evidence_ids: ["ev-1"], remediation: "review", confidence: "low", status: "reviewed" } };
    const gate = evaluateAcceptance(p.state, evidence);
    expect(gate).toMatchObject({ ready: false, required_reviews_complete: false, blocking_error_count: 1 });
    expect(gate.issues).toContainEqual(expect.objectContaining({ code: "FINDING_REVIEW_INVALID", path: "findings.f1.review" }));
    p.state.findings.f1!.review = { actor: "observer", reason: "evidence consistent", evidence_ids: ["ev-1"], at: 1 };
    expect(evaluateAcceptance(p.state, evidence).ready).toBe(true);
  });

  /**
   * 预算收口：一次评估不可能在预算内把每条任务都推到终态。
   * 收口时"没轮到"的任务必须**声明**而不是悬着，否则验收门永远开不了口，
   * 会话只能由人按暂停键结束（2026-11-05 实测 094d157f6fc028f6）。
   */
  describe("settled-but-not-reached tasks", () => {
    it("lets a declared gap pass the gate while keeping the task pending and the report honest", () => {
      const p = new BlackboxProgress();
      p.state.tasks.inspect = { status: "completed", evidence_ids: ["ev-1"] };
      p.state.tasks.sweep = { status: "pending", settled: "not_reached", outcome_reason: "预算没轮到" };
      const gate = evaluateAcceptance(p.state, facts);
      expect(gate).toMatchObject({ ready: true, all_tasks_accounted: true, all_tasks_terminal: false });
      // 状态不改：真的没做，就不能写成"试过但不行"。
      expect(p.state.tasks.sweep.status).toBe("pending");
      expect(gate.issues).toContainEqual(expect.objectContaining({ code: "TASK_NOT_REACHED", severity: "warning" }));
      expect(gate.reason_codes).not.toContain("TASKS_NOT_TERMINAL");
    });

    it("still blocks on a task nobody accounted for", () => {
      const p = new BlackboxProgress();
      p.state.tasks.inspect = { status: "completed", evidence_ids: ["ev-1"] };
      p.state.tasks.sweep = { status: "pending" };
      const gate = evaluateAcceptance(p.state, facts);
      expect(gate).toMatchObject({ ready: false, all_tasks_accounted: false });
      expect(gate.reason_codes).toContain("TASKS_NOT_TERMINAL");
      expect(gate.pending).toEqual(["sweep"]);
    });

    it("keeps the review gate strict: a dropped terminal review is not an acceptance input", () => {
      const p = fixture();
      p.state.supervision = { observerRuns: 2, reviewPending: true, reviewDropped: "run_terminated:tool_budget_exhausted" };
      /**
       * reviewDropped 只用来放行**这一次收口**的终止判定（desk 的 finished），不能进验收：
       * 它留在 checkpoint 里，若当成验收输入，恢复后的下一场会带着"审查已过"的假状态起跑
       * ——实测 test/blackbox.test.ts 的 resume 场景因此把完成声明烧在没证据的那一轮，
       * 整场从 completed 退化成 stalled。
       */
      expect(evaluateAcceptance(p.state, facts)).toMatchObject({ ready: false, required_reviews_complete: false });
      p.state.supervision.reviewPending = false;
      expect(evaluateAcceptance(p.state, facts)).toMatchObject({ ready: true, required_reviews_complete: true });
    });
  });
});

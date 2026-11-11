import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { boundedContext } from "../src/blackbox/context.js";
import { autoSalvageReason, salvageAdviceIds } from "../src/blackbox/advice.js";

const adviceId = "review-d9a3260b5fbd6a8a5ec9d6b9";

function withAdvice() {
  const progress = new BlackboxProgress();
  progress.state.tasks.T1 = { status: "pending", reason: "测试任务" };
  progress.supplement({ suggestions: ["改打 open.oppomobile.com 的 /base/v1/*"] }, adviceId);
  return progress;
}

/** 主 Agent 一轮没写 advice_decisions 的输出（schema 已通过后的形态）。 */
const noDecision = (summary = "本轮未处置任何建议。") => ({ summary, required_tasks: [], completed_tasks: [], blocked_tasks: [], failed_tasks: [], task_outcomes: [] });

describe("advice auto-disposition", () => {
  it("keeps advice pending for one round so the agent can still claim it", () => {
    const progress = withAdvice();
    progress.merge(noDecision());
    expect(progress.state.advice?.[adviceId]).toMatchObject({ status: "pending", misses: 1 });
    expect(progress.sweepAdvice()).toEqual([]);
    expect(evaluateAcceptance(progress.state, []).unhandled_advice).toBe(1);
  });

  it("archives advice that was ignored for two rounds instead of failing the run", () => {
    const progress = withAdvice();
    progress.merge(noDecision());
    progress.merge(noDecision());
    const swept = progress.sweepAdvice();
    expect(swept).toEqual([adviceId]);
    expect(progress.state.advice?.[adviceId]).toMatchObject({ status: "superseded", auto_skipped: true });
    const acceptance = evaluateAcceptance(progress.state, []);
    expect(acceptance.unhandled_advice).toBe(0);
    expect(acceptance.blocking_error_count).toBe(0);
    expect(acceptance.reason_codes).not.toContain("UNHANDLED_ADVICE");
    expect(acceptance.reason_codes).not.toContain("VALIDATION_ERRORS_REMAIN");
  });

  it("archives a text-mentioned advice id in the same round and clears its decision error", () => {
    const progress = withAdvice();
    // 模型给了指向不存在任务链的"采纳"：决定非法，但正文点到了 id。
    progress.merge({ ...noDecision(`采纳 ${adviceId} 的方向`), advice_decisions: [{ advice_id: adviceId, accepted: true, reason: "采纳", task_ids: ["T404"] }] });
    expect(progress.state.advice?.[adviceId]?.status).toBe("pending");
    expect(progress.state.transitionErrors).toContain(`invalid_advice_decision:${adviceId}`);
    const swept = progress.sweepAdvice({ salvaged: progress.state.adviceSalvaged });
    expect(swept).toEqual([adviceId]);
    expect(progress.state.advice?.[adviceId]?.reason).toBe(autoSalvageReason());
    // 归档后不再留着"修不了的决定错误"继续堵门禁。
    expect(progress.state.transitionErrors).not.toContain(`invalid_advice_decision:${adviceId}`);
    expect(evaluateAcceptance(progress.state, []).blocking_error_count).toBe(0);
  });

  it("treats a code-side archive without reason as a warning, never a blocker", () => {
    const progress = withAdvice();
    progress.state.advice![adviceId] = { tasks: [], suggestions: [], status: "superseded" };
    const acceptance = evaluateAcceptance(progress.state, []);
    expect(acceptance.blocking_error_count).toBe(0);
    expect(acceptance.issues.map(issue => issue.code)).toContain("ADVICE_ARCHIVED_WITHOUT_REASON");
  });

  it("keeps a malformed disposition visible but unblocks once the advice is archived", () => {
    const progress = withAdvice();
    // 模型想采纳，但没给出对应任务：这是它自己写错的决定，必须能被看见。
    progress.merge({ ...noDecision(), advice_decisions: [{ advice_id: adviceId, accepted: true, reason: "采纳", task_ids: [] }] });
    expect(evaluateAcceptance(progress.state, []).issues).toContainEqual(
      expect.objectContaining({ code: "invalid_advice_decision", severity: "error" }));
    // 一旦建议被归档（不可处置），这条错误必须一起消失，否则就是永远修不好的死锁。
    progress.sweepAdvice({ maxMisses: 1 });
    const acceptance = evaluateAcceptance(progress.state, []);
    expect(acceptance.blocking_error_count).toBe(0);
    expect(progress.state.transitionErrors || []).not.toContain(`invalid_advice_decision:${adviceId}`);
  });

  it("auto-archived advice clears the orphan decision error left by supplement()", () => {
    const progress = new BlackboxProgress();
    progress.state.tasks.T1 = { status: "completed", evidence_ids: ["ev-1"], outcome_reason: "done" };
    progress.state.advice = { [adviceId]: { tasks: [{ id: "T1" }], suggestions: ["旧建议"], status: "pending" } };
    progress.state.transitionErrors = [`invalid_advice_decision:${adviceId}`];
    // 任务已终态 → supplement 归档旧建议，同时清掉它名下那条再也修不掉的错误。
    progress.supplement({ suggestions: ["新建议"] }, "advice-2");
    expect(progress.state.advice?.[adviceId]?.status).toBe("superseded");
    expect(progress.state.transitionErrors).not.toContain(`invalid_advice_decision:${adviceId}`);
    expect(evaluateAcceptance(progress.state, [{ id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "T1", url: "https://a.test/" } }]).blocking_error_count).toBe(0);
  });

  it("surfaces pending advice as critical_actions in the model context", () => {
    const progress = withAdvice();
    progress.merge(noDecision());
    const context = boundedContext({ id: "s1", checkpoint: progress.state, evidence: [] }, {}) as Record<string, any>;
    expect(context.critical_actions?.advice?.[0]?.advice_id).toBe(adviceId);
    expect(context.critical_actions?.advice?.[0]?.misses).toBe(1);
    expect(String(context.critical_actions?.must_do_first)).toContain("advice_decisions");
  });

  it("only salvages ids that actually exist and dedupes case differences", () => {
    expect(salvageAdviceIds(`见 review-abcdef123456 与 REVIEW-ABCDEF123456，还有 advice-7`, [adviceId, "review-abcdef123456", "advice-7"]))
      .toEqual(["review-abcdef123456", "advice-7"]);
    expect(salvageAdviceIds("纯文本没有任何 id")).toEqual([]);
  });
});
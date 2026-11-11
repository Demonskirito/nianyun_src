import { describe, expect, it } from "vitest";
import { BlackboxProgress, type ObserverReview } from "../src/blackbox/progress.js";
import { planStaleReview, reviewIssueFingerprint, shouldQueueIssueReview, unresolvedReviewIssues } from "../src/blackbox/review-stale.js";

/**
 * 过期 Observer 审查的处置语义。
 *
 * 事故背景：catch-all 目标上 Observer 审查被异步化，结果回来时状态版本已经变了，走 stale 分支。
 * 旧实现把结果标成"仅历史"，但 `reviewPending` 留 true —— 建议丢掉、门禁永久打不开，
 * 会话最后停在 `required_review_pending`，20 条待办一条没跑（4 次 review-stale 实测）。
 *
 * 新规则：建议一律保留；门禁按接受度重算，过期本身不再是阻塞理由。
 */
const acceptance = (patch: Partial<{ blocking_error_count: number; unhandled_advice: number; reason_codes: string[] }> = {}) => ({
  blocking_error_count: 0, unhandled_advice: 0, reason_codes: [] as string[], ...patch,
});

describe("过期审查的处置", () => {
  it("只是快照过期、没有阻塞项 → 清门禁并保留建议", () => {
    const plan = planStaleReview({ acceptance: acceptance(), suggestionCount: 2 });
    expect(plan.keepPending).toBe(false);
    expect(plan.halt).toBe(false);
    expect(plan.injectAdvice).toBe(true);
    expect(plan.reason).toBe("stale_cleared");
  });

  it("仍然有阻塞项 → 门禁保持并中止本轮", () => {
    const plan = planStaleReview({ acceptance: acceptance({ blocking_error_count: 1 }), suggestionCount: 1 });
    expect(plan.keepPending).toBe(true);
    expect(plan.halt).toBe(true);
    expect(plan.reason).toBe("stale_blocking");
  });

  it("有未处置建议 → 门禁保持（交给下一轮处置）", () => {
    const plan = planStaleReview({ acceptance: acceptance({ unhandled_advice: 2 }), suggestionCount: 1 });
    expect(plan.keepPending).toBe(true);
    expect(plan.halt).toBe(true);
  });

  it("终态审查未完成 → 门禁保持", () => {
    const plan = planStaleReview({ acceptance: acceptance({ reason_codes: ["TERMINAL_REVIEW_PENDING"] }), suggestionCount: 0 });
    expect(plan.keepPending).toBe(true);
    expect(plan.injectAdvice).toBe(false);
  });

  it("没有建议、也没有阻塞 → 清门禁且不注入", () => {
    const plan = planStaleReview({ acceptance: acceptance(), suggestionCount: 0 });
    expect(plan.keepPending).toBe(false);
    expect(plan.injectAdvice).toBe(false);
    expect(plan.reason).toBe("stale_no_advice");
  });

  it("点名的问题已全部修好 → 清掉自设的终审门户，不再空转", () => {
    const reviewed = [{ code: "OUTCOME_WITHOUT_EVIDENCE_REFERENCE", severity: "error", path: "tasks.T1", task_id: "T1", message: "旧说明" }];
    const plan = planStaleReview({ acceptance: acceptance({ reason_codes: ["TERMINAL_REVIEW_PENDING"] }), suggestionCount: 1,
      reviewIssues: reviewed, currentIssues: [] });
    expect(plan.keepPending).toBe(false);
    expect(plan.halt).toBe(false);
    expect(plan.reason).toBe("stale_issues_resolved");
    expect(plan.issuesCompared).toEqual({ reviewed: 1, unresolved: [], blocking: 0, warning_only: 0 });
  });

  it("点名的问题仍然存在 / 冒出新的阻塞问题 → 门禁保持", () => {
    const reviewed = [{ code: "A", severity: "error", path: "tasks.T1", task_id: "T1" }];
    const stillThere = planStaleReview({ acceptance: acceptance(), suggestionCount: 0,
      reviewIssues: reviewed, currentIssues: reviewed });
    expect(stillThere.keepPending).toBe(true);
    expect(stillThere.reason).toBe("stale_blocking");
    expect(stillThere.issuesCompared?.unresolved).toHaveLength(1);
    const newBlocker = planStaleReview({ acceptance: acceptance({ blocking_error_count: 1 }), suggestionCount: 0,
      reviewIssues: reviewed, currentIssues: [{ code: "B", severity: "error", path: "tasks.T2", task_id: "T2" }] });
    expect(newBlocker.keepPending).toBe(true);
  });
});

describe("审查排队的 issues 去重", () => {
  const issue = (code: string, task = "T1", message = "说明") =>
    ({ code, severity: "error", path: `tasks.${task}`, task_id: task, message });
  const review = (status: ObserverReview["status"], issues: unknown[]): ObserverReview =>
    ({ id: "r1", reason: "validation_failed", trigger_event_id: "e1", session_id: "s1",
      state_version: "sv2-fixture", status, created_at: Date.now(), attempts: 0, issues });

  it("指纹与顺序 / message 文本无关，未修好的问题能被点出来", () => {
    const a = [issue("A"), issue("B", "T2")];
    expect(reviewIssueFingerprint(a)).toBe(reviewIssueFingerprint([a[1], { ...a[0], message: "改了措辞" }, a[0]]));
    expect(reviewIssueFingerprint([])).toBe("");
    expect(unresolvedReviewIssues(a, [issue("A")])).toHaveLength(1);
    expect(unresolvedReviewIssues(a, [issue("C", "T3")])).toHaveLength(0);
  });

  it("同一批 issues 连跑 5 轮只排 1 次审查", () => {
    const state = new BlackboxProgress().state;
    const issues = [issue("A"), issue("B", "T2")];
    expect(shouldQueueIssueReview(state, issues)).toMatchObject({ queue: true, reason: "first_seen" });
    state.supervision!.reviews = { r1: review("pending", issues) };
    for (let round = 0; round < 5; round++) {
      expect(shouldQueueIssueReview(state, [...issues].reverse())).toMatchObject({ queue: false, reason: "deduped" });
    }
    expect(state.supervision?.lastReviewIssueQueue?.reason).toBe("first_seen");
  });

  it("问题集合变化、修好后重现、审查失败 → 都允许重排（防漏审）", () => {
    const state = new BlackboxProgress().state;
    const issues = [issue("A")];
    expect(shouldQueueIssueReview(state, issues).queue).toBe(true);
    state.supervision!.reviews = { r1: review("completed", issues) };
    expect(shouldQueueIssueReview(state, [...issues, issue("B", "T2")])).toMatchObject({ queue: true, reason: "changed" });
    expect(shouldQueueIssueReview(state, [])).toMatchObject({ queue: false, reason: "no_issues" });
    expect(state.supervision?.lastReviewIssueFingerprint).toBeUndefined();
    expect(shouldQueueIssueReview(state, issues)).toMatchObject({ queue: true, reason: "first_seen" });
    state.supervision!.reviews = { r1: review("failed", issues) };
    expect(shouldQueueIssueReview(state, issues).queue).toBe(true);
  });
});
import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";

/**
 * 2026-11-02 会话 `b9601629efd1f137` 的收场方式：
 *
 *   1. 两轮 `protocol_error`（output_tokens 顶到 8000 被截断）→ 代码直接 `stopReason="protocol_error"`，
 *      用掉 12/600 次工具调用就整场结束，7 个待办一个没跑；
 *   2. 收尾补跑一回合（不执行工具）把建议标成 `accepted`，理由写着"tool_requests 压到 0 条
 *      以规避协议再次失败"；门禁看到 `openAdvice=0`，认为没有未办事项，停在 required_review_pending。
 *
 * 这里钉住第二层：**签收不等于执行**。零动作回合里的 accepted 记 `paper`，
 * 门禁仍当它是未处置，直到出现一次真实动作。
 */

const ADVICE = "review-a203e21cdf5b48fc162c2bed";

function withAdvice() {
  const progress = new BlackboxProgress();
  progress.state.tasks.T1 = { status: "pending", reason: "收口 T1" };
  progress.state.tasks.T2 = { status: "pending", reason: "SPA 逆向" };
  progress.supplement({ suggestions: ["T1 本轮就该收口"] }, ADVICE);
  return progress;
}

const emptyRound = (extra: Record<string, unknown> = {}) => ({
  summary: "本轮只做记账。", required_tasks: [], completed_tasks: [], blocked_tasks: [], failed_tasks: [],
  task_outcomes: [], tool_requests: [], ...extra,
});

const accepted = (taskIds = ["T1"]) => ({
  advice_decisions: [{ advice_id: ADVICE, accepted: true, reason: "采纳：压到 0 条 tool_requests 以规避协议失败", task_ids: taskIds }],
});

describe("纸面采纳：零动作回合签收不算处置", () => {
  it("零动作回合里 accepted → 记 paper，门禁口径仍算未处置", () => {
    const progress = withAdvice();
    progress.merge(emptyRound(accepted()));
    expect(progress.state.advice?.[ADVICE]).toMatchObject({ status: "accepted", paper: true });
    expect(progress.openAdviceCount()).toBe(1);
    // 旧口径（只数 pending）会得到 0，这正是提前停场的原因。
    expect(Object.values(progress.state.advice || {}).filter(item => item.status === "pending")).toHaveLength(0);
  });

  it("同一回合真发了工具请求 → 不算纸面采纳", () => {
    const progress = withAdvice();
    progress.merge(emptyRound({ ...accepted(), tool_requests: [{ tool: "http.request", task_id: "T1", input: { url: "https://m.example.com/x" } }] }));
    expect(progress.state.advice?.[ADVICE]?.paper).toBeFalsy();
    expect(progress.openAdviceCount()).toBe(0);
  });

  it("同一回合把任务推进到终态 → 不算纸面采纳（收口建议本来就只改状态）", () => {
    const progress = withAdvice();
    progress.state.tasks.T1 = { ...progress.state.tasks.T1, contract_required: false } as typeof progress.state.tasks[string];
    progress.merge(emptyRound({ ...accepted(), completed_tasks: ["T1"] }));
    const item = progress.state.advice?.[ADVICE];
    if (item?.status === "accepted") expect(item.paper).toBeFalsy();
  });

  it("纸面采纳之后出现一次真实动作 → paper 清掉，门禁不再算未处置", () => {
    const progress = withAdvice();
    progress.merge(emptyRound(accepted()));
    expect(progress.openAdviceCount()).toBe(1);
    progress.merge(emptyRound({ tool_requests: [{ tool: "http.request", task_id: "T2", input: { url: "https://m.example.com/y" } }] }));
    expect(progress.state.advice?.[ADVICE]?.paper).toBeFalsy();
    expect(progress.openAdviceCount()).toBe(0);
  });

  it("纸面采纳不会被当成 pending 自动归档（账要留在 accepted 上）", () => {
    const progress = withAdvice();
    progress.merge(emptyRound(accepted()));
    expect(progress.sweepAdvice()).toEqual([]);
    expect(progress.state.advice?.[ADVICE]?.status).toBe("accepted");
  });
});

describe("离场前隔离不可修复的历史错误", () => {
  it("任务已终态时，closure_deliverables_partial 不再阻塞验收", () => {
    const progress = withAdvice();
    progress.state.tasks.T1 = { status: "completed", reason: "已收口" };
    progress.state.transitionErrors = ["closure_deliverables_partial:T1"];
    progress.state.validationErrors = [...progress.state.transitionErrors];
    const before = evaluateAcceptance(progress.state, []).blocking_error_count;
    const pruned = progress.pruneAdviceErrors();
    const after = evaluateAcceptance(progress.state, []);
    expect(pruned).toContain("closure_deliverables_partial:T1");
    // 该条不再计入阻塞（本用例里 T1 也没有证据，那条错误应该留着）。
    expect(after.blocking_error_count).toBe(before - 1);
    expect(after.validationErrors).not.toContain("closure_deliverables_partial:T1");
    // 不是删掉而是隔离：dlq 里有记录，控制台仍能看见。
    expect(progress.deadLetters().some(letter => letter.code === "closure_deliverables_partial")).toBe(true);
  });
});

import { describe, expect, it } from "vitest";
import { envelopeLine, envelopeText, errorTypeForField, type RejectEnvelope } from "../src/blackbox/envelope.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { unquarantinableDigest } from "../src/blackbox/quarantine.js";

/**
 * 缺陷 3/4/5/7 的回归：
 *   3  非工具字段被丢 → 必须有结构化信封（字段/原因/该写什么）
 *   4  结案是状态迁移，任务记录与结案凭据都不能消失
 *   5  历史遗留 / 终态后不可修复的错误进 DLQ，退出 blocking 计数但保留可见
 *   7  audit_ids 引用错证据 → 信封里要带"本任务可引用的 id 池"
 */
const target = "https://app.example.test/";
const evId = "ev-0123456789abcdef";

describe("结构化错误信封", () => {
  it("字段名映射到 error_type，未知字段也有兜底", () => {
    expect(errorTypeForField("task_outcomes")).toBe("invalid_task_outcome");
    expect(errorTypeForField("tool_requests")).toBe("invalid_tool_request");
    expect(errorTypeForField("who_knows")).toBe("invalid_who_know");
  });

  it("一行文本同时给出原因、该写什么、候选 id 与示例", () => {
    const envelope: RejectEnvelope = {
      error_type: "invalid_task_outcome", dropped_field: "task_outcomes", index: 0,
      reason: "TASK_AUDIT_INVALID", hint: "audit_ids 只接受 tool-request", valid_ids: [evId],
      example: { task_id: "T1" },
    };
    const line = envelopeLine(envelope);
    expect(line).toContain("invalid_task_outcome");
    expect(line).toContain("task_outcomes[0]");
    expect(line).toContain(evId);
    expect(line).toContain("示例");
  });

  it("批量文本按 limit 截断，不会把上下文撑爆", () => {
    const many: RejectEnvelope[] = Array.from({ length: 10 }, (_, index) => ({
      error_type: "invalid_tool_request", dropped_field: "tool_requests", index, reason: "r", hint: "h",
    }));
    expect(envelopeText(many, 3).split("\n")).toHaveLength(3);
  });
});

describe("结案留档（缺陷 4）", () => {
  it("结案后任务仍在，且留下 completion_proof（含 deliverables_met 与证据）", () => {
    const p = new BlackboxProgress();
    p.merge({ required_tasks: [{ id: "T1", target, purpose: "p", reason: "r", completion_criteria: "c", deliverables: ["endpoint_list"] }] });
    const evidence = [{ id: evId, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T1", url: `${target}a` } }];
    p.merge({
      completed_tasks: ["T1"],
      task_outcomes: [{ task_id: "T1", reason: `按 ${evId} 判定成立`, evidence_ids: [evId], deliverables_met: true }],
    }, evidence);
    const task = p.state.tasks.T1!;
    expect(task.status).toBe("completed");
    const proof = (task.completion_proof || [])[0];
    expect(proof?.evidence_ids).toEqual([evId]);
    // deliverables_met: true 表示"全部达成"，留档成 "all" 而不是被丢弃
    expect(proof?.deliverables_met).toBe("all");
  });
});

describe("死信队列（缺陷 5）", () => {
  it("任务终态后残留的转移错误移出 blocking，但进 dlq 可见", () => {
    const p = new BlackboxProgress();
    p.state.transitionErrors = ["anomaly_requires_diff:T1", "task_duplicate:T2->T1"];
    p.state.tasks.T1 = { status: "completed" } as never;
    const removed = p.pruneAdviceErrors();
    expect(removed.sort()).toEqual(["anomaly_requires_diff:T1", "task_duplicate:T2->T1"]);
    expect(p.state.transitionErrors).toEqual([]);
    expect(p.state.validationErrors).toEqual([]);
    expect(p.deadLetters().map(item => item.code).sort()).toEqual(["anomaly_requires_diff", "task_duplicate"]);
  });

  it("仍在 pending 的任务不会被误清（还能修就不算死信）", () => {
    const p = new BlackboxProgress();
    p.state.transitionErrors = ["anomaly_requires_diff:T1"];
    p.state.tasks.T1 = { status: "pending" } as never;
    expect(p.pruneAdviceErrors()).toEqual([]);
    expect(p.deadLetters()).toEqual([]);
    expect(p.state.transitionErrors).toEqual(["anomaly_requires_diff:T1"]);
  });

  /**
   * 2026-11-10 现场（会话 1dd9ded9ed239711）：
   * `completion_without_verdict:T` 打回时任务是 pending，后来被收口成 blocked；
   * 旧码表漏了这个码，剪枝永远碰不到它，门禁每轮把它当阻塞，5 场连续停场。
   */
  it("completion_without_verdict 在任务终态后可剪（同族码一直都能剪）", () => {
    const p = new BlackboxProgress();
    p.state.transitionErrors = [
      "completion_without_verdict:H_auth_wall_a8e39f4d",
      "completion_without_verdict:H_still_running",
    ];
    p.state.tasks.H_auth_wall_a8e39f4d = { status: "blocked" } as never;
    p.state.tasks.H_still_running = { status: "pending" } as never;
    expect(p.pruneAdviceErrors()).toEqual(["completion_without_verdict:H_auth_wall_a8e39f4d"]);
    expect(p.state.transitionErrors).toEqual(["completion_without_verdict:H_still_running"]);
    expect(p.deadLetters().map(item => item.code)).toEqual(["completion_without_verdict"]);
  });

  /** 建议已终态且自洽 = 处置冲突是一次「被拒的写入」，不是待办。 */
  it("建议终态自洽时 disposition_conflict 可剪", () => {
    const p = new BlackboxProgress();
    p.state.tasks.auth_unauth = { status: "pending" } as never;
    p.state.advice = {};
    p.state.advice.a = { status: "accepted", reason: "采纳", task_ids: ["auth_unauth"], suggestions: [] } as never;
    p.state.transitionErrors = ["disposition_conflict:a", "invalid_advice_decision:a"];
    expect(p.pruneAdviceErrors().sort()).toEqual(["disposition_conflict:a", "invalid_advice_decision:a"]);
    expect(p.state.transitionErrors).toEqual([]);
  });

  it("建议仍在 pending、或终态但不自洽时不剪（还轮得到处置 / 另有校验去报）", () => {
    const p = new BlackboxProgress();
    p.state.advice = {};
    p.state.advice.pendingOne = { status: "pending", suggestions: [] } as never;
    // 终态但不自洽：accepted 却没有指向任何任务
    p.state.advice.broken = { status: "accepted", reason: "采纳", task_ids: [], suggestions: [] } as never;
    // 终态但指向不存在的任务
    p.state.advice.dangling = { status: "rejected", reason: "不采纳", task_ids: ["gone"], suggestions: [] } as never;
    const errors = ["disposition_conflict:pendingOne", "disposition_conflict:broken", "disposition_conflict:dangling"];
    p.state.transitionErrors = [...errors];
    expect(p.pruneAdviceErrors()).toEqual([]);
    expect(p.state.transitionErrors).toEqual(errors);
  });
});

describe("无隔离路径时的解释（2026-11-10）", () => {
  it("全部落在转移账本上 → 点明是账本残渣、该修剪枝而不是隔离", () => {
    const digest = unquarantinableDigest([
      { code: "completion_without_verdict", severity: "error", path: "transitionErrors.completion_without_verdict:H1" },
      { code: "disposition_conflict", severity: "error", path: "transitionErrors.disposition_conflict:a" },
    ]);
    expect(digest?.text).toContain("completion_without_verdict:H1");
    expect(digest?.text).toContain("pruneAdviceErrors");
    expect(digest?.data.stop).toBe("ledger_residue");
  });

  it("混着结论类错误 → 判成「隔离会洗白」并保留停场", () => {
    const digest = unquarantinableDigest([
      { code: "COMPLETION_ON_DENIED_EVIDENCE", severity: "error", path: "tasks.T1.evidence_ids" },
    ]);
    expect(digest?.data.stop).toBe("unsupported_conclusion");
    expect(digest?.text).toContain("洗白");
  });

  it("没有 error 级阻塞时不产生事件", () => {
    expect(unquarantinableDigest([{ code: "TASK_OUTCOME_NO_FACT", severity: "warning", path: "tasks.T1.outcome_reason" }])).toBeUndefined();
  });
});
/**
 * P1-4/5（2026-11-10）：待办码只给"改得动的"，已终态任务的重交不再制造噪声。
 *
 * 现场依据：会话 1dd9ded9ed239711 每轮把 49 条 task_outcomes 全量重放，
 * 其中已 blocked 的条目每次必被拒，1–3 条/轮，错误被写回账本形成正反馈。
 */
describe("账本残渣（P1-4/5）", () => {
  it("actionableTransitionErrors 只留还有合法输入能改的条目", () => {
    const p = new BlackboxProgress();
    p.state.tasks.done = { status: "completed" } as never;
    p.state.tasks.blockedOne = { status: "blocked" } as never;
    p.state.tasks.live = { status: "pending" } as never;
    p.state.advice = {
      pendingAdvice: { status: "pending", suggestions: [] },
      settledAdvice: { status: "accepted", reason: "采纳", task_ids: ["live"], suggestions: [] },
    } as never;
    p.state.transitionErrors = [
      "completion_without_verdict:blockedOne",
      "completion_without_verdict:live",
      "disposition_conflict:pendingAdvice",
      "disposition_conflict:settledAdvice",
      "task_evidence_invalid:done:ev-0123456789abcdef",
      "task_backlog_full:T9",
    ];
    expect(p.actionableTransitionErrors()).toEqual([
      "completion_without_verdict:live",
      "disposition_conflict:pendingAdvice",
      "task_backlog_full:T9",
    ]);
  });

  it("已终态任务的结案重交被静默跳过：不写错误、不记打回、清掉旧拒收明细", () => {
    const p = new BlackboxProgress();
    p.state.tasks.T1 = { status: "blocked", outcome_reason: "前提消失" } as never;
    p.state.taskOutcomeResults = { T1: { status: "rejected", issues: [{ code: "COMPLETION_WITHOUT_VERDICT" }] } } as never;
    p.state.taskOutcomeRejects = { T1: 2 };
    const evidence = [{ id: evId, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T1", url: `${target}a` } }];
    p.merge({ completed_tasks: ["T1"], task_outcomes: [{ task_id: "T1", reason: "再交一次", evidence_ids: [evId] }] }, evidence);
    expect(p.state.transitionErrors ?? []).toEqual([]);
    expect(p.state.taskOutcomeResults?.T1).toBeUndefined();
    expect(p.state.taskOutcomeRejects?.T1).toBeUndefined();
    expect(p.state.taskOutcomeSkipped).toEqual([expect.objectContaining({ task_id: "T1", status: "blocked" })]);
    // 账本本体不动：终态不可重开，也不能被这次重交改成 completed。
    expect(p.state.tasks.T1?.status).toBe("blocked");
  });

  it("retireUnrepairableTransitions 按主体兜底，且与待办清单同源", () => {
    const p = new BlackboxProgress();
    p.state.tasks.blockedOne = { status: "blocked" } as never;
    p.state.tasks.live = { status: "pending" } as never;
    p.state.transitionErrors = ["completion_without_verdict:blockedOne", "completion_without_verdict:live"];
    expect(p.retireUnrepairableTransitions()).toEqual(["completion_without_verdict:blockedOne"]);
    expect(p.state.transitionErrors).toEqual(["completion_without_verdict:live"]);
    expect(p.state.validationErrors).toEqual(["completion_without_verdict:live"]);
    expect(p.deadLetters().map(entry => entry.code)).toEqual(["completion_without_verdict"]);
    expect(p.state.dlq?.[0]?.origin).toBe("unrepairable:subject_dead");
    // 幂等：没东西可退时返回空数组，不会反复写事件。
    expect(p.retireUnrepairableTransitions()).toEqual([]);
  });
});

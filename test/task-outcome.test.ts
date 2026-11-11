import { describe, expect, it } from "vitest";
import { autoRepairOutcomeEvidence, OUTCOME_CODES, hasConcreteFact, looksLikeCode, outcomeIssue, settleTask } from "../src/blackbox/task-outcome.js";

/**
 * 结案说明契约（2026-11-05）。
 *
 * 这几条测试锁的是"报告里一排 blocked 但看不出为什么"那个问题的根因：
 * 说明是可选字段、验收拿创建理由兜底、控制面收口不写证据。
 */
describe("settleTask", () => {
  it("writes the outcome without touching the creation reason", () => {
    const task = { status: "pending", reason: "派它去确认 /actuator 是否暴露", target: "https://a.test/actuator" };
    const settled = settleTask(task, { code: "dead_end", reason: "攻击图判死胡同（同特征响应 5 次）", evidence_ids: ["ev-1", "ev-2"], by: "control", at: 42 });
    expect(settled.outcome_code).toBe("dead_end");
    expect(settled.outcome_reason).toContain("死胡同");
    expect(settled.outcome_evidence_ids).toEqual(["ev-1", "ev-2"]);
    expect(settled.outcome_by).toBe("control");
    expect(settled.outcome_at).toBe(42);
    // 创建理由必须原样保留：历史上有 7 处收口把它覆盖成机器码，任务意图全丢。
    expect(settled.reason).toBe("派它去确认 /actuator 是否暴露");
    expect(settled.target).toBe("https://a.test/actuator");
  });

  it("refuses an unregistered code instead of inventing one", () => {
    expect(() => settleTask({}, { code: "made_up" as never, reason: "x", by: "control" })).toThrow(/unknown outcome code/);
  });

  it("does not write an empty evidence array", () => {
    const settled = settleTask({}, { code: "zero_entropy", reason: "连续 3 次 diff=0", by: "control" });
    expect("outcome_evidence_ids" in settled).toBe(false);
  });
});

describe("outcomeIssue", () => {
  const live = { status: "blocked", outcome_by: "control" as const };

  it("ignores tasks that are not blocked or failed", () => {
    expect(outcomeIssue({ status: "completed" })).toEqual([]);
    expect(outcomeIssue({ status: "pending" })).toEqual([]);
  });

  it("requires a code and says so as an error for new writes", () => {
    const issues = outcomeIssue({ ...live, outcome_reason: "被 403 挡住，试了 3 次" });
    expect(issues).toContainEqual(expect.objectContaining({ code: "TASK_OUTCOME_CODE_MISSING", severity: "error" }));
  });

  it("requires a human readable reason", () => {
    const issues = outcomeIssue({ ...live, outcome_code: "dead_end" });
    expect(issues).toContainEqual(expect.objectContaining({ code: "TASK_OUTCOME_MISSING", severity: "error" }));
  });

  it("rejects a bare machine code copied into outcome_reason", () => {
    const issues = outcomeIssue({ ...live, outcome_code: "focus_stalled", outcome_reason: "focus_stalled" });
    expect(issues).toContainEqual(expect.objectContaining({ code: "TASK_OUTCOME_NOT_EXPLAINED", severity: "error" }));
  });

  it("rejects a one-word reason", () => {
    const issues = outcomeIssue({ ...live, outcome_code: "dead_end", outcome_reason: "挡住了" });
    expect(issues).toContainEqual(expect.objectContaining({ code: "TASK_OUTCOME_TOO_SHORT", severity: "error" }));
  });

  it("warns when the reason has no concrete fact at all", () => {
    const issues = outcomeIssue({ ...live, outcome_code: "dead_end", outcome_reason: "这个入口没有继续打下去的必要了" });
    expect(issues).toContainEqual(expect.objectContaining({ code: "TASK_OUTCOME_NO_FACT", severity: "warning" }));
  });

  it("accepts a reason anchored on a status code, url or evidence id", () => {
    for (const reason of [
      "连续 3 次 403 之后放弃，这个入口需要 Token",
      "攻击图判死胡同：https://a.test/actuator 同特征响应反复出现",
      "零熵熔断：最后一条是 ev-624f9c3499a7e116，diff_score=0",
    ]) {
      const issues = outcomeIssue({ ...live, outcome_code: "dead_end", outcome_reason: reason });
      expect(issues.filter(i => i.severity === "error")).toEqual([]);
    }
  });

  it("flags a blocked task that cites no evidence although evidence exists", () => {
    const issues = outcomeIssue(
      { ...live, outcome_code: "budget_settled", outcome_reason: "预算到上限时还在打 /actuator" },
      { evidenceOnRecord: ["ev-1", "ev-2"] },
    );
    expect(issues).toContainEqual(expect.objectContaining({ code: "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE", severity: "error" }));
    const cited = outcomeIssue(
      { ...live, outcome_code: "budget_settled", outcome_reason: "预算到上限时还在打 /actuator", outcome_evidence_ids: ["ev-1"] },
      { evidenceOnRecord: ["ev-1", "ev-2"] },
    );
    // 引用到位后只剩"缺事实锚"这类 warning，不再有阻塞。
    expect(cited.filter(issue => issue.severity === "error")).toEqual([]);
  });

  it("keeps pre-contract checkpoints as warnings so an upgrade does not block resume", () => {
    const legacy = outcomeIssue({ status: "blocked", outcome_reason: "假设已收口，任务不再需要执行" });
    expect(legacy.every(issue => issue.severity === "warning")).toBe(true);
    expect(legacy.map(issue => issue.code)).toContain("TASK_OUTCOME_CODE_LEGACY");
    const silent = outcomeIssue({ status: "blocked" });
    expect(silent.every(issue => issue.severity === "warning")).toBe(true);
    expect(silent.map(issue => issue.code)).toContain("TASK_OUTCOME_LEGACY_MISSING");
  });
});

describe("helpers", () => {
  it("recognises machine codes and real sentences", () => {
    expect(looksLikeCode("focus_stalled")).toBe(true);
    expect(looksLikeCode("dead_end:ep:https://a.test/")).toBe(true);
    expect(looksLikeCode("连续 3 轮没有新证据，已收口")).toBe(false);
  });

  it("detects concrete facts", () => {
    expect(hasConcreteFact("没有数字")).toBe(false);
    expect(hasConcreteFact("拿到 403")).toBe(true);
    expect(hasConcreteFact("见 ev-624f9c3499a7e116")).toBe(true);
  });

  it("every registered code is lowercase snake_case", () => {
    for (const code of OUTCOME_CODES) expect(code).toMatch(/^[a-z][a-z0-9_]*$/);
  });
});

describe("autoRepairOutcomeEvidence：结案引用自动回填（2026-11-07）", () => {
  const own = (id: string, extra: Record<string, unknown> = {}) => ({
    id, kind: "tool-result", summary: "一次工具结果", data: { task_id: "T1", tool: "http.request", status: 403, ...extra },
  });

  it("理由命中关键词时只取命中的证据，不硬凑最近 3 条", () => {
    const evidence = [
      own("ev-a", { url: "/ask/1", status: 200 }),
      own("ev-b", { url: "/ecs", status: 403 }),
      own("ev-c", { url: "/lingma", status: 200 }),
    ];
    const result = autoRepairOutcomeEvidence({ reason: "ecs 路径连续 403，无法继续", taskId: "T1", evidence });
    expect(result?.matched).toBe(true);
    // "ecs" 只在 ev-b 的 url 里出现；"/ask/1" 之类不相关项不能被硬凑进来。
    expect(result?.ids).toEqual(["ev-b"]);
    expect(result?.basis).toContain("未命中项不硬凑");
  });

  it("一条都不命中才退回最近 N 条，并标成启发式待复核", () => {
    const evidence = [own("ev-a"), own("ev-b"), own("ev-c"), own("ev-d")];
    const result = autoRepairOutcomeEvidence({ reason: "外部依赖迟迟没有回应，暂时收口", taskId: "T1", evidence });
    expect(result?.matched).toBe(false);
    expect(result?.ids).toEqual(["ev-b", "ev-c", "ev-d"]);
    expect(result?.basis).toContain("启发式");
    expect(result?.basis).toContain("人工确认");
  });

  it("绝不串到别的任务的证据上", () => {
    const result = autoRepairOutcomeEvidence({
      reason: "403", taskId: "T1",
      evidence: [{ id: "ev-other", kind: "tool-result", summary: "403", data: { task_id: "T2" } }],
    });
    expect(result).toBeUndefined();
  });

  it("支持自定义上限且至少回填 1 条", () => {
    const evidence = [own("ev-a"), own("ev-b")];
    expect(autoRepairOutcomeEvidence({ reason: "随便", taskId: "T1", evidence, limit: 1 })?.ids).toEqual(["ev-b"]);
  });
});

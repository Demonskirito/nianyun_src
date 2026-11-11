/**
 * 会话完成判据（2026-11-05）。
 *
 * 事故：11 场实盘 **0 场 completed**。不是没跑完，是判据走不通——
 * 旧口径「有 blocked 任务就永远不算 tasks_completed」，而一次渗透评估几乎
 * 不可能让每个任务都成功：T2 被鉴权墙挡住、SPA 逆不出接口面，本身就是
 * 带证据的有效结论。于是一个只认「全成功」的门槛，把每场都逼成人按取消键。
 *
 * 这批用例钉住新口径：完成 = 评估收口（所有任务都有结论），
 * 但不是「把所有任务标 blocked 就算完成」（0 条 completed 仍判 blocked）——
 * 因为预算耗尽要留续跑通道，见文件末尾那条用例的注释。
 */
import { describe, expect, it } from "vitest";
import { completionVerdictOf, isCompletedVerdict } from "../src/blackbox/acceptance.js";

const tasks = (specs: Record<string, string>) =>
  Object.fromEntries(Object.entries(specs).map(([id, status]) => [id, { status }]));

describe("completionVerdictOf", () => {
  it("全部结案 → tasks_completed", () => {
    expect(completionVerdictOf(tasks({ T1: "completed", T2: "completed" }))).toBe("tasks_completed");
  });

  it("有结论也有受阻 → partial_completed（这是本次要打开的那条路）", () => {
    expect(completionVerdictOf(tasks({ T1: "completed", T2: "blocked" }))).toBe("partial_completed");
    expect(completionVerdictOf(tasks({ T1: "completed", T2: "blocked", T3: "completed" }))).toBe("partial_completed");
  });

  it("一条都没完成 → blocked，不能靠「全标 blocked」冒充完成", () => {
    expect(completionVerdictOf(tasks({ T1: "blocked", T2: "blocked" }))).toBe("blocked");
    // 写过 outcome_code、也声明过 not_reached，但一条都没做成 —— 仍然不是完成。
    // 预算耗尽不是评估完成：标成 completed 就再没有"续跑把剩下的做完"这条路了
    // （test/blackbox.test.ts 的 resume 场景钉的就是这个）。
    const concludedButNothingDone = {
      T1: { status: "blocked", outcome_code: "budget_settled" },
      T2: { status: "pending", settled: "not_reached" },
    };
    expect(completionVerdictOf(concludedButNothingDone)).toBe("blocked");
    expect(isCompletedVerdict(completionVerdictOf(concludedButNothingDone))).toBe(false);
  });

  it("有 failed → failed（执行层出错，报告不可信）", () => {
    expect(completionVerdictOf(tasks({ T1: "completed", T2: "failed" }))).toBe("failed");
    expect(completionVerdictOf(tasks({ T1: "blocked", T2: "failed" }))).toBe("failed");
  });

  it("action:<hash> 占位记录不算任务（否则永远有「未终结」）", () => {
    const withActions = {
      T1: { status: "completed" },
      "action:abc123": { status: "blocked" },
      "action:def456": { status: "blocked" },
    };
    expect(completionVerdictOf(withActions)).toBe("tasks_completed");
    // 只有占位记录、没有真任务 → 不能判完成
    expect(completionVerdictOf({ "action:abc": { status: "blocked" } })).toBe("blocked");
  });

  it("空任务簿不算完成", () => {
    expect(completionVerdictOf({})).toBe("blocked");
  });
});

describe("isCompletedVerdict", () => {
  it("partial_completed 也算完成（评估已收口）", () => {
    expect(isCompletedVerdict("tasks_completed")).toBe(true);
    expect(isCompletedVerdict("partial_completed")).toBe(true);
  });

  it("blocked / failed / paused 类原因都不算", () => {
    for (const reason of ["blocked", "failed", "operator_cancelled", "focus_stalled", "agent_turn_budget_exhausted", ""]) {
      expect(isCompletedVerdict(reason)).toBe(false);
    }
  });
});

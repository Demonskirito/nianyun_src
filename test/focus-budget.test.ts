import { describe, expect, it } from "vitest";
import { blackboxRules, blackboxRulesDiagnostics } from "../src/blackbox/rules.js";
import { focusView } from "../src/blackbox/focus.js";
import { checkpointView } from "../src/blackbox/context.js";
import { chargeFocusRound, recordFocusCost, recordFocusValue, type FocusLimits } from "../src/blackbox/focus-budget.js";
import { scoreIngest } from "../src/blackbox/evidence-value.js";
import type { RunCheckpoint } from "../src/blackbox/progress.js";

const limits: FocusLimits = {
  max_turns_per_task: 8, max_tp_per_task: 50, stall_rounds: 3, appeal_pool: 1, max_session_convergences: 5,
};

function state(): RunCheckpoint {
  return {
    tasks: { T1: { status: "pending", target: "http://a.test/", purpose: "探" } },
    graph: { nodes: {}, edges: {} },
    focus_task_id: "T1",
    usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
  } as unknown as RunCheckpoint;
}

describe("焦点预算的上下文投影", () => {
  it("把轮数 / TP / 增益 / 停滞都投影给模型", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    recordFocusCost(s, "T1", { calls: 3, tp: 12 });
    recordFocusValue(s, "T1", scoreIngest({ newNodes: ["ep:http://a.test/x"], newEdges: [], deadEnds: [] }));
    chargeFocusRound(s, "T1", limits);
    const view = focusView(s) as {
      current_focus_task_id: string;
      budget: { turns: number; max_turns: number; tp: number; max_tp: number; value_score: number; high_value: number; noise: number; appeals_used: number };
      directive: string;
    };
    expect(view.current_focus_task_id).toBe("T1");
    expect(view.budget.turns).toBe(2);
    expect(view.budget.max_turns).toBe(8);
    expect(view.budget.tp).toBe(12);
    expect(view.budget.max_tp).toBe(50);
    expect(view.budget.value_score).toBe(3);
    expect(view.budget.high_value).toBe(1);
    expect(view.budget.appeals_used).toBe(0);
    expect(view.directive).toContain("执行纪律");
  });

  it("收口时把指令换成【强制收口】，申诉后换成【预算警告】", () => {
    const s = state();
    chargeFocusRound(s, "T1", { ...limits, max_turns_per_task: 1 });
    const charged = chargeFocusRound(s, "T1", { ...limits, max_turns_per_task: 1 });
    expect(charged.convergence?.text).toContain("【强制收口】");
    s.focus_convergence = charged.convergence;
    expect(String((focusView(s) as { directive: string }).directive)).toContain("【强制收口】");
    s.focus_convergence = { ...charged.convergence!, appealed: true, text: "【预算警告】宽限一轮" };
    expect(String((focusView(s) as { directive: string }).directive)).toContain("【预算警告】");
  });

  it("宏观熔断的指令压过收口指令", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    const charged = chargeFocusRound(s, "T1", { ...limits, max_turns_per_task: 1 });
    s.focus_convergence = charged.convergence;
    s.macro_interrupt = { count: 5, limit: 5, text: "【宏观战略调整】停手", at: Date.now() };
    expect(String((focusView(s) as { directive: string }).directive)).toContain("【宏观战略调整】");
  });

  it("没有未结案任务时也不丢熔断指令", () => {
    const s = state();
    s.tasks = {};
    s.macro_interrupt = { count: 5, limit: 5, text: "【宏观战略调整】停手", at: Date.now() };
    expect(String((focusView(s) as { directive: string }).directive)).toContain("【宏观战略调整】");
  });

  it("焦点块进入系统上下文（预算不会被裁掉）", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    recordFocusCost(s, "T1", { calls: 1, tp: 5 });
    const focusLock = focusView(s) as { budget?: { tp: number; max_tp: number } };
    expect(focusLock.budget?.tp).toBe(5);
    const view = checkpointView(s as unknown as Record<string, unknown>, focusLock as Record<string, unknown>);
    expect(view.current_focus_task_id).toBe("T1");
  });
});

describe("焦点预算的规则解析", () => {
  it("默认值：8 轮 / 50 TP / 5 轮无增益 / 3 次全局申诉 / 不熔断", () => {
    const rules = blackboxRules({});
    expect(rules.focus_lock).toMatchObject({
      on: true, max_turns_per_task: 8, max_tp_per_task: 50, stall_rounds: 5, appeal_pool: 3, appeal_potential_max: 6, max_session_convergences: 0,
    });
    // 上限 0 = 不限（消费端只在 > 0 时拦）。整场熔断不可逆，是所有限制的公约数，默认不再开。
    expect(rules.focus_lock.max_session_convergences).toBe(0);
    // 旧的"按次数记账"已被 TP 取代
    expect("max_tool_calls_per_task" in rules.focus_lock).toBe(false);
  });

  it("规则文档里的 focus_lock 生效（不是未知段），非法值落默认并报出来", () => {
    const values = { BLACKBOX_RULES_DOCUMENT: JSON.stringify({ focus_lock: { max_turns_per_task: 3, max_tp_per_task: 12, appeal_pool: 0 } }) };
    const rules = blackboxRules(values);
    expect(rules.focus_lock.max_turns_per_task).toBe(3);
    expect(rules.focus_lock.max_tp_per_task).toBe(12);
    expect(rules.focus_lock.appeal_pool).toBe(0);
    expect(blackboxRulesDiagnostics(values).issues.join(" ")).not.toContain("focus_lock");

    const bad = blackboxRules({ BLACKBOX_RULES_DOCUMENT: JSON.stringify({ focus_lock: { max_tp_per_task: "many" } }) });
    expect(bad.focus_lock.max_tp_per_task).toBe(50);
  });
});
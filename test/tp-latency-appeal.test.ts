import { describe, expect, it } from "vitest";
import {
  LATENCY_BASE_MS, LATENCY_MAX_MULTIPLIER, batchTp, latencyMultiplier, tpCost, updateLatency,
} from "../src/blackbox/tool-cost.js";
import {
  appealPoolLeft, appealText, appealWorthy, criticalSignal, emptyUsage, macroInterruptText,
  recordFocusValue, resetFocusUsage, spendAppeal, type FocusLimits,
} from "../src/blackbox/focus-budget.js";
import type { RunCheckpoint } from "../src/blackbox/progress.js";

const limits: FocusLimits = {
  max_turns_per_task: 8, max_tp_per_task: 50, stall_rounds: 3,
  appeal_pool: 3, appeal_potential_max: 6, max_session_convergences: 5,
};

function checkpoint(): RunCheckpoint {
  return { version: 1, tasks: {}, usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 } } as RunCheckpoint;
}

describe("TP 自适应通胀（EWMA）", () => {
  it("基准延迟以内不打折、不涨价", () => {
    expect(latencyMultiplier(undefined)).toBe(1);
    expect(latencyMultiplier(0)).toBe(1);
    expect(latencyMultiplier(LATENCY_BASE_MS)).toBe(1);
    expect(tpCost("http.request", 0, 400)).toBe(1);
  });

  it("慢目标按比例涨价，且封顶 3×", () => {
    expect(latencyMultiplier(1500)).toBe(3);
    expect(tpCost("http.request", 0, 1500)).toBe(3);
    expect(latencyMultiplier(9000)).toBe(LATENCY_MAX_MULTIPLIER);
    expect(tpCost("browser.open", 0, 9000)).toBe(12);  // 4 × 3 = 12（正好撞单次封顶）
    expect(tpCost("recon.nuclei", 0, 9000)).toBe(12);  // 5 × 3 = 15 → 封顶 12
  });

  it("一批请求的预检也吃通胀：3 个 http 探针在 3 秒延迟下要 9 TP", () => {
    const batch = [{ tool: "http.request" }, { tool: "http.request" }, { tool: "http.request" }];
    expect(batchTp(batch)).toBe(3);
    expect(batchTp(batch, 3000)).toBe(9);
  });

  it("EWMA 平滑：一次慢请求不会立刻把价目表打翻", () => {
    expect(updateLatency(undefined, 800)).toBe(800);
    expect(updateLatency(800, 800)).toBe(800);
    // 800 之后来一条 3000ms：0.7×800 + 0.3×3000 = 1460
    expect(updateLatency(800, 3000)).toBe(1460);
    expect(latencyMultiplier(1460)).toBeCloseTo(2.92, 1);
    expect(updateLatency(100, 0)).toBe(100);
  });
});

describe("全局申诉池 + 价值门槛", () => {
  it("池子初始为上限，消耗递减，耗尽后拒绝", () => {
    const state = checkpoint();
    expect(appealPoolLeft(state, limits)).toBe(3);
    expect(spendAppeal(state, limits)).toBe(true);
    expect(appealPoolLeft(state, limits)).toBe(2);
    expect(spendAppeal(state, limits)).toBe(true);
    expect(spendAppeal(state, limits)).toBe(true);
    expect(spendAppeal(state, limits)).toBe(false);
    expect(appealPoolLeft(state, limits)).toBe(0);
  });

  it("只有接近核心的任务才配申诉：身份 > 势能门槛 > 高价值证据", () => {
    const usage = emptyUsage("T1", limits);
    const hot = appealWorthy({ state: { focus_usage: usage, appealPotentialMax: 6 }, potential: 3.5 });
    expect(hot.ok).toBe(true);
    expect(hot.why).toContain("拓扑势能");
    expect(appealWorthy({ state: { focus_usage: usage, appealPotentialMax: 6 }, potential: 12 }).ok).toBe(false);
    expect(appealWorthy({ state: { focus_usage: usage, appealPotentialMax: 6 }, identity: true }).ok).toBe(true);

    const edge = emptyUsage("T2", limits);
    edge.value_score = 0;
    expect(appealWorthy({ state: { focus_usage: edge, appealPotentialMax: 6 }, potential: undefined }).ok).toBe(false);

    const rich = emptyUsage("T3", limits);
    rich.value_score = 3;
    expect(appealWorthy({ state: { focus_usage: rich, appealPotentialMax: 6 }, potential: 40 }).ok).toBe(true);
  });

  it("边缘任务的弱信号不构成临界信号，也不消耗池子", () => {
    const state = checkpoint();
    const usage = emptyUsage("T9", limits);
    state.focus_usage = usage;
    recordFocusValue(state, "T9", {
      score: 1, tier: 1, high: 0, medium: 1, noise: 0, reasons: ["+1 普通响应"], critical: {},
    });
    expect(criticalSignal(state, "T9")).toBeUndefined();

    const denied = appealWorthy({ state: { focus_usage: usage, appealPotentialMax: 6 }, potential: 30 });
    expect(denied.ok).toBe(false);
    expect(denied.why).toContain("边缘");
    expect(appealPoolLeft(state, limits)).toBe(3);   // 没扣额度
  });

  it("申诉文案带池子余量与门槛理由", () => {
    const text = appealText(emptyUsage("T1", limits), "新身份 id:role=user（已掌握身份凭证）", "focus_budget_exhausted", 2);
    expect(text).toContain("全局申诉池剩余 2 次");
    expect(text).toContain("关键路径");
    expect(macroInterruptText(5, 5)).toContain("宏观战略调整");
  });

  it("切焦点清空任务级记账，但全局池不动", () => {
    const state = checkpoint();
    spendAppeal(state, limits);
    state.usage = { ...state.usage!, session_appeals_pool: 2 };
    state.focus_usage = emptyUsage("T1", limits);
    recordFocusValue(state, "T1", { score: 3, tier: 3, high: 1, medium: 0, noise: 0, reasons: ["+3"], critical: {} });
    expect(state.focus_usage?.value_score).toBe(3);
    resetFocusUsage(state, "T2");
    expect(state.focus_usage).toBeUndefined();          // 任务级记账清空，新焦点从零开始
    expect(state.usage?.session_appeals_pool).toBe(2);   // 全局池是会话资产，不随焦点走
  });
});
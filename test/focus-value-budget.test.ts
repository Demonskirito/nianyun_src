import { describe, expect, it } from "vitest";
import { batchTp, DEFAULT_TP, MAX_TP_PER_CALL, tpCost, toolTpTable, TOOL_TP } from "../src/blackbox/tool-cost.js";
import { emptyValue, looksCatchAll, mergeValue, scoreIngest, valueLine } from "../src/blackbox/evidence-value.js";
import {
  appealText, chargeFocusRound, criticalSignal, emptyUsage, macroInterruptText, recordFocusCost, recordFocusValue, resetFocusUsage, tpOverBudget,
  type FocusLimits,
} from "../src/blackbox/focus-budget.js";
import type { RunCheckpoint } from "../src/blackbox/progress.js";

const limits: FocusLimits = {
  max_turns_per_task: 8, max_tp_per_task: 50, stall_rounds: 3, appeals_per_task: 1, max_session_convergences: 5,
};

function state(): RunCheckpoint {
  return {
    tasks: { T1: { status: "pending", target: "http://a.test/", purpose: "探" }, T2: { status: "pending", target: "http://b.test/" } },
    graph: { nodes: {}, edges: {} },
    usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
  } as unknown as RunCheckpoint;
}

describe("tactical points", () => {
  it("charges by cost, not by call count", () => {
    expect(tpCost("http.request")).toBe(1);
    expect(tpCost("exec.bash")).toBe(3);
    expect(tpCost("browser.open")).toBe(4);
    expect(tpCost("recon.nuclei")).toBe(5);
    expect(tpCost("unknown.tool")).toBe(DEFAULT_TP);
  });

  it("adds a surcharge per minute of runtime", () => {
    expect(tpCost("recon.nuclei", 30_000)).toBe(5);
    expect(tpCost("recon.nuclei", 180_000)).toBe(8);
    // 单次封顶：一条 40 分钟的工具调用不该一次性打穿整条预算。
    expect(tpCost("recon.nuclei", 40 * 60_000)).toBe(MAX_TP_PER_CALL);
  });

  it("sums a batch", () => {
    expect(batchTp([{ tool: "http.request" }, { tool: "recon.nuclei" }, { tool: "browser.open" }])).toBe(10);
  });

  it("exposes a readable price table", () => {
    const table = toolTpTable();
    expect(table[0]).toEqual({ tool: "http.request", tp: 1 });
    expect(Object.keys(TOOL_TP).length).toBe(table.length);
  });
});

describe("evidence value tiering", () => {
  it("scores a new endpoint as high value", () => {
    const value = scoreIngest({ newNodes: ["ep:http://a.test/api/user"], newEdges: ["ep:http://a.test->ep:http://a.test/api/user"], deadEnds: [] });
    expect(value.tier).toBe(3);
    expect(value.score).toBe(3);
    expect(value.reasons[0]).toContain("新端点");
  });

  it("keeps repeated 404s at zero", () => {
    const value = scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], repeated: true });
    expect(value.tier).toBe(0);
    expect(value.score).toBe(0);
    expect(value.noise).toBe(1);
  });

  it("treats catch-all endpoints as noise instead of discovery", () => {
    const value = scoreIngest({
      newNodes: ["ep:http://a.test/random-123"], newEdges: [], deadEnds: [],
      before: { status: "untested", code: 200, content_length: 512, content_type: "text/html" },
      after: { status: "untested", code: 200, content_length: 512, content_type: "text/html" },
    });
    expect(value.tier).toBe(0);
    expect(value.noise).toBeGreaterThan(0);
    expect(value.reasons.join(" ")).toContain("catch-all");
  });

  it("counts a status transition and a body-size jump as medium value", () => {
    const value = scoreIngest({
      newNodes: [], newEdges: ["x"], deadEnds: [],
      before: { status: "untested", code: 200, content_length: 1000 },
      after: { status: "untested", code: 403, content_length: 400 },
    });
    expect(value.tier).toBe(1);
    expect(value.medium).toBeGreaterThanOrEqual(2);
  });

  it("reads Set-Cookie and Location as critical signals", () => {
    const value = scoreIngest({
      newNodes: [], newEdges: [], deadEnds: [],
      headers: { "set-cookie": "sid=abc; HttpOnly", Location: "/admin" },
    });
    expect(value.critical.identity).toBe("set-cookie");
    expect(value.critical.redirect).toBe("/admin");
    expect(value.score).toBeGreaterThan(0);
  });

  it("假设计分只认「转成任务」的条数：95 条池推导不再给焦点预算续命（2026-11-07）", () => {
    const pooled = scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], newHypotheses: 95 });
    expect(pooled.medium).toBe(0);
    expect(pooled.score).toBe(0);
    expect(pooled.critical.hypothesis).toBeUndefined();
    expect(pooled.reasons.join(" ")).toContain("未转成任务");

    const tasked = scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], newHypothesisTasks: 8 });
    expect(tasked.medium).toBe(1);
    expect(tasked.score).toBeGreaterThan(0);
    // critical 只留给 comparison-diff 那种真定性信号，不再由计数触发。
    expect(tasked.critical.hypothesis).toBeUndefined();
    expect(tasked.reasons.join(" ")).toContain("新假设任务 8 条");
  });

  it("detects catch-all shape", () => {
    expect(looksCatchAll({ status: 200, contentLength: 10, contentType: "text/html", baseline: { status: 200, content_length: 10, content_type: "text/html" } })).toBe(true);
    expect(looksCatchAll({ status: 200, contentLength: 11, contentType: "text/html", baseline: { status: 200, content_length: 10, content_type: "text/html" } })).toBe(false);
    expect(looksCatchAll({ status: 200 })).toBe(false);
  });

  it("merges and formats", () => {
    const merged = mergeValue(
      scoreIngest({ newNodes: ["param:x"], newEdges: [], deadEnds: [] }),
      scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], repeated: true }),
    );
    expect(merged.tier).toBe(3);
    expect(merged.score).toBe(3);
    expect(merged.noise).toBe(1);
    expect(valueLine(merged)).toContain("证据增益 +3");
    expect(valueLine(emptyValue())).toContain("+0");
  });
});

describe("focus budget on value + tp", () => {
  it("does not reset the stall counter when nothing valuable was found", () => {
    const s = state();
    const first = chargeFocusRound(s, "T1", limits);
    expect(first.usage.turns).toBe(1);
    recordFocusCost(s, "T1", { calls: 2, tp: 6 });
    recordFocusValue(s, "T1", scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], repeated: true }));
    const second = chargeFocusRound(s, "T1", limits);
    expect(second.usage.no_progress_rounds).toBe(1);
    expect(second.usage.value_score).toBe(0);
  });

  it("resets the stall counter once a high-value finding lands", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    recordFocusValue(s, "T1", scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], repeated: true }));
    chargeFocusRound(s, "T1", limits);
    expect(s.focus_usage!.no_progress_rounds).toBe(1);
    recordFocusValue(s, "T1", scoreIngest({ newNodes: ["ep:http://a.test/x"], newEdges: [], deadEnds: [] }));
    const next = chargeFocusRound(s, "T1", limits);
    expect(next.usage.no_progress_rounds).toBe(0);
    expect(next.usage.value_score).toBe(3);
    expect(next.convergence).toBeUndefined();
  });

  it("converges on stall after three flat rounds", () => {
    const s = state();
    let convergence;
    // 第 4 次准入才判死：进入本轮之前已经平了 3 轮（turns=1 的那轮不算停滞）。
    for (let round = 1; round <= 4; round += 1) {
      const result = chargeFocusRound(s, "T1", limits);
      convergence = result.convergence || convergence;
      recordFocusValue(s, "T1", scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], repeated: true }));
      recordFocusCost(s, "T1", { calls: 1, tp: 1 });
    }
    expect(convergence?.reason).toBe("focus_stalled");
    expect(convergence?.text).toContain("【强制收口】");
    // 收口不再只是"标 blocked"，而是要模型对当前任务下结案 verdict（有洞→finding，无洞→带证据引用的负面结案）。
    expect(convergence?.text).toContain("结案 verdict");
    expect(convergence?.text).toContain("task_outcomes");
  });

  it("converges on the TP cap even while finding things", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    recordFocusCost(s, "T1", { calls: 10, tp: 50 });
    const next = chargeFocusRound(s, "T1", limits);
    expect(next.convergence?.reason).toBe("focus_budget_exhausted");
    expect(next.convergence?.detail).toContain("TP");
  });

  it("refuses a batch that does not fit the remaining TP", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    recordFocusCost(s, "T1", { calls: 3, tp: 45 });
    expect(tpOverBudget(s, "T1", tpCost("recon.nuclei"), limits)).toBe(true);
    expect(tpOverBudget(s, "T1", tpCost("http.request"), limits)).toBe(false);
    // 别的任务不受这条账影响
    expect(tpOverBudget(s, "T2", 99, limits)).toBe(false);
  });

  it("keeps the turn cap independent of TP", () => {
    const s = state();
    let convergence;
    for (let round = 1; round <= 9; round += 1) {
      const result = chargeFocusRound(s, "T1", { ...limits, max_tp_per_task: 0, stall_rounds: 0 });
      convergence = result.convergence || convergence;
      recordFocusValue(s, "T1", scoreIngest({ newNodes: [`param:p${round}`], newEdges: [], deadEnds: [] }));
    }
    expect(convergence?.reason).toBe("focus_budget_exhausted");
    expect(convergence?.detail).toContain("轮");
  });

  it("treats 0 as unlimited and resets when the focus moves", () => {
    const s = state();
    chargeFocusRound(s, "T1", { ...limits, max_turns_per_task: 0, max_tp_per_task: 0, stall_rounds: 0 });
    recordFocusCost(s, "T1", { calls: 99, tp: 999 });
    expect(chargeFocusRound(s, "T1", { ...limits, max_turns_per_task: 0, max_tp_per_task: 0, stall_rounds: 0 }).convergence).toBeUndefined();
    const moved = chargeFocusRound(s, "T2", limits);
    expect(moved.usage.task_id).toBe("T2");
    expect(moved.usage.turns).toBe(1);
    expect(moved.usage.tp).toBe(0);
  });

  it("surfaces critical signals for the appeal channel", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    expect(criticalSignal(s, "T1")).toBeUndefined();
    recordFocusValue(s, "T1", scoreIngest({ newNodes: [], newEdges: [], deadEnds: [], headers: { "set-cookie": "sid=1" } }));
    expect(criticalSignal(s, "T1")).toContain("set-cookie");
    expect(appealText(s.focus_usage!, "新身份 tok", "focus_stalled")).toContain("【预算警告】");
    expect(macroInterruptText(5, 5)).toContain("【宏观战略调整】");
  });

  it("clears usage when the focus is released", () => {
    const s = state();
    chargeFocusRound(s, "T1", limits);
    resetFocusUsage(s, "T1");
    expect(s.focus_usage?.task_id).toBe("T1");
    resetFocusUsage(s);
    expect(s.focus_usage).toBeUndefined();
    expect(emptyUsage("T9", limits).max_tp).toBe(50);
  });
});
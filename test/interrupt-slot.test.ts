import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";

/**
 * 插话池的淘汰顺序（2026-11-09，P1）。
 *
 * 现场病灶：`graph-signal` 15 分钟写了 7 条，其中两条正文完全相同（301 字符、同一批 roots）。
 * 根因不在指纹，而在池子只有 12 格：`focus-auto-handoff:${round}` / `zero-action:${round}`
 * 这类一次性 id 每轮新增一条，把 `graph:*` 的长期欠账挤出去；下一轮欠账重新插入，
 * `addInterrupts` 就返回 `added=1`，事件门禁据此又写一条。
 *
 * 这组测试锁住两件事：
 * ① 超限时**已确认的**插话先出局，未确认的欠账优先保留；
 * ② 全都未确认时仍按新旧截断（不能让池子无限长）。
 */

const push = (progress: BlackboxProgress, id: string, text = `插话 ${id}`): number =>
  progress.addInterrupts([{ id, kind: "advice", severity: "high", text }]);

describe("插话池 12 格：先淘汰已确认的", () => {
  it("已读的噪声被挤掉，未读的 graph 欠账留下", () => {
    const progress = new BlackboxProgress();
    for (let index = 0; index < 11; index += 1) push(progress, `noise:${index}`);
    // 第一轮全部被模型看到并确认。
    expect(progress.takeInterrupts()).toHaveLength(11);

    // 巡检的欠账（未确认）压在最后。
    push(progress, "graph:component_drift:component_drift");
    expect((progress.state.interrupts || []).length).toBe(12);

    // 新的一条噪声进来，池子溢出。
    push(progress, "focus-auto-handoff:T_X");

    const ids = (progress.state.interrupts || []).map(item => item.id);
    expect(ids).toHaveLength(12);
    expect(ids).toContain("graph:component_drift:component_drift");
    expect(ids).toContain("focus-auto-handoff:T_X");
    // 最老的已确认噪声出局。
    expect(ids).not.toContain("noise:0");
    // 未确认的欠账不能被新噪声顶掉。
    expect((progress.state.interrupts || []).find(item => item.id.startsWith("graph:"))?.acknowledged).toBeFalsy();
  });

  it("全部未确认时仍按新旧截断", () => {
    const progress = new BlackboxProgress();
    push(progress, "graph:component_drift:component_drift");
    for (let index = 0; index < 11; index += 1) push(progress, `noise:${index}`);
    push(progress, "noise:last");

    const ids = (progress.state.interrupts || []).map(item => item.id);
    expect(ids).toHaveLength(12);
    expect(ids).not.toContain("graph:component_drift:component_drift");
    expect(ids).toContain("noise:last");
  });

  it("指纹不变时只累加 repeats，正文原地刷新，不算新增", () => {
    const progress = new BlackboxProgress();
    const first = progress.addInterrupts([{
      id: "graph:component_drift:component_drift", kind: "component_drift", severity: "medium",
      text: "图裂成 62 块", fingerprint: "component_drift:https://t.example/a",
    }]);
    expect(first).toBe(1);

    const second = progress.addInterrupts([{
      id: "graph:component_drift:component_drift", kind: "component_drift", severity: "medium",
      text: "图裂成 63 块", fingerprint: "component_drift:https://t.example/a",
    }]);
    expect(second).toBe(0);
    const entry = (progress.state.interrupts || [])[0];
    expect(entry.repeats).toBe(2);
    expect(entry.text).toBe("图裂成 63 块");
  });

  it("恢复老检查点时丢掉旧格式的轮次 id", () => {
    const progress = new BlackboxProgress({
      version: 1, tasks: {}, actions: {}, seenResults: [], stalledBatches: 0,
      usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0, toolMs: 0 },
      interrupts: [
        { id: "focus-auto-handoff:7", kind: "focus_auto_handoff", severity: "high", text: "旧", at: 1 },
        { id: "focus-auto-handoff:14", kind: "focus_auto_handoff", severity: "high", text: "旧", at: 2 },
        { id: "zero-action:3", kind: "zero_action", severity: "high", text: "旧", at: 3 },
        { id: "focus-redirect:1", kind: "focus_redirect", severity: "medium", text: "旧", at: 4 },
        { id: "focus-auto-handoff:T_GRAPH_DRIFT_ROOTS_abc", kind: "focus_auto_handoff", severity: "high", text: "新", at: 5 },
        { id: "graph:component_drift:component_drift", kind: "component_drift", severity: "medium", text: "欠账", at: 6 },
      ],
    });
    const ids = (progress.state.interrupts || []).map(item => item.id);
    expect(ids).toEqual([
      "focus-auto-handoff:T_GRAPH_DRIFT_ROOTS_abc",
      "graph:component_drift:component_drift",
    ]);
  });
});

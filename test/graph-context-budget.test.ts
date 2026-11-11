import { describe, expect, it } from "vitest";
import { MAX_NODES, graphState } from "../src/blackbox/graph/builder.js";
import type { GraphNode, NodeStatus } from "../src/blackbox/graph/types.js";
import { boundedContext } from "../src/blackbox/context.js";

/**
 * 图视图预算（2026-11-08）。
 *
 * 线上实测：500 节点图的 60 节点投影是 22221 字符，而 `bounded()` 对 object 超限的处理是
 * **整块替换成 `{omitted:true}`** —— 模型在整个会话里从未看到过攻击图。
 *
 * 这组测试锁两件事：
 *   1. 大图投影必须**降级**（保留节点/假设/counts），绝不能整体 omitted；
 *   2. 上限提到 1500 后，节点数不裁剪到 500 就不再触发 prune。
 */

function node(id: string, status: NodeStatus, updatedAt: number): GraphNode {
  return {
    id, type: "endpoint", status,
    properties: { hits: 1 }, discovered_by: "test", updated_at: updatedAt,
  };
}

/**
 * 构造 n 个端点节点的图：id 长度与线上 `ep:host/document/<长段>/{id}` 一致，用来压真实字符预算。
 *
 * 全部 `untested`（同一 rank）→ 视图按 updated_at 降序取前 N，保留的是"最近更新的一批"，
 * 在链式图里是连续区间，因此边的两端往往都在保留集内，可以稳定验证"边不悬空"。
 */
function bigGraph(count: number) {
  const state = graphState(undefined);
  const longPart = "x".repeat(48);
  const idOf = (i: number): string => `ep:next.api.aliyun.com/document/${longPart}/service-${i}/detail/{id}`;
  for (let i = 0; i < count; i++) {
    const id = idOf(i);
    state.nodes[id] = node(id, "untested", 1_700_000_000_000 + i);
  }
  state.edges = Array.from({ length: Math.max(0, count - 1) }, (_, i) => ({
    id: `e${i}`,
    source_id: idOf(i),
    target_id: idOf(i + 1),
    type: "calls_api" as const,
    properties: {},
    weight: 1,
  }));
  return state;
}

function contextOf(graph: ReturnType<typeof bigGraph>) {
  const session = {
    id: "s1", target: "https://next.api.aliyun.com/", status: "running", phase: "explore",
    cookie_count: 0, cookies: [], checkpoint: { graph },
  };
  const view = boundedContext(session, {}) as Record<string, unknown>;
  return view.attack_graph as Record<string, unknown>;
}

describe("图视图预算：装不下要降级，不能整体 omitted", () => {
  it("500 节点图的投影不再是 {omitted:true}，且节点仍在", () => {
    const view = contextOf(bigGraph(500));

    expect(view.omitted).toBeUndefined();
    expect(Array.isArray(view.nodes)).toBe(true);
    expect((view.nodes as unknown[]).length).toBeGreaterThan(0);
    // 保底字段必须留下：模型据此判断"图有多大、被裁了多少"
    expect((view.counts as { nodes?: number }).nodes).toBe(500);
    expect((view.truncated as { nodes?: number }).nodes).toBeGreaterThan(0);
  });

  it("超出预算的图走硬截断：字符数受控、标记 hard_limited", () => {
    const view = contextOf(bigGraph(1200));

    expect(view.omitted).toBeUndefined();
    expect(JSON.stringify(view).length).toBeLessThanOrEqual(10000);
    expect((view.truncated as { hard_limited?: boolean }).hard_limited).toBe(true);
    // 截断后仍有足够的节点可供换面，不是退化成 1~2 个
    expect((view.nodes as unknown[]).length).toBeGreaterThanOrEqual(20);
    expect((view.counts as { nodes?: number }).nodes).toBe(1200);
  });

  it("图很小时不打 hard_limited 标记（避免误报被裁剪）", () => {
    const view = contextOf(bigGraph(20));
    expect(view.omitted).toBeUndefined();
    expect((view.truncated as { hard_limited?: boolean }).hard_limited).toBeUndefined();
    expect((view.nodes as unknown[]).length).toBe(20);
  });

  it("被截断时边不会指向已被裁掉的节点", () => {
    const view = contextOf(bigGraph(1200));
    const kept = new Set((view.nodes as Array<{ id: string }>).map(item => item.id));
    expect((view.edges as unknown[]).length).toBeGreaterThan(0);
    for (const edge of view.edges as Array<{ from: string; to: string }>) {
      expect(kept.has(edge.from)).toBe(true);
      expect(kept.has(edge.to)).toBe(true);
    }
  });
});

describe("节点上限提到 1500", () => {
  it("上限是 1500（500 会在 306 次工具调用后封顶，把未打过的端点淘汰掉）", () => {
    expect(MAX_NODES).toBe(1500);
  });
});

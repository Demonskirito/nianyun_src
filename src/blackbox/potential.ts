import type { AttackGraphState, GraphNode } from "./graph/types.js";
import { dynamicPenalty, highValueTargets } from "./graph/pathfind.js";
import { activeHypotheses } from "./graph/hypotheses.js";

/**
 * 拓扑势能：从"发现了什么"升级到"离核心目标近了没有"。
 *
 * 结构增益（§39）会把 10 个静态页当 10 次发现，因为每个新端点都是 +3。判断"值不值"的真正依据是
 * 全局寻路视角：这个发现有没有让"当前节点 → 高价值目标"的最短路径变短。
 *
 * 实现方式：从所有目标（vuln_state / vulnerable 端点 / 活跃假设 / 高价值目标）出发做一次**多源反向**
 * Dijkstra（图按无向处理，因为攻击图里的边大多是单向发现的，单向寻路会把"我在终点"当成"我够不到"），
 * 得到每个节点到最近目标的成本。成本越低 = 势能越高。
 *
 * 只在图刚变化时算一次（调用方保证），复杂度与一次 planRoutes 同级。
 */

/** 势能目标：漏洞态、已判 vulnerable 的端点、活跃假设、以及 pathfind 认定的高价值端点。 */
export function potentialGoals(graph: AttackGraphState): string[] {
  const goals = new Set<string>(highValueTargets(graph));
  for (const node of Object.values(graph.nodes)) {
    if (node.type === "vuln_state") goals.add(node.id);
    if (node.type === "endpoint" && node.status === "vulnerable") goals.add(node.id);
  }
  // 活跃假设也是"值得逼近的目标"：它们是系统推出来的"这里可能打得动"。
  for (const hypothesis of activeHypotheses(graph as never)) {
    for (const id of hypothesis.nodes || []) if (graph.nodes[id]) goals.add(id);
  }
  return [...goals];
}

type Adjacency = Map<string, Array<{ to: string; cost: number }>>;

/** 无向邻接表 + 动态罚分（被拦过的节点更贵），与 planRoutes 用同一套代价语义。 */
function adjacency(graph: AttackGraphState, now: number): Adjacency {
  const map: Adjacency = new Map();
  const push = (from: string, to: string, cost: number) => {
    const list = map.get(from) || [];
    list.push({ to, cost });
    map.set(from, list);
  };
  for (const edge of Object.values(graph.edges)) {
    if (!graph.nodes[edge.source_id] || !graph.nodes[edge.target_id]) continue;
    const cost = Math.max(0.1, Number(edge.weight || 1)) * (1 + dynamicPenalty(graph, edge.target_id, now));
    push(edge.source_id, edge.target_id, cost);
    // 反向复制：asset → endpoint 这类单向发现边也要能用来"往回退一步"评估距离。
    push(edge.target_id, edge.source_id, cost);
  }
  return map;
}

/**
 * 多源 Dijkstra：目标们作为起点，反向扩散到整张图。
 *
 * 返回 `nodeId → 到最近高价值目标的最短成本`；不可达的节点不出现在表里。
 */
export function potentialMap(graph: AttackGraphState, options: { now?: number; maxDepth?: number } = {}): Map<string, number> {
  const now = options.now ?? Date.now();
  const maxDepth = options.maxDepth ?? 12;
  const goals = potentialGoals(graph);
  const result = new Map<string, number>();
  if (!goals.length) return result;
  const adj = adjacency(graph, now);
  // 简单二叉堆不够用的场景很少（<500 节点），这里用有序数组即可，省一个依赖。
  const queue: Array<{ id: string; cost: number; depth: number }> = goals.map(id => ({ id, cost: 0, depth: 0 }));
  for (const goal of goals) result.set(goal, 0);
  while (queue.length) {
    queue.sort((a, b) => a.cost - b.cost);
    const current = queue.shift()!;
    if (current.depth >= maxDepth) continue;
    const known = result.get(current.id);
    if (known !== undefined && known < current.cost) continue;
    for (const next of adj.get(current.id) || []) {
      if (!graph.nodes[next.to]) continue;
      const cost = current.cost + next.cost;
      const previous = result.get(next.to);
      if (previous !== undefined && previous <= cost) continue;
      result.set(next.to, cost);
      queue.push({ id: next.to, cost, depth: current.depth + 1 });
    }
  }
  return result;
}

/** 单点势能：节点到最近目标的成本（不可达 = undefined，代表"这条路根本不通"）。 */
export function potentialOf(graph: AttackGraphState, nodeId: string, options: { now?: number } = {}): number | undefined {
  if (!nodeId || !graph.nodes[nodeId]) return undefined;
  return potentialMap(graph, options).get(nodeId);
}

/** 整图最低势能成本（用于判断"全场还有没有希望"）。 */
export function bestPotential(graph: AttackGraphState, options: { now?: number } = {}): number | undefined {
  const map = potentialMap(graph, options);
  if (!map.size) return undefined;
  let min: number | undefined;
  for (const cost of map.values()) if (min === undefined || cost < min) min = cost;
  return min;
}

export type PotentialDelta = {
  before?: number;
  after?: number;
  /** 正数 = 势能提升（成本下降），负数 = 变差，0 = 没动。 */
  delta: number;
  improved: boolean;
  reason: string;
};

/** 两次势能快照对比。只有明显下降（>0.05）才算提升，避免浮点抖动刷分。 */
export function potentialDelta(before: number | undefined, after: number | undefined): PotentialDelta {
  if (before === undefined && after === undefined) return { delta: 0, improved: false, reason: "无可达目标，势能不可测" };
  if (before === undefined && after !== undefined) return { before, after, delta: 1, improved: true, reason: `首次打通到目标的路径（成本 ${round(after)}）` };
  if (before !== undefined && after === undefined) return { before, after, delta: -before, improved: false, reason: "原本可达的路径被切断" };
  const delta = Number(before) - Number(after);
  if (delta > 0.05) return { before, after, delta, improved: true, reason: `最短路径成本 ${round(before!)} → ${round(after!)}` };
  if (delta < -0.05) return { before, after, delta, improved: false, reason: `最短路径成本变差 ${round(before!)} → ${round(after!)}` };
  return { before, after, delta: 0, improved: false, reason: `最短路径成本不变（${round(after!)}）` };
}

function round(value: number): number {
  return Math.round(value * 10) / 10;
}

/** 势能视图：给上下文/控制台用（目标数、最优成本、焦点节点势能）。 */
export function potentialView(graph: AttackGraphState, nodeId?: string): { goals: number; best?: number; focus?: number; focus_node?: string } {
  const map = potentialMap(graph);
  const focusNode = nodeId && graph.nodes[nodeId] ? nodeId : undefined;
  return {
    goals: potentialGoals(graph).length,
    ...(map.size ? { best: round(Math.min(...map.values())) } : {}),
    ...(focusNode && map.has(focusNode) ? { focus: round(map.get(focusNode)!), focus_node: focusNode } : {}),
  };
}

export type { GraphNode };
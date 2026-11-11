/**
 * 按需 Dijkstra：只在"图刚变了"的时候跑，不是每轮都跑。
 *
 * 触发条件（由控制面判断）：
 *   - 新身份节点出现（刚注册/刚拿到 Token）
 *   - 新端点节点出现（刚爬到新面）
 *
 * 目的只有一个：给出 **Next Hop**——下一步该打哪个接口。不做全图最短路表，
 * 也不给 LLM 一张图让它自己算（它会幻觉出不存在的边）。
 *
 * 权重是动态的：最近连续 403 的节点，出边权重随时间指数增长，
 * 逼算法绕路而不是硬撞鉴权墙。
 */
import { isActiveHypothesis } from "./hypotheses.js";
import type { AttackGraphState, GraphEdge } from "./types.js";

/** 参与寻路的边：能走过去的路（不是结论边）。 */
const WALKABLE = new Set<GraphEdge["type"]>(["navigates_to", "calls_api", "flows_data_to", "requires_auth"]);

/** 基础权重：从边自身 weight 出发，未定义的按类型给默认值。 */
const DEFAULT_WEIGHT: Record<string, number> = {
  navigates_to: 1,
  calls_api: 2,
  flows_data_to: 2,
  requires_auth: 3,
  exploits: 5,
};

/** 连续被拦后，每多一次的时间窗口与放大系数。 */
export const BLOCK_PENALTY = {
  /** 每 10 分钟未成功一次，权重乘 2。 */
  windowMs: 10 * 60 * 1000,
  factor: 2,
  /** 上限，避免溢出成一个所有人都走不通的图。 */
  cap: 64,
};

/**
 * 节点动态难度：最近连续 403 的次数 × 时间衰减放大。
 *
 * `blocked_streak` / `blocked_at` 由 builder 在 ingest 时维护：
 * 一次成功清零，一次 401/403 +1。
 */
export function dynamicPenalty(state: AttackGraphState, nodeId: string, now = Date.now()): number {
  const node = state.nodes[nodeId];
  if (!node) return 1;
  const streak = Number(node.properties.blocked_streak || 0);
  if (streak <= 0) return 1;
  const last = Number(node.properties.blocked_at || node.updated_at || now);
  const windows = Math.max(0, Math.floor((now - last) / BLOCK_PENALTY.windowMs));
  const multiplier = Math.min(BLOCK_PENALTY.cap, Math.pow(BLOCK_PENALTY.factor, windows));
  return 1 + streak * multiplier;
}

export type PathStep = { from: string; to: string; type: GraphEdge["type"]; cost: number };
export type Route = { target: string; cost: number; hops: PathStep[]; next_hop: string; why: string };

/** 高价值目标：漏洞节点、已确认漏洞的端点、带高危假设的端点。 */
export function highValueTargets(state: AttackGraphState): string[] {
  const out = new Set<string>();
  for (const node of Object.values(state.nodes)) {
    if (node.type === "vuln_state" || node.status === "vulnerable") out.add(node.id);
  }
  for (const hypothesis of state.hypotheses) {
    // 只有座位池里的活跃假设算"高价值目标"：冷宫/已定案的不该把寻路引过去。
    if (!isActiveHypothesis(hypothesis) || hypothesis.severity !== "high") continue;
    for (const node of hypothesis.nodes) if (node.startsWith("ep:")) out.add(node);
  }
  // 端点 id 自己就带高危语义的（pay/order/admin…）也算目标，否则新会话一开始没有可寻的路。
  for (const node of Object.values(state.nodes)) {
    if (node.type === "endpoint" && node.status !== "dead_end" && /pay|refund|transfer|admin|internal|withdraw/i.test(node.id)) out.add(node.id);
  }
  return [...out];
}

/**
 * 单源 Dijkstra。
 *
 * `start` 通常是一个新节点（新身份 / 新端点）。身份节点通过 `requires_auth`
 * 反向边进入端点世界——所以这里把身份节点的出边当作"可访问"的正常路径。
 */
export function dijkstra(state: AttackGraphState, start: string, options: { now?: number; maxDepth?: number } = {}): Map<string, Route> {
  const now = options.now ?? Date.now();
  const maxDepth = Math.max(1, options.maxDepth ?? 8);
  const outgoing = new Map<string, GraphEdge[]>();
  for (const edge of state.edges) {
    if (!WALKABLE.has(edge.type)) continue;
    const list = outgoing.get(edge.source_id) || [];
    list.push(edge);
    outgoing.set(edge.source_id, list);
  }

  const best = new Map<string, Route>();
  if (!state.nodes[start]) return best;
  best.set(start, { target: start, cost: 0, hops: [], next_hop: "", why: "start" });
  const visited = new Set<string>();

  while (true) {
    // 简化版：每轮线性取最小（图 <= 500 节点，不值得上二叉堆）。
    let cursor = "";
    let cursorCost = Infinity;
    for (const [node, route] of best) {
      if (visited.has(node)) continue;
      if (route.cost < cursorCost) { cursor = node; cursorCost = route.cost; }
    }
    if (!cursor) break;
    visited.add(cursor);
    if (best.get(cursor)!.hops.length >= maxDepth) continue;

    for (const edge of outgoing.get(cursor) || []) {
      const target = state.nodes[edge.target_id];
      if (!target) continue;
      if (target.status === "dead_end") continue; // 死胡同不参与寻路
      const base = Number(edge.weight ?? DEFAULT_WEIGHT[edge.type] ?? 1);
      const cost = cursorCost + base * dynamicPenalty(state, edge.target_id, now);
      const current = best.get(edge.target_id);
      if (current && current.cost <= cost) continue;
      const hops = [...best.get(cursor)!.hops, { from: cursor, to: edge.target_id, type: edge.type, cost }];
      best.set(edge.target_id, {
        target: edge.target_id, cost, hops,
        next_hop: hops[0] ? hops[0].to : "",
        why: `经由 ${edge.type}`,
      });
    }
  }
  return best;
}

/**
 * 从起点出发，算出通往所有高价值目标的最便宜路径，按代价从低到高排。
 *
 * `limit` 默认 3：Context 里塞 10 条 Next Hop 等于没给建议。
 */
export function planRoutes(state: AttackGraphState, start: string, options: { limit?: number; now?: number } = {}): Route[] {
  const limit = Math.max(1, options.limit ?? 3);
  const routes = dijkstra(state, start, { now: options.now });
  const targets = new Set(highValueTargets(state));
  return [...routes.values()]
    .filter(route => route.hops.length > 0 && targets.has(route.target))
    .sort((a, b) => a.cost - b.cost)
    .slice(0, limit)
    .map(route => ({ ...route, why: `${route.hops.length} 跳 · cost ${route.cost.toFixed(1)}` }));
}
/**
 * 存下来的路线是否已经过期。
 *
 * 只在新节点出现时重算是省算力，但如果推荐的那一跳后来被标死胡同或连续被拦，
 * 存着的建议就成了"算法让你去撞墙"——这比不给建议更糟。所以每次 ingest 后顺带查一次。
 */
export function routeStale(state: AttackGraphState, nextHops: string[]): boolean {
  return nextHops.some(hop => {
    const node = state.nodes[hop];
    if (!node) return true;
    if (node.status === "dead_end" || node.status === "vulnerable") return true;
    return Number(node.properties.blocked_streak || 0) >= 2;
  });
}
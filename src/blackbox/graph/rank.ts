/**
 * 图驱动排序：Playbook 基础分 + 拓扑加成 − 死胡同罚分。
 *
 * 为什么不上 Dijkstra：现在缺的不是最短路径，是"这一回合先打哪个"。
 * 拓扑加成用两跳以内的结构就能算：这个端点是不是某条活跃假设的落脚点、
 * 是不是通往漏洞节点的必经之路。真要做寻路，等图里有真实的漏洞节点再谈。
 *
 * 公式：final = playbookBase + topologyBonus − deadEndPenalty
 * 同分时保留模型原本的推理顺序（越靠前越优先）。
 */
import { endpointNodeId } from "./builder.js";
import { isActiveHypothesis } from "./hypotheses.js";
import type { AttackGraphState, GraphNode } from "./types.js";

export const WEIGHT = {
  /** 基础分：priority 1（未授权）→ 90，priority 14 → 0。未知打法 0。 */
  baseTop: 90,
  baseStep: 10,
  /** 端点是活跃假设（severity=high）的节点：最值钱的加分。 */
  hypothesisHigh: 20,
  /** 端点是活跃假设（medium）的节点。 */
  hypothesisMedium: 12,
  /** 端点处于"通往漏洞/高危节点的必经之路"。 */
  bridge: 15,
  /** 端点被拦过但有可用身份：带凭证重打很便宜。 */
  authWallRetry: 8,
  /** 死胡同：即使执行器会拦，排序也该把它排到最后。 */
  deadEnd: 30,
} as const;

const HIGH_VALUE = /pay|order|refund|transfer|admin|internal|withdraw|upload|export/i;

export type GraphRank = {
  /** 该请求目标端点对应的图节点 id（无则空串）。 */
  node: string;
  base: number;
  bonus: number;
  penalty: number;
  final: number;
  reasons: string[];
};

/** 沿出边能到达的所有节点（限深，防止在稠密图上烧 CPU）。 */
function reachable(state: AttackGraphState, from: string, maxDepth = 4): Set<string> {
  const seen = new Set<string>([from]);
  let frontier = [from];
  for (let depth = 0; depth < maxDepth && frontier.length; depth += 1) {
    const next: string[] = [];
    for (const edge of state.edges) {
      if (!frontier.includes(edge.source_id)) continue;
      if (seen.has(edge.target_id)) continue;
      seen.add(edge.target_id);
      next.push(edge.target_id);
    }
    frontier = next;
  }
  return seen;
}

/** 从入口节点能否走到这个节点（"必经之路"的另一半判断）。 */
function reachableFromEntry(state: AttackGraphState, target: string): boolean {
  const incoming = new Set(state.edges.map(edge => edge.target_id));
  const entries = Object.values(state.nodes).filter(node => node.type === "endpoint" && !incoming.has(node.id)).map(node => node.id);
  for (const entry of entries.slice(0, 40)) {
    if (entry === target) return true;
    if (reachable(state, entry, 4).has(target)) return true;
  }
  return false;
}

/**
 * 该端点所在的**活跃**假设（座位池里的；冷宫与已定案的不算）。
 *
 * 2026-11-04：判据从 `status !== "unreachable"` 换成 isActiveHypothesis()。
 * 状态机扩成 active/evicted/confirmed/archived 之后，旧判断会把冷宫和 confirmed
 * 都当成"活跃"，排序继续给一个已经不打算打的面加分。
 */
function activeHypothesesFor(state: AttackGraphState, nodeId: string): Array<{ severity: string; text: string }> {
  return state.hypotheses
    .filter(item => isActiveHypothesis(item) && item.nodes.includes(nodeId))
    .map(item => ({ severity: item.severity, text: item.text }));
}

/**
 * 单个请求的图加成。
 *
 * `url` 为空时（例如 `recon.nuclei` 这类以 host 为目标的工具）退回按 asset 节点算。
 */
export function graphRank(state: AttackGraphState | undefined, url: string): GraphRank {
  const empty: GraphRank = { node: "", base: 0, bonus: 0, penalty: 0, final: 0, reasons: [] };
  if (!state || !url) return empty;
  const node = endpointNodeId(url);
  const target = state.nodes[node];
  if (!target) return { ...empty, node };

  const reasons: string[] = [];
  let bonus = 0;
  let penalty = 0;

  for (const hypothesis of activeHypothesesFor(state, node)) {
    if (hypothesis.severity === "high") {
      if (bonus < WEIGHT.hypothesisHigh) { bonus = WEIGHT.hypothesisHigh; reasons.push("活跃高危假设的落脚点"); }
    } else if (bonus < WEIGHT.hypothesisMedium) {
      bonus = WEIGHT.hypothesisMedium;
      reasons.push("活跃假设的落脚点");
    }
  }

  if (bonus < WEIGHT.bridge && isBridge(state, node)) {
    bonus = WEIGHT.bridge;
    reasons.push("通往漏洞/高危节点的必经之路");
  }

  const identities = Object.values(state.nodes).filter(item => item.type === "identity" && item.id !== "id:anon");
  if (target.status === "blocked" && identities.length) {
    bonus += WEIGHT.authWallRetry;
    reasons.push("被拦过且有可用身份");
  }

  if (target.status === "dead_end") {
    penalty = WEIGHT.deadEnd;
    reasons.push("死胡同");
  }

  return { node, base: 0, bonus, penalty, final: bonus - penalty, reasons };
}

/** 是否是通往漏洞/高危节点的必经之路（近似：能走到高危节点，且从入口可达）。 */
function isBridge(state: AttackGraphState, nodeId: string): boolean {
  const node: GraphNode | undefined = state.nodes[nodeId];
  if (!node || node.status === "vulnerable") return false;
  if (!reachableFromEntry(state, nodeId)) return false;
  const downstream = reachable(state, nodeId, 4);
  for (const id of downstream) {
    if (id === nodeId) continue;
    const candidate = state.nodes[id];
    if (!candidate) continue;
    // 参数节点的 id 里带着父端点路径（param:host/api/order#id），拿它判"高危"会假阳性：
    // 任何带 order 的端点都会因为自己的参数节点被认成必经之路。
    if (candidate.type === "parameter") continue;
    if (candidate.status === "vulnerable" || candidate.type === "vuln_state") return true;
    if (candidate.type === "endpoint" && HIGH_VALUE.test(id)) return true;
  }
  return false;
}

export type RankableRequest = { tool: string; task_id?: string; input?: Record<string, unknown> };

export type ScoredRequest<T> = { request: T; index: number; base: number; bonus: number; penalty: number; final: number; reasons: string[] };

/**
 * 混合排序：打法基础分 + 图加成 − 死胡同罚分。
 *
 * 返回排序后的请求**和**打分明细（明细进事件流，出问题才能复盘"为什么这条先跑"）。
 */
export function sortRequestsByGraph<T extends RankableRequest>(
  requests: T[],
  options: { graph?: AttackGraphState; playbookOf: (taskId: string) => string | undefined; playbookPriority: (id: string | undefined) => number },
): { requests: T[]; scores: Array<{ tool: string; url: string; final: number; reasons: string[] }> } {
  const scored: ScoredRequest<T>[] = requests.map((request, index) => {
    const priority = options.playbookPriority(options.playbookOf(String(request.task_id || "")));
    // 未知打法与 priority=MAX 都给 0 分底，但仍排序在已知打法之后（靠 index 兜底）。
    const base = Number.isFinite(priority) && priority < 1000
      ? Math.max(0, WEIGHT.baseTop - (priority - 1) * WEIGHT.baseStep)
      : 0;
    const url = String((request.input as Record<string, unknown> | undefined)?.url || "");
    const rank = graphRank(options.graph, url);
    return {
      request, index, base,
      bonus: rank.bonus, penalty: rank.penalty,
      final: base + rank.bonus - rank.penalty,
      reasons: [...(base ? [] : ["未绑定打法"]), ...rank.reasons],
    };
  });
  scored.sort((a, b) => (b.final - a.final) || (a.index - b.index));
  return {
    requests: scored.map(item => item.request),
    scores: scored.map(item => ({
      tool: item.request.tool,
      url: String((item.request.input as Record<string, unknown> | undefined)?.url || ""),
      final: item.final,
      reasons: item.reasons,
    })),
  };
}
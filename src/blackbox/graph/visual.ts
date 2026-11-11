/**
 * 图谱可视化的"视觉语义"层：把数据结构翻译成人类直觉。
 *
 * 为什么放在后端（TS）而不是前端（React）：
 *   1. 形状/颜色/线条的映射是**领域决定**，不是样式偏好——审核员截图写报告时，
 *      「红色八角星 = 已确认漏洞」必须是全局一致的，不能因为前端重构而漂移；
 *   2. 前端只做渲染，所以这份映射可以被 vitest 覆盖；
 *   3. 报告导出（Mermaid）与控制台用**同一套**语义，图不会两边长得不一样。
 *
 * 只输出"该画什么"，不输出像素：具体渲染（Cytoscape / Mermaid / 打印）由消费方决定。
 */
import { connectedComponents } from "./analyze.js";
import { highValueTargets } from "./pathfind.js";
import { killChain, normalizeHypothesisStatus } from "./hypotheses.js";
import type { AttackGraphState, EdgeType, GraphNode, NodeStatus, NodeType } from "./types.js";

/** 节点形状：与 Cytoscape 的形状名一致，前端直接透传。 */
export type NodeShape = "hexagon" | "round-rectangle" | "diamond" | "shield" | "octagon";

export type VisualNode = {
  id: string;
  type: NodeType;
  status: NodeStatus;
  /** 图上显示的文字（端点带方法前缀，太长就截断）。 */
  label: string;
  shape: NodeShape;
  /** 前端据此套 class（`status-*` / `type-*`），颜色在样式表里定义一次。 */
  class: string;
  /** 状态变异：dead_end 虚线、vulnerable 发光。 */
  dimmed: boolean;
  highlighted: boolean;
  props: Record<string, unknown>;
  discovered_by: string;
  updated_at: number;
  /** 第几次 run 发现的：拓扑断链时控制台按它兜底排序。 */
  round: number;
  /** 距入口跳数：dagre 的 rank 靠它拉出从左到右的纵深。 */
  depth: number;
  /** 特种兵（沙箱 RPC）参与过的节点。 */
  rpc: boolean;
};

export type VisualEdge = {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  class: string;
  label: string;
  weight: number;
  rpc_tool?: string;
  /** 假设边：前端用流动虚线画，和"已证实的边"区分开。 */
  hypothesis: boolean;
};

export type VisualKillChain = {
  /** 漏洞节点 id（报告的锚点）。 */
  node: string;
  /** 关联的 finding 目标（有就带上，前端下拉框按它选）。 */
  target: string;
  severity: "high" | "medium" | "critical" | "low" | "info" | "unknown";
  chain: string[];
};

export type GraphVisualView = {
  nodes: VisualNode[];
  edges: VisualEdge[];
  kill_chains: VisualKillChain[];
  hypotheses: Array<{ id: string; kind: string; text: string; severity: string; attempts: number; nodes: string[]; status?: string }>;
  closed_hypotheses: string[];
  components: Array<{ id: string; size: number; has_vuln: boolean }>;
  stats: {
    nodes: number; edges: number; vulnerable: number; dead_end: number; blocked: number;
    identities: number; untested: number; rpc_edges: number; hypotheses: number; hypotheses_closed: number;
    /** 冷宫里的假设数：不占调度名额，可在后续轮次复活。 */
    hypotheses_evicted: number;
    /** 叠加在图上、并非真实边的假设线数量（画出来的线 = edges + hypothesis_edges）。 */
    hypothesis_edges: number;
    /** 图上被裁剪掉的节点数（后端上限 500）。 */
    pruned: number;
  };
  /** 高价值目标：寻路与排序都在追这些节点。 */
  targets: string[];
  generated_at: number;
};

const SHAPE: Record<NodeType, NodeShape> = {
  asset: "hexagon",
  endpoint: "round-rectangle",
  parameter: "diamond",
  identity: "shield",
  vuln_state: "octagon",
};

/** 边的视觉类别：前端按这个类名查样式表（实线/虚线/点划/粗线/闪电）。 */
export function edgeClassOf(type: EdgeType): string {
  switch (type) {
    case "requires_auth": return "edge-auth";       // 粗虚线 绿
    case "flows_data_to": return "edge-data";       // 点划线 紫
    case "exploits": return "edge-exploit";         // 粗实线 红
    case "bypasses": return "edge-bypass";          // 折线 橙
    case "calls_api": return "edge-api";            // 实线 浅灰
    // 发现来源：历程图主干（读作"从这里挖到那里"）。
    case "discovered_from": return "edge-discovery";
    default: return "edge-nav";                     // 实线 浅灰
  }
}

function nodeLabel(node: GraphNode): string {
  const method = String(node.properties.method || "").toUpperCase();
  const params = Array.isArray(node.properties.params) && node.properties.params.length
    ? `?${node.properties.params.slice(0, 3).join(",")}`
    : "";
  const base = node.id.replace(/^(ep|asset|id|param|vuln):/, "");
  const text = `${method ? `${method} ` : ""}${base}${params}`;
  return text.length > 64 ? `${text.slice(0, 61)}…` : text;
}

/**
 * 生成可视化视图。
 *
 * `maxNodes` 默认 300：控制台要能看全貌，但 500 个节点上 Canvas 依然会掉帧，
 * 所以按"重要度"截断（vulnerable > identity > 假设引用 > blocked > 其他），
 * 并在 stats.pruned 里说清楚砍了多少——**不静默截断**。
 */
export function graphVisualView(
  state: AttackGraphState,
  options: { maxNodes?: number; maxEdges?: number; killChainFindings?: Array<{ target: string; severity: string }> } = {},
): GraphVisualView {
  const maxNodes = Math.max(20, options.maxNodes ?? 300);
  const maxEdges = Math.max(40, options.maxEdges ?? 900);
  // stall 已降级为端点属性 `stall_hits`（2026-11-04）：旧 checkpoint 里的 stall
  // 假设若不过滤，历程图上会画出几十条形状相同的 `hyp:` 虚线，把真假设的边压不见。
  // 控制台要能看见冷宫（它是"还有备选在排队"的证据），但已定案的（confirmed/archived）
  // 与 stall 不进图：前者已由 vuln_state 表达，后者一律降级为端点属性 stall_hits。
  const liveHypotheses = state.hypotheses.filter(item => {
    const status = normalizeHypothesisStatus(item.status);
    return (status === "active" || status === "evicted") && item.kind !== "stall";
  });
  const referenced = new Set(liveHypotheses.flatMap(item => item.nodes));
  const rpcTargets = new Set(state.edges.filter(edge => edge.rpc_tool).flatMap(edge => [edge.source_id, edge.target_id]));

  const rank = (node: GraphNode): number => {
    if (node.status === "vulnerable" || node.type === "vuln_state") return 100;
    if (node.type === "identity") return 90;
    if (referenced.has(node.id)) return 80;
    if (node.status === "blocked") return 60;
    if (node.status === "dead_end") return 20;
    return 40;
  };
  const all = Object.values(state.nodes);
  const kept = [...all].sort((a, b) => (rank(b) - rank(a)) || (b.updated_at - a.updated_at)).slice(0, maxNodes);
  const keptIds = new Set(kept.map(node => node.id));

  const nodes: VisualNode[] = kept.map(node => ({
    id: node.id,
    type: node.type,
    status: node.status,
    label: nodeLabel(node),
    shape: SHAPE[node.type],
    class: `type-${node.type} status-${node.status}`,
    dimmed: node.status === "dead_end",
    highlighted: node.status === "vulnerable" || node.type === "vuln_state",
    props: {
      method: node.properties.method, status_code: node.properties.status_code,
      content_length: node.properties.content_length, auth_required: node.properties.auth_required,
      params: node.properties.params, hits: node.properties.hits, repeats: node.properties.repeats,
      blocked_streak: node.properties.blocked_streak, role: node.properties.role,
      host: node.properties.host, note: node.properties.note,
      // WAF 墙与重复签名：控制台据此把“被墙挡住”和“重复到没意义”画成不同颜色，
      // 否则 412 和 200 在图上长得一模一样（2026-10-28 note.yun 会话就是这样）。
      wall: node.properties.wall, signature_repeats: node.properties.signature_repeats,
      // 事实层两字段（2026-11-03）：控制台图上同样要分得清"真打过 / 只是看到 / 打了没回"，
      // 否则 nuclei 探过的端点和 http.request 打过的端点在图上一模一样。
      origin: node.properties.origin, status_unknown: node.properties.status_unknown,
      // 停滞信号（2026-11-04）：原来是一条 stall 假设，已降级为端点属性。
      // 控制台要能看到"这个端点打过很多次还是没变"，否则回放时看不出为什么绕开它。
      ...(node.type === "endpoint" && Number(node.properties.hits || 0) >= 4
        ? { stall_hits: Number(node.properties.hits) }
        : {}),
    },
    discovered_by: node.discovered_by,
      round: Number(node.round || 1),
      depth: Number(node.depth || 1),
    updated_at: node.updated_at,
    rpc: rpcTargets.has(node.id),
  }));

  const edges: VisualEdge[] = state.edges
    .filter(edge => keptIds.has(edge.source_id) && keptIds.has(edge.target_id))
    .slice(0, maxEdges)
    .map(edge => ({
      id: edge.id,
      source: edge.source_id,
      target: edge.target_id,
      type: edge.type,
      class: edgeClassOf(edge.type),
      label: edge.type,
      weight: edge.weight,
      ...(edge.rpc_tool ? { rpc_tool: edge.rpc_tool } : {}),
      hypothesis: false,
    }));

  // 假设线：从"能打的端点"指向假设涉及的漏洞/高危端点，画成流动虚线。
  // 只画一跳，不画整条路径——那是 kill chain 的事，混在一起就成了毛线球。
  for (const hypothesis of liveHypotheses) {
    const endpoints = hypothesis.nodes.filter(id => id.startsWith("ep:") && keptIds.has(id));
    if (endpoints.length < 2) continue;
    const [from, ...rest] = endpoints;
    for (const to of rest.slice(0, 2)) {
      edges.push({
        id: `hyp:${hypothesis.id}:${from}->${to}`,
        source: from!, target: to, type: "flows_data_to",
        class: "edge-hypothesis", label: hypothesis.kind, weight: 99, hypothesis: true,
      });
    }
  }

  const findings = options.killChainFindings || [];
  const killChainsRaw: VisualKillChain[] = all
    .filter(node => node.type === "vuln_state" || node.status === "vulnerable")
    .slice(0, 20)
    .map(node => {
      const endpoint = node.type === "vuln_state" ? node.id.replace(/^vuln:[^@]+@/, "ep:") : node.id;
      const finding = findings.find(item => endpoint === `ep:${item.target.replace(/^https?:\/\//, "")}`
        || node.id.includes(item.target.replace(/^https?:\/\//, "")));
      return {
        node: node.id, target: finding?.target || endpoint,
        severity: (finding?.severity as VisualKillChain["severity"]) || (node.type === "vuln_state" ? "high" : "unknown"),
        chain: killChain(state, node.id),
      };
    });
  // 同一个漏洞可能在图上有两个锚点（端点被标 vulnerable + 独立的 vuln_state 节点）。
  // 面板给审核员选的是"这个漏洞的路径"，所以按 target 去重，保留跳数最多的那条。
  const byTarget = new Map<string, VisualKillChain>();
  for (const chain of killChainsRaw) {
    const seen = byTarget.get(chain.target);
    if (!seen || chain.chain.length > seen.chain.length) byTarget.set(chain.target, chain);
  }
  const killChains = [...byTarget.values()];

  const components = connectedComponents(state);
  const byStatus = (status: NodeStatus): number => all.filter(node => node.status === status).length;

  return {
    nodes,
    edges,
    kill_chains: killChains,
    hypotheses: liveHypotheses.slice(-20).map(item => ({
      id: item.id, kind: item.kind, text: item.text, severity: item.severity,
      attempts: item.attempts || 0, nodes: item.nodes,
      status: normalizeHypothesisStatus(item.status),
    })),
    closed_hypotheses: state.hypotheses
      .filter(item => normalizeHypothesisStatus(item.status) === "archived")
      .map(item => item.id).slice(-20),
    components: components.slice(0, 12).map(component => ({ id: component.id, size: component.size, has_vuln: component.hasVuln })),
    stats: {
      nodes: all.length, edges: state.edges.length,
      vulnerable: byStatus("vulnerable"), dead_end: byStatus("dead_end"), blocked: byStatus("blocked"),
      identities: all.filter(node => node.type === "identity").length,
      untested: byStatus("untested"),
      rpc_edges: state.edges.filter(edge => edge.rpc_tool).length,
      hypotheses: liveHypotheses.length,
      // 与 closed_hypotheses 同口径：只数进坟墓的（archived）；冷宫单独算。
      hypotheses_closed: state.hypotheses.filter(item => normalizeHypothesisStatus(item.status) === "archived").length,
      hypotheses_evicted: state.hypotheses.filter(item => normalizeHypothesisStatus(item.status) === "evicted").length,
      hypothesis_edges: edges.filter(edge => edge.hypothesis).length,
      pruned: Math.max(0, all.length - kept.length),
    },
    targets: highValueTargets(state).filter(id => keptIds.has(id)).slice(0, 20),
    generated_at: Date.now(),
  };
}

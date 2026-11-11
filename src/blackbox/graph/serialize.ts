/**
 * 序列化与裁剪：把图压成"能进 prompt 的体量"。
 *
 * 经验值：一次工具结果原文 4–20KB，而整张图的摘要稳定在 6–8KB。
 * 这是"用结构换 token"的兑现点——不是把 body 截断，而是不再需要 body。
 *
 * 输出两种视图：
 *   - `graphContextView()`：给 LLM 的精简 JSON（节点 + 关键边 + 假设 + 建议下一步）
 *   - `graphMermaid()`：给报告/人工审阅的图（离场时生成，不进 prompt）
 */
import { isActiveHypothesis, killChain, normalizeHypothesisStatus } from "./hypotheses.js";
import type { AttackGraphState, GraphEdge, GraphNode } from "./types.js";

export type GraphContextView = {
  /**
   * 字段图例（**每轮都带**，约 200 字符）。
   *
   * 为什么放在图里而不是系统提示词里：判定依据跟着图走，模型每次看节点就知道
   * `origin:request` 与省略 origin 的区别；提示词被截断/被覆盖时图例不会跟着消失。
   * 这是"让模型看得见机器判定依据"，不是新增一条行为约束。
   */
  field_legend: string[];
  nodes: Array<{ id: string; type: string; status: string; note?: string; props?: Record<string, unknown> }>;
  edges: Array<{ from: string; to: string; type: string; weight?: number }>;
  hypotheses: Array<{ id: string; kind: string; text: string; severity: string; attempts?: number }>;
  /** 已降级的假设 id（Agent 看得到"我放弃过什么"，避免反复重推同一条）。 */
  closed_hypotheses: string[];
  dead_ends: string[];
  identities: string[];
  vulns: Array<{ node: string; chain: string[] }>;
  truncated: { nodes: number; edges: number };
  counts: Record<string, number>;
};

/** 图字段图例：只在 serialize 头部输出一次，不重复进每个节点。 */
export const ATTACK_GRAPH_FIELD_LEGEND: string[] = [
  "origin:request = 本 agent 亲手发过 HTTP 请求，status_code 是这次响应的真实值",
  "origin:discovery（默认，已省略）= 从工具输出里看到、但没请求过；status_code 不可信，别当响应比",
  "status_unknown:true = 发过包但工具 schema 没给状态码（nuclei/sqlmap 这类）；勿假设 200，换能给状态码的工具重测",
  "counts.probed_unknown = 处于上一条状态的端点数",
  "stall_hits:N = 该端点已被请求 N 次且状态没变；停止换 payload，改换攻击面（同目录其他端点 / 换身份 / 换方法）",
  // 站点自报的业务面（2026-11-04）：18 个 /help/*.html 是 sitemap 主动声明的，
  // 可信度高于爬到的导航外链；不给模型这个标记，它没有理由优先打这些页面。
  "source:sitemap|robots = 这条 URL 由站点自己声明（sitemap/robots），属于业务面而非导航外链，优先请求",
];

const PROP_KEYS = [
  "method", "status_code", "content_length", "auth_required", "params", "hits",
  "repeats", "role", "host", "note", "wall", "signature_repeats",
  // 事实层的两个字段（2026-11-03）：不加进来，模型看到的"真打过"和"只是看到"
  // 长得一模一样，而 cannotLocateObject / hasComparableResponse 全按它判定——
  // 判定依据对模型不可见，它就无法理解自己为什么被拦。
  "origin", "status_unknown",
  // 站点自报来源：不加进白名单，`source: sitemap` 就只存在于 checkpoint 里，
  // 模型在 attack_graph 中看到的 18 个业务页和普通导航外链长得一模一样。
  "source",
];

function slimProps(node: GraphNode): Record<string, unknown> | undefined {
  const out: Record<string, unknown> = {};
  for (const key of PROP_KEYS) {
    const value = (node.properties as Record<string, unknown>)[key];
    if (value === undefined || value === "") continue;
    // ── 语义压缩（省 token，不丢信息）──
    // discovery 是默认态：500 个节点每个都写一遍 origin:discovery 纯属浪费，
    // 省略即 discovery，语义等价（图例里写了）。
    if (key === "origin" && value === "discovery") continue;
    // false 是默认态，只有 true 才值得占字符。
    if (key === "status_unknown" && value !== true) continue;
    if (Array.isArray(value)) out[key] = value.slice(0, 8);
    else if (typeof value === "string") out[key] = value.slice(0, 40);
    else out[key] = value;
  }
  // 停滞信号从"假设"降级为"事实"（2026-11-04）。
  //
  // 原来它是一条 stall 假设（`hits >= 4` 就产一条），实测这条判据没有区分度：
  // 283 个端点里 180 个满足，单轮产出 179 条，把 40 个假设座位全占满，
  // 而 hypothesisTasks 又过滤 stall → 假设任务恒为 0 → attempts 恒为 0 →
  // 永不归档，形成死锁。详情见 deriveHypotheses ⑤。
  //
  // 现在它只作为端点属性出现：覆盖全部高 hits 端点（而不是 13 个座位），
  // 不占假设池，也不需要 attempts 生命周期。阈值沿用原来的 4，保持行为可对照。
  const hits = Number((node.properties as Record<string, unknown>).hits || 0);
  if (node.type === "endpoint" && hits >= 4) out.stall_hits = hits;
  return Object.keys(out).length ? out : undefined;
}

function edgePriority(edge: GraphEdge, state: AttackGraphState): number {
  const target = state.nodes[edge.target_id];
  if (edge.type === "exploits") return 100;
  if (target?.status === "vulnerable") return 95;
  if (edge.type === "requires_auth") return 80;
  if (edge.type === "calls_api") return 60;
  if (edge.type === "flows_data_to") return 50;
  return 10;
}

export function graphContextView(
  state: AttackGraphState,
  options: { maxNodes?: number; maxEdges?: number; maxHypotheses?: number } = {},
): GraphContextView {
  const maxNodes = Math.max(10, options.maxNodes ?? 60);
  const maxEdges = Math.max(10, options.maxEdges ?? 90);
  const maxHypotheses = Math.max(4, options.maxHypotheses ?? 12);

  // 节点排序：vulnerable > identity > blocked > 有假设引用 > 最近更新
  // 2026-11-04 状态机：只把 active 当"活跃"。冷宫（evicted）不进 prompt——
  // 它不参与调度，显示出来只会挤掉真假设的名额；数量在 counts.hypotheses_evicted 里。
  // stall 的历史残留仍然过滤（已降级为端点上的 `stall_hits`）。
  const live = state.hypotheses.filter(item => isActiveHypothesis(item) && item.kind !== "stall");
  const evictedCount = state.hypotheses.filter(item => normalizeHypothesisStatus(item.status) === "evicted").length;
  const archivedIds = state.hypotheses
    .filter(item => normalizeHypothesisStatus(item.status) === "archived")
    .map(item => item.id);
  const referenced = new Set(live.flatMap(item => item.nodes));
  const rank = (node: GraphNode): number => {
    if (node.status === "vulnerable") return 100;
    if (node.type === "identity") return 90;
    if (referenced.has(node.id)) return 80;
    if (node.status === "blocked") return 60;
    if (node.status === "dead_end") return 10;
    return 40;
  };
  const sortedNodes = Object.values(state.nodes)
    .sort((a, b) => (rank(b) - rank(a)) || (b.updated_at - a.updated_at));
  const keptNodes = sortedNodes.slice(0, maxNodes);
  const keptIds = new Set(keptNodes.map(node => node.id));

  const sortedEdges = state.edges
    .slice()
    .sort((a, b) => edgePriority(b, state) - edgePriority(a, state));
  const keptEdges = sortedEdges.filter(edge => keptIds.has(edge.source_id) && keptIds.has(edge.target_id)).slice(0, maxEdges);

  // 取前 N 而不是 slice(-N)：旧写法依赖"生成顺序"，而生成顺序由 derive 的循环次序决定，
  // 与价值无关（stall 时代正是因此把 idor 全挤了出去）。现在按 severity + 最近评估排。
  const hypotheses = [...live]
    .sort((a, b) => (a.severity === "high" ? 0 : 1) - (b.severity === "high" ? 0 : 1)
      || (b.lastEvaluatedAt ?? 0) - (a.lastEvaluatedAt ?? 0))
    .slice(0, maxHypotheses)
    .map(item => ({
      id: item.id, kind: item.kind, text: item.text, severity: item.severity,
      ...(item.attempts ? { attempts: item.attempts } : {}),
    }));

  const vulns = Object.values(state.nodes)
    .filter(node => node.type === "vuln_state" || node.status === "vulnerable")
    // vuln_state 排在前面：报告/Kill Chain 要从"漏洞节点"而不是"被打过的端点"往回走。
    .sort((a, b) => (a.type === "vuln_state" ? -1 : 0) - (b.type === "vuln_state" ? -1 : 0))
    .slice(0, 8)
    .map(node => ({ node: node.id, chain: killChain(state, node.id) }));

  return {
    // 图例放最前：模型先拿到"怎么读"，再看节点。JSON 的 key 顺序在序列化后仍然保持。
    field_legend: ATTACK_GRAPH_FIELD_LEGEND,
    nodes: keptNodes.map(node => ({
      id: node.id, type: node.type, status: node.status,
      ...(node.properties.note ? { note: String(node.properties.note).slice(0, 60) } : {}),
      ...(slimProps(node) ? { props: slimProps(node) } : {}),
    })),
    edges: keptEdges.map(edge => ({
      from: edge.source_id, to: edge.target_id, type: edge.type,
      ...(edge.weight > 1 ? { weight: edge.weight } : {}),
    })),
    hypotheses,
    closed_hypotheses: archivedIds.slice(-10),
    dead_ends: Object.values(state.nodes).filter(node => node.status === "dead_end").map(node => node.id).slice(0, 20),
    identities: Object.values(state.nodes).filter(node => node.type === "identity").map(node => node.id),
    vulns,
    truncated: { nodes: Math.max(0, sortedNodes.length - keptNodes.length), edges: Math.max(0, sortedEdges.length - keptEdges.length) },
    counts: {
      nodes: Object.keys(state.nodes).length,
      edges: state.edges.length,
      hypotheses: live.length,
      // 冷宫：不参与调度、不进 prompt，但让模型知道"还有备选在等座位"。
      hypotheses_evicted: evictedCount,
      // 与 closed_hypotheses 同口径：只数真正进坟墓的（archived）。
      hypotheses_closed: archivedIds.length,
      vulnerable: Object.values(state.nodes).filter(node => node.status === "vulnerable").length,
      dead_end: Object.values(state.nodes).filter(node => node.status === "dead_end").length,
      // 「打了但没拿到状态码」的端点数：模型据此知道"这些面还没被真正证实/证伪"，
      // 该换能给状态码的工具重测，而不是把它们当成已打过或未打过。
      probed_unknown: Object.values(state.nodes).filter(node => node.properties.status_unknown === true).length,
    },
  };
}

/** Mermaid 有向图：报告/人工审阅用，不进 prompt。 */
export function graphMermaid(state: AttackGraphState, options: { maxNodes?: number } = {}): string {
  const view = graphContextView(state, { maxNodes: options.maxNodes ?? 40, maxEdges: 80 });
  const shape = (type: string, id: string): string => {
    const label = id.replace(/"/g, "'");
    if (type === "asset") return `${sanitize(id)}(["${label}"])`;
    if (type === "identity") return `${sanitize(id)}{{"${label}"}}`;
    if (type === "vuln_state") return `${sanitize(id)}[["${label}"]]`;
    if (type === "parameter") return `${sanitize(id)}>"${label}"]`;
    return `${sanitize(id)}["${label}"]`;
  };
  const lines = ["graph LR"];
  for (const node of view.nodes) lines.push(`  ${shape(node.type, node.id)}`);
  for (const edge of view.edges) lines.push(`  ${sanitize(edge.from)} -->|${edge.type}| ${sanitize(edge.to)}`);
  const dead = view.nodes.filter(node => node.status === "dead_end").map(node => sanitize(node.id));
  if (dead.length) lines.push(`  classDef deadEnd fill:#eee,stroke:#999,color:#666`);
  if (dead.length) lines.push(`  class ${dead.join(",")} deadEnd`);
  return lines.join("\n");
}

function sanitize(id: string): string {
  return id.replace(/[^A-Za-z0-9_]/g, "_");
}
/**
 * 把一条 Kill Chain 渲染成 Mermaid（报告里的复现路径）。
 *
 * 只画链上的节点，不画全图：报告读者要的是"这条路怎么走过来的"，
 * 而不是我再把 500 个节点摊一遍。
 */
export function chainMermaid(chain: string[]): string {
  if (!chain.length) return "";
  const lines = ["graph LR"];
  chain.forEach((node, index) => lines.push(`  n${index}["${node.replace(/"/g, "'")}"]`));
  for (let index = 1; index < chain.length; index += 1) lines.push(`  n${index - 1} --> n${index}`);
  return lines.join("\n");
}

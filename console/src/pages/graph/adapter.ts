/**
 * 后端视图 → Cytoscape elements。
 *
 * 只做格式转换，不做判断：哪些节点该高亮、哪些边是假设，后端已经说了。
 * 这样"图长什么样"这件事只有一个事实来源。
 */
import type { ElementDefinition } from "cytoscape";

export type VisualNode = {
  id: string; type: string; status: string; label: string; shape: string; class: string;
  dimmed: boolean; highlighted: boolean; props: Record<string, unknown>;
  discovered_by: string; updated_at: number; rpc: boolean;
  /** 第几次 run 发现的（横轴）。 */ round?: number;
  /** 距入口跳数（纵轴分簇）。 */ depth?: number;
};

export type VisualEdge = {
  id: string; source: string; target: string; type: string; class: string; label: string;
  weight: number; rpc_tool?: string; hypothesis: boolean;
};

export type GraphView = {
  ok?: boolean;
  session_id?: string;
  target?: string;
  status?: string;
  nodes: VisualNode[];
  edges: VisualEdge[];
  kill_chains: Array<{ node: string; target: string; severity: string; chain: string[] }>;
  hypotheses: Array<{ id: string; kind: string; text: string; severity: string; attempts: number; nodes: string[] }>;
  closed_hypotheses: string[];
  components: Array<{ id: string; size: number; has_vuln: boolean }>;
  stats: Record<string, number>;
  targets: string[];
  generated_at: number;
};

export function formatForCytoscape(view: GraphView, options: { rpcOnly?: boolean } = {}): ElementDefinition[] {
  const source = options.rpcOnly ? view.nodes.filter(node => node.rpc) : view.nodes;
  const ids = new Set(source.map(node => node.id));
  const elements: ElementDefinition[] = [];

  for (const node of source) {
    elements.push({
      data: {
        id: node.id, label: node.label, type: node.type, status: node.status,
        shape: node.shape, props: node.props, evidence: node.discovered_by, updated_at: node.updated_at,
        round: Number(node.round || 1), depth: Number(node.depth || 1),
      },
      classes: [node.class, node.rpc ? "rpc" : "", node.dimmed ? "dimmed" : ""].filter(Boolean).join(" "),
    });
  }

  for (const edge of view.edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target)) continue;
    if (options.rpcOnly && !edge.rpc_tool) continue;
    elements.push({
      data: { id: edge.id, source: edge.source, target: edge.target, type: edge.type, label: edge.label, weight: edge.weight },
      classes: [edge.class, edge.hypothesis ? "hypothesis" : "", edge.rpc_tool ? "rpc" : ""].filter(Boolean).join(" "),
    });
  }
  return elements;
}

/** Kill Chain 的节点与边 id 集合（前端据此加 `path` class）。 */
export function killChainSelection(view: GraphView, chainNode: string): { nodes: string[]; edges: string[] } {
  const chain = view.kill_chains.find(item => item.node === chainNode)?.chain || [];
  const nodes = chain.length ? chain : [chainNode];
  const edges: string[] = [];
  for (let index = 1; index < nodes.length; index += 1) {
    const edge = view.edges.find(item => item.source === nodes[index - 1] && item.target === nodes[index]);
    if (edge) edges.push(edge.id);
  }
  return { nodes, edges };
}

/** Mermaid 导出：给报告/复制按钮用，和报告里的那段保持一致。 */
export function toMermaid(view: GraphView, options: { chain?: string } = {}): string {
  const nodes = options.chain
    ? (view.kill_chains.find(item => item.node === options.chain)?.chain || [view.kill_chains[0]?.node || ""]).filter(Boolean)
    : view.nodes.map(node => node.id);
  const keep = new Set(nodes);
  const id = (raw: string): string => raw.replace(/[^A-Za-z0-9_]/g, "_");
  const lines = ["graph LR"];
  for (const node of view.nodes) {
    if (!keep.has(node.id)) continue;
    lines.push(`  ${id(node.id)}["${node.label.replace(/"/g, "'")}"]`);
  }
  for (const edge of view.edges) {
    if (!keep.has(edge.source) || !keep.has(edge.target)) continue;
    lines.push(`  ${id(edge.source)} -->|${edge.type}| ${id(edge.target)}`);
  }
  return lines.join("\n");
}
/**
 * 视觉语义 → Cytoscape 样式表。
 *
 * 规则和 `src/blackbox/graph/visual.ts` 一一对应：后端给 class，这里给画法。
 * 放在前端是因为它只影响渲染；"什么算高危"这种判断在后端。
 */
import type { StylesheetStyle } from "cytoscape";

export const graphStyles: StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      shape: "data(shape)" as never,
      width: 34, height: 34,
      "background-color": "#6c757d",
      "border-width": 1.5, "border-color": "#495057",
      label: "data(label)",
      "font-size": 9,
      color: "#212529",
      "text-valign": "bottom", "text-halign": "center",
      "text-margin-y": 4,
      "text-wrap": "ellipsis", "text-max-width": "130px",
      "min-zoomed-font-size": 6,
      "overlay-opacity": 0,
    },
  },
  // 类型 → 颜色（形状由后端 shape 给）
  { selector: "node.type-asset", style: { "background-color": "#6c757d" } },
  { selector: "node.type-endpoint", style: { "background-color": "#0d6efd" } },
  { selector: "node.type-parameter", style: { "background-color": "#6f42c1", width: 26, height: 26 } },
  { selector: "node.type-identity", style: { "background-color": "#198754" } },
  { selector: "node.type-vuln_state", style: { "background-color": "#dc3545", width: 40, height: 40 } },
  // 状态变异
  { selector: "node.status-dead_end", style: { "background-color": "#adb5bd", "border-style": "dashed", "border-color": "#868e96", opacity: 0.55, color: "#6c757d" } },
  { selector: "node.status-vulnerable", style: { "border-width": 3, "border-color": "#b02a37", "background-color": "#dc3545", color: "#842029" } },
  { selector: "node.status-blocked", style: { "border-style": "double", "border-width": 3, "border-color": "#ffc107" } },
  { selector: "node.status-testing", style: { "border-color": "#0dcaf0" } },
  // 特种兵（RPC）参与过的节点
  { selector: "node.rpc", style: { "underlay-color": "#20c997", "underlay-opacity": 0.25, "underlay-padding": 6 } },
  // 高亮/淡出（Kill Chain 与聚焦）
  { selector: "node.faded", style: { opacity: 0.18 } },
  { selector: "node.path", style: { "border-width": 4, "border-color": "#dc3545", width: 46, height: 46, "z-index": 20 } },
  { selector: "node:selected", style: { "border-width": 3, "border-color": "#212529" } },
  // 边
  {
    selector: "edge",
    style: {
      width: 1.4,
      "line-color": "#adb5bd",
      "target-arrow-color": "#adb5bd",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.8,
      "font-size": 7,
      color: "#6c757d",
      "text-rotation": "autorotate",
      "min-zoomed-font-size": 6,
      "overlay-opacity": 0,
    },
  },
  { selector: "edge.edge-auth", style: { "line-color": "#198754", "target-arrow-color": "#198754", "line-style": "dashed", width: 2.4 } },
  { selector: "edge.edge-data", style: { "line-color": "#6f42c1", "target-arrow-color": "#6f42c1", "line-style": "dotted", width: 2 } },
  { selector: "edge.edge-exploit", style: { "line-color": "#dc3545", "target-arrow-color": "#dc3545", width: 3.4 } },
  { selector: "edge.edge-bypass", style: { "line-color": "#fd7e14", "target-arrow-color": "#fd7e14", "line-style": "dashed", width: 2.6 } },
  { selector: "edge.edge-api", style: { "line-color": "#ced4da" } },
  // 发现来源边：历程图主干。深青实线，比 navigates_to 更"有信息"但不抢漏洞的红。
  { selector: "edge.edge-discovery", style: { "line-color": "#0dcaf0", "target-arrow-color": "#0dcaf0", width: 1.8 } },
  { selector: "edge.edge-hypothesis", style: { "line-color": "#ffc107", "target-arrow-color": "#ffc107", "line-style": "dashed", width: 2.2, "curve-style": "unbundled-bezier" } },
  { selector: "edge.faded", style: { opacity: 0.1 } },
  { selector: "edge.path", style: { "line-color": "#dc3545", "target-arrow-color": "#dc3545", width: 3.6, "z-index": 20 } },
  { selector: "edge.rpc", style: { "line-color": "#20c997", "target-arrow-color": "#20c997", "line-style": "dashed" } },
];

/** Dagre 分层布局：从左到右，符合"入口 → 中转 → 沦陷"的时间线直觉。 */
export const dagreLayout = {
  name: "dagre",
  rankDir: "LR",
  nodeSep: 46,
  rankSep: 90,
  edgeSep: 12,
  padding: 24,
  animate: false,
  fit: true,
} as const;

/** 环形兜底布局：图里有环时 Dagre 会退化成一坨，用这个换一口气。 */
export const concentricLayout = {
  name: "concentric",
  concentric: (node: { data: (key: string) => string }) => (node.data("status") === "vulnerable" ? 10 : 1),
  levelWidth: () => 2,
  padding: 24,
  animate: false,
  fit: true,
} as const;

export const graphStyleText = [
  "Cytoscape 样式表（要点）：",
  "  形状：asset 六边形 / endpoint 圆角矩形 / parameter 菱形 / identity 盾形 / vuln_state 八角形",
  "  颜色：endpoint 蓝 / parameter 紫 / identity 绿 / vuln_state 红 / asset 灰",
  "  状态：dead_end 灰+虚线+半透明；vulnerable 粗红边发光；blocked 双线黄色（鉴权墙）",
  "  边：navigates_to·calls_api 浅灰实线；requires_auth 绿粗虚线；flows_data_to 紫点划；exploits 红粗线；假设边 黄流动虚线",
].join("\n");

/**
 * 历程布局（preset，手工算坐标）：**横轴 = 第几次 run**，纵轴 = 该轮内按 depth 分簇。
 *
 * 为什么不能只靠 dagre：Dagre 的 rank 只认边。2026-10-28 实测那个 11 轮会话，
 * 边修好之后是 226 条 discovered_from，但 221 个节点都是同一轮一次目录爆破的产物，
 * 拓扑深度就是 2 —— dagre 把它们排成"一竖列"，看起来仍然没有"历程"。
 * 历程轴必须是时间（round），不是拓扑；两个轴分开才读得出"第 N 轮从左往右推进了什么"。
 */
export function journeyLayout(elements: ElementDefinitionLike[]): { name: string; positions: (node: { id: () => string; data: (key: string) => unknown }) => { x: number; y: number }; fit: boolean; animate: boolean; padding: number } {
  // 每轮一列；列内按 depth 升序、再按 id 稳定排序，保证同一份数据每次画出来一样。
  const rounds = new Map<number, ElementDefinitionLike[]>();
  for (const element of elements) {
    if (element.data.source) continue;
    const round = Number(element.data.round || 1);
    if (!rounds.has(round)) rounds.set(round, []);
    rounds.get(round)!.push(element);
  }
  // 一轮可能有 200+ 个节点（一次目录爆破）。一列 200 行等于又变回"竖条"，
  // 所以轮内按 16 行分块，块横着排：整体读法是"轮次列 → 块 → 行"。
  const positions = new Map<string, { x: number; y: number }>();
  const columnWidth = 320;
  const blockWidth = 86;
  const rowHeight = 52;
  const rowsPerBlock = 16;
  const orderedRounds = [...rounds.keys()].sort((a, b) => a - b);
  orderedRounds.forEach((round, columnIndex) => {
    const column = rounds.get(round)!.slice().sort((a, b) => {
      const depthDiff = Number(a.data.depth || 1) - Number(b.data.depth || 1);
      return depthDiff || String(a.data.id).localeCompare(String(b.data.id));
    });
    column.forEach((element, index) => {
      const block = Math.floor(index / rowsPerBlock);
      const row = index % rowsPerBlock;
      positions.set(String(element.data.id), {
        x: columnIndex * columnWidth + block * blockWidth,
        y: row * rowHeight - (Math.min(column.length, rowsPerBlock) - 1) * rowHeight / 2,
      });
    });
  });  return {
    name: "preset",
    positions: (node) => positions.get(String(node.id())) || { x: 0, y: 0 },
    fit: true,
    animate: false,
    padding: 24,
  };
}

type ElementDefinitionLike = { data: Record<string, unknown> & { id?: string; source?: string } };

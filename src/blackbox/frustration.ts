import type { AttackGraphState } from "./graph/types.js";
import { graphState } from "./graph/builder.js";
import { activeHypotheses } from "./graph/hypotheses.js";
import { bestPotential, potentialMap } from "./potential.js";

/**
 * 熔断即交付：整场会话判死时，自动产出《阻碍分析与防御测绘报告》。
 *
 * 失败的情报也是情报。人工最想知道的从来不是"SRC 有没有出报告"，而是"这台资产为什么啃不动、
 * 我下次该从哪进"。所以这份报告不写漏洞，只写：哪些路试过、死在哪、哪些边被 WAF 挡住、
 * 还有哪些假设没验证完 —— 加上一张能直接看的 Mermaid 图。
 */

export type FrustrationReport = {
  markdown: string;
  /** 报告里引用的统计，便于事件里落数字。 */
  counts: { blocked: number; failed: number; pending: number; dead_ends: number; blocked_edges: number; hypotheses: number; convergences: number };
};

type Task = { id: string; status?: string; target?: string; purpose?: string; reason?: string; outcome_reason?: string; outcome_code?: string; outcome_evidence_ids?: string[]; playbook?: string; evidence_ids?: string[] };

export function frustrationAudit(state: Record<string, unknown>, meta: { session_id?: string; target?: string; stopReason?: string } = {}): FrustrationReport {
  const tasks = (state.tasks || {}) as Record<string, Task>;
  const graph: AttackGraphState = graphState(state.graph as never);
  const entries = Object.entries(tasks).map(([id, task]) => ({ ...task, id }));
  const by = (status: string) => entries.filter(task => String(task.status || "") === status);
  const blocked = by("blocked");
  const failed = by("failed");
  const pending = by("pending").concat(by("running"));
  const deadEnds = Object.values(graph.nodes).filter(node => node.status === "dead_end");
  const blockedEdges = Object.values(graph.edges).filter(edge => Number((edge.properties || {}).status_code || 0) === 401
    || Number((edge.properties || {}).status_code || 0) === 403 || edge.type === "requires_auth");
  const hypotheses = activeHypotheses(graph as never);
  const potential = potentialMap(graph);
  const convergences = Number((state.usage as { session_convergences?: number } | undefined)?.session_convergences || 0);

  const lines: string[] = [];
  lines.push(`# 阻碍分析与防御测绘 · ${meta.target || "目标"}`);
  lines.push("");
  lines.push(`- 会话：\`${meta.session_id || "-"}\``);
  lines.push(`- 停止原因：\`${meta.stopReason || "macro_frustration"}\``);
  lines.push(`- 本场焦点收口：${convergences} 次`);
  lines.push(`- 任务：完成 ${by("completed").length} · 阻塞 ${blocked.length} · 失败 ${failed.length} · 未结束 ${pending.length}`);
  lines.push(`- 图：${Object.keys(graph.nodes).length} 节点 / ${Object.keys(graph.edges).length} 边 · 死胡同 ${deadEnds.length} · 鉴权/拦截边 ${blockedEdges.length} · 活跃假设 ${hypotheses.length}`);
  lines.push("");
  lines.push("> 这份报告不谈漏洞。它回答一个问题：**为什么没打进去，下次该从哪进。**");
  lines.push("");

  lines.push("## 一、被阻塞的任务及原因");
  if (!blocked.length) lines.push("（无）");
  for (const task of blocked) {
    lines.push(`### ${task.id}${task.playbook ? ` · ${task.playbook}` : ""}`);
    lines.push(`- 目标：\`${task.target || "-"}\``);
    lines.push(`- 目的：${task.purpose || "未记录"}`);
    // 结案说明优先取 outcome_reason（"为什么被阻止"）；`reason` 是创建时的意图，
    // 拿它兜底会让每个受阻任务都显示"当初想做什么"，看起来像没写原因。
    const why = String(task.outcome_reason || "").trim() || (task.status === "blocked" || task.status === "failed" ? "未记录（只标了状态，没写原因）" : String(task.reason || "未记录"));
    lines.push(`- 收口原因${task.outcome_code ? `（${task.outcome_code}）` : ""}：${why}`);
    const cited = task.outcome_evidence_ids?.length ? task.outcome_evidence_ids : task.evidence_ids;
    if (cited?.length) lines.push(`- 已有证据：${cited.slice(0, 6).join(", ")}`);
    else lines.push(`- 已有证据：（无引用）`);
  }
  lines.push("");

  lines.push("## 二、死胡同与拦截面");
  if (!deadEnds.length) lines.push("（没有节点被标死）");
  for (const node of deadEnds.slice(0, 20)) {
    lines.push(`- \`${node.id}\` · ${String((node.properties || {}).note || "反复同特征响应")}`);
  }
  if (blockedEdges.length) {
    lines.push("");
    lines.push("被鉴权/拦截的边（这些是「有东西但够不着」的地方）：");
    for (const edge of blockedEdges.slice(0, 20)) {
      const code = (edge.properties || {}).status_code;
      lines.push(`- ${edge.source_id} → ${edge.target_id}（${edge.type}${code ? ` · HTTP ${code}` : ""}）`);
    }
  }
  lines.push("");

  lines.push("## 三、未验证完的假设");
  if (!hypotheses.length) lines.push("（无活跃假设）");
  for (const hypothesis of hypotheses.slice(0, 15)) {
    lines.push(`- [${hypothesis.kind}] ${hypothesis.text}`);
    if (hypothesis.nodes?.length) lines.push(`  - 相关节点：${hypothesis.nodes.slice(0, 5).join(", ")}`);
  }
  lines.push("");

  lines.push("## 四、仍然可达的攻击面（势能最低的点）");
  const reachable = [...potential.entries()].sort((a, b) => a[1] - b[1]).slice(0, 10);
  if (!reachable.length) lines.push("（没有任何节点能连到高价值目标：图的连通性本身就是结论——目标被彻底隔离）");
  for (const [id, cost] of reachable) {
    lines.push(`- \`${id}\` · 势能 ${Math.round(cost * 10) / 10}（越小越接近高价值目标）`);
  }
  lines.push("");

  lines.push("## 五、攻击图（死胡同与拦截边高亮）");
  lines.push("");
  lines.push("```mermaid");
  lines.push("flowchart LR");
  const nodeIds = Object.keys(graph.nodes).slice(0, 60);
  const index = new Map(nodeIds.map((id, position) => [id, `n${position}`]));
  for (const id of nodeIds) {
    const node = graph.nodes[id]!;
    const label = id.replace(/"/g, "'").slice(0, 46);
    const style = node.status === "dead_end" ? ":::dead" : node.status === "vulnerable" ? ":::vuln" : node.type === "identity" ? ":::identity" : "";
    lines.push(`  ${index.get(id)}["${label}"]${style}`);
  }
  for (const edge of Object.values(graph.edges).slice(0, 80)) {
    const from = index.get(edge.source_id);
    const to = index.get(edge.target_id);
    if (!from || !to) continue;
    const code = Number((edge.properties || {}).status_code || 0);
    const blocked = code === 401 || code === 403 || edge.type === "requires_auth";
    lines.push(blocked ? `  ${from} -.->|${edge.type} ${code || ""}| ${to}` : `  ${from} -->|${edge.type}| ${to}`);
  }
  lines.push("  classDef dead fill:#ffe0e0,stroke:#c00,stroke-dasharray:3 3");
  lines.push("  classDef vuln fill:#e0ffe0,stroke:#080");
  lines.push("  classDef identity fill:#e0e8ff,stroke:#008");
  lines.push("```");
  lines.push("");
  lines.push("实线 = 已验证的发现关系；虚线 = 被 401/403 挡住的边（这才是防御测绘的产出）。");
  lines.push("");

  lines.push("## 六、下次的入口建议");
  const advice: string[] = [];
  if (blockedEdges.length) advice.push(`${blockedEdges.length} 条边需要身份：先解决"从哪拿 Token"（登录入口/客户端硬编码/其他子域的宽松 Cookie），再回来打这些边。`);
  if (hypotheses.length) advice.push(`有 ${hypotheses.length} 条假设没验完：优先挑"只需一个已知参数"的（IDOR / logic_bypass），它们最便宜。`);
  if (potential.size) advice.push(`势能最低的节点是最短路径的入口：\`${reachable[0]?.[0] || "-"}\`（成本 ${reachable[0] ? Math.round(reachable[0][1] * 10) / 10 : "-"}）。`);
  if (!blockedEdges.length && !deadEnds.length) advice.push("既没被拦也没死胡同却打不动：多半是打法选错了（工具都在回 200，但没人看响应差异）。人工过一遍 Evidence Ledger 的响应体。");
  if (!advice.length) advice.push("证据不足，建议人工从 Evidence Ledger 的时间线重新看一遍。");
  for (const item of advice) lines.push(`- ${item}`);
  lines.push("");
  lines.push("---");
  lines.push("由 Nianyun 在会话熔断（macro_frustration）时自动生成，未经人工复核。");

  return {
    markdown: lines.join("\n"),
    counts: {
      blocked: blocked.length, failed: failed.length, pending: pending.length,
      dead_ends: deadEnds.length, blocked_edges: blockedEdges.length,
      hypotheses: hypotheses.length, convergences,
    },
  };
}

/** 一次熔断里能拿到的"最优势能"，用于事件留痕。 */
export function bestPotentialOf(state: Record<string, unknown>): number | undefined {
  return bestPotential(graphState(state.graph as never));
}
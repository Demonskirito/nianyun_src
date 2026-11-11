import { z } from "zod/v4";
import { evidenceUrls } from "./facts.js";
import { normalizePath } from "./urlnorm.js";
import { chainMermaid, killChainForTarget, type AttackGraphState } from "./graph/index.js";

const text = z.string().trim().min(1).max(8000);
export const findingSchema = z.object({
  id: z.string().trim().min(1).max(200), title: text, type: text, target: z.string().url(),
  description: text, impact: text, severity: z.enum(["info", "low", "medium", "high", "critical"]),
  reproduction_steps: z.array(text).min(1).max(50), evidence_ids: z.array(text).min(1).max(100),
  remediation: text, confidence: z.enum(["low", "medium", "high"]),
});
export type Finding = z.infer<typeof findingSchema> & {
  status: "candidate" | "needs_evidence" | "reviewed" | "confirmed" | "rejected";
  review?: { actor: string; reason: string; evidence_ids: string[]; at: number };
  /**
   * 证据引用无效、被隔离出报告正文（quarantine.ts）。
   *
   * 刻意**不动 status**：`confirmed` / `rejected` 是评审发生过的历史事实，
   * 改它等于篡改账本。报告按这个标志把它挪到附录，并写明"原计划收录，因引用
   * 不存在被自动过滤"——既不交付站不住的结论，也不假装它从没存在。
   */
  quarantined?: boolean;
  quarantine_reason?: string;
  quarantine_code?: string;
  quarantined_at?: number;
};

export function validateFinding(finding: z.infer<typeof findingSchema>, evidence: Record<string, unknown>[]): string | undefined {
  const referenced = finding.evidence_ids.map(id => evidence.find(e => e.id === id));
  if (referenced.some(e => !e)) return "候选发现引用了不存在的会话证据";
  // 用 href 全等比较会让重定向、尾斜杠、以及越权场景里的"另一个 id"全部引用失败，
  // 而报错只说"必须引用该目标成功的原始工具结果"，模型无从自查。
  const sameTarget = (a: string, b: string): boolean => {
    try {
      const left = new URL(a); const right = new URL(b);
      return left.host === right.host && normalizePath(left.pathname).path === normalizePath(right.pathname).path;
    } catch { return a === b; }
  };
  if (!referenced.some(e => e?.kind === "tool-result" && (e.data as Record<string, unknown>)?.ok === true
    && evidenceUrls(e).some(url => sameTarget(url, finding.target)))) return "候选发现必须引用该目标成功的原始工具结果";
  return undefined;
}

/**
 * 报告里的 Kill Chain：只有图里真有的资产才给路径。
 *
 * 图缺失（旧会话/无图）时返回空数组，报告退回原来的纯步骤形态——
 * 绝不能凭空编一条"看起来很像"的路径，那是最坏的一种谎。
 */
function killChainOf(graph: AttackGraphState | undefined, target: unknown): string[] {
  if (!graph || graph.version !== 1 || !graph.nodes) return [];
  const url = String(target || "");
  if (!url) return [];
  try {
    return killChainForTarget(graph, url)?.chain || [];
  } catch {
    return [];
  }
}

// Report uses durable facts only. A read-only review does not establish exploitability.
export function blackboxReport(session: Record<string, unknown>): { json: Record<string, unknown>; markdown: string } {
  const checkpoint = (session.checkpoint || {}) as { tasks?: Record<string, { status: string; outcome_reason?: string; reason?: string; evidence_ids?: string[]; audit_ids?: string[]; evidence_status?: string; evidence_status_reason?: string; stripped_refs?: Array<{ field: string; dropped: string[] }> }>; findings?: Record<string, Finding>; stopReason?: string; graph?: AttackGraphState; deliverables_waived?: Array<{ task_id: string; items: string[] }> };
  const evidence = (session.evidence || []) as Record<string, unknown>[];
  const allFindings = Object.values(checkpoint.findings || {});
  /**
   * 报告主体只收"证据链闭合"的结论（2026-11-06）。
   *
   * 被隔离的发现（引用了不存在的证据）不进正文，但也不消失：附录逐条列出
   * "原计划收录 X，因引用 Y 不存在被系统自动过滤"。读者因此知道两件事——
   * 这条确实被提出过，以及为什么不该信它。静默丢弃是最坏的做法：报告看起来干净，
   * 而实际上有一条结论被无声抹掉，没人知道发生过什么。
   */
  const findings = allFindings.filter(finding => !finding.quarantined);
  const quarantined = allFindings.filter(finding => finding.quarantined);
  const unverifiedTasks = Object.entries(checkpoint.tasks || {})
    .filter(([, task]) => String(task?.evidence_status || "") === "unverified")
    .map(([id, task]) => ({ id, reason: String(task.evidence_status_reason || "证据引用无效，已从账本摘除") }));
  // `action:<hash>` 是单次工具调用的记账伪任务，不是计划任务：写进报告只会让读者看到一串哈希。
  const tasks = Object.entries(checkpoint.tasks || {}).filter(([id]) => !id.startsWith("action:")).map(([id, task]) => ({ id, ...task }));
  // 豁免只在结案成功时入账，所以这里每一条都是"模型申报做不到、控制面审计后放行"的交付物。
  // 报告必须写出来，否则读者会把"结论成立"误读成"该任务完整交付"。
  const waived = (checkpoint.deliverables_waived || [])
    .filter(entry => entry?.task_id && Array.isArray(entry.items) && entry.items.length);
  const json = { version: "blackbox-summary-v1", session_id: session.id, target: session.target, status: session.status,
    stop_reason: checkpoint.stopReason, assessment: tasks.length && tasks.every(t => t.status === "completed") ? "计划任务已完成；不代表目标安全或全面覆盖" : "部分完成的评估",
    tasks, deliverables_waived: waived.map(entry => ({ task_id: entry.task_id, items: [...entry.items] })), findings: findings.map(f => ({ ...f, kill_chain: killChainOf(checkpoint.graph, f.target), screenshots: evidence.filter(e => e.kind === "artifact" && f.evidence_ids.includes(String((e.data as Record<string, unknown>)?.result_evidence_id))).map(e => ({ evidence_id: e.id, path: e.artifact_path })) })),
    // 机器可读的隔离清单：正文之外，但同样在交付物里。
    ...(quarantined.length || unverifiedTasks.length ? {
      quarantined: [
        ...quarantined.map(f => ({ kind: "finding", id: f.id, title: f.title, code: f.quarantine_code, reason: f.quarantine_reason, evidence_ids: f.evidence_ids })),
        ...unverifiedTasks.map(task => ({ kind: "task", id: task.id, code: "EVIDENCE_UNVERIFIED", reason: task.reason })),
      ],
    } : {}) };
  const safe = (v: unknown) => String(v ?? "").replace(/[\\`*_{}\[\]<>#|]/g, "\\$&").replace(/\r?\n/g, " ");
  /**
   * 证据反查：按 `data.task_id` 把账本证据归到任务上（2026-11-05）。
   *
   * 结案契约上线前写下的 blocked 任务没有 `evidence_ids`，报告只能显示"（无）"，
   * 而它的请求其实都在账本里躺着——读者要的是"凭什么这么判"，不是"没记录"。
   * 有引用就信引用，没有就从账本反查；两边都空才写"（无）"。
   */
  const evidenceByTask = new Map<string, string[]>();
  for (const item of evidence) {
    const taskId = String((item.data as Record<string, unknown> | undefined)?.task_id || "");
    const evidenceId = String(item.id || "");
    if (!taskId || !evidenceId) continue;
    const list = evidenceByTask.get(taskId) || [];
    list.push(evidenceId);
    evidenceByTask.set(taskId, list);
  }
  const lines = ["# 黑盒漏洞 Summary", "", `目标：${safe(session.target)}`, `评估：${json.assessment}`, `停止原因：${safe(checkpoint.stopReason)}`, "", "## 任务覆盖", ""];
  for (const task of tasks) {
    /**
     * 每条任务都要能回答"为什么是这个状态"（2026-11-05）。
     *
     * 旧实现取 `outcome_reason || reason`：`reason` 是创建时的"为什么派这个任务"，
     * 于是 blocked 任务在报告里显示的是当初的意图，看起来像"没有结案原因"；
     * 更糟的是部分收口路径把机器码写进了 `outcome_reason`（`focus_stalled`），
     * 读者只得到一行 `blocked · focus_stalled`。
     * 现在：状态后面跟结案码，说明优先取 outcome_reason；确实没有就明写"未记录"，
     * 让缺口暴露出来，而不是用创建理由糊过去。
     */
    const code = String((task as { outcome_code?: string }).outcome_code || "");
    const status = String(task.status || "");
    const settled = status === "blocked" || status === "failed";
    const cited = (task as { outcome_evidence_ids?: string[] }).outcome_evidence_ids;
    const proofList = cited?.length ? cited : task.evidence_ids?.length ? task.evidence_ids : evidenceByTask.get(task.id) || [];
    // 一条任务动辄几十条证据：全列出来会把整段报告变成一堵哈希墙，反而没人看。
    const proof = proofList.length > 4 ? `${proofList.slice(0, 3).join(", ")} 等 ${proofList.length} 条` : proofList.join(", ");
    /**
     * 未结案的任务不写"结果说明"：它还没有结果。
     * 旧实现把 `reason`（"为什么派这个任务"）填在同一栏，读者会把它当成结论，
     * 于是 pending 任务看起来"有说明"，blocked 任务看起来"说明与状态对不上"。
     */
    if (!settled && status !== "completed") {
      const tail = (task as { settled?: string }).settled === "not_reached" ? " · 未开展（预算未轮到）" : "";
      lines.push(`- ${safe(task.id)} · ${safe(status)}${tail} · 未结案 · 目的：${safe(task.reason) || "（未记录）"} · 执行证据：${safe(proof) || "（无）"}`);
      continue;
    }
    const why = String(task.outcome_reason || "").trim() || (settled ? "（未记录结案原因）" : String(task.reason || "").trim());
    const unverifiedNote = String((task as { evidence_status?: string }).evidence_status || "") === "unverified"
      ? " · 结论未经证据支撑（引用无效，已隔离）" : "";
    lines.push(`- ${safe(task.id)} · ${safe(status)}${code ? ` · ${safe(code)}` : ""} · ${safe(why)}${unverifiedNote} · 执行证据：${safe(proof) || "（无）"} · 审计引用：${safe(task.audit_ids?.join(", ")) || "（无）"}`);
  }
  if (waived.length) {
    lines.push("", "## 部分交付物未达成", "", "以下交付物由模型对照证据后申报做不到，控制面审计后放行。结论成立，但覆盖面存在缺口，需人工确认。", "");
    // 交付物与任务 id 都是标识符（post_surface_xxx / exposed_endpoint 这类），
    // 包成代码块比 markdown 转义下划线更好读。
    for (const entry of waived) lines.push(`- \`${String(entry.task_id).replace(/`/g, "")}\` · 未达成：${entry.items.map(item => `\`${String(item).replace(/`/g, "")}\``).join(", ")}`);
  }
  lines.push("", "## 候选发现与复核", "", "confirmed 由 Observer 依据可复现证据裁决（人工可覆盖）；needs_evidence 表示证据链未闭合；rejected 表示被证伪。确认不代表已复测第三方系统。", "");
  if (!findings.length) lines.push("没有记录候选漏洞；不能据此认定目标安全。");
  for (const finding of json.findings) {
    lines.push(`### ${safe(finding.title)}`, "", `状态：${finding.status} · 风险：${finding.severity} · 可信度：${finding.confidence}`, `目标：${safe(finding.target)}`, `类型：${safe(finding.type)}`, `描述：${safe(finding.description)}`, `影响：${safe(finding.impact)}`);
    // 攻击路径放在复现步骤之前：先看"这条路怎么走过来的"，再看按钮级步骤。
    const chain = killChainOf(checkpoint.graph, finding.target);
    if (chain.length > 1) {
      lines.push("", "攻击路径（历程图）：", "", chain.map((node, i) => `${i + 1}. ${node}`).join(" → "), "", "```mermaid", chainMermaid(chain), "```");
    }
    // 复现步骤标题放在攻击路径之后：先看路，再看按钮级步骤。
    lines.push("", "复现步骤：");
    finding.reproduction_steps.forEach((step, i) => lines.push(`${i + 1}. ${safe(step)}`));
    lines.push("", `证据：${safe(finding.evidence_ids.join(", "))}`, `截图证据：${safe(finding.screenshots.map(s => s.evidence_id).join(", "))}`, `修复：${safe(finding.remediation)}`, `复核：${safe(finding.review?.actor)} · ${safe(finding.review?.reason)}`, "");
  }
  /**
   * 附录：被自动隔离的结论（2026-11-06）。
   *
   * 放在正文之后、并且明确写"不计入结论"：读者既不会误信它，也不会以为报告被
   * 无声剪辑过。每一条都要能回答三个问题——原本要报什么、哪里不成立、怎么被处置的。
   */
  if (quarantined.length || unverifiedTasks.length) {
    lines.push("## 附录：被自动隔离的结论", "",
      "以下内容曾计划进入报告正文，但引用的会话证据在账本里不存在（或该引用的没引），"
        + "已由系统过滤，**不计入本次评估结论**。原始记录保留在账本与事件流中，供人工复核。", "");
    for (const finding of quarantined) {
      lines.push(`- 发现 \`${String(finding.id).replace(/`/g, "")}\` · ${safe(finding.title)}（风险 ${safe(finding.severity)}）`,
        `  原引用：${safe(finding.evidence_ids.join(", ")) || "（无）"}`,
        `  隔离原因：${safe(finding.quarantine_reason) || "证据引用无效"}（${safe(finding.quarantine_code) || "EVIDENCE_INVALID"}）`);
    }
    for (const task of unverifiedTasks) {
      lines.push(`- 任务 \`${String(task.id).replace(/`/g, "")}\` · 结论未经证据支撑`,
        `  隔离原因：${safe(task.reason)}`);
    }
    lines.push("");
  }
  return { json, markdown: lines.join("\n") };
}

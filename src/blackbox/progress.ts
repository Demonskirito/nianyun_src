import { createHash } from "node:crypto";
import type { BlackboxToolRequest, BlackboxToolResult } from "./tools.js";
import { requestHeaders, requestHeadersWithDropped } from "./tools.js";
import { canonicalTool } from "./aliases.js";
import { normalizePath, normalizeBody, routeTemplate, type RouteMemory } from "./urlnorm.js";
import { detectAnomaly, observationOf, type AnomalyAlert, type AnomalyObservation } from "./anomaly.js";
import { samePurpose } from "./task-fingerprint.js";
import { isAnonymousWallRequest, CREDENTIAL_DATA_KEYS } from "./credential.js";
import { CONSISTENCY_PLAYBOOKS, evaluateRequirements, isVulnPlaybook } from "./vuln-predicates.js";
import type { DeclarationHostState } from "./site-declaration.js";

/** 证据 id 形如 ev-03d12a0975caa819（16 位十六进制）。 */
const EVIDENCE_REF = /ev-[0-9a-f]{16}/g;

/**
 * ② 背压前移（2026-11-07）：任务簿满时，同一 host + 同一「可合并探测」playbook
 * 的任务不必再开一条 pending。对照会话里 9/8 队列每轮都因 task_backlog_full 被拒，
 * 模型只会原样重发同一批声明，transition-rejected 占 31/40 轮。
 * 折叠不是丢信息：被折的 id / target / purpose 进已有任务的 folded_samples，
 * 并在 planMergeLog 与 task_aliases 里留痕，后续引用新 id 会解析回老任务。
 *
 * 白名单刻意收窄：idor / logic_bypass / auth_wall 这类「一个对象一条结论」的任务
 * 合并就等于丢攻击面，不能折。key 带 playbook，避免 content_review 折进 retest。
 */
const FOLDABLE_PLAYBOOKS = new Set(["content_review", "retest_for_status", "data_flow"]);
function foldableReviewKey(spec: Record<string, string>): string | undefined {
  const playbook = String(spec.playbook || "").trim().toLowerCase();
  const id = String(spec.id || "");
  const purpose = String(spec.purpose || "");
  const isReview = FOLDABLE_PLAYBOOKS.has(playbook)
    || /content_review|retest_for_status|data_flow/i.test(id)
    || /内容审阅|正文巡检|content review|状态复测/i.test(purpose);
  if (!isReview) return undefined;
  try {
    const host = new URL(String(spec.target || "")).host.toLowerCase();
    return host ? `${host}|${playbook || "generic"}` : undefined;
  } catch { return undefined; }
}

/**
 * 身份记账字段（credential_mode/source）是「这次请求带没带我方凭证」的元数据，
 * 不属于结果内容：放进去重指纹会让同一 URL 的匿名/带凭证对照被误判成"新信息"，
 * 也会让罐无关的重复探针意外洗掉 repeated_without_new_information 计数。
 */
function withoutCredentialMetadata(data: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...data };
  for (const key of CREDENTIAL_DATA_KEYS) delete copy[key];
  return copy;
}

/** 端点级归一：去尾斜杠、去 fragment、小写。没有 scheme/host 的裸路径原样比较。 */
function normalizeUrl(raw: string): string {
  const text = String(raw || "").trim().toLowerCase();
  if (!text) return "";
  return text.replace(/#.*$/, "").replace(/\/+$/, "");
}

/**
 * 过于通用的交付物名：出现在任何任务里都不代表同一件事。
 * 实测 T3（证书 SAN 横向铺面）与 T2_im_surface_discovery（本体路径发现）都带 `endpoint_list`，
 * 但一个是"去同族域名上找入口"、一个是"把 404 外壳翻译成路径清单"，合并就是吃掉一条攻击面。
 */
const GENERIC_DELIVERABLES = new Set([
  "endpointlist", "jscontent", "evidenceids", "hostlist", "hostfingerprints",
  "baselineheaders", "responsebodyfingerprint", "techfingerprint",
]);

/** 交付物归一：`catch_all_verdict` 与 `catchall_verdict` 是同一个东西（模型重写任务时命名会飘）。 */
function normalizeDeliverable(raw: unknown): string {
  return String(raw ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** 两边都写明的、非通用的交付物交集。用于打法标签互相矛盾时判断是不是同一件活。 */
function sharedSpecificDeliverables(a: unknown, b: unknown): string[] {
  const left = (Array.isArray(a) ? a : []).map(normalizeDeliverable).filter(Boolean)
    .filter(item => !GENERIC_DELIVERABLES.has(item));
  const right = new Set((Array.isArray(b) ? b : []).map(normalizeDeliverable).filter(Boolean));
  return [...new Set(left.filter(item => right.has(item)))];
}

/**
 * 这条转移错误属于"任务已终态就再没有意义"的那一类吗？
 *
 * 这些码只在**一次**转移尝试里有意义：任务一旦落到 completed/blocked/failed，
 * 模型再也没有输出能"修复"它们，留着只会让验收永远报 VALIDATION_ERRORS_REMAIN。
 *
 * `completion_without_verdict`（2026-11-10 补）：它记的是"标 completed 却拿不出 verdict"
 * 的那一次打回。打回时任务被退回 pending，所以当时它是**真错误**；但任务后来被收口成
 * blocked（前提消失 / 预算 settle）之后，这条记录就再没有任何输出能修它——模型重交结案
 * 走的是 `["blocked","failed"].includes(record.status)` 那条分支，只会产生另一条
 * `completion_without_valid_task_evidence`（本来就可剪）。旧码表漏了这个码，实测
 * `1dd9ded9ed239711` 因此每轮停场，8 条 pending 任务一条都推不动。
 */
const TERMINAL_SCOPED_ERRORS = /^(anomaly_requires_diff|completion_without_valid_task_evidence|completion_without_verdict|completion_on_denied_evidence|outcome_without_evidence_reference|closure_deliverables_unmet|closure_deliverables_partial|invalid_task_transition):(.+?)(?::[a-z_]+)?$/;
function isTerminalTransitionError(error: string, terminal: Set<string>): boolean {
  const match = TERMINAL_SCOPED_ERRORS.exec(error);
  return Boolean(match && terminal.has(match[2]!));
}

/**
 * 延后登记的人话说明（2026-11-10）。
 *
 * 控制面自己写的账不能是纯机器码：`outcome_reason` 的判据会把 `advice_disposal_only`
 * 这类值判成"不是说明"（TASK_OUTCOME_NOT_EXPLAINED），于是我们一边写码一边被自己的门禁拦。
 */
function deferNote(reason: string): string {
  return `已登记延后（${reason}）：本轮不执行这个请求，下一轮从检查点继续。`;
}

/** 从一段文本里抽出被引用的证据 id（去重）。R4 的唯一判据。 */
export function evidenceReferenceIds(text: unknown): string[] {
  const matches = String(text ?? "").match(EVIDENCE_REF) || [];
  return [...new Set(matches)];
}

/**
 * 模型自报的负向结论（verified-negative）。
 *
 * 实跑 b7142138263c586d（第五场，im.ctrip.com）里 T2 把 15 条 404/13B/sha256 指纹 + 四组
 * 机器对照写成了 `blocked`，理由开头就是 "verified-negative：im.ctrip.com 无未授权可读端点"。
 * 状态落成 blocked 之后：结案审计不跑、交付物申报不走、Observer 复核不触发，报告里
 * 任务覆盖只显示 "T2 · blocked"，整场 113 次调用被判成"部分完成的评估"。
 *
 * 语义上 blocked = "缺条件、没做完"，verified-negative = "做完了，结论是没有"，
 * 这两件事共用一条桶就是账本失真。凡理由里**明确自报** verified-negative 的，
 * 一律按结案归位（只认这一个显式词，不做"无洞/不存在"这种语义猜测）。
 */
const NEGATIVE_VERDICT = /verified[\s_-]?negative/i;

/**
 * 统一负向结论的写法：`verified-negative:` / `verified_negative:` 一律归一成
 * `verified_negative: …`。
 *
 * 报告、门禁、`completion_proof` 都按这个前缀读；模型两种写法都出现过
 * （第七场写 `verified-negative:`，第六场写 `verified_negative:`），
 * 不归一会让"这条到底算不算负向结案"取决于哪个正则先匹配上。
 * 只处理**出现在开头**的写法，句中顺带提到的不动——那不是在结案。
 */
function normalizeVerdictReason(reason: unknown): string {
  const text = String(reason ?? "").trim();
  if (!/^[\s:：]*verified[\s_-]?negative/i.test(text)) return text;
  const rest = text.replace(/^[\s:：]*verified[\s_-]?negative[\s:：\-—_]*/i, "").trim();
  return `verified_negative: ${rest || text}`;
}

/**
 * R5 结案审计：声明过的交付物有没有逐条认领。
 *
 * 不做语义判断——那不是代码能做的事。这里只守结构底线：
 *   ① 任务声明了 deliverables，结案必须在 task_outcomes[].deliverables_met 里逐条认领；
 *   ② 认领了但漏项，明确指出漏了哪几条；
 *   ③ 没声明交付物的任务不拦（否则升级后所有老任务都收不了口）。
 * 契约本身"该不该有"由提示词负责（runtimeRules 已强制要求），代码只审"说了就要做到"。
 */
function closureAudit(
  task: string,
  record: { deliverables?: string[]; success_criteria?: string; completion_criteria?: string; contract_required?: boolean },
  outcome: { deliverables_met?: string[] | boolean; deliverables_unmet?: Array<{ item: string; reason: string }> } | undefined,
  /** 本条结案引用的证据条数：全豁免时要求它是"一组"而不是"打了一下"。 */
  evidenceCount = 0,
  /**
   * 同一条任务被"交付物未认领"打回过几次。
   *
   * 实跑 090e71cc2732165e 里 T1 连续 3 轮都撞在同一处：模型反复说"提交 T1 completed"，
   * 但它的 deliverables（render_xhr_list / exposed_endpoint）在纯 404 站点上拿不到，
   * 而它又不去写 deliverables_unmet。打回文案已经点名了缺项与两条出路，仍然原地打转——
   * 这时候继续打回只是在烧轮次。第 3 次起按"控制面代为申报未达成"记账，放行并留痕。
   */
  priorRejects = 0,
): { code: string; severity: "error" | "warning"; message: string; hint: string; detail?: string; waived?: string[] } | undefined {
  // 历史任务（直接写进 checkpoint 的、升级前建的）不做契约审计：只约束由 required_tasks 新起的任务。
  if (!record.contract_required) return undefined;
  const declared = (record.deliverables || []).map(item => item.trim()).filter(Boolean);
  if (!declared.length) return undefined;
  // deliverables_met 允许 boolean（true = 全部达成，schema 已放开）：这里统一成数组再比对。
  const met = (Array.isArray(outcome?.deliverables_met) ? outcome.deliverables_met : outcome?.deliverables_met === true ? declared : [])
    .map(item => String(item).trim()).filter(Boolean);
  // 认领要"逐条"，但允许 true 一次性全认（模型实测就这么写）。
  const unmet = declared.filter(item => !met.some(done => done.toLowerCase() === item.toLowerCase()));
  /**
   * 逃生门：模型逐条申报"这项做不到 + 理由"的，不再要求认领。
   *
   * 为什么必须有：目标整个是 catch-all 404 时，「抽取前端 JS 里的接口前缀」这类交付物
   * **物理上不成立**。没有这个出口，诚实结案只有两条路——撒谎把没做的写成做到，
   * 或者被门禁卡到控制面强制 blocked（实跑 768287bceb5e2e01 就是这么烧掉 9 轮的）。
   * 申报项会进 completion_proof 留痕，验收侧报一条 warning，不会静默消失。
   */
  const waivedReason = new Map<string, string>();
  for (const entry of outcome?.deliverables_unmet || []) {
    const item = String(entry?.item ?? "").trim();
    const why = String(entry?.reason ?? "").trim();
    if (item && why) waivedReason.set(item.toLowerCase(), why);
  }
  const waived = unmet.filter(item => waivedReason.has(item.toLowerCase()));
  const stillUnmet = unmet.filter(item => !waivedReason.has(item.toLowerCase()));
  /**
   * 兜底：被"未认领"打回过、这次仍然没认领的，控制面代为申报。
   *
   * 判据不变（证据还要够），只是不再要求模型自己写出 deliverables_unmet——
   * 它显然写不出来。放行时按 warning 留痕，报告里能看到"哪几项是被控制面记成未达成的"。
   *
   * 为什么阈值是"被打回过一次"而不是三次：实跑 d56b08402bbf49ab 里计数器只涨到 1，
   * 而事件流里有 3 次打回——Observer 审查会用旧快照替换 `progress.state`，计数器跟着回滚。
   * 计数器本身不可靠，改用"上一条记录已经是 rejected"这个二元事实（它随快照一起回滚，
   * 回滚后至多退化成"还没打回过"，不会误判成"打回很多次"）。
   */
  if (priorRejects >= 1 && evidenceCount >= 2 && stillUnmet.length) {
    return {
      code: "CLOSURE_DELIVERABLES_WAIVED",
      severity: "warning",
      message: `closure_deliverables_auto_waived:${task}`,
      hint: `已连续 ${priorRejects + 1} 次未认领这几项，控制面代为记成"未达成"并放行结案：${stillUnmet.join(" / ")}。`,
      detail: stillUnmet.map(item => `${item} —— 模型 ${priorRejects + 1} 次未认领，按控制面兜底记未达成`).join("；"),
      waived: stillUnmet,
    };
  }
  // 一项都没认领：打回——除非它申报了全部未达成，并且手上真的"有一组证据"。
  // 下限 2 条是为了堵"打一下就说全都做不到"的免费出口（与 verified_negative 同口径：
  // 一条 401 不是"鉴权正确"，一条 404 也不是"整站是空壳"）。
  if (!met.length && (!waived.length || evidenceCount < 2)) {
    return {
      code: "CLOSURE_DELIVERABLES_UNMET",
      severity: "error",
      message: `closure_deliverables_unmet:${task}`,
      hint: met.length || !waived.length
        ? `结案前请用 task_outcomes[].deliverables_met 逐条认领交付物：${declared.join(" / ")}。`
          + `确实做不到的项改写进 task_outcomes[].deliverables_unmet（逐条 item + reason），控制面会按"已验证的负向结论"记账。`
        : `你申报了全部交付物未达成，但只有 ${evidenceCount} 条证据：至少要有 2 条互相印证的观测（例如多条不同路径的响应）才能把"都做不到"当结论。`,
      detail: met.length || !waived.length ? `未认领：${declared.join(" / ")}` : `证据不足：${evidenceCount} < 2`,
    };
  }
  // 有既没认领、也没申报豁免的：这才是真"漏了"，打回并点名缺哪几条。
  if (stillUnmet.length) {
    return {
      code: "CLOSURE_DELIVERABLES_UNMET",
      severity: "error",
      message: `closure_deliverables_partial:${task}`,
      hint: `以下交付物未认领：${stillUnmet.join(" / ")}。`
        + `做到就写进 deliverables_met；做不到就写进 task_outcomes[].deliverables_unmet（逐条 item + reason），别再空着。`,
      detail: `未认领：${stillUnmet.join(" / ")}`,
    };
  }
  // 剩下的都是"如实申报做不到"的项：不拦结案，但要留痕（warning 挂在验收 issues 上）。
  if (waived.length) {
    return {
      code: "CLOSURE_DELIVERABLES_WAIVED",
      severity: "warning",
      message: `closure_deliverables_waived:${task}`,
      hint: `已按申报记成未达成：${waived.join(" / ")}。报告里会标"部分交付物未达成"。`,
      detail: waived.map(item => `${item} —— ${waivedReason.get(item.toLowerCase())}`).join("；"),
      waived,
    };
  }
  return undefined;
}
import type { Finding } from "./findings.js";
import type { RecoveryRecord } from "./recovery.js";
import type { AcceptanceResult, ValidationIssue } from "./acceptance.js";
import { taskEvidenceIssue, taskAuditIssues } from "./task-evidence.js";
import { autoRepairOutcomeEvidence, settleTask } from "./task-outcome.js";
import { playbookById, stepForTool, type PlaybookRun } from "./playbooks.js";
import { bypassChannelOf, completionDenial, denialOf, hostOf, recordWallBypass, trackDenial, wallVerdict, type AuthWallState } from "./authwall.js";
import { identityWallOf, wallKind, wallSignature, type WallKind } from "./waf-ledger.js";
import { isHeavyTool } from "./weights.js";
import { autoSalvageReason, autoSkipReason, pendingAdviceView, salvageAdviceIds } from "./advice.js";
import { BLACKBOX_TOOL_ENUM, splitToolInput } from "./protocol.js";

export type TaskState = "pending" | "running" | "completed" | "blocked" | "failed";
export type AdviceDecision = { advice_id: string; accepted: boolean; reason: string; task_ids: string[] };
export type AdviceDecisionResult = { advice_id: string; status: "applied" | "already_applied" | "disposition_conflict" | "invalid_advice_decision" };
export type ObserverReview = { id: string; reason: "ordinary" | "validation_failed" | "terminal_review"; trigger_event_id: string; session_id: string; state_version: string; status: "pending" | "running" | "completed" | "failed"; created_at: number; attempts: number; issues?: unknown[]; result?: Record<string, unknown>; failure?: string; failure_fingerprint?: string; retryable?: boolean; completed_at?: number };
type TaskRecord = {
  status: TaskState; reason?: string; failures?: number; target?: string; purpose?: string; completion_criteria?: string;
  source?: string; evidence_ids?: string[]; audit_ids?: string[]; outcome_reason?: string;
  /**
   * 结案说明（2026-11-05）。blocked/failed 的**唯一**合法说明书，见 task-outcome.ts。
   *
   * 与 `reason` 的分工：`reason` 是创建时写的"为什么派这个任务"，只读；
   * 结案一律写 outcome_*，不再覆盖 `reason`（历史上 7 处收口把 `reason` 改成
   * `dead_end:ep:x` / `zero_entropy_diff`，创建意图全丢，报告只能显示一个机器码）。
   */
  outcome_code?: string;
  outcome_evidence_ids?: string[];
  outcome_at?: number;
  outcome_by?: "agent" | "control";
  /**
   * 收口标记（2026-11-05）：预算/熔断到达上限时由控制面写入，回答"这条为什么还没有结论"。
   *
   * `not_reached` = 一次都没派发过。这时**不改 status**（保持 pending：真的没做），
   * 只补一条账，让验收门知道"悬着的原因已经写明"，而不是把它当成"漏了"。
   * 直接把没打过的任务写成 blocked 是伪造结论（"这条不行"≠"没轮到"）。
   */
  settled?: "not_reached";
  /** 打法库 id，见 playbooks.ts。 */
  playbook?: string;
  /**
   * 结构化任务契约（R6）：交付物 / 成功判据 / 兜底路线。
   * 缺契约的任务在第一次结案时会被打回一次并附上"怎么补"，补完才放过（见 closureAudit）。
   */
  deliverables?: string[];
  success_criteria?: string;
  fallback_strategy?: string;
  /** 契约缺失的教学是否已经发生过（只打回一次，避免老任务永远收不了口）。 */
  contract_taught?: boolean;
  /** 只有由 required_tasks 新建的任务才做契约审计；历史任务豁免（否则升级后老任务全部收不了口）。 */
  contract_required?: boolean;
  /** 被语义去重吞噬掉的 id（见 merge() 的自动合并）。 */
  merged_from?: string[];
  /** 结案凭据（缺陷 4）：每次结案追加一条，任务记录本身永远不被抹除。 */
  completion_proof?: Array<{ at: number; reason: string; evidence_ids: string[]; deliverables_met: string[] | "all"; audit_ids?: string[] }>;
  /**
   * 证据状态（2026-11-06）：`unverified` = 这条任务的结论没有可核实的证据支撑
   * （引用不存在被摘掉，或者压根没引）。报告据此写"结论未经证据支撑"，
   * 验收据此把证据类错误降级为 warning——**看得见，但不拦住交付**。见 quarantine.ts。
   */
  evidence_status?: "unverified";
  evidence_status_reason?: string;
  /** 被摘掉的无效引用（原文留档，绝不静默丢弃）。 */
  stripped_refs?: Array<{ field: string; dropped: string[]; at: number }>;
};
/** 种子自检在某个 host 上的结论（见 blackbox/seedcheck.ts 的 SeedVerdict）。 */
export type SeedHealthRecord = {
  verdict: "healthy" | "seed_tainted" | "seed_stale" | "host_walled" | "inconclusive";
  /** 探测 URL（同一主机只测一个代表路径）。 */
  url?: string;
  /** 带凭证那一发的状态码。 */
  seeded?: number;
  /** 匿名那一发的状态码。 */
  anonymous?: number;
  /** 被隔离出来、已从罐里剔除的 Cookie 名（seed_tainted 才有）。 */
  tainted?: string[];
  /** 是否改成过种子文件（改过会写 .bak）。 */
  seed_rewritten?: boolean;
  /** 自检一共发了几发请求。 */
  probes?: number;
  /** 结论成立时项目 Cookie 罐的指纹（见 credential.ts）。罐变了结论即失效。 */
  jar_fingerprint?: string;
  at: number;
  detail?: string;
};
/** 一次格式被拒的回执：带允许键与示例，下一轮直接进上下文（见 tool-guide.ts）。 */
export type DropReceipt = {
  field: string; index: number; message: string;
  tool?: string; dropped_keys?: string[]; allowed_keys?: string[]; hint?: string;
};
export type RunCheckpoint = {
  version: 1;
  rule_version?: number;
  rule_hash?: string;
  /** Tools the active rules document allowed to run credential attacks when this run started. */
  credential_tools?: string[];
  /** Problems found in the rules document; the ignored values are listed here. */
  rule_issues?: string[];
  findings?: Record<string, Finding>;
  tasks: Record<string, TaskRecord>;
  planRevision?: number;
  /** 本轮是第几次 run（1 起）：图节点的 round 用它，历程图的横轴就是它。 */
  graphRound?: number;
  /**
   * 图分量漂移的欠账（见 graph/analyze.ts 的 component_drift）。
   *
   * 为什么要有：2026-10-28 note.yun 那轮系统连发 3 次"另有 224 块没动过，从这些 Root 开始"，
   * agent 三次都没采纳（继续打同一批 412 路径）。信号只是"提示"就一定会被忽略，
   * 所以这里记成欠账：累计到第 2 轮起，上下文里给出**可直接复制的工具请求模板**，
   * 让"采纳"从判断题变成填空题。
   */
  graph_drift?: {
    rounds: number;
    roots: string[];
    last_at: number;
    /** 这一批对应的桶（`host + 一级路径`，2026-11-10 S2-③）：轮换与计数都按它算。 */
    buckets?: string[];
    /** 这一批各条的分档（observed / unprobed / rewall / revived），面板据此解释"为什么要打这条"。 */
    tiers?: string[];
    /**
     * 降级原因（2026-11-07）。
     *
     * `template_only`：这一轮确实检测到漂移，但可提醒的入口全是 `{id}` 模板路径，
     * 过滤后一条可执行的都不剩。此时不再发"照抄这些 URL"，而是降级成提示；
     * 面板必须看到这个标记，否则它会一直显示上一轮的 roots，看起来像"巡检停了"。
     */
    degraded?: "template_only";
    /**
     * 已建议过的 root URL → 次数（2026-11-09，A2）。
     *
     * 老实现每轮都从"分量顺序前 6 个"里取前 3 条，图不变就永远吐同一批：
     * 对照组里那批 URL 已 404，巡检却催了 129 轮。这个计数器让换批有依据——
     * `rotate` 时优先给"从没被建议过"的端点。
     */
    suggested?: Record<string, number>;
    /** 这一批欠账对应的任务 id（按 roots 派生，采纳/解锁时用）。 */
    task_id?: string;
    /**
     * **这一批**在桌上待了几轮（2026-11-10）。
     *
     * `rounds` 是"欠账连续轮数"，换批不清零，可以跨好几个批次；所以拿它当"这批压了多久"
     * 会读出假数（一批刚换上来就显示 40 轮）。这个字段在 roots 集合变化时归 1，
     * 采纳/换批事件带上它，才能回答"建议发出后多少轮才被真的执行"。
     */
    batch_rounds?: number;
  };
  /**
   * 已建议过的漂移 root → 次数（2026-11-09，P3）。
   *
   * 为什么放在 `graph_drift` 外面：采纳时会把 `graph_drift` 整个清掉，计数跟着丢，
   * 下一轮 `rankDriftRoots` 又从全 0 开始——实际效果是"每次采纳后重排一次"，
   * 批次在两组 URL 之间来回切，每切一次就多写一条 graph-signal。
   * 计数只涨不落，属于跨欠账的长期账本，与"这一轮该打哪批"分开记。
   */
  graph_drift_suggested?: Record<string, number>;
  /**
   * 上次写 graph-signal 事件时的语义指纹（2026-11-09，P2）。
   *
   * 事件门禁不能看 `addInterrupts` 的返回值：插话池只有 12 格，`graph:*` 被一次性
   * 条目挤出后重新插入也算"新增"，于是同一批 roots 会重复落账（现场 15 分钟 7 条）。
   * 这里只记语义指纹，指纹没变就不写事件。
   */
  graph_signal_gate?: {
    prints: string[];
    quiet: boolean;
    /**
     * 停摆段（quiet）的段号（2026-11-10）。
     *
     * 为什么不能只用布尔：`quiet` 被"清空门禁"复位成 false 之后，下一轮它再出现
     * 又会被当成"首次"，于是同一条"连续无新节点"重复落账。段号让 quiet 拥有
     * **跨复位**的身份：复位只清 `prints`，段号保留；只有图真长过（quiet 断过）
     * 段号才 +1，新的停摆段才有资格再报一次。
     */
    quiet_epoch?: number;
    /** 连续多少轮没有 quiet（复位不清）。单轮缺失算抖动，不算换段。 */
    quiet_gap?: number;
    /** 上次写汇总事件时的图轮次；按图轮次计，采纳清零不影响它（2026-11-10）。 */
    summary_round?: number;
  };
  /**
   * 本巡检周期内是否出现过新节点（由 ingest 置位、由巡检消费并复位）。
   *
   * 为什么不直接数节点：图满 500 时节点总数恒定，`pruned` 又每轮都涨，
   * 两个计数都无法区分"图在长"和"原地打转"。这里只用一次性的布尔信号。
   */
  graph_growth_pending?: boolean;
  /**
   * 主权转移：301/302 跨主机跳转后，由控制面（不是模型）决定"目标已经换了"。
   * 见 blackbox/sovereignty.ts。写进上下文的是不可协商指令。
   */
  sovereignty?: { from_host: string; to_host: string; from_url: string; to_url: string; code: number; at: number; rewrites: string[] };
  /**
   * 跨主机跳转的候选记录（见 blackbox/sovereignty.ts 的 RedirectCandidate）。
   *
   * 存在的理由：跨主机 301 分"整站换域"和"单页迁移"两类，判定需要累积证据
   * （同一 (from,to) 至少 2 条不同路径才算整站）。只升级真迁移，单页迁移记在这里不动 tasks。
   * 不进模型上下文——它是判定依据，不是给模型的指令。
   */
  redirect_hops?: Array<{ from: string; to: string; code: number; at: number }>;
  /** SPA 外壳指纹：命中后对主机的步兵工具被缴械（见 blackbox/spa.ts）。 */
  spa?: { host: string; at: number; bytes: number; signals: string[]; task_id?: string };
  /** 字典抽样探针计划（见 graph/cluster.ts）：224 个节点折叠成 ≤5 个代表。 */
  dict_probe?: { host: string; total: number; at: number; task_id: string; buckets: Array<{ name: string; members: string[]; probe: string }> };
  /**
   * Burp 被动扫描账（见 blackbox/burp-scan.ts）。
   *
   * 21 场会话里 `burp.issues` 0 次调用：流量都过 Burp，被动扫描器早把响应审完了，
   * 但没人去读。这里记：启动过哪次审计（audit_id 可给 burp.scan_issues 用）、
   * 每次收账收了多少、哪些问题已经告诉过模型（避免同一轮反复插话）。
   */
  burp_scan?: {
    at: number;
    mode: "passive" | "active";
    ok: boolean;
    url?: string;
    audit_id?: string;
    error?: string;
    /** 收账（读 /issues）自己的失败原因：与"启动审计失败"是两件事，分开记。 */
    harvest_error?: string;
    seen?: string[];
    harvested_at?: number;
    total?: number;
    /** 站点地图里高/中危的条数（去重前的总数）：为 0 时"读了等于没读"，必须在上下文里说清。 */
    actionable?: number;
    /** 审计对象自己产出的问题条数（`/scan/issues`）：这是主动/被动审计真发过请求换来的那部分。 */
    scan_total?: number;
    /** 读审计问题失败的原因（Community 没有 Scanner）。和 harvest_error 分开记，别混成一个。 */
    scan_error?: string;
    /** 严重度分布：{information: 12, low: 8}。报告与上下文据此拒绝"报了 20 条问题"这种假话。 */
    severity?: Record<string, number>;
    /** 是否已经就"全是 info/low"解释过一次（只解释一次，之后不再占轮次）。 */
    quiet_reported?: boolean;
  };
  /**
   * 站点声明文件引水账（见 blackbox/site-declaration.ts）。
   *
   * 存在的理由：实测 5b59aa1d059b56da，`/sitemap.xml` 第一次 403 之后再没重试，
   * 站点自报的 18 个业务页整批丢失。这里按 host 记账：哪些文件拿到了终态、
   * 哪些还是"待重试"、上一轮是什么状态码、下一轮最早什么时候可以再打。
   * 不进模型上下文——它是控制面的调度依据，落到上下文的是任务与插话。
   */
  site_declaration?: Record<string, DeclarationHostState>;
  /** 被控制面强制劫持的焦点（sovereignty / spa / dict_probe）：优先于 sticky。只在被锁任务结案（completed/blocked/failed）时释放，不靠轮数定时器。 */
  forced_focus?: { task_id: string; kind: string; at: number; note?: string };
  /**
   * 主权转移后仍允许探的"旧 host 新路径"（上限 3）：
   * catch-all 判定需要 3 条同形 30x 才能成立，一刀切锁死会把真信号也挡掉。
   * 已探过的路径（图里有节点）一律拒收 —— 那才是纯重复。
   */
  sovereignty_fresh?: string[];
  /** 零熵熔断计数：recon.traffic_diff 连续返回 identical / diff_score=0 的次数（≥2 判 blocked）。 */
  zero_diff_streak?: number;
  plans?: Array<{ revision: number; created_at: number; task_ids: string[] }>;
  /** 语义重复任务的别名表：新 id → 已有任务的 id（见 task-fingerprint.ts）。 */
  task_aliases?: Record<string, string>;
  /** 自动吞噬日志：哪个新 id 被并进哪条老任务、补了哪些字段（替代原来的 task_duplicate 报警）。 */
  planMergeLog?: Array<{ at: number; dropped: string; into: string; fields: string[] }>;
  /** 任务簿满时因"承载未处置建议"而破例入簿的记录（见 merge 的 admitsAdvice）。 */
  backlog_admissions?: Array<{ at: number; task_id: string; backlog: number; limit: number }>;
  /** 任务簿满而被拒收的新任务（带出路提示，下一轮回灌上下文，见 merge）。 */
  backlog_rejects?: Array<{ at: number; task_id: string; pending: number; limit: number; deferred?: boolean }>;
  /**
   * ② 背压前移（2026-11-07）：簿满时**排队**而不是打回。旧实现每轮把同一条
   * `task_backlog_full:9/8` 塞进 transitionErrors，模型只会原样重发，80+ 轮零进展。
   * deferred 按 FIFO 在下一轮有空位时自动入簿，attempts 防止死规格永远占队列。
   */
  backlog_deferred?: Array<{ at: number; spec: Record<string, unknown>; attempts: number; round: number }>;
  /** 入队次数游标：desk 据此落 backlog-deferred 审计事件，resume / 同毫秒不重复。 */
  backlog_deferred_seq?: number;
  /** 事件流已落账到的游标。 */
  backlog_deferred_emitted_seq?: number;
  /** 任务簿水位（由 desk 从 rules.loop_control.task_pending_limit 写入，供上下文展示）。 */
  task_pending_limit?: number;
  /** 如实申报"做不到"的交付物（结案照过、报告标未达成，见 closureAudit 的逃生门）。 */
  deliverables_waived?: Array<{ at: number; task_id: string; items: string[] }>;
  /** 结案证据引用自动回填的审计账（desk 按未落账部分写 auto-repaired 事件）。 */
  outcomeAutoRepairs?: Array<{ seq: number; at: number; task_id: string; ids: string[]; matched: boolean; basis: string }>;
  /** 事件流已落账到的序号游标；用自增 seq 而非时间戳，避免同毫秒/日志截断导致重复或漏写。 */
  outcomeAutoRepairsEmittedSeq?: number;
  /** ④ 0 findings 时的覆盖度缺项（启发式清单，见 coverage.ts）；由监督器每轮刷新。 */
  coverage_gaps?: string[];
  /**
   * 假设推导调用账（2026-11-07）：只记数不写事件，供回放对比 deriveHypotheses 的调用量。
   * 对照会话 1dd9ded9ed239711 的 4502 条事件里 3532 条是 graph-hypothesis。
   */
  hypothesisRefresh?: { checked: number; skipped: number; ran: number; ranMs: number };
  /** 同一任务被"结案打回"的次数：连续 3 次以上由控制面兜底，不再要求模型自己改对。 */
  taskOutcomeRejects?: Record<string, number>;
  /**
   * 已终态任务被重交结案的记录（2026-11-10）。
   *
   * 这些提交**不再产生**拒收、错误与上下文信封，只留一份计数供调用方聚合播报一次
   * （"这条已经结了，别再交"）。长跑里模型每轮会把整份 task_outcomes 重放一遍，
   * 其中已 blocked 的条目占大头——拒它一次等于给模型一个"改对了就能过"的假信号。
   */
  taskOutcomeSkipped?: Array<{ task_id: string; status: string; at: number }>;
  /** 焦点锁：上一轮锁定的任务（非终态则本轮继续它，见 focus.ts）。 */
  focus_task_id?: string;
  /**
   * 焦点申诉账：整批请求连续两轮都指向同一条被拒任务时，焦点交接给它（见 desk 的 focus-appeal 分支）。
   *
   * 只记账不交接的版本会让 run 空转：2b92c7fad2779398 连续三轮"拒收 5/3/4 个、放行 0 个"，
   * 全场只跑 3 次调用。焦点契约的初衷是"一轮只推一件事"，不是"模型永远不能改主意"。
   */
  /**
   * 焦点申诉票（整批请求被焦点锁拒收时由 desk 记账）。
   *
   * `suspended` 是 2026-11-02 实跑（会话 6ee79b87a797904f）补的：forced_focus（SPA 缴械）
   * 在 computeFocus 里排在 appeal 之前，于是"连续三轮整批被拒"也照样被 forced 抢回焦点，
   * 4 轮 11 个请求零放行，40 次调用只用了 3 次就 stalled。挂起标记让 forced 让位一次，
   * 让位任务结案后 forced 自动恢复（forced_focus 字段本身不动）。
   */
  focus_appeal?: { task_id: string; votes: number; at: number; suspended?: boolean; suspended_from?: string };
  /**
   * 任务饥饿账（2026-11-05 加）：每个非终态任务"连续多少轮一条放行请求都没拿到"。
   *
   * 为什么要有：焦点锁 + sticky 焦点会让新任务永远排在队尾。实测会话 51f8d006a7192f24 里
   * content_review 任务全程 pending、37 次请求一条都没派到它——焦点一直在 T1 首页打转。
   * 改法 1（拒收带改投建议）只解决"模型不知道"，这里解决"模型知道也不动"。
   * 连续 `STARVATION_ROUNDS` 轮 0 派发 → 控制面强制把焦点交给它（focus-auto-handoff）。
   */
  task_starvation?: Record<string, { rounds: number; first_at: number; last_at?: number }>;
  /** 焦点微预算：这条任务花了几轮/几次调用、连续几轮无进展（见 focus-budget.ts）。 */
  focus_usage?: import("./focus-budget.js").FocusUsage;
  /** 已发出【强制收口】指令但模型还没照办（下一轮由代码兜底判 blocked）。 */
  focus_convergence?: import("./focus-budget.js").Convergence;
  /** 会话级熔断：全场收口次数到阈值后停止常规探测（见 focus-budget.ts）。 */
  macro_interrupt?: import("./focus-budget.js").MacroInterrupt;
  /** 后台 Observer 插话（System Interrupt）：只提示、不建 pending advice、不卡验收门。 */
  interrupts?: Array<{ id: string; kind: string; severity: "high" | "medium"; text: string; at: number; acknowledged?: boolean; repeats?: number; data?: Record<string, unknown>; fingerprint?: string }>;
  advice?: Record<string, { tasks: unknown[]; suggestions?: unknown[]; status: "pending" | "accepted" | "rejected" | "superseded"; reason?: string; task_ids?: string[];
    /** 连续几轮没被主 Agent 用 advice_decisions 签收（见 sweepAdvice）。 */
    misses?: number;
    /**
     * 纸面采纳：在**零动作回合**里被标 accepted（没有 tool_request、也没有任务状态变更）。
     *
     * 2026-11-02 实测 b9601629efd1f137：模型为了躲协议错误，一轮发 0 个请求就把建议标成
     * accepted，验收门禁看到 `openAdvice=0` 便认为"没有未办事项"，整场在 12/600 次调用时收工。
     * 签收只是记账，不是执行——这类采纳对门禁仍然算"未处置"，直到出现一次真实动作。
     */
    paper?: boolean;
    /** 由代码兜底归档（auto-skip / auto-salvaged），不是模型自己认的账。 */
    auto_skipped?: boolean; superseded_at?: number }>;
  validationErrors?: string[];
  transitionErrors?: string[];
  /** 上一轮被协议层丢弃的请求（带允许键 + 示例）：不做这件事，模型会连撞同一堵墙。 */
  drop_receipts?: DropReceipt[];
  /** 缺结构化契约（deliverables）的任务 id；每轮进上下文提示，补齐或终态后消失。 */
  contract_nudges?: string[];
  /** 被 schema 摘掉的键（请求照跑）：下一轮回执，避免同一个坑换静默方式复发。 */
  ignored_keys?: Array<{ field: string; index: number; tool: string; keys: string[]; valid_keys: string[]; hint: string }>;
  /** 死信队列：历史遗留 / 终态后不可修复的错误移到隔离区，不再计入 blocking_error_count。 */
  dlq?: Array<{ at: number; code: string; message: string; origin: "unrepairable" | "unrepairable:subject_dead" }>;
  adviceDecisionResults?: AdviceDecisionResult[];
  /** 上一轮从正文里抢救出来的建议 id（见 advice.ts）。 */
  adviceSalvaged?: string[];
  taskOutcomeResults?: Record<string, { status: "applied" | "rejected"; issues: ValidationIssue[] }>;
  retrievedEvidence?: Record<string, unknown>[];
  endpoints?: Record<string, { evidence_ids: string[]; task_ids: string[] }>;
  /** Agent 历程图（Attack Graph）：节点/边/假设，序列化进 checkpoint 跟着会话走。 */
  graph?: import("./graph/types.js").AttackGraphState;
  /** 最近打过的端点节点 id（时间倒序，最多 12 个）：Observer 图巡检据此判断"在哪儿转圈"。 */
  graphRecent?: string[];
  /** 按需寻路结果（新身份/新端点出现时才算一次）：下一步该打哪个接口。 */
  graphRoute?: {
    start: string;
    start_kind: "identity" | "endpoint";
    routes: Array<{ target: string; cost: number; next_hop: string; why: string; via: string[] }>;
    at: number;
  };
  actions: Record<string, { attempts: number; failures: number; unchanged: number; fingerprint?: string; inFlight?: boolean }>;
  seenResults: string[];
  stalledBatches: number;
  usage: { elapsedMs: number; toolCalls: number; agentTurns: number; tokens: number; cost: number; retries: number;
    /** 工具执行累计耗时（毫秒）。调度时间 = 墙钟 − toolMs，两者分开计预算。 */
    toolMs?: number;
    /** 本场会话触发的焦点收口次数（宏观熔断依据，见 focus-budget.ts）。 */
    session_convergences?: number;
    /** 全局申诉池余量（整场会话共享）。 */
    session_appeals_pool?: number;
    /** 目标平均延迟 EWMA（毫秒）：TP 通胀乘数的输入。 */
    avg_latency_ms?: number;
  };
  /** 本次运行的停止原因（failed / blocked / tasks_completed / macro_frustration 等）。 */
  stopReason?: string;
  /** 打法覆盖账本：每条 playbook 被调用几次、成功几次、走完哪些步骤（见 playbooks.ts）。 */
  playbook_runs?: Record<string, PlaybookRun>;
  /** 鉴权墙判定状态：同一主机连续被同样拒绝的不同入口数（见 authwall.ts）。 */
  auth_wall?: AuthWallState;
  /** 参数面熔断：同一路径打了多少次、参数变了几种、响应指纹只有几种。 */
  param_watch?: Record<string, { calls: number; queries: string[]; variants?: string[]; fingerprints: string[]; stalled_at?: number }>;
  /** 冒烟校验结果：会话开跑前对每个工具做一次空跑校验，失败项执行器直接拒绝。 */
  preflight?: { ok: boolean; checked_at: number; failed: string[]; skipped?: string[]; entries: Array<{ tool: string; ok: boolean; detail: string }> };
  /** 每个工具被成功执行过几次（联动判定用：OAST 起过没有、Burp 扫过没有）。 */
  tool_calls?: Record<string, number>;
  /** 排他任务：POST 面枚举被连续忽略后，只允许它（和认证链）继续执行。 */
  exclusive_task?: string;
  /** 排他锁的来源与时间，便于事件与上下文解释。 */
  exclusive_reason?: { task_id: string; since: number; ignored_turns: number };
  /** 异常响应观测窗口与最近一次告警（catch-all 跳转 / 统一响应体）。 */
  anomaly?: { recent: AnomalyObservation[]; seen_at?: number };
  anomaly_alert?: AnomalyAlert;
  /** 工具健康：连续 0 产出的工具会被禁用到会话结束，避免反复烧预算。 */
  tool_health?: Record<string, { zeros: number; disabled?: boolean; detail?: string; last_at?: number }>;
  /** 跨域 JS 来源（第三方 SDK / 统一认证域名），键是 host。 */
  cross_domain?: Record<string, { first_seen: number; from?: string; identity?: boolean }>;
  /**
   * 身份账本（2026-10-31）：键是身份名（anon / auth / 显式角色）。
   * 由 Cookie jar 判定，用来让越权结论有"双身份对照"这个前提，而不是靠模型自觉。
   */
  identities?: Record<string, { role: string; source: string; host: string; cookie_names: string[]; first_seen: number }>;
  /**
   * 死胡同拒收计数（2026-10-31）：键是图节点 id。
   * 第 2 次拒收同一节点时要把"指这条路"的任务收口并给出替代节点——
   * 实测会话 d87c3ea2c2d8eeba：http.request 被 dead_end 连拒 11 次，调用数直接从 14 冻住。
   */
  dead_end_rejects?: Record<string, number>;
  /** 终审"建议先打一轮再停"的放行次数（每次会话最多 2 次，防止永不收尾）。 */
  review_continue_count?: number;
  /**
   * 证据类校验失败已给过的修正次数（2026-11-06）。
   *
   * 门禁发现"引用的证据不存在"时不再直接停场，而是给模型几次带具体错误的修正机会，
   * 改不动才隔离（quarantine.ts）。计数写在 checkpoint 里而不是进程内变量：
   * resume 之后不该重新获得无限次机会，否则"改不动"这件事永远到不了隔离那一步。
   */
  evidence_repair_attempts?: number;
  /** OAST / Burp 联动任务的投递记录，避免每轮重复投递。 */
  /** OAST / Burp 联动任务账本：投递记录 + post_surface 的忽略计数。 */
  linkage?: {
    post_surface?: { task_id: string; ignored_turns: number; escalated_at?: number; disarmed?: boolean };
    oast_tasks?: string[];
    burp_scan_tasks?: string[];
    /** 异常响应派过的利用任务 id（避免同一告警重复投递）。 */
    anomaly_tasks?: string[];
    /** 已经派发过异常利用任务的 (kind:host)：catch-all 会持续存在，不能每轮重发三条。 */
    anomaly_key?: string;
    /** 已被 Fail-Fast 禁用的工具（只用于事件去重）。 */
    disabled_tools?: string[];
    /** 已报告过的登录门禁（kind:task），避免同一门禁重复写事件。 */
    auth_gates?: string[];
    /** 横向逃逸派过的任务（Plan B 只派一次）。 */
    lateral_tasks?: string[];
    /** WAF 阶梯派过的任务（先绕墙再逃逸，只派一次）。 */
    waf_tasks?: string[];
    /** 已经补过"根路径判墙一枪"的 host：同一主机只探一次，避免把预算花在复读上。 */
    waf_probe_hosts?: string[];
    /** 整场会话的补枪次数（上限 3）。 */
    waf_probe_count?: number;
    /**
     * 工具缺口：主 Agent 说"要是有 X 就能少走 N 轮"的地方。
     * need 归一化后去重（同一缺口不重复记），最多留 12 条，回灌到 context.tool_gaps。
     */
    tool_gaps?: Array<{ need: string; why?: string; tool?: string; alternative?: string; blocked_task?: string; missing?: boolean; at: number }>;
  };
  /** 路由模板学习记忆：同一位置出现过 ≥2 个取值才折叠成 {pN}。 */
  route_memory?: RouteMemory;
  /** 目标主域：跨域 JS 来源据此判断"是不是第三方"。 */
  target_host?: string;
  /** 登录门禁（验证码 / MFA / SSO / 滑块）：识别到就停手，别在登录页里死循环。 */
  auth_gate?: { kind: "captcha" | "mfa" | "sso" | "slider"; task?: string; detail?: string; at: number };
  /** 单主机被拦次数：WAF / 强鉴权累计到阈值就触发横向逃逸（Plan B）。 */
  blocked_hosts?: Record<string, { hits: number; kinds: string[]; at: number; last_fp?: string }>;
  lateral_escape?: { host: string; at: number; hits: number };
  /**
   * WAF 阶梯提示：同一 host 第 2 次命中拦截就先派 waf_bypass 任务，
   * 而不是等到 3 次直接横向逃逸。规则墙是可绕的，"换 host"是最后一档。
   *
   * `kind` 是墙的**性质**（见 waf-ledger.ts 的 WallKind），决定 desk 派哪种任务：
   *   - rule_wall     → 派 waf_bypass，跑 8 档阶梯（原来的行为）
   *   - identity_wall → 不派阶梯（payload 维度不参与判定，跑了必空），改派"拿身份"
   *   - unstable      → 不派阶梯（无墙可绕），降频重试
   * 缺省按 rule_wall 处理——老 checkpoint 没有这个字段，读入时必须保守地当成可绕。
   */
  waf_escalation?: { host: string; at: number; hits: number; marker?: string; kind?: WallKind };
  /**
   * 0 产出判墙：字典/爬虫一条都没扫到时，"没路径"和"整片被墙"在结果上长得一样。
   * 这里只登记"该补一枪根路径"，真正发请求由 desk 做（progress 不执行工具）。
   * 判据由 desk 落地：拦截码 + 两次指纹一致（或命中战例库同签名）才算墙。
   */
  waf_probe?: { host: string; url: string; reason: string; at: number };
  /**
   * 认证种子健康自检的结果（按 host）。
   *
   * 为什么必须有（2026-11-07）：种子里的 `cna` 把阿里云整站打成 403，
   * 系统把它当身份墙 → 整机拉黑 → 17M tokens 全打在水上。
   * 这里存的是"同一 URL 带凭证 vs 匿名"的对照结论，见 blackbox/seedcheck.ts。
   *
   * 判据的用处有两层：
   *   1. `seed_tainted` 的 host，`recordHostBlock` **不再累计**拦截次数——
   *      墙是我方造的，累计只会把自己越推越远；
   *   2. 没有结论的 host 撞墙时先登记一次自检（`seed_probe`），
   *      自检没跑完之前不允许升到横向逃逸（"别急着拉黑整机"）。
   */
  seed_health?: Record<string, SeedHealthRecord>;
  /**
   * 待执行的种子自检（progress 不执行工具，只登记；desk 负责发那一对请求）。
   * 与 `waf_probe` 同构：同一 host 只登记一次。
   */
  seed_probe?: { host: string; url: string; reason: string; at: number };
  /**
   * 当前项目 Cookie 罐指纹，由 desk 每轮从 DB 刷新写进来。progress 不碰 DB，
   * 但撞墙时要能判断「已有自检结论对应的是不是现在这罐」。
   */
  seed_jar_fingerprint?: string;
  /** 罐指纹变化后作废的旧结论留痕（只用于审计，不参与门禁判定）。 */
  seed_health_stale?: Record<string, { previous_verdict: string; old_fingerprint?: string; new_fingerprint?: string; at: number }>;
  /** 重检冷却窗口（毫秒）。开发环境可调短；默认 5 分钟，避免罐频繁抖动时每轮重检。 */
  seed_probe_cooldown_ms?: number;
  /** 最近一次参数面熔断的告警（供上下文与事件展示）。 */
  param_stall_alert?: { path: string; calls: number; queries: number; fingerprints: number; variants?: number; at: number };
  /** 本次运行需要立刻让 Observer 介入的事件（鉴权墙触发/拒绝结案）。 */
  auth_wall_alert?: { kind: "wall" | "denied_completion"; host?: string; tasks?: string[]; at: number };
  recovery?: RecoveryRecord;
  supervision?: {
    observerRuns: number;
    reviewPending?: boolean;
    reviews?: Record<string, ObserverReview>;
    terminalReviewVersion?: string;
    /** 连续几次 Observer 审查失败（成功一次即归零）。 */
    reviewFailures?: number;
    /**
     * Observer 连续 3 次审查失败后置真：审查被降级为"不可用"，验收不再要求它跑完。
     * 2026-11-02 实跑（8a2b134101b62649）：审查失败直接把 39/40 次调用、1 条 finding 的 run
     * 停成 observer_review_failed。Observer 是辅助，不是主循环的必要条件。
     */
    reviewUnavailable?: boolean;
    /**
     * 终止时被撤销的审查（2026-11-05）：run 已经收口，排队中的 Observer 审查不再有产出价值
     * （它审的是旧快照）。留着 `reviewPending` 会让验收门永远开不了口——实测 094d157f6fc028f6
     * 收口后停在 TERMINAL_REVIEW_PENDING + review-stale 循环，session 只能落 paused。
     * 记下撤销原因，验收按"审查不可用"同级处理，事件里留痕。
     */
    reviewDropped?: string;
    /** 已经交给 Observer 的鉴权墙告警时间，避免同一堵墙每轮都打断。 */
    authWallSeenAt?: number;
    /** 已经上报过的参数面熔断时间。 */
    paramStallSeenAt?: number;
    lastFingerprint?: string;
    /**
     * 同一批阻塞 issues 只排一次 Observer 审查（2026-11-07）。
     * 指纹存在 checkpoint 里、随 CAS 一起提交，多实例/多进程不会各记各的。
     * issues 被修好时清空，之后再出现同一批问题视为新一轮，允许重排。
     */
    lastReviewIssueFingerprint?: string;
    /** 上次按 issues 排队审查的时间与判据，供 review-deduped 事件审计。 */
    lastReviewIssueQueue?: { at: number; reason: string; fingerprint: string };
    /** 同一批 issues 连续判 stale 的次数（≥3 降级放行）；指纹变化即归零。 */
    staleStreak?: number;
    lastStaleFingerprint?: string;
    /** ④ 0 findings 覆盖度补审：最多 2 次、间隔 ≥20 轮，避免把收口无限推迟。 */
    coverageReviewCount?: number;
    coverageReviewAtTurn?: number;
    /**
     * 连续多少轮没有新节点进图（2026-11-07）。
     *
     * 图巡检原来只认「环路」和「分量漂移」两种拓扑信号。一旦可提醒的入口全是
     * `{id}` 模板路径、被过滤器丢光，巡检就彻底静默 —— 这正是"图卡住"最该出声的时候。
     * 这里按轮累计，到 3 轮就发一次兜底提示，保证"过滤到零"不等于"没有异常"。
     */
    graphQuietStreak?: number;
    warnings?: string[];
    coverage?: number;
    acceptance?: Pick<AcceptanceResult, "ready" | "pending" | "invalidEvidence"> & Partial<AcceptanceResult>;
  };
};

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, canonical(v)]));
  return value;
}
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(canonical(value)) ?? "null").digest("hex");
export const OBSERVER_VERSION_PREFIX = "sv2-";

/**
 * 旧版（黑名单式）状态版本：**只**用来兼容存量会话里已经落盘的 `state_version`。
 *
 * 它把 checkpoint 除了少数黑名单之外的所有字段都 hash 进去。每新增一个调度计数器
 * （task_starvation.rounds / focus_usage.turns / interrupts / seenResults /
 * hypothesisRefresh / outcomeAutoRepairs / graph.seenHypothesisIds …）都会让后台审查
 * 回来时判成 stale，2026-11-07 的对照会话里 15 次 review-stale 就是这么来的。
 * 保留实现是为了 resume 老会话时不把已完成的审查一笔勾销，不用于新审查。
 */
export function legacyObserverStateVersion(state: RunCheckpoint, evidence: Record<string, unknown>[] = []): string {
  const { supervision: _supervision, stopReason: _stopReason, usage: _usage,
    credential_tools: _credentialTools, rule_issues: _ruleIssues, playbook_runs: _playbookRuns,
    target_host: _targetHost, focus_task_id: _focusTaskId, task_pending_limit: _taskPendingLimit,
    graphRound: _graphRound, burp_scan: _burpScan, evidence_repair_attempts: _evidenceRepairAttempts,
    auth_wall: _authWall, ...material } = state;
  const facts = evidence.filter(e => !["agent-analysis", "observer-review", "run-summary"].includes(String(e.kind)))
    .map(e => ({ id: e.id, kind: e.kind, source: e.source, summary: e.summary, confidence: e.confidence, data: e.data, artifact_path: e.artifact_path, created_at: e.created_at }))
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
  return hash({ material, facts });
}

/** 只投影白名单键：运行期计数器 / 时间戳 / 插话一律不进语义版本。 */
const reviewPick = (value: unknown, keys: string[]): Record<string, unknown> => {
  const source = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of keys) if (source[key] !== undefined) out[key] = canonical(source[key]);
  return out;
};
const sortedIds = (value: unknown): string[] => Array.isArray(value)
  ? [...new Set(value.filter((item): item is string => typeof item === "string" && Boolean(item)).map(String))].sort()
  : [];
/**
 * pending ↔ running 是调度器的抢占/派发动作，不是任务结论变化。
 * 归一化后不会因为"派出去又收回来"作废一次已排队的审查（用户要求的 status 归一化）。
 */
const reviewTaskStatus = (status: unknown): string => {
  const raw = String(status || "unknown");
  return ["pending", "running", "queued", "in_progress"].includes(raw) ? "open" : raw;
};

/**
 * 语义状态版本：只认「会影响 Observer 结论的执行事实」。
 *
 * 白名单：任务结论与证据引用、发现、建议、阻塞错误集合、图的结构性事实、
 * 墙与身份判定结论、证据内容（含 data / summary / confidence，防漏审）。
 * 排除：usage / 轮次 / 焦点 / 饥饿计数 / 插话 / 时间戳 / 假设池 LRU 账 /
 * 协议回执 / 各种 seen* 计数 —— 它们每轮都变，却与"该审什么"无关。
 *
 * ⚠️ 新增执行事实字段时必须在这里登记，否则会漏审；新增调度元数据则不要登记。
 */
export function observerStateVersion(state: RunCheckpoint, evidence: Record<string, unknown>[] = []): string {
  const tasks = Object.fromEntries(Object.entries(state.tasks || {}).map(([id, raw]) => {
    const task = (raw || {}) as Record<string, unknown>;
    return [id, {
      status: reviewTaskStatus(task.status),
      evidence_ids: sortedIds(task.evidence_ids),
      outcome_evidence_ids: sortedIds(task.outcome_evidence_ids),
      ...reviewPick(task, ["outcome_code", "outcome_reason", "reason", "completion_criteria", "deliverables", "settled", "playbook", "target"]),
    }];
  }));
  const findings = Object.fromEntries(Object.entries(state.findings || {}).map(([id, raw]) => {
    const finding = (raw || {}) as Record<string, unknown>;
    return [id, {
      ...reviewPick(finding, ["id", "title", "type", "target", "status", "severity", "confidence", "description", "impact", "reproduction_steps", "remediation"]),
      evidence_ids: sortedIds(finding.evidence_ids),
    }];
  }));
  const advice = Object.fromEntries(Object.entries(state.advice || {}).map(([id, item]) =>
    [id, reviewPick(item, ["status", "reason", "tasks", "task_ids", "paper", "auto_skipped"])]));
  const outcomeResults = Object.fromEntries(Object.entries(state.taskOutcomeResults || {}).map(([id, record]) => [id, {
    status: record.status,
    // detail / basis 里带修正说明文本，只取稳定的定位字段，避免审计文本变化触发复审。
    issues: (record.issues || []).map(issue => JSON.stringify(reviewPick(issue,
      ["code", "severity", "path", "task_id", "advice_id", "evidence_id", "rule"]))).sort(),
  }]));
  const errors = {
    validation: sortedIds(state.validationErrors),
    transition: sortedIds(state.transitionErrors),
    contract_nudges: sortedIds(state.contract_nudges),
    outcomes: outcomeResults,
    dlq: sortedIds((state.dlq || []).map(item => `${item.code}:${item.message}`)),
  };
  const graph = state.graph ? {
    nodes: Object.entries(state.graph.nodes || {}).map(([id, raw]) => ({
      id, ...reviewPick(raw, ["type", "status", "origin"]),
      properties: reviewPick((raw as { properties?: unknown })?.properties,
        ["method", "status_code", "auth_required", "host", "role", "object_id", "object_ids"]),
    })).sort((a, b) => a.id.localeCompare(b.id)),
    edges: Object.entries(state.graph.edges || {}).map(([id, raw]) =>
      ({ id, ...reviewPick(raw, ["source_id", "target_id", "type", "rpc_tool"]) })).sort((a, b) => a.id.localeCompare(b.id)),
    // hypotheses 的 attempts / lastEvaluatedAt / seenHypothesisIds 是 LRU 账，不进版本。
    hypotheses: (state.graph.hypotheses || []).map(item => JSON.stringify(reviewPick(item,
      ["id", "kind", "status", "text", "severity"]))).sort(),
  } : null;
  const walls = {
    seed_health: Object.fromEntries(Object.entries(state.seed_health || {}).map(([host, record]) =>
      [host, reviewPick(record, ["verdict", "seeded", "anonymous", "tainted", "seed_rewritten"])])),
    blocked_hosts: Object.fromEntries(Object.entries(state.blocked_hosts || {}).map(([host, record]) =>
      [host, sortedIds(record.kinds)])),
    auth_gate: reviewPick(state.auth_gate, ["kind", "task", "detail"]),
    anomaly_alert: reviewPick(state.anomaly_alert, ["kind", "host"]),
    waf_escalation: reviewPick(state.waf_escalation, ["host", "kind"]),
    identities: Object.fromEntries(Object.entries(state.identities || {}).map(([id, record]) =>
      [id, reviewPick(record, ["role", "source", "host", "cookie_names"])])),
  };
  // 证据内容必须进版本：同一个 id 的 data / summary / confidence 变了，审查结论就可能变。
  // 但 created_at 是落库时间戳，和结论无关；模型旁白类证据是投影，不是执行事实。
  const facts = evidence.filter(e => !["agent-analysis", "observer-review", "run-summary"].includes(String(e.kind)))
    .map(e => JSON.stringify(reviewPick(e,
      ["id", "kind", "source", "summary", "confidence", "data", "artifact_path"]))).sort();
  return OBSERVER_VERSION_PREFIX + hash({ v: 2, tasks, findings, advice, errors, walls, graph, facts }).slice(0, 40);
}

/** 存量 review 的 state_version 是旧算法算出来的；两套都认，避免 resume 时一次性全判 stale。 */
export function observerStateVersionMatches(stored: unknown, state: RunCheckpoint, evidence: Record<string, unknown>[] = []): boolean {
  const value = String(stored || "");
  if (!value) return false;
  if (value.startsWith(OBSERVER_VERSION_PREFIX)) return value === observerStateVersion(state, evidence);
  return value === legacyObserverStateVersion(state, evidence);
}
export function observerReviewId(reason: ObserverReview["reason"], version: string, issues: unknown): string {
  const issueSet = Array.isArray(issues)
    ? [...new Map(issues.map(issue => [JSON.stringify(canonical(issue)), issue])).entries()]
      .sort(([a], [b]) => a.localeCompare(b)).map(([, issue]) => issue)
    : issues;
  return `review-${hash({ reason, version, issues: issueSet }).slice(0, 24)}`;
}
const names = (value: unknown): string[] => Array.isArray(value) ? [...new Set(value.filter((v): v is string => typeof v === "string" && Boolean(v.trim())).map(v => v.trim()))] : [];

// 漏洞确认类打法见 vuln-predicates.ts（唯一来源）。
//
// 旧版本这里手抄了一份 VULN_PLAYBOOKS，且名字与真实 playbook id 不符
// （command_injection / jwt_forgery / subdomain_takeover / business_logic / graphql
//  实际叫 cmdi / jwt_auth / cloud_supply / logic / graphql_ws），
// 于是"CMDI、JWT 伪造、子域接管、业务逻辑、GraphQL"这五类打法的门槛从未生效。
// 现在改成按谓词表反查，不再维护第二份名单。

/**
 * 一条 completed 任务是否具备可引用的结案 verdict：
 * - 交付/侦察型打法（spa_reverse）与未登记打法：完成即交付，豁免；
 * - 漏洞确认型打法：① 必须有一条 finding 覆盖本任务证据（结论被写下来）；
 *   ② **且该打法的确认谓词必须成立**（证据真的够，不是只有"请求发出去了"）。
 *
 * ② 是 2026-11-02 补的一层：在此之前"匿名 GET 返回 200"就能通过门槛成为一个
 * 合法 finding，而 playbook 里写的确认标准（"body 含敏感字段""凭证属于 A 却返回 B 的对象"）
 * 没有任何代码消费。谓词把标准变成可判定的，未通过时把**缺哪件证据**直接回给 agent。
 * verified_negative 负向结案在前面的 denial 分支处理，不会落到这里。
 */
function completionHasVerdict(
  output: Record<string, unknown>,
  state: RunCheckpoint,
  task: string,
  references: string[],
  evidence: Record<string, unknown>[],
  reason?: string,
): { ok: boolean; missing: string[] } {
  const playbook = String((state.tasks[task] as { playbook?: string } | undefined)?.playbook || "").toLowerCase();
  /**
   * 负向结论对**任何**打法都是合法 verdict——包括漏洞确认型打法。
   *
   * `unauth_exposure` 这类的确认谓词是 `anonymous_ok + sensitive_body`，都是"要看到东西"的
   * 正向条件；目标整个是 catch-all 真空壳时它永远不可能成立，而 finding 也不该凭空造。
   * 旧代码只让 401/403 那一路 denial 分支走负向结案，于是"证明了没有洞"反而比"发现了洞"
   * 更难结案：实跑 e8526ef215536256 里 T1 写了 verified_negative + 一组 404 同指纹对照，
   * 依然被 COMPLETION_WITHOUT_VERDICT 拒收，整场因此停在 VALIDATION_ERRORS_REMAIN。
   * 门槛不放松：负向结案要 ≥2 条证据（一条 404 不是"整站是空壳"）。
   */
  if (NEGATIVE_VERDICT.test(String(reason || ""))) {
    return references.length >= 2
      ? { ok: true, missing: [] }
      : { ok: false, missing: ["一组 ≥2 条互相印证的证据（含对照组）——负向结论不能只凭一次请求"] };
  }
  if (!isVulnPlaybook(playbook)) return { ok: true, missing: [] };
  const findingEvidence = new Set<string>();
  for (const f of [...(Array.isArray(output.findings) ? (output.findings as Array<{ evidence_ids?: string[] }>) : []), ...Object.values(state.findings || {})]) {
    for (const eid of (f.evidence_ids || []) as string[]) findingEvidence.add(eid);
  }
  if (!references.some(id => findingEvidence.has(id))) {
    return { ok: false, missing: ["一条引用本任务证据的 finding（确认漏洞）"] };
  }
  // 谓词用的是全场证据：diff verdict / 响应正文散落在各条 tool-result 里，
  // 按任务切反而会把"同一对象的两次对照"拆到两边导致永远凑不齐。
  const verdict = evaluateRequirements(playbook, evidence);
  if (verdict.registered && !verdict.satisfied) return { ok: false, missing: verdict.missing };
  return { ok: true, missing: [] };
}

export class BlackboxProgress {
  state: RunCheckpoint;
  /** 本轮是第几次 run（1 起）：历程图节点的 round 用它做横轴。 */
  graphRound = 1;
  /** 鉴权墙判定参数（rules.auth_wall），由 desk 在构造后注入。 */
  authWall: { streak_limit: number; codes: string[] } = { streak_limit: 3, codes: ["10403", "10401", "10402", "401"] };
  /** 参数面熔断阈值（rules.loop_control），desk 构造后注入。 */
  paramStall: { calls: number; queries: number; variants: number; ratio: number } = { calls: 5, queries: 3, variants: 3, ratio: 3 };
  /** 待处置建议上限（rules.loop_control.advice_pending_limit）。 */
  advicePendingLimit = 6;
  /** 待办任务上限（rules.loop_control.task_pending_limit）：超了就拒收新任务，逼它先收口。 */
  taskPendingLimit = 16;
  /** 鉴权墙放行通道（rules.auth_wall），desk 构造后注入。 */
  wallOptions: { safePaths: string[]; allowUnauthPlaybook: boolean; allowBypass: boolean } = { safePaths: [], allowUnauthPlaybook: true, allowBypass: true };
  /**
   * @param options.resume 是否按"会话重新开始"处理（默认 true）。
   *   只有真正的 run 启动/崩溃恢复才该把 in-flight 当作"结果未知"；
   *   同一进程内为了审查/对账而重读账本时，in-flight 只表示"正在跑"，
   *   当成未知结果会连带把真实任务判死——实测 8fa38aaa1cd6a72d 的 T1：
   *   Observer 每轮都 new 一次 Progress，恰好读到在飞的动作就把它标成
   *   interrupted_unknown_outcome，下一次同名 begin() 直接把 T1 打成 blocked，
   *   而那轮浏览器调用其实已经被拒收、什么都没发生。
   */
  constructor(saved?: unknown, options: { resume?: boolean } = {}) {
    this.state = saved && typeof saved === "object" && (saved as RunCheckpoint).version === 1
      ? structuredClone(saved as RunCheckpoint)
      : { version: 1, tasks: {}, actions: {}, seenResults: [], stalledBatches: 0, usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0, toolMs: 0 } };
    // 老 checkpoint 可能缺字段（升级/手工构造）：补齐后再走原有逻辑。
    this.state.tasks ??= {};
    this.state.actions ??= {};
    this.state.seenResults ??= [];
    this.state.stalledBatches ??= 0;
    this.state.usage ??= { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0, toolMs: 0 };
    /**
     * 旧格式的一次性插话 id 清理（2026-11-09，P1 迁移）。
     *
     * 旧代码把轮次拼进 id（`focus-auto-handoff:${round}` / `zero-action:${round}` /
     * `focus-redirect:${round}`），这些条目 ack 之后也不出列，恢复老检查点时池子里
     * 还躺着几条两小时前的历史——继续挤占 12 格窗口，把 `graph:*` 欠账顶出去。
     * 同一件事现在用稳定 id 表达，旧的直接扔。
     * 注意 `focus-auto-handoff:T_XXX`（带任务 id 的新格式）不匹配 `\d+$`，要保留。
     */
    if (Array.isArray(this.state.interrupts)) {
      this.state.interrupts = this.state.interrupts.filter(entry =>
        !/^(?:focus-auto-handoff|zero-action|focus-redirect):\d+$/.test(String(entry?.id || "")));
    }
    // In-flight tool actions have an unknown outcome: never silently replay them.
    if (options.resume !== false) for (const [key, action] of Object.entries(this.state.actions)) if (action.inFlight) {
      action.inFlight = false;
      this.state.tasks[`action:${key}`] = { status: "blocked", reason: "interrupted_unknown_outcome" };
    }
    /**
     * 迁移：把控制面写进去的**延后码**换成说明（2026-11-10）。
     *
     * `defer()` 以前把 `advice_disposal_only` / `budget_degraded` / `stage_timeout`
     * 直接写进 `outcome_reason`。这几个码是我们自己写的账，但结案说明的判据会把纯机器码
     * 判成 `TASK_OUTCOME_NOT_EXPLAINED`——于是控制面自己给验收门禁埋雷，实测
     * `1dd9ded9ed239711` 就有一个已 blocked 的任务顶着 `advice_disposal_only` 停了两场。
     * 源头已改（见 defer），这里把老账本上残留的同类值一并换成同一句话。
     */
    const DEFER_MARKERS = new Set(["advice_disposal_only", "budget_degraded", "stage_timeout"]);
    for (const task of Object.values(this.state.tasks)) {
      const reason = String(task.outcome_reason || "").trim();
      if (DEFER_MARKERS.has(reason)) task.outcome_reason = deferNote(reason);
    }
  }
  /** 待办任务数（pending + running）。 */
  pendingCount(): number {
    return Object.values(this.state.tasks).filter(task => task.status === "pending" || task.status === "running").length;
  }

  /**
   * 门禁口径的"未处置建议"数：pending 的，加上**纸面采纳**的（accepted 但那一轮零动作）。
   * 签收不是执行，见 advice 里的 `paper` 注释。
   */
  openAdviceCount(): number {
    return Object.values(this.state.advice || {})
      .filter(item => item.status === "pending" || (item.status === "accepted" && item.paper === true)).length;
  }

  /** 别名解析：模型用新 id 指同一件事时，落到已有任务上。 */
  resolveTaskId(id: string): string {
    let current = String(id || "");
    const aliases = this.state.task_aliases || {};
    // 别名链必须能收敛：手工/迁移留下 A→B→A 的环时，走到重复节点就停，别兜圈子。
    const seen = new Set<string>();
    for (let hop = 0; hop < 8; hop += 1) {
      if (seen.has(current)) break;
      seen.add(current);
      const next = aliases[current];
      if (!next || next === current) break;
      current = next;
    }
    return current;
  }

  /**
   * 已是同一件事的既有任务 id（含已终态的）；没有则返回 undefined。
   *
   * 终态任务也参与判重：模型每轮都会把"已 completed 的任务"在 required_tasks 里复述一遍
   * （它看到的是任务簿，不是"待办清单"）。对这种复述新建一条 pending，等于每轮给自己造一个
   * 永不结案的影子任务——实测 test/blackbox-observer-reliability 的 18 个用例就是这样从
   * `tasks_completed` 退化成 `required_review_pending` 的。真正要"换条路重开"时，
   * 模型会给出不同的 purpose（dead_end 另按签名放行），不靠同名新建。
   */
  duplicateOf(purpose: unknown, playbook = "", target = "", deliverables?: unknown): string | undefined {
    if (!String(purpose ?? "").trim()) return undefined;
    const host = hostOf(target);
    /** 同一个 host 下的不同端点仍是两件事：`/p0` 与 `/p1` 的任务文本可以只差一个数字。 */
    const url = normalizeUrl(target);
    for (const [id, task] of Object.entries(this.state.tasks)) {
      if (!task.purpose) continue;
      // 端点级否决：两边都点名了具体 URL、且不相等 → 不是重复任务（同 host 也一样）。
      const otherUrl = normalizeUrl(String(task.target || ""));
      if (url && otherUrl && url !== otherUrl) continue;
      const otherPlaybook = String(task.playbook || "");
      /**
       * 打法关系的三种情况要分开：
       *   两边都写了、且不同 → 明确的并行验证面（控制面自己会一次注入 host_header/open_redirect/takeover），
       *     哪怕共享 http.diff 这类模板术语也**不许合并**；
       *   一边没写 → 未知，不能当成"不同"就放弃判重（实跑 768287bceb5e2e01 的 T1-im-baseline 就这么漏的）；
       *   两边相同 → 正常放宽。
       * 但打法标签是模型自己写的，噪声很大：同一件"建基线 + 判 catch-all"的活，
       * 这一轮标 unauth_exposure、下一轮标 spa_reverse（实跑 7fbbc513e18b66b4 的
       * T1 / T1_im_baseline_catchall，两条各占一个焦点）。所以打法不同时再看一层**具体交付物**：
       * 交付物写的是"要交什么"，比打法标签诚实；共享一个具体交付物就是同一件活。
       */
      let playbookRelation = otherPlaybook === playbook || !otherPlaybook || !playbook;
      if (!playbookRelation) {
        const shared = sharedSpecificDeliverables(deliverables, (task as { deliverables?: unknown }).deliverables);
        if (!shared.length) continue;
        playbookRelation = true;
      }
      // 文本近似，或同打法 + 同目标 + 术语重合（阈值来源见 task-fingerprint.ts 文件头）。
      // sameTarget 用三态：两边都有 target 时判等，缺 target 时交回文本判据。
      const taskHost = hostOf(String(task.target || ""));
      const sameTarget = host && taskHost ? host === taskHost : undefined;
      if (samePurpose(purpose, task.purpose, playbookRelation, sameTarget)) return id;
    }
    return undefined;
  }

  /**
   * 语义重复的任务被吞噬时，把新声明里更完整的那部分并进老任务。
   * 只补空、只并集，绝不覆盖老任务已有的判断——模型换个说法重复登记，不该把已落账的契约改坏。
   *
   * `allowUnion=false` 只用于「同 id 重新声明」这条路径（见 merge 的第一个分支）。
   * 交付物在那里**只能补空、不能并集**：实测 b7142138263c586d 的 T1 被反复重声明，
   * 每轮把别的任务的交付物（sensitive_path_probe_result / exposed_endpoint /
   * response_body_fingerprint）并进来，契约从 5 项涨到 8 项，其中 3 项 T1 根本不该做，
   * 于是结案时永远"未认领"，连打回 3 次才靠控制面兜底放行。
   * 契约漂移的代价是整整 3 轮，而模型"想加新交付物"的正确表达是新建任务，不是改老任务。
   */
  private absorbTaskSpec(target: TaskRecord, spec: Record<string, unknown>, playbook: string, allowUnion = true): string[] {
    const fields: string[] = [];
    const incoming = (Array.isArray(spec.deliverables) ? spec.deliverables as unknown[] : [])
      .map(item => String(item).trim()).filter(Boolean).slice(0, 8);
    if (incoming.length) {
      const union = allowUnion ? [...(target.deliverables || [])] : [];
      if (allowUnion) {
        for (const item of incoming) if (!union.some(existing => existing.toLowerCase() === item.toLowerCase())) union.push(item);
        if (union.length !== (target.deliverables || []).length) { target.deliverables = union.slice(0, 8); fields.push("deliverables"); }
      } else if (!(target.deliverables || []).length) {
        target.deliverables = incoming.slice(0, 8); fields.push("deliverables");
      }
    }
    for (const key of ["success_criteria", "fallback_strategy"] as const) {
      const value = String(spec[key] ?? "").trim();
      if (value && !String(target[key] ?? "").trim()) { target[key] = value.slice(0, 500); fields.push(key); }
    }
    if (playbook && !target.playbook) { target.playbook = playbook; fields.push("playbook"); }
    const id = String(spec.id || "").trim();
    if (id) target.merged_from = [...(target.merged_from || []), id].slice(-8);
    // 契约补齐了就把提示撤掉（提示只服务"缺什么"，不缺了还挂着就是噪音）。
    if ((target.deliverables || []).length) this.dropContractNudge(id);
    return fields;
  }

  /** 从"待补契约"清单里移除（终态、被补齐、被合并时调用）。 */
  dropContractNudge(id: string): void {
    if (!id || !this.state.contract_nudges?.length) return;
    this.state.contract_nudges = this.state.contract_nudges.filter(item => item !== id);
  }

  /** 仍然缺结构化契约的 pending/running 任务（按登记顺序，最多 limit 条）。 */
  pendingContractNudges(limit = 6): string[] {
    const alive = this.state.contract_nudges || [];
    const next: string[] = [];
    for (const id of alive) {
      const task = this.state.tasks[id];
      if (!task) continue;
      if (["completed", "blocked", "failed"].includes(String(task.status))) continue;
      if ((task.deliverables || []).length) continue;
      next.push(id);
    }
    this.state.contract_nudges = next;
    return next.slice(0, limit);
  }

  merge(output: Record<string, unknown>, evidence: Record<string, unknown>[] = []): boolean {
    const before = hash(this.lists().completed_tasks);
    this.state.transitionErrors ??= [...(this.state.validationErrors || [])];
    // ② 迁移：存量会话里残留的 task_backlog_full 错误不再有对应的拒收路径，留着会让
    // transition-rejected 事件每轮重复播报同一句。一次性清干净，validationErrors 同步。
    if (this.state.transitionErrors.some(error => error.startsWith("task_backlog_full:"))) {
      this.state.transitionErrors = this.state.transitionErrors.filter(error => !error.startsWith("task_backlog_full:"));
      this.state.validationErrors = (this.state.validationErrors || []).filter(error => !error.startsWith("task_backlog_full:"));
    }
    // 每轮开账时把"待补契约"清单收敛一次（终态/已补齐的自动出列）。
    this.pendingContractNudges();
    const reject = (message: string) => {
      if (!this.state.transitionErrors!.includes(message)) this.state.transitionErrors!.push(message);
    };
    const resolve = (message: string) => { this.state.transitionErrors = this.state.transitionErrors!.filter(error => error !== message); };
    let changedPlan = false;
    /**
     * 冲突 2（2026-11-02 规则审计）：任务簿满时 `task_backlog_full` 拒收新任务，而"采纳建议必须带
     * 已存在的 task_id"（applyAdviceDecision）让建议只剩 rejected 一条路——两条规则合起来把 Observer
     * 的判断变成噪声。出路：**这次输出里 advice_decisions 点名的新任务**享有优先入簿权（最多 2 条、
     * 硬上限 limit+2）。它们承载的是一条已经存在的建议，不是又一轮重新规划。
     */
    const adviceTaskIds = new Set<string>();
    for (const decision of Array.isArray(output.advice_decisions) ? output.advice_decisions : []) {
      const ids = (decision as { task_ids?: unknown } | null)?.task_ids;
      if (!Array.isArray(ids)) continue;
      for (const id of ids) if (typeof id === "string" && id.trim()) adviceTaskIds.add(id.trim());
    }
    let adviceAdmitted = 0;
    /**
     * ② 背压不是拒收而是排队：上一轮因簿满暂缓的任务，在本轮腾出空位后按 FIFO 自动补入。
     * 每轮最多补 2 条，避免一次把簿子重新灌满；attempts ≥3 的死规格不再回灌。
     */
    const declared = (Array.isArray(output.required_tasks) ? output.required_tasks : []) as unknown[];
    const free = this.taskPendingLimit > 0 ? Math.max(0, this.taskPendingLimit - this.pendingCount()) : 2;
    const queue = this.state.backlog_deferred || [];
    const drained: typeof queue = [];
    while (drained.length < Math.min(2, free) && queue.length) {
      const entry = queue.shift()!;
      if ((entry.attempts || 0) < 3) drained.push(entry);
    }
    if (drained.length) {
      (this.state.planMergeLog ||= []).push({ at: Date.now(), dropped: "",
        into: drained.map(entry => String(entry.spec?.id || "")).filter(Boolean).join("、"),
        fields: ["backlog_deferred_admitted"] });
      if (this.state.planMergeLog.length > 40) this.state.planMergeLog = this.state.planMergeLog.slice(-40);
    }
    for (const item of [...drained.map(entry => entry.spec), ...declared]) {
      const spec = typeof item === "string" ? { id: item } : item as Record<string, string>;
      if (!spec?.id) continue;
      const playbook = typeof spec.playbook === "string" ? spec.playbook.trim().toLowerCase() : "";
      if (this.state.tasks[spec.id]) {
        // 已有任务：允许补契约（只补空、不覆盖），这是 closure_contract_missing 被打回后的修复通道。
        // 同 id 重声明**不并集交付物**（见 absorbTaskSpec 的 allowUnion 注释）：那是契约漂移的入口。
        const filled = this.absorbTaskSpec(this.state.tasks[spec.id]!, spec, playbook, false);
        if (filled.length) { (this.state.planMergeLog ||= []).push({ at: Date.now(), dropped: "", into: spec.id, fields: filled }); changedPlan = true; }
        continue;
      }
      // 语义去重：模型换个 id 再登记同一件事（"T6" → "T6_cors_verify" → "T20_cors_verify"）时，
      // 不要新增 pending，而是记别名，后续 tool_requests/task_outcomes 里出现新 id 时解析回已有任务。
      const duplicate = this.duplicateOf(spec.purpose, playbook, String(spec.target || ""), spec.deliverables);
      if (duplicate) {
        // 语义重复不是错误，是同义事件：以前 reject 一条 task_duplicate 只会把验收门禁
        // 卡在 TASKS_NOT_TERMINAL（实测 planRevision 19、26 条 blocked）。现在直接吞噬：
        // 把新声明里更完整的契约并进老任务，静默丢弃新 id。
        (this.state.task_aliases ||= {})[spec.id] = duplicate;
        const absorbed = this.absorbTaskSpec(this.state.tasks[duplicate]!, spec, playbook);
        (this.state.planMergeLog ||= []).push({ at: Date.now(), dropped: spec.id, into: duplicate, fields: absorbed });
        if (this.state.planMergeLog.length > 40) this.state.planMergeLog = this.state.planMergeLog.slice(-40);
        continue;
      }
      // 待办上限：任务簿塞满以后模型每轮都在"重新规划"，永远不会收口。
      const backlog = this.pendingCount();
      if (this.taskPendingLimit > 0 && backlog >= this.taskPendingLimit) {
        const admitsAdvice = adviceTaskIds.has(spec.id) && adviceAdmitted < 2 && backlog < this.taskPendingLimit + 2;
        if (!admitsAdvice) {
          // ② 同类可合并探测先折叠，不直接打回（保留明细样本，不做成纯计数合并）。
          const foldKey = foldableReviewKey(spec as Record<string, string>);
          const sibling = foldKey ? Object.entries(this.state.tasks || {}).find(([id, task]) => {
            if (!task || ["completed", "blocked", "failed"].includes(String(task.status || ""))) return false;
            return foldableReviewKey({ id, playbook: String(task.playbook || ""), purpose: String(task.purpose || ""), target: String(task.target || "") }) === foldKey;
          }) : undefined;
          if (sibling) {
            const [siblingId, siblingTask] = sibling;
            (this.state.task_aliases ||= {})[spec.id] = siblingId;
            const record = siblingTask as unknown as Record<string, unknown>;
            const samples = Array.isArray(record.folded_samples) ? record.folded_samples as unknown[] : [];
            record.folded_samples = [...samples, { id: spec.id, target: spec.target, purpose: String(spec.purpose || "").slice(0, 200) }].slice(-10);
            (this.state.planMergeLog ||= []).push({ at: Date.now(), dropped: spec.id, into: siblingId, fields: ["folded_mergeable_probe"] });
            if (this.state.planMergeLog.length > 40) this.state.planMergeLog = this.state.planMergeLog.slice(-40);
            continue;
          }
          // ② 簿满 ≠ 模型写错：排队而不是 reject。旧实现每轮往 transitionErrors 里塞
          // 同一条 task_backlog_full，模型只能原样重发（对照会话 31/40 轮被这条噪声占满）。
          const deferred = this.state.backlog_deferred ||= [];
          const already = deferred.find(entry => String(entry.spec?.id || "") === String(spec.id));
          if (already) {
            already.attempts += 1;
            already.at = Date.now();
          } else {
            deferred.push({ at: Date.now(), spec: { ...(spec as Record<string, unknown>) }, attempts: 1, round: Number(this.state.planRevision || 0) });
            this.state.backlog_deferred_seq = (this.state.backlog_deferred_seq || 0) + 1;
            (this.state.planMergeLog ||= []).push({ at: Date.now(), dropped: "", into: String(spec.id), fields: ["backlog_deferred"] });
          }
          if (deferred.length > 30) this.state.backlog_deferred = deferred.slice(-30);
          (this.state.backlog_rejects ||= []).push({
            at: Date.now(), task_id: spec.id, pending: backlog, limit: this.taskPendingLimit, deferred: true,
          });
          if (this.state.backlog_rejects.length > 5) this.state.backlog_rejects = this.state.backlog_rejects.slice(-5);
          continue;
        }
        adviceAdmitted += 1;
        (this.state.backlog_admissions ||= []).push({ at: Date.now(), task_id: spec.id, backlog, limit: this.taskPendingLimit });
        if (this.state.backlog_admissions.length > 20) this.state.backlog_admissions = this.state.backlog_admissions.slice(-20);
      }
      this.state.tasks[spec.id] = { status: "pending", target: spec.target, purpose: spec.purpose, reason: spec.reason,
        completion_criteria: spec.completion_criteria, source: "main-agent", contract_required: true, ...(playbook ? { playbook } : {}),
        // R6：结构化契约随任务一起落账；缺了会在第一次结案时被打回一次（见 closureAudit）。
        ...(Array.isArray(spec.deliverables) && spec.deliverables.length
          ? { deliverables: (spec.deliverables as unknown[]).map(item => String(item).trim()).filter(Boolean).slice(0, 8) } : {}),
        ...(String(spec.success_criteria || "").trim() ? { success_criteria: String(spec.success_criteria).trim().slice(0, 500) } : {}),
        ...(String(spec.fallback_strategy || "").trim() ? { fallback_strategy: String(spec.fallback_strategy).trim().slice(0, 500) } : {}) };
      // R6 提示：实测（2026-10-28）模型从不主动写 deliverables/success_criteria，40 条任务里 0 条带契约，
      // 于是结案审计根本没东西可审。缺契约就进"待补契约"清单，每轮出现在上下文里，直到补上或任务终态。
      if (!Array.isArray(spec.deliverables) || !(spec.deliverables as unknown[]).length) {
        (this.state.contract_nudges ||= []).push(spec.id);
      }
      changedPlan = true;
    }
    if (changedPlan) {
      this.state.planRevision = (this.state.planRevision || 0) + 1;
      (this.state.plans ||= []).push({ revision: this.state.planRevision, created_at: Date.now(), task_ids: Object.keys(this.state.tasks) });
      // 计划历史只留最近 5 份：每份都带全量 task_ids，19 份就是 7.5KB 的上下文噪音。
      if (this.state.plans.length > 5) this.state.plans = this.state.plans.slice(-5);
    }
    const outcomes = (Array.isArray(output.task_outcomes) ? output.task_outcomes : []) as Array<{ task_id: string; reason: string; evidence_ids: string[]; audit_ids?: string[]; deliverables_met?: string[] | boolean; deliverables_unmet?: Array<{ item: string; reason: string }> }>;
    // 模型可能用别名 id 报结：先解析回真实任务 id，否则完成声明会落到不存在的任务上。
    for (const outcome of outcomes) if (outcome && typeof outcome.task_id === "string") outcome.task_id = this.resolveTaskId(outcome.task_id);
    this.state.adviceDecisionResults = ((Array.isArray(output.advice_decisions) ? output.advice_decisions : []) as AdviceDecision[])
      .map(decision => this.applyAdviceDecision(decision));
    // 没被本轮签收的建议记一次 miss：连续两轮漏处置就由 sweepAdvice 自动归档，
    // 而不是让验收门禁把整场 run 掐掉（见 advice.ts）。
    const decided = new Set(this.state.adviceDecisionResults
      .filter(result => result.status === "applied" || result.status === "already_applied")
      .map(result => result.advice_id));
    // 只有**本轮新发生的** accepted 才可能是纸面采纳；重复声明（already_applied）不改账。
    const freshlyAccepted = new Set(this.state.adviceDecisionResults
      .filter(result => result.status === "applied")
      .map(result => result.advice_id));
    // 纸面采纳：本轮既没有工具请求、也没有任务结案，却把建议标成 accepted。
    // 这不是处置，只是记账；门禁仍把它算作未办，直到出现一次真实动作（见 desk 的 openAdvice）。
    const actedThisRound = (Array.isArray(output.tool_requests) ? (output.tool_requests as unknown[]).length : 0) > 0
      || names(output.completed_tasks).length > 0;
    for (const [id, item] of Object.entries(this.state.advice || {})) {
      if (item.status !== "accepted") continue;
      if (actedThisRound) { delete item.paper; continue; }
      if (freshlyAccepted.has(id)) item.paper = true;
    }
    for (const [id, item] of Object.entries(this.state.advice || {})) {
      if (item.status === "pending" && !decided.has(id)) item.misses = (item.misses || 0) + 1;
    }
    // 模型把 advice_id 写在正文 review 里却没进结构化字段：抢救出来，这一轮就归档。
    this.state.adviceSalvaged = salvageAdviceIds(String(output.summary || ""), Object.keys(this.state.advice || {}));
    /**
     * 豁免入账时机：**只在结案真的通过之后**。
     *
     * 旧写法把本轮所有 waiver 统一在 merge 末尾 flush，于是被打回的那次结案也照样记账：
     * 实跑 e8526ef215536256 里 T1 三次都没结成功（COMPLETION_WITHOUT_VERDICT），
     * `deliverables_waived` 里却已经躺着 T1 的 shell_baseline_headers，
     * 报告会说"部分交付物未达成"，而任务其实还是 pending。
     */
    const recordWaiver = (task: string, items: string[]): void => {
      const last = this.state.deliverables_waived?.at(-1);
      if (last && last.task_id === task && last.items.length === items.length
        && last.items.every((item, index) => item === items[index])) return;
      (this.state.deliverables_waived ||= []).push({ at: Date.now(), task_id: task, items: [...items] });
      if (this.state.deliverables_waived.length > 20) this.state.deliverables_waived = this.state.deliverables_waived.slice(-20);
    };
    for (const task of names(output.completed_tasks)) {
      const record = this.state.tasks[task];
      const outcome = outcomes.find(o => o.task_id === task);
      /**
       * 已终态（blocked / failed）任务又交了一次结案：**静默跳过**（2026-11-10）。
       *
       * 这类重交在长跑里是纯噪声：任务已经结案，系统没有"重新打开"的入口，所以每一次
       * 提交都必然被拒、必然写一条 `completion_without_valid_task_evidence`、必然把上一轮
       * 的 `taskOutcomeResults[task].issues` 又抬成验收阻塞项。实测 `1dd9ded9ed239711`
       * 每轮把 49 条 task_outcomes 全量重放，其中 `host_header_injection_*` 与
       * `H_auth_wall_a8e39f4d` 每次都撞在同一堵墙上，一轮就产 1–3 条被拒记录。
       *
       * 跳过而不是"照旧拒一次"：拒绝本身也是输出，它会让模型以为"改了什么就能过"。
       * 真正该说的是"这条已经结了，别再交"——由调用方聚合成一条事件说明一次。
       * 顺带清掉它名下的历史拒收明细，否则那些 issues 会从 `taskOutcomeResults`
       * 里继续被 acceptance 抬成阻塞（跨任务证据引用那条就是这么复活的）。
       */
      if (record && (record.status === "blocked" || record.status === "failed")) {
        delete this.state.taskOutcomeResults?.[task];
        delete this.state.taskOutcomeRejects?.[task];
        const log = (this.state.taskOutcomeSkipped ||= []);
        log.push({ task_id: task, status: String(record.status), at: Date.now() });
        if (log.length > 20) this.state.taskOutcomeSkipped = log.slice(-20);
        continue;
      }
      /**
       * 已结案的任务再声明一次：审计照跑（坏的重提交必须被拒，见 blackbox-task-evidence 的
       * "preserves previously valid completion on a bad resubmission"），但**不再记账**。
       *
       * 实测 b9882a565690c603 里 T1 被申报两次（第二次换了未达成项的措辞），
       * `completion_proof` 与 `deliverables_waived` 各多一条，报告于是说四项未达成，
       * 其中两项其实已被第一次结案覆盖。
       */
      const alreadyCompleted = record?.status === "completed";
      /** 本条任务被记成"未达成"的交付物：只在结案通过时入账（见 recordWaiver）。 */
      let waivedItems: string[] = [];
      const linked = evidence.filter(e => !taskEvidenceIssue(this.state, evidence, task, String(e.id), ""));
      const references = outcome?.evidence_ids || linked.map(e => String(e.id));
      const path = `task_outcomes.${outcomes.findIndex(o => o.task_id === task)}`;
      const issues = references.flatMap((id, index) => {
        const issue = taskEvidenceIssue(this.state, evidence, task, id, `${path}.evidence_ids.${index}`);
        return issue ? [issue] : [];
      });
      issues.push(...taskAuditIssues(evidence, task, outcome?.audit_ids || record?.audit_ids || [], `${path}.audit_ids`));
      if (!references.length) issues.push({ code: "TASK_EVIDENCE_MISSING", severity: "error", task_id: task, path: `${path}.evidence_ids`,
        rule: "completed_task_requires_execution_evidence", message: `task_evidence_missing:${task}` });
      // R4：结论必须引用证据 id。判据是"该任务的证据里有没有 ev 形态的 id"——
      // 有就必须点名引用（生产环境恒成立），单测里用 exec/audit 这类占位 id 时不触发。
      const citable = [...new Set([...references, ...linked.map(item => String(item.id))])].filter(id => /^ev-[0-9a-f]{16}$/.test(id));
      const cited = evidenceReferenceIds(String(outcome?.reason || ""));
      // 结构化 evidence_ids 已经点名证据时不再要求散文重复一遍；只有「写了结论、没给证据」才拦。
      // 完全没写 task_outcome 的情况交给上面的 TASK_EVIDENCE_MISSING / completion_criteria 判定。
      const structurallyCited = Boolean(outcome?.evidence_ids?.length);
      if (outcome?.reason && !structurallyCited && citable.length && !cited.some(id => citable.includes(id))) {
        issues.push({ code: "OUTCOME_WITHOUT_EVIDENCE_REFERENCE", severity: "error", task_id: task, path: `${path}.reason`,
          rule: "completed_task_requires_evidence_citation",
          message: `outcome_without_evidence_reference:${task}` });
      }
      // R5：结案审计——交付物有没有逐条认领、任务契约在不在（缺契约只教学一次）。
      // 上一轮这条任务已经被打回过（含"被打回后 Observer 用旧快照回滚"的情形）。
      const priorRejects = Math.max(this.state.taskOutcomeResults?.[task]?.status === "rejected" ? 1 : 0,
        this.state.taskOutcomeRejects?.[task] || 0);
      const closure = record ? closureAudit(task, record, outcome, references.length, priorRejects) : undefined;
      if (closure) {
        /**
         * `hint` 必须落到 `detail` 上（2026-11-02 结案死锁的根因）。
         *
         * 旧写法只塞了 `message: closure.message`，也就是一个 `closure_deliverables_partial:T1`
         * 这样的码，**"缺哪几项"全在 hint 里被丢掉**。模型看到的是"partial"却没拿到清单，
         * 只能猜着补，实跑 768287bceb5e2e01 里 4 次结案全撞在这堵看不见的墙上，
         * 最后由控制面强制 blocked 才收场。
         */
        issues.push({
          code: closure.code, severity: closure.severity, task_id: task, path: `${path}.reason`,
          rule: "closure_audit_requires_contract_and_deliverables",
          message: closure.message,
          detail: [closure.detail, closure.hint].filter(Boolean).join("；"),
        });
        if (closure.waived?.length) waivedItems = closure.waived;
      }
      // 只有 error 级 issue 才拦结案。warning（如"交付物已按申报记成未达成"）照过：
      // 它是给报告和操作员看的留痕，不是"模型写错了什么"。
      const blockingIssues = issues.filter(issue => issue.severity === "error");
      if (!record || ["blocked", "failed"].includes(record.status) || !references.length ||
        blockingIssues.length || (record.completion_criteria && !outcome?.reason)) {
        (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues };
        // 记一次打回：同一个交付物缺口连续打回三次以上就改由控制面兜底（见 closureAudit）。
        const rejects = this.state.taskOutcomeRejects ||= {};
        rejects[task] = (rejects[task] || 0) + 1;
        reject(`completion_without_valid_task_evidence:${task}`); continue;
      }
      // "发个请求被拒"不是完成：只有拒绝证据的结案改成 blocked_by_auth 并交 Observer。
      const denial = completionDenial(evidence, task, references, { NIANYUN_AUTH_WALL_CODES: this.authWall.codes.join(",") });
      // 一组探测"一致地证明该入口鉴权正确"是可交付的负向结论，不是受阻。
      // 不区分这两种，模型为了拿到 completed 会倾向于把"疑似"写成 finding —— 那是唯一会主动
      // 降低报告质量的惩罚。名单取 vuln-predicates 的单一事实源（与零熵熔断同源）。
      const negativeByDesign = CONSISTENCY_PLAYBOOKS.has(String(record.playbook || ""));
      // 至少要两条证据才算"一组探测"：只有一条 401 是"发了个请求被拒"，不是负向结论。
      // 这个下限是防"打一个接口就宣布验证完成"的捷径。
      if (denial.deniedOnly && denial.evidence >= 2 && negativeByDesign) {
        Object.assign(record, { status: "completed", evidence_ids: [...references],
          outcome_reason: `verified_negative: ${denial.denied}/${denial.evidence} 条证据一致指向鉴权正确（401/10403，无数据泄漏），结论是无该问题。` });
        (this.state.taskOutcomeResults ||= {})[task] = { status: "applied", issues: [] };
        resolve(`completion_without_valid_task_evidence:${task}`);
        continue;
      }
      if (denial.deniedOnly && denial.evidence > 0) {
        (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues: [...issues, { code: "COMPLETION_ON_DENIED_EVIDENCE", severity: "error", task_id: task, path: `${path}.evidence_ids`,
          rule: "completion_requires_positive_evidence", message: `completion_on_denied_evidence:${task}` }] };
        // 顺序要紧：settleTask 返回的是"原记录 + outcome_*"，带着旧 status。
        // 写成 `{ status: "blocked" }` 在前会把 blocked 覆盖回 running。
        Object.assign(record, settleTask(record, {
          code: "blocked_by_auth",
          reason: `证据全部是鉴权拒绝（${denial.denied}/${denial.evidence} 条，命中 ${this.authWall.codes.join("/")}）：这个入口要么需要 Token、要么需要未授权入口，同一条路继续遍历不会再出结论。`,
          evidence_ids: [...references], by: "control",
        }), { status: "blocked" });
        this.state.auth_wall_alert = { kind: "denied_completion", tasks: [task], at: Date.now() };
        reject(`completion_on_denied_evidence:${task}`); continue;
      }
      // 异常利用类任务（Host 头注入 / 开放重定向 / 子域接管）必须带 http.diff 对比证据：
      // "只发过一次伪造包"不叫验证，所以这里把结案打回去重做，而不是记一笔了事。
      if (/^(host_header_injection|open_redirect|takeover_check)_/.test(task)) {
        const tools = new Set(evidence
          .filter(item => String(item.kind || "") === "tool-result" && String((item.data as Record<string, unknown> | undefined)?.task_id || "") === task && references.includes(String(item.id)))
          .map(item => String(item.source || "")));
        if (!tools.has("http.diff")) {
          (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues: [...issues, { code: "ANOMALY_REQUIRES_DIFF", severity: "error", task_id: task, path: `${path}.evidence_ids`,
            rule: "anomaly_task_requires_http_diff", message: `anomaly_requires_diff:${task}` }] };
          Object.assign(record, { status: "pending", outcome_reason: "缺 http.diff 对比证据：默认请求与伪造 Host/恶意参数的两份响应要各取一份再 diff。" });
          reject(`anomaly_requires_diff:${task}`); continue;
        }
      }
      // 变更③ + 谓词化：漏洞确认类任务标 completed 必须
      // ① 有一条引用本任务证据的 finding，且 ② 本打法的确认谓词成立。
      // 未通过时把**缺哪件证据**直接写进 outcome_reason —— 让下一轮知道补什么，
      // 而不是只看到一句"不允许完成"。
      const verdictGate = completionHasVerdict(output, this.state, task, references, evidence, outcome?.reason);
      if (!verdictGate.ok) {
        const missingText = verdictGate.missing.join("；");
        (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues: [...issues, { code: "COMPLETION_WITHOUT_VERDICT", severity: "error", task_id: task, path: `${path}.evidence_ids`,
          rule: "completed_requires_finding_or_verified_negative", message: `completion_without_verdict:${task}:missing=${missingText}` }] };
        Object.assign(record, { status: "pending", outcome_reason: `标 completed 前还缺：${missingText}。补齐后再结案；确实拿不到就改标 blocked/failed 并带否定证据（verified_negative）。只把请求发出去不算验证。` });
        reject(`completion_without_verdict:${task}`); continue;
      }
      Object.assign(record, { status: "completed", evidence_ids: [...references], ...(outcome?.audit_ids ? { audit_ids: [...outcome.audit_ids] } : {}),
        outcome_reason: normalizeVerdictReason(outcome?.reason) || "legacy completion supported by successful task tool results" });
      // 缺陷 4 的除根：结案是"状态迁移 + 证据留档"，不是"把记录抹掉"。
      // 实测隐患：`deliverables_met` 写错类型时整条 outcome 被 schema 丢弃 → 任务没结案、
      // 也没有任何地方留下"曾经尝试结案"的痕迹，只能靠人翻事件流。这里把结案凭据写进任务本体。
      const proof = {
        at: Date.now(),
        reason: String(outcome?.reason || "").slice(0, 600),
        evidence_ids: [...references],
        deliverables_met: Array.isArray(outcome?.deliverables_met) ? outcome.deliverables_met : (outcome?.deliverables_met === true ? "all" : []),
        ...(outcome?.audit_ids?.length ? { audit_ids: [...outcome.audit_ids] } : {}),
        // 如实申报做不到的项：留痕进结案凭据，报告里能查到"当时为什么没做到"。
        ...(Array.isArray(outcome?.deliverables_unmet) && outcome.deliverables_unmet.length
          ? { deliverables_unmet: outcome.deliverables_unmet.map(item => ({ item: String(item?.item ?? ""), reason: String(item?.reason ?? "") })) } : {}),
      };
      /**
       * 重复声明同一条结案（模型经常把已 completed 的任务再复述一遍）不再追加一份凭据。
       * 实跑 d8c9509f972ebfb5 里 T1 被复述，completion_proof 与 deliverables_waived 都入账两条。
       * 只去重"内容完全一样"的，理由换了仍要留档——那是新的结案主张，得审。
       */
      const proofs = (record.completion_proof as Array<{ reason?: string }> | undefined) || [];
      const repeated = proofs.length > 0 && String(proofs.at(-1)?.reason || "") === proof.reason;
      // 已结案的任务不再追加凭据：第二次申报只回执，不重写账本。
      if (!alreadyCompleted) Object.assign(record, { completion_proof: [...proofs, ...(repeated ? [] : [proof])].slice(-5) });
      // 结案照过，但把 warning 回执给模型（它下一轮才知道哪几项被记成未达成，不会重复申报）。
      (this.state.taskOutcomeResults ||= {})[task] = { status: "applied", issues };
      // 只有这里才真正入账"未达成"：前面的打回分支已经 continue，走不到这一步。
      if (!alreadyCompleted && waivedItems.length) recordWaiver(task, waivedItems);
      resolve(`completion_without_valid_task_evidence:${task}`);
    }
    for (const status of ["blocked", "failed"] as const) for (const task of names(output[`${status}_tasks`])) {
      const record = this.state.tasks[task];
      const outcome = outcomes.find(o => o.task_id === task);
      // 幂等：任务已经是这个状态，再声明一次不是错误（实测模型会重复写 blocked_tasks，
      // 于是 invalid_task_transition 每轮都冒出来一次，把验收卡成 VALIDATION_ERRORS_REMAIN）。
      if (record && record.status === status) {
        /**
         * 补引用通道（2026-11-06）。
         *
         * 幂等跳过有个盲区：任务已经 blocked，`outcome_evidence_ids` 却是空的。
         * 验收判 `TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE`（有证据却没引用），
         * 而模型**没有任何入口能补**——再声明一次会走进这个 continue，什么也不改。
         * 于是整场只能停在 `validation_failed_review_required`（实测 e8bdb447acf02283）。
         *
         * 这里只补**空位**，绝不覆盖已有引用：历史结论不可被悄悄改写，
         * 但"忘了写"和"写错了"应该都还有救。
         */
        const citedBefore = (Array.isArray(record.outcome_evidence_ids) ? record.outcome_evidence_ids as string[] : []).filter(Boolean);
        const incoming = (Array.isArray(outcome?.evidence_ids) ? outcome!.evidence_ids as string[] : []).map(String).filter(Boolean);
        if (!citedBefore.length && incoming.length && !task.startsWith("action:")) {
          const known = new Set(evidence.map(item => String(item.id || "")));
          const valid = [...new Set(incoming.filter(id => known.has(id)))];
          const dropped = [...new Set(incoming.filter(id => !known.has(id)))];
          const index = outcomes.findIndex(o => o.task_id === task);
          if (valid.length) {
            record.outcome_evidence_ids = valid;
            // 补上了就不再是"未经证据支撑"，报告里那条注记要跟着消失。
            delete record.evidence_status;
            delete record.evidence_status_reason;
            (this.state.taskOutcomeResults ||= {})[task] = { status: "applied", issues: [{
              code: "OUTCOME_EVIDENCE_PATCHED", severity: "warning", task_id: task,
              path: `task_outcomes.${index}.evidence_ids`, rule: "backfill_only",
              message: `outcome_evidence_patched:${task}`,
              detail: `已为这条已结案任务补上 ${valid.length} 条证据引用（${valid.join("、")}）。`
                + (dropped.length ? `另有 ${dropped.length} 条在账本里不存在，已丢弃：${dropped.join("、")}。` : ""),
            }] };
          } else {
            (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues: [{
              code: "OUTCOME_EVIDENCE_PATCH_REJECTED", severity: "error", task_id: task,
              path: `task_outcomes.${index}.evidence_ids`,
              message: `outcome_evidence_patch_rejected:${task}`,
              detail: `补引用没生效：提交的 ${dropped.length} 条 id 在账本里都不存在（${dropped.slice(0, 4).join("、")}）。`
                + `只能用真实存在、且属于这条任务的 ev-xxxxxxxxxxxxxxxx。`,
              valid_ids: evidence
                .filter(item => String((item.data as Record<string, unknown> | undefined)?.task_id || "") === task)
                .map(item => String(item.id || "")).filter(Boolean).slice(-6),
            }] };
          }
        }
        resolve(`invalid_task_transition:${task}:${status}`);
        continue;
      }
      if (!record || record.status === "completed" || !outcome?.reason) { reject(`invalid_task_transition:${task}:${status}`); continue; }
      const auditIssues = taskAuditIssues(evidence, task, outcome.audit_ids || record.audit_ids || [], `task_outcomes.${outcomes.indexOf(outcome)}.audit_ids`);
      // R4：受阻/失败也是结论。只要这条任务有证据落账，就必须点名引用——
      // 否则"打不动、理由随便写"会变成模型逃避收口的免费出口。
      const statusCited = evidenceReferenceIds(outcome.reason);
      const hasTaskEvidence = evidence.some(item => String((item.data as Record<string, unknown> | undefined)?.task_id || "") === task);
      /**
       * 结案引用缺失：先自动回填，实在补不上才打回（2026-11-07，对照会话 1dd9ded9ed239711）。
       *
       * 旧写法只要 reason 里没有 ev-id 就直接 reject，哪怕账本里躺着这条任务的 8 条证据。
       * 模型没有补引用的入口（幂等分支只接受它主动提交的 id），于是同一条错误每轮重演、
       * 最后以 `unrepairable` 进 DLQ。这里由控制面补齐——**只补空位**，已有引用绝不覆盖。
       *
       * 相关性校验见 task-outcome.ts 的 autoRepairOutcomeEvidence：命中关键词就只取命中的，
       * 一条都不命中才退回最近 N 条，并把 rule 标成 heuristic_needs_review，
       * 审计时能一眼分出「有依据的回填」和「纯记账补齐」。
       */
      let effectiveEvidenceIds = statusCited;
      if (!statusCited.length && hasTaskEvidence) {
        const repair = autoRepairOutcomeEvidence({ reason: String(outcome.reason || ""), taskId: task, evidence });
        if (!repair?.ids.length) {
          (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues: [{ code: "OUTCOME_WITHOUT_EVIDENCE_REFERENCE",
            severity: "error", task_id: task, path: `task_outcomes.${outcomes.indexOf(outcome)}.reason`,
            rule: "blocked_task_requires_evidence_citation", message: `outcome_without_evidence_reference:${task}` }] };
          reject(`outcome_without_evidence_reference:${task}`); continue;
        }
        effectiveEvidenceIds = repair.ids;
        (this.state.taskOutcomeResults ||= {})[task] = { status: "applied", issues: [{
          code: "OUTCOME_EVIDENCE_AUTO_REPAIRED", severity: "warning", task_id: task,
          path: `task_outcomes.${outcomes.indexOf(outcome)}.evidence_ids`,
          rule: repair.matched ? "auto_backfill:related" : "auto_backfill:heuristic_needs_review",
          message: `auto-repaired:${task}`,
          detail: `结案说明没有点名证据，控制面已从本任务账本回填 ${repair.ids.length} 条（${repair.ids.join("、")}）。${repair.basis}`
            + (repair.matched ? "" : " ⚠ 启发式回填：请在报告复核时确认这几条确实支撑该结论。")
            + " 下一次请直接在 task_outcomes[].reason 里点名 ev-id，或填进 evidence_ids。",
        }] };
        // 独立审计账：事件流会按这条账落 auto-repaired 事件，不依赖转移是否被拒。
        const log = (this.state.outcomeAutoRepairs ||= []);
        const duplicate = log.some(entry => entry.task_id === task
          && entry.ids.length === repair!.ids.length && entry.ids.every((id, index) => id === repair!.ids[index]));
        if (!duplicate) {
          log.push({ seq: (log.at(-1)?.seq || 0) + 1, at: Date.now(), task_id: task, ids: [...repair.ids], matched: repair.matched, basis: repair.basis });
          if (log.length > 40) this.state.outcomeAutoRepairs = log.slice(-40);
        }
      }
      if (auditIssues.length) {
        (this.state.taskOutcomeResults ||= {})[task] = { status: "rejected", issues: auditIssues };
        reject(`invalid_task_transition:${task}:${status}`); continue;
      }
      /**
       * 自报 verified-negative 的 blocked/failed = 结案（见 NEGATIVE_VERDICT 的注释）。
       *
       * 为什么不打回让它改写成 completed：模型对"这条到底算不算做完"的判断已经是
       * "结论是没有"，再让它改一遍状态只会烧掉一轮（它在 b7142138263c586d 里连续
       * 3 轮都在用 blocked 表达同一个负向结论）。控制面直接归位并回一条 warning 回执，
       * 下一轮的账本就是对的。
       *
       * 门槛照旧不放松：必须 ≥2 条**账上真实存在**的证据 id，且要含对照证据——
       * 这是堵"打一个 404 就宣布整站没洞"的免费出口（与 verified_negative 同口径）。
       */
      if (NEGATIVE_VERDICT.test(String(outcome.reason))) {
        const known = statusCited.filter(id => evidence.some(item => String(item.id || "") === id));
        if (known.length >= 2) {
          const declared = (record.deliverables || []).map(item => String(item).trim()).filter(Boolean);
          const unmet = declared.map(item => ({ item, reason: "负向结论：该交付物本身不存在（已用对照证据证否）" }));
          Object.assign(record, {
            status: "completed",
            evidence_ids: [...known],
            outcome_reason: normalizeVerdictReason(outcome.reason) || "verified_negative: 模型自报负向结论",
            ...(outcome.audit_ids ? { audit_ids: [...outcome.audit_ids] } : {}),
            completion_proof: [...((record.completion_proof as unknown[]) || []), {
              at: Date.now(),
              reason: `控制面归位：原写 ${status}，理由是负向结论（verified-negative）。${String(outcome.reason).slice(0, 500)}`,
              evidence_ids: [...known],
              deliverables_met: [],
              ...(unmet.length ? { deliverables_unmet: unmet } : {}),
            }].slice(-5),
          });
          if (unmet.length) recordWaiver(task, unmet.map(entry => entry.item));
          (this.state.taskOutcomeResults ||= {})[task] = { status: "applied", issues: [{
            code: "NEGATIVE_VERDICT_PROMOTED", severity: "warning", task_id: task,
            path: `task_outcomes.${outcomes.indexOf(outcome)}.reason`,
            rule: "negative_verdict_counts_as_completion",
            message: `negative_verdict_promoted:${task}`,
            detail: `你写的是 ${status}，但理由是负向结论（verified-negative），已按结案记成 completed（证据 ${known.length} 条）。`
              + (unmet.length ? `交付物 ${unmet.map(entry => entry.item).join(" / ")} 同时记成未达成——负向结论下它本来就不存在。` : "")
              + `下一轮直接推进下一个任务，不要重复提交 ${task}。`,
          }] };
          resolve(`invalid_task_transition:${task}:${status}`);
          continue;
        }
      }
      /**
       * 模型自己交的 blocked/failed（2026-11-05）：同样走结案契约。
       *
       * 它在这里给出的 reason 是**结案理由**（缺凭证/缺权限/等外部回应），
       * 与创建时的 `tasks[].reason`（为什么派这个任务）是两件事，
       * 所以写进 outcome_reason 而不是覆盖 `reason`。证据引用取它在 reason 里
       * 点到的 id（statusCited）——上文已经要求 blocked 必须引用已有证据。
       */
      Object.assign(record, {
        ...settleTask(record, {
          code: status === "failed" ? "agent_failed" : "agent_blocked",
          reason: String(outcome.reason || ""),
          // 模型自己点名的 id（statusCited）或控制面按账本回填的 id；
          // 后者只在「一个引用都没有」时出现，不会覆盖模型写过的引用。
          evidence_ids: effectiveEvidenceIds,
          by: "agent",
        }),
        status,
        ...(outcome.audit_ids ? { audit_ids: [...outcome.audit_ids] } : {}),
      });
      resolve(`invalid_task_transition:${task}:${status}`);
    }
    this.state.validationErrors = [...this.state.transitionErrors];
    return hash(this.lists().completed_tasks) !== before;
  }
  applyAdviceDecision(decision: AdviceDecision): AdviceDecisionResult {
    this.state.transitionErrors ??= [...(this.state.validationErrors || [])];
    const advice = this.state.advice?.[decision.advice_id];
    const status = decision.accepted ? "accepted" : "rejected";
    let result: AdviceDecisionResult["status"];
    // 别名先归一：建议指向的新 id 若被语义去重吞进老任务（T20→T6），直接用新 id 校验会把
    // 一条完全正确的采纳判成 invalid_advice_decision——模型没有别的写法可选，只能放弃建议。
    const resolvedTaskIds = [...new Set(decision.task_ids.map(id => this.resolveTaskId(id)).filter(Boolean))];
    // Terminal dispositions are immutable, even when the retry changes its reason or task links.
    if (advice?.status === "accepted" || advice?.status === "rejected") {
      result = advice.status === status ? "already_applied" : "disposition_conflict";
    } else if (!advice || advice.status !== "pending" || !decision.reason.trim() ||
        resolvedTaskIds.some(id => !this.state.tasks[id]) || (decision.accepted && !resolvedTaskIds.length)) {
      result = "invalid_advice_decision";
    } else {
      Object.assign(advice, { status, reason: decision.reason, task_ids: resolvedTaskIds });
      result = "applied";
    }
    if (result === "applied" || result === "already_applied") {
      const resolved = new Set([`invalid_advice_decision:${decision.advice_id}`, `disposition_conflict:${decision.advice_id}`]);
      this.state.transitionErrors = this.state.transitionErrors.filter(error => !resolved.has(error));
    } else if (this.state.advice?.[decision.advice_id]) {
      // Only a real advice can be dispositioned badly and repaired later. A decision aimed at a
      // non-existent id (the agent passed an evidence id) is recorded in adviceDecisionResults and
      // must not become an unreachable transition error that blocks every future run.
      const error = `${result}:${decision.advice_id}`;
      if (!this.state.transitionErrors.includes(error)) this.state.transitionErrors.push(error);
    }
    this.state.validationErrors = [...this.state.transitionErrors];
    return { advice_id: decision.advice_id, status: result };
  }
  /**
   * 兜底处置：连续 maxMisses 轮没被签收、或正文里被点名却未结构化的建议，
   * 一律归档为 superseded（未采纳）。RUN 继续跑，绝不为一条建议停整场。
   * 返回本轮被兜底归档的 id，调用方据此写 advice-auto-skip 事件。
   */
  sweepAdvice(options: { maxMisses?: number; salvaged?: string[]; actedTasks?: Iterable<string> } = {}): string[] {
    // maxMisses = 0 表示"所有 pending 建议一律归档"（离场且补跑过后使用）。
    const maxMisses = Math.max(0, Math.floor(options.maxMisses ?? 2));
    /**
     * 本轮真的在建议指向的任务上发了请求 → 不要归档这条建议。
     *
     * 冲突 1 的延伸（2026-11-02 实测）：模型没在 advice_decisions 里认领，但已经把请求投给了
     * 建议指向的任务——这恰恰说明它读懂了建议，只是还没写处置。旧实现按 misses 直接归档，
     * 于是焦点锁下一轮就没有让位依据，请求继续被拒（"行动了却被判没行动"）。
     */
    const acted = new Set(options.actedTasks || []);
    // 归档过的建议名下的决定错误一律清掉：建议已不可处置，这条错误永远修不好。
    this.pruneAdviceErrors();
    const salvaged = new Set((options.salvaged || this.state.adviceSalvaged || []).map(id => id.toLowerCase()));
    const swept: string[] = [];
    for (const [id, item] of Object.entries(this.state.advice || {})) {
      if (item.status !== "pending") continue;
      if ((item.task_ids || []).some(taskId => acted.has(String(taskId)))) continue;
      const fromText = salvaged.has(id.toLowerCase());
      const misses = Number(item.misses || 0);
      if (!fromText && misses < maxMisses) continue;
      Object.assign(item, {
        status: "superseded",
        reason: fromText ? autoSalvageReason() : autoSkipReason(misses),
        auto_skipped: true,
        superseded_at: Date.now(),
      });
      // 相关决定错误已经无从修正：一并清掉，避免下一轮拿旧 id 反复撞门禁。
      this.clearAdviceDecisionErrors(id);
      swept.push(id);
    }
    if (swept.length) this.state.validationErrors = [...this.state.transitionErrors || []];
    return swept;
  }

  /**
   * 清掉「建议已归档、错误还在」的孤儿处置错误。
   * 这类错误既不能被任何合法重提交修复（advice 已不在 pending），也不该阻塞验收，
   * 留着只会让长跑永远停在 validation_failed_review_required。
   */
  /**
   * 清掉「已经不可能被任何输出修复」的历史校验错误。
   *
   * 三类：
   *   ① 建议已归档、错误还在的孤儿处置错误（advice 已不在 pending）；
   *   ② `task_duplicate:*` —— 语义重复现在由 merge() 自动吞噬并记进 task_aliases，
   *      老 checkpoint 里残留的这条错误永远等不到"修复"，却让每轮验收都停在
   *      VALIDATION_ERRORS_REMAIN（2026-10-28 实测：blocking_error_count 恒为 4）；
   *   ③ 任务**已经终态**的转移类错误（anomaly_requires_diff / completion_without_valid_task_evidence /
   *      outcome_without_evidence_reference / closure_deliverables_*）：这些码只在"这一次转移"里
   *      有意义，终态之后没有任何输出能修复它们，留着只会让 run 永远停在 validation_failed。
   *      实测：host_header 任务在 05:05 用三条 http.diff verdict 正常结案，但 04:58 留下的
   *      anomaly_requires_diff 还在，验收于是继续报 VALIDATION_ERRORS_REMAIN。
   *   ④ 建议**已终态且自洽**时的处置冲突（`disposition_conflict`）——终态不可变，
   *      相反结论再提交也只会再撞一次，留着等于把一次被拒的写入当成永久待办。
   */
  pruneAdviceErrors(): string[] {
    const archived = new Set(Object.entries(this.state.advice || {})
      .filter(([, item]) => item.status === "superseded")
      .map(([id]) => id));
    /**
     * 已**终态且自洽**的建议（2026-11-10 补）：accepted / rejected 不可变，且处置本身
     * 立得住（有理由、指向的任务都真实存在）。名下的 `disposition_conflict` 记的是
     * "有人想改成相反结论、被拒了"——那是一次**被拒的写入**，不是待办。
     *
     * 旧判据只认 superseded，于是终态建议的冲突永远留着：实测
     * `disposition_conflict:advice-authwall-20261110095549`（建议早已 accepted）从 18:xx
     * 一直卡到 21:xx，每轮把会话摁在 validation_failed_review_required。
     * 判据与 acceptance 里 ADVICE_DISPOSITION_INVALID 的口径对齐：自洽就不拦，不自洽
     * 另有 ADVICE_DISPOSITION_INVALID 去报，不靠这条冲突兜底。
     */
    const disposed = new Set(Object.entries(this.state.advice || {})
      .filter(([, item]) => {
        if (!["accepted", "rejected"].includes(String(item.status))) return false;
        if (!String(item.reason || "").trim()) return false;
        const ids = (item.task_ids || []) as string[];
        if (String(item.status) === "accepted" && !ids.length) return false;
        return ids.every(id => Boolean(this.state.tasks?.[id]));
      })
      .map(([id]) => id));
    const terminal = new Set(Object.entries(this.state.tasks || {})
      .filter(([, task]) => ["completed", "blocked", "failed"].includes(String(task.status)))
      .map(([id]) => id));
    const removed: string[] = [];
    const kept = (this.state.transitionErrors || []).filter(error => {
      if (/^task_duplicate:/.test(error)) { removed.push(error); return false; }
      if (isTerminalTransitionError(error, terminal)) { removed.push(error); return false; }
      if (!archived.size && !disposed.size) return true;
      const match = /^(?:invalid_advice_decision|disposition_conflict):(.+)$/.exec(error);
      if (!match) return true;
      const adviceId = match[1]!;
      if (!archived.has(adviceId) && !disposed.has(adviceId)) return true;
      removed.push(error);
      return false;
    });
    if (removed.length) {
      this.state.transitionErrors = kept;
      this.state.validationErrors = [...kept];
      // 不是"删掉"而是"隔离"：这些错误永远修不好，但删掉就没人知道账本脏过。
      // 进 dlq，退出 blocking_error_count，控制台仍可见（缺陷 5 的除根做法）。
      this.state.dlq ||= [];
      for (const message of removed) {
        const code = message.split(":")[0] || "unknown";
        this.state.dlq.push({ at: Date.now(), code, message: message.slice(0, 300), origin: "unrepairable" });
      }
      if (this.state.dlq.length > 60) this.state.dlq = this.state.dlq.slice(-60);
    }
    return removed;
  }

  /**
   * 只列「模型这轮还改得动」的账本错误（2026-11-10）。
   *
   * `transition-rejected` 的正文以前把 `validationErrors` 全量当"待办码"塞给模型，
   * 里面混着已终态任务/已处置建议的历史记录。模型于是每轮都去"修"这些根本改不动的
   * 条目，把 49 条 task_outcomes 全量重放一遍——一轮 1–3 条再被拒，错误又被写回账本。
   *
   * 判据就是"还有没有合法输入能让它消失"：任务终态不可重开、建议已处置不可改判，
   * 这两类不该再出现在待办里；它们由 pruneAdviceErrors 收进 dlq 留痕。
   */
  actionableTransitionErrors(): string[] {
    return (this.state.transitionErrors || []).filter(error => {
      const separator = error.indexOf(":");
      if (separator < 0) return true;
      const code = error.slice(0, separator);
      const subject = error.slice(separator + 1);
      if (code === "invalid_advice_decision" || code === "disposition_conflict") {
        return String(this.state.advice?.[subject]?.status || "") === "pending";
      }
      const taskId = subject.split(":")[0] || "";
      const record = this.state.tasks?.[taskId];
      if (!record) return true;
      return !["completed", "blocked", "failed"].includes(String(record.status));
    });
  }

  /**
   * 主体已死的转移错误 → 死信队列（2026-11-10，P1-5 的兜底）。
   *
   * `pruneAdviceErrors` 按**码表**剪枝，新出现的码要等人补名单——补之前那个码就是
   * 又一条死锁（`completion_without_verdict` 就是这么把会话卡了五场）。这里换成
   * **按主体**判断：任务已终态、建议已处置，就再也不会有合法输入让这条错误消失，
   * 于是它与码表无关，一律收进 dlq（`origin: unrepairable:subject_dead`）并退出阻塞。
   *
   * 与 `actionableTransitionErrors` 用同一判据，所以"报给模型的待办"和"留在门禁里的
   * 阻塞"永远是同一批东西，不会出现"让改却改不动"的错位。
   */
  retireUnrepairableTransitions(): string[] {
    const errors = this.state.transitionErrors || [];
    if (!errors.length) return [];
    const alive = new Set(this.actionableTransitionErrors());
    const removed = errors.filter(error => !alive.has(error));
    if (!removed.length) return [];
    this.state.transitionErrors = errors.filter(error => alive.has(error));
    this.state.validationErrors = [...this.state.transitionErrors];
    this.state.dlq ||= [];
    for (const message of removed) {
      this.state.dlq.push({ at: Date.now(), code: message.split(":")[0] || "unknown",
        message: message.slice(0, 300), origin: "unrepairable:subject_dead" });
    }
    if (this.state.dlq.length > 60) this.state.dlq = this.state.dlq.slice(-60);
    return removed;
  }

  /** 死信队列快照（控制台 / 运维看这里，不参与验收判定）。 */
  deadLetters(limit = 20): Array<{ at: number; code: string; message: string }> {
    return (this.state.dlq || []).slice(-limit);
  }

  /** 供上下文注入 <CRITICAL>：这些建议下一轮必须逐条处置。 */
  pendingAdvice(): Array<{ advice_id: string; misses: number; suggestions: string[] }> {
    return pendingAdviceView(this.state.advice).map(item => ({ advice_id: item.advice_id, misses: item.misses, suggestions: item.suggestions }));
  }

  /**
   * 追加后台插话。与 supplement 的区别：**不进验收门禁**、不产生 pending advice，
   * 只在下一次上下文里出现一次（模型看到后 acknowledged 由下一轮清除）。
   */
  addInterrupts(items: Array<{ id: string; kind: string; severity: "high" | "medium"; text: string; data?: Record<string, unknown>; fingerprint?: string }>): number {
    if (!items.length) return 0;
    const list = this.state.interrupts ||= [];
    let added = 0;
    for (const item of items) {
      /**
       * 按 id 去重（2026-11-07）。旧写法 (id,text) 双键，而调用方把「第 N 次提醒」
       * 拼进 text，N 每轮递增 → 每轮都算新插话 → 同一句提醒写了 77 条事件。
       * 现在同 id 只留一条：文本相同累计 repeats；文本真的变了（换了目标 URL）
       * 才算一次新插话，避免把有效的新目标也吞掉。
       *
       * 2026-11-09（A3）：判"文本真的变了"改用 `fingerprint`。
       * 只看 text 仍然会被"文案里带个数"击穿——现场 `component_drift` 的正文写着
       * "图裂成 60/61/62 块、另有 35/36 块没动过"，数字一变就算新插话，
       * 13 分钟照样写了 7 条同义事件。指纹由调用方给**语义**（如 kind + roots），
       * 数字漂移不再影响判新旧；没给指纹时退回 text，行为与旧版一致。
       */
      const existing = list.find(entry => entry.id === item.id);
      if (existing) {
        const nextKey = item.fingerprint ?? item.text;
        const prevKey = existing.fingerprint ?? existing.text;
        existing.at = Date.now();
        existing.repeats = (existing.repeats || 1) + 1;
        if (prevKey !== nextKey) {
          existing.text = item.text;
          existing.severity = item.severity;
          existing.data = item.data;
          existing.fingerprint = item.fingerprint;
          existing.acknowledged = false;
          added += 1;
        } else {
          // 指纹没变：正文可以原地刷新（数字会变，但语义没变），不算新插话。
          existing.text = item.text;
          existing.data = item.data;
          if (existing.repeats! % 10 === 0) {
            // 每 10 轮把同一条欠账重新顶进上下文一次，别让它被一次 acknowledged 永久埋掉。
            existing.acknowledged = false;
          }
        }
        continue;
      }
      list.push({ ...item, at: Date.now(), repeats: 1 });
      added += 1;
    }
    // 只留最近 12 条：插话是提示，不是账本。
    //
    // 2026-11-09（P1）：超限时**先淘汰已确认的**，再按新旧截断。
    // 旧实现直接 slice(-12)：已 acknowledged 的老插话（focus-auto-handoff 之类）
    // 会在池子里躺几小时不走，新插话一来就把还没被看到的 `graph:*` 欠账挤出去；
    // 下一轮欠账重新插入又被算成"新插话"，graph-signal 因此重复写事件。
    // 现在确认过的先出局，未确认的欠账优先保留。
    if (list.length > 12) {
      let overflow = list.length - 12;
      const kept: typeof list = [];
      for (const entry of list) {
        if (overflow > 0 && entry.acknowledged) { overflow -= 1; continue; }
        kept.push(entry);
      }
      this.state.interrupts = overflow > 0 ? kept.slice(overflow) : kept;
    }
    return added;
  }

  /** 取走未确认的插话并标记已读（下一轮上下文里不再重复出现）。 */
  takeInterrupts(): Array<{ id: string; kind: string; severity: "high" | "medium"; text: string; at: number }> {
    const list = this.state.interrupts || [];
    const fresh = list.filter(item => !item.acknowledged);
    for (const item of fresh) item.acknowledged = true;
    return fresh.map(item => ({ id: item.id, kind: item.kind, severity: item.severity, text: item.text, at: item.at }));
  }

  supplement(output: Record<string, unknown>, adviceId = `advice-${Object.keys(this.state.advice || {}).length + 1}`): boolean {
    const tasks = Array.isArray(output.supplemental_tasks) ? output.supplemental_tasks : [];
    // Observer 的 next_steps 是结构化的"工具 + 目标 + 参数"，比自由文本建议更该被执行。
    // 这里折成建议行（带工具名与可直接照抄的 input），主 Agent 在 critical_actions.advice
    // 里看到的就是"用 http.diff 打这个 URL、带这些头"，而不是"建议继续测试"。
    const nextSteps = Array.isArray(output.next_steps) ? output.next_steps as Array<Record<string, unknown>> : [];
    const stepLines = nextSteps.map(step => {
      const rawTool = String(step.tool || "").trim();
      const tool = (rawTool ? canonicalTool(rawTool) : "") || rawTool;
      const target = String(step.target || "").trim();
      const why = String(step.why || "").trim();
      /**
       * 2026-10-31：Observer 的建议必须先过"执行器能力校验"。
       *
       * m.ctrip.com 那轮 Observer 建议过 `exec.python` + `params.code`、`exec.bash` + `input.cmd`、
       * `http.request` + `force_armored` —— 三种写法执行器都不认，主 Agent 照着打就是空跑。
       * 建议不能执行时必须说明原因，而不是伪装成"下一步"。
       */
      const problems: string[] = [];
      const enumTools = BLACKBOX_TOOL_ENUM as readonly string[];
      if (tool && !enumTools.includes(tool)) problems.push(`工具 ${tool} 不在可用清单`);
      let clean: Record<string, unknown> = {};
      if (step.input && typeof step.input === "object" && !Array.isArray(step.input)) {
        const split = splitToolInput(step.input);
        clean = split.clean;
        if (split.ignored.length) problems.push(`键 ${split.ignored.join("/")} 不被该工具接受`);
      }
      if (tool.startsWith("exec.") && clean.code === undefined && clean.script === undefined) {
        problems.push("exec.* 只读顶层 code/script（写在 params 里会被拒收）");
      }
      const input = Object.keys(clean).length ? JSON.stringify(clean) : "";
      if (problems.length) {
        return `不可执行建议（${problems.join("；")}）：${tool || "?"}${target ? ` → ${target}` : ""}${why ? `（${why}）` : ""}。换成清单内工具或按正确键重写后再执行。`;
      }
      // 没给工具名 = Observer 认为清单里没有对应能力：标成缺口，而不是伪装成可执行步骤。
      return tool
        ? `下一步指定工具 ${tool}${target ? ` → ${target}` : ""}${input ? ` input=${input}` : ""}${why ? `（${why}）` : ""}`
        : `缺口：${why || target || "Observer 未说明"}`;
    });
    const suggestions = [...(Array.isArray(output.suggestions) ? output.suggestions : []), ...stepLines];
    if (!tasks.length && !suggestions.length) return false;
    // Identical unresolved recommendations do not grow the checkpoint each round.
    if (Object.values(this.state.advice || {}).some(a => a.status === "pending" && hash({ tasks: a.tasks, suggestions: a.suggestions || [] }) === hash({ tasks, suggestions }))) return false;
    this.state.advice ||= {};
    // Advice about tasks that already reached a terminal state can never be acted on. Leaving it
    // pending made the acceptance gate report unhandled advice forever on long runs.
    for (const [id, older] of Object.entries(this.state.advice)) {
      if (older.status !== "pending") continue;
      const declared: string[] = (older.task_ids || []).length
        ? [...(older.task_ids || [])]
        : ((older.tasks || []) as Array<{ id?: string }>).map(spec => String(spec?.id || "")).filter(Boolean);
      const linked = declared.filter(taskId => this.state.tasks[taskId]);
      if (linked.length && linked.every(taskId => ["completed", "blocked", "failed"].includes(String(this.state.tasks[taskId]?.status)))) {
        Object.assign(older, { status: "superseded", reason: older.reason || "任务已全部终态，建议自动归档。", superseded_at: Date.now() });
        this.clearAdviceDecisionErrors(id);
      }
    }
    this.state.advice[adviceId] = { tasks, suggestions, status: "pending" };
    // 待处置建议是有上限的：Observer 每轮都可能加一条，长跑后会积到十几条把门禁卡死。
    // 只保留最新的 N 条 pending，其余归档成 superseded（可从证据重生，不是删除）。
    const cap = Math.max(1, this.advicePendingLimit);
    const pending = Object.entries(this.state.advice).filter(([id, item]) => item.status === "pending" && id !== adviceId);
    if (pending.length >= cap) {
      const stale = pending.slice(0, pending.length - cap + 1);
      for (const [id, item] of stale) {
        Object.assign(item, { status: "superseded", reason: item.reason || `建议积压超过上限 ${cap}，旧的自动归档。`, superseded_at: Date.now() });
        this.clearAdviceDecisionErrors(id);
      }
    }
    return false;
  }

  /**
   * 归档一条建议时顺手清掉它名下的处置错误。
   * 起因：push.oppo.com 那轮，Observer 的两条建议被 supplement() 归档成 superseded，
   * 但它们名下的 `invalid_advice_decision:<id>` 还留在 transitionErrors 里——建议已经
   * 不可处置了，这条错误永远修不好，验收门禁因此把整场 run 判成 validation_failed。
   * 「会计账本写错一个字就把公司关了」的根源就在这里。
   */
  private clearAdviceDecisionErrors(adviceId: string): void {
    const prefix = new RegExp(`^(invalid_advice_decision|disposition_conflict):${adviceId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
    const before = this.state.transitionErrors || [];
    const after = before.filter(error => !prefix.test(error));
    if (after.length === before.length) return;
    this.state.transitionErrors = after;
    this.state.validationErrors = [...after];
  }
  enqueue(requests: BlackboxToolRequest[], target: string): void {
    for (const request of requests) {
      const task = this.task(request, this.identity(request, target));
      this.state.tasks[task] ||= { status: "pending", target: String(request.input?.url || target), source: "tool-request", reason: `${request.tool}: ${String(request.input?.url || target)} — ${request.reason || ""}` };
    }
  }
  lists() {
    const list = (statuses: TaskState[]) => Object.entries(this.state.tasks).filter(([, v]) => statuses.includes(v.status)).map(([k]) => k);
    return { completed_tasks: list(["completed"]), blocked_tasks: list(["blocked"]), failed_tasks: list(["failed"]), pending_tasks: list(["pending", "running"]) };
  }
  identity(request: BlackboxToolRequest, target: string): string {
    const rawInput = request.input || {};
    const input: Record<string, unknown> = { url: rawInput.url || target };
    try { const url = new URL(String(input.url)); url.hash = ""; input.url = url.toString(); } catch { /* Invalid URLs retain their identity and fail normally. */ }
    const raw = request.tool || (request as BlackboxToolRequest & { name?: string }).name || "";
    const tool = canonicalTool(raw);
    if (["http.request", "burp.request"].includes(tool)) {
      input.method = String(rawInput.method || "GET").toUpperCase();
      const headerReport = requestHeadersWithDropped(rawInput.headers);
      input.headers = headerReport.headers;
      // 被丢弃的头必须留在证据里：否则"我明明发了 Host"永远对不上账。
      if (headerReport.dropped.length) input.headers_dropped = headerReport.dropped;
      for (const key of ["body", "body_base64", "json", "form", "multipart"]) {
        if (rawInput[key] !== undefined) input[key] = rawInput[key];
      }
    }
    if (["burp.history", "burp.sitemap", "burp.issues"].includes(tool)) {
      input.limit = Number.isInteger(Number(rawInput.limit)) ? Math.max(1, Math.min(100, Number(rawInput.limit))) : 30;
      input.offset = Number.isInteger(Number(rawInput.offset)) ? Math.max(0, Math.min(100000, Number(rawInput.offset))) : 0;
    }
    if (tool === "burp.entry") input.entry_id = String(rawInput.entry_id || "").trim();
    if (tool === "burp.ws_history") {
      input.limit = Number.isInteger(Number(rawInput.limit)) ? Math.max(1, Math.min(100, Number(rawInput.limit))) : 30;
      input.offset = Number.isInteger(Number(rawInput.offset)) ? Math.max(0, Math.min(100000, Number(rawInput.offset))) : 0;
    }
    if (["burp.send", "burp.repeater", "burp.organizer", "burp.scan"].includes(tool)) {
      if (rawInput.url !== undefined) input.url = String(rawInput.url).slice(0, 2048);
      if (rawInput.method !== undefined) input.method = String(rawInput.method).toUpperCase().slice(0, 16);
      if (rawInput.headers && typeof rawInput.headers === "object") input.headers = rawInput.headers;
      if (rawInput.body !== undefined) input.body = typeof rawInput.body === "string" ? rawInput.body.slice(0, 8192) : rawInput.body;
      if (tool === "burp.send") input.follow_redirects = rawInput.follow_redirects === true;
      if (tool === "burp.repeater" && rawInput.tab !== undefined) input.tab = String(rawInput.tab).slice(0, 64);
      if (tool === "burp.scan") input.mode = rawInput.mode === "active" ? "active" : "passive";
    }
    if (tool === "burp.decoder") {
      input.operation = String(rawInput.operation || "").toLowerCase().slice(0, 32);
      input.value = String(rawInput.value ?? "").slice(0, 4096);
    }
    if ((tool === "burp.scan_status" || tool === "burp.scan_stop") && rawInput.audit_id !== undefined) input.audit_id = String(rawInput.audit_id).slice(0, 64);
    if (tool === "burp.collab_poll") input.limit = Number.isInteger(Number(rawInput.limit)) ? Math.max(1, Math.min(100, Number(rawInput.limit))) : 30;
    if (tool === "burp.scope" && rawInput.url !== undefined) input.url = String(rawInput.url).slice(0, 2048);
    if (tool === "burp.intercept" && rawInput.enabled !== undefined) input.enabled = rawInput.enabled === true;
    if (tool.startsWith("burp.") && !["burp.history","burp.sitemap","burp.entry","burp.issues","burp.ws_history","burp.scope","burp.intercept","burp.decoder","burp.send","burp.repeater","burp.organizer","burp.scan","burp.scan_status","burp.scan_stop","burp.collab_generate","burp.collab_poll","burp.ws_history"].includes(tool)) {
      // Full-surface actions: keep a bounded, serialisable record without copying huge bodies.
      for (const [key, value] of Object.entries(rawInput)) {
        if (value === undefined) continue;
        if (typeof value === "string") input[key] = value.length > 2048 ? `${value.slice(0, 2048)}…[truncated]` : value;
        else if (typeof value === "number" || typeof value === "boolean") input[key] = value;
        else if (Array.isArray(value)) input[key] = value.slice(0, 50);
        else if (value && typeof value === "object") input[key] = value;
      }
    }
    if (tool === "browser.screenshot") input.full_page = rawInput.full_page === true;
    if (tool === "katana.crawl") {
      const integer = (value: unknown, fallback: number, min: number, max: number) => Number.isInteger(Number(value ?? fallback)) ? Math.max(min, Math.min(max, Number(value ?? fallback))) : fallback;
      input.depth = integer(rawInput.depth, 2, 1, 3);
      input.duration_seconds = integer(rawInput.duration_seconds, 20, 5, 60);
    }
    // External tools authenticate through the same headers: a nuclei run with an auth header
    // is different work from an anonymous one, so headers must be part of the identity.
    if (!["http.request", "burp.request"].includes(tool) && rawInput.headers !== undefined) {
      const headerReport = requestHeadersWithDropped(rawInput.headers);
      input.headers = headerReport.headers;
      if (headerReport.dropped.length) input.headers_dropped = headerReport.dropped;
    }
    // Every other parameter changes what the tool actually does, so it must change the
    // identity: a second nuclei run with different templates is new work, not a repeat.
    // Timeout tuning and rewritten prose are not new targets or new purposes.
    const identityKeys = new Set(["url", "method", "headers", "body", "body_base64", "json", "form", "multipart", "limit", "offset", "entry_id", "full_page", "depth", "duration_seconds"]);
    for (const [key, value] of Object.entries(rawInput)) {
      if (identityKeys.has(key) || ["timeout_ms", "timeout_seconds", "wait_seconds", "reason", "runtime_id"].includes(key)) continue;
      if (key === "params" && value && typeof value === "object" && !Array.isArray(value)) {
        // Sorted keys so the same knobs in a different order are the same action.
        input.params = Object.fromEntries(Object.entries(value as Record<string, unknown>)
          .sort(([a], [b]) => a.localeCompare(b)).map(([name, item]) => [name, typeof item === "string" ? item.slice(0, 2000) : item]));
        continue;
      }
      input[key] = typeof value === "string" ? value.slice(0, 2000) : value;
    }
    return hash({ tool, input });
  }
  task(request: BlackboxToolRequest, key: string): string { const raw = String(request.task_id || `action:${key}`).trim(); return this.resolveTaskId(raw); }
  /**
   * 同一路径的参数面熔断。
   *
   * 一轮里对 /api/list?docType=0..10 换着值打 30 次、响应却只有 7 种，是最常见的预算黑洞：
   * 每个请求参数不同 → 身份哈希不同 → 现有 repeat 检测完全不触发。所以这里按**路径**聚合，
   * 一旦“调用够多、参数变过、响应指纹却几乎不变”，就把任务判死让模型换打法。
   */
  /**
   * POST 面任务的看门狗：连续 N 轮没人给它派活就提权成唯一可执行任务。
   * 返回 escalated=true 表示这一轮刚刚上锁（desk 用它写事件）。
   */
  tickPostSurface(served: boolean, limit = 2): { ignored_turns: number; escalated: boolean; released?: boolean; blocked_by?: string } {
    const watch = this.state.linkage?.post_surface;
    if (!watch) return { ignored_turns: 0, escalated: false };
    if (served) {
      watch.ignored_turns = 0;
      return { ignored_turns: 0, escalated: false };
    }
    watch.ignored_turns += 1;
    // ① 提权后仍无人服务：这是死锁，不是"再等等"。释放锁并把任务判 blocked。
    //    2026-10-31 m.ctrip.com：post_surface 提权后模型一直在打 SPA 任务，
    //    8 次请求全被 skip，run 直接空转到墙钟上限。
    if (this.state.exclusive_task === watch.task_id) {
      if (watch.ignored_turns >= 4) {
        this.state.exclusive_task = undefined;
        this.state.exclusive_reason = undefined;
        const record = this.state.tasks[watch.task_id];
        if (record) {
          this.state.tasks[watch.task_id] = {
            ...settleTask(record, {
              code: "exclusive_starved",
              reason: `排他提权后连续 ${watch.ignored_turns} 轮无人服务：控制面释放排他锁并判 blocked（不释放的话整轮请求都因排他锁被 skip）。`,
              by: "control",
            }),
            status: "blocked",
          };
        }
        watch.ignored_turns = 0;
        watch.disarmed = true;
        return { ignored_turns: 0, escalated: false, released: true };
      }
      return { ignored_turns: watch.ignored_turns, escalated: false };
    }
    if (watch.disarmed) return { ignored_turns: watch.ignored_turns, escalated: false };
    if (this.state.exclusive_task) return { ignored_turns: watch.ignored_turns, escalated: false };
    // ② 已有更强的强制焦点（SPA 外壳 / 主权转移）时不要抢锁：抢了就是互相 skip。
    const forced = this.state.forced_focus;
    const forcedTask = forced ? this.state.tasks[forced.task_id] : undefined;
    if (forcedTask && !["completed", "blocked", "failed"].includes(String(forcedTask.status || ""))) {
      return { ignored_turns: watch.ignored_turns, escalated: false, blocked_by: "forced_focus" };
    }
    if (watch.ignored_turns < limit) return { ignored_turns: watch.ignored_turns, escalated: false };
    watch.escalated_at = Date.now();
    this.state.exclusive_task = watch.task_id;
    this.state.exclusive_reason = { task_id: watch.task_id, since: watch.escalated_at, ignored_turns: watch.ignored_turns };
    const record = this.state.tasks[watch.task_id];
    if (record) this.state.tasks[watch.task_id] = { ...record, status: record.status === "completed" ? record.status : "pending",
      reason: "exclusive_until_done", outcome_reason: "POST 面枚举被连续忽略，已提权为唯一可执行任务。" };
    return { ignored_turns: watch.ignored_turns, escalated: true };
  }

  /**
   * 记一次 http 结果的"形状"。命中 catch-all（不同路径同一跳转 / 同一响应长度）时写
   * `anomaly_alert`，desk 据此派发 Host 头注入、开放重定向、子域接管三条利用任务。
   */
  recordAnomaly(request: BlackboxToolRequest, result: BlackboxToolResult): void {
    if (!result.ok) return;
    if (!["http.request", "burp.request"].includes(String(request.tool))) return;
    const data = (result.data || {}) as Record<string, unknown>;
    const url = String(request.input?.url || data.final_url || data.url || "");
    if (!url) return;
    const observation = observationOf({
      url,
      status: Number(data.status || 0),
      location: typeof data.location === "string" ? data.location : undefined,
      body_bytes: Number(data.body_bytes || 0),
    });
    if (!observation) return;
    this.state.anomaly ||= { recent: [] };
    this.state.anomaly.recent = [...this.state.anomaly.recent, observation].slice(-12);
    const alert = detectAnomaly(this.state.anomaly.recent);
    if (!alert) return;
    this.state.anomaly.seen_at = alert.at;
    this.state.anomaly_alert = alert;
  }

  /**
   * 工具 Fail-Fast：连续两次 0 产出（nuclei 模板不匹配、目标无命中）就禁用到会话结束。
   * "跑成功但什么都没有"比报错更贵——它一直看起来像还有希望。
   */
  recordToolHealth(tool: string, result: BlackboxToolResult): void {
    const name = String(tool || "");
    if (!["recon.nuclei", "recon.xss", "recon.sql"].includes(name)) return;
    // 被拒绝/没配置的调用不算"0 产出"
    if (!result.ok && !/0 (results|findings|items)/i.test(String(result.summary || ""))) return;
    this.state.tool_health ||= {};
    const health = (this.state.tool_health[name] ||= { zeros: 0 });
    const data = (result.data || {}) as Record<string, unknown>;
    const produced = Number(Array.isArray(data.findings) ? data.findings.length : 0) > 0
      || Number(Array.isArray(data.items) ? data.items.length : 0) > 0;
    health.last_at = Date.now();
    if (produced) {
      health.zeros = 0;
      health.disabled = false;
      health.detail = undefined;
      return;
    }
    health.zeros += 1;
    if (health.zeros < 2) return;
    // 不用"会话内禁用"惩罚 0 产出：nuclei 默认模板打不到目标、dalfox 对 SPA 无命中、
    // sqlmap 参数不对，都能连续两次 0 产出，但换个模板 tag / 字典就有效。
    // 真正的刹车是权重预算；这里只留一次提示。
    health.detail = `${name} 已连续 ${health.zeros} 次 0 产出：换模板 tag / 换字典 / 换档位，不要用同一组参数重试。`;
    if (health.zeros === 2) this.addInterrupts([{
      id: `tool-health:${name}:${health.last_at}`, kind: "tool_health", severity: "medium",
      text: `${name} 连续 2 次 0 产出。同参数重试不划算：换 tags/字典/扫描档位，或改用 http.request 手工验证。`,
      data: { tool: name },
    }]);
  }

  /**
   * 登录门禁识别：验证码 / MFA / SSO 跳转 / 滑块。命中就把认证链任务判 blocked（reason=auth_gate:*），
   * 让调度器和 Observer 立刻换打法，而不是在登录页里反复尝试把账号打锁。
   */
  recordAuthGate(task: string, request: BlackboxToolRequest, result: BlackboxToolResult): boolean {
    if (!result.ok || String(request.tool) !== "browser.open") return false;
    const data = (result.data || {}) as Record<string, unknown>;
    // 优先用页面里 evaluate 出来的布尔量：直接匹配整段 JSON 会把 "captcha":false 这种键名当命中。
    const probe = (data.evaluate && typeof data.evaluate === "object" ? data.evaluate : undefined) as Record<string, unknown> | undefined;
    const flag = (key: string): boolean => probe?.[key] === true;
    const text = String(probe?.text || data.body || data.summary || "");
    const kind: "captcha" | "mfa" | "sso" | "slider" | undefined =
      flag("captcha") || (!probe && /captcha|验证码|图形码|geetest/i.test(text)) ? "captcha"
        : flag("mfa") || (!probe && /动态口令|两步验证|谷歌验证|authenticator|totp|短信验证码|\bmfa\b/i.test(text)) ? "mfa"
          : flag("slider") || (!probe && /滑块|拖动验证/i.test(text)) ? "slider"
            : flag("sso") || (!probe && /统一认证|单点登录|passport\.|oauth2?\/authorize|\bsaml\b/i.test(text)) ? "sso"
              : undefined;
    if (!kind) return false;
    this.state.auth_gate = { kind, task, detail: JSON.stringify(probe || text).slice(0, 240), at: Date.now() };
    const record = this.state.tasks[task];
    if (record && !["completed", "blocked", "failed"].includes(String(record.status))) {
      this.state.tasks[task] = {
        ...settleTask(record, {
          code: "auth_gate",
          reason: `登录门禁不可自动通过（识别到 ${kind}，证据：${String(this.state.auth_gate?.detail || "").slice(0, 120)}）：不要再试第二次，改走 unauth_exposure 或找别的取 Token 通道。`,
          by: "control",
        }),
        status: "blocked",
      };
    }
    return true;
  }

  /**
   * 攻击面降级（Plan B）的触发器：同一 host 被 WAF/强鉴权累计拦住 3 次，
   * 就把 `lateral_escape` 立起来（desk 据此派子域/旧版/移动端探测任务）。
   * 判断只看"被拦"特征，不看单次 403——单次 403 往往就是这个接口本身没权限。
   */
  recordHostBlock(request: BlackboxToolRequest, result: BlackboxToolResult): void {
    const tool = String(request.tool);
    const scanData = (result.data || {}) as Record<string, unknown>;
    // 字典/爬虫扫出来的一整片 412/403，本身就是 host 级 WAF 信号。
    // 只认 http.request 的话，qwen 那种"字典全被挡"的场面永远不上报 waf_escalation，
    // 战例库也就永远没机会被调用。
    if (["recon.content_discovery", "recon.api_routes", "katana.crawl"].includes(tool)) {
      this.recordScanWall(request, scanData, result);
      return;
    }
    if (!["http.request", "burp.request"].includes(tool)) return;
    const data = scanData;
    const url = String(request.input?.url || data.url || data.final_url || "");
    if (!url) return;
    let host = "";
    try { host = new URL(url).host; } catch { return; }
    const status = Number(data.status || 0);
    const body = String(data.body || data.summary || "");
    // 412/418/1020 是云 WAF 的典型"阻断"码（securityfs 就是 412），
    // 只把 403 当 WAF 会漏掉最常见的那一堵墙。
    //
    // 身份/人机挑战也必须算墙（2026-11-04）：`proxy_authentication_required` 这类正文
    // 一个 "waf" 字样都没有，只按下面那条正则判会落到 kind="auth"，
    // 于是一堵真墙连 waf_escalation 都立不起来——白名单永远不覆盖它。
    const identityHit = identityWallOf(body);
    const waf = Boolean(identityHit)
      || /waf|拦截|阻断|blocked by|security policy|securityfs|cloudflare|cf-error|安全策略|请求异常|非法请求|forbidden/i.test(body);
    const kind = waf && [403, 406, 412, 418, 429, 503, 1020].includes(status) ? "waf" : [401, 403].includes(status) ? "auth" : undefined;
    if (!kind) return;
    /**
     * 匿名基线撞墙 ≠ 整机被封（2026-11-07 干净对照实测）。
     *
     * `anonymous:true` 会跳过整个 Cookie/Token 罐，请求里一条我方凭证都没有。
     * 这种请求被身份墙挡回来，只能说明「这个路径需要登录 / 被目标风控覆盖」，
     * 恰恰是未授权访问面**应当记录的观测**；拿它去累计 `blocked_hosts`、
     * 立 `waf_escalation`、推 `lateral_escape`，等于把「匿名进不去」误判成
     * 「带凭证也进不去」，进而把整台主机判死。
     *
     * 实测：对照会话 1dd9ded9ed239711 开局自检 healthy（带凭证 200 / 匿名 200），
     * 之后 3 发 `anonymous:true` 的 /ecs、/lingma 撞 403 风控信封，仍被记成
     * `blocked_hosts` 3 hits + `kinds:["waf"]`，指纹 3909321a6519 与当初
     * 毒 cna 造出来的假墙**一模一样**（同一个阿里云 punish 信封）——
     * 说明按 body 指纹也分不清这两类根因，只能靠「请求带不带凭证」。
     */
    // 统一身份闸：结果自带的 credential_mode 优先，兼容旧证据/单测直接构造的 input 标记。
    // 不能再只读 request.input.anonymous —— httpTool 会原地 delete 它（同一对象引用），
    // 2026-11-07 实测这道闸从未生效，匿名 403 把 blocked_hosts 累到 11 hits。
    if (isAnonymousWallRequest(request, result)) return;
    const health = this.state.seed_health?.[host];
    /**
     * 先怀疑自己，再怀疑目标（2026-11-07 的教训）。
     *
     * 种子里的 `cna` 让阿里云整站回 403 + attestation 挑战页，而同一时刻匿名访问同一个 URL
     * 是 200 正常页。系统当时把它当身份墙 → 3 次拉黑整机 → 6+8 个任务全建在错误前提上，
     * 两场共烧 17.0M tokens、拿到 2 条低中危。**这一条判断的成本是一发匿名请求。**
     */
    if (health?.verdict === "seed_tainted") {
      this.addInterrupts([{
        id: `seed-tainted:${host}`, kind: "seed_tainted", severity: "high",
        text: `${host} 返回 ${status} 但自检证明这是**我方 Cookie 造成的**（带凭证被拦、匿名正常，已剔除 ${(health.tainted || []).join("/") || "污染项"}）：`
          + `这不是目标的墙，别再换编码/换头去绕它，也**不要**把这个 host 记成封锁——`
          + `直接用（已清理的）会话罐继续打原接口，或显式传 anonymous:true 做未授权基线。`,
        data: { host, status, tainted: health.tainted || [] },
      }]);
      return;
    }
    // 没见过结论的 host：先登记自检，别急着累计。自检由 desk 真正发出（2 发请求）。
    if (!health) {
      this.requestSeedProbe(host, url,
        `首次在 ${host} 收到 ${status}${identityHit ? `/${identityHit}` : ""}：先做「带凭证 vs 匿名」对照，确认这堵墙不是我方种子造的`);
    }
    this.state.blocked_hosts ||= {};
    const record = (this.state.blocked_hosts[host] ||= { hits: 0, kinds: [], at: Date.now() });
    /**
     * 上一次拦截的指纹（同一 host）。用来判"这墙稳不稳"。
     *
     * 为什么必须记（2026-11-04 wanxiaozhi 实测）：同一 URL 在 200/33947 和 403/7155 之间
     * 反复横跳，连一个**不存在**的路径都一次 403 一次 404。这种"墙"没有稳定规则，
     * 8 档阶梯打的是空气；正确处理是降频重试，而判据只能是"两次指纹不一样"。
     * 只观测一次时不判抖动（没有两次观测就不该猜）。
     */
    const fingerprint = body ? wallSignature({ status, body }) : "";
    const previousFingerprint = record.last_fp;
    record.hits += 1;
    record.at = Date.now();
    record.last_fp = fingerprint;
    if (!record.kinds.includes(kind)) record.kinds = [...record.kinds, kind].slice(-4);
    // 第 2 次命中 WAF 就先立 waf_bypass（阶梯），别等第 3 次直接放弃墙。
    // 判性质要看**完整 body**，不能用截断后的 marker——attestation 特征串常在后半段。
    if (kind === "waf" && record.hits >= 2 && !this.state.waf_escalation) {
      this.state.waf_escalation = {
        host, at: Date.now(), hits: record.hits,
        marker: body.replace(/\s+/g, " ").slice(0, 60),
        kind: wallKind({ status, body, firstFp: fingerprint, secondFp: previousFingerprint }),
      };
    }
    if (record.hits >= 3 && !this.state.lateral_escape) {
      // WAF 类拦截先让 waf_bypass 阶梯跑过：墙是规则堆出来的，人能绕，脚本也能。
      // 阶梯一次没跑（0 calls）就跳横向逃逸 = 把可绕的墙判成永久封锁。
      //
      // 再加一道闸（2026-11-07）：`lateral_escape` 是全系统最贵的动作——一旦立起来，
      // 后面所有任务都从"打这个接口"变成"去找别的资产"，而它的前提
      // （这是目标自己的墙）从来没被验证过。那次两场 17.0M tokens 就是被一个
      // 自己造的假墙推上去的。所以：**没做过种子自检、也没跑过绕过阶梯时，
      // 门槛翻倍（3→6、兜底 6→12）**——先把"是不是我方凭证造的"这件事问清楚。
      const gateOpen = Boolean(health) || (this.state.playbook_runs?.waf_bypass?.calls || 0) > 0;
      const needHits = gateOpen ? 3 : 6;
      const ladderTried = (this.state.playbook_runs?.waf_bypass?.calls || 0) > 0;
      if (record.hits >= needHits && (kind !== "waf" || ladderTried || record.hits >= (gateOpen ? 6 : 12))) {
        this.state.lateral_escape = { host, at: Date.now(), hits: record.hits };
      }
    }
  }

  /** 扫描类工具整片被挡时的 WAF 累计：先判"是不是整片"，再走和单请求同一条累加路径。 */
  private recordScanWall(request: BlackboxToolRequest, data: Record<string, unknown>, result?: BlackboxToolResult): void {
    // 与单发请求同一条身份闸：匿名字典/爬虫整片 403 也不能判成 host 级 WAF。
    if (isAnonymousWallRequest(request, result || { data })) return;
    const items = (Array.isArray(data.items) ? data.items : Array.isArray(data.results) ? data.results : []) as Array<Record<string, unknown>>;
    const targetUrl = String(request.input?.url || data.target || data.url || "");
    // 0 产出：撞墙与"本来就没什么路径"在结果上一模一样（ffuf 的 -ac 还会把整片
    // 同款 412 当 catch-all 滤掉）。这里不猜，登记一次根路径补枪，由 desk 判。
    if (!items.length) {
      if (Number(data.count || 0) > 0) return;
      let host = "";
      try { host = new URL(targetUrl).host; } catch { return; }
      this.requestWallProbe(host, targetUrl, `${request.tool} 0 产出，无法区分"没路径"与"整片被墙"`);
      return;
    }
    const wafStatuses = [403, 406, 412, 418, 503, 1020];
    const blocked = items.filter(item => wafStatuses.includes(Number(item.status || 0)));
    if (!blocked.length) return;
    const total = items.length;
    // 样本太少不算墙（一次只命中 1 条的结果本来就说明不了 host 级问题）；
    // 3 条以上，或"全部命中项都是同一个拦截码"才算墙。
    if (total < 3) return;
    if (blocked.length < 3 && blocked.length !== total) return;
    const statuses = [...new Set(blocked.map(item => Number(item.status || 0)))];
    const first = String(blocked[0]?.url || blocked[0]?.input || request.input?.url || "");
    let host = "";
    try { host = new URL(first).host; } catch { return; }
    if (!host) return;
    // 整片字典被挡同样要先问"是不是我方凭证造的"：字典里 100 条 403 全是种子污染时，
    // 判成 WAF 会让整套侦察线整体报废（2026-11-07 就是这么烧掉两场的）。
    const scanHealth = this.state.seed_health?.[host];
    if (scanHealth?.verdict === "seed_tainted") {
      this.addInterrupts([{
        id: `seed-tainted:${host}`, kind: "seed_tainted", severity: "high",
        text: `${host} 整片字典被挡，但自检证明这是**我方 Cookie** 造成的（已剔除 ${(scanHealth.tainted || []).join("/") || "污染项"}）：`
          + `不是 WAF，别换字典/降速/换编码；换已清理的会话罐或 anonymous:true 重跑同一本字典。`,
        data: { host, tainted: scanHealth.tainted || [] },
      }]);
      return;
    }
    if (!scanHealth) {
      this.requestSeedProbe(host, first || targetUrl, `${request.tool} 整片被挡（${blocked.length}/${total}）：先做「带凭证 vs 匿名」对照，确认不是我方种子造的墙`);
    }
    this.state.blocked_hosts ||= {};
    const record = (this.state.blocked_hosts[host] ||= { hits: 0, kinds: [], at: Date.now() });
    record.hits += 1;
    record.at = Date.now();
    if (!record.kinds.includes("waf")) record.kinds = [...record.kinds, "waf"].slice(-4);
    const marker = `${request.tool} 扫描 ${blocked.length}/${total} 条返回 ${statuses.join("/")}`;
    // 一整片字典被同一个拦截码挡回来，证据强度远高于单条请求，第一次就立墙；
    // 横向逃逸仍然要求阶梯先跑过（墙先绕，逃逸是最后一档）。
    if (!this.state.waf_escalation) {
      // 扫描结果只有状态码、没有正文，判不出身份墙特征。按保守方向落 rule_wall
      // （继续绕），由 desk 的补枪再拿正文复核一次。
      this.state.waf_escalation = { host, at: Date.now(), hits: record.hits, marker, kind: wallKind({}) };
    }
    if (record.hits >= 3 && !this.state.lateral_escape) {
      // 与单请求同一条闸：没做种子自检、也没跑过阶梯时，门槛翻倍（3→6、兜底 6→12）。
      const ladderTried = (this.state.playbook_runs?.waf_bypass?.calls || 0) > 0;
      const gateOpen = Boolean(scanHealth) || ladderTried;
      const needHits = gateOpen ? 3 : 6;
      if (record.hits >= needHits && (ladderTried || record.hits >= (gateOpen ? 6 : 12))) {
        this.state.lateral_escape = { host, at: Date.now(), hits: record.hits };
      }
    }
  }

  /**
   * 登记一次"补一枪"：同一 host 一次、整场上限 3 次。
   * 补枪由 desk 真正发出（2 发：基线 + 复测），这里只保证不重复登记。
   */
  requestWallProbe(host: string, url: string, reason: string): boolean {
    if (!host) return false;
    this.state.linkage ||= {};
    const hosts = this.state.linkage.waf_probe_hosts || [];
    if (hosts.includes(host)) return false;
    if (Number(this.state.linkage.waf_probe_count || 0) >= 3) return false;
    this.state.waf_probe = { host, url, reason, at: Date.now() };
    return true;
  }

  /** 补枪已处理（desk 调）：记账并入 host 名单，避免下一轮又登记。 */
  consumeWallProbe(): { host: string; url: string; reason: string; at: number } | undefined {
    const probe = this.state.waf_probe;
    if (!probe) return undefined;
    this.state.waf_probe = undefined;
    this.state.linkage ||= {};
    const hosts = this.state.linkage.waf_probe_hosts || [];
    this.state.linkage.waf_probe_hosts = [...new Set([...hosts, probe.host])].slice(-20);
    this.state.linkage.waf_probe_count = Number(this.state.linkage.waf_probe_count || 0) + 1;
    return probe;
  }

  /**
   * 登记一次种子自检。同一 host 只登记一次（整场最多 4 个 host）。
   *
   * 与 `requestWallProbe` 的区别：那个问的是"这堵墙是不是真的整片拦截"，
   * 这个问的是**更前置的一层**——"这堵墙是不是我们自己造的"。
   * 顺序不能反：先证伪自己的凭证，再去判目标的风控。
   */
  requestSeedProbe(host: string, url: string, reason: string): boolean {
    if (!host || !url) return false;
    const jarFp = String(this.state.seed_jar_fingerprint || "");
    const existing = this.state.seed_health?.[host];
    if (existing) {
      /**
       * 结论只对「当时那罐」成立（2026-11-07 对照实测）：服务端 Set-Cookie 会让
       * `cna` 运行时重生、browser.open 会注入种子、自检会剔除毒 cookie。
       * 罐一变，旧结论必须作废重检，否则「healthy」会一直沿用到凭证已经换了的状态。
       * 冷却窗口避免开发环境里罐频繁抖动时每轮重检（默认 5 分钟，可由 desk 配）。
       */
      const changed = Boolean(jarFp) && Boolean(existing.jar_fingerprint) && existing.jar_fingerprint !== jarFp;
      if (!changed) return false;
      const cooldown = Math.max(0, Number(this.state.seed_probe_cooldown_ms ?? 300_000));
      if (Date.now() - Number(existing.at || 0) < cooldown) return false;
      (this.state.seed_health_stale ||= {})[host] = {
        previous_verdict: existing.verdict,
        old_fingerprint: existing.jar_fingerprint,
        new_fingerprint: jarFp,
        at: Date.now(),
      };
      // 删掉结论：recordHostBlock 的 gateOpen 会自然回到「无结论」的保守门槛。
      const health = (this.state.seed_health ||= {}) as Record<string, SeedHealthRecord>;
      delete health[host];
    }
    if (this.state.seed_probe?.host === host) return false;
    const done = Object.keys(this.state.seed_health || {}).length;
    if (done >= 4) return false;
    this.state.seed_probe = { host, url, reason, at: Date.now() };
    return true;
  }

  consumeSeedProbe(): { host: string; url: string; reason: string; at: number } | undefined {
    const probe = this.state.seed_probe;
    if (!probe) return undefined;
    this.state.seed_probe = undefined;
    return probe;
  }

  /** 记下自检结论。返回 false 表示这条结论比已有的更弱，没有覆盖（避免来回翻烧饼）。 */
  noteSeedHealth(host: string, record: SeedHealthRecord): boolean {
    if (!host || !record) return false;
    this.state.seed_health ||= {};
    const previous = this.state.seed_health[host];
    const rank: Record<SeedHealthRecord["verdict"], number> = {
      seed_tainted: 4, host_walled: 3, seed_stale: 2, healthy: 1, inconclusive: 0,
    };
    if (previous && rank[previous.verdict] > rank[record.verdict]) return false;
    // 把结论钉在当时的罐上：调用方可显式传，否则用 desk 每轮刷新的当前指纹。
    this.state.seed_health[host] = {
      ...record,
      jar_fingerprint: record.jar_fingerprint ?? this.state.seed_jar_fingerprint,
    };
    return true;
  }

  /** 该 host 的墙是不是"我方凭证造的"。用于 recordHostBlock 提前收手。 */
  seedTaintedHost(host: string): boolean {
    return this.state.seed_health?.[host]?.verdict === "seed_tainted";
  }

  /**
   * 登记工具缺口（主 Agent 的 tool_gaps）。返回本次真正新增的条目：
   * 同一条缺口重复上报不写事件、不进上下文，免得每轮复读同一句"我缺个反连平台"。
   */
  recordToolGaps(gaps: Array<Record<string, unknown>>): Array<{ need: string; why?: string; tool?: string; alternative?: string; blocked_task?: string; missing?: boolean; at: number }> {
    const fresh: Array<{ need: string; why?: string; tool?: string; alternative?: string; blocked_task?: string; missing?: boolean; at: number }> = [];
    if (!Array.isArray(gaps) || !gaps.length) return fresh;
    this.state.linkage ||= {};
    const list = this.state.linkage.tool_gaps || [];
    const key = (text: unknown) => String(text || "").toLowerCase().replace(/\s+/g, "");
    for (const gap of gaps) {
      const need = String(gap?.need || "").trim();
      if (!need) continue;
      const normalized = key(need);
      if (list.some(item => key(item.need) === normalized)) continue;
      const entry = {
        need: need.slice(0, 200),
        why: String(gap.why || "").trim().slice(0, 400) || undefined,
        tool: String(gap.tool || "").trim().slice(0, 120) || undefined,
        alternative: String(gap.alternative || "").trim().slice(0, 300) || undefined,
        blocked_task: String(gap.blocked_task || "").trim().slice(0, 120) || undefined,
        missing: gap.missing === true ? true : undefined,
        at: Date.now(),
      };
      list.push(entry);
      fresh.push(entry);
    }
    if (fresh.length) this.state.linkage.tool_gaps = list.slice(-12);
    return fresh;
  }

  recordParamWander(task: string, request: BlackboxToolRequest, result: { ok: boolean; data?: Record<string, unknown> }): void {
    if (!result.ok) return;
    const data = (result.data || {}) as Record<string, unknown>;
    const raw = String(request.input?.url || data.final_url || data.requested_url || "");
    if (!raw) return;
    let parsed: URL;
    try { parsed = new URL(raw); } catch { return; }
    if (!["http.request", "http.diff"].includes(String(request.tool))) return;
    // RESTful 归一化：/api/doc/86 与 /api/doc/118 属于同一资源族，聚合到 /api/doc/{id}。
    const normalized = routeTemplate(parsed.pathname, (this.state.route_memory ||= {}));
    const key = `${parsed.host}${normalized.path}`;
    const body = normalizeBody(String(data.body || "").replace(/\s+/g, " ").trim(), normalized.ids).slice(0, 300);
    // 耗时也是"形状"。时间盲注 / sleep 探测的响应体 100% 相同，唯一区别是耗时；
    // 不把耗时纳入指纹，等于把"最需要重复请求的打法"直接判成"参数面榨干"。
    const timingBucket = (ms: number): number => (ms < 300 ? 0 : ms < 1000 ? 1 : ms < 2500 ? 2 : 3);
    const fingerprint = hash({ status: Number(data.status || 0), t: timingBucket(Number(data.duration_ms || 0)), body });
    this.state.param_watch ||= {};
    // 模板一旦折叠成功（/api/users/{p3}），把先前记在**同一 stem 的原始路径**上的计数全迁移过来：
    // alice 一次 + bob 一次若各自记在自己路径下，永远凑不满阈值，熔断就漏判。
    const rawKey = `${parsed.host}${parsed.pathname}`;
    const watch = (this.state.param_watch[key] ||= { calls: 0, queries: [], variants: [], fingerprints: [] });
    if (key !== rawKey) {
      const stem = key.slice(0, key.lastIndexOf("/"));
      const depth = key.split("/").length;
      for (const existing of Object.keys(this.state.param_watch)) {
        if (existing === key || !existing.startsWith(`${stem}/`) || existing.split("/").length !== depth) continue;
        const stale = this.state.param_watch[existing]!;
        watch.calls += stale.calls;
        watch.queries = [...new Set([...watch.queries, ...stale.queries])].slice(-20);
        watch.variants = [...new Set([...(watch.variants || []), ...(stale.variants || [])])].slice(-20);
        // 折叠前那几次的指纹天生带路径噪音（alice / bob 原样留在正文里），
        // 带进来会把 1 种"真实形状"算成 2 种，直接把熔断阈值顶掉——所以只迁计数，不迁指纹。
        delete this.state.param_watch[existing];
      }
    }
    watch.calls += 1;
    const query = parsed.search || "(none)";
    if (!watch.queries.includes(query)) watch.queries = [...watch.queries, query].slice(-20);
    // 路径即 ID 的遍历没有 query，用原始 pathname 当"变体"计数。
    watch.variants ||= [];
    if (parsed.pathname !== normalized.path && !watch.variants.includes(parsed.pathname)) {
      watch.variants = [...(watch.variants || []), parsed.pathname].slice(-20);
    }
    if (!watch.fingerprints.includes(fingerprint)) watch.fingerprints = [...watch.fingerprints, fingerprint].slice(-10);
    const keys = Object.keys(this.state.param_watch);
    if (keys.length > 40) delete this.state.param_watch[keys[0]!];
    if (watch.stalled_at) return;
    // 每 ratio 次调用必须产出一个新指纹；产出速度掉下来就说明参数面榨干了。
    // 5 次 / 5 种指纹（真在探测）不会熔断；31 次 / 7 种（本机现状）会熔断。
    // "参数面在变"有两种：query 变了，或者路径里的 id 变了（RESTful 遍历）。
    const varied = watch.queries.length >= this.paramStall.queries || (watch.variants || []).length >= this.paramStall.variants;
    const stalled = watch.calls >= this.paramStall.calls && varied
      && watch.fingerprints.length * Math.max(1, this.paramStall.ratio) <= watch.calls;
    if (!stalled) return;
    watch.stalled_at = Date.now();
    this.state.param_stall_alert = { path: key, calls: watch.calls, queries: watch.queries.length, fingerprints: watch.fingerprints.length, variants: (watch.variants || []).length, at: watch.stalled_at };
    // 熔断只发提示，不把任务判死。盲注与越权遍历本来就要"同一形状打很多次"，
    // 判 blocked 会把需要耐心的打法提前掐死；真正的浪费由权重预算兜住。
    this.addInterrupts([{
      id: `param-stall:${key}:${watch.stalled_at}`, kind: "param_stall", severity: "medium",
      text: `${key} 已打 ${watch.calls} 次、${watch.queries.length} 种参数，响应指纹只有 ${watch.fingerprints.length} 种：若是盲注/越权遍历，改看 time/status 维度继续；若是纯换参数穷举，换端点。`,
      data: { path: key, calls: watch.calls, queries: watch.queries.length, fingerprints: watch.fingerprints.length },
    }]);
  }

  /**
   * 记一次响应：被拒绝就累加 streak，触墙后把当前任务置 blocked 并留一条 alert 让 Observer 介入。
   * 401/业务码一律算拒绝；换到凭证能进（非拒绝响应）会把 streak 清零。
   */
  recordAuthDenial(task: string, request: BlackboxToolRequest, result: { ok: boolean; data?: Record<string, unknown> }): void {
    const data = (result.data || {}) as Record<string, unknown>;
    // 以这次请求自己的 URL 为准：同一任务会打很多入口，退回任务 target 会把它们压成同一个入口。
    const url = String(request.input?.url || data.final_url || data.requested_url || this.state.tasks[task]?.target || "");
    if (!url) return;
    const verdict = denialOf(data, { NIANYUN_AUTH_WALL_CODES: this.authWall.codes.join(",") });
    // 放行通道里的探测是"绕墙的正路"，不是撞墙：被拒也不进 streak，否则墙会被自己人推倒。
    // 只在 denied 时跳过——正常响应仍然要经过 trackDenial，那里负责把 streak 清零。
    if (verdict.denied && bypassChannelOf(url, request.input, {
      playbook: this.playbookOf(task),
      taskIntent: this.intentOf(task),
      safePaths: this.wallOptions.safePaths,
      allowUnauthPlaybook: this.wallOptions.allowUnauthPlaybook,
      allowBypass: this.wallOptions.allowBypass,
    })) return;
    const tracked = trackDenial(this.state, { url, denied: verdict.denied, code: verdict.code }, this.authWall.streak_limit);
    if (!verdict.denied) return;
    const wall = tracked.state;
    if (!wall) return;
    if (tracked.tripped) {
      this.state.auth_wall_alert = { kind: "wall", host: wall.host, tasks: [task], at: Date.now() };
      const streak = Number((wall as { streak?: number }).streak || this.authWall.streak_limit);
      this.state.tasks[task] = {
        ...settleTask(this.state.tasks[task] || {}, {
          code: "blocked_by_auth",
          reason: `统一鉴权拦截（${wall.host} 连续 ${streak} 次 ${verdict.reason}）：该主机需要 Token 才能继续，同一条路再遍历不会改变结论。`,
          by: "control",
        }),
        status: "blocked",
      };
      return;
    }
    if (wall.tripped_at && this.state.tasks[task]?.status === "running") {
      this.state.tasks[task] = {
        ...settleTask(this.state.tasks[task] || {}, {
          code: "blocked_by_auth",
          reason: `统一鉴权拦截（${wall.host} 在 ${new Date(wall.tripped_at).toISOString()} 判定需要凭证，本次 ${verdict.reason}）：等拿到登录态/Token 再试。`,
          by: "control",
        }),
        status: "blocked",
      };
    }
  }
  /** 该任务绑定的 playbook（别名归一后）。 */
  playbookOf(task: string): string | undefined {
    return playbookById(String(this.state.tasks[task]?.playbook || ""))?.id;
  }
  /** 任务的意图文本（purpose + completion_criteria）：没绑 playbook 时用它认"未授权验证"。 */
  intentOf(task: string): string {
    const record = this.state.tasks[task];
    if (!record) return "";
    return `${record.purpose || ""} ${record.completion_criteria || ""}`.trim();
  }
  /** 记一次调用：先记 calls，成功与否在 finish 里补。 */
  recordPlaybookCall(task: string, tool: string): void {
    const id = this.playbookOf(task);
    if (!id) return;
    const runs = this.state.playbook_runs ||= {};
    const run = runs[id] ||= { calls: 0, ok: 0, failed: 0, steps: {} };
    run.calls = Number(run.calls || 0) + 1;
    const step = stepForTool(id, tool);
    if (step) {
      const entry = (run.steps ||= {})[step] ||= { calls: 0, ok: 0 };
      entry.calls = Number(entry.calls || 0) + 1;
    }
    run.last_at = Date.now();
  }
  /** 记一次结果：成功点亮步骤，失败留下最后错误，覆盖表据此回答"卡在哪一步"。 */
  recordPlaybookResult(task: string, tool: string, result: { ok: boolean; summary?: string }): void {
    const id = this.playbookOf(task);
    if (!id) return;
    const runs = this.state.playbook_runs ||= {};
    const run = runs[id] ||= { calls: 0, ok: 0, failed: 0, steps: {} };
    run.last_at = Date.now();
    const step = stepForTool(id, tool);
    if (result.ok) {
      run.ok = Number(run.ok || 0) + 1;
      if (step) {
        const entry = (run.steps ||= {})[step] ||= { calls: 0, ok: 0 };
        entry.ok = Number(entry.ok || 0) + 1;
      }
      return;
    }
    run.failed = Number(run.failed || 0) + 1;
    run.last_error = { step, tool, summary: String(result.summary || "").slice(0, 240), at: Date.now() };
  }
  /**
   * Pending work that was never started (or was interrupted by the batch deadline) stays
   * pending with a reason instead of looking like a failure the model has to guess about.
   */
  defer(request: BlackboxToolRequest, key: string, reason: string): void {
    const action = this.state.actions[key];
    if (action) action.inFlight = false;
    const task = this.task(request, key);
    const current = this.state.tasks[task];
    /**
     * 终态不可回退（2026-11-10）。
     *
     * 旧写法无条件写 `status: "pending"`，于是"这条已 blocked"的判定会被一次延后登记
     * 悄悄撤销：任务在"结案 → 复活成 pending"之间来回，验收永远看到它没终态
     * （实测 1dd9ded9ed239711 的 8 条 pending 里有 3 条就是这么来的）。
     * 延后只对**还没结案**的任务有意义。
     */
    if (current && ["completed", "blocked", "failed"].includes(String(current.status))) return;
    /**
     * `reason` 是人话，不是码：它同时写进 `reason` 与 `outcome_reason`。
     * 旧写法把 `stage_timeout` / `advice_disposal_only` 这类机器码直接塞给
     * `outcome_reason`，而结案说明的验收判据会把纯机器码判成"不是说明"
     * （TASK_OUTCOME_NOT_EXPLAINED）。延后登记是控制面自己写的账，不该由模型背这口锅。
     */
    this.state.tasks[task] = { ...current, status: "pending", reason, outcome_reason: deferNote(reason) };
  }
  begin(request: BlackboxToolRequest, target: string, retryLimit: number, repeatLimit: number,
    options: { allowHeavy?: boolean } = {}): { key: string; blocked?: string } {
    const key = this.identity(request, target);
    const task = this.task(request, key);
    const action = this.state.actions[key] ||= { attempts: 0, failures: 0, unchanged: 0 };
    const status = this.state.tasks[task]?.status;
    const playbook = this.state.tasks[task]?.playbook;
    let blocked: string | undefined;
    // 已经判定鉴权墙：同主机、没带凭证、也不是登录入口的请求直接拒绝，别再当复读机。
    // 但未授权打法、敏感路径、显式 bypass 三条通道仍然放行（墙不是禁做未授权验证）。
    const verdict = wallVerdict(this.state, String(request.input?.url || target), request.input, {
      playbook,
      taskIntent: this.intentOf(task),
      safePaths: this.wallOptions.safePaths,
      allowUnauthPlaybook: this.wallOptions.allowUnauthPlaybook,
      allowBypass: this.wallOptions.allowBypass,
    });
    if (verdict.blocked) blocked = "auth_wall_requires_token";
    else if (verdict.bypass) recordWallBypass(this.state, String(request.input?.url || target), verdict.bypass);
    // 预算降级：墙钟/权重放不下完整时间盒时，重型扫描器本批不放行（不是失败，是延后）。
    if (!blocked && options.allowHeavy === false && isHeavyTool(String(request.tool || ""))) blocked = `budget_degraded:${String(request.tool)}`;
    // 排他任务：POST 面枚举被连续忽略后，除它本身与认证链外全部停手。
    const exclusive = this.state.exclusive_task;
    const authTask = ["auth_token", "jwt_auth"].includes(String(this.state.tasks[task]?.playbook || "")) || task.startsWith("auth_");
    if (exclusive && task !== exclusive && !authTask) blocked = `exclusive_task:${exclusive}`;
    // 工具 Fail-Fast：连续 0 产出已被判定无用的工具，会话内不再放行。
    if (this.state.tool_health?.[String(request.tool)]?.disabled) blocked = `tool_disabled:${String(request.tool)}`;
    if (["blocked", "failed"].includes(status || "") || (request.task_id && status === "completed")) blocked = `task_${status}`;
    else if (this.state.tasks[`action:${key}`]?.reason === "interrupted_unknown_outcome") blocked = "interrupted_unknown_outcome";
    else if (action.failures >= retryLimit + 1 || (this.state.tasks[task]?.failures || 0) >= retryLimit + 1) blocked = "task_retry_exhausted";
    else if (action.unchanged >= repeatLimit) blocked = "repeated_without_new_information";
    if (blocked) {
      // 排他锁只是"现在不许动"，不是任务失败：不能把它写成 blocked，否则锁解除后这些任务
      // 会永久停在 task_blocked（实测复现）。预算降级同理：延后，不是失败。
      const transient = blocked.startsWith("exclusive_task:") || blocked.startsWith("tool_disabled:") || blocked.startsWith("budget_degraded:");
      if (!transient && !["completed", "blocked", "failed"].includes(status || "")) this.state.tasks[task] = { ...this.state.tasks[task], status: blocked === "task_retry_exhausted" ? "failed" : "blocked", reason: blocked };
      return { key, blocked };
    }
    this.state.tasks[task] = { ...this.state.tasks[task], status: "running" };
    action.attempts += 1;
    action.inFlight = true;
    this.recordPlaybookCall(task, request.tool);
    return { key };
  }
  finish(request: BlackboxToolRequest, key: string, result: BlackboxToolResult, retryLimit: number, options: { timedOut?: boolean; rejected?: boolean } = {}): boolean {
    const action = this.state.actions[key]!;
    action.inFlight = false;
    const task = this.task(request, key);
    // A deadline hit says nothing about the tool or the target: keep the task pending and do
    // not bill it as a failure or as "no new information", otherwise three slow scans fail the run.
    if (options.timedOut) {
      this.state.tasks[task] = { ...this.state.tasks[task], status: "pending", outcome_reason: result.summary };
      return false;
    }
    // A rejected request (disabled tool, missing configuration, unusable input) never ran, so it
    // is not a failure either. Identical rejections still stop repeating; there is nothing new to learn.
    if (options.rejected) {
      const fingerprint = hash({ tool: result.tool, ok: false, data: withoutCredentialMetadata(result.data) });
      action.unchanged = action.fingerprint === fingerprint ? action.unchanged + 1 : 0;
      action.fingerprint = fingerprint;
      this.state.tasks[task] = { ...this.state.tasks[task], status: "pending", outcome_reason: result.summary };
      return false;
    }
    // Ignore timestamps and generated artifact filenames; they are not progress.
    const data = withoutCredentialMetadata(result.data);
    if (data.headers && typeof data.headers === "object") data.headers = Object.fromEntries(Object.entries(data.headers).filter(([k]) => !["date", "x-request-id", "traceparent", "server-timing"].includes(k.toLowerCase())));
    const fingerprint = hash({ tool: result.tool, ok: result.ok, data });
    action.unchanged = action.fingerprint === fingerprint ? action.unchanged + 1 : 0;
    action.fingerprint = fingerprint;
    this.recordPlaybookResult(task, request.tool, result);
    this.recordAuthDenial(task, request, result);
    this.recordParamWander(task, request, result);
    this.recordAuthGate(task, request, result);
    this.recordAnomaly(request, result);
    this.recordToolHealth(request.tool, result);
    this.recordHostBlock(request, result);
    if (this.state.exclusive_task && ["completed", "blocked", "failed"].includes(String(this.state.tasks[this.state.exclusive_task]?.status))) {
      this.state.exclusive_task = undefined;
      this.state.exclusive_reason = undefined;
    }
    this.state.tool_calls ||= {};
    this.state.tool_calls[String(request.tool)] = (this.state.tool_calls[String(request.tool)] || 0) + 1;
    if (!result.ok) {
      action.failures += 1;
      const failures = (this.state.tasks[task]?.failures || 0) + 1;
      this.state.tasks[task] = { ...this.state.tasks[task], status: failures >= retryLimit + 1 ? "failed" : "pending", failures, outcome_reason: result.summary };
    } else this.state.tasks[task] = { ...this.state.tasks[task], status: request.task_id ? "pending" : "completed" };
    const newResult = result.ok && !this.state.seenResults.includes(fingerprint);
    if (newResult) this.state.seenResults.push(fingerprint);
    return newResult;
  }
}

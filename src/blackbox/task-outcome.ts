/**
 * 任务结案说明（2026-11-05）。
 *
 * 起因是一个很直白的问题：报告里一排 `blocked`，但读者看不出**为什么被阻止**。
 * 盘完发现不是"忘了写"，是压根没有契约：
 *
 * 1. `reason` 一个字段被双向使用——创建时是"为什么派这个任务"，收口时被覆盖成
 *    `dead_end:ep:xxx` / `zero_entropy_diff` / `blocked_by_auth` 这类机器码，
 *    于是创建意图丢了，结案说明又只剩一个码。
 * 2. `outcome_reason` 是可选字段，只有模型主动提交 `task_outcomes` 才会写。
 *    控制面自己的 8 处自动收口（死胡同、零熵、焦点预算、假设归档、预算 settle…）
 *    一处都没写，报告直接落到 `reason` 兜底——而 `reason` 是"为什么派它"。
 * 3. 验收 (`acceptance.ts`) 判定"说明是否齐全"时写了
 *    `!task.outcome_reason?.trim() && !task.reason?.trim()`：`reason` 几乎永远非空，
 *    所以这条检查从上线起就没有真正拦住过任何东西。
 *
 * 这里把结案说明做成**结构化契约**：`outcome_code` 给机器统计，`outcome_reason`
 * 给人读且必须写清"卡在哪"，`outcome_evidence_ids` 指向证据，`outcome_by` 区分
 * 是模型自己结的案还是控制面兜底的。`reason` 从此只读。
 */

/** 结案码。新增收口路径时必须在这里登记，否则写不进去（见 settleTask）。 */
export const OUTCOME_CODES = [
  /** 模型自己判的 blocked/failed：缺凭证、缺权限、等外部回应。 */
  "agent_blocked", "agent_failed",
  /** 鉴权/登录门禁：本入口需要 Token，继续遍历无意义。 */
  "blocked_by_auth", "auth_gate",
  /** 攻击图判死胡同：同特征响应反复出现，任务指向的节点已无意义。 */
  "dead_end",
  /** 零熵熔断：同身份下连续多次对照无差异，没有新信息。 */
  "zero_entropy",
  /** 焦点预算：连续多轮没有高价值证据。 */
  "focus_stalled", "focus_budget_exhausted",
  /** 排他任务长期无人服务，控制面释放锁。 */
  "exclusive_starved",
  /** 依赖的假设已收口（归档/定案），任务前提消失。 */
  "hypothesis_closed",
  /** 预算/熔断收口：打过但没得出结论。 */
  "budget_settled",
  /** 交付面（站点声明文件等）多轮后仍被挡。 */
  "declaration_unmet",
  /** 攻击面枯竭：入口全被挡，没有可继续的路。 */
  "surface_starved",
  /** 人工取消/中断，结果未知。 */
  "operator_cancelled", "operator_blocked", "interrupted_unknown_outcome",
  /** 重试次数耗尽。 */
  "retries_exhausted",
] as const;

export type OutcomeCode = (typeof OUTCOME_CODES)[number];

export type TaskOutcomeInput = {
  code: OutcomeCode;
  /** 人话：必须写清"卡在哪"。纯机器码会被验收打回。 */
  reason: string;
  /** 支撑这条结论的证据 id。空表示"没有可引用证据"，此时 reason 必须说明原因。 */
  evidence_ids?: string[];
  /** agent = 模型自己结的案；control = 控制面兜底。 */
  by: "agent" | "control";
  at?: number;
};

const CODE_SET = new Set<string>(OUTCOME_CODES);

/**
 * 把结案说明写进任务记录。
 *
 * 刻意**不动 `reason`**：那个字段是"为什么派这个任务"，被覆盖过 7 次之后
 * 已经没法用来回答"这条最初要干什么"（e8b2c209 里 T1 的 reason 变成了
 * "焦点预算无实质进展"）。结案一律走 outcome_*。
 */
export function settleTask<T extends Record<string, unknown>>(task: T, outcome: TaskOutcomeInput): T {
  if (!CODE_SET.has(outcome.code)) {
    throw new Error(`unknown outcome code: ${outcome.code}`);
  }
  const evidence = (outcome.evidence_ids || []).map(id => String(id)).filter(Boolean);
  return {
    ...task,
    outcome_code: outcome.code,
    outcome_reason: String(outcome.reason || "").trim(),
    ...(evidence.length ? { outcome_evidence_ids: [...new Set(evidence)] } : {}),
    outcome_by: outcome.by,
    outcome_at: outcome.at ?? Date.now(),
  };
}

/** 纯机器码判定：`focus_stalled` / `dead_end:ep:x` 这类，人看了等于没写。 */
export function looksLikeCode(text: string): boolean {
  const value = String(text || "").trim();
  if (!value) return false;
  // 没有空格 + 只由小写字母/数字/下划线/冒号/点/斜杠/连字符组成 → 当成码。
  return !/\s/.test(value) && /^[a-z0-9_:./-]+$/.test(value);
}

/** 有没有"事实锚"：数字、URL、证据 id、括号里的具体值。说清"卡在哪"至少要有一个。 */
export function hasConcreteFact(text: string): boolean {
  const value = String(text || "");
  return /\d/.test(value) || /https?:\/\//.test(value) || /\bev-[0-9a-f]{6,}/i.test(value) || /`[^`]+`/.test(value);
}

export type OutcomeIssue = { code: string; severity: "error" | "warning"; message: string; detail?: string };

/**
 * 校验一条任务的结案说明是否够用。验收与结案审计共用这一份判据。
 *
 * `evidenceOnRecord` 是账本里**属于该任务**的证据 id：明明打过却不引用，
 * 比"没有证据可引用"严重得多，单独给一条 error。
 */
export function outcomeIssue(
  task: { status?: string; outcome_code?: string; outcome_reason?: string; outcome_evidence_ids?: string[]; outcome_by?: string },
  option: { evidenceOnRecord?: string[] } = {},
): OutcomeIssue[] {
  const status = String(task.status || "");
  if (!["blocked", "failed"].includes(status)) return [];
  /**
   * 代际区分：`outcome_by` 是本轮新增字段，**新写入一定带**（settleTask 强制）。
   * 没有它的都是升级前的老 checkpoint —— 对历史数据只报 warning：
   * 判据再对也不能把"升级前跑过的会话"变成验收不通过，否则 resume 一开就卡死。
   * 报告仍会把缺口显示出来（"（未记录结案原因）"），补救留给操作员。
   */
  const legacy = !task.outcome_by;
  const issues: OutcomeIssue[] = [];
  const reason = String(task.outcome_reason || "").trim();
  const code = String(task.outcome_code || "").trim();
  if (!code) {
    issues.push({
      code: legacy ? "TASK_OUTCOME_CODE_LEGACY" : "TASK_OUTCOME_CODE_MISSING",
      severity: legacy ? "warning" : "error",
      message: legacy ? `task_outcome_code_legacy` : `task_outcome_code_missing`,
      detail: legacy
        ? "这条任务结案于结案契约上线之前，没有 outcome_code；不阻塞验收，但报告里无法按原因归类。"
        : "blocked/failed 必须带 outcome_code（见 task-outcome.ts 的 OUTCOME_CODES），否则报告无法归类「这条为什么结束」。",
    });
  }
  if (!reason) {
    issues.push({
      code: legacy ? "TASK_OUTCOME_LEGACY_MISSING" : "TASK_OUTCOME_MISSING",
      severity: legacy ? "warning" : "error",
      message: legacy ? `task_outcome_legacy_missing` : `task_outcome_missing`,
      detail: "blocked/failed 必须写 outcome_reason：说清被什么挡住、卡在哪一步。只写状态不写原因等于没给结论。",
    });
    return issues;
  }
  if (looksLikeCode(reason)) {
    issues.push({
      code: "TASK_OUTCOME_NOT_EXPLAINED", severity: "error", message: `task_outcome_not_explained`,
      detail: `outcome_reason 是机器码「${reason}」，不是说明。要写清：被什么挡住（状态码/墙类型）、试到哪一步、为什么不再试。`,
    });
  } else if (reason.length < 10) {
    issues.push({
      code: "TASK_OUTCOME_TOO_SHORT", severity: "error", message: `task_outcome_too_short`,
      detail: `outcome_reason 只有 ${reason.length} 个字符（「${reason}」），不足以回答"为什么被阻止"。`,
    });
  } else if (!hasConcreteFact(reason)) {
    issues.push({
      code: "TASK_OUTCOME_NO_FACT", severity: "warning", message: `task_outcome_no_fact`,
      detail: "outcome_reason 里没有任何具体事实（状态码、轮数、URL、证据 id），读者仍无法判断依据。",
    });
  }
  const cited = (task.outcome_evidence_ids || []).filter(Boolean);
  const onRecord = (option.evidenceOnRecord || []).filter(Boolean);
  if (!cited.length && onRecord.length) {
    issues.push({
      code: "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE", severity: "error", message: `task_outcome_without_evidence_reference`,
      detail: `这条任务名下有 ${onRecord.length} 条执行证据（${onRecord.slice(0, 3).join("、")}${onRecord.length > 3 ? "…" : ""}），但结案说明一条都没引用。`
        + `"为什么被阻止"必须能回到具体请求上。`,
    });
  }
  return issues;
}

/**
 * 结案证据引用自动回填（2026-11-07，对照会话 1dd9ded9ed239711）。
 *
 * 旧行为：模型把 blocked/failed 的理由写成一段人话、没点名 ev-id 时，
 * `progress.merge` 直接 reject `outcome_without_evidence_reference`，而账本里
 * 明明躺着这条任务的 8 条证据。模型没有补引用的入口（幂等分支只接受它主动
 * 提交的 id），同一条错误于是每轮重演，最后以 `unrepairable` 进 DLQ。
 *
 * 这里不猜语义，只做两件事：
 *   ① 从账本里筛出 **data.task_id 属于本任务** 的证据；
 *   ② 用结案理由里的词做一次轻量相关性筛选，命中就只取命中的、不硬凑；
 *      一条都不命中才退回「最近 N 条」，并把结果标成 heuristic 供人工复核。
 *
 * 调用方必须只回填「完全没引用」的空位：已有引用一律不动，历史结论不可被悄悄改写。
 */
export type AutoRepairResult = {
  ids: string[];
  /** 结案理由的关键词是否命中了证据元数据。false = 纯启发式，需要复核。 */
  matched: boolean;
  /** 审计日志用的一句话：为什么选这几条。 */
  basis: string;
};

type RepairEvidence = { id?: unknown; kind?: unknown; summary?: unknown; data?: unknown };

function repairTokens(text: string): string[] {
  const raw = String(text || "").toLowerCase().match(/[a-z0-9_]{3,}|[\u4e00-\u9fff]{2,}/g) || [];
  return [...new Set(raw)].filter(token => token.length >= 2).slice(0, 40);
}

function repairHaystack(item: RepairEvidence): string {
  const data = item?.data && typeof item.data === "object" && !Array.isArray(item.data)
    ? item.data as Record<string, unknown> : {};
  return [item?.id, item?.kind, item?.summary, data.tool, data.status, data.status_code,
    data.url, data.result_evidence_id, data.diff_field]
    .map(value => String(value ?? "").toLowerCase()).join(" ");
}

export function autoRepairOutcomeEvidence(input: {
  reason: string;
  taskId: string;
  evidence: RepairEvidence[];
  limit?: number;
}): AutoRepairResult | undefined {
  const limit = Math.max(1, Math.min(Math.trunc(Number(input.limit ?? 3)) || 3, 8));
  const own = (input.evidence || []).filter(item => {
    const data = item?.data && typeof item.data === "object" && !Array.isArray(item.data)
      ? item.data as Record<string, unknown> : {};
    return String(data.task_id || "") === input.taskId && Boolean(String(item?.id || "").trim());
  });
  if (!own.length) return undefined;
  const tokens = repairTokens(input.reason);
  const scored = own.map((item, index) => {
    const hay = repairHaystack(item);
    return { id: String(item.id), index, hits: tokens.filter(token => hay.includes(token)) };
  });
  const related = scored.filter(entry => entry.hits.length).slice(-limit);
  if (related.length) {
    const words = [...new Set(related.flatMap(entry => entry.hits))].slice(0, 4).join("、");
    return {
      ids: related.map(entry => entry.id),
      matched: true,
      basis: `结案理由里的「${words}」命中 ${related.length}/${own.length} 条本任务证据，按命中项回填；未命中项不硬凑。`,
    };
  }
  const fallback = own.slice(-limit).map(item => String(item.id));
  return {
    ids: fallback,
    matched: false,
    basis: `结案理由与本任务 ${own.length} 条证据没有关键词重叠，启发式取最近 ${fallback.length} 条；`
      + "这只是记账补齐，不代表它们能支撑该结论，报告复核时请人工确认。",
  };
}

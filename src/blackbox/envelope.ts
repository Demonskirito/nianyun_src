/**
 * 结构化错误信封（Structured Error Envelope）。
 *
 * 2026-10-28 实测的两个"猜谜循环"：
 *   ① `task_outcomes[0]` 因 `deliverables_met: true` 被丢，模型只收到一句 zod 原文；
 *   ② `audit_ids` 引用了 `agent-analysis` 证据，模型只收到 `actual kind=agent-analysis`，
 *      于是同一错证据被提交了 7 轮——它不知道"该换成哪一条"。
 *
 * 结论：协议层每次拒绝都必须回答三个问题——**哪个字段、为什么、该写什么**，
 * 能给出候选池的（可用 id / 该工具真实键）就直接给池子，让模型做选择而不是猜。
 */

export type RejectEnvelope = {
  /** 粗分类：invalid_tool_request / invalid_task_outcome / invalid_finding / … */
  error_type: string;
  /** 被拒的顶层字段（tool_requests / task_outcomes / findings / …）。 */
  dropped_field?: string;
  /** 该字段内的序号。 */
  index?: number;
  /** 机器可读原因（zod message 或校验码），供日志聚合。 */
  reason: string;
  /** 人话纠错：下一轮该写成什么。 */
  hint: string;
  /** 该工具/schema 真正接受的键（有就填，直接抄）。 */
  valid_keys?: string[];
  /** 可直接复制的最小示例。 */
  example?: Record<string, unknown>;
  /** 可用的候选 id 池（audit_ids / evidence_ids 场景）。 */
  valid_ids?: string[];
  /** 定位：`required_tasks[2]`——模型可以直接对应到自己发的那一条。 */
  target?: string;
  /** 缺字段（invalid_type + received=undefined 翻译而来）：补上就能过。 */
  missing_keys?: string[];
  /** 取值不合法：键 → "expected X, got Y"。 */
  invalid_keys?: Record<string, string>;
  /** 不认识的键：摘掉即可。 */
  unknown_keys?: string[];
  /** 可直接照抄的正确形状（来自 fieldGuide / toolGuide 的示例）。 */
  correct_shape_example?: Record<string, unknown>;
};

/** 字段名 → error_type 前缀，避免把工具请求和结案记录混为一类。 */
const TYPE_BY_FIELD: Record<string, string> = {
  tool_requests: "invalid_tool_request",
  task_outcomes: "invalid_task_outcome",
  required_tasks: "invalid_required_task",
  findings: "invalid_finding",
  hypotheses: "invalid_hypothesis",
  advice_decisions: "invalid_advice_decision",
  evidence_queries: "invalid_evidence_query",
};

export function errorTypeForField(field: string): string {
  return TYPE_BY_FIELD[field] || `invalid_${String(field || "item").replace(/s$/, "")}`;
}

/** 一行文本形式：事件正文、下一轮上下文都直接用它。 */
export function envelopeLine(envelope: RejectEnvelope): string {
  const parts = [`[${envelope.error_type}]`];
  if (envelope.dropped_field) {
    parts.push(envelope.index === undefined ? envelope.dropped_field : `${envelope.dropped_field}[${envelope.index}]`);
  }
  parts.push(`原因：${envelope.reason}`);
  parts.push(`改成：${envelope.hint}`);
  if (envelope.valid_keys?.length) parts.push(`可用键：${envelope.valid_keys.join(", ")}`);
  if (envelope.valid_ids?.length) parts.push(`可用 id：${envelope.valid_ids.join("、")}`);
  if (envelope.example) parts.push(`示例：${JSON.stringify(envelope.example)}`);
  return parts.join(" ｜ ");
}

/** 把一批信封压成一段可读文本（限制条数，避免上下文爆炸）。 */
export function envelopeText(envelopes: RejectEnvelope[], limit = 6): string {
  return envelopes.slice(0, limit).map(envelopeLine).join("\n");
}

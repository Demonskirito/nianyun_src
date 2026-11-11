/**
 * Observer 审查结果"过期"时该怎么处置，以及审查排队的 issues 去重。
 *
 * 背景（gray-push-intl.oppo.com 那一轮的真实死法）：Observer 审查被转成后台守护进程异步跑，
 * 主循环继续推进状态；等结果回来时 `reviewVersionOf(state)` 已经变了，于是走 stale 分支：
 * 结果标成"仅历史"，**却把 `reviewPending` 留成 true**。后果有两条，都很致命：
 *
 *   1. 建议被整条丢掉——Observer 明明指出了"去抓 CDN 上的 umi bundle"，但那条建议只写进
 *      历史事件，主循环拿不到；
 *   2. 门禁永远打不开——没有别的代码会清 `reviewPending`，循环最后停在
 *      `required_review_pending`，20 条待办原样躺在检查点里（实测 4 次 review-stale）。
 *
 * 这里的判定规则：
 *   - 建议（suggestions）一律保留：它描述的是战术方向，不依赖快照版本；
 *   - 门禁按**接受度重算**决定，不按"这次审查是不是过期"决定：
 *       blocking_error_count > 0、有未处置建议、或 TERMINAL_REVIEW_PENDING → 继续等；
 *       否则清掉（过期审查不该成为永久阻塞）；
 *   - 2026-11-07 追加：如果调用方给了「排队时的 issues」和「当前 issues」，
 *     且点名的问题**已全部消失**，就把 `TERMINAL_REVIEW_PENDING` 这类自设门户一并清掉——
 *     否则 `validation_failed → 排队 → stale → 门禁保持 → 再排队` 会一直空转；
 *   - 只有"还在等"才算需要中止本轮（halt），避免把过期结果当成判决书用。
 */

import { createHash } from "node:crypto";
import type { AcceptanceResult } from "./acceptance.js";
import type { RunCheckpoint } from "./progress.js";

export type StaleReviewPlan = {
  /** 仍然要等审查（门禁不清）。 */
  keepPending: boolean;
  /** 需要中止本轮（把 stale 当成停止理由）。 */
  halt: boolean;
  /** 建议要不要保留下来注入下一轮上下文。 */
  injectAdvice: boolean;
  /** 写进事件的原因码，便于事后统计。 */
  reason: "stale_blocking" | "stale_cleared" | "stale_no_advice" | "stale_issues_resolved" | "stale_degraded";
  /** 排队时点名、现在仍然存在（或已消失）的问题键，供事件审计。 */
  issuesCompared?: { reviewed: number; unresolved: string[]; blocking: number; warning_only: number };
};

/** 只看稳定的定位字段：message / detail 里的审计文本变化不该让同一条问题变成"新问题"。 */
export function reviewIssueKeys(issues: unknown): string[] {
  if (!Array.isArray(issues)) return [];
  return [...new Set(issues.map(raw => {
    const item = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    return [item.code, item.severity, item.path, item.task_id, item.advice_id, item.evidence_id, item.rule]
      .filter(part => part !== undefined && part !== null && String(part) !== "")
      .map(String).join("|");
  }).filter(Boolean))].sort();
}

export function reviewIssueFingerprint(issues: unknown): string {
  const keys = reviewIssueKeys(issues);
  return keys.length ? createHash("sha256").update(keys.join("\n")).digest("hex").slice(0, 20) : "";
}

/** 排队时点名、现在仍然没修好的问题。 */
export function unresolvedReviewIssues(reviewIssues: unknown, currentIssues: unknown): string[] {
  const current = new Set(reviewIssueKeys(currentIssues));
  return reviewIssueKeys(reviewIssues).filter(key => current.has(key));
}

export type IssueReviewQueueDecision = {
  queue: boolean;
  fingerprint: string;
  reason: "no_issues" | "first_seen" | "changed" | "deduped";
};

/**
 * 同一批阻塞 issues 只排一次审查：修好（issues 清空）或问题集合变化才允许重排。
 *
 * 防漏审的三条例外：
 *   1. 指纹变了（新问题 / 问题被修掉后再次出现）→ 重排；
 *   2. 已有审查不是"活着"的（failed 且不再重试 / 被撤销）→ 重排；
 *   3. issues 为空 → 清空指纹，下一次出现任何问题都算新一轮。
 *
 * 指纹与排队时间都写进 checkpoint（不是进程内变量），随 CAS 提交：
 * 多实例共用一个会话时不会各记各的、重复排队。
 */
export function shouldQueueIssueReview(state: RunCheckpoint, issues: unknown): IssueReviewQueueDecision {
  const supervision = (state.supervision ||= { observerRuns: 0 });
  const fingerprint = reviewIssueFingerprint(issues);
  if (!fingerprint) {
    supervision.lastReviewIssueFingerprint = undefined;
    return { queue: false, fingerprint: "", reason: "no_issues" };
  }
  const live = Object.values(supervision.reviews || {}).some(review =>
    reviewIssueFingerprint(review.issues) === fingerprint &&
    ["pending", "running", "completed"].includes(review.status));
  if (supervision.lastReviewIssueFingerprint === fingerprint && live) {
    return { queue: false, fingerprint, reason: "deduped" };
  }
  const reason = supervision.lastReviewIssueFingerprint && supervision.lastReviewIssueFingerprint !== fingerprint ? "changed" : "first_seen";
  supervision.lastReviewIssueFingerprint = fingerprint;
  supervision.lastReviewIssueQueue = { at: Date.now(), reason, fingerprint };
  return { queue: true, fingerprint, reason };
}

export function planStaleReview(input: {
  acceptance: Pick<AcceptanceResult, "blocking_error_count" | "unhandled_advice" | "reason_codes">;
  suggestionCount: number;
  /** 这次审查排队时点名的问题（review.issues）。 */
  reviewIssues?: unknown[];
  /** 当前验收重新算出的问题集合；给了才做「问题是否已解决」的判定。 */
  currentIssues?: unknown[];
  /**
   * 同一批 issues 连续判 stale 的次数。≥3 时降级放行（2026-11-07）：现场
   * `PARTIAL_TASK_OUTCOME` / `TASK_OUTCOME_NO_FACT` 这类 warning 永不消失，
   * 主循环每轮 apply 结案又必然改 v2 语义版本，于是「排队→stale→门禁保持→再排队」
   * 无限空转。审查是辅助，不该让整场 run 永久停在等一个追不上的快照。
   */
  staleStreak?: number;
}): StaleReviewPlan {
  const blockers = Number(input.acceptance.blocking_error_count || 0);
  const unhandled = Number(input.acceptance.unhandled_advice || 0);
  const terminal = (input.acceptance.reason_codes || []).includes("TERMINAL_REVIEW_PENDING");
  const injectAdvice = input.suggestionCount > 0;
  const rawCompared = Array.isArray(input.reviewIssues) && Array.isArray(input.currentIssues)
    ? { reviewed: reviewIssueKeys(input.reviewIssues).length,
        unresolved: unresolvedReviewIssues(input.reviewIssues, input.currentIssues) }
    : undefined;
  /**
   * 「还有问题没修」必须按 severity 分级：warning 级（部分交付/结案措辞）不该让
   * 门禁永久保持。这里也是「审查范围钉住」的落地形式——判据是**排队时点名的
   * 那批问题**是否还有阻塞项，而不是整个 checkpoint 的全状态哈希有没有变。
   */
  const blockingUnresolved = (rawCompared?.unresolved || []).filter(key => !/\|(?:warning|info)\|/i.test(key));
  const compared = rawCompared ? { ...rawCompared, blocking: blockingUnresolved.length,
    warning_only: rawCompared.unresolved.length - blockingUnresolved.length } : undefined;
  const issuesResolved = Boolean(compared && compared.reviewed > 0 && blockingUnresolved.length === 0 &&
    blockers === 0 && unhandled === 0);
  const issuesStillOpen = blockingUnresolved.length > 0;
  const degraded = Number(input.staleStreak || 0) >= 3;
  const keepPending = degraded ? false : issuesResolved ? false : blockers > 0 || unhandled > 0 || terminal || issuesStillOpen;
  return {
    keepPending,
    halt: keepPending,
    injectAdvice,
    reason: degraded ? "stale_degraded" : issuesResolved ? "stale_issues_resolved"
      : keepPending ? "stale_blocking" : injectAdvice ? "stale_cleared" : "stale_no_advice",
    ...(compared ? { issuesCompared: compared } : {}),
  };
}

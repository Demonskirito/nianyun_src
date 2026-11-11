import { createHash } from "node:crypto";
import type { RunCheckpoint, TaskState } from "./progress.js";
import { evaluateAcceptance, type AcceptanceResult } from "./acceptance.js";
import { shouldQueueIssueReview } from "./review-stale.js";
import { coverageChecklist } from "./coverage.js";

export type SupervisionBudget = {
  timeMs: number; toolCalls: number; agentTurns: number; tokens: number; cost: number; retries: number;
  /** 整次 run 的墙钟上限（含工具执行）；0 = 不限。timeMs 只算调度时间。 */
  wallClockMs?: number;
  /** Session totals when this run started; budgets are measured against the current run only. */
  base?: { elapsedMs: number; toolCalls: number; agentTurns: number; tokens: number; cost: number; retries: number; toolMs?: number };
};
export type SupervisionEvent = {
  /** 鉴权墙触发或"拒绝结案"被拦下：必须让 Observer 介入而不是继续跑。 */
  authWall?: boolean;
  kind: "analysis" | "tool_batch" | "tool_failure" | "checkpoint";
  madeProgress?: boolean;
  toolCalls?: number;
  failed?: boolean;
  failureKind?: string;
  newFinding?: boolean;
  evidenceCount?: number;
};
export type SupervisionDecision = {
  action: "continue" | "observer" | "pause" | "acceptance";
  reasons: string[];
  warnings: string[];
  coverage: number;
  acceptance: AcceptanceResult;
};

const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const terminal = (s: TaskState) => ["completed", "blocked", "failed"].includes(s);

/** Mechanical supervision. It never calls a model and its state is checkpointed. */
export function superviseCheckpoint(state: RunCheckpoint, budget: SupervisionBudget, event: SupervisionEvent, evidence: Record<string, unknown>[] = []): SupervisionDecision {
  const tasks = Object.entries(state.tasks);
  state.supervision ||= { observerRuns: 0 };
  if (event.newFinding) state.supervision.reviewPending = true;
  const acceptance = evaluateAcceptance(state, evidence);
  // ④ 每轮刷新覆盖度清单：0 findings 时这四类对照是代码可验的"挖得深不深"，
  // 而不是模型一句"已全面测试"。只写提示，不改验收结论。
  state.coverage_gaps = coverageChecklist(state, evidence).gaps;
  const { pending, invalidEvidence, validationErrors } = acceptance;
  const total = tasks.length;
  const coverage = total ? (tasks.filter(([, task]) => terminal(task.status)).length / total) : 0;
  const warnings: string[] = [];
  const reasons: string[] = [];
  const usage = state.usage;
  // Budgets are per run: a session that already spent its time must be able to work again.
  const base = budget.base || { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 };
  const run = { elapsedMs: Math.max(0, usage.elapsedMs - base.elapsedMs), toolCalls: Math.max(0, usage.toolCalls - base.toolCalls),
    agentTurns: Math.max(0, usage.agentTurns - base.agentTurns), tokens: Math.max(0, usage.tokens - base.tokens),
    cost: Math.max(0, usage.cost - base.cost), retries: Math.max(0, usage.retries - base.retries) };
  // 调度时间 = 墙钟 − 工具执行耗时：一个跑 300 秒的 nuclei 不该被记成"Agent 思考了 300 秒"。
  const scheduleBase = Math.max(0, base.elapsedMs - Number(base.toolMs || 0));
  const scheduleMs = Math.max(0, (usage.elapsedMs - Number(usage.toolMs || 0)) - scheduleBase);
  const ratio = (used: number, limit: number) => limit > 0 ? used / limit : 0;
  if (ratio(scheduleMs, budget.timeMs) >= .8 || ratio(run.elapsedMs, Number(budget.wallClockMs || 0)) >= .8 || ratio(run.toolCalls, budget.toolCalls) >= .8 || ratio(run.agentTurns, budget.agentTurns) >= .8 || ratio(run.tokens, budget.tokens) >= .8 || ratio(run.cost, budget.cost) >= .8 || ratio(run.retries, budget.retries) >= .8) warnings.push("budget_warning");
  if (event.failed) warnings.push("tool_failure");
  // 鉴权墙：一次触发只问一次 Observer，之后由建议处置推进。
  const wallAlert = state.auth_wall_alert;
  const wallFresh = Boolean(wallAlert && wallAlert.at > Number(state.supervision?.authWallSeenAt || 0));
  const authWall = Boolean(event.authWall || wallFresh);
  if (authWall) {
    reasons.push(wallAlert?.kind === "denied_completion" ? "denied_completion" : "auth_wall_detected");
    if (wallAlert) state.supervision.authWallSeenAt = wallAlert.at;
  }
  if (event.failureKind === "critical") { reasons.push("critical_failure"); }
  if (event.failureKind === "stall") reasons.push("no_progress");
  if (invalidEvidence.length) reasons.push("evidence_traceability_failed");
  if (validationErrors.length) reasons.push("state_validation_failed");
  const fingerprint = hash({ kind: event.kind, failed: event.failed, failureKind: event.failureKind, newFinding: event.newFinding, coverage, pending, validationErrors, evidence: event.evidenceCount, authWall });
  const previousWarnings = state.supervision?.warnings || [];
  const warningsChanged = warnings.length !== previousWarnings.length || warnings.some((warning, index) => warning !== previousWarnings[index]);
  state.supervision = { ...state.supervision, lastFingerprint: fingerprint, warnings, coverage, acceptance };
  if (reasons.some(r => r.startsWith("critical_"))) return { action: "pause", reasons, warnings, coverage, acceptance };
  if (validationErrors.length || invalidEvidence.length) {
    const reviewedAcceptance = evaluateAcceptance(state, evidence);
    state.supervision.acceptance = reviewedAcceptance;
    // A rejected completion claim is the agent's own bookkeeping error against a task it can redo
    // next round. Pausing for it burned whole runs, so keep working and let the agent repair it.
    if (reviewedAcceptance.repairableOnly && !invalidEvidence.length) {
      return { action: "continue", reasons: [...reasons, "repairable_rejections"], warnings: [...warnings, "repairable_task_rejections"], coverage, acceptance: reviewedAcceptance };
    }
    // 2026-11-07：同一批 issues 只排一次审查。旧逻辑每轮都置 reviewPending + 排 Observer，
    // 审查回来又因版本变化判 stale、门禁保持 → 下一轮再失败 → 再排队（对照会话 15 次 stale）。
    const queue = shouldQueueIssueReview(state, reviewedAcceptance.issues);
    if (!queue.queue) {
      warnings.push("review_deduped");
      const alive = Object.values(state.supervision.reviews || {})
        .some(review => ["pending", "running"].includes(review.status));
      if (!alive) state.supervision.reviewPending = false;
      return { action: "continue", reasons: [...reasons, "review_deduped"], warnings, coverage, acceptance: reviewedAcceptance };
    }
    state.supervision.reviewPending = true;
    return { action: "observer", reasons: [...reasons, "validation_failed"], warnings, coverage, acceptance: reviewedAcceptance };
  }
  // 问题已修好：清空指纹，之后再出现同类问题算新一轮，允许重新排审查（防漏审）。
  if (!acceptance.blocking_error_count && !invalidEvidence.length && state.supervision.lastReviewIssueFingerprint) {
    state.supervision.lastReviewIssueFingerprint = undefined;
  }
  // 每 5 个权重就唤醒一次 Observer，等于把预算砍半：600 权重下是 120 次额外 LLM 调用。
  // 语义事件（新发现、失败、鉴权墙、预算告警）已经足够触发审阅，这里只留低频心跳。
  const semanticEvent = Boolean(authWall || event.newFinding || event.failed || event.failureKind === "stall" ||
    (event.madeProgress && usage.toolCalls > 0 && (usage.toolCalls === 1 || usage.toolCalls % 20 === 0)) || warningsChanged);
  /**
   * ④ 0 findings 的反证义务：任务都终态、却没有任何已确认漏洞时，四类对照还缺就不该
   * 静默收工。放在 semanticEvent 判定里（而不是只在 acceptance.ready 分支），是因为
   * 真实会话在收口前常还有若干 warning 级账目没清，acceptance.ready 未必为真。
   * 最多 2 次、间隔 20 轮，避免把收口无限推迟成另一种死锁。
   *
   * 轮次门槛必须是「至少跑满 20 轮」：早先用 -999 兜底间隔，结果第 0 轮就满足，
   * 把验收门禁 / review 重试 / 建议处置这些短跑路径全抢成 Observer（全量回归 6 条）。
   * 0 findings 是"打过一阵子却没结果"才需要反证，刚起跑就追问覆盖度没有意义。
   * 有 validation error / 无效证据时上面第 79 行已经 return，这里不必重复判。
   */
  const coverageGaps = state.coverage_gaps || [];
  const findingCount = Object.keys(state.findings || {}).length;
  const coverageCount = Number(state.supervision?.coverageReviewCount || 0);
  const turns = Number(usage.agentTurns || 0);
  const coverageDue = turns >= 20 && acceptance.all_tasks_terminal && findingCount === 0
    && coverageGaps.length > 0 && coverageCount < 2
    && turns - Number(state.supervision?.coverageReviewAtTurn ?? 0) >= 20;
  if (coverageDue) {
    state.supervision = { ...state.supervision, coverageReviewCount: coverageCount + 1,
      coverageReviewAtTurn: turns, reviewPending: true };
    reasons.push("coverage_gaps");
    warnings.push(...coverageGaps.map(gap => `coverage_gap:${gap}`));
  }
  // A new finding still needs Observer review before a completed task set is accepted.
  if (semanticEvent || coverageDue || !acceptance.required_reviews_complete) {
    state.supervision.reviewPending = true;
    const reviewedAcceptance = evaluateAcceptance(state, evidence);
    state.supervision.acceptance = reviewedAcceptance;
    return { action: "observer", reasons, warnings, coverage, acceptance: reviewedAcceptance };
  }
  if (acceptance.ready) return { action: "acceptance", reasons: ["acceptance_ready"], warnings, coverage, acceptance };
  return { action: "continue", reasons, warnings, coverage, acceptance };
}

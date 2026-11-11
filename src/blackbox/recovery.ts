import type { RunCheckpoint } from "./progress.js";
import { completionVerdictOf } from "./acceptance.js";
import { settleTask } from "./task-outcome.js";

type Fact = Record<string, unknown>;
type Link = { task_id: string; request_id: string };
export type RecoveryRecord = { version: 1; audit_id: string; at: number; links: Record<string, Link> };
export type RecoveryPlan = {
  reason: string;
  tasks: Array<{ task_id: string; status: "completed" | "blocked" | "failed"; reason: string; evidence_ids: string[]; urls?: string[] }>;
  advice_decisions: Array<{ advice_id: string; reason: string }>;
};
const data = (e?: Fact): Fact => e?.data && typeof e.data === "object" ? e.data as Fact : {};

/** Check original request/result provenance, never infer success from a model summary. */
function legacyPair(evidence: Fact[], result: Fact): Fact {
  const d = data(result);
  const request = evidence.find(e => e.id === d.request_evidence_id && e.kind === "tool-request");
  if (!request || !["tool-result", "tool-error"].includes(String(result.kind)) ||
      d.task_id || data(request).task_id || data(request).tool !== result.source ||
      result.session_id !== request.session_id || result.project_id !== request.project_id) {
    throw new Error(`invalid_legacy_provenance:${result.id}`);
  }
  return request;
}

function successfulHttpPair(evidence: Fact[], result: Fact): Fact {
  const request = legacyPair(evidence, result);
  const d = data(result);
  const input = data(request).input as Fact | undefined;
  if (result.kind !== "tool-result" || result.source !== "http.request" || d.ok === false || d.error ||
      d.method !== "GET" || String(input?.method || "GET").toUpperCase() !== "GET" ||
      d.url !== input?.url || !Number.isInteger(d.status) || Number(d.status) < 200 || Number(d.status) >= 300 ||
      typeof d.body !== "string" || !d.headers || d.body_truncated === true) {
    throw new Error(`invalid_legacy_http_result:${result.id}`);
  }
  return request;
}

export function taskHasRecoveredEvidence(state: RunCheckpoint, evidence: Fact[], result: Fact, taskId: string): boolean {
  const link = state.recovery?.links[String(result.id)];
  if (!link || link.task_id !== taskId || !state.recovery?.audit_id) return false;
  try { return successfulHttpPair(evidence, result).id === link.request_id; } catch { return false; }
}

/** Explicitly reviewed offline plan only. This function performs no network requests or ledger edits. */
export function recoverLegacyCheckpoint(saved: RunCheckpoint, evidence: Fact[], target: string, plan: RecoveryPlan, auditId: string): RunCheckpoint {
  if (saved.version !== 1 || saved.recovery || !auditId || !plan.reason?.trim()) throw new Error("invalid_or_already_recovered_checkpoint");
  const state = structuredClone(saved);
  const links: Record<string, Link> = {};
  const seen = new Set<string>();
  for (const item of plan.tasks) {
    const task = state.tasks[item.task_id];
    if (!task || seen.has(item.task_id) || !item.reason?.trim() || !item.evidence_ids.length ||
        !["completed", "blocked", "failed"].includes(item.status)) throw new Error(`invalid_recovery_task:${item.task_id}`);
    seen.add(item.task_id);
    const facts = item.evidence_ids.map(id => {
      const result = evidence.find(e => e.id === id);
      if (!result) throw new Error(`missing_recovery_evidence:${id}`);
      legacyPair(evidence, result);
      return result;
    });
    if (item.status === "completed") {
      if (!item.urls?.length || item.urls.length !== facts.length || new Set(item.urls).size !== facts.length) throw new Error("explicit_unique_urls_required");
      for (const fact of facts) {
        const request = successfulHttpPair(evidence, fact);
        const url = String(data(fact).url);
        if (!item.urls.includes(url) || new URL(url).origin !== new URL(target).origin || links[String(fact.id)]) throw new Error(`recovery_target_mismatch:${fact.id}`);
        links[String(fact.id)] = { task_id: item.task_id, request_id: String(request.id) };
      }
    } else if (task.status === "completed") throw new Error(`cannot_downgrade_completed_task:${item.task_id}`);
    /**
     * 恢复时的终态处置也走结案契约：模型给的 `item.reason` 是**结案理由**，
     * 直接盖到 outcome_reason 而不带 outcome_code 的话，报告里会出现
     * "有原因但无法归类"的半成品（验收也会判 TASK_OUTCOME_CODE_MISSING）。
     */
    Object.assign(task, {
      ...settleTask(task, {
        code: item.status === "failed" ? "agent_failed" : "agent_blocked",
        reason: String(item.reason || ""),
        evidence_ids: item.evidence_ids,
        by: "agent",
      }),
      status: item.status,
      evidence_ids: item.evidence_ids,
    });
  }
  // Close superseded recommendations explicitly; no claim that their proposed tests ran.
  for (const decision of plan.advice_decisions) {
    const advice = state.advice?.[decision.advice_id];
    if (!advice || advice.status !== "pending" || !decision.reason?.trim()) throw new Error(`invalid_recovery_advice:${decision.advice_id}`);
    Object.assign(advice, { status: "rejected", reason: decision.reason, task_ids: [] });
  }
  if (Object.values(state.advice || {}).some(a => a.status === "pending") ||
      Object.values(state.tasks).some(t => !["completed", "blocked", "failed"].includes(t.status))) throw new Error("recovery_requires_explicit_terminal_disposition");
  for (const [id, task] of Object.entries(state.tasks)) if (task.status === "completed" &&
    (!task.evidence_ids?.length || task.evidence_ids.some(ref => !links[ref] && !evidence.some(e => e.id === ref && e.kind === "tool-result" && data(e).task_id === id && data(e).ok === true)))) {
    throw new Error(`unverified_completed_task:${id}`);
  }
  state.recovery = { version: 1, audit_id: auditId, at: Date.now(), links };
  state.validationErrors = [];
  state.transitionErrors = [];
  state.retrievedEvidence = [];
  // Historical invocations predate the scheduler counters; do not erase consumed budget.
  state.usage.toolCalls = Math.max(state.usage.toolCalls, evidence.filter(e => e.kind === "tool-request").length);
  state.stopReason = completionVerdictOf(state.tasks);
  if (state.supervision) delete state.supervision.acceptance;
  return state;
}

export function recoveredTerminalReason(state: RunCheckpoint, evidence: Fact[]): string {
  if (!state.recovery || state.validationErrors?.length || !Object.keys(state.tasks).length ||
      Object.values(state.advice || {}).some(a => a.status === "pending")) return "";
  for (const [id, task] of Object.entries(state.tasks)) {
    if (!["completed", "blocked", "failed"].includes(task.status)) return "";
    if (task.status === "completed" && (!task.evidence_ids?.length || task.evidence_ids.some(ref => !evidence.some(e => e.id === ref &&
      ((e.kind === "tool-result" && data(e).task_id === id && data(e).ok === true) || taskHasRecoveredEvidence(state, evidence, e, id)))))) return "";
  }
  return completionVerdictOf(state.tasks);
}

import { BlackboxProgress, type RunCheckpoint, type AdviceDecisionResult } from "./progress.js";
import { mainSchema } from "./protocol.js";

type Event = { id: number; kind: string; data: Record<string, unknown> };
export type HistoricalAdviceError = { event_id: number; advice_id: string; code: string; message: string };

/** Historical rejections are immutable audit facts; they are not a new source of current blockers. */
export function auditAdviceHistory(state: RunCheckpoint, events: Event[]) {
  const historical_errors: HistoricalAdviceError[] = [];
  for (const event of events) {
    if (event.kind === "advice-disposition" && Array.isArray(event.data.results)) {
      for (const result of event.data.results as AdviceDecisionResult[]) {
        if (["invalid_advice_decision", "disposition_conflict"].includes(result.status))
          historical_errors.push({ event_id: event.id, advice_id: result.advice_id, code: result.status, message: `${result.status}:${result.advice_id}` });
      }
    }
    if (event.kind !== "transition-rejected") continue;
    for (const message of Array.isArray(event.data.errors) ? event.data.errors : []) {
      if (typeof message !== "string" || !/^(invalid_advice_decision|disposition_conflict):/.test(message)) continue;
      const colon = message.indexOf(":");
      historical_errors.push({ event_id: event.id, advice_id: message.slice(colon + 1), code: message.slice(0, colon), message });
    }
  }
  // This is only the transition-error projection. Full current validity is decided by evaluateAcceptance.
  const current_transition_errors = (state.transitionErrors ?? state.validationErrors ?? [])
    .filter(message => /^(invalid_advice_decision|disposition_conflict):/.test(message));
  return { historical_errors, current_transition_errors };
}

/** Read-only replay of advice submissions AFTER a trusted checkpoint boundary, in ledger order.
 * Other task/Observer/tool events must still be restored by their own handlers.
 * Legacy recorded rejections remain rejected under the historical engine; never relabel them
 * as successful just because today's idempotency rules would allow the same submission.
 */
export function replayAdviceEvents(saved: RunCheckpoint, events: Event[]) {
  const progress = new BlackboxProgress(saved);
  const submissions: Array<{ event_id: number; results: AdviceDecisionResult[]; historically_rejected: string[] }> = [];
  const protocol_errors: number[] = [];
  let legacyRejected: string[] = [];
  let previousId = -1;
  for (const event of events) {
    if (event.id <= previousId) throw new Error("advice_replay_requires_ledger_order");
    previousId = event.id;
    if (event.kind === "transition-rejected") {
      legacyRejected = auditAdviceHistory(progress.state, [event]).historical_errors.map(e => e.message);
      continue;
    }
    if (event.kind !== "analysis" && event.kind !== "advice-disposition") continue;
    const output = event.kind === "analysis" ? event.data : event.data.output as Record<string, unknown> | undefined;
    const parsed = mainSchema.pick({ advice_decisions: true }).safeParse({ advice_decisions: output?.advice_decisions });
    if (!parsed.success) { protocol_errors.push(event.id); legacyRejected = []; continue; }
    const results: AdviceDecisionResult[] = [];
    const historically_rejected: string[] = [];
    for (const decision of parsed.data.advice_decisions) {
      const legacyError = event.kind === "analysis" && !event.data.advice_decision_results &&
        legacyRejected.find(message => message.slice(message.indexOf(":") + 1) === decision.advice_id);
      if (legacyError) {
        progress.state.transitionErrors ??= [...(progress.state.validationErrors || [])];
        if (!progress.state.transitionErrors.includes(legacyError)) progress.state.transitionErrors.push(legacyError);
        progress.state.validationErrors = [...progress.state.transitionErrors];
        historically_rejected.push(legacyError);
      } else results.push(progress.applyAdviceDecision(decision));
    }
    submissions.push({ event_id: event.id, results, historically_rejected });
    const recorded = event.kind === "analysis" ? event.data.advice_decision_results : event.data.results;
    if (Array.isArray(recorded) && JSON.stringify(recorded) !== JSON.stringify(results)) protocol_errors.push(event.id);
    legacyRejected = [];
  }
  return { state: progress.state, submissions, protocol_errors, ...auditAdviceHistory(progress.state, events) };
}

import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { auditAdviceHistory, replayAdviceEvents } from "../src/blackbox/advice-history.js";

function fixture() {
  const p = new BlackboxProgress();
  p.state.tasks.http = { status: "blocked", reason: "out of scope" };
  p.state.advice = { a: { status: "rejected", tasks: [], reason: "original", task_ids: [] } };
  return p.state;
}
const decision = { advice_id: "a", accepted: false, reason: "repeat", task_ids: [] };
const rejected = { id: 1, kind: "transition-rejected", data: { errors: ["invalid_advice_decision:a"] } };
const legacy = { id: 2, kind: "analysis", data: { advice_decisions: [decision] } };
const correction = { id: 3, kind: "advice-disposition", data: { output: { advice_decisions: [decision] }, results: [{ advice_id: "a", status: "already_applied" }] } };

describe("historical advice audit and current state", () => {
  it("preserves historical rejection and only resolves it through a later legal submission", () => {
    const saved = fixture();
    const events = [rejected, legacy, correction];
    const original = structuredClone({ saved, events });
    const before = replayAdviceEvents(saved, events.slice(0, 2));
    expect(before.submissions[0]?.historically_rejected).toEqual(["invalid_advice_decision:a"]);
    expect(evaluateAcceptance(before.state, []).ready).toBe(false);
    const after = replayAdviceEvents(saved, events);
    expect(after.protocol_errors).toEqual([]);
    expect(after.historical_errors).toEqual([{ event_id: 1, advice_id: "a", code: "invalid_advice_decision", message: "invalid_advice_decision:a" }]);
    expect(after.current_transition_errors).toEqual([]);
    expect(after.state.advice).toEqual(saved.advice);
    expect(evaluateAcceptance(after.state, []).ready).toBe(true);
    expect({ saved, events }).toEqual(original);
    expect(replayAdviceEvents(saved, events)).toEqual(replayAdviceEvents(JSON.parse(JSON.stringify(saved)), events));
    const resumed = replayAdviceEvents(before.state, [correction]);
    expect(resumed.state).toEqual(after.state);
  });

  it("keeps conflicts, malformed submissions and unhandled advice visible", () => {
    const saved = fixture();
    const opposite = { ...correction, data: { output: { advice_decisions: [{ ...decision, accepted: true, task_ids: ["http"] }] } } };
    const replay = replayAdviceEvents(saved, [rejected, legacy, opposite]);
    expect(replay.state.advice).toEqual(saved.advice);
    expect(evaluateAcceptance(replay.state, []).ready).toBe(false);
    expect(replay.current_transition_errors).toContain("disposition_conflict:a");
    const pending = fixture(); pending.advice!.a = { status: "pending", tasks: [] };
    const invalid = replayAdviceEvents(pending, [{ ...legacy, data: { advice_decisions: [{ ...decision, accepted: true }] } }]);
    expect(evaluateAcceptance(invalid.state, [])).toMatchObject({ ready: false, unhandled_advice: 1 });
    const malformed = replayAdviceEvents(saved, [{ ...legacy, data: { advice_decisions: [{ advice_id: "a" }] } }]);
    expect(malformed.protocol_errors).toEqual([2]);
    expect(malformed.state.advice).toEqual(saved.advice);
  });

  it("does not bypass evidence, Observer or unrelated transition errors", () => {
    const saved = fixture();
    saved.tasks.http = { status: "completed", evidence_ids: ["missing"] };
    saved.transitionErrors = ["invalid_advice_decision:a", "invalid_task_transition:other:failed"];
    saved.supervision = { observerRuns: 0, reviewPending: true };
    const replay = replayAdviceEvents(saved, [correction]);
    const gate = evaluateAcceptance(replay.state, []);
    expect(gate).toMatchObject({ ready: false, evidence_integrity_ok: false, required_reviews_complete: false });
    expect(gate.validationErrors).toContain("invalid_task_transition:other:failed");
    expect(gate.issues.some(i => i.code === "TASK_EVIDENCE_INVALID")).toBe(true);
  });

  it("requires ledger order and reports a recorded result inconsistent with replay", () => {
    expect(() => replayAdviceEvents(fixture(), [correction, legacy])).toThrow("ledger_order");
    const replay = replayAdviceEvents(fixture(), [{ ...correction, data: { ...correction.data, results: [{ advice_id: "a", status: "applied" }] } }]);
    expect(replay.protocol_errors).toEqual([3]);
    expect(auditAdviceHistory(fixture(), [{ ...correction, data: { results: [{ advice_id: "a", status: "disposition_conflict" }] } }]).historical_errors).toHaveLength(1);
  });
});

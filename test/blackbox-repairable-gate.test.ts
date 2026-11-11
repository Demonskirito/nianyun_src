import { describe, expect, it } from "vitest";
import { superviseCheckpoint } from "../src/blackbox/supervision.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import type { RunCheckpoint } from "../src/blackbox/progress.js";

const budget = { timeMs: 900_000, toolCalls: 50, agentTurns: 24, tokens: 0, cost: 0, retries: 5 };
const facts = [{ id: "ev-1", kind: "tool-result", data: { ok: true, task_id: "inspect", url: "http://127.0.0.1:1/" } }];
const event = { kind: "tool_batch" as const, madeProgress: true, toolCalls: 1, evidenceCount: 1 };

function state(rejectedIssues: Record<string, unknown>[], transitionErrors: string[]): RunCheckpoint {
  return {
    tasks: { inspect: { status: "pending" }, other: { status: "pending" } },
    usage: { elapsedMs: 1000, toolCalls: 1, agentTurns: 1, tokens: 0, cost: 0, retries: 0 },
    supervision: { observerRuns: 0, reviewPending: false },
    taskOutcomeResults: { inspect: { status: "rejected", issues: rejectedIssues } },
    transitionErrors,
  } as unknown as RunCheckpoint;
}

describe("repairable completion claims", () => {
  it("keeps the round going when every blocking error is the agent's own rejected claim", () => {
    const rejected = [{ code: "TASK_AUDIT_INVALID", severity: "error", task_id: "inspect", evidence_id: "ev-1", path: "task_outcomes.0.audit_ids.0", rule: "audit_reference_must_exist_and_have_audit_kind", message: "task_audit_invalid:inspect:ev-1" }];
    const checkpoint = state(rejected, ["completion_without_valid_task_evidence:inspect"]);
    const acceptance = evaluateAcceptance(checkpoint, facts);
    expect(acceptance.repairableOnly).toBe(true);
    const decision = superviseCheckpoint(checkpoint, budget, event, facts);
    // No Observer review, no pause: the next round fixes the citation.
    expect(decision.action).toBe("continue");
    expect(decision.reasons).toContain("repairable_rejections");
  });

  it("still pauses for a real evidence-integrity failure", () => {
    const checkpoint = state([], []);
    checkpoint.tasks!.inspect = { status: "completed", evidence_ids: ["ev-1"] };
    const broken = [{ id: "ev-1", kind: "tool-result", data: { ok: false, task_id: "inspect" } }];
    const acceptance = evaluateAcceptance(checkpoint, broken);
    expect(acceptance.repairableOnly).toBe(false);
    const decision = superviseCheckpoint(checkpoint, budget, event, broken);
    expect(decision.action).toBe("observer");
    expect(decision.reasons).toContain("validation_failed");
  });
});
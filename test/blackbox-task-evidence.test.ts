import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { mainSchema } from "../src/blackbox/protocol.js";

const facts = [
  { id: "exec", kind: "tool-result", data: { ok: true, task_id: "inspect" } },
  { id: "audit", kind: "checkpoint-recovery", source: "operator-recovery", data: {} },
  { id: "review", kind: "operator-review", source: "operator", data: {} },
];
const output = (evidence_ids: string[], audit_ids: string[] = []) => mainSchema.parse({ summary: "review", completed_tasks: ["inspect"],
  task_outcomes: [{ task_id: "inspect", reason: "recorded response only", evidence_ids, audit_ids }] });
function fixture() { const p = new BlackboxProgress(); p.state.tasks.inspect = { status: "pending", completion_criteria: "record response" }; return p; }

describe("execution evidence and audit references", () => {
  it("persists valid execution and audit references independently across restart", () => {
    const p = fixture();
    expect(p.merge(output(["exec"], ["audit", "review"]), facts)).toBe(true);
    const restored = new BlackboxProgress(JSON.parse(JSON.stringify(p.state)));
    expect(restored.state.tasks.inspect).toMatchObject({ status: "completed", evidence_ids: ["exec"], audit_ids: ["audit", "review"] });
    expect(evaluateAcceptance(restored.state, facts).ready).toBe(true);
    expect(evaluateAcceptance(restored.state, facts.filter(f => f.id !== "audit")).ready).toBe(false);
  });

  it.each(["audit", "review"])("rejects mixed execution references without filtering %s", id => {
    const p = fixture(); const submitted = output(["exec", id]); const snapshot = JSON.stringify({ facts, submitted });
    expect(p.merge(submitted, facts)).toBe(false);
    expect(p.state.tasks.inspect.status).toBe("pending");
    expect(p.state.tasks.inspect.evidence_ids).toBeUndefined();
    expect(p.state.taskOutcomeResults?.inspect.issues).toContainEqual(expect.objectContaining({ evidence_id: id,
      path: "task_outcomes.0.evidence_ids.1", rule: "execution_evidence_must_be_tool_result" }));
    expect(evaluateAcceptance(p.state, facts).ready).toBe(false);
    expect(JSON.stringify({ facts, submitted })).toBe(snapshot);
    p.merge(output(["exec"], [id]), facts);
    expect(evaluateAcceptance(p.state, facts).ready).toBe(true);
  });

  it.each([
    { evidence_ids: [], audit_ids: ["audit"] },
    { evidence_ids: ["missing"], audit_ids: [] },
    { evidence_ids: ["exec"], audit_ids: ["exec"] },
    { evidence_ids: ["exec"], audit_ids: ["missing"] },
  ])("rejects missing execution evidence or invalid audit references %#", refs => {
    const p = fixture(); p.merge(output(refs.evidence_ids, refs.audit_ids), facts);
    expect(p.state.tasks.inspect.status).toBe("pending");
    expect(evaluateAcceptance(p.state, facts).ready).toBe(false);
  });

  it.each([{ ok: false, task_id: "inspect" }, { task_id: "inspect" }, { ok: true, task_id: "other" }, { ok: true, task_id: "inspect", error: "failed" }])(
    "uses identical success and ownership rules at completion and acceptance %#", data => {
      const p = fixture(); const altered = [{ ...facts[0], data }];
      p.merge(output(["exec"]), altered);
      expect(p.state.tasks.inspect.status).toBe("pending");
      p.state.tasks.inspect = { status: "completed", evidence_ids: ["exec"] };
      expect(evaluateAcceptance(p.state, altered).ready).toBe(false);
    });

  it("preserves other blockers after a valid correction and cannot complete blocked tasks", () => {
    const p = fixture();
    p.state.transitionErrors = ["invalid_advice_decision:other", "completion_without_valid_task_evidence:inspect"];
    p.merge(output(["exec"], ["audit"]), facts);
    expect(p.state.transitionErrors).toEqual(["invalid_advice_decision:other"]);
    expect(evaluateAcceptance(p.state, facts).ready).toBe(false);
    p.state.tasks.inspect.status = "blocked";
    p.merge(output(["exec"]), facts);
    expect(p.state.tasks.inspect.status).toBe("blocked");
  });

  it("rejects audit-only completed state and preserves previously valid completion on a bad resubmission", () => {
    const p = fixture();
    p.state.tasks.inspect = { status: "completed", evidence_ids: [], audit_ids: ["audit"] };
    expect(evaluateAcceptance(p.state, facts)).toMatchObject({ ready: false, evidence_integrity_ok: false });
    p.merge(output(["exec"], ["audit"]), facts);
    const original = structuredClone(p.state.tasks.inspect);
    p.merge(output(["exec", "audit"]), facts);
    expect(p.state.tasks.inspect).toEqual(original);
    expect(evaluateAcceptance(p.state, facts).ready).toBe(false);
    p.merge(output(["exec"], ["audit"]), facts);
    expect(evaluateAcceptance(p.state, facts).ready).toBe(true);
  });

  it("still validates the exact historical task IDs and audited request/result links", () => {
    const p = new BlackboxProgress();
    const groups = {
      "t-http-baseline": ["ev-759cb53efdf80fa5"],
      "t-public-files": ["ev-4dd484796b7a2c92", "ev-4840fd11ca03ef3f", "ev-c81716c14eb6d764"],
    };
    const audit = "ev-6d590dff33ffe906";
    const ledger: Record<string, unknown>[] = [{ id: audit, kind: "checkpoint-recovery", source: "operator-recovery", data: {} }];
    p.state.recovery = { version: 1, audit_id: audit, at: 1, links: {} };
    for (const [task, refs] of Object.entries(groups)) {
      p.state.tasks[task] = { status: "pending" };
      for (const ref of refs) {
        const request_id = `req-${ref}`; const url = `http://example.invalid/${ref}`;
        ledger.push({ id: request_id, kind: "tool-request", session_id: "s", project_id: "p", data: { tool: "http.request", input: { url } } },
          { id: ref, kind: "tool-result", session_id: "s", project_id: "p", source: "http.request", data: { request_evidence_id: request_id, url, method: "GET", status: 200, body: "SPA", headers: {} } });
        p.state.recovery.links[ref] = { task_id: task, request_id };
      }
    }
    const outcomes = Object.entries(groups).map(([task_id, evidence_ids]) => ({ task_id, evidence_ids, audit_ids: [audit], reason: "audited legacy GET" }));
    p.merge({ completed_tasks: Object.keys(groups), task_outcomes: outcomes }, ledger);
    expect(evaluateAcceptance(p.state, ledger).ready).toBe(true);
    p.state.transitionErrors = ["unrelated_blocker:task"];
    expect(evaluateAcceptance(p.state, ledger)).toMatchObject({ ready: false, blocking_error_count: 1 });
  });
});

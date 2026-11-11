import { expect, it } from "vitest";
import { boundedContext, boundedMainOutput } from "../src/blackbox/context.js";

it("bounds duplicated database payloads while retaining evidence identities and recovery state", () => {
  const raw = "large response".repeat(100000);
  const evidence = Array.from({ length: 120 }, (_, i) => ({ id: `ev-${i}`, kind: "tool-result", summary: "response", data_json: raw, data: { task_id: "baseline", body: raw } }));
  const session = { checkpoint: { tasks: { baseline: { status: "pending" } }, usage: { tokens: 100 }, retrievedEvidence: evidence },
    evidence, events: Array.from({ length: 100 }, () => ({ kind: "analysis", text: "summary", data_json: raw, data: { raw } })) };
  const before = session.evidence[0].data.body;
  const context = boundedContext(session, { value: "https://example.invalid" });
  const serialized = JSON.stringify(context);
  expect(serialized.length).toBeLessThan(92000);
  expect(serialized).not.toContain("data_json");
  expect(context.checkpoint).toMatchObject({ tasks: { baseline: { status: "pending" } }, usage: { tokens: 100 } });
  expect(context.evidence_index).toEqual(expect.arrayContaining([expect.objectContaining({ id: "ev-99", task_id: "baseline" })]));
  expect(JSON.stringify(boundedMainOutput({ summary: raw })).length).toBeLessThan(1300);
  expect(session.evidence[0].data.body).toBe(before);
});

it("selects referenced and recent success/failure evidence beyond the old first-16 window", () => {
  const evidence = Array.from({ length: 40 }, (_, i) => ({
    id: `ev-${i}`, kind: i === 5 ? "tool-error" : "agent-analysis", created_at: i + 1,
    summary: i === 5 ? "timeout from endpoint" : `analysis ${i}`,
    data: { task_id: i === 5 ? "current" : "other", url: "https://example.invalid/" },
  }));
  const referenced = evidence[0]!;
  const session = { checkpoint: { tasks: { current: { status: "pending" } }, retrievedEvidence: [], hypotheses: [{ evidence_ids: [referenced.id] }] }, evidence, events: [] };
  const context = boundedContext(session, {}, { source: { findings: [{ evidence_ids: [referenced.id] }] } });
  const ids = (context.evidence as Array<{ id: string }>).map(item => item.id);
  expect(ids).toContain(referenced.id);
  expect(ids).toContain("ev-5");
  expect(ids).toContain("ev-39");
  expect(ids).toEqual([...new Set(ids)]);
});

it("uses created_at rather than input order and marks context truncation", () => {
  const evidence = [
    { id: "old", kind: "tool-result", created_at: 1, summary: "old", data: {} },
    { id: "new", kind: "tool-result", created_at: 3, summary: "new", data: {} },
    { id: "middle", kind: "tool-error", created_at: 2, summary: "failure", data: {} },
  ];
  const context = boundedContext({ checkpoint: {}, evidence, events: [] }, {});
  expect((context.evidence as Array<{ id: string }>)[0]?.id).toBe("new");
  const hugeEvidence = Array.from({ length: 30 }, (_, index) => ({ id: `large-${index}`, kind: "agent-analysis", created_at: index + 1, summary: "large", data: { body: "x".repeat(5000) } }));
  const huge = boundedContext({ checkpoint: {}, evidence: hugeEvidence, events: [] }, {});
  expect(JSON.stringify(huge)).toContain("context size limit");
});

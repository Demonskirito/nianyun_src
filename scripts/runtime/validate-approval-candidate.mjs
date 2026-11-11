// Release-only checks. Never instantiate the application Database on /source.
import assert from "node:assert/strict";
import { DatabaseSync, backup } from "node:sqlite";
import { createHash } from "node:crypto";
import { copyFileSync } from "node:fs";

const mode = process.argv[2];
const digest = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const sessionId = "c06b59f56596c0bb";
function history(db) {
  return Object.fromEntries(["blackbox_events", "blackbox_evidence"].map(table => {
    const rows = db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
    return [table, { count: rows.length, digest: digest(rows) }];
  }));
}
if (mode === "verify-source") {
  const source = new DatabaseSync("/source/nianyun.db", { readOnly: true });
  const current = source.prepare("SELECT status,phase,checkpoint_json FROM blackbox_sessions WHERE id=?").get(sessionId);
  assert.equal(current?.status, "paused");
  assert.equal(current?.phase, "awaiting_operator");
  assert.equal(digest(current.checkpoint_json), "0238ce2e316e028cc987a2b1b978c0173ee2c48130262b135c688849c63bb60d");
  const audit = history(source);
  assert.equal(audit.blackbox_events.digest, "01018cecc6cc6cd1ec27e8d4d3989aaf15253c0bd665dc4482cf905c56c28b59");
  assert.equal(audit.blackbox_evidence.digest, "bee7412a73265270c865829dad0bd02cfab260b657775b71111b18f3fec5cff2");
  console.log(JSON.stringify({ mode, status: current.status, phase: current.phase, checkpoint_unchanged: true, history_unchanged: true, audit }));
  source.close();
} else if (mode === "backup") {
  const source = new DatabaseSync("/source/nianyun.db", { readOnly: true });
  await backup(source, "/validation/snapshot.db");
  const current = source.prepare("SELECT status,phase,checkpoint_json FROM blackbox_sessions WHERE id=?").get(sessionId);
  assert.equal(current?.status, "paused");
  console.log(JSON.stringify({ mode, production_session: { id: sessionId, status: current.status, phase: current.phase, checkpoint_digest: digest(current.checkpoint_json) }, history: history(source) }));
  source.close();
} else if (mode === "compatibility") {
  copyFileSync("/validation/snapshot.db", "/validation/working.db");
  const original = new DatabaseSync("/validation/snapshot.db", { readOnly: true });
  const sessions = original.prepare("SELECT id,project_id,status,phase,checkpoint_json FROM blackbox_sessions ORDER BY id").all();
  const before = history(original);
  const { Database } = await import("/opt/nianyun/dist/shared/db.js");
  const { BlackboxProgress } = await import("/opt/nianyun/dist/blackbox/progress.js");
  const { evaluateAcceptance } = await import("/opt/nianyun/dist/blackbox/acceptance.js");
  const app = new Database("/validation/working.db");
  app.recoverBlackboxSessions();
  const working = new DatabaseSync("/validation/working.db", { readOnly: true });
  const acceptance = [];
  for (const row of sessions) {
    const restored = app.getBlackboxSession(row.project_id, row.id);
    assert.ok(restored);
    const progress = new BlackboxProgress(restored.checkpoint);
    const result = evaluateAcceptance(progress.state, restored.evidence || []);
    if (row.id === sessionId) {
      assert.equal(restored.status, "paused");
      assert.equal(restored.phase, row.phase);
      assert.equal(JSON.stringify(restored.checkpoint), row.checkpoint_json);
      acceptance.push({ id: row.id, ready: result.ready, blocking_error_count: result.blocking_error_count, status: restored.status, phase: restored.phase });
    }
    if (row.status !== "running") assert.deepEqual(JSON.parse(JSON.stringify(working.prepare("SELECT status,phase,checkpoint_json FROM blackbox_sessions WHERE id=?").get(row.id))), { status: row.status, phase: row.phase, checkpoint_json: row.checkpoint_json });
  }
  // Original history must remain a prefix, including when interrupted sessions add recovery events.
  for (const table of ["blackbox_events", "blackbox_evidence"]) {
    const rows = working.prepare(`SELECT * FROM ${table} ORDER BY rowid LIMIT ?`).all(before[table].count);
    assert.equal(digest(rows), before[table].digest);
  }
  assert.deepEqual(history(original), before);
  console.log(JSON.stringify({ mode, sessions_checked: sessions.length, historical_rows_preserved: before, acceptance, integrity: working.prepare("PRAGMA integrity_check").get() }));
  original.close(); working.close();
} else if (mode === "seed-smoke") {
  const { Database } = await import("/opt/nianyun/dist/shared/db.js");
  const { BlackboxProgress } = await import("/opt/nianyun/dist/blackbox/progress.js");
  const db = new Database("/opt/nianyun/data/nianyun.db");
  const { importAssetCandidates } = await import("/opt/nianyun/dist/asset/candidates.js");
  const candidate = importAssetCandidates(db, "phase22-fixture", [{ value: "http://127.0.0.1:1/", source: "fixture" }]).accepted[0];
  for (const status of ["pending", "approved", "executing"]) {
    const session = db.createBlackboxSession("phase22-fixture", candidate.id, "http://127.0.0.1:1/");
    const p = new BlackboxProgress();
    const request = { tool: "http.request", task_id: "fixture", requires_confirmation: true, input: { url: session.target } };
    p.enqueue([request], session.target);
    const a = p.requestApproval(request, session.target, session.id, null);
    a.status = status;
    db.updateBlackboxSession("phase22-fixture", session.id, { status: "running", checkpoint: p.state });
  }
  console.log(JSON.stringify({ mode, fixture_sessions: 3 }));
} else if (mode === "check-smoke") {
  const db = new DatabaseSync("/opt/nianyun/data/nianyun.db", { readOnly: true });
  const rows = db.prepare("SELECT status,phase,checkpoint_json FROM blackbox_sessions WHERE project_id='phase22-fixture'").all();
  assert.equal(rows.length, 3);
  const approvals = [];
  for (const row of rows) {
    const checkpoint = JSON.parse(row.checkpoint_json);
    assert.equal(row.status, "paused");
    assert.equal(checkpoint.usage.toolCalls, 0);
    assert.equal(checkpoint.usage.agentTurns, 0);
    approvals.push(Object.values(checkpoint.approvals)[0].status);
  }
  assert.deepEqual(approvals.sort(), ["approved", "interrupted", "pending"]);
  const executions = db.prepare("SELECT count(*) AS count FROM blackbox_evidence").get().count;
  assert.equal(executions, 0);
  console.log(JSON.stringify({ mode, fixture_sessions: rows.length, approval_states: approvals, tool_or_model_calls: 0, evidence_count: executions }));
  db.close();
} else throw new Error("Expected verify-source, backup, compatibility, seed-smoke or check-smoke");

// Offline repair: dry-run by default. Original evidence is never rewritten.
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { recoverLegacyCheckpoint, recoveredTerminalReason } from "../../dist/blackbox/recovery.js";

const [dbPath, sessionId, planPath, mode] = process.argv.slice(2);
if (!dbPath || !sessionId || !planPath || (mode && mode !== "--apply")) throw new Error("usage: node scripts/runtime/repair-blackbox-checkpoint.mjs DB SESSION PLAN [--apply]");
const db = new DatabaseSync(dbPath, { readOnly: mode !== "--apply", timeout: 5000 });
try {
  if (mode === "--apply") db.exec("BEGIN IMMEDIATE");
  const row = db.prepare("SELECT * FROM blackbox_sessions WHERE id=?").get(sessionId);
  if (!row || !["paused", "ready"].includes(row.status)) throw new Error("session must exist and be paused or ready");
  const facts = db.prepare("SELECT * FROM blackbox_evidence WHERE session_id=? AND project_id=?").all(sessionId, row.project_id)
    .map(e => ({ ...e, data: JSON.parse(e.data_json) }));
  const plan = JSON.parse(readFileSync(planPath, "utf8"));
  const auditId = `ev-${randomBytes(8).toString("hex")}`;
  const before = JSON.parse(row.checkpoint_json);
  const after = recoverLegacyCheckpoint(before, facts, row.target, plan, auditId);
  if (!recoveredTerminalReason(after, facts)) throw new Error("repaired checkpoint failed validation");
  const lists = Object.fromEntries(["completed", "blocked", "failed"].map(status => [status, Object.entries(after.tasks).filter(([, t]) => t.status === status).map(([id]) => id)]));
  const summary = `旧检查点离线修复完成：完成 ${lists.completed.length}，受阻 ${lists.blocked.length}，失败 ${lists.failed.length}；未发送目标请求，未确认漏洞。`;
  if (mode === "--apply") {
    const now = Date.now() / 1000;
    db.prepare("INSERT INTO blackbox_evidence(id,session_id,project_id,kind,source,summary,confidence,data_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(auditId, sessionId, row.project_id, "checkpoint-recovery", "operator-recovery", summary, "high", JSON.stringify({ plan, before_checkpoint: before, before_status: row.status, before_phase: row.phase, after_checkpoint: after }), now);
    db.prepare("UPDATE blackbox_sessions SET checkpoint_json=?,status=?,phase=?,updated_at=? WHERE id=? AND project_id=?")
      .run(JSON.stringify(after), "paused", "awaiting_operator", now, sessionId, row.project_id);
    db.prepare("INSERT INTO blackbox_events(session_id,project_id,actor,kind,text,data_json,created_at) VALUES(?,?,?,?,?,?,?)")
      .run(sessionId, row.project_id, "system", "checkpoint-recovered", summary, JSON.stringify({ audit_id: auditId, ...lists, stopReason: after.stopReason }), now);
    db.exec("COMMIT");
  }
  console.log(JSON.stringify({ applied: mode === "--apply", session_id: sessionId, audit_id: auditId, ...lists, stopReason: after.stopReason, tool_calls: after.usage.toolCalls }));
} catch (error) {
  if (mode === "--apply") { try { db.exec("ROLLBACK"); } catch {} }
  throw error;
} finally { db.close(); }

import { existsSync, readFileSync, readdirSync, mkdirSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as typeof import("node:sqlite");
const versions = new WeakMap<Ledger, string | null>();
import type { Config } from "./config.js";

export type Ledger = { projects: Record<string, unknown>[]; tasks: Record<string, unknown>[] };
export class LedgerError extends Error {
  readonly code: string = "ledger_unavailable";
  constructor(message = "Project data is unavailable. Restore the project ledger from a verified backup before changing projects.") { super(message); }
}
export class LedgerConflictError extends LedgerError {
  readonly code = "ledger_conflict";
  constructor() { super("Project data changed in another desk. Refresh and retry this change."); }
}
export const ledgerPath = (cfg: Config): string => join(cfg.data_dir, "console", "ledger.json");

function validate(raw: unknown): Ledger {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new LedgerError();
  const doc = raw as Ledger;
  if (!Array.isArray(doc.projects) || !Array.isArray(doc.tasks)) throw new LedgerError();
  const ids = new Set<string>();
  for (const p of doc.projects) {
    if (!p || typeof p.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(p.id) || p.id.includes("..") || ids.has(p.id)) throw new LedgerError();
    ids.add(p.id);
  }
  const tasks = new Set<string>();
  for (const t of doc.tasks) {
    if (!t || typeof t.id !== "string" || !t.id || tasks.has(t.id) || typeof t.project_id !== "string" || !ids.has(t.project_id)) throw new LedgerError();
    tasks.add(t.id);
  }
  return doc;
}

function firstInstallation(cfg: Config): boolean {
  const path = ledgerPath(cfg);
  if (existsSync(`${path}.initialized`) || existsSync(`${path}.bak`)) return false;
  const projects = join(cfg.data_dir, "projects");
  if (existsSync(projects) && readdirSync(projects).length) return false;
  if (!existsSync(cfg.db_path)) return true;
  const db = new DatabaseSync(cfg.db_path, { readOnly: true });
  try {
    const tables = new Set((db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]).map(r => r.name));
    if (tables.has("jobs") && (db.prepare("PRAGMA table_info(jobs)").all() as { name: string }[]).some(c => c.name === "project_id")
      && db.prepare("SELECT 1 FROM jobs WHERE project_id IS NOT NULL AND project_id!='' LIMIT 1").get()) return false;
    if (tables.has("task_goals") && db.prepare("SELECT 1 FROM task_goals WHERE workspace LIKE ? LIMIT 1").get(`${projects}/%`)) return false;
    return !tables.has("deleted_projects") || !db.prepare("SELECT 1 FROM deleted_projects LIMIT 1").get();
  } finally { db.close(); }
}

/** Reads never initialize, repair or overwrite metadata. An absent, fresh store is empty. */
export function readLedger(cfg: Config): Ledger {
  try {
    const body = readFileSync(ledgerPath(cfg), "utf8");
    const doc = validate(JSON.parse(body));
    versions.set(doc, body);
    return doc;
  }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      try { if (firstInstallation(cfg)) { const doc = { projects: [], tasks: [] }; versions.set(doc, null); return doc; } } catch { /* preserve uncertain stores */ }
    }
    throw new LedgerError();
  }
}

function replace(path: string, body: string): void {
  const temp = `${path}.${randomUUID()}.tmp`;
  try {
    const fd = openSync(temp, "wx", 0o600);
    try { writeFileSync(fd, body); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path);
    // Windows does not support fsync on directory handles; the file fsync above
    // still protects the ledger contents before the atomic rename.
    if (process.platform === "win32") return;
    const dir = openSync(dirname(path), "r");
    try { fsyncSync(dir); } finally { closeSync(dir); }
  } finally { rmSync(temp, { force: true }); }
}

export function writeLedger(cfg: Config, data: Ledger): void {
  validate(data);
  const path = ledgerPath(cfg);
  mkdirSync(dirname(path), { recursive: true });
  // SQLite supplies a crash-safe interprocess writer lock. Compare the version
  // read by this mutation so two desks cannot silently overwrite each other.
  const lock = new DatabaseSync(`${path}.lock.sqlite`, { timeout: 5000 });
  try {
    lock.exec("BEGIN IMMEDIATE");
    const previous = readLedger(cfg);
    const body = existsSync(path) ? readFileSync(path, "utf8") : null;
    if (!versions.has(data) || versions.get(data) !== body) throw new LedgerConflictError();
    if (body !== null) replace(`${path}.bak`, JSON.stringify(previous, null, 2) + "\n");
    replace(`${path}.initialized`, "1\n");
    const next = JSON.stringify(data, null, 2) + "\n";
    replace(path, next);
    versions.set(data, next);
    lock.exec("COMMIT");
  } finally { lock.close(); }
}

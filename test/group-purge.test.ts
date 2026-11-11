import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";
import { createProject } from "../src/control/console/workspace.js";

/**
 * 删除整个资产分组（项目）的数据层回归。
 *
 * `purgeProjectRecords` 是"一次删干净"的唯一实现：会话、证据、事件、Cookie、候选、观测、
 * 资产、发现、探活/复核任务与队列，一个都不能漏。漏一张表，分组删掉之后报告/统计里
 * 还会飘出孤儿行——这正是"删了但看着没删"的来源。
 */
const opened: Database[] = [];
afterEach(() => { for (const db of opened.splice(0)) { try { db.close(); } catch { /* 已关 */ } } });

function makeDb(): { db: Database; pid: string } {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-purge-"));
  mkdirSync(join(dir, "data"), { recursive: true });
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  const db = new Database(join(dir, "data", "nianyun.db"));
  opened.push(db);
  const pid = String(createProject(cfg, "purge test", "test").id);
  return { db, pid };
}

function seed(db: Database, pid: string, tag = ""): void {
  const now = Date.now() / 1000;
  db.db.prepare("INSERT INTO blackbox_sessions (id, project_id, candidate_id, target, status, phase, environment_json, checkpoint_json, cookies_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run(`s1${tag}`, pid, `c1${tag}`, "https://t.example/", "pending", "tool_execution", "{}", "{}", "[]", now, now);
  db.db.prepare("INSERT INTO blackbox_events (session_id, project_id, actor, kind, text, data_json, created_at) VALUES (?,?,?,?,?,?,?)")
    .run(`s1${tag}`, pid, "system", "note", "x", "{}", now);
  db.db.prepare("INSERT INTO blackbox_evidence (id, session_id, project_id, kind, source, summary, confidence, data_json, artifact_path, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(`e1${tag}`, `s1${tag}`, pid, "http", "tool", "resp", "high", "{}", null, now);
  // asset_candidates 用的是 first_seen / last_seen（不是 created_at/updated_at）
  db.db.prepare("INSERT OR REPLACE INTO asset_candidates (id, project_id, kind, value, source, status, score, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(`c1${tag}`, pid, "url", "https://t.example/", "test", "accepted", 50, now, now);
  db.db.prepare("INSERT OR REPLACE INTO project_cookies (project_id, cookies_json, updated_at) VALUES (?,?,?)")
    .run(pid, "[]", now);
}

const count = (db: Database, table: string, pid: string): number =>
  (db.db.prepare(`SELECT count(*) c FROM ${table} WHERE project_id=?`).get(pid) as { c: number }).c;

describe("删除整个分组", () => {
  it("会话/事件/证据/候选/Cookie 全部清掉，并留下墓碑", () => {
    const { db, pid } = makeDb();
    seed(db, pid);
    expect(count(db, "blackbox_sessions", pid)).toBe(1);

    const stats = db.purgeProjectRecords(pid);
    expect(stats.sessions).toBe(1);
    expect(stats.candidates).toBe(1);

    for (const table of ["blackbox_sessions", "blackbox_events", "blackbox_evidence", "asset_candidates", "project_cookies", "assets", "findings"]) {
      expect(count(db, table, pid), `${table} 应清空`).toBe(0);
    }
    const tomb = db.db.prepare("SELECT project_id FROM deleted_projects WHERE project_id=?").get(pid) as { project_id: string } | undefined;
    expect(tomb?.project_id).toBe(pid);
  });

  it("重复删除不会抛错，也不会复活数据", () => {
    const { db, pid } = makeDb();
    seed(db, pid);
    db.purgeProjectRecords(pid);
    const again = db.purgeProjectRecords(pid);
    expect(again.sessions).toBe(0);
    expect(again.candidates).toBe(0);
    expect(count(db, "blackbox_evidence", pid)).toBe(0);
  });

  it("只删目标分组，别的分组原样保留", () => {
    const { db, pid } = makeDb();
    const dir = mkdtempSync(join(tmpdir(), "nianyun-purge-other-"));
    mkdirSync(join(dir, "data"), { recursive: true });
    writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: join(dir, "data"), tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
    const other = String(createProject(loadConfig(join(dir, "config.yaml"), dir), "keep me", "test").id);
    seed(db, pid, "a");
    seed(db, other, "b");
    db.purgeProjectRecords(pid);
    expect(count(db, "blackbox_sessions", other)).toBe(1);
    expect(count(db, "asset_candidates", other)).toBe(1);
  });
});
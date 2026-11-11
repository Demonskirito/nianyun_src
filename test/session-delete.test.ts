import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";
import { createProject } from "../src/control/console/workspace.js";

/**
 * 批量删除会话的回归测试。
 *
 * 背景：控制台会话列表里只能先选中再删，列表行本身没有删除入口；加批量入口时最怕两件事：
 *   1. 运行中的会话被删掉（Agent 还在跑，删了等于留一个孤儿进程）；
 *   2. 删了会话却留下证据/事件，报告还能读出已删会话的东西。
 */
const opened: Database[] = [];
// Windows 上临时目录里 sqlite 的 -wal/-shm 常让 rm 报 EPERM（文件没人关），
// 所以只关连接不删目录：程勋退到 .tmp-tests 下自然清掉，测试不因清理失败变红。
afterEach(() => { for (const db of opened.splice(0)) { try { db.close(); } catch { /* 已关 */ } } });

function makeDb(): { db: Database; pid: string } {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-del-"));
  mkdirSync(join(dir, "data"), { recursive: true });
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  const db = new Database(join(dir, "data", "nianyun.db"));
  opened.push(db);
  const pid = String(createProject(cfg, "delete test", "test").id);
  return { db, pid };
}

function seed(db: Database, projectId: string, sessionId: string, status: string): void {
  db.db.prepare("INSERT INTO blackbox_sessions (id, project_id, candidate_id, target, status, phase, created_at, updated_at, checkpoint_json, cookies_json, environment_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run(sessionId, projectId, `cand-${sessionId}`, "https://t.example/", status, "tool_execution", Date.now() / 1000, Date.now() / 1000, "{}", "[]", "{}");
  // events.id 是 INTEGER AUTOINCREMENT，evidence.confidence 是 TEXT（'high' 之类），
  // 这两点写错会得到 SQLite 的 "datatype mismatch"。
  db.db.prepare("INSERT INTO blackbox_events (session_id, project_id, actor, kind, text, data_json, created_at) VALUES (?,?,?,?,?,?,?)")
    .run(sessionId, projectId, "system", "note", "hello", "{}", Date.now() / 1000);
  db.db.prepare("INSERT INTO blackbox_evidence (id, session_id, project_id, kind, source, summary, confidence, data_json, artifact_path, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(`e-${sessionId}`, sessionId, projectId, "http", "tool", "resp", "high", "{}", null, Date.now() / 1000);
}

describe("批量删除黑盒会话", () => {
  it("删除选中：会话、事件、证据一起清掉", () => {
    const { db, pid } = makeDb();
    seed(db, pid, "s1", "pending");
    seed(db, pid, "s2", "paused");
    seed(db, pid, "s3", "pending");

    const result = db.deleteBlackboxSessions(pid, ["s1", "s3"]);
    expect(result.ok).toBe(true);
    expect(result.deleted.sort()).toEqual(["s1", "s3"]);
    expect(result.skipped).toEqual([]);
    expect(result.events).toBe(2);
    expect(result.evidence).toBe(2);

    const left = db.db.prepare("SELECT id FROM blackbox_sessions WHERE project_id=?").all(pid) as Array<{ id: string }>;
    expect(left.map(row => row.id)).toEqual(["s2"]);
    const orphans = db.db.prepare("SELECT count(*) c FROM blackbox_events e LEFT JOIN blackbox_sessions s ON s.id=e.session_id WHERE s.id IS NULL").get() as { c: number };
    expect(orphans.c).toBe(0);
  });

  it("运行中的会话跳过并说明原因，不静默吞掉", () => {
    const { db, pid } = makeDb();
    seed(db, pid, "run1", "running");
    seed(db, pid, "idle1", "pending");

    const result = db.deleteBlackboxSessions(pid, ["run1", "idle1"]);
    expect(result.deleted).toEqual(["idle1"]);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0]!.id).toBe("run1");
    expect(result.skipped[0]!.reason).toContain("运行");
    const left = db.db.prepare("SELECT id FROM blackbox_sessions WHERE project_id=?").all(pid) as Array<{ id: string }>;
    expect(left.map(row => row.id)).toEqual(["run1"]);
  });

  it("重复 id 去重，未知 id 记为跳过", () => {
    const { db, pid } = makeDb();
    seed(db, pid, "a", "pending");
    const result = db.deleteBlackboxSessions(pid, ["a", "a", "nope"]);
    expect(result.deleted).toEqual(["a"]);
    expect(result.skipped.map(item => item.id)).toEqual(["nope"]);
    expect(result.events).toBe(1);
  });

  it("空列表不报成功（没有东西可删就是没有）", () => {
    const { db, pid } = makeDb();
    const result = db.deleteBlackboxSessions(pid, []);
    expect(result.deleted).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
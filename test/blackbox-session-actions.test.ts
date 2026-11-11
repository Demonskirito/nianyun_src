import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Desk } from "../src/control/console/desk.js";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";

/**
 * 会话动作（pause / resume / cancel）的终态保护。
 *
 * 2026-11-05 实测 6e716ecad149f8d7：那场在 14:09 已经按 partial_completed 收口
 * （run-settled 记着 completed:true、ready:true、reason_codes:[]），14:45 一次误调
 * pause 把 status 无条件改成 paused。收口结论就此从列表里消失，而没有任何入口
 * 能把 completed 写回来——数据库里只剩证据能证明它完成过。
 */

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-session-actions-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Actions", "test").id);
  const target = "https://example.test/";
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid, desk: new Desk(cfg, db) };
}

describe("黑盒会话动作", () => {
  it("已完成的会话拒绝 pause，状态保持 completed", () => {
    const f = fixture();
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "completed" });
    const rec = f.desk.updateProjectBlackboxSession(f.pid, f.sid, "pause");
    expect(rec.ok).toBe(false);
    expect(String(rec.error)).toContain("已完成");
    expect(f.db.getBlackboxSession(f.pid, f.sid)!.status).toBe("completed");
  });

  it("运行中的会话仍然可以暂停", () => {
    const f = fixture();
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "running" });
    expect(f.desk.updateProjectBlackboxSession(f.pid, f.sid, "pause").ok).toBe(true);
    expect(f.db.getBlackboxSession(f.pid, f.sid)!.status).toBe("paused");
  });

  it("已完成的会话仍可 resume：那是「继续评估」，不是结束", () => {
    const f = fixture();
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "completed" });
    expect(f.desk.updateProjectBlackboxSession(f.pid, f.sid, "resume").ok).toBe(true);
    expect(f.db.getBlackboxSession(f.pid, f.sid)!.status).toBe("ready");
  });
});

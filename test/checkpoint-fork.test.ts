import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Database } from "../src/shared/db.js";

/**
 * 时光机：归档快照 → 从快照 fork。
 *
 * 起因（2026-10-28）：为了控成本按了 cancel，而 cancel 是不可逆状态，同一账本再也跑不了，
 * 最后只能 `UPDATE blackbox_sessions SET status='paused'` 手工复原。有了快照 fork，
 * "改前 / 改后"可以并行跑，不用碰数据库状态位。
 */
const dirs: string[] = [];
const databases: Database[] = [];

afterEach(() => {
  // Windows 不允许删除仍被句柄占用的 SQLite 文件：先关库再删目录。
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

function seeded() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-fork-"));
  dirs.push(dir);
  const db = new Database(join(dir, "nianyun.db"));
  databases.push(db);
  const pid = "p_fork";
  const imported = db.upsertAssetCandidate(pid, {
    kind: "url", value: "https://app.example.test/", hostname: "app.example.test",
    port: 0, protocol: "", url: "https://app.example.test/", title: "fork",
    technologies: [], source: "seed", evidence: {},
  } as never);
  const candidateId = String(imported.id);
  const session = db.createBlackboxSession(pid, candidateId, "https://app.example.test/");
  db.updateBlackboxSession(pid, String(session.id), { environment: { ready: true } });
  return { db, pid, sessionId: String(session.id) };
}

describe("checkpoint 快照与 fork", () => {
  it("归档递增 run_index，列表按新到旧返回且不携带正文", () => {
    const { db, pid, sessionId } = seeded();
    const first = db.addBlackboxCheckpoint(pid, sessionId, { planRevision: 3 }, "run_start");
    db.addBlackboxCheckpoint(pid, sessionId, { planRevision: 4 }, "run_start");
    const list = db.listBlackboxCheckpoints(pid, sessionId);
    expect(list).toHaveLength(2);
    expect(list[0]!.run_index).toBe(2);
    expect(list[0]!.id).toBeGreaterThan(first);
    expect(list[0]!.bytes).toBeGreaterThan(0);
    expect((list[0] as unknown as { checkpoint_json?: string }).checkpoint_json).toBeUndefined();
  });

  it("fork 出新会话：同一目标、账本一致、状态 paused、不复制证据", () => {
    const { db, pid, sessionId } = seeded();
    const checkpointId = db.addBlackboxCheckpoint(pid, sessionId, { planRevision: 7, tasks: { T1: { status: "pending" } } }, "run_start");
    const snapshot = db.getBlackboxCheckpoint(pid, sessionId, checkpointId)!;
    const forked = db.forkBlackboxSession(pid, sessionId, snapshot, 1);
    expect(String(forked.id)).not.toBe(sessionId);
    expect(String(forked.target)).toBe("https://app.example.test/");
    expect(String(forked.status)).toBe("paused");
    // environment 跟着继承：fork 出来直接能点 run，不用重新检查一遍环境
    expect((forked.environment as { ready?: boolean }).ready).toBe(true);
    expect((forked.checkpoint as { planRevision?: number }).planRevision).toBe(7);
    const events = ((db.getBlackboxSession(pid, String(forked.id)) as { events?: Array<{ data?: { forked_from?: string } }> }).events || []);
    expect(events.some(event => String(event.data?.forked_from || "") === sessionId)).toBe(true);
    expect(((forked.evidence as unknown[]) || []).length).toBe(0);
  });

  it("不存在的快照返回 undefined 而不是抛错", () => {
    const { db, pid, sessionId } = seeded();
    expect(db.getBlackboxCheckpoint(pid, sessionId, 999)).toBeUndefined();
  });
});
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { Database } from "../src/shared/db.js";

const dirs: string[] = [];
const databases: Database[] = [];

afterEach(() => {
  databases.splice(0).forEach((db) => db.close());
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(): { db: Database; projectId: string; candidateId: string } {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-"));
  dirs.push(dir);
  const db = new Database(join(dir, "nianyun.db"));
  databases.push(db);
  const projectId = "p_blackbox";
  const candidateId = String(importAssetCandidates(db, projectId, [{ value: "https://app.example.com", source: "test" }]).accepted[0]?.id);
  return { db, projectId, candidateId };
}

describe("blackbox session deletion", () => {
  it("removes the session with its timeline and evidence, refusing a live run", () => {
    const { db, projectId, candidateId } = fixture();
    const session = db.createBlackboxSession(projectId, candidateId, "https://app.example.com/");
    const sessionId = String(session.id);
    db.addBlackboxEvent(projectId, sessionId, "system", "note", "hello", {});
    const eventCount = Number(db.getBlackboxSession(projectId, sessionId)?.events?.length || 0);
    expect(eventCount).toBeGreaterThan(0);
    db.updateBlackboxSession(projectId, sessionId, { status: "running", phase: "analysis" });
    expect(db.deleteBlackboxSession(projectId, sessionId)).toMatchObject({ ok: false });
    db.updateBlackboxSession(projectId, sessionId, { status: "paused", phase: "interrupted" });
    const result = db.deleteBlackboxSession(projectId, sessionId);
    expect(result.ok).toBe(true);
    expect(result.events).toBe(eventCount);
    expect(db.getBlackboxSession(projectId, sessionId)).toBeNull();
    expect(db.listBlackboxSessions(projectId)).toHaveLength(0);
  });
});

describe("blackbox session reuse", () => {
  it("finds the open session for a candidate and ignores a cancelled one", () => {
    const { db, projectId, candidateId } = fixture();
    expect(db.findBlackboxSessionByCandidate(projectId, candidateId)).toBeNull();

    const first = db.createBlackboxSession(projectId, candidateId, "https://app.example.com/");
    expect(String(db.findBlackboxSessionByCandidate(projectId, candidateId)?.id)).toBe(String(first.id));
    expect(db.listBlackboxSessions(projectId)).toHaveLength(1);

    db.updateBlackboxSession(projectId, String(first.id), { status: "cancelled", phase: "cancelled" });
    // A cancelled session must not be presented as the live one for this candidate.
    expect(db.findBlackboxSessionByCandidate(projectId, candidateId)).toBeNull();
  });
});
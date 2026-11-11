import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Desk } from "../src/control/console/desk.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { loadConfig } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";

const dirs: string[] = [];
const databases: Database[] = [];

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  databases.splice(0).forEach((db) => db.close());
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(target = "http://127.0.0.1:1/") {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-review-resume-"));
  dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret",
    BLACKBOX_AGENT_TURN_BUDGET: "1", BURP_PROXY_REQUIRED: "false",
  });
  const db = new Database(join(dir, "data", "nianyun.db"));
  databases.push(db);
  const pid = String(createProject(cfg, "ReviewResume", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid, target };
}

const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
const observerReply = { review: "read-only", should_continue: true };

describe("observer review survives an interrupted run", () => {
  it("does not spend the review retry budget when the operator pauses mid-review", async () => {
    const f = fixture();
    const desk = new Desk(f.cfg, f.db);
    let pauseRequested = false;
    // Pause through the real operator path so the run's abort controller fires, exactly like
    // clicking 暂停 while the Observer is thinking.
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      const body = String(init?.body || "");
      if (body.includes("main_agent_output")) {
        pauseRequested = true;
        desk.updateProjectBlackboxSession(f.pid, f.sid, "pause");
        throw new Error("模型请求已取消");
      }
      return answer({ summary: "turn", required_tasks: ["inspect"], tool_requests: [{ tool: "http.request", task_id: "inspect", input: { url: f.target } }] });
    }));
    await desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(pauseRequested).toBe(true);

    const state = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = state.checkpoint as BlackboxProgress["state"];
    const reviews = Object.values(checkpoint.supervision?.reviews || {});
    // Either nothing was recorded, or the review is back to pending with its attempt returned.
    for (const review of reviews) {
      expect(review.status).not.toBe("failed");
      if (review.status === "pending") expect(Number(review.attempts || 0)).toBe(0);
    }
    expect(checkpoint.stopReason).not.toBe("observer_review_retry_exhausted");

    // A second run must get past the failure instead of stopping instantly.
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "ready" });
    const network = vi.fn(async (_url: string, init?: RequestInit) => answer(String(init?.body || "").includes("main_agent_output") ? observerReply : {
      summary: "done", required_tasks: ["inspect"], completed_tasks: ["inspect"],
    }));
    vi.stubGlobal("fetch", network);
    const second = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(second.ok).toBe(true);
    const after = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((after.checkpoint as BlackboxProgress["state"]).stopReason).not.toBe("observer_review_retry_exhausted");
  });

  it("resets a review left in running by a killed process", async () => {
    const f = fixture();
    const progress = new BlackboxProgress();
    progress.state.tasks.inspect = { status: "pending" };
    progress.state.supervision = {
      observerRuns: 0,
      reviewPending: true,
      reviews: { "review-stale": { id: "review-stale", reason: "ordinary", trigger_event_id: "e1", session_id: f.sid, state_version: "v0", status: "running", created_at: Date.now(), attempts: 1, issues: [] } },
    } as unknown as NonNullable<BlackboxProgress["state"]["supervision"]>;
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state, status: "ready" });

    const network = vi.fn(async (_url: string, init?: RequestInit) => answer(String(init?.body || "").includes("main_agent_output") ? observerReply : {
      summary: "turn", required_tasks: ["inspect"], completed_tasks: ["inspect"],
    }));
    vi.stubGlobal("fetch", network);
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const state = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((state.checkpoint as BlackboxProgress["state"]).stopReason).not.toBe("observer_review_checkpoint_conflict");
    expect((state.events as Array<{ kind: string }>).some((event) => event.kind === "review-recovered")).toBe(true);
  });
});
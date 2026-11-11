import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Desk } from "../src/control/console/desk.js";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { blackboxReport, validateFinding, type Finding } from "../src/blackbox/findings.js";
import { executeAndRecordBlackboxTool, runKatana } from "../src/blackbox/tools.js";
import { acquire } from "../src/blackbox/cancellation.js";
import { recoverLegacyCheckpoint } from "../src/blackbox/recovery.js";
import { observerSchema } from "../src/blackbox/protocol.js";
import { chromium } from "playwright";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  // Windows denies deleting an open SQLite file; close handles before cleanup.
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});
function fixture(target = "http://127.0.0.1:1/") {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-lifecycle-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" }; // Mock/local execution only.
  Object.assign(cfg.tools_env.values, { BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret", BLACKBOX_AGENT_TURN_BUDGET: "1", BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Lifecycle", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid, target, desk: new Desk(cfg, db) };
}
function answer(output: unknown) { return Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] }); }
const observer = { review: "read-only", should_continue: true };
async function listen(server: Server) {
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
}
async function close(server: Server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
const candidateFinding: Finding = { id: "f-1", title: "Candidate", type: "exposure", target: "http://127.0.0.1:1/", description: "Observed fixture", impact: "Needs verification", severity: "low", reproduction_steps: ["Read fixture"], evidence_ids: ["ev-1"], remediation: "Review access", confidence: "low", status: "candidate" };

describe("blackbox execution lifecycle", () => {
  it("legally corrects advice errors with append-only auditing and no disposition side effects", () => {
    const f = fixture();
    const p = new BlackboxProgress();
    p.state.tasks.http = { status: "blocked", reason: "outside scope" };
    p.state.advice = { a: { tasks: [], status: "rejected", reason: "original", task_ids: [] } };
    p.state.transitionErrors = ["invalid_advice_decision:a", "invalid_advice_decision:other"];
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: p.state, status: "paused" });
    f.db.addBlackboxEvent(f.pid, f.sid, "system", "transition-rejected", "old rejected submission", { errors: ["invalid_advice_decision:a"] });
    const before = f.db.getBlackboxSession(f.pid, f.sid)!;
    const submit = (accepted = false) => f.desk.reviewProjectBlackboxItem(f.pid, f.sid, {
      kind: "advice_decisions", reason: "explicit correction", output: { advice_decisions: [{ advice_id: "a", accepted, reason: "resubmit", task_ids: accepted ? ["http"] : [] }] },
    });
    for (let i = 0; i < 2; i++) {
      expect(submit()).toMatchObject({ ok: true, results: [{ advice_id: "a", status: "already_applied" }],
        acceptance: { ready: false, blocking_error_count: 1 }, advice_audit: { current_transition_errors: ["invalid_advice_decision:other"] } });
    }
    expect(submit(true)).toMatchObject({ ok: false, results: [{ status: "disposition_conflict" }] });
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const c = saved.checkpoint as typeof p.state;
    expect(c.advice).toEqual(p.state.advice);
    expect(c.tasks).toEqual(p.state.tasks);
    expect(c.usage).toEqual(p.state.usage);
    expect(saved.status).toBe("paused");
    expect((saved.events as unknown[]).slice(0, (before.events as unknown[]).length)).toEqual(before.events);
    expect((saved.events as Array<{ kind: string }>).filter(e => e.kind === "advice-disposition")).toHaveLength(3);
    expect((saved.evidence as Array<{ kind: string }>).filter(e => e.kind === "advice-disposition")).toHaveLength(3);
    expect(f.desk.projectBlackboxReport(f.pid, f.sid)).toMatchObject({ acceptance: { ready: false }, advice_audit: { historical_errors: expect.any(Array) } });
  });

  it("rolls back failed advice corrections and refuses stale or running commits", () => {
    const f = fixture();
    const p = new BlackboxProgress();
    p.state.advice = { a: { status: "pending", tasks: [] } };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: p.state, status: "paused" });
    const before = f.db.getBlackboxSession(f.pid, f.sid)!;
    const spy = vi.spyOn(f.db, "updateBlackboxSession").mockImplementationOnce(() => { throw new Error("write failed"); });
    expect(() => f.desk.reviewProjectBlackboxItem(f.pid, f.sid, { kind: "advice_decisions", reason: "test",
      output: { advice_decisions: [{ advice_id: "a", accepted: false, reason: "original", task_ids: [] }] } })).toThrow("write failed");
    spy.mockRestore();
    const after = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect(after.events).toEqual(before.events);
    expect(after.evidence).toEqual(before.evidence);
    expect(after.checkpoint).toEqual(before.checkpoint);
    expect(f.db.commitBlackboxProgressReview(f.pid, f.sid, { stale: true }, p.state, { reason: "stale" }, "advice-disposition")).toBe(false);
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "running" });
    expect(f.db.commitBlackboxProgressReview(f.pid, f.sid, before.checkpoint as object, p.state, { reason: "race" }, "advice-disposition")).toBe(false);
    expect(f.desk.reviewProjectBlackboxItem(f.pid, f.sid, { kind: "advice_decisions", reason: "race", output: { advice_decisions: [] } }).ok).toBe(false);
    expect(f.db.getBlackboxSession(f.pid, f.sid)!.events).toEqual(before.events);
  });

  it("persists Observer review transitions atomically and rejects stale checkpoints", () => {
    const f = fixture();
    const before = f.db.getBlackboxSession(f.pid, f.sid)!;
    const next = new BlackboxProgress(before.checkpoint).state;
    next.supervision = { observerRuns: 0, reviewPending: true, reviews: { review: {
      id: "review", reason: "terminal_review", trigger_event_id: "event", session_id: f.sid,
      state_version: "v1", status: "pending", created_at: 1, attempts: 0,
    } } };
    expect(f.db.commitBlackboxObserverReview(f.pid, f.sid, before.checkpoint as object, next, {
      kind: "review-pending", text: "pending", data: { review_id: "review" },
    })).toBe(true);
    expect(f.db.commitBlackboxObserverReview(f.pid, f.sid, before.checkpoint as object, next, {
      kind: "review-running", text: "stale", data: { review_id: "review" },
    })).toBe(false);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((saved.events as Array<{ kind: string }>).filter(event => event.kind === "review-pending")).toHaveLength(1);
    expect((saved.checkpoint as BlackboxProgress["state"]).supervision?.reviews?.review.status).toBe("pending");
  });

  it("rolls back an Observer review transition when its checkpoint write fails", () => {
    const f = fixture();
    const before = f.db.getBlackboxSession(f.pid, f.sid)!;
    const next = new BlackboxProgress(before.checkpoint).state;
    next.supervision = { observerRuns: 0, reviewPending: true };
    const spy = vi.spyOn(f.db, "updateBlackboxSession").mockImplementationOnce(() => { throw new Error("review write failed"); });
    expect(() => f.db.commitBlackboxObserverReview(f.pid, f.sid, before.checkpoint as object, next, {
      kind: "review-pending", text: "pending", data: { review_id: "review" },
    })).toThrow("review write failed");
    spy.mockRestore();
    const after = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect(after.checkpoint).toEqual(before.checkpoint);
    expect(after.events).toEqual(before.events);
  });

  it("marks interrupted running Observer reviews failed during database recovery", () => {
    const f = fixture();
    const progress = new BlackboxProgress();
    progress.state.supervision = { observerRuns: 0, reviewPending: true, reviews: { interrupted: {
      id: "interrupted", reason: "validation_failed", trigger_event_id: "event", session_id: f.sid,
      state_version: "v1", status: "running", created_at: 1, attempts: 1,
    } } };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state, status: "running" });
    f.db.recoverBlackboxSessions();
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const review = (saved.checkpoint as BlackboxProgress["state"]).supervision?.reviews?.interrupted;
    expect(saved.status).toBe("paused");
    expect(review).toMatchObject({ status: "failed", failure: "process_interrupted_during_observer_review", retryable: true, completed_at: expect.any(Number) });
  });

  it.each([
    ["empty", {}],
    ["malformed", { protocol_error: "invalid observer fixture" }],
  ])("does not complete a required Observer review on %s output", async (_label, output) => {
    const f = fixture();
    const network = vi.fn()
      .mockResolvedValueOnce(answer({ summary: "terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture blocked", evidence_ids: [] }] }))
      .mockResolvedValue(answer(output));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const reviews = Object.values((saved.checkpoint as BlackboxProgress["state"]).supervision?.reviews || {});
    expect(saved.status).toBe("paused");
    // 2026-11-10：空正文/协议不过属于模型侧抖动，允许下一轮重来（attempts 上限仍是 2），
    // 不再一次性判"不可重试"——那会把一次抖动变成 observer_review_retry_exhausted 停场。
    expect(reviews.some(review => review.status === "failed" && review.retryable === true && Boolean(review.failure_fingerprint) && Boolean(review.completed_at))).toBe(true);
    expect(reviews.some(review => review.status === "completed")).toBe(false);
    expect((saved.events as Array<{ kind: string }>).some(event => event.kind === "review-failed")).toBe(true);
  });

  it.each([0, 5])("runs terminal review with agent_turns=%s when no tool call is needed", async agentTurns => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: agentTurns } });
    const network = vi.fn()
      .mockResolvedValueOnce(answer({ summary: "terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture boundary", evidence_ids: [] }] }))
      .mockResolvedValueOnce(answer({ review: "terminal state reviewed", decision: "finish" }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const state = saved.checkpoint as BlackboxProgress["state"];
    expect(network).toHaveBeenCalledTimes(2);
    expect(state.tasks.inspect.status).toBe("blocked");
    expect(Object.values(state.supervision?.reviews || {})).toContainEqual(expect.objectContaining({ reason: "terminal_review", status: "completed" }));
    expect(state.stopReason).toBe("blocked");
  });

  it("reuses a completed terminal review for the same state version after resume", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
    const network = vi.fn()
      .mockResolvedValueOnce(answer({ summary: "terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture boundary", evidence_ids: [] }] }))
      .mockResolvedValueOnce(answer({ review: "terminal state reviewed", decision: "finish" }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const first = f.db.getBlackboxSession(f.pid, f.sid)!;
    const resumed = new BlackboxProgress(first.checkpoint).state;
    const firstReviews = Object.keys(resumed.supervision?.reviews || {});
    resumed.usage.agentTurns = 2;
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "ready", checkpoint: resumed });
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const second = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect(network).toHaveBeenCalledTimes(2);
    expect(Object.keys((second.checkpoint as BlackboxProgress["state"]).supervision?.reviews || {})).toEqual(firstReviews);
  });

  it("resumes a pending terminal review before another Main Agent turn", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 1 } });
    const network = vi.fn()
      .mockResolvedValueOnce(answer({ summary: "terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture boundary", evidence_ids: [] }] }))
      .mockResolvedValueOnce(answer({ review: "resumed terminal review", decision: "finish" }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const interrupted = new BlackboxProgress(f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint).state;
    expect(Object.values(interrupted.supervision?.reviews || {})).toContainEqual(expect.objectContaining({ status: "pending", reason: "terminal_review" }));
    interrupted.usage.agentTurns = 0;
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "ready", checkpoint: interrupted });
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const resumed = new BlackboxProgress(f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint).state;
    expect(network).toHaveBeenCalledTimes(2);
    expect(Object.values(resumed.supervision?.reviews || {})).toContainEqual(expect.objectContaining({ status: "completed", attempts: 1 }));
    expect(resumed.stopReason).toBe("blocked");
  });

  it("retries a recoverable failed review before another Main Agent turn", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
    const network = vi.fn()
      .mockResolvedValueOnce(answer({ summary: "terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture boundary", evidence_ids: [] }] }))
      .mockRejectedValueOnce(new Error("temporary observer outage"))
      .mockResolvedValueOnce(answer({ review: "retry completed", decision: "finish" }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const failed = new BlackboxProgress(f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint).state;
    expect(Object.values(failed.supervision?.reviews || {})).toContainEqual(expect.objectContaining({ status: "failed", retryable: true, attempts: 1 }));
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "ready", checkpoint: failed });
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const resumed = new BlackboxProgress(f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint).state;
    expect(network).toHaveBeenCalledTimes(3);
    expect(Object.values(resumed.supervision?.reviews || {})).toContainEqual(expect.objectContaining({ status: "completed", attempts: 2 }));
    expect(resumed.stopReason).toBe("blocked");
  });

  it("keeps working when the terminal review proposes new actions instead of waiting for sign-off", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 8 } });
    let mainTurns = 0;
    const network = vi.fn(async (_url: string, init: { body?: string }) => {
      // 审查请求和主回合共用同一个出口：靠 review_request 区分（同 review-stale 用例）。
      if (String(init.body).includes("review_request")) {
        return answer({ review: "coverage gap: 还有一条未打过的路径", decision: "finish", suggestions: ["probe /api/orders"] });
      }
      mainTurns += 1;
      return answer({ summary: "idle", required_tasks: ["inspect"] });
    });
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as BlackboxProgress["state"];
    const events = saved.events as Array<{ kind: string }>;
    // 门禁全放行：终审提了新动作时不再停下来等签收，而是再开一轮把动作跑掉。
    expect(events.some(event => event.kind === "review-continue")).toBe(true);
    expect(mainTurns).toBeGreaterThanOrEqual(2);
    expect(checkpoint.stopReason).not.toBe("required_review_pending");
    // 排队中的审查照样保留，操作员下一次 resume 仍然能跑它（不再靠它拦收口）。
    expect(checkpoint.supervision?.reviewPending || checkpoint.supervision?.reviewDropped).toBeTruthy();
  });

  it("retains an Observer result as stale history when the checkpoint changes during review", async () => {
    const f = fixture();
    const network = vi.fn(async (_url, init) => {
      if (!String(init.body).includes("main_agent_output")) return answer({ summary: "terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture blocked", evidence_ids: [] }] });
      const current = f.db.getBlackboxSession(f.pid, f.sid)!;
      const changed = new BlackboxProgress(current.checkpoint).state;
      changed.tasks.concurrent = { status: "blocked", reason: "concurrent fixture update" };
      f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: changed });
      return answer({ review: "old snapshot reviewed", decision: "finish" });
    });
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const reviews = Object.values((saved.checkpoint as BlackboxProgress["state"]).supervision?.reviews || {});
    expect(saved.status).toBe("paused");
    expect((saved.checkpoint as BlackboxProgress["state"]).stopReason).toBe("observer_review_stale_snapshot");
    expect(reviews).toContainEqual(expect.objectContaining({ status: "completed", failure: "stale_snapshot_retained_as_history" }));
    expect((saved.events as Array<{ kind: string }>).some(event => event.kind === "review-stale")).toBe(true);
  });

  it("appends task corrections without changing history, blocked tasks or unrelated blockers", () => {
    const f = fixture();
    const exec = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "response", data: { ok: true, task_id: "inspect" } })!;
    const audit = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "checkpoint-recovery", source: "operator-recovery", summary: "audit", data: {} })!;
    const p = new BlackboxProgress();
    p.state.tasks.inspect = { status: "pending", completion_criteria: "response recorded" };
    p.state.tasks.https = { status: "blocked", reason: "outside scope" };
    p.state.transitionErrors = ["invalid_advice_decision:other"];
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: p.state, status: "paused" });
    const original = f.db.getBlackboxSession(f.pid, f.sid)!;
    const originalEvents = structuredClone(original.events as Record<string, unknown>[]);
    const originalEvidence = structuredClone(original.evidence as Record<string, unknown>[]);
    const submit = (evidence_ids: string[], audit_ids: string[]) => f.desk.reviewProjectBlackboxItem(f.pid, f.sid, {
      kind: "task_outcomes", reason: "explicit offline correction", output: { completed_tasks: ["inspect"],
        task_outcomes: [{ task_id: "inspect", reason: "recorded only", evidence_ids, audit_ids }] },
    });
    const rejected = submit([String(exec.id), String(audit.id)], []);
    expect(rejected.ok).toBe(false);
    expect((f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint as typeof p.state).tasks.inspect.status).toBe("pending");
    expect(submit([String(exec.id)], [String(audit.id)])).toMatchObject({ ok: true, acceptance: { ready: false } });
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as typeof p.state;
    expect(checkpoint.tasks.inspect).toMatchObject({ status: "completed", evidence_ids: [exec.id], audit_ids: [audit.id] });
    expect(checkpoint.tasks.https).toEqual(p.state.tasks.https);
    expect(checkpoint.transitionErrors).toEqual(["invalid_advice_decision:other"]);
    expect(saved.status).toBe("paused");
    const events = saved.events as Record<string, unknown>[];
    expect(events.slice(0, originalEvents.length)).toEqual(originalEvents);
    const corrections = events.filter(e => e.kind === "task-outcome-correction");
    expect(corrections).toHaveLength(2);
    expect(corrections[0].data).toMatchObject({ rejected: true, before_checkpoint: original.checkpoint });
    expect(corrections[1].data).toMatchObject({ rejected: false });
    for (const fact of originalEvidence) expect((saved.evidence as Record<string, unknown>[]).find(e => e.id === fact.id)).toEqual(fact);
  });

  it("atomically rolls back correction records on failure and rejects stale checkpoints", () => {
    const f = fixture();
    const before = f.db.getBlackboxSession(f.pid, f.sid)!;
    const spy = vi.spyOn(f.db, "updateBlackboxSession").mockImplementationOnce(() => { throw new Error("write failed"); });
    expect(() => f.db.commitBlackboxProgressReview(f.pid, f.sid, before.checkpoint as object, new BlackboxProgress().state, { reason: "test" })).toThrow("write failed");
    spy.mockRestore();
    const after = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect(after.events).toEqual(before.events);
    expect(after.evidence).toEqual(before.evidence);
    expect(after.checkpoint).toEqual(before.checkpoint);
    expect(f.db.commitBlackboxProgressReview(f.pid, f.sid, { stale: true }, {}, { reason: "test" })).toBe(false);
    expect(f.db.getBlackboxSession(f.pid, f.sid)!.events).toEqual(before.events);
  });

  it.each(["missing finding review", "pending advice", "complete review"])("Observer finish obeys the acceptance gate: %s", async blocker => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 3 } });
    const evidence = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "fixture", data: { url: f.target, ok: true, task_id: "inspect" } })!;
    const finding = { ...candidateFinding, evidence_ids: [String(evidence.id)] };
    const review = { finding_id: finding.id, status: "reviewed", reason: "consistent", evidence_ids: finding.evidence_ids };
    const network = vi.fn()
      .mockResolvedValueOnce(answer({ summary: "stage complete", required_tasks: ["inspect"], completed_tasks: ["inspect"], findings: [finding] }))
      .mockResolvedValueOnce(answer({ review: "finish suggested", decision: "finish", finding_reviews: blocker !== "missing finding review" ? [review] : [], suggestions: blocker === "pending advice" ? ["Review remaining coverage"] : [] }))
      .mockRejectedValueOnce(new Error("fixture reached next main turn"));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as BlackboxProgress["state"];
    if (blocker === "complete review") {
      expect(network).toHaveBeenCalledTimes(2);
      expect(saved.status).toBe("completed");
      expect(checkpoint.stopReason).toBe("tasks_completed");
      expect(checkpoint.supervision?.acceptance).toMatchObject({ ready: true, required_reviews_complete: true, blocking_error_count: 0 });
      return;
    }
    expect(network.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(saved.status).toBe("paused");
    /**
     * 门禁全放行（2026-11-06）：`required_review_pending` 不再是可能的停止理由。
     * 停在这里的真实原因是「这一轮没有可用输出（fixture 直接抛错）」或「轮次预算到顶」，
     * 而不是「还在等操作员签收」——后者在无人值守场景下永远不会发生，等于提前收工。
     */
    expect(checkpoint.stopReason).not.toBe("required_review_pending");
    expect(["agent_error", "agent_turn_budget_exhausted"]).toContain(checkpoint.stopReason);
    expect(checkpoint.supervision?.acceptance).toMatchObject({ ready: false, all_tasks_terminal: true });
    expect(checkpoint.supervision?.acceptance?.reason_codes).toContain(blocker === "pending advice" ? "UNHANDLED_ADVICE" : "TERMINAL_REVIEW_PENDING");
    expect((saved.evidence as { kind: string }[]).filter(e => e.kind === "tool-request")).toHaveLength(0);
  });

  it.each([false, true])("handles repeated advice decisions without bypassing conflicts: opposite=%s", async opposite => {
    const f = fixture();
    const progress = new BlackboxProgress();
    progress.state.tasks.inspect = { status: "blocked", outcome_reason: "outside scope" };
    progress.state.advice = { old: { tasks: [], status: "rejected", reason: "already decided" } };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state });
    const network = vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : { summary: "partial stage", continue: false, advice_decisions: [{ advice_id: "old", accepted: opposite, reason: "repeat previous decision", task_ids: ["inspect"] }] }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as typeof progress.state;
    expect(checkpoint.stopReason).toBe("blocked");
    /**
     * 2026-11-10 改判：终态建议的处置冲突不再阻塞。
     *
     * `old` 已经 rejected（终态不可变、理由齐全），相反结论再提交只会被拒一次——
     * 那是一次**被拒的写入**，不是待办。旧行为把它当阻塞，实测让会话连续五场停在
     * `validation_failed_review_required`。现在它进 dlq 留痕，结论照常交付。
     * 「不许绕过冲突」这条语义没变：`advice.old` 仍然是原来那条 rejected，
     * 冲突只是不再把整场 run 掐掉。
     */
    expect(checkpoint.validationErrors).toEqual([]);
    expect(checkpoint.supervision?.acceptance).toMatchObject({ ready: true });
    expect(checkpoint.advice?.old).toEqual(progress.state.advice.old);
    expect(checkpoint.adviceDecisionResults).toEqual([{ advice_id: "old", status: opposite ? "disposition_conflict" : "already_applied" }]);
    expect(saved.status).toBe("paused");
    expect(checkpoint.tasks.inspect.status).toBe("blocked");
    expect(network).toHaveBeenCalledTimes(2);
    const events = saved.events as Array<{ kind: string; data: { reasons?: string[] } }>;
    // 冲突仍然要留痕，但落在死信队列而不是阻塞门禁上。
    expect(Boolean(checkpoint.dlq?.some(entry => entry.message === "disposition_conflict:old"))).toBe(opposite);
    expect(events.some(e => e.kind === "validation-failed")).toBe(false);
  });

  it("runs the main Agent normally after offline checkpoint recovery", async () => {
    const f = fixture();
    const request = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-request", source: "main-agent", summary: "old GET", data: { tool: "http.request", input: { url: f.target, method: "GET" } } })!;
    const response = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "old response", data: { request_evidence_id: request.id, method: "GET", url: f.target, status: 200, body: "fixture", headers: {} } })!;
    const progress = new BlackboxProgress();
    progress.state.tasks.baseline = { status: "blocked" };
    progress.state.tasks.https = { status: "blocked", outcome_reason: "outside scope" };
    const facts = f.db.getBlackboxSession(f.pid, f.sid)!.evidence as Record<string, unknown>[];
    const recovered = recoverLegacyCheckpoint(progress.state, facts, f.target, { reason: "offline review", tasks: [{ task_id: "baseline", status: "completed", reason: "old response verified", evidence_ids: [String(response.id)], urls: [f.target] }], advice_decisions: [] }, "audit");
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: recovered });
    const network = vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : { summary: "review repaired checkpoint", continue: false }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    // 2026-11-05 判据变更：baseline 已给出结论（completed + 证据），https 因范围外受阻。
    // 旧口径记 "blocked"（等于宣告整场失败），新口径记 partial_completed（可交付的部分完成）。
    expect((saved.checkpoint as typeof recovered).stopReason).toBe("partial_completed");
    expect((saved.checkpoint as typeof recovered).usage.agentTurns).toBe(1);
    expect((saved.evidence as Record<string, unknown>[]).filter(e => e.kind === "tool-request")).toHaveLength(1);
    expect(network).toHaveBeenCalledTimes(2);
    expect((saved.events as Record<string, unknown>[]).some(e => e.kind === "checkpoint-recovered")).toBe(false);
  });

  it.each([
    { decision: "finish", should_continue: false, expected: "agent_turn_budget_exhausted" },
    { decision: "continue", should_continue: true, expected: "agent_turn_budget_exhausted" },
    { decision: "pause", should_continue: false, pause_reason: "task inspect requires an authorization decision", expected: "observer_paused" },
  ])("Observer $decision preserves scheduler control and explicit safety stops", async result => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 1 } });
    const network = vi.fn().mockResolvedValueOnce(answer({ summary: "pending work", required_tasks: ["inspect"] }))
      .mockResolvedValue(answer({ review: "reviewed current stage", ...result }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    // The main turn consumes the configured one-turn budget. The required terminal
    // review is persisted as pending, but no Observer model call may exceed budget.
    expect(network).toHaveBeenCalledTimes(1);
    expect((saved.checkpoint as { stopReason: string }).stopReason).toBe("agent_turn_budget_exhausted");
    const events = saved.events as Array<{ kind: string; actor: string; text: string }>;
    expect(events.some(e => e.actor === "observer" && e.kind === "pause")).toBe(false);
    expect(events.some(e => e.kind === "review-complete")).toBe(false);
    expect(events.some(e => e.text.includes("严重异常"))).toBe(false);
    expect((saved.checkpoint as { tasks: Record<string, { status: string }> }).tasks.inspect.status).toBe("pending");
  });

  it.each(["pause", "cancel"])("%s aborts a pending model call and preserves state", async action => {
    const f = fixture();
    let entered!: () => void;
    const ready = new Promise<void>(resolve => { entered = resolve; });
    let signal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn((_url, init) => new Promise((_resolve, reject) => {
      signal = init.signal; entered(); signal!.addEventListener("abort", () => reject(signal!.reason), { once: true });
    })));
    const run = f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    await ready;
    expect(f.desk.updateProjectBlackboxSession(f.pid, f.sid, action).ok).toBe(true);
    expect(f.desk.updateProjectBlackboxSession(f.pid, f.sid, "resume").ok).toBe(false);
    await run;
    expect(signal?.aborted).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect(saved.status).toBe(action === "cancel" ? "cancelled" : "paused");
    expect((saved.checkpoint as { usage: { retries: number } }).usage.retries).toBe(0);
    if (action === "cancel") expect((await f.desk.runProjectBlackboxAgents(f.pid, f.sid)).ok).toBe(false);
  });

  it("executes a requested tool in the same run and never waits for an approval", async () => {
    const hits: string[] = [];
    const server = createServer((req, res) => { hits.push(req.url!); res.end("fixture"); });
    const target = await listen(server);
    try {
      const f = fixture(target);
      f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
      let mainCalls = 0;
      vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : mainCalls++ === 0 ? {
        summary: "approval-free", required_tasks: ["probe"], tool_requests: [{ tool: "http.request", task_id: "probe", input: { url: `${target}exact?x=1`, method: "HEAD" }, requires_confirmation: true }],
      } : { summary: "done" })));
      const result = await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
      expect(result.ok).toBe(true);
      expect(hits).toEqual(["/exact?x=1"]);
      const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
      expect((saved.checkpoint as { approvals?: unknown }).approvals).toBeUndefined();
      expect((saved.checkpoint as { usage: { toolCalls: number; retries: number } }).usage).toMatchObject({ toolCalls: 1, retries: 0 });
      expect((saved.events as Array<{ kind: string }>).some(event => event.kind.startsWith("approval"))).toBe(false);
    } finally { await close(server); }
  });

  it("lets the focus follow an undecided Observer advice instead of rejecting its requests", async () => {
    // 冲突 1 的端到端版本：焦点粘在 T1，但 Observer 建议指着 T3。旧行为是 T3 的请求被焦点锁
    // 全部拒收 → 建议没处置 → 判无进展 → 更快收口。断言新的让位路径：请求被放行、留下 handoff 事件。
    const hits: string[] = [];
    const server = createServer((req, res) => { hits.push(req.url!); res.end("fixture"); });
    const target = await listen(server);
    try {
      const f = fixture(target);
      f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
      const seeded = new BlackboxProgress();
      seeded.state.tasks.T1 = { status: "pending", target, purpose: "深挖 T1 的越权面" };
      seeded.state.tasks.T3 = { status: "pending", target, purpose: "验证 /advice 未授权访问" };
      seeded.state.focus_task_id = "T1";
      seeded.state.advice = { advice_1: { tasks: [], status: "pending", task_ids: ["T3"], misses: 1 } };
      f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: seeded.state, status: "ready" });
      let mainCalls = 0;
      vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : mainCalls++ === 0
        ? { summary: "按建议补证", tool_requests: [{ tool: "http.request", task_id: "T3", input: { url: `${target}advice` } }] }
        : { summary: "done" })));
      const result = await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
      expect(result.ok).toBe(true);
      const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
      const events = saved.events as Array<{ kind: string; data?: { task_id?: string } }>;
      expect(events.some(event => event.kind === "focus-handoff" && event.data?.task_id === "T3")).toBe(true);
      expect(events.some(event => event.kind === "focus-lock")).toBe(false);
      expect(hits).toContain("/advice");
    } finally { await close(server); }
  });

  it("never lets a forced focus starve the run: rejected batches overflow instead of stalling", async () => {
    // 2026-11-02 实跑（6ee79b87a797904f / f77278fb6b829eda）的端到端复现：SPA 缴械把
    // forced_focus 钉在 T_SPA，模型每轮都投 T1，于是整批被 focus-lock 拒收 → 旧代码把它算成
    // "零动作" → 第 3 轮 stalled；只加让位后又在任务间反复交接（3 次 handoff、10/40 次调用就收场）。
    // 最终形态：整批全拒时溢出放行被拒最多的任务（上限 2 条/轮），焦点不动。
    const hits: string[] = [];
    const server = createServer((req, res) => { hits.push(req.url!); res.end("fixture"); });
    const target = await listen(server);
    try {
      const f = fixture(target);
      f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 3 } });
      const seeded = new BlackboxProgress();
      seeded.state.tasks.T1 = { status: "pending", target, purpose: "模型真正想打的未授权面" };
      seeded.state.tasks.T_SPA = { status: "pending", target, purpose: "SPA 外壳逆向（强制焦点）" };
      seeded.state.focus_task_id = "T1";
      seeded.state.forced_focus = { task_id: "T_SPA", kind: "spa", at: 1, note: "SPA 外壳强制焦点" };
      f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: seeded.state, status: "ready" });
      let mainCalls = 0;
      vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : mainCalls++ < 3
        ? { summary: "打未授权面", tool_requests: [{ tool: "http.request", task_id: "T1", input: { url: `${target}forced-target` } }] }
        : { summary: "done" })));
      const result = await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
      expect(result.ok).toBe(true);
      const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
      const events = saved.events as Array<{ kind: string; text?: string }>;
      expect(events.some(event => event.kind === "focus-overflow")).toBe(true);
      expect(events.some(event => /stalled/.test(String(event.text || "")))).toBe(false);
      expect((saved.checkpoint as { stopReason?: string }).stopReason).not.toBe("stalled");
      expect(hits).toContain("/forced-target");
    } finally { await close(server); }
  });

  it("hands the focus over when the batch's real centre of gravity sits on another task", async () => {
    // 2026-11-02 实跑（a007634f）的根因复现：焦点在 T1，模型每轮投 1 条给 T1、3 条给 T2。
    // 旧判据只在"整批被拒（放行 0 条）"时计票，而焦点溢出会先把 T2 的 2 条塞回 requests，
    // 于是申诉永远不计票 → 11 次 focus-lock + 9 次 overflow 之后焦点仍钉在 T1。
    // 现在"另一任务被拒 ≥2 条且多于焦点任务的派活数"也算重心偏移，连续两轮就交接。
    const hits: string[] = [];
    const server = createServer((req, res) => { hits.push(req.url!); res.end("fixture"); });
    const target = await listen(server);
    try {
      const f = fixture(target);
      f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 4 } });
      const seeded = new BlackboxProgress();
      seeded.state.tasks.T1 = { status: "pending", target, purpose: "顺带确认的边角任务" };
      seeded.state.tasks.T2 = { status: "pending", target, purpose: "模型真正在打的未授权面" };
      seeded.state.focus_task_id = "T1";
      f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: seeded.state, status: "ready" });
      let mainCalls = 0;
      vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : mainCalls++ < 3
        ? {
          summary: "推进未授权面",
          tool_requests: [
            { tool: "http.request", task_id: "T1", input: { url: `${target}minor?n=${mainCalls}` } },
            { tool: "http.request", task_id: "T2", input: { url: `${target}majority-a?n=${mainCalls}` } },
            { tool: "http.request", task_id: "T2", input: { url: `${target}majority-b?n=${mainCalls}` } },
            { tool: "http.request", task_id: "T2", input: { url: `${target}majority-c?n=${mainCalls}` } },
          ],
        }
        : { summary: "done" })));
      const result = await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
      expect(result.ok).toBe(true);
      const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
      const events = saved.events as Array<{ kind: string; data?: { task_id?: string; displaced?: string } }>;
      expect(events.some(event => event.kind === "focus-appeal" && event.data?.displaced === "majority")).toBe(true);
      expect(events.some(event => event.kind === "focus-handoff" && event.data?.task_id === "T2")).toBe(true);
      // 交接之后 T2 的请求必须真的被执行，而不是继续靠溢出放行。
      expect(hits.some(url => url.includes("majority-"))).toBe(true);
      expect((saved.checkpoint as { stopReason?: string }).stopReason).not.toBe("scheduler_deadlock");
    } finally { await close(server); }
  });

  it("asks for a verdict instead of a new request when the focus is already converging", async () => {
    // 五重惩罚叠加（2026-11-02 审计第 7 条）里最致命的一组：焦点预算判"强制收口"要求结案，
    // 模型照做只结案不发请求 → 被算成"零动作" → 老的零动作文案要求"必须发 1 个请求"。
    // 发请求被收口拒、结案被审计拒，模型只能空转到 stalled。
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
    const seeded = new BlackboxProgress();
    seeded.state.tasks.T1 = { status: "pending", target: f.target, purpose: "深挖 T1 的越权面", playbook: "unauth_exposure" };
    seeded.state.focus_task_id = "T1";
    // 不 seed focus_convergence：那等价于"上一轮已经收口但没执行"，第一轮开始就会被兜底标 blocked。
    // 这里把微观预算顶到上限，让**本轮**结算时触发收口，才能复现"收口 + 零动作"同轮叠加。
    seeded.state.focus_usage = {
      task_id: "T1", turns: 8, tool_calls: 9, tp: 20, value_score: 0, high_value: 0, medium_value: 0,
      noise: 2, last_value_score: 0, no_progress_rounds: 3, appeals_used: 0, max_turns: 8, max_tp: 50,
    };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: seeded.state, status: "ready" });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : { summary: "按收口指令结案中" })));
    const result = await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const events = (saved.events as Array<{ kind: string; text?: string; data?: { converging?: string | null } }>)
      .filter(event => event.kind === "zero-action-round");
    expect(events.length).toBeGreaterThan(0);
    // 指令必须换成"先结案"，而不是"必须发请求"。
    expect(events.some(event => String(event.text || "").includes("结案优先"))).toBe(true);
    expect(events.every(event => event.data?.converging === "T1")).toBe(true);
    const interrupts = (saved.checkpoint as { interrupts?: Array<{ text?: string }> }).interrupts || [];
    expect(interrupts.some(item => String(item.text || "").includes("不要发新的探测请求"))).toBe(true);
  });

  it("ignores legacy approval records instead of blocking resumed execution", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 1 } });
    const legacy = new BlackboxProgress();
    (legacy.state as Record<string, unknown>).approvals = {
      "approval-legacy": { id: "approval-legacy", status: "pending", created_at: 1, request: { tool: "http.request" } },
    };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: legacy.state, status: "ready" });
    expect(legacy.begin({ tool: "http.request", input: { url: `${f.target}legacy` } }, f.target, 2, 2).blocked).toBeUndefined();
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : { summary: "legacy checkpoint resumed" })));
    const result = await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((saved.events as Array<{ kind: string }>).some(event => event.kind === "approval-pending")).toBe(false);
    expect(saved.status).not.toBe("running");
  });

  it("aborts an active HTTP request, records cancellation and terminates Katana", async () => {
    let entered!: () => void;
    const hit = new Promise<void>(resolve => { entered = resolve; });
    const server = createServer(() => entered());
    const target = await listen(server);
    try {
      const f = fixture(target);
      const controller = new AbortController();
      const running = executeAndRecordBlackboxTool({ cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target, values: f.cfg.tools_env.values, signal: controller.signal }, { tool: "http.request", task_id: "inspect", input: { url: target } });
      await hit; controller.abort(new Error("operator pause"));
      expect((await running).data.cancelled).toBe(true);
      const childController = new AbortController();
      const child = runKatana(process.execPath, ["-e", "setInterval(() => {}, 1000)"], 60000, childController.signal);
      childController.abort(new Error("stop child"));
      await expect(child).rejects.toThrow("stop child");
    } finally { await close(server); }
  });

  it("closes a browser resource acquired after cancellation", async () => {
    const controller = new AbortController();
    let resolve!: (value: { close: () => Promise<void> }) => void;
    const closing = vi.fn(async () => {});
    const pending = new Promise<{ close: () => Promise<void> }>(done => { resolve = done; });
    const acquisition = acquire(pending, controller.signal, resource => resource.close());
    controller.abort(new Error("stop launch"));
    await expect(acquisition).rejects.toThrow("stop launch");
    resolve({ close: closing });
    await Promise.resolve();
    expect(closing).toHaveBeenCalledOnce();
  });

  it("closes an active browser navigation on operator cancellation", async () => {
    const f = fixture();
    let entered!: () => void;
    const navigating = new Promise<void>(resolve => { entered = resolve; });
    let rejectNavigation!: (error: Error) => void;
    const closeBrowser = vi.fn(async () => { rejectNavigation?.(new Error("browser closed")); });
    vi.spyOn(chromium, "launch").mockResolvedValue({
      close: closeBrowser,
      newContext: async () => ({ route: async () => {}, newPage: async () => ({ goto: () => new Promise((_resolve, reject) => { rejectNavigation = reject; entered(); }) }) }),
    } as never);
    const controller = new AbortController();
    const running = executeAndRecordBlackboxTool({ cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: f.target, values: f.cfg.tools_env.values, signal: controller.signal }, { tool: "browser.open", input: { url: f.target } });
    await navigating; controller.abort(new Error("operator stopped"));
    expect((await running).data.cancelled).toBe(true);
    expect(closeBrowser).toHaveBeenCalled();
  });

  it("executes a confirmation-flagged request immediately and never queues an approval", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
    let mainCalls = 0;
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? observer : mainCalls++ === 0 ? {
      summary: "confirm", required_tasks: ["inspect"], tool_requests: [{ tool: "http.request", task_id: "inspect", input: { url: f.target }, requires_confirmation: true }],
    } : { summary: "done" })));
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((saved.checkpoint as { approvals?: unknown }).approvals).toBeUndefined();
    expect((saved.checkpoint as { usage: { toolCalls: number; retries: number } }).usage).toMatchObject({ toolCalls: 1, retries: 1 });
    expect((saved.events as Array<{ kind: string }>).some(event => event.kind.startsWith("approval"))).toBe(false);
  });

  it("accepts structured main findings and records Observer review without confirming a vulnerability", async () => {
    const f = fixture();
    const evidence = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "fixture response", data: { url: f.target, ok: true, task_id: "inspect" } })!;
    const finding = { ...candidateFinding, evidence_ids: [String(evidence.id)] };
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
      const isObserver = String(init.body).includes("main_agent_output");
      return answer(isObserver ? { ...observer, finding_reviews: [{ finding_id: finding.id, status: "reviewed", reason: "Evidence consistent, manual replication required", evidence_ids: finding.evidence_ids }] } : { summary: "candidate", required_tasks: ["inspect"], completed_tasks: ["inspect"], findings: [finding] });
    }));
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = new BlackboxProgress(f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint);
    expect(saved.state.findings![finding.id]).toMatchObject({ status: "reviewed", review: { actor: "observer" } });
    expect(f.desk.projectBlackboxReport(f.pid, f.sid).markdown).toContain("reviewed");
    expect(f.desk.reviewProjectBlackboxItem(f.pid, f.sid, { kind: "finding", id: finding.id, action: "confirm", reason: "fixture independently checked by operator" }).ok).toBe(true);
  });

  it("lets the Observer confirm a finding that cites reproducible evidence", async () => {
    const f = fixture();
    const evidence = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "fixture response", data: { url: f.target, ok: true, task_id: "inspect" } })!;
    const finding = { ...candidateFinding, evidence_ids: [String(evidence.id)] };
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
      const isObserver = String(init.body).includes("main_agent_output");
      return answer(isObserver
        ? { ...observer, finding_reviews: [{ finding_id: finding.id, status: "confirmed", reason: "未带凭证返回 200，http.diff 与登录态一致", evidence_ids: finding.evidence_ids }] }
        : { summary: "candidate", required_tasks: ["inspect"], completed_tasks: ["inspect"], findings: [finding] });
    }));
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = new BlackboxProgress(f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint);
    expect(saved.state.findings![finding.id]).toMatchObject({ status: "confirmed", review: { actor: "observer" } });
    expect(f.desk.projectBlackboxReport(f.pid, f.sid).markdown).toContain("confirmed");
  });

  it("rejects an Observer confirmation that cites no evidence", () => {
    // The schema refuses a confirmed review with an empty evidence list: confirmation is
    // an evidence claim, not a mood.
    const parsed = observerSchema.safeParse({ review: "x", finding_reviews: [{ finding_id: "f-1", status: "confirmed", reason: "looks fine", evidence_ids: [] }] });
    expect(parsed.success).toBe(false);
  });

  it("validates finding provenance and distinguishes human confirmation in reports", () => {
    const f = fixture();
    const evidence = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "fixture", data: { url: f.target, ok: true } })!;
    const finding = { ...candidateFinding, evidence_ids: [String(evidence.id)] };
    expect(validateFinding({ ...finding, evidence_ids: ["missing"] }, [evidence])).toContain("不存在");
    expect(validateFinding({ ...finding, target: "https://other.example/" }, [evidence])).toContain("该目标");
    const progress = new BlackboxProgress(); progress.state.findings = { [finding.id]: finding };
    progress.state.tasks = { inspect: { status: "blocked", reason: "incomplete" } };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state });
    const payload = { kind: "finding", id: finding.id, action: "confirm", reason: "manual fixture review" };
    expect(f.desk.reviewProjectBlackboxItem(f.pid, f.sid, payload).ok).toBe(false);
    finding.status = "reviewed";
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state });
    expect(f.desk.reviewProjectBlackboxItem(f.pid, f.sid, payload).ok).toBe(true);
    const report = blackboxReport(f.db.getBlackboxSession(f.pid, f.sid)!);
    expect(report.markdown).toContain("部分完成");
    expect(report.markdown).toContain("confirmed");
    expect(report.markdown).toContain("blocked");
    expect(report.markdown).toContain(String(evidence.id));
  });

  it("does not kill the run over advice the model ignored (push.oppo.com regression)", async () => {
    const f = fixture();
    const progress = new BlackboxProgress();
    const evidence = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "fixture", data: { url: f.target, ok: true, task_id: "inspect" } })!;
    progress.state.tasks.inspect = { status: "completed", evidence_ids: [String(evidence.id)], outcome_reason: "done" };
    const ignored = "review-d9a3260b5fbd6a8a5ec9d6b9";
    const archived = "review-8f5650eb55315eca885ffbde";
    // 复刻 session c88cc901 的收尾状态：一条被 supplement 归档成 superseded 却还挂着
    // invalid_advice_decision 的孤儿错误，另一条干脆没被处置。
    progress.state.advice = {
      [ignored]: { tasks: [], suggestions: ["改打 open.oppomobile.com 的 /base/v1/*"], status: "pending" },
      [archived]: { tasks: [], suggestions: ["bdev 当独立资产打"], status: "superseded", reason: "任务已全部终态，建议自动归档。" },
    };
    progress.state.transitionErrors = [`invalid_advice_decision:${archived}`];
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state, status: "paused" });
    const network = vi.fn(async (_url: string, init: RequestInit) => answer(String(init.body).includes("main_agent_output")
      ? observer
      : { summary: "本轮继续验证，未处置任何建议", continue: false, required_tasks: [], completed_tasks: [], task_outcomes: [] }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as typeof progress.state;
    expect(checkpoint.stopReason).not.toBe("validation_failed_review_required");
    expect(checkpoint.advice?.[ignored]?.status).toBe("superseded");
    expect(checkpoint.advice?.[ignored]?.auto_skipped).toBe(true);
    expect(checkpoint.transitionErrors || []).not.toContain(`invalid_advice_decision:${archived}`);
    expect((saved.events as Array<{ kind: string }>).some(event => event.kind === "advice-auto-skip")).toBe(true);
    expect(checkpoint.supervision?.acceptance?.blocking_error_count).toBe(0);
  });

  it("gives the agent one extra round to dispose advice produced by the final review", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 4 } });
    const evidence = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "http.request", summary: "fixture", data: { url: f.target, ok: true, task_id: "inspect" } })!;
    let mainRounds = 0;
    const network = vi.fn(async (_url: string, init: RequestInit) => {
      if (String(init.body).includes("main_agent_output")) return answer({ review: "收尾复核通过", decision: "finish", suggestions: ["把 dict/get_key 带真实 DictKey 再打一次"] });
      mainRounds += 1;
      if (mainRounds === 1) return answer({ summary: "任务完成", required_tasks: ["inspect"], completed_tasks: ["inspect"],
        task_outcomes: [{ task_id: "inspect", reason: "done", evidence_ids: [String(evidence.id)] }], continue: false });
      // 补跑的处置回合：模型只写正文、不输出结构化处置（最容易被忽略的那种输出）。
      return answer({ summary: "建议已阅读，按低危收口，不再继续探测。", required_tasks: [], completed_tasks: [], task_outcomes: [], continue: false });
    });
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as BlackboxProgress["state"];
    // 终审产出的建议让模型补跑了一回合，而不是带着"没看过的建议"离场。
    expect(mainRounds).toBe(2);
    const kinds = (saved.events as Array<{ kind: string }>).map(event => event.kind);
    expect(kinds).toContain("advice-disposal-round");
    expect(kinds).toContain("advice-auto-skip");
    expect(checkpoint.stopReason).not.toBe("required_review_pending");
    expect(checkpoint.stopReason).not.toBe("validation_failed_review_required");
    // 补跑后仍未处置的建议按「未采纳」归档，不留在 pending 里拖住门禁。
    expect(Object.values(checkpoint.advice || {}).every(item => item.status !== "pending")).toBe(true);
    expect(checkpoint.supervision?.acceptance?.unhandled_advice).toBe(0);
    expect(saved.status).toBe("completed");
  });
});

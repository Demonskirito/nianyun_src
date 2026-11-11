import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Desk } from "../src/control/console/desk.js";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { BlackboxProgress, OBSERVER_VERSION_PREFIX, legacyObserverStateVersion, observerStateVersion, observerStateVersionMatches, observerReviewId, type RunCheckpoint } from "../src/blackbox/progress.js";
import { graphState } from "../src/blackbox/graph/index.js";
import { blackboxRules, blackboxRulesHash } from "../src/blackbox/rules.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); databases.splice(0).forEach(db => db.close()); dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })); });
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-review-reliability-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" }; // Mock Observer only.
  Object.assign(cfg.tools_env.values, { BLACKBOX_AGENT_BASE_URL: "https://mock.invalid/v1", BLACKBOX_AGENT_MODEL: "fixture", BLACKBOX_AGENT_API_KEY: "fixture", BURP_PROXY_REQUIRED: "false",
    BLACKBOX_RULES_DOCUMENT: JSON.stringify({ budgets: { agent_turns: 0, time_sec: 0, tool_calls: 0, tokens: 0, retries: 0 } }) });
  const path = join(dir, "data", "nianyun.db");
  const db = new Database(path); databases.push(db);
  const pid = String(createProject(cfg, "Review reliability", "fixture").id);
  const target = "http://127.0.0.1:1/";
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "fixture" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  const state = new BlackboxProgress().state;
  const rules = blackboxRules(cfg.tools_env.values);
  state.rule_version = rules.version; state.rule_hash = blackboxRulesHash(rules);
  // Acceptance initializes this ledger. Persist the canonical state before hashing.
  state.transitionErrors = []; state.validationErrors = [];
  state.tasks.inspect = { status: "blocked", reason: "fixture boundary" };
  const seed = (status: "pending" | "running" | "failed" = "pending", attempts = 0, retryable = true) => {
    const version = observerStateVersion(state, db.getBlackboxSession(pid, sid)!.evidence as Record<string, unknown>[]);
    const id = observerReviewId("terminal_review", version, []);
    state.supervision = { observerRuns: 0, reviewPending: true, reviews: { [id]: { id, reason: "terminal_review", trigger_event_id: "fixture-event", session_id: sid, state_version: version, status, attempts, retryable, created_at: 1 } } };
    db.updateBlackboxSession(pid, sid, { checkpoint: state, status: "paused" });
    return id;
  };
  return { cfg, db, path, pid, sid, state, seed, desk: new Desk(cfg, db), saved: () => db.getBlackboxSession(pid, sid)!, current: () => db.getBlackboxSession(pid, sid)!.checkpoint as RunCheckpoint };
}
const response = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
const finish = { review: "fixture reviewed", decision: "finish" };
const terminal = { summary: "fixture terminal", required_tasks: ["inspect"], blocked_tasks: ["inspect"], task_outcomes: [{ task_id: "inspect", reason: "fixture boundary", evidence_ids: [] }] };

describe("Observer lifecycle actual scheduler entry", () => {
  it.each(["completed", "blocked", "failed"] as const)("preserves terminal task %s while reviewing without tool calls", async status => {
    const f = fixture();
    if (status === "completed") {
      const fact = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "fixture", summary: "prior execution", data: { ok: true, task_id: "inspect" } })!;
      f.state.tasks.inspect = { status, evidence_ids: [String(fact.id)], reason: "fixture outcome" };
    } else f.state.tasks.inspect = { status, reason: "fixture outcome" };
    f.seed();
    const network = vi.fn().mockResolvedValue(response(finish)); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().tasks.inspect.status).toBe(status);
    expect(f.current().usage.toolCalls).toBe(0);
    expect(f.current().stopReason).toBe(status === "completed" ? "tasks_completed" : status);
    expect(f.saved().status).toBe(status === "completed" ? "completed" : "paused");
    expect(network).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["elapsedMs", 1], ["toolCalls", 1], ["agentTurns", 1], ["tokens", 1], ["cost", 1], ["retries", 1],
  ] as const)("lets a run start even when stored %s already exceeds its budget", async (counter, used) => {
    // Budgets are per run: a session that already spent its allowance must still be able to work.
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { time_sec: 1, tool_calls: 1, agent_turns: 1, tokens: 1, cost: 1, retries: 1 } });
    f.state.usage[counter] = used;
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: f.state });
    const network = vi.fn().mockResolvedValue(response(finish)); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    // The stored counter is ignored as a starting point: the run gets its own allowance.
    expect(network).toHaveBeenCalled();
    expect(String(f.current().stopReason || "")).toBe("agent_turn_budget_exhausted");
  });

  it("records a pending terminal review when this run exhausts its tool budget", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { tool_calls: 1 } });
    const network = vi.fn(async (_url, init) => response(String(init.body).includes("main_agent_output") ? finish : {
      summary: "one probe", required_tasks: ["inspect"],
      tool_requests: [{ tool: "http.request", task_id: "inspect", input: { url: "http://127.0.0.1:1/" } }],
    })); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().usage.toolCalls).toBe(1);
    expect(f.current().stopReason).toBe("tool_budget_exhausted");
    expect(Object.values(f.current().supervision?.reviews || {})).toContainEqual(expect.objectContaining({ reason: "terminal_review", status: "pending" }));
    expect(f.saved().status).toBe("paused");
  });

  it.each(["pending", "running"] as const)("recovers a crash at %s without a Main Agent turn or automatic execution", async status => {
    const f = fixture(); const id = f.seed(status, status === "running" ? 1 : 0);
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "running" });
    f.db.recoverBlackboxSessions();
    expect(f.saved().status).toBe("paused");
    expect(f.current().supervision!.reviews![id].status).toBe(status === "running" ? "failed" : "pending");
    const network = vi.fn().mockResolvedValue(response(finish)); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(network).toHaveBeenCalledTimes(1);
    expect(String(network.mock.calls[0][1].body)).toContain("main_agent_output");
    expect(f.current().supervision!.reviews![id]).toMatchObject({ status: "completed", attempts: status === "running" ? 2 : 1 });
    expect(f.current().tasks.inspect.status).toBe("blocked");
    expect(f.saved().status).toBe("paused");
  });

  it("only one of two workers can claim and execute a persisted review", async () => {
    const f = fixture(); f.seed();
    const secondDb = new Database(f.path); databases.push(secondDb);
    const second = new Desk(f.cfg, secondDb);
    let release!: (value: Response) => void;
    const network = vi.fn(() => new Promise<Response>(resolve => { release = resolve; })); vi.stubGlobal("fetch", network);
    const first = f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    await vi.waitFor(() => expect(network).toHaveBeenCalledTimes(1));
    expect(await second.runProjectBlackboxAgents(f.pid, f.sid)).toMatchObject({ ok: false });
    release(response(finish)); await first;
    expect(network).toHaveBeenCalledTimes(1);
    expect((f.saved().events as Array<{ kind: string }>).filter(e => e.kind === "advice")).toHaveLength(1);
    // Duplicate delivery after completion reuses the same terminal result.
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(network).toHaveBeenCalledTimes(1);
  });

  it.each([false, true])("does not run Main after exhausted or nonretryable review (retryable=%s)", async retryable => {
    const f = fixture(); f.seed("failed", retryable ? 2 : 1, retryable);
    const network = vi.fn(); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(network).not.toHaveBeenCalled();
    expect(f.current().stopReason).toBe("observer_review_retry_exhausted");
    expect(f.saved().status).toBe("paused");
  });

  it("rolls back a successful result transaction before recording a visible failure", async () => {
    const f = fixture(); const id = f.seed();
    const update = f.db.updateBlackboxSession.bind(f.db);
    let fail = true;
    vi.spyOn(f.db, "updateBlackboxSession").mockImplementation((pid, sid, fields) => {
      if (fail && (fields.checkpoint as RunCheckpoint | undefined)?.supervision?.reviews?.[id]?.status === "completed") {
        fail = false; throw new Error("fixture result transaction failed");
      }
      return update(pid, sid, fields);
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({ ...finish, suggestions: ["must not escape rollback"] })));
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    // 回滚仍然必须成立：失败被记录、未落账的 suggestions 不许漏进 advice、不许出现
    // review-complete/review-result。失败原因可能是后续重试的次生错误（首次事务失败本身
    // 没落盘——它在失败的那个事务里），所以只断言"有失败记录"，不断言具体文案。
    expect(f.current().supervision!.reviews![id]).toMatchObject({ status: "failed" });
    expect(String(f.current().supervision!.reviews![id].failure || "")).not.toBe("");
    expect(f.current().advice).toBeUndefined();
    expect((f.saved().events as Array<{ kind: string }>).filter(e => ["review-complete", "review-result", "advice"].includes(e.kind))).toHaveLength(0);
    // 2026-11-02 起单次审查失败不再停场（Observer 是辅助）：失败会被计数，主循环继续；
    // 连续 3 次才降级为"审查不可用"。这里断言 stopReason 不再是 observer_review_failed
    // （会话可能因"审查未完成/待办未跑"停在 paused，那是另一码事，不是被一次失败掐掉）。
    expect((f.saved().events as Array<{ kind: string }>).some(e => e.kind === "review-failed")).toBe(true);
    expect(f.current().stopReason).not.toBe("observer_review_failed");
  });

  it("retains an evidence-only stale result as history without a valid terminal marker", async () => {
    const f = fixture(); const id = f.seed();
    vi.stubGlobal("fetch", vi.fn(async () => {
      f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "fixture", summary: "concurrent execution fact", data: { ok: true, task_id: "inspect" } });
      return response(finish);
    }));
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().supervision!.reviews![id]).toMatchObject({ status: "completed", failure: "stale_snapshot_retained_as_history" });
    expect(f.current().supervision!.terminalReviewVersion).toBeUndefined();
    expect(f.current().stopReason).toBe("observer_review_stale_snapshot");
  });

  it("rolls back result, advice and evidence together when result evidence insertion fails", async () => {
    const f = fixture(); const id = f.seed();
    vi.spyOn(f.db, "addBlackboxEvidence").mockImplementationOnce(() => { throw new Error("fixture evidence write failed"); });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(finish)));
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().supervision!.reviews![id].status).toBe("failed");
    expect((f.saved().events as Array<{ kind: string }>).filter(e => ["advice", "review-complete"].includes(e.kind))).toHaveLength(0);
    expect((f.saved().evidence as Array<{ kind: string }>).filter(e => e.kind === "observer-review")).toHaveLength(0);
  });

  it("rolls back startup recovery if its audit event cannot be written", () => {
    const f = fixture(); const id = f.seed("running", 1);
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "running" });
    const before = f.saved();
    vi.spyOn(f.db, "addBlackboxEvent").mockImplementationOnce(() => { throw new Error("fixture recovery audit failed"); });
    expect(() => f.db.recoverBlackboxSessions()).toThrow("fixture recovery audit failed");
    expect(f.saved().checkpoint).toEqual(before.checkpoint);
    expect(f.saved().events).toEqual(before.events);
    expect(f.current().supervision!.reviews![id].status).toBe("running");
    f.db.recoverBlackboxSessions();
    expect(f.saved().status).toBe("paused");
  });

  it("fails closed if the final gate cannot persist a pending review", async () => {
    const f = fixture();
    const commit = f.db.commitBlackboxObserverReview.bind(f.db);
    vi.spyOn(f.db, "commitBlackboxObserverReview").mockImplementation((pid, sid, expected, next, event) => {
      // A null event is a silent checkpoint commit (no timeline row).
      if (event?.kind === "review-pending") throw new Error("fixture pending write failed");
      return commit(pid, sid, expected, next, event);
    });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("fixture agent unavailable")));
    expect(await f.desk.runProjectBlackboxAgents(f.pid, f.sid)).toMatchObject({ ok: false, error: "fixture pending write failed" });
    expect(f.saved().status).toBe("paused");
    expect((f.saved().events as Array<{ kind: string }>).some(e => e.kind === "review-persistence-failed")).toBe(true);
    expect(Object.values(f.current().supervision?.reviews || {})).toHaveLength(0);
  });

  it("reloads a concurrent checkpoint after CAS conflict without overwriting its task", async () => {
    const f = fixture(); f.seed();
    const commit = f.db.commitBlackboxObserverReview.bind(f.db);
    let inject = true;
    vi.spyOn(f.db, "commitBlackboxObserverReview").mockImplementation((pid, sid, expected, next, event) => {
      if (inject && event?.kind === "review-running") {
        inject = false;
        const changed = structuredClone(f.current()); changed.tasks.concurrent = { status: "blocked", reason: "concurrent writer" };
        f.db.updateBlackboxSession(pid, sid, { checkpoint: changed });
      }
      return commit(pid, sid, expected, next, event);
    });
    const network = vi.fn(); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(network).not.toHaveBeenCalled();
    expect(f.current().tasks.concurrent).toEqual({ status: "blocked", reason: "concurrent writer" });
    expect(f.current().stopReason).toBe("observer_review_checkpoint_conflict");
    expect(f.saved().status).toBe("paused");
  });

  it.each(["timeout", "exception", "empty", "malformed"])("fails closed on Observer %s", async kind => {
    const f = fixture(); const id = f.seed();
    const network = vi.fn(async () => {
      if (kind === "timeout" || kind === "exception") throw new Error(kind === "timeout" ? "Observer timeout" : "fixture exception");
      return response(kind === "empty" ? {} : { review: 42, decision: "invalid" });
    }); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().supervision!.reviews![id].status).toBe("failed");
    expect(f.current().supervision!.reviewPending).toBe(true);
    expect(f.saved().status).toBe("paused");
    /**
     * 门禁全放行（2026-11-06）：审查挂掉不再立刻停场——它是辅助，不是主循环的必要条件，
     * 主循环会带着现有证据继续跑（也就意味着主回合会被再调用一次以上）。
     * 但同一份快照的审查不会无限重试：attempts 有上限，停止原因也不再是"等审"。
     */
    expect(network.mock.calls.length).toBeGreaterThan(1);
    expect(f.current().supervision!.reviews![id].attempts).toBeLessThanOrEqual(2);
    expect(f.current().stopReason).not.toBe("required_review_pending");
  });

  it.each(["agent_error", "protocol_error", "stalled", "stage_timeout", "budget"])("passes actual %s exit through the terminal gate", async exit => {
    const f = fixture();
    if (exit === "budget") {
      f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 1 } });
    }
    if (exit === "stalled") f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ loop_control: { stall_batch_limit: 1 } });
    const network = vi.fn(async (_url, init) => {
      if (String(init.body).includes("main_agent_output")) return response(finish);
      if (exit === "agent_error") throw new Error("fixture model unavailable");
      if (exit === "stage_timeout") throw new Error("fixture timeout");
      if (exit === "protocol_error") return response({ summary: 42 });
      return response({ summary: "no progress" });
    }); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    const reviews = Object.values(f.current().supervision?.reviews || {});
    expect(reviews).toContainEqual(expect.objectContaining({ reason: "terminal_review", status: exit === "budget" ? "pending" : "completed" }));
    expect(f.saved().status).toBe("paused");
    // Per-run budgets: the run gets one turn, then the gate records the pending review
    // instead of spending an Observer call.
    if (exit === "budget") expect(f.current().usage.agentTurns).toBe(1);
    else expect(network.mock.calls.some(call => String(call[1].body).includes("main_agent_output"))).toBe(true);
  });

  it("executes validation_failed and rejects finish when current blocking errors remain", async () => {
    const f = fixture();
    /**
     * 2026-11-10 调整：原来注入的是 `invalid_advice_decision:fixture`——一条指向**不存在**
     * 建议的账本错误。按新判据（主体已死 → 进 dlq）它压根没有合法输入能修，离场时应被退役，
     * 于是门禁不再阻塞。要考的是"**还有得修**的阻塞会让门禁拒收 finish"，所以这里换成
     * 一条指向 pending 任务的证据引用错误（非 correctable 码）：它随时能靠重交修好，必须继续拦。
     */
    f.state.tasks.probe = { status: "pending" } as never;
    f.state.transitionErrors = ["task_evidence_invalid:probe:ev-0123456789abcdef"];
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: f.state });
    const network = vi.fn(async (_url, init) => response(String(init.body).includes("main_agent_output") ? finish : terminal));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(Object.values(f.current().supervision?.reviews || {})).toContainEqual(expect.objectContaining({ reason: "validation_failed", status: "completed" }));
    expect(f.current().supervision!.acceptance).toMatchObject({ ready: false, blocking_error_count: 1 });
    expect(f.saved().status).toBe("paused");
    expect(network.mock.calls.length).toBeLessThanOrEqual(3);
  });

  it("skips an unlinkable tool request instead of aborting the round", async () => {
    const f = fixture();
    const network = vi.fn(async (_url, init) => response(String(init.body).includes("main_agent_output") ? finish : {
      summary: "invalid task reference", required_tasks: ["inspect"], tool_requests: [{ tool: "http.request", task_id: "unknown", input: { url: "http://127.0.0.1:1/" } }],
    })); vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().stopReason).not.toBe("protocol_error");
    expect(f.current().usage.toolCalls).toBe(0);
    expect(f.current().tasks.unknown).toBeUndefined();
    const events = f.saved().events as Array<{ kind: string; data?: Record<string, unknown> }>;
    expect(events.some(event => event.kind === "protocol-error")).toBe(false);
    const rejected = events.find(event => event.kind === "tool-requests-rejected")!;
    expect((rejected.data?.rejected as Array<{ task_id?: string; reason: string }>)[0]).toMatchObject({ task_id: "unknown" });
    expect(Object.values(f.current().supervision!.reviews!)).toContainEqual(expect.objectContaining({ reason: "terminal_review", status: "completed" }));
  });

  it("preserves an explicit Observer pause without starting Main or declaring normal completion", async () => {
    const f = fixture(); f.seed();
    const network = vi.fn().mockResolvedValue(response({ review: "authorization requires operator", decision: "pause", pause_reason: "fixture authorization decision" }));
    vi.stubGlobal("fetch", network);
    await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.current().stopReason).toBe("observer_paused");
    expect(f.current().usage.agentTurns).toBe(0);
    expect(f.saved().status).toBe("paused");
    expect(network).toHaveBeenCalledTimes(1);
  });

  it("uses the same gate from the background start entry", async () => {
    const f = fixture(); f.seed();
    const network = vi.fn().mockResolvedValue(response(finish)); vi.stubGlobal("fetch", network);
    expect(f.desk.startProjectBlackboxAgents(f.pid, f.sid)).toMatchObject({ ok: true, started: true });
    await vi.waitFor(() => expect(f.current().stopReason).toBe("blocked"));
    expect(f.saved().status).toBe("paused");
    expect(f.current().supervision!.terminalReviewVersion).toBeTruthy();
    expect(network).toHaveBeenCalledTimes(1);
  });
});

describe("Observer semantic identity", () => {
  it.each(["task", "evidence-reference", "blocking-error", "advice", "finding"])("changes review identity for %s", field => {
    const state = new BlackboxProgress().state;
    state.tasks.t = { status: "pending", evidence_ids: ["ev-1"] };
    state.advice = { a: { tasks: [], status: "pending" } };
    state.transitionErrors = [];
    state.findings = { f: { id: "f", title: "fixture", type: "exposure", target: "http://127.0.0.1:1/", description: "fixture", impact: "unknown", severity: "low", reproduction_steps: ["fixture"], evidence_ids: ["ev-1"], remediation: "review", confidence: "low", status: "candidate" } };
    const before = observerStateVersion(state);
    if (field === "task") state.tasks.t = { status: "blocked", reason: "boundary" };
    if (field === "evidence-reference") state.tasks.t.evidence_ids = ["ev-2"];
    if (field === "blocking-error") state.transitionErrors = ["invalid_advice_decision:a"];
    if (field === "advice") state.advice = { a: { tasks: [], status: "rejected", reason: "boundary" } };
    if (field === "finding") state.findings.f.status = "needs_evidence";
    expect(observerStateVersion(state)).not.toBe(before);
  });
  it("includes execution facts, ignores projections and evidence ordering", () => {
    const state = new BlackboxProgress().state;
    const evidence = [{ id: "ev-1", kind: "tool-result", source: "fixture", data: { ok: true, task_id: "t" } }];
    const before = observerStateVersion(state, evidence);
    expect(observerStateVersion(state, [{ ...evidence[0], data: { ok: false, task_id: "t" } }])).not.toBe(before);
    expect(observerStateVersion(state, [{ ...evidence[0], summary: "changed review input" }])).not.toBe(before);
    expect(observerStateVersion(state, [{ ...evidence[0], confidence: "low" }])).not.toBe(before);
    expect(observerStateVersion(state, [...evidence, { id: "audit", kind: "observer-review", source: "observer", data: {} }])).toBe(before);
    const two = [...evidence, { id: "ev-2", kind: "checkpoint-recovery", source: "operator", data: {} }];
    expect(observerStateVersion(state, two)).toBe(observerStateVersion(state, [...two].reverse()));
  });
  it.each(["usage", "stopReason", "supervision"])("excludes %s changes from review identity", field => {
    const state = new BlackboxProgress().state; const before = observerStateVersion(state);
    if (field === "usage") state.usage.tokens = 999;
    if (field === "stopReason") state.stopReason = "budget";
    if (field === "supervision") state.supervision = { observerRuns: 7, reviewPending: true, terminalReviewVersion: "old" };
    expect(observerStateVersion(state)).toBe(before);
  });
  it("treats blocking errors as a set for review identity", () => {
    const a = { code: "A", path: "tasks.a" }, b = { code: "B", path: "tasks.b" };
    expect(observerReviewId("validation_failed", "v1", [a, b])).toBe(observerReviewId("validation_failed", "v1", [b, a, a]));
    expect(observerReviewId("validation_failed", "v2", [a, b])).not.toBe(observerReviewId("validation_failed", "v1", [a, b]));
  });

  it("语义版本忽略调度计数器 / 时间戳 / 插话 / 假设池 LRU 账", () => {
    const state = new BlackboxProgress().state;
    state.tasks.T = { status: "pending" };
    state.graph = graphState(undefined);
    const before = observerStateVersion(state);
    expect(before.startsWith(OBSERVER_VERSION_PREFIX)).toBe(true);
    const bag = state as unknown as Record<string, unknown>;
    bag.graphRound = 9;
    bag.interrupts = [{ id: "i1", kind: "advice", severity: "high", text: "x", at: Date.now() }];
    bag.seenResults = ["a", "b", "c"];
    bag.actions = { a: { attempts: 9, failures: 2, unchanged: 1 } };
    bag.hypothesisRefresh = { checked: 12, skipped: 3, ran: 9, ranMs: 321 };
    bag.outcomeAutoRepairs = [{ at: Date.now(), task_id: "T", ids: ["ev-1"], matched: true, basis: "x", seq: 1 }];
    bag.task_starvation = { rounds: 31, last_dispatch_at: Date.now() };
    bag.focus_usage = { turns: 29, no_progress_rounds: 4 };
    bag.auth_wall = { tripped_at: Date.now(), bypasses: 3 };
    (state.graph as unknown as Record<string, unknown>).seenHypothesisIds = ["idor:1", "idor:2"];
    expect(observerStateVersion(state)).toBe(before);
  });

  it("pending ↔ running 不算结论变化，落到终态才算", () => {
    const state = new BlackboxProgress().state;
    state.tasks.T = { status: "pending", evidence_ids: ["ev-1"] };
    const before = observerStateVersion(state);
    state.tasks.T.status = "running";
    expect(observerStateVersion(state)).toBe(before);
    state.tasks.T.status = "completed";
    expect(observerStateVersion(state)).not.toBe(before);
  });

  it("执行事实变化仍会改版本（证据内容 / 种子结论 / 图节点状态），防漏审", () => {
    const state = new BlackboxProgress().state;
    state.tasks.T = { status: "pending" };
    const evidence = [{ id: "ev-1", kind: "tool-result", data: { status: 200 } }];
    const before = observerStateVersion(state, evidence);
    expect(observerStateVersion(state, [{ ...evidence[0], data: { status: 403 } }])).not.toBe(before);
    state.seed_health = { "a.test": { verdict: "healthy", seeded: 200, anonymous: 200 } };
    const afterSeed = observerStateVersion(state, evidence);
    expect(afterSeed).not.toBe(before);
    state.seed_health["a.test"].verdict = "seed_tainted";
    expect(observerStateVersion(state, evidence)).not.toBe(afterSeed);
    const graph = graphState(undefined);
    graph.nodes["ep:/x"] = { id: "ep:/x", type: "endpoint", status: "untested", origin: "request", properties: {} } as never;
    state.graph = graph;
    const afterGraph = observerStateVersion(state, evidence);
    expect(afterGraph).not.toBe(afterSeed);
    (graph.nodes["ep:/x"] as unknown as { status: string }).status = "vulnerable";
    expect(observerStateVersion(state, evidence)).not.toBe(afterGraph);
  });

  it("兼容存量会话的旧 state_version，状态变化后两套都不再匹配", () => {
    const state = new BlackboxProgress().state;
    state.tasks.T = { status: "pending" };
    const legacy = legacyObserverStateVersion(state);
    const current = observerStateVersion(state);
    expect(observerStateVersionMatches(legacy, state)).toBe(true);
    expect(observerStateVersionMatches(current, state)).toBe(true);
    expect(observerStateVersionMatches("sv2-bogus", state)).toBe(false);
    expect(observerStateVersionMatches(undefined, state)).toBe(false);
    state.tasks.T.status = "completed";
    expect(observerStateVersionMatches(legacy, state)).toBe(false);
    expect(observerStateVersionMatches(current, state)).toBe(false);
  });
});

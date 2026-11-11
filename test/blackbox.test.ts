import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { proxyEndpoint } from "../src/blackbox/environment.js";
import { runBlackboxAgents } from "../src/blackbox/agent.js";
import { executeAndRecordBlackboxTool } from "../src/blackbox/tools.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import type { Config } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { Desk } from "../src/control/console/desk.js";
import { createProject } from "../src/control/console/workspace.js";

const dirs: string[] = [];
const databases: Database[] = [];

function trackDatabase(db: Database): Database {
  databases.push(db);
  return db;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  for (const db of databases.splice(0)) db.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("blackbox sessions", () => {
  it("persists session events, environment state and evidence", () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-"));
    dirs.push(dir);
    const db = trackDatabase(new Database(join(dir, "nianyun.db")));
    const candidate = importAssetCandidates(db, "p_src", [{ value: "https://app.example.com/login", source: "test" }]).accepted[0]!;
    const session = db.createBlackboxSession("p_src", String(candidate.id), String(candidate.url));

    db.updateBlackboxSession("p_src", String(session.id), {
      status: "ready",
      environment: { ready: true, burp: { reachable: true, proxy_url: "http://127.0.0.1:8080" } },
    });
    db.addBlackboxEvent("p_src", String(session.id), "operator", "instruction", "只执行低影响检查");
    db.addBlackboxEvidence("p_src", String(session.id), {
      kind: "environment", source: "nianyun", summary: "Burp proxy reachable", confidence: "high",
    });

    const saved = db.getBlackboxSession("p_src", String(session.id));
    expect(saved).toMatchObject({ status: "ready", target: "https://app.example.com/login", environment: { ready: true } });
    expect(saved?.events).toHaveLength(2);
    expect(saved?.evidence).toHaveLength(1);
    expect(db.listBlackboxSessions("p_src")).toHaveLength(1);
    db.updateBlackboxSession("p_src", String(session.id), { status: "running", checkpoint: { version: 1, marker: "kept" } });
    db.recoverBlackboxSessions();
    expect(db.getBlackboxSession("p_src", String(session.id))).toMatchObject({ status: "paused", phase: "interrupted", checkpoint: { marker: "kept" } });
  });

  it("normalizes Docker and native Burp proxy endpoints", () => {
    expect(proxyEndpoint("host.docker.internal:8080")).toEqual({ host: "host.docker.internal", port: 8080, url: "http://host.docker.internal:8080" });
    expect(proxyEndpoint("http://127.0.0.1:8080")).toEqual({ host: "127.0.0.1", port: 8080, url: "http://127.0.0.1:8080" });
    expect(() => proxyEndpoint("ftp://127.0.0.1:21")).toThrow("http or https");
  });

  it("runs one contextual main Agent turn followed by a read-only Observer turn", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json({ choices: [{ message: { content: JSON.stringify({ summary: "review login", hypotheses: [], next_actions: ["inspect traffic"], tool_requests: [] }) } }] }))
      .mockResolvedValueOnce(Response.json({ choices: [{ message: { content: JSON.stringify({ review: "plan is bounded", concerns: [], suggestions: [], evidence_gaps: [], should_continue: true }) } }] }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxAgents({
      BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1",
      BLACKBOX_AGENT_MODEL: "test-model",
      BLACKBOX_AGENT_API_KEY: "secret",
    }, { id: "bb-1", target: "https://app.example.com", status: "ready", phase: "analysis", events: [], evidence: [] }, { id: "asset-1", url: "https://app.example.com" });
    expect(result.main.summary).toBe("review login");
    expect(result.observer.review).toBe("plan is bounded");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const observerBody = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body));
    expect(observerBody.messages[1].content).toContain("review login");
  });

  it("executes a bounded local HTTP tool and records request and result evidence", async () => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json", "x-powered-by": "vitest" });
        res.end(JSON.stringify({
          path: req.url, method: req.method, body: Buffer.concat(chunks).toString("utf8"),
          authorization: req.headers.authorization, cookie: req.headers.cookie,
        }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("test server did not bind");
      const target = `http://127.0.0.1:${address.port}/start`;
      const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-tools-"));
      dirs.push(dir);
      const db = trackDatabase(new Database(join(dir, "nianyun.db")));
      const candidate = importAssetCandidates(db, "p_tools", [{ value: target, source: "test" }]).accepted[0]!;
      const session = db.createBlackboxSession("p_tools", String(candidate.id), target);
      const result = await executeAndRecordBlackboxTool({
        cfg: { data_dir: dir, execution: { mode: "execute", source: "config" } } as Config,
        db, projectId: "p_tools", sessionId: String(session.id), target, values: { BURP_PROXY_REQUIRED: "false" },
      }, { tool: "http.request", reason: "inspect local fixture", input: { url: `http://127.0.0.1:${address.port}/api`, method: "GET" } });

      expect(result.ok).toBe(true);
      expect(result.data).toMatchObject({ status: 200, method: "GET" });
      expect(String(result.data.body)).toContain('"path":"/api"');
      const post = await executeAndRecordBlackboxTool({
        cfg: { data_dir: dir, execution: { mode: "execute", source: "config" } } as Config,
        db, projectId: "p_tools", sessionId: String(session.id), target, values: { BURP_PROXY_REQUIRED: "false" },
      }, {
        tool: "http.request", reason: "authenticated POST fixture",
        input: {
          url: `http://127.0.0.1:${address.port}/api/login`, method: "POST",
          headers: { Authorization: "Bearer fixture", Cookie: "sid=fixture; theme=dark" },
          json: { username: "alice", password: "secret" },
        },
      });
      expect(post.ok).toBe(true);
      expect(post.data).toMatchObject({ status: 200, method: "POST" });
      const echoed = JSON.parse(String(post.data.body)) as Record<string, string>;
      expect(echoed.body).toContain('"username":"alice"');
      expect(echoed.authorization).toBe("Bearer fixture");
      expect(echoed.cookie).toContain("sid=fixture");
      const requestEvidence = (db.getBlackboxSession("p_tools", String(session.id))?.evidence || [])
        .find((item: Record<string, unknown>) => item.kind === "tool-request" && String(item.summary).includes("POST")) as Record<string, unknown> | undefined;
      expect(JSON.stringify(requestEvidence?.data)).not.toContain("Bearer fixture");
      expect(JSON.stringify(requestEvidence?.data)).not.toContain("secret");
      const saved = db.getBlackboxSession("p_tools", String(session.id));
      expect(saved?.evidence?.map((item) => item.kind)).toEqual(expect.arrayContaining(["tool-request", "tool-result"]));
      expect(saved?.events?.map((item) => item.kind)).toEqual(expect.arrayContaining(["tool-request", "tool-result"]));
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("normalizes common Agent tool aliases before execution", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-alias-"));
    dirs.push(dir);
    const db = trackDatabase(new Database(join(dir, "nianyun.db")));
    const target = "http://127.0.0.1:1";
    const candidate = importAssetCandidates(db, "p_alias", [{ value: target, source: "test" }]).accepted[0]!;
    const session = db.createBlackboxSession("p_alias", String(candidate.id), target);
    const result = await executeAndRecordBlackboxTool({
      cfg: { data_dir: dir, execution: { mode: "execute", source: "config" } } as Config,
      db, projectId: "p_alias", sessionId: String(session.id), target, values: { BURP_PROXY_REQUIRED: "false" },
    }, { name: "http", reason: "alias test", input: { url: target, method: "GET" } } as BlackboxToolRequest & { name: string });
    expect(result.tool).toBe("http.request");
    expect(result.summary).not.toContain("unsupported blackbox tool");
  });

  it("rejects methods outside the rule whitelist and records errors", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-policy-"));
    dirs.push(dir);
    const db = trackDatabase(new Database(join(dir, "nianyun.db")));
    const target = "https://app.example.test";
    const candidate = importAssetCandidates(db, "p_policy", [{ value: target, source: "test" }]).accepted[0]!;
    const session = db.createBlackboxSession("p_policy", String(candidate.id), target);
    const ctx = {
      cfg: { data_dir: dir, execution: { mode: "execute", source: "config" } } as Config,
      db, projectId: "p_policy", sessionId: String(session.id), target, values: { BURP_PROXY_REQUIRED: "false" },
    };
    const trace = await executeAndRecordBlackboxTool(ctx, { tool: "http.request", input: { method: "TRACE" } });
    expect(trace.ok).toBe(false);
    expect(trace.summary).toContain("HTTP method TRACE is not allowed by the active rules");
    const saved = db.getBlackboxSession("p_policy", String(session.id));
    expect(saved?.evidence?.filter((item) => item.kind === "tool-error")).toHaveLength(1);
  });

  it.each(["duplicate", "premature", "resume", "stage"])("persists checkpoints and stops safely: %s", async (scenario) => {
    const hits: string[] = [];
    const server = createServer((req, res) => {
      hits.push(req.url || "");
      if (scenario === "stage") setTimeout(() => res.end("late"), 1500);
      else res.end("same content");
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("server did not bind");
      const target = `http://127.0.0.1:${address.port}/`;
      const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-checkpoint-"));
      dirs.push(dir);
      writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
      const cfg = loadConfig(join(dir, "config.yaml"), dir);
      cfg.execution = { mode: "execute", source: "config" };
      Object.assign(cfg.tools_env.values, {
        BLACKBOX_RULES_DOCUMENT: JSON.stringify({ budgets: { time_sec: 0, tool_calls: scenario === "resume" ? 1 : 0, agent_turns: 0, retries: 0 }, loop_control: { stage_timeout_sec: scenario === "stage" ? 1 : 180, stage_rollover_limit: 0 } }),
        BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret",
        BURP_PROXY_REQUIRED: "false",
      });
      const db = trackDatabase(new Database(join(dir, "data", "nianyun.db")));
      const projectId = String(createProject(cfg, "Checkpoint", "test").id);
      const candidate = importAssetCandidates(db, projectId, [{ value: target, source: "test" }]).accepted[0]!;
      const sessionId = String(db.createBlackboxSession(projectId, String(candidate.id), target).id);
      db.updateBlackboxSession(projectId, sessionId, { status: "ready", environment: { ready: true } });
      let turns = 0;
      let recoveredContext: Record<string, unknown> = {};
      vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body || "{}"));
        const context = JSON.parse(body.messages.at(-1).content);
        if (context.main_agent_output) return Response.json({ choices: [{ message: { content: JSON.stringify({ review: "review", supplemental_tasks: [], should_continue: true }) } }] });
        turns += 1;
        if (turns === 2) recoveredContext = context.checkpoint;
        const output = scenario === "resume" ? {
          summary: "progress", required_tasks: ["first", "second"],
          completed_tasks: turns >= 3 ? ["first", "second"] : turns === 2 ? ["first"] : [],
          tool_requests: turns >= 3 ? [] : [{ tool: "http.request", task_id: turns === 1 ? "first" : "second", input: { url: `${target}${turns === 1 ? "first" : "second"}` } }],
        } : {
          summary: "still checking", required_tasks: ["inspect"], completed_tasks: [], continue: scenario !== "premature",
          tool_requests: scenario === "premature" ? [] : [{ tool: "http.request", task_id: "inspect", reason: `attempt ${turns}`, input: { url: target } }],
        };
        return Response.json({ choices: [{ message: { content: JSON.stringify(output) } }], usage: { prompt_tokens: 10, completion_tokens: 5 } });
      }));
      const desk = new Desk(cfg, db);
      await desk.runProjectBlackboxAgents(projectId, sessionId);
      let saved = db.getBlackboxSession(projectId, sessionId)!;
      const checkpoint = saved.checkpoint as { stopReason: string; usage: { toolCalls: number }; tasks: Record<string, { status: string }> };
      expect(saved.status).toBe("paused");
      if (scenario === "resume") {
        expect(checkpoint.stopReason).toBe("tool_budget_exhausted");
        expect(hits).toEqual(["/first"]);
        cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { time_sec: 0, tool_calls: 0, agent_turns: 0, retries: 0 } });
        const reopened = trackDatabase(new Database(join(dir, "data", "nianyun.db")));
        await new Desk(cfg, reopened).runProjectBlackboxAgents(projectId, sessionId);
        saved = reopened.getBlackboxSession(projectId, sessionId)!;
        expect(saved.status).toBe("completed");
        expect(hits).toEqual(["/first", "/second"]);
        expect((recoveredContext.usage as { toolCalls: number }).toolCalls).toBe(1);
        expect((saved.checkpoint as typeof checkpoint).usage.toolCalls).toBe(2);
      } else if (scenario === "stage") {
        expect(checkpoint.stopReason).toBe("stage_timeout");
        expect(checkpoint.usage.toolCalls).toBe(1);
        // A stage deadline is not a tool failure: no retry is consumed and the task stays open.
        expect((checkpoint.usage as { retries: number }).retries).toBe(0);
        expect(checkpoint.tasks.inspect?.status).toBe("pending");
        const stageEvidence = (saved.evidence as Array<{ kind: string; data?: Record<string, unknown> }>);
        expect(stageEvidence.some(item => item.kind === "tool-error" && item.data?.timed_out === true)).toBe(true);
        const stageEvents = saved.events as Array<{ kind: string; data?: Record<string, unknown> }>;
        expect(stageEvents.some(event => event.kind === "tool-timeout")).toBe(true);
      } else {
        expect(checkpoint.stopReason).toBe("stalled");
        expect(turns).toBeLessThanOrEqual(7);
        expect(checkpoint.usage.toolCalls).toBe(scenario === "premature" ? 0 : 3);
        expect(checkpoint.tasks.inspect?.status).toBe(scenario === "duplicate" ? "blocked" : "pending");
      }
      expect((saved.evidence as Array<{ kind: string }>).some(item => item.kind === "run-summary")).toBe(true);
    } finally { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
  });

  it("continues beyond the former six-call limit until required tasks complete", async () => {
    const server = createServer((_req, res) => { res.writeHead(200); res.end("ok"); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("test server did not bind");
      const target = `http://127.0.0.1:${address.port}/`;
      const dir = mkdtempSync(join(tmpdir(), "nianyun-blackbox-dynamic-"));
      dirs.push(dir);
      mkdirSync(join(dir, "data"), { recursive: true });
      writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
      const cfg = loadConfig(join(dir, "config.yaml"), dir);
      cfg.execution = { mode: "execute", source: "config" };
      Object.assign(cfg.tools_env.values, {
        BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret",
        BLACKBOX_TOOL_BUDGET: "20", BLACKBOX_AGENT_TURN_BUDGET: "20", BLACKBOX_RETRY_BUDGET: "3", BURP_PROXY_REQUIRED: "false",
      });
      const db = trackDatabase(new Database(join(dir, "data", "nianyun.db")));
      const project = createProject(cfg, "Dynamic blackbox", "test");
      const projectId = String(project.id);
      const candidate = importAssetCandidates(db, projectId, [{ value: target, source: "test" }]).accepted[0]!;
      const session = db.createBlackboxSession(projectId, String(candidate.id), target);
      db.updateBlackboxSession(projectId, String(session.id), { status: "ready", environment: { ready: true } });
      const oldEvidence = db.addBlackboxEvidence(projectId, String(session.id), { kind: "tool-result", source: "http.request", summary: "old response", data: { task_id: "historical", url: target, ok: true } })!;
      for (let n = 0; n < 110; n++) db.addBlackboxEvidence(projectId, String(session.id), { kind: "agent-analysis", source: "test", summary: `filler ${n}` });
      let mainTurns = 0;
      let observed = 0;
      vi.stubGlobal("fetch", vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body || "{}"));
        const context = JSON.parse(body.messages.at(-1).content);
        const isObserver = String(body.messages?.at(-1)?.content || "").includes("main_agent_output");
        if (!isObserver && mainTurns === 1) expect(context.retrieved_evidence.map((e: { id: string }) => e.id)).toContain(oldEvidence.id);
        const adviceIds = Object.keys(context.checkpoint?.advice || {});
        const content = isObserver
          ? { review: "continue", concerns: [], suggestions: ++observed === 1 ? ["review additional endpoint"] : [], supplemental_tasks: [], evidence_gaps: [], should_continue: true }
          : (++mainTurns <= 7
              ? { summary: `task ${mainTurns}`, required_tasks: [{ id: "inspect seven routes", target, purpose: "inspect responses", reason: "coverage", completion_criteria: "read seven route responses" }],
                evidence_queries: mainTurns === 1 ? [{ evidence_id: String(oldEvidence.id) }] : [],
                advice_decisions: mainTurns === 2 ? adviceIds.map(id => ({ advice_id: id, accepted: false, reason: "already included in seven routes", task_ids: [] })) : [],
                completed_tasks: [], blocked_tasks: [], continue: true, tool_requests: [{ tool: "http.request", task_id: "inspect seven routes", reason: "inspect", input: { url: `${target}route-${mainTurns}` } }] }
              : { summary: "complete", required_tasks: [], completed_tasks: ["inspect seven routes"],
                task_outcomes: [{ task_id: "inspect seven routes", reason: "examined seven successful responses", evidence_ids: context.evidence.filter((e: { kind: string; data: { task_id?: string } }) => e.kind === "tool-result" && e.data.task_id === "inspect seven routes").map((e: { id: string }) => e.id) }],
                blocked_tasks: [], continue: false, tool_requests: [] });
        return Response.json({ choices: [{ message: { content: JSON.stringify(content) } }], usage: { prompt_tokens: 10, completion_tokens: 5 } });
      }));
      const result = await new Desk(cfg, db).runProjectBlackboxAgents(projectId, String(session.id));
      const saved = result.session as Record<string, unknown>;
      const evidence = saved.evidence as Array<Record<string, unknown>>;
      expect(saved.status).toBe("completed");
      expect(evidence.filter((item) => item.kind === "tool-result")).toHaveLength(8);
      expect((saved.checkpoint as { tasks: Record<string, { status: string }> }).tasks["inspect seven routes"].status).toBe("completed");
      const checkpoint = saved.checkpoint as { advice: Record<string, { status: string }>; endpoints: Record<string, unknown>; planRevision: number };
      // 架构变更：普通（advisory）Observer 审查改为后台守护进程 + System Interrupt，
  // 不再产生需要主 Agent 签收的 pending advice。收尾/证据闸门审查仍是同步的（见 observer_daemon）。
  expect(Object.keys(checkpoint.advice || {})).toHaveLength(0);
  const events = (saved.events || []) as Array<{ kind?: string; type?: string }>;
  expect(events.some(event => event.kind === "review-dispatched" || event.type === "review-dispatched")).toBe(true);
      expect(Object.keys(checkpoint.endpoints)).toHaveLength(8);
      expect(checkpoint.planRevision).toBe(1);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});


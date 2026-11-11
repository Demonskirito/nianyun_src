import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { BLACKBOX_TOOL_NAMES, executeAndRecordBlackboxTool, externalFailureDetail, resolvePipelineSource, runKatana, toolExitAccepted, wpscanAbort, type BlackboxToolRequest } from "../src/blackbox/tools.js";
import { mainSchema } from "../src/blackbox/protocol.js";
import { submitBlackboxMcpTool } from "../src/blackbox/mcp.js";
import { Desk } from "../src/control/console/desk.js";
import { GROUPS } from "../src/control/console/llm-io.js";

const dirs: string[] = [];
const databases: Database[] = [];
const servers: Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await Promise.all(servers.splice(0).map(server => close(server)));
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

async function listen(server: Server): Promise<string> {
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
}
async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
}

function fixture(target = "http://127.0.0.1:1/") {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-tool-access-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" }; // Isolated execution fixture.
  Object.assign(cfg.tools_env.values, { BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "fixture", BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Tool access", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });
  const ctx = { cfg, db, projectId: pid, sessionId: sid, target, values: cfg.tools_env.values };
  return { cfg, db, pid, sid, target, ctx };
}

describe("direct tool access without per-action approval", () => {
  it("accepts every registered tool name without an approval flag", () => {
    const parsed = mainSchema.safeParse({
      summary: "tool coverage",
      tool_requests: BLACKBOX_TOOL_NAMES.map(tool => ({ tool, input: tool === "recon.content_discovery" ? { wordlist: "/approved/words.txt" } : {} })),
    });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.tool_requests.every(request => request.requires_confirmation === false)).toBe(true);
  });

  it("executes a controlled tool directly and reports configuration, not an approval gate", async () => {
    const f = fixture();
    const result = await executeAndRecordBlackboxTool(f.ctx, { tool: "recon.interactsh", reason: "fixture", requires_confirmation: true, input: { action: "start" } });
    expect(result.ok).toBe(false);
    expect(result.summary).toMatch(/INTERACTSH_(URL|CLIENT_PATH)/);
    expect(result.summary).not.toMatch(/approval|tool navigation|disabled/i);
    const session = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((session.checkpoint as { approvals?: unknown }).approvals).toBeUndefined();
    expect((session.events as Array<{ kind: string }>).some(event => event.kind.startsWith("approval"))).toBe(false);
  });

  it("ignores a legacy enabled flag and still runs the tool up to its configuration check", async () => {
    const f = fixture();
    const values = { ...f.ctx.values, BLACKBOX_RULES_DOCUMENT: JSON.stringify({ tools: { "recon.nuclei": { enabled: false } } }) };
    const result = await executeAndRecordBlackboxTool({ ...f.ctx, values }, { tool: "recon.nuclei", reason: "fixture", input: {} });
    expect(result.ok).toBe(false);
    expect(result.summary).toMatch(/NUCLEI_PATH/);
    expect(result.summary).not.toMatch(/disabled by the active rules/);
  });

  it("runs state-changing HTTP and MCP calls immediately and records evidence", async () => {
    const hits: Array<{ method?: string; url?: string }> = [];
    const server = createServer((req, res) => { hits.push({ method: req.method, url: req.url }); res.end("fixture"); });
    const target = await listen(server);
    const f = fixture(target);
    const http = await executeAndRecordBlackboxTool(f.ctx, { tool: "http.request", requires_confirmation: true, reason: "state change", input: { url: `${target}orders`, method: "POST", json: { quantity: 1 } } });
    expect(http.ok).toBe(true);
    const mcp = await submitBlackboxMcpTool(f.ctx, { tool: "http.request", reason: "mcp call", input: { url: `${target}mcp`, method: "GET" } });
    expect(mcp.ok).toBe(true);
    expect(hits).toEqual([{ method: "POST", url: "/orders" }, { method: "GET", url: "/mcp" }]);
    const session = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((session.checkpoint as { approvals?: unknown }).approvals).toBeUndefined();
    expect((session.evidence as Array<{ kind: string }>).filter(item => item.kind === "tool-result")).toHaveLength(2);
  });

  it("rejects model-supplied approval credentials and ignores deprecated flags", () => {
    const request: BlackboxToolRequest = { tool: "http.request", input: { url: "https://app.example.test/" } };
    for (const injected of [{ approval_id: "approval-1" }, { confirmation_granted: true }]) {
      expect(mainSchema.safeParse({ summary: "fixture", tool_requests: [{ ...request, ...injected }] }).success).toBe(false);
    }
    const progress = new BlackboxProgress();
    expect(progress.begin({ ...request, requires_confirmation: true }, "https://app.example.test/", 2, 2).blocked).toBeUndefined();
  });

  it("does not consult legacy approval records on a resumed checkpoint", () => {
    const progress = new BlackboxProgress();
    (progress.state as Record<string, unknown>).approvals = {
      pending: { id: "pending", status: "pending", created_at: 1, request: { tool: "http.request" } },
      rejected: { id: "rejected", status: "rejected", created_at: 1, request: { tool: "http.request" } },
      consumed: { id: "consumed", status: "executed", created_at: 1, request: { tool: "http.request" } },
    };
    const request: BlackboxToolRequest = { tool: "http.request", input: { url: "https://app.example.test/legacy" } };
    expect(progress.begin(request, "https://app.example.test/", 2, 2).blocked).toBeUndefined();
  });

  it("reports credential opt-ins in the checkpoint, the lifecycle event and the tool catalog", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 }, tools: { "recon.nuclei": { allow_credential_attack: true } } });
    let mainCalls = 0;
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? { review: "read-only", should_continue: true } : mainCalls++ === 0
      ? { summary: "probe", required_tasks: ["probe"], tool_requests: [{ tool: "recon.nuclei", task_id: "probe", input: {} }] }
      : { summary: "done" })));
    const desk = new Desk(f.cfg, f.db);
    const result = await desk.runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    expect((saved.checkpoint as { credential_tools?: string[] }).credential_tools).toEqual(["recon.nuclei"]);
    const events = saved.events as Array<{ kind: string; text: string; data?: Record<string, unknown> }>;
    const lifecycle = events.find(event => event.kind === "lifecycle" && event.data?.automatic_tool_execution === true)!;
    expect(lifecycle.data?.credential_tools).toEqual(["recon.nuclei"]);
    expect(lifecycle.text).toContain("本次开启凭据爆破：recon.nuclei");
    expect(events.some(event => event.kind === "rule-warning")).toBe(false);
    const rejection = events.find(event => event.kind === "tool-rejected" && event.data?.billed === false)!;
    expect(rejection.data).toMatchObject({ billed: false, tool: "recon.nuclei" });
    expect((saved.evidence as Array<{ kind: string; source: string; summary: string }>)
      .some(item => item.kind === "tool-error" && item.source === "recon.nuclei" && item.summary.includes("NUCLEI_PATH"))).toBe(true);
    // A refused request never ran: it must not charge the tool-call or retry budget.
    const usage = (saved.checkpoint as { usage: { toolCalls: number; retries: number } }).usage;
    expect(usage.toolCalls).toBe(0);
    expect(usage.retries).toBe(0);
    expect((saved.checkpoint as { tasks: Record<string, { status: string; failures?: number }> }).tasks.probe).toMatchObject({ status: "pending" });
    expect((saved.checkpoint as { tasks: Record<string, { failures?: number }> }).tasks.probe?.failures).toBeUndefined();
    const catalog = desk.systemTools() as { rules: { credential_tools: string[] }; tools: Array<{ id: string; status: string; disabled?: boolean }> };
    expect(catalog.rules.credential_tools).toEqual(["recon.nuclei"]);
    const nuclei = catalog.tools.find(tool => tool.id === "recon.nuclei")!;
    expect(nuclei.disabled).toBeUndefined();
    expect(nuclei.status).toBe("unconfigured");
    expect(catalog.tools.find(tool => tool.id === "http.request")).toMatchObject({ status: "ready" });
  });

  it("surfaces an unparsable rules document in the session timeline instead of silently defaulting", async () => {
    const f = fixture();
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = "{ not json";
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init.body).includes("main_agent_output") ? { review: "read-only", should_continue: true } : { summary: "idle" })));
    const desk = new Desk(f.cfg, f.db);
    await desk.runProjectBlackboxAgents(f.pid, f.sid);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const checkpoint = saved.checkpoint as { credential_tools?: string[]; rule_issues?: string[] };
    expect(checkpoint.credential_tools).toEqual([]);
    expect(checkpoint.rule_issues?.join(" ")).toContain("回退到默认规则");
    const warning = (saved.events as Array<{ kind: string; text: string; data?: Record<string, unknown> }>).find(event => event.kind === "rule-warning")!;
    expect(warning.text).toContain("默认规则");
    expect(String((warning.data as { issues?: string[] }).issues?.join(" "))).toContain("回退到默认规则");
  });

  it("rejects saving an unparsable rules document from the console", () => {
    const f = fixture();
    const desk = new Desk(f.cfg, f.db);
    expect(() => desk.updateSettings({ llm: { BLACKBOX_RULES_DOCUMENT: "{ not json" } })).toThrow(/回退到默认规则/);
    const saved = desk.updateSettings({ llm: { BLACKBOX_RULES_DOCUMENT: JSON.stringify({ tools: { "recon.sql": { allow_credential_attack: true } } }) } }) as { tools: { rules: { credential_tools: string[] } } };
    expect(saved.tools.rules.credential_tools).toEqual(["recon.sql"]);
    expect(f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT).toContain("recon.sql");
  });
});

describe("external tool diagnostics", () => {
  it("quotes stdout when a CLI writes its failure there (katana flag errors)", () => {
    const detail = externalFailureDetail({ stdout: Buffer.from("flag provided but not defined: -duration\n"), stderr: "" });
    expect(detail).toContain("flag provided but not defined");
    expect(externalFailureDetail({ stdout: Buffer.from(""), stderr: "boom\n" })).toBe("boom");
  });

  it("separates a non-WordPress target from a missing wpscan database", () => {
    const notWordPress = wpscanAbort(Buffer.from('{"scan_aborted": "The remote website is up, but does not seem to be running WordPress."}'));
    expect(notWordPress).toMatchObject({ kind: "not_wordpress" });
    const missing = wpscanAbort(Buffer.from('{"scan_aborted": "Update required, you can not run a scan if a database file is missing."}'));
    expect(missing).toMatchObject({ kind: "missing_database" });
    expect(wpscanAbort(Buffer.from("plain text"))).toBeNull();
  });
});

describe("tool execution taxonomy", () => {
  it("reports a killed child process as a timeout instead of a crash", async () => {
    const run = await runKatana(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], 300);
    expect(run.timed_out).toBe(true);
    expect(run.code).not.toBe(0);
  });

  it("keeps stdout captured before the kill", async () => {
    const run = await runKatana(process.execPath, ["-e", "console.log('partial');setTimeout(() => {}, 30000)"], 600);
    expect(run.timed_out).toBe(true);
    expect(run.stdout.toString("utf8")).toContain("partial");
  });

  it("accepts exit code 1 only for tools that use it to mean no findings", () => {
    expect(toolExitAccepted("recon.content_discovery", 1)).toBe(true);
    expect(toolExitAccepted("recon.api_routes", 1)).toBe(true);
    expect(toolExitAccepted("recon.nuclei", 1)).toBe(false);
    expect(toolExitAccepted("recon.sql", 1)).toBe(false);
    expect(toolExitAccepted("recon.nuclei", 0)).toBe(true);
  });

  it("focus lock: only the focused task may issue tool requests in a round", async () => {
    const server = createServer((_req, res) => { res.end("ok"); });
    const target = await listen(server);
    const f = fixture(target);
    // 默认 focus_lock.on=true：一轮只准推进一个任务。这里故意让模型一次打两个任务。
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2 } });
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output") ? { review: "read-only", should_continue: true } : {
      summary: "two tasks at once",
      required_tasks: ["focus_task", "side_task"],
      tool_requests: [
        { tool: "http.request", task_id: "focus_task", input: { url: target } },
        { tool: "http.request", task_id: "side_task", input: { url: `${target}side` } },
      ],
    })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const lockEvents = (saved.events as Array<{ kind: string; text: string; data?: Record<string, unknown> }>).filter(event => event.kind === "focus-lock");
    // 每轮都会复检一次：只要焦点任务还没结案，其它任务的请求一律拒收。
    expect(lockEvents.length).toBeGreaterThanOrEqual(1);
    const last = lockEvents[lockEvents.length - 1]!;
    expect(last.data?.focus_task_id).toBe("focus_task");
    expect(last.text).toContain("焦点锁定在 focus_task");
    const rejected = (last.data?.rejected || []) as Array<{ task_id?: string; reason: string }>;
    expect(rejected.some(item => item.task_id === "side_task")).toBe(true);
    expect(rejected.find(item => item.task_id === "side_task")!.reason).toContain("请先完成它");
    // 被拒的请求不进证据账本：所有 http.request 结果都归属焦点任务
    const evidence = (saved.evidence || []) as Array<{ kind: string; source: string; data?: Record<string, unknown> }>;
    const results = evidence.filter(item => item.kind === "tool-result" && item.source === "http.request");
    expect(results.length).toBeGreaterThanOrEqual(1);
    // 被拒的 side_task 请求根本没执行：工具类证据里不该出现它的 URL
    const toolRows = ((saved.evidence || []) as Array<{ kind: string; data?: Record<string, unknown> }>)
      .filter(item => item.kind === "tool-result" || item.kind === "tool-request" || item.kind === "tool-error");
    expect(toolRows.filter(item => JSON.stringify(item.data || {}).includes("/side"))).toHaveLength(0);
    // 会话在预算耗尽时收口：真打过的 focus_task 会被补一条 blocked 结论（带理由），
    // 焦点随之顺延——所以这里不再断言 focus_task_id 的最终值。
    // 「锁」的证据在上面：焦点事件里有 side_task 被拒，且它的请求从未执行。
    const checkpoint = saved.checkpoint as {
      focus_task_id?: string;
      tasks: Record<string, { status: string; outcome_reason?: string }>;
    };
    expect(checkpoint.tasks.focus_task.status).toBe("blocked");
    expect(checkpoint.tasks.focus_task.outcome_reason).toContain("未结案收口");
    // 反过来：从没打过的任务必须保持 pending。把「没看」写成「不行」是伪造结论。
    expect(checkpoint.tasks.side_task.status).toBe("pending");
  });

  it("focus budget: forces convergence, then blocks the task when the model keeps hammering", async () => {
    const server = createServer((_req, res) => { res.end("ok"); });
    const target = await listen(server);
    const f = fixture(target);
    // 1 轮上限：第 2 轮准入就触发【强制收口】，第 3 轮模型还不收口 → 代码兜底判 blocked
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({
      budgets: { agent_turns: 5 },
      focus_lock: { max_turns_per_task: 1, stall_rounds: 0 },
    });
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output") ? { review: "read-only", should_continue: true } : {
      summary: "keep hammering the same task",
      required_tasks: ["stuck_task", "next_task"],
      tool_requests: [{ tool: "http.request", task_id: "stuck_task", input: { url: `${target}step` } }],
    })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const events = (saved.events as Array<{ kind: string; text: string; data?: Record<string, unknown> }>);
    const convergences = events.filter(event => event.kind === "focus-convergence");
    // 第一次只发指令，第二次兜底判死
    expect(convergences.length).toBeGreaterThanOrEqual(2);
    expect(convergences[0]!.text).toContain("收益递减");
    expect(convergences.some(event => event.data?.forced === true)).toBe(true);
    const forced = convergences.find(event => event.data?.forced === true)!;
    expect(String(forced.text)).toContain("强制收口");
    // 任务真的被判死了，不是嘴上说说
    const checkpoint = saved.checkpoint as {
      tasks: Record<string, { status: string; reason?: string; outcome_code?: string; outcome_reason?: string }>;
      focus_usage?: { task_id: string; turns: number };
      focus_convergence?: unknown;
    };
    expect(checkpoint.tasks.stuck_task?.status).toBe("blocked");
    // 机器码进 outcome_code，人话进 outcome_reason；`reason` 是创建意图，收口不再覆盖它。
    expect(checkpoint.tasks.stuck_task?.outcome_code).toBe("focus_budget_exhausted");
    expect(String(checkpoint.tasks.stuck_task?.outcome_reason || "")).toContain("焦点预算");
    // 收口后控制面会切到下一条任务继续跑（2026-10-31：不再 3 次调用就判 stalled），
    // 所以 focus_convergence 可能落在 next_task 上；关键是 stuck_task 自己不再被计数。
    const convergence = checkpoint.focus_convergence as { task_id?: string } | undefined;
    expect(convergence?.task_id).not.toBe("stuck_task");
    const toolRows = ((saved.evidence || []) as Array<{ kind: string; data?: Record<string, unknown> }>)
      .filter(item => item.kind === "tool-result" && String((item.data as { url?: string })?.url || "").includes("/step"));
    expect(toolRows).toHaveLength(1);
  });

  it("defers the rest of a batch when the stage budget is spent", async () => {
    const server = createServer((_req, res) => { setTimeout(() => res.end("late"), 1500); });
    const target = await listen(server);
    const f = fixture(target);
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 2, time_sec: 0, tool_calls: 0 }, focus_lock: { on: false }, loop_control: { stage_timeout_sec: 1, stage_rollover_limit: 0 } });
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output") ? { review: "read-only", should_continue: true } : {
      summary: "two probes",
      required_tasks: ["first", "second"],
      tool_requests: [
        { tool: "http.request", task_id: "first", input: { url: target } },
        { tool: "http.request", task_id: "second", input: { url: `${target}second` } },
      ],
    })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const deferred = (saved.events as Array<{ kind: string; text: string; data?: Record<string, unknown> }>).filter(event => event.kind === "action-deferred");
    expect(deferred).toHaveLength(1);
    expect(deferred[0]!.data?.task_id).toBe("second");
    expect(deferred[0]!.text).toContain("stage_timeout");
    const checkpoint = saved.checkpoint as { stopReason?: string; usage: { retries: number; toolCalls: number }; tasks: Record<string, { status: string; reason?: string }> };
    expect(checkpoint.stopReason).toBe("stage_timeout");
    expect(checkpoint.usage.toolCalls).toBe(1);
    expect(checkpoint.usage.retries).toBe(0);
    expect(checkpoint.tasks.first?.status).toBe("pending");
    expect(checkpoint.tasks.second).toMatchObject({ status: "pending", reason: "stage_timeout" });
  });

  it("opens a new stage instead of ending the run when rollover is allowed", async () => {
    const server = createServer((_req, res) => { setTimeout(() => res.end("late"), 1500); });
    const target = await listen(server);
    const f = fixture(target);
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ budgets: { agent_turns: 3, time_sec: 0, tool_calls: 0 }, focus_lock: { on: false }, loop_control: { stage_timeout_sec: 1, stage_rollover_limit: 2 } });
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output") ? { review: "read-only", should_continue: true } : {
      summary: "probe",
      required_tasks: ["first"],
      tool_requests: [{ tool: "http.request", task_id: "first", input: { url: target } }],
    })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const events = saved.events as Array<{ kind: string; text: string }>;
    // One slow tool consumed the first stage; the run must keep going rather than stop at once.
    expect(events.some(event => event.kind === "stage-rollover")).toBe(true);
    const checkpoint = saved.checkpoint as { stopReason?: string };
    expect(checkpoint.stopReason).not.toBe("stage_timeout");
  });

  it("keeps the batch running when some requests are malformed, aliased or unlinkable", async () => {
    const server = createServer((_req, res) => { res.writeHead(200); res.end("ok"); });
    const target = await listen(server);
    const f = fixture(target);
    let calls = 0;
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output") ? { review: "read-only", should_continue: true }
      : ++calls === 1 ? {
        summary: "mixed batch",
        required_tasks: ["probe"],
        tool_requests: [
          { tool: "recon.nuclei", task_id: "probe", input: { url: target }, params: { wrong: true } },
          { tool: "sqlmap", task_id: "probe", input: { url: target } },
          { tool: "http.request", task_id: "probe", input: { url: target } },
          { tool: "http.request", task_id: "probe", input: { url: target, params: { rate: 5 } } },
          { tool: "http", task_id: "unknown", input: { url: target } },
        ],
      }
      : { summary: "done" })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const events = saved.events as Array<{ kind: string; data?: Record<string, unknown>; text: string }>;
    // The malformed nuclei request is dropped by item-level validation (extra `params` key).
    const warning = events.find(event => event.kind === "protocol-warning")!;
    expect((warning.data?.dropped as Array<{ field: string; message: string }>)[0]).toMatchObject({ field: "tool_requests" });
      // 2026-10-28 起：message 是结构化摘要（`tool_requests[0]: 多 params`），
      // 具体哪个键不认识由 unknown_keys / dropped_keys 承载，不再靠 zod 原文文案。
      const dropped0 = (warning.data?.dropped as Array<{ message: string; dropped_keys?: string[]; envelope?: { unknown_keys?: string[] } }>)[0]!;
      expect(dropped0.message).toContain("tool_requests[0]");
      expect(dropped0.dropped_keys).toContain("params");
      expect(dropped0.envelope?.unknown_keys).toContain("params");
    // The alias `sqlmap` maps to recon.sql and reaches the executor (rejected: binary not configured).
    const rejectedEvent = events.find(event => event.kind === "tool-rejected" && event.data?.billed === false)!;
    expect(rejectedEvent.data).toMatchObject({ tool: "recon.sql", billed: false });
    // The bare `http` alias is canonicalised, then dropped because its task is unknown.
    const unlinkable = events.find(event => event.kind === "tool-requests-rejected")!;
    expect((unlinkable.data?.rejected as Array<{ tool: string; task_id?: string }>)[0]).toMatchObject({ tool: "http.request", task_id: "unknown" });
    expect(events.some(event => event.kind === "protocol-error")).toBe(false);
    // Exactly one request actually ran, and only that one is billed.
    expect((saved.evidence as Array<{ kind: string; source: string }>).filter(item => item.kind === "tool-result" && item.source === "http.request")).toHaveLength(1);
    const usage = (saved.checkpoint as { usage: { toolCalls: number; retries: number } }).usage;
    expect(usage.toolCalls).toBe(1);
    expect(usage.retries).toBe(0);
    // A built-in tool that was given params it does not support is rejected, not silently ignored.
    const rejectedEvidence = (saved.evidence as Array<{ kind: string; source: string; summary: string; data?: Record<string, unknown> }>)
      .filter(item => item.kind === "tool-error" && item.data?.rejected === true);
    const unsupported = rejectedEvidence.filter(item => item.source === "http.request");
    expect(unsupported).toHaveLength(1);
    expect(unsupported[0]!.summary).toContain("does not accept input.params");
    expect(rejectedEvidence).toHaveLength(2);
    // Health statistics come from the same ledger: one real execution plus two refusals.
    const health = new Desk(f.cfg, f.db).toolHealth({}) as { totals: { executions: number; successes: number; rejections: number }; tools: Array<{ tool: string; executions: number; successes: number; rejections: number; state: string }> };
    expect(health.totals).toMatchObject({ executions: 1, successes: 1, rejections: 2 });
    expect(health.tools.find(tool => tool.tool === "http.request")).toMatchObject({ successes: 1 });
    expect(health.tools.find(tool => tool.tool === "recon.sql")).toMatchObject({ executions: 0, rejections: 1 });
    // The requested window is echoed so the page can label it.
    const day = new Desk(f.cfg, f.db).toolHealth({ windowSeconds: 86400 }) as { window_seconds: number; totals: { executions: number } };
    expect(day.window_seconds).toBe(86400);
    expect(day.totals.executions).toBe(1);
  });

  it("lets the console configure every tool path and raises the output cap", async () => {
    const paths = ["SUBFINDER_PATH", "DNSX_PATH", "GAU_PATH", "NAABU_PATH", "FFUF_PATH", "WAYBACKURLS_PATH", "NIANYUN_WORDLIST_ROOT"];
    expect(GROUPS.blackbox).toEqual(expect.arrayContaining(paths));
    const f = fixture();
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
      bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
      return Response.json({ choices: [{ message: { content: JSON.stringify({ summary: "idle" }) } }] });
    }));
    await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(bodies.length).toBeGreaterThan(0);
    // 默认输出预算 12000：8000 对"思维链 + 结构化 JSON"的模型偏紧，2026-11-02 实测顶格截断
    // 两次（JSON 尾部被切、整轮作废）。显式配置仍然优先，见下一条断言。
    expect(bodies.every(body => body.max_tokens === 12_000)).toBe(true);
    f.cfg.tools_env.values.BLACKBOX_AGENT_MAX_TOKENS = "9000";
    bodies.length = 0;
    await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(bodies.every(body => body.max_tokens === 9000)).toBe(true);
  });

  it("chains a recorded tool artifact into the next tool and pages it", async () => {
    const f = fixture();
    const relative = `blackbox-artifacts/${f.pid}/${f.sid}/crawl.jsonl`;
    mkdirSync(join(f.cfg.data_dir, `blackbox-artifacts/${f.pid}/${f.sid}`), { recursive: true });
    writeFileSync(join(f.cfg.data_dir, relative), [
      JSON.stringify({ url: "https://app.example.test/a" }),
      JSON.stringify({ url: "https://app.example.test/b" }),
    ].join("\n"));
    const result = f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "tool-result", source: "katana.crawl", summary: "crawl", data: { items: [] } });
    f.db.addBlackboxEvidence(f.pid, f.sid, { kind: "artifact", source: "katana.crawl", summary: "tool-output", artifactPath: relative, data: { media_type: "application/x-ndjson", result_evidence_id: result?.id } });
    // The pipeline source resolves to the artifact's full list, not the bounded items array.
    expect(resolvePipelineSource(f.ctx, { tool: "katana.crawl" }).targets)
      .toEqual(["https://app.example.test/a", "https://app.example.test/b"]);
    // The agent can page the artifact past the 2000-line result window.
    const page = await executeAndRecordBlackboxTool(f.ctx, { tool: "evidence.read", input: { tool: "katana.crawl", limit: 2 } });
    expect(page.ok).toBe(true);
    expect(page.data.total_lines).toBe(2);
    expect(String(page.data.lines[1])).toContain("app.example.test/b");
  });
});

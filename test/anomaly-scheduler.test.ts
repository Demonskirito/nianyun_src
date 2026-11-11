import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { Desk } from "../src/control/console/desk.js";

const dirs: string[] = [];
const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  for (const server of servers.splice(0)) await new Promise<void>(resolve => server.close(() => resolve()));
  for (const dir of dirs.splice(0)) { try { await import("node:fs/promises").then(fs => fs.rm(dir, { recursive: true, force: true })); } catch { /* ignore */ } }
});

describe("catch-all responses change the plan", () => {
  it("injects host-header / open-redirect / takeover tasks when three paths share one redirect", async () => {
    const server = createServer((_req, res) => { res.writeHead(302, { location: "https://sso.example.test/login" }); res.end(); });
    servers.push(server);
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const target = `http://127.0.0.1:${address.port}/`;

    const dir = mkdtempSync(join(tmpdir(), "nianyun-anomaly-"));
    dirs.push(dir);
    mkdirSync(join(dir, "data"), { recursive: true });
    writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
    const cfg = loadConfig(join(dir, "config.yaml"), dir);
    cfg.execution = { mode: "execute", source: "config" };
    Object.assign(cfg.tools_env.values, {
      BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret",
      BLACKBOX_TOOL_BUDGET: "8", BLACKBOX_AGENT_TURN_BUDGET: "6", BLACKBOX_RETRY_BUDGET: "3", BURP_PROXY_REQUIRED: "false",
    });
    const db = new Database(join(dir, "data", "nianyun.db"));
    const project = createProject(cfg, "Anomaly blackbox", "test");
    const projectId = String(project.id);
    const candidate = importAssetCandidates(db, projectId, [{ value: target, source: "test" }]).accepted[0]!;
    const session = db.createBlackboxSession(projectId, String(candidate.id), target);
    db.updateBlackboxSession(projectId, String(session.id), { status: "ready", environment: { ready: true } });

    let mainTurns = 0;
    vi.stubGlobal("fetch", vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body || "{}"));
      const isObserver = String(body.messages?.at(-1)?.content || "").includes("main_agent_output");
      const content = isObserver
        ? { review: "continue", concerns: [], suggestions: ["test Host header injection"], supplemental_tasks: [], evidence_gaps: [], finding_reviews: [], decision: "continue" }
        : (++mainTurns === 1
            ? {
                summary: "map three routes",
                hypotheses: [],
                required_tasks: [{ id: "map routes", target, purpose: "map", reason: "coverage", completion_criteria: "three responses" }],
                completed_tasks: [], blocked_tasks: [], failed_tasks: [], task_outcomes: [], advice_decisions: [],
                evidence_queries: [], findings: [], continue: true, next_actions: [],
                tool_requests: ["/a", "/b", "/c"].map(path => ({ tool: "http.request", task_id: "map routes", reason: `probe ${path}`, input: { url: `${target}${path.slice(1)}` } })),
              }
            : { summary: "stop", required_tasks: [], completed_tasks: [], blocked_tasks: [], failed_tasks: [], task_outcomes: [], advice_decisions: [], evidence_queries: [], findings: [], continue: false, next_actions: [], tool_requests: [] });
      return Response.json({ choices: [{ message: { content: JSON.stringify(content) } }], usage: { prompt_tokens: 10, completion_tokens: 5 } });
    }));

    const result = await new Desk(cfg, db).runProjectBlackboxAgents(projectId, String(session.id));
    const saved = result.session as Record<string, unknown>;
    const events = saved.events as Array<{ kind: string; text?: string }>;
    const checkpoint = saved.checkpoint as { tasks: Record<string, { status: string; playbook?: string }>; anomaly_alert?: { kind: string } };

    expect(checkpoint.anomaly_alert?.kind).toBe("catch_all_redirect");
    expect(events.some(event => event.kind === "anomaly-exploit")).toBe(true);
    const ids = Object.keys(checkpoint.tasks);
    expect(ids.some(id => id.startsWith("host_header_injection_"))).toBe(true);
    expect(ids.some(id => id.startsWith("open_redirect_"))).toBe(true);
    expect(ids.some(id => id.startsWith("takeover_check_"))).toBe(true);
    expect(checkpoint.tasks[ids.find(id => id.startsWith("takeover_check_"))!]?.playbook).toBe("cloud_supply");
  }, 40_000);
});
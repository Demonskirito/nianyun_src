import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { executeAndRecordBlackboxTool } from "../src/blackbox/tools.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { loadConfig } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";

const dirs: string[] = [];
const databases: Database[] = [];
const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  databases.splice(0).forEach(db => db.close());
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(target: string) {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-http-diff-"));
  dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, { BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret", BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db"));
  databases.push(db);
  const pid = String(createProject(cfg, "HttpDiff", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid, target };
}

async function listen(handler: Parameters<typeof createServer>[1]) {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

describe("http.diff end to end", () => {
  it("confirms an IDOR-shaped pair and records it as evidence", async () => {
    const base = await listen((req, res) => {
      const who = new URL(req.url || "/", "http://local").searchParams.get("user") || "alice";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ user: who, phone: who === "alice" ? "13800000000" : "13911111111", orders: who === "alice" ? [1, 2] : [7, 8, 9] }));
    });
    const f = fixture(base);
    const controller = new AbortController();
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: controller.signal },
      { tool: "http.diff", task_id: "inspect", reason: "compare own resource with another user id", input: { url: `${base}/api/order?user=alice`, variant: { url: `${base}/api/order?user=bob` } } },
    );
    expect(result.ok).toBe(true);
    const data = result.data as Record<string, unknown>;
    const delta = data.delta as Record<string, unknown>;
    expect(delta.status_changed).toBe(false);
    expect(delta.similarity).toBeLessThan(0.99);
    expect(["different", "same_shape"]).toContain(String(data.verdict));
    expect(String(data.hint)).toContain("越权");
    // The ledger keeps both calls reachable through one evidence row.
    const evidence = (f.db.getBlackboxSession(f.pid, f.sid)?.evidence || []) as Array<{ kind: string; data?: Record<string, unknown> }>;
    const results = evidence.filter(item => item.kind === "tool-result");
    expect(results.some(item => Boolean(item.data?.verdict) && Boolean(item.data?.delta) && item.data?.url === `${base}/api/order?user=alice`)).toBe(true);
  }, 60_000);

  it("reports a guard bypass when the variant turns 403 into 200", async () => {
    const base = await listen((req, res) => {
      const admin = String(req.headers.cookie || "").includes("role=admin");
      if (admin) { res.writeHead(200, { "content-type": "application/json" }); res.end('{"accounts":42}'); return; }
      res.writeHead(403, { "content-type": "text/plain" }); res.end("forbidden");
    });
    const f = fixture(base);
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.diff", task_id: "inspect", input: { url: `${base}/admin`, headers: { Cookie: "role=user" }, variant: { headers: { Cookie: "role=admin" } } } },
    );
    const data = result.data as Record<string, unknown>;
    expect((data.delta as Record<string, unknown>).status_changed).toBe(true);
    expect(String(data.hint)).toContain("bypassed");
    expect(data.auth_only_change).toBe(true);
  }, 60_000);

  // turn 62：时间盲注的端到端证明——同一 body，只有耗时不同，必须判 timing_delta。
  it("confirms a blind injection from timing alone when bodies are identical", async () => {
    const base = await listen((req, res) => {
      const slow = String(req.url || "").includes("sleep");
      const reply = () => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"code":0,"msg":"ok"}'); };
      if (slow) setTimeout(reply, 400); else reply();
    });
    const f = fixture(base);
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.diff", task_id: "inspect", reason: "confirm blind injection via timing", input: { url: `${base}/api/item?id=1`, variant: { url: `${base}/api/item?id=1&sleep=1` }, timing_threshold_ms: 200 } },
    );
    const data = result.data as Record<string, unknown>;
    const timing = data.timing as Record<string, unknown>;
    expect(data.verdict).toBe("timing_delta");
    expect(timing.suspect).toBe(true);
    expect(Number(timing.delta_ms)).toBeGreaterThanOrEqual(200);
    expect(String(data.hint)).toContain("时间盲注");
    expect(String(result.summary)).toContain("时间维度异常");
    const evidence = (f.db.getBlackboxSession(f.pid, f.sid)?.evidence || []) as Array<{ kind: string; data?: Record<string, unknown> }>;
    expect(evidence.some(item => item.kind === "tool-result" && String(item.data?.verdict) === "timing_delta")).toBe(true);
  }, 60_000);
});
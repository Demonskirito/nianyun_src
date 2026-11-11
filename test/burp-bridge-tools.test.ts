import { createServer, type Server } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { executeBlackboxTool, type BlackboxToolContext } from "../src/blackbox/tools.js";

const dirs: string[] = [];
const databases: Database[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => {
    server.closeAllConnections();
    return new Promise<void>(resolve => server.close(() => resolve()));
  }));
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

const TOKEN = "bridge-fixture-token";

type Seen = { path: string; method: string; host: string | null; auth: string | null; headers: string[]; body: string };

/** Fake bridge: records what the client sent and answers with canned shapes. */
async function bridge(): Promise<{ url: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", chunk => chunks.push(chunk as Buffer));
    request.on("end", () => {
      const url = new URL(request.url || "/", "http://127.0.0.1");
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({
        path: url.pathname,
        method: String(request.method),
        host: url.searchParams.get("host"),
        auth: String(request.headers.authorization || ""),
        headers: url.searchParams.getAll("h"),
        body,
      });
      const json = (value: unknown) => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
      };
      switch (url.pathname) {
        case "/proxy/history":
          return json({ ok: true, total: 1, entries: [{ entry_id: "proxy:0123456789abcdef", method: "GET", status: 200, url: "https://app.test/" }] });
        case "/proxy/entry":
          return json({ ok: true, entry_id: "proxy:0123456789abcdef", request: "GET / HTTP/1.1", redacted: true });
        case "/sitemap":
          return json({ ok: true, total: 0, entries: [] });
        case "/issues":
          return json({ ok: true, total: 1, issues: [{ name: "SQL injection", severity: "HIGH" }] });
        case "/ws/history":
          return json({ ok: true, total: 0, entries: [] });
        case "/scope":
          return json({ ok: true, in_scope: true, url: url.searchParams.get("url") });
        case "/intercept":
          return json({ ok: true, enabled: false });
        case "/decoder":
          return json({ ok: true, operation: url.searchParams.get("op"), result: Buffer.from(body).toString("base64") });
        case "/http/send":
          return json({ ok: true, status: 201, elapsed_ms: 12, response_bytes: 4, body_preview: "done", redacted: true });
        case "/http/send_batch": {
          let parsed: Record<string, unknown> = {};
          try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { parsed = {}; }
          return json({ ok: true, sent: Array.isArray(parsed.requests) ? parsed.requests.length : 0 });
        }
        case "/repeater":
        case "/organizer":
          return json({ ok: true, url: url.searchParams.get("url"), method: url.searchParams.get("method") });
        case "/collab/generate":
          return json({ ok: true, payload: "abc123.oastify.test", id: "1" });
        case "/collab/poll":
          return json({ ok: true, total: 0, interactions: [] });
        case "/scan/audit":
          return json({ ok: true, audit_id: "audit-1", mode: url.searchParams.get("mode"), status: "running" });
        case "/scan/status":
          return json({ ok: true, audits: [{ audit_id: "audit-1", status: "running", requests: 3, errors: 0, issue_count: 1, issues: [] }] });
        case "/rules":
          return json({ ok: true, total: 1, rules: [{ id: "rule-1", name: "add-header", enabled: true, hits: 2 }] });
        case "/websocket": {
          let parsed: Record<string, unknown> = {};
          try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { parsed = {}; }
          if (parsed.action === "open") return json({ ok: true, session_id: "ws-1", url: parsed.url, status: "SUCCESS" });
          if (parsed.action === "messages") return json({ ok: true, session_id: "ws-1", total: 1, messages: [{ index: 0, direction: "in", kind: "text", payload: "hello" }] });
          if (parsed.action === "send") return json({ ok: true, session_id: "ws-1", sent: "text", bytes: 5 });
          if (parsed.action === "close") return json({ ok: true, session_id: "ws-1", closed: true });
          return json({ ok: true, total: 0, sessions: [] });
        }
        case "/bchecks":
          return json({ ok: true, status: "LOADED_WITHOUT_ERRORS", errors: [], selected: true });
        case "/info":
          return json({ ok: true, name: "nianyun-burp-bridge", bridge_version: 3, burp_version: "2024.7.3", project: "fixture", intercept: false, task_engine: "RUNNING", capabilities: ["info"] });
        case "/convert": {
          // The real bridge reads op/value from the JSON body, so the fake does the same.
          let parsed: Record<string, unknown> = {};
          try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { parsed = {}; }
          return json({ ok: true, operation: String(parsed.op ?? "base64_encode"), result: Buffer.from(String(parsed.value ?? "")).toString("base64") });
        }
        case "/compare":
          return json({ ok: true, mode: "diff", added: 1, removed: 0, unchanged: 2, hunks: ["+b"] });
        case "/intruder":
          return json({ ok: true, attack_id: "atk-1234", status: "started" });
        case "/intruder/status":
          return json({ ok: true, attack_id: "atk-1234", planned: 4, sent: 4, matched: 1, errors: 0, done: true, hits: [] });
        case "/storage":
          return json({ ok: true, keys: ["note"], key: url.searchParams.get("key") ?? "", value: "saved" });
        case "/cookies":
          return json({ ok: true, total: 0, cookies: [], values_redacted: true });
        case "/control":
          return json({ ok: true, action: "task_engine", state: "PAUSED" });
        case "/scan/stop":
          return json({ ok: true, audit_id: url.searchParams.get("id"), stopped: true });
        default:
          response.writeHead(404, { "content-type": "application/json" });
          return response.end(JSON.stringify({ ok: false, error: "unknown" }));
      }
    });
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}`, seen };
}

function fixture(bridgeUrl: string) {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-burp-bridge-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "fixture",
    BURP_PROXY_REQUIRED: "false", BURP_BRIDGE_URL: bridgeUrl, BURP_BRIDGE_TOKEN: TOKEN,
  });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const target = "https://app.test/";
  const pid = String(createProject(cfg, "Burp bridge", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  const ctx: BlackboxToolContext = { cfg, db, projectId: pid, sessionId: sid, target, values: cfg.tools_env.values };
  return { cfg, db, pid, sid, ctx };
}

describe("burp bridge tools", () => {
  it("scopes every read to the session target host and sends the bearer token", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const result = await executeBlackboxTool(f.ctx, { tool: "burp.history", input: { limit: 5 } });
    expect(result.ok).toBe(true);
    expect(result.data.entries).toHaveLength(1);
    expect(fake.seen[0]).toMatchObject({ path: "/proxy/history", host: "https://app.test", auth: `Bearer ${TOKEN}` });
  });

  it("rejects a malformed entry id before touching the network", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    await expect(executeBlackboxTool(f.ctx, { tool: "burp.entry", input: { entry_id: "not-an-id" } }))
      .rejects.toThrow(/entry_id must come from/);
    expect(fake.seen).toHaveLength(0);
  });

  it("sends method, headers and body through the Burp HTTP stack", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const result = await executeBlackboxTool(f.ctx, {
      tool: "burp.send",
      input: { method: "post", headers: { "Content-Type": "application/json", "X-Test": "1" }, body: '{"a":1}' },
    });
    expect(result.ok).toBe(true);
    expect(result.summary).toMatch(/Burp sent POST https:\/\/app\.test\/ → 201/);
    const seen = fake.seen[0]!;
    expect(seen.path).toBe("/http/send");
    expect(seen.method).toBe("POST");
    expect(seen.headers).toEqual(["Content-Type: application/json", "X-Test: 1"]);
    expect(seen.body).toBe('{"a":1}');
  });

  it("decodes and encodes through the decoder route", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const result = await executeBlackboxTool(f.ctx, { tool: "burp.decoder", input: { operation: "base64_encode", value: "hi" } });
    expect(result.ok).toBe(true);
    expect(String(result.data.result)).toBe(Buffer.from("hi").toString("base64"));
  });

  it("runs active scans by default and honours an explicit opt-out", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    f.ctx.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({ tools: { "burp.scan": { allow_active_scan: false } } });
    await expect(executeBlackboxTool(f.ctx, { tool: "burp.scan", input: { mode: "active" } }))
      .rejects.toThrow(/allow_active_scan/);
    delete f.ctx.values.BLACKBOX_RULES_DOCUMENT;
    const result = await executeBlackboxTool(f.ctx, { tool: "burp.scan", input: { mode: "active" } });
    expect(result.ok).toBe(true);
    expect(fake.seen.some(item => item.path === "/scan/audit" && item.host === "https://app.test")).toBe(true);
    expect(String(result.data.audit_id)).toBe("audit-1");
  });

  it("reads Burp info and reports the bridge surface", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const result = await executeBlackboxTool(f.ctx, { tool: "burp.info", input: {} });
    expect(result.ok).toBe(true);
    expect(result.summary).toMatch(/Burp 2024\.7\.3/);
    expect(fake.seen[0]!.path).toBe("/info");
  });

  it("converts values through the Burp utility surface", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const result = await executeBlackboxTool(f.ctx, { tool: "burp.convert", input: { op: "base64_encode", value: "hello" } });
    expect(result.ok).toBe(true);
    expect(String(result.data.result)).toBe(Buffer.from("hello").toString("base64"));
    expect(fake.seen[0]!.body).toBe(JSON.stringify({ op: "base64_encode", value: "hello" }));
  });

  it("drives an Intruder-style attack and reads its status", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const started = await executeBlackboxTool(f.ctx, {
      tool: "burp.intruder",
      input: { action: "run", url: "https://app.test/login", type: "sniper", template: "POST /login HTTP/1.1\nHost: app.test\n\nuser=\u00a7admin\u00a7", payloads: ["admin", "root"] },
    });
    expect(started.ok).toBe(true);
    expect(String(started.data.attack_id)).toBe("atk-1234");
    const status = await executeBlackboxTool(f.ctx, { tool: "burp.intruder", input: { action: "status", attack_id: "atk-1234" } });
    expect(status.summary).toMatch(/4\/4 sent/);
  });

  it("refuses an attack template without markers but allows a cross-host batch entry", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    await expect(executeBlackboxTool(f.ctx, { tool: "burp.intruder", input: { template: "GET / HTTP/1.1" } }))
      .rejects.toThrow(/marker/);
    // 2026-11-03 scope 解除：跨域批量子请求（跨主机 pivot）必须放行。
    const batch = await executeBlackboxTool(f.ctx, { tool: "burp.send_batch", input: { requests: [{ url: "https://other.test/" }] } });
    expect(batch.ok).toBe(true);
    expect(batch.summary).toMatch(/1 requests/);
  });

  it("manages rewrite rules and previews them without sending", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const listed = await executeBlackboxTool(f.ctx, { tool: "burp.proxy_rule", input: {} });
    expect(listed.summary).toMatch(/1 rewrite rules/);
    expect(fake.seen[0]!.body).toBe(JSON.stringify({ action: "list" }));
    const tested = await executeBlackboxTool(f.ctx, { tool: "burp.proxy_rule", input: { action: "test", url: "https://app.test/a", body: "x" } });
    expect(tested.summary).toMatch(/rule test/);
    // 2026-11-03 scope 解除：允许对任意 host（含跨域 API 宿主）下发 rewrite 规则。
    const added = await executeBlackboxTool(f.ctx, { tool: "burp.proxy_rule", input: { action: "add", url_regex: "https://other\\.test/.*" } });
    expect(added.ok).toBe(true);
  });

  it("opens a websocket, sends a frame and reads frames back", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const opened = await executeBlackboxTool(f.ctx, { tool: "burp.websocket", input: { action: "open", url: "ws://app.test/socket" } });
    expect(opened.summary).toMatch(/websocket open ws-1/);
    const sent = JSON.parse(fake.seen[0]!.body) as Record<string, unknown>;
    expect(sent.url).toBe("ws://app.test/socket");
    // Without an explicit url the scheme follows the session target (https -> wss).
    await executeBlackboxTool(f.ctx, { tool: "burp.websocket", input: { action: "open" } });
    const derived = JSON.parse(fake.seen[fake.seen.length - 1]!.body) as Record<string, unknown>;
    expect(derived.url).toBe("wss://app.test/");
    const frames = await executeBlackboxTool(f.ctx, { tool: "burp.websocket", input: { action: "messages", session_id: "ws-1" } });
    expect(frames.summary).toMatch(/1 new frames/);
    // 2026-11-03 scope 解除：跨域 WebSocket 握手也放行。
    const cross = await executeBlackboxTool(f.ctx, { tool: "burp.websocket", input: { action: "open", url: "wss://other.test/socket" } });
    expect(cross.ok).toBe(true);
  });

  it("imports a bcheck and forwards race settings to the attack engine", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const imported = await executeBlackboxTool(f.ctx, { tool: "burp.bchecks", input: { bcheck: '{"metadata":{"name":"x"}}' } });
    expect(imported.summary).toMatch(/LOADED_WITHOUT_ERRORS/);
    await expect(executeBlackboxTool(f.ctx, { tool: "burp.bchecks", input: {} })).rejects.toThrow(/bcheck is required/);
    await executeBlackboxTool(f.ctx, {
      tool: "burp.intruder",
      input: { template: "GET /?a=\u00a7p\u00a7 HTTP/1.1\nHost: app.test\n\n", payloads: ["1"], race: true, threads: 8, extract: [{ name: "title", regex: "<title>(.*?)</title>" }] },
    });
    const attackBody = JSON.parse(fake.seen[fake.seen.length - 1]!.body) as Record<string, unknown>;
    expect(attackBody.race).toBe(true);
    expect(attackBody.threads).toBe(8);
    expect(Array.isArray(attackBody.extract)).toBe(true);
  });

  it("polls audit status and stops the audit by id", async () => {
    const fake = await bridge();
    const f = fixture(fake.url);
    const status = await executeBlackboxTool(f.ctx, { tool: "burp.scan_status", input: { audit_id: "audit-1" } });
    expect(status.ok).toBe(true);
    const stop = await executeBlackboxTool(f.ctx, { tool: "burp.scan_stop", input: { audit_id: "audit-1" } });
    expect(stop.ok).toBe(true);
    expect(fake.seen.map(item => item.path)).toEqual(["/scan/status", "/scan/stop"]);
  });
});
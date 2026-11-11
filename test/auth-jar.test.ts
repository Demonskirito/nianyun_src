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

const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4NiJ9.c2lnbmF0dXJlLXZhbHVl";

function fixture(target: string) {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-auth-jar-"));
  dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, { BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret", BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db"));
  databases.push(db);
  const pid = String(createProject(cfg, "AuthJar", "test").id);
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

/** 鉴权接口：只有 Authorization: Bearer <jwt> 才返回业务数据。 */
const guarded = (req: Parameters<Parameters<typeof createServer>[1]>[0], res: Parameters<Parameters<typeof createServer>[1]>[1]) => {
  const auth = String(req.headers.authorization || "");
  if (auth !== `Bearer ${jwt}`) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"code":10403,"msg":"TOKEN 错误","data":null}');
    return;
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end('{"code":0,"data":{"userId":86,"name":"张三"}}');
};

describe("Token 传递：执行器自动带凭证", () => {
  it("sends a top-level token as Authorization: Bearer", async () => {
    const base = await listen(guarded);
    const f = fixture(base);
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.request", task_id: "T1", reason: "auth_token replay with top-level token", input: { method: "GET", url: `${base}/api/user/info`, token: jwt } },
    );
    expect(result.ok).toBe(true);
    const data = result.data as Record<string, unknown>;
    expect(String(data.body)).toContain('"code":0');
    expect(String(result.summary)).toContain("Authorization");
    expect(JSON.stringify((data.auth_applied as string[]) || [])).not.toContain(jwt);
  }, 60_000);

  it("attaches the stored project token when the model passes no credential at all", async () => {
    const base = await listen(guarded);
    const f = fixture(base);
    const host = new URL(base).host;
    expect(f.db.mergeProjectTokens(f.pid, [{ host, value: jwt, source: "browser.open" }])).toBe(1);
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.request", task_id: "T1", reason: "business endpoint after login", input: { method: "GET", url: `${base}/api/user/info` } },
    );
    const data = result.data as Record<string, unknown>;
    expect(String(data.body)).toContain('"code":0');
    expect(JSON.stringify((data.auth_applied as string[]) || [])).toContain("全局 Token 罐命中");
    // 父域后缀匹配：子域请求也能命中同一条 Token
    expect(f.db.getTokenForHost(f.pid, `api.${host}`)?.value).toBe(jwt);
  }, 60_000);

  // 罐子装满后 http.diff 仍必须能打"匿名基线 vs 带凭据变体"，否则未授权证据出不来。
  it("keeps an anonymous baseline in http.diff after the jar is filled", async () => {
    const base = await listen(guarded);
    const f = fixture(base);
    f.db.mergeProjectTokens(f.pid, [{ host: new URL(base).host, value: jwt, source: "browser.open" }]);
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.diff", task_id: "T1", reason: "anonymous vs authed", input: { url: `${base}/api/user/info`, anonymous: true, variant: { token: jwt } } },
    );
    const data = result.data as Record<string, unknown>;
    expect(["same_shape", "different"]).toContain(String(data.verdict));
    const hint = String(data.hint);
    expect(hint.length).toBeGreaterThan(0);
    const similarity = (data.delta as Record<string, number>).similarity;
    expect(similarity).toBeLessThan(0.9);
  }, 60_000);

  it("keeps a 10403 body when the token is wrong, without inventing success", async () => {
    const base = await listen(guarded);
    const f = fixture(base);
    const result = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.request", task_id: "T1", reason: "stale token check", input: { method: "GET", url: `${base}/api/user/info`, token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3cm9uZyJ9.stale" } },
    );
    const data = result.data as Record<string, unknown>;
    expect(String(data.body)).toContain("10403");
    expect((data.auth_applied as string[]).join(" ")).toContain("Authorization");
  }, 60_000);

  // 罐子装满之后，"匿名基线"必须还能发得出去，否则未授权/绕过类证据永远测不了。
  it("lets an anonymous call bypass the jar on purpose", async () => {
    const base = await listen(guarded);
    const f = fixture(base);
    const host = new URL(base).host;
    f.db.mergeProjectTokens(f.pid, [{ host, value: jwt, source: "browser.open" }]);
    f.db.mergeProjectCookies(f.pid, [{ name: "SESSION", value: "abc", domain: "127.0.0.1", path: "/", expires: Date.now() / 1000 + 3600 } as never]);
    const authed = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.request", task_id: "T1", reason: "authed read", input: { method: "GET", url: `${base}/api/user/info` } },
    );
    expect(String((authed.data as Record<string, unknown>).body)).toContain('"code":0');
    const anon = await executeAndRecordBlackboxTool(
      { cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: base, values: f.cfg.tools_env.values, signal: new AbortController().signal },
      { tool: "http.request", task_id: "T2", reason: "anonymous baseline", input: { method: "GET", url: `${base}/api/user/info`, anonymous: true } },
    );
    const anonData = anon.data as Record<string, unknown>;
    expect(String(anonData.body)).toContain("10403");
    expect((anonData.auth_applied as string[]).join(" ")).toContain("anonymous");
    expect(anonData.anonymous).toBeUndefined();
  }, 60_000);
});
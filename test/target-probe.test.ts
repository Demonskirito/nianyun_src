/**
 * 目标可达性前置检查（2026-11-06）。
 *
 * 事故：环境检查只验工具链，目标早已下线也照样开跑。Burp 用自己的错误页顶替每个响应
 * （状态码仍 200），于是"7 条路径同长度"变成 `uniform_body` 异常 → 派发 3 条假任务，
 * browser.open 每次吃 5 分钟，25 分钟预算换来一堆假信号（ce01b328599615a7）。
 *
 * 这里锁三件事：
 *   1. 判决只看代理专有标记与传输层错误，**不看状态码**（403/404 是情报，不是故障）；
 *   2. 命中就判环境不通过（ready=false），会话停在 environment_check；
 *   3. 开关关掉时给 skipped + ready=true，跳过检查不能把会话判死。
 */
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { Desk } from "../src/control/console/desk.js";
import { judgeTargetError, judgeTargetResponse, probeTarget } from "../src/blackbox/target-probe.js";

/** 实拍样本形状：Burp 在目标不可达时回的页面（标题固定，正文自述 Failed to connect）。 */
const BURP_ERROR_PAGE = `<html><head><title>Burp Suite Professional</title></head>
<body><h1>Burp Suite Professional</h1>
<p>Burp Proxy error: Failed to connect to the target server.</p></body></html>`;

const NORMAL_PAGE = `<html><head><title>后台登录</title></head><body><form action="/login"><input name="user"></form></body></html>`;

const servers: ReturnType<typeof createServer>[] = [];
const dirs: string[] = [];
const databases: Database[] = [];

afterEach(async () => {
  databases.splice(0).forEach(db => db.close());
  for (const server of servers.splice(0)) await new Promise<void>(resolve => server.close(() => resolve()));
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

async function serve(body: string, status = 200): Promise<string> {
  const server = createServer((_req, res) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
    res.end(body);
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind");
  return `http://127.0.0.1:${address.port}/`;
}

/** 拿一个刚被释放的端口：用来制造"连不上"。 */
async function deadPort(): Promise<number> {
  const server = createServer(() => {});
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise<void>(resolve => server.close(() => resolve()));
  if (!address || typeof address === "string") throw new Error("test server did not bind");
  return address.port;
}

function fixture(values: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-target-probe-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    // 没有 Burp 的纯直连：环境检查的 ready 只由目标探测决定，正是要测的那条路径。
    BURP_PROXY_REQUIRED: "false",
    BLACKBOX_TARGET_PROBE_TIMEOUT_MS: "3000",
    ...values,
  });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  return { cfg, db };
}

async function checkWith(target: string, values: Record<string, string> = {}, preset: Record<string, unknown> = {}) {
  const { cfg, db } = fixture(values);
  const pid = String(createProject(cfg, "target probe", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  if (Object.keys(preset).length) db.updateBlackboxSession(pid, sid, preset);
  const desk = new Desk(cfg, db);
  const checked = await desk.checkProjectBlackboxEnvironment(pid, sid) as {
    ok: boolean; environment: Record<string, any>; session: Record<string, any>;
  };
  return { checked, db, pid, sid };
}

describe("目标探测的判决", () => {
  it("代理自己的错误页 → 不可达（不能当目标响应）", () => {
    const verdict = judgeTargetResponse({ status: 200, body: BURP_ERROR_PAGE, url: "https://dead.example/" });
    expect(verdict.reachable).toBe(false);
    expect(verdict.code).toBe("proxy_error");
    expect(verdict.proxy_error?.vendor).toBe("burp");
    expect(verdict.reason).toContain("不要带着一个连不上的目标开跑");
  });

  it("正常页面 → 可达", () => {
    const verdict = judgeTargetResponse({ status: 200, body: NORMAL_PAGE });
    expect(verdict).toMatchObject({ reachable: true, code: "reachable" });
  });

  it("403/404 也算可达：目标在说话，那是情报不是故障", () => {
    for (const status of [403, 404, 500, 502]) {
      expect(judgeTargetResponse({ status, body: NORMAL_PAGE })).toMatchObject({ reachable: true, code: "reachable" });
    }
  });

  it("正文里出现 burp 字样但明显是目标自己的页面 → 仍然可达", () => {
    const page = `<html><head><title>招聘：Burp Suite 使用经验</title></head><body>我们招人，要求熟悉 burp suite professional。</body></html>`;
    expect(judgeTargetResponse({ status: 200, body: page }).reachable).toBe(true);
  });

  it("超时 → timeout，连接拒绝 → network_error", () => {
    expect(judgeTargetError(new Error("Timeout 12000ms exceeded."), { url: "https://a.example/", timeoutMs: 12000 }))
      .toMatchObject({ reachable: false, code: "timeout" });
    expect(judgeTargetError(new Error("net::ERR_CONNECTION_REFUSED at http://127.0.0.1:9/"), { url: "http://127.0.0.1:9/" }))
      .toMatchObject({ reachable: false, code: "network_error" });
  });
});

describe("probeTarget", () => {
  it("非 HTTP(S) 目标 → invalid_url，且不发请求", async () => {
    const probe = await probeTarget({ url: "ftp://example.com/pub" });
    expect(probe).toMatchObject({ reachable: false, code: "invalid_url" });
    expect(probe.reason).toContain("HTTP(S)");
  });

  it("空目标 → invalid_url", async () => {
    expect(await probeTarget({ url: "" })).toMatchObject({ reachable: false, code: "invalid_url" });
  });

  it("活目标 → reachable，带上状态码/字节数/是否经代理", async () => {
    const url = await serve(NORMAL_PAGE);
    const probe = await probeTarget({ url, retries: 0, timeoutMs: 3000 });
    expect(probe).toMatchObject({ reachable: true, code: "reachable", status: 200, via_proxy: false });
    expect(probe.bytes).toBeGreaterThan(0);
  });

  it("死目标 → network_error，不落成可达", async () => {
    const port = await deadPort();
    const probe = await probeTarget({ url: `http://127.0.0.1:${port}/`, retries: 0, timeoutMs: 2000 });
    expect(probe.reachable).toBe(false);
    expect(probe.code).toBe("network_error");
  });

  it("BLACKBOX_TARGET_PROBE=off → skipped 且不阻断", async () => {
    const probe = await probeTarget({ url: "https://dead.example/", values: { BLACKBOX_TARGET_PROBE: "off" } });
    expect(probe).toMatchObject({ reachable: true, code: "skipped" });
  });

  it("空字符串的超时配项不能把探测压成 1 秒（Number 空串等于 0 的坑）", async () => {
    // 慢 1.5s 的活目标：如果被误判成 1000ms 超时，这条会挂——正是线上那次的表现
    // （elapsed_ms=1012 报"目标没响应"）。
    const slow = createServer((_req, res) => {
      setTimeout(() => { res.writeHead(200, { "content-type": "text/html" }); res.end(NORMAL_PAGE); }, 1500);
    });
    servers.push(slow);
    await new Promise<void>(resolve => slow.listen(0, "127.0.0.1", resolve));
    const address = slow.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const probe = await probeTarget({
      url: `http://127.0.0.1:${address.port}/`,
      values: { BLACKBOX_TARGET_PROBE_TIMEOUT_MS: "", BLACKBOX_TARGET_PROBE_RETRIES: "" },
    });
    expect(probe).toMatchObject({ reachable: true, code: "reachable", status: 200 });
    expect(probe.elapsed_ms).toBeGreaterThan(1400);
  });
});

describe("环境检查把目标可达性算进 ready", () => {
  it("目标活着 → ready，会话可开跑", async () => {
    const url = await serve(NORMAL_PAGE);
    const { checked } = await checkWith(url);
    expect(checked.environment.ready).toBe(true);
    expect(checked.environment.target).toMatchObject({ reachable: true, code: "reachable" });
    expect(checked.session.status).toBe("ready");
  });

  it("目标回的是代理错误页 → 不 ready，会话停在 environment_check，且不再跑工具探活", async () => {
    const url = await serve(BURP_ERROR_PAGE);
    const { checked } = await checkWith(url);
    expect(checked.environment.ready).toBe(false);
    expect(checked.environment.target).toMatchObject({ reachable: false, code: "proxy_error" });
    expect(checked.session.status).toBe("paused");
    expect(checked.session.phase).toBe("environment_check");
    // 已经判不通过了，就别再花时间跑二进制探活
    expect((checked.session.checkpoint || {}).preflight).toBeUndefined();
  });

  it("时间线里写清「为什么」：是目标不可达，不是 Burp 有问题", async () => {
    const url = await serve(BURP_ERROR_PAGE);
    const { db, pid, sid } = await checkWith(url);
    const session = db.getBlackboxSession(pid, sid) as unknown as { events: Array<{ kind: string; text: string }> };
    const warning = session.events.find(event => event.kind === "warning" && event.text.includes("目标"));
    expect(warning?.text).toContain("目标可达性检查未通过");
    expect(warning?.text).toContain("burp");
  });

  it("关掉开关时不会把会话判死（skipped 不等于失败）", async () => {
    const url = await serve(BURP_ERROR_PAGE);
    const { checked } = await checkWith(url, { BLACKBOX_TARGET_PROBE: "off" });
    expect(checked.environment.target).toMatchObject({ code: "skipped" });
    expect(checked.environment.ready).toBe(true);
  });

  it("已完成会话被复检且目标已死 → 只更新 environment，不把 completed 打回 paused", async () => {
    const url = await serve(BURP_ERROR_PAGE);
    const { checked } = await checkWith(url, {}, { status: "completed", phase: "report" });
    expect(checked.environment.ready).toBe(false);
    expect(checked.session.status).toBe("completed");
    expect(checked.session.phase).toBe("report");
  });
});

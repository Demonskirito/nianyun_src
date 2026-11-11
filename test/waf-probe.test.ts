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
import { Desk } from "../src/control/console/desk.js";

/**
 * 0 产出判墙（"补一枪"）。
 *
 * 场景：ffuf 的 `-ac` 会把整片同款 412 当 catch-all 滤掉，字典结果是"0 发现"。
 * 于是"目标没路径"和"目标整片被墙"在账本里长得一模一样，waf_bypass 与战例库都不会被触发。
 * 现在补两枪根路径，用"拦截码 + 指纹"判定：
 *   - 412/403 且两次 status+bytes+sha 一致 且（阻断字样 / 认出厂商 / 战例库同签名）→ 判墙
 *   - 200 或两次不一致 → 判否，明确告诉模型"这里是真没路径，别再磨字典"
 */
const dirs: string[] = [];
const databases: Database[] = [];
const servers: Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); })));
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

async function listen(server: Server): Promise<string> {
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
}

function fixture(target: string) {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-waf-probe-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, { BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "WAF probe", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });
  return { cfg, db, pid, sid, target };
}

type ProbeRunner = { runWallProbe: (pid: string, sid: string, progress: BlackboxProgress, ctx: Record<string, unknown>) => Promise<void> };

function runProbe(f: ReturnType<typeof fixture>, progress: BlackboxProgress, url: string) {
  const desk = new Desk(f.cfg, f.db) as unknown as ProbeRunner;
  const ctx = {
    cfg: f.cfg, db: f.db, projectId: f.pid, sessionId: f.sid, target: f.target,
    values: f.cfg.tools_env.values, deadline: Date.now() + 30000,
  };
  progress.state.waf_probe = { host: new URL(url).host, url, reason: "recon.content_discovery 0 产出", at: Date.now() };
  return desk.runWallProbe(f.pid, f.sid, progress, ctx);
}

const eventsOf = (db: Database, pid: string, sid: string) =>
  (db.getBlackboxSession(pid, sid)!.events as Array<{ kind: string; text: string; data?: Record<string, unknown> }>);

describe("0 产出补枪判墙", () => {
  it("稳定 412 + 阻断页 → 立 waf_escalation 并派 waf_bypass 任务", async () => {
    const server = createServer((_req, res) => {
      res.statusCode = 412;
      res.end("您的访问被阻断 securityfs");
    });
    const target = await listen(server);
    const f = fixture(target);
    const progress = new BlackboxProgress();
    await runProbe(f, progress, target);

    expect(progress.state.waf_escalation?.host).toBe(new URL(target).host);
    expect(String(progress.state.waf_escalation?.marker)).toContain("412");
    const dispatched = progress.state.linkage?.waf_tasks || [];
    expect(dispatched).toHaveLength(1);
    expect(progress.state.tasks[dispatched[0]!]?.playbook).toBe("waf_bypass");

    const kinds = eventsOf(f.db, f.pid, f.sid).map(event => event.kind);
    expect(kinds).toContain("waf-probe");
    expect(kinds).toContain("waf-escalation");
    // 补过枪的 host 进名单，不会每轮重复补
    expect(progress.state.linkage?.waf_probe_hosts).toContain(new URL(target).host);
    expect(progress.state.waf_probe).toBeUndefined();
  }, 30000);

  it("根路径 200 → 判否，写明\"是没路径不是墙\"，不派任务", async () => {
    const server = createServer((_req, res) => { res.statusCode = 200; res.end("<html>ok</html>"); });
    const target = await listen(server);
    const f = fixture(target);
    const progress = new BlackboxProgress();
    await runProbe(f, progress, target);

    expect(progress.state.waf_escalation).toBeUndefined();
    expect(progress.state.linkage?.waf_tasks).toBeUndefined();
    const negative = eventsOf(f.db, f.pid, f.sid).filter(event => event.kind === "waf-probe-negative");
    expect(negative).toHaveLength(1);
    expect(negative[0]!.text).toContain("没路径");
  }, 30000);

  it("拦截码但两次指纹不一致（抖动）→ 不判墙", async () => {
    let hits = 0;
    const server = createServer((_req, res) => {
      hits += 1;
      res.statusCode = 503;
      res.end(`busy-${hits}-${"x".repeat(20)}`);
    });
    const target = await listen(server);
    const f = fixture(target);
    const progress = new BlackboxProgress();
    await runProbe(f, progress, target);

    expect(progress.state.waf_escalation).toBeUndefined();
    const negative = eventsOf(f.db, f.pid, f.sid).filter(event => event.kind === "waf-probe-negative");
    expect(negative).toHaveLength(1);
    expect(negative[0]!.data?.stable).toBe(false);
  }, 30000);
it("302 跳人机校验 → 判挑战（不派任务、也不说\"没路径\"）", async () => {
    const server = createServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader("location", "/cdn-cgi/challenge-platform/verify");
      res.end("");
    });
    const target = await listen(server);
    const f = fixture(target);
    const progress = new BlackboxProgress();
    await runProbe(f, progress, target);

    expect(progress.state.waf_escalation).toBeUndefined();
    const kinds = eventsOf(f.db, f.pid, f.sid).map(event => event.kind);
    expect(kinds).toContain("waf-probe-challenge");
    expect(kinds).not.toContain("waf-probe-negative");
  }, 30000);
});

describe("补枪登记的节流", () => {
  it("同 host 只登记一次，整场最多 3 次", () => {
    const progress = new BlackboxProgress();
    expect(progress.requestWallProbe("a.example", "https://a.example/", "0 产出")).toBe(true);
    progress.consumeWallProbe();
    expect(progress.requestWallProbe("a.example", "https://a.example/", "0 产出")).toBe(false);
    expect(progress.requestWallProbe("b.example", "https://b.example/", "0 产出")).toBe(true);
    progress.consumeWallProbe();
    expect(progress.requestWallProbe("c.example", "https://c.example/", "0 产出")).toBe(true);
    progress.consumeWallProbe();
    // 已经是第 3 次之后，第 4 个 host 不再登记
    expect(progress.requestWallProbe("d.example", "https://d.example/", "0 产出")).toBe(false);
    expect(progress.state.linkage?.waf_probe_count).toBe(3);
  });

  it("字典 0 产出会自己登记补枪，有结果时不登记", () => {
    const scan = (items: unknown[]) => ({
      tool: "recon.content_discovery" as const, ok: true, summary: "ffuf",
      data: { items, count: items.length }, duration_ms: 10, artifacts: [],
    });
    const request = { tool: "recon.content_discovery" as const, task_id: "dict", reason: "brute", input: { url: "https://w.example/" } };
    const empty = new BlackboxProgress();
    empty.recordHostBlock(request, scan([]));
    expect(empty.state.waf_probe?.host).toBe("w.example");
    const hit = new BlackboxProgress();
    hit.recordHostBlock(request, scan([{ url: "https://w.example/admin", status: 200 }]));
    expect(hit.state.waf_probe).toBeUndefined();
  });
});
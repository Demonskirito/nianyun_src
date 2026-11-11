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
import type { WallKind } from "../src/blackbox/waf-ledger.js";

/**
 * 墙的性质 → 派什么任务（2026-11-04）。
 *
 * 这组测试守的是"**下次碰到 WAF 墙还能不能正常绕过**"这个问题的答案：
 *   - rule_wall（含判不出性质的默认）→ 必须照常派 waf_bypass 阶梯。
 *     这条一旦挂了，说明改动把真规则墙一起关掉了，是灾难性回归。
 *   - identity_wall → 不派阶梯（8 档改 payload，这堵墙不看 payload），改派拿凭证。
 *   - unstable → 两个都不派（无墙可绕），只写降频事件。
 *
 * 直接调私有的 dispatchWafTask：走完整主循环要跑两轮模型调用且每轮从 DB 重读
 * checkpoint，测一条 60 秒还测不准；分流决策本身是纯的，单独测更可靠。
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
  const dir = mkdtempSync(join(tmpdir(), "nianyun-wall-dispatch-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test",
    BLACKBOX_AGENT_API_KEY: "fixture", BURP_PROXY_REQUIRED: "false",
  });
  cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({
    budgets: { agent_turns: 2 },
    focus_lock: { max_turns_per_task: 5, stall_rounds: 3, appeal_pool: 0, max_session_convergences: 99 },
  });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "wall dispatch", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  return { cfg, db, pid, sid, target };
}

type Dispatch = (pid: string, sid: string, progress: BlackboxProgress, stamp: string) => string | undefined;

function dispatch(f: ReturnType<typeof fixture>, kind?: WallKind) {
  const progress = new BlackboxProgress();
  const host = new URL(f.target).host;
  progress.state.waf_escalation = {
    host, at: Date.now(), hits: 2, marker: "fixture wall",
    ...(kind ? { kind } : {}),
  };
  const desk = new Desk(f.cfg, f.db) as unknown as { dispatchWafTask: Dispatch };
  const taskId = desk.dispatchWafTask(f.pid, f.sid, progress, "T0");
  const session = f.db.getBlackboxSession(f.pid, f.sid)!;
  return {
    taskId,
    taskIds: Object.keys(progress.state.tasks || {}),
    wafTasks: progress.state.linkage?.waf_tasks || [],
    events: (session.events as Array<{ kind: string; text?: string }>).map(e => e.kind),
  };
}

describe("墙的性质决定派哪种任务", () => {
  it("rule_wall → 照常派 waf_bypass 阶梯（核心回归：绕过能力不能被改动关掉）", async () => {
    const target = await listen(createServer((_req, res) => { res.statusCode = 412; res.end("您的访问被阻断"); }));
    const f = fixture(target);
    const r = dispatch(f, "rule_wall");
    expect(r.taskId?.startsWith("waf_bypass_")).toBe(true);
    expect(r.taskIds.some(id => id.startsWith("waf_bypass_"))).toBe(true);
    expect(r.taskIds.some(id => id.startsWith("identity_wall_"))).toBe(false);
    expect(r.events).toContain("waf-escalation");
  });

  it("老 checkpoint 没有 kind → 默认按 rule_wall 派阶梯（判不出性质时照常尝试）", async () => {
    const target = await listen(createServer((_req, res) => { res.statusCode = 412; res.end("您的访问被阻断"); }));
    const f = fixture(target);
    const r = dispatch(f, undefined);
    expect(r.taskId?.startsWith("waf_bypass_")).toBe(true);
    expect(r.events).toContain("waf-escalation");
  });

  it("identity_wall → 不派 waf_bypass，改派拿凭证的任务", async () => {
    const target = await listen(createServer((_req, res) => { res.statusCode = 403; res.end("blocked"); }));
    const f = fixture(target);
    const r = dispatch(f, "identity_wall");
    expect(r.taskId?.startsWith("identity_wall_")).toBe(true);
    expect(r.taskIds.some(id => id.startsWith("waf_bypass_"))).toBe(false);
    expect(r.wafTasks.some(id => id.startsWith("identity_wall_"))).toBe(true);
    expect(r.events).toContain("waf-identity-wall");
  });

  it("identity_wall 的任务文案里必须有'禁止提交身份字段'", async () => {
    const target = await listen(createServer((_req, res) => { res.statusCode = 403; res.end("blocked"); }));
    const f = fixture(target);
    const progress = new BlackboxProgress();
    progress.state.waf_escalation = { host: new URL(f.target).host, at: Date.now(), hits: 2, marker: "x", kind: "identity_wall" };
    const desk = new Desk(f.cfg, f.db) as unknown as { dispatchWafTask: Dispatch };
    desk.dispatchWafTask(f.pid, f.sid, progress, "T0");
    const entry = Object.entries(progress.state.tasks || {}).find(([id]) => id.startsWith("identity_wall_"));
    const purpose = String((entry?.[1] as { purpose?: string } | undefined)?.purpose || "");
    expect(purpose).toContain("不要");
    expect(purpose).toContain("principal");
  });

  it("unstable → 两个梯队都不派，只写降频事件", async () => {
    const target = await listen(createServer((_req, res) => { res.statusCode = 403; res.end("blocked"); }));
    const f = fixture(target);
    const r = dispatch(f, "unstable");
    expect(r.taskId).toBeUndefined();
    expect(r.taskIds.some(id => id.startsWith("waf_bypass_"))).toBe(false);
    expect(r.taskIds.some(id => id.startsWith("identity_wall_"))).toBe(false);
    expect(r.events).toContain("waf-unstable");
  });
});

describe("战例库不再收假战例", () => {
  it("模型只报'成功档位'没有可复制变体 → 不入库", async () => {
    const target = await listen(createServer((_req, res) => { res.statusCode = 412; res.end("您的访问被阻断"); }));
    const f = fixture(target);
    f.db.updateBlackboxSession(f.pid, f.sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });

    let rounds = 0;
    vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init?: { body?: unknown }) => {
      const body = String(init?.body || "");
      if (body.includes("main_agent_output")) return Response.json({ choices: [{ message: { content: JSON.stringify({ review: "ok", decision: "continue" }) } }] });
      rounds += 1;
      return Response.json({ choices: [{ message: { content: JSON.stringify({
        summary: "fixture",
        required_tasks: [],
        // 只有档位描述、没有可复制的变体 —— 旧代码会把拦截基线当 payload 存进去，
        // 产出一条 source=auto、hits 越滚越大的假战例，此后每个会话都被它带到沟里。
        waf_bypasses: [{ vendor: "aliyun", dimension: "other", tactic: "其它（waf_bypass.recall 命中）", note: "模型未回报变体" }],
        tool_requests: [], continue: rounds < 1,
      }) } }] });
    }));

    await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(f.db.listWafBypasses({ limit: 10 })).toHaveLength(0);
  }, 60000);
});

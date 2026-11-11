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
 * 战例库的端到端闭环（跑真实 Desk 主循环，只 stub 模型）：
 *
 * 第 1 轮：模型打穿一堵墙并回报 waf_bypasses → 落库 + 写 waf-ledger 事件。
 * 第 2 轮：同一会话的 system prompt 里必须出现战例库（厂商 + 档位 + 完整变体 + "照抄"指令），
 *         否则"下次先照抄再思考"就只是口号，模型根本看不到这些东西。
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
  const dir = mkdtempSync(join(tmpdir(), "nianyun-waf-ledger-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test",
    BLACKBOX_AGENT_API_KEY: "fixture", BURP_PROXY_REQUIRED: "false",
  });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "WAF ledger", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });
  return { cfg, db, pid, sid, target };
}

describe("WAF 战例库：打穿一次，下一轮就出现在 prompt 里", () => {
  it("模型回报的 waf_bypasses 落库，并在后续轮次的 system prompt 中作为复刻清单出现", async () => {
    const server = createServer((_req, res) => {
      res.statusCode = 412;
      res.setHeader("x-waf", "safedog");
      res.end("您的访问被阻断");
    });
    const target = await listen(server);
    const f = fixture(target);
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({
      budgets: { agent_turns: 2 },
      focus_lock: { max_turns_per_task: 5, stall_rounds: 3, appeal_pool: 0, max_session_convergences: 99 },
    });

    const prompts: string[] = [];
    let mainRounds = 0;
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init?: { body?: unknown }) => {
      const body = String(init?.body || "");
      if (body.includes("main_agent_output")) return answer({ review: "waf bypass recorded", decision: "continue" });
      prompts.push(body);
      mainRounds += 1;
      return answer({
        summary: "在 safedog 上打穿一档参数污染",
        required_tasks: [],
        waf_bypasses: [{
          vendor: "安全狗", dimension: "param", tactic: "同名参数双写",
          payload: "id=1&id=union%20select", host: "app.example.test", evidence_id: "ev-fixture",
        }],
        tool_requests: [],
        continue: mainRounds < 2,
      });
    }));

    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);

    // 1. 落库：厂商被归一成 id，变体原样保留。
    const rows = f.db.listWafBypasses({ limit: 10 });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ vendor: "safedog", dimension: "param", tactic: "同名参数双写" });
    expect(String(rows[0]!.payload)).toContain("union%20select");

    // 2. 事件：告诉操作员战例已入库（控制台/会话记录里能看到）。
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const kinds = (saved.events as Array<{ kind: string }>).map(event => event.kind);
    expect(kinds).toContain("waf-ledger");

    // 3. prompt：第二轮必须带上"先照抄"的清单，且含厂商名与变体。
    expect(mainRounds).toBeGreaterThanOrEqual(2);
    const withLedger = prompts.filter(body => body.includes("WAF 战例库"));
    expect(withLedger.length).toBeGreaterThan(0);
    expect(withLedger.at(-1)).toContain("安全狗");
    expect(withLedger.at(-1)).toContain("同名参数双写");
    expect(withLedger.at(-1)).toContain("id=1&id=union%20select");
    expect(withLedger.at(-1)).toContain("照抄");
  }, 60000);
});
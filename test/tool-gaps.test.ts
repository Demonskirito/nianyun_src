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
import { BLACKBOX_TOOL_ENUM, mainSchema, observerSchema } from "../src/blackbox/protocol.js";

/**
 * 三件事的可验证边界：
 *   ① 主 Agent 能调到全部 74 个工具（tool_requests[].tool 的枚举就是注册表全集）；
 *   ② Observer 能精确点名下一步用哪个工具（next_steps 结构化，工具名受同一枚举约束）；
 *   ③ 主 Agent 能上报"缺什么工具"（tool_gaps → 事件 + 回灌 context，重复不记）。
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
  const dir = mkdtempSync(join(tmpdir(), "nianyun-tool-gap-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test",
    BLACKBOX_AGENT_API_KEY: "fixture", BURP_PROXY_REQUIRED: "false",
  });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Gaps", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });
  return { cfg, db, pid, sid, target };
}

describe("工具枚举就是注册表全集", () => {
  it("75 项（含 browser.network），且 tool_requests 只接受清单内的名字", () => {
    expect(BLACKBOX_TOOL_ENUM.length).toBe(75);
    const ok = mainSchema.safeParse({ summary: "s", tool_requests: [{ tool: "burp.send", input: { url: "https://a.example/" } }] });
    expect(ok.success).toBe(true);
    const bad = mainSchema.safeParse({ summary: "s", tool_requests: [{ tool: "sqlmap.turbo", input: {} }] });
    expect(bad.success).toBe(false);
  });

  it("Observer 的 next_steps 能点名真实工具，写了不存在的工具名整条被拒", () => {
    const ok = observerSchema.safeParse({
      review: "r", decision: "continue",
      next_steps: [{ tool: "http.diff", target: "https://a.example/x", input: { url: "https://a.example/x", variant: { headers: { "x-forwarded-host": "evil.example" } } }, why: "验证 Host 改写" }],
    });
    expect(ok.success).toBe(true);
    if (ok.success) expect((ok.data as { next_steps: Array<{ tool?: string }> }).next_steps[0]!.tool).toBe("http.diff");
    const bad = observerSchema.safeParse({ review: "r", decision: "continue", next_steps: [{ tool: "jwt.forge", why: "伪造 token" }] });
    expect(bad.success).toBe(false);
    // 没有工具但说明缺什么能力，仍然合法（等价于替主 Agent 报缺口）
    const gap = observerSchema.safeParse({ review: "r", decision: "continue", next_steps: [{ why: "需要能伪造 ES256 的 JWT 工具" }] });
    expect(gap.success).toBe(true);
  });

  it("next_steps 会折成主 Agent 可执行的建议（含工具名与 input）", () => {
    const progress = new BlackboxProgress();
    progress.supplement({
      review: "r",
      suggestions: [],
      next_steps: [{ tool: "http.diff", target: "https://a.example/x", input: { url: "https://a.example/x" }, why: "对比 Host 改写" }],
    }, "review-1");
    const advice = (progress.state.advice || {})["review-1"];
    expect(advice).toBeTruthy();
    const line = (advice!.suggestions || []).join("\n");
    expect(line).toContain("下一步指定工具 http.diff");
    expect(line).toContain("https://a.example/x");
  });
});

describe("工具缺口上报", () => {
  it("main 的 tool_gaps 落成事件、写进 linkage，并在下一轮 prompt 里回灌", async () => {
    const server = createServer((_req, res) => { res.statusCode = 200; res.end("ok"); });
    const target = await listen(server);
    const f = fixture(target);
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({
      budgets: { agent_turns: 2 },
      focus_lock: { max_turns_per_task: 5, stall_rounds: 3, appeal_pool: 0, max_session_convergences: 99 },
    });

    const prompts: string[] = [];
    let rounds = 0;
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init?: { body?: unknown }) => {
      const body = String(init?.body || "");
      if (body.includes("main_agent_output")) return answer({ review: "gap recorded", decision: "continue" });
      prompts.push(body);
      rounds += 1;
      return answer({
        summary: "缺一个反连平台和无损 JWT 伪造器",
        required_tasks: [],
        tool_gaps: [
          { need: "反连平台用于盲 SSRF/OAST 回连", why: "recon.interactsh 未配置，DNS 外带收不到", alternative: "exec.python + 公网 webhook 占位", blocked_task: "t-oast" },
          // 同一缺口换个措辞再报一次：不该重复入库
          { need: "反连平台用于盲 SSRF / OAST 回连" },
        ],
        tool_requests: [],
        continue: rounds < 2,
      });
    }));

    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);

    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const gapEvents = (saved.events as Array<{ kind: string; data?: Record<string, unknown> }>).filter(event => event.kind === "tool-gap");
    expect(gapEvents).toHaveLength(1);
    expect(gapEvents[0]!.data).toMatchObject({ tool: null, missing: true });

    const checkpoint = saved.checkpoint as { linkage?: { tool_gaps?: Array<{ need: string }> } };
    expect(checkpoint.linkage?.tool_gaps).toHaveLength(1);

    // 第二轮 prompt 带上已登记缺口 + "不要重复报"的规则
    const withGaps = prompts.filter(body => body.includes("tool_gaps"));
    expect(withGaps.length).toBeGreaterThan(0);
    const last = withGaps.at(-1)!;
    expect(last).toContain("反连平台用于盲 SSRF/OAST 回连");
    expect(last).toContain("不要再报");
    expect(rounds).toBeGreaterThanOrEqual(2);
  }, 60000);

  it("点名了不存在的工具时标 missing，点了已注册但不可用的工具时在 why 里注明", () => {
    const progress = new BlackboxProgress();
    const fresh = progress.recordToolGaps([
      { need: "需要 NoSQL 注入扫描", tool: "nosql.scan", missing: true },
      { need: "需要竞态批量器", tool: "recon.race_condition", missing: false },
    ]);
    expect(fresh).toHaveLength(2);
    expect(fresh[0]!.missing).toBe(true);
    // 幂等：同样的 need 不再进第二次
    expect(progress.recordToolGaps([{ need: "需要 NoSQL 注入扫描" }])).toHaveLength(0);
    expect(progress.state.linkage?.tool_gaps).toHaveLength(2);
  });
});
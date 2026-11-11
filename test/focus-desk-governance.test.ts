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
 * 焦点预算的三条"人性化"分支：申诉、熔断、操作员干预。
 *
 * 这些用例全部跑真实的 Desk 主循环（stub 掉 LLM 的 fetch），因为它们的价值就在"代码真的停下来了"，
 * 单测 focus-budget.ts 只能证明函数返回字符串。
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
  const dir = mkdtempSync(join(tmpdir(), "nianyun-focus-budget-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, { BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "fixture", BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Focus budget", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });
  return { cfg, db, pid, sid, target };
}

const events = (rows: unknown[]) => rows as Array<{ kind: string; text: string; data?: Record<string, unknown> }>;

describe("focus budget: appeal channel", () => {
  it("grants exactly one extra round when a critical signal appeared, then still blocks", async () => {
    // 目标第一次回 Set-Cookie（临界信号），之后都是纯 ok —— 诱饵线索。
    let hits = 0;
    const server = createServer((_req, res) => {
      hits += 1;
      if (hits === 1) res.setHeader("set-cookie", "sid=fixture; HttpOnly");
      res.end("ok");
    });
    const target = await listen(server);
    const f = fixture(target);
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({
      budgets: { agent_turns: 6 },
      focus_lock: { max_turns_per_task: 1, stall_rounds: 0, appeal_pool: 1, max_session_convergences: 99 },
    });
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output")
      ? { review: "read-only", should_continue: true }
      : { summary: "same task again", required_tasks: ["stuck_task"], tool_requests: [{ tool: "http.request", task_id: "stuck_task", input: { url: `${target}probe` } }] })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const all = events(saved.events as unknown[]);
    const appeals = all.filter(event => event.kind === "focus-appeal");
    expect(appeals).toHaveLength(1);
    expect(String(appeals[0]!.data?.signal || "")).toContain("set-cookie");
    const checkpoint = saved.checkpoint as {
      tasks: Record<string, { status: string; outcome_code?: string; outcome_reason?: string }>;
      focus_usage?: { appeals_used: number };
    };
    // 申诉只买一轮：最后还是被判死，而不是无限宽限。
    expect(checkpoint.tasks.stuck_task?.status).toBe("blocked");
    // 机器码归 outcome_code；outcome_reason 必须是能读的说明（旧实现把码写进了说明位）。
    expect(checkpoint.tasks.stuck_task?.outcome_code).toBe("focus_budget_exhausted");
    expect(String(checkpoint.tasks.stuck_task?.outcome_reason || "")).toContain("焦点预算");
  });
});

  it("stops the run with macro_frustration once convergences hit the cap", async () => {
    const server = createServer((_req, res) => res.end("ok"));
    const target = await listen(server);
    const f = fixture(target);
    // 上一段运行已经收口过一次：这次再收口一次就到阈值（真实场景：暂停后继续跑）。
    const seeded = new BlackboxProgress();
    seeded.state.usage.session_convergences = 1;
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: seeded.state });
    f.cfg.tools_env.values.BLACKBOX_RULES_DOCUMENT = JSON.stringify({
      budgets: { agent_turns: 6 },
      focus_lock: { max_turns_per_task: 1, stall_rounds: 0, appeals_per_task: 0, max_session_convergences: 2 },
    });
    const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });
    vi.stubGlobal("fetch", vi.fn(async (_url, init) => answer(String(init?.body).includes("main_agent_output")
      ? { review: "read-only", should_continue: true }
      : { summary: "keep hammering", required_tasks: ["stuck_task"], tool_requests: [{ tool: "http.request", task_id: "stuck_task", input: { url: `${target}probe` } }] })));
    const result = await new Desk(f.cfg, f.db).runProjectBlackboxAgents(f.pid, f.sid);
    expect(result.ok).toBe(true);
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const all = events(saved.events as unknown[]);
    const macro = all.filter(event => event.kind === "macro-interrupt");
    expect(macro).toHaveLength(1);
    const checkpoint = saved.checkpoint as {
      stopReason?: string;
      macro_interrupt?: { count: number; limit: number; text: string };
      usage: { session_convergences?: number };
    };
    expect(checkpoint.usage.session_convergences).toBeGreaterThanOrEqual(2);
    expect(checkpoint.macro_interrupt?.count).toBeGreaterThanOrEqual(2);
    expect(checkpoint.macro_interrupt?.text).toContain("【宏观战略调整】");
    expect(checkpoint.stopReason).toBe("macro_frustration");
  });

describe("focus dashboard API", () => {
  it("projects usage/limits and supports operator converge, extend and switch", () => {
    const f = fixture("http://127.0.0.1:9/");
    const desk = new Desk(f.cfg, f.db);
    const progress = new BlackboxProgress();
    progress.merge({ required_tasks: [
      { id: "T1", target: f.target, purpose: "第一条" },
      { id: "T2", target: f.target, purpose: "第二条" },
    ] });
    progress.state.focus_task_id = "T1";
    progress.state.focus_usage = {
      task_id: "T1", turns: 4, tool_calls: 6, tp: 32, value_score: 3, high_value: 1, medium_value: 0, noise: 2,
      last_value_score: 3, no_progress_rounds: 2, appeals_used: 0, max_turns: 8, max_tp: 50,
    };
    f.db.updateBlackboxSession(f.pid, f.sid, { checkpoint: progress.state });

    const view = desk.projectBlackboxFocus(f.pid, f.sid) as {
      ok: boolean; focus_task_id: string; usage?: { tp: number }; limits: { max_tp_per_task: number }; tasks: Array<{ id: string }>; tp_table: unknown[];
    };
    expect(view.ok).toBe(true);
    expect(view.focus_task_id).toBe("T1");
    expect(view.usage?.tp).toBe(32);
    expect(view.limits.max_tp_per_task).toBe(50);
    expect(view.tp_table.length).toBeGreaterThan(0);
    expect(view.tasks.map(task => task.id)).toContain("T2");

    // 强制收口：任务变 blocked，账本清空
    const converged = desk.updateProjectBlackboxFocus(f.pid, f.sid, "converge") as { ok: boolean; usage?: unknown };
    expect(converged.ok).toBe(true);
    const afterConverge = f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint as { tasks: Record<string, { status: string; outcome_reason?: string }> };
    expect(afterConverge.tasks.T1?.status).toBe("blocked");
    expect(afterConverge.tasks.T1?.outcome_reason).toBe("operator_blocked");

    // 切换焦点 + 手动延期
    const switched = desk.updateProjectBlackboxFocus(f.pid, f.sid, "switch", "T2") as { ok: boolean; focus_task_id: string };
    expect(switched.focus_task_id).toBe("T2");
    const extended = desk.updateProjectBlackboxFocus(f.pid, f.sid, "extend", "T2") as { ok: boolean };
    expect(extended.ok).toBe(true);
    expect(desk.updateProjectBlackboxFocus(f.pid, f.sid, "nope").ok).toBe(false);
    expect(desk.projectBlackboxFocus(f.pid, "missing").ok).toBe(false);
  });
});

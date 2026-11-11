/**
 * 引水调度（desk.ensureSiteDeclaration，2026-11-05）。
 *
 * 守两件事：
 *   ① **403 之后必须还能再试**——实测会话 5b59aa1d059b56da 就是死在这里：
 *      sitemap 第一次 403，模型再没碰它，18 个 /help 业务页整批丢失。
 *   ② **不能变成新的空转源**——首次只提示不建任务（建了会改整个任务簿与验收口径），
 *      冷却期间必须把强制焦点摘掉（否则 45s 内模型打什么都被焦点锁拒收），
 *      3 轮后必须收口（不能永远悬着）。
 */
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { Desk } from "../src/control/console/desk.js";
import { recordDeclaration, SITE_DECLARATION_COOLDOWN_MS, SITE_DECLARATION_MAX_ATTEMPTS } from "../src/blackbox/site-declaration.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

const TARGET = "https://wanxiaozhi.aliyun.com/";
const HOST = "wanxiaozhi.aliyun.com";

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-site-decl-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "site declaration", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: TARGET, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), TARGET).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid };
}

type Ensure = (pid: string, sid: string, progress: BlackboxProgress, target: string) => void;

function run(f: ReturnType<typeof fixture>, prepare: (progress: BlackboxProgress) => void) {
  const progress = new BlackboxProgress();
  prepare(progress);
  const desk = new Desk(f.cfg, f.db) as unknown as { ensureSiteDeclaration: Ensure };
  desk.ensureSiteDeclaration(f.pid, f.sid, progress, TARGET);
  const session = f.db.getBlackboxSession(f.pid, f.sid)!;
  return {
    progress,
    task: progress.state.tasks.T_SITE_DECLARATION,
    focus: progress.state.forced_focus,
    interrupts: progress.state.interrupts || [],
    events: (session.events as Array<{ kind: string; text?: string }>).map(event => event.kind),
  };
}

describe("引水：从未尝试只提示，不建任务", () => {
  it("没有账 → 不建任务、不抢焦点，只给一条提示", () => {
    const f = fixture();
    const r = run(f, () => {});
    expect(r.task).toBeUndefined();
    expect(r.focus).toBeUndefined();
    expect(r.interrupts.some(item => item.kind === "site_declaration")).toBe(true);
  });
});

describe("引水：403 之后要能再试", () => {
  it("冷却中不重试，并把钉在引水上的焦点摘掉", () => {
    const f = fixture();
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: Date.now() }) };
      progress.state.forced_focus = { task_id: "T_SITE_DECLARATION", kind: "site_declaration", at: Date.now() };
    });
    expect(r.task).toBeUndefined();
    // 冷却期不抢焦点：否则这 45s 内模型打什么都会被焦点锁拒收
    expect(r.focus).toBeUndefined();
  });

  it("冷却过后建任务、写清「403 不是结论」、钉住焦点", () => {
    const f = fixture();
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: past }) };
    });
    expect(r.task?.status).toBe("pending");
    expect(String(r.task?.reason)).toContain("不是结论");
    expect(String(r.task?.completion_criteria)).toContain("404");
    expect(r.focus?.task_id).toBe("T_SITE_DECLARATION");
    expect(String(r.focus?.note)).toContain("403");
    expect(r.events).toContain("site-declaration");
  });

  it("已经有别的活着的强制焦点时不抢（SPA / 主权转移优先）", () => {
    const f = fixture();
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: past }) };
      progress.state.tasks.T_SPA_REVERSE_0001 = { status: "pending", target: TARGET };
      progress.state.forced_focus = { task_id: "T_SPA_REVERSE_0001", kind: "spa", at: Date.now() };
    });
    expect(r.task?.status).toBe("pending");
    expect(r.focus?.task_id).toBe("T_SPA_REVERSE_0001");
  });

  it(`${SITE_DECLARATION_MAX_ATTEMPTS} 轮后收口 blocked，不再重试`, () => {
    const f = fixture();
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    let state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: past - 2 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 403, at: past - SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 403, at: past });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: state };
      progress.state.tasks.T_SITE_DECLARATION = { status: "pending", target: TARGET, reason: "引水" };
      progress.state.forced_focus = { task_id: "T_SITE_DECLARATION", kind: "site_declaration", at: Date.now() };
    });
    expect(r.task?.status).toBe("blocked");
    expect(String(r.task?.outcome_reason)).toContain("不再重试");
    expect(r.focus).toBeUndefined();
    expect(r.events).toContain("site-declaration-blocked");
  });

  it("拿到终态但没有本任务证据 → blocked，不硬置 completed（否则验收永远 ready 不了）", () => {
    const f = fixture();
    let state = recordDeclaration(undefined, { path: "/robots.txt", status: 200, bytes: 120, at: 1 });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 200, bytes: 1927, at: 2 });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: state };
      progress.state.tasks.T_SITE_DECLARATION = { status: "pending", target: TARGET, reason: "引水" };
    });
    expect(r.task?.status).toBe("blocked");
    expect(String(r.task?.outcome_reason)).toContain("没有属于本任务的成功证据");
  });

  it("拿到终态且有本任务证据 → completed，并带上 evidence_ids", () => {
    const f = fixture();
    f.db.addBlackboxEvidence(f.pid, f.sid, {
      kind: "tool-result", source: "http.request", summary: "GET /sitemap.xml",
      data: { task_id: "T_SITE_DECLARATION", ok: true, status: 200 },
    });
    const evidenceId = String((f.db.getBlackboxSession(f.pid, f.sid)!.evidence as Array<{ id: string }>)[0]!.id);
    let state = recordDeclaration(undefined, { path: "/robots.txt", status: 200, bytes: 120, at: 1 });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 200, bytes: 1927, at: 2 });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: state };
      progress.state.tasks.T_SITE_DECLARATION = { status: "pending", target: TARGET, reason: "引水", completion_criteria: "两个文件拿到终态" };
    });
    expect(r.task?.status).toBe("completed");
    expect(r.task?.evidence_ids).toEqual([evidenceId]);
    expect(String(r.task?.outcome_reason)).toContain("引水完成");
    expect(r.events).toContain("site-declaration-done");
  });
});

/**
 * 部分交付（2026-11-05 实测会话 773eae1a2d5b6c0c）。
 *
 * sitemap 在 06:49:21 拿到 200，18 个 /help 页全部入图；robots 的 200 因为正文没带回来
 * 被判 retry，4 轮后整条任务落 blocked，结案文案写成「3 轮后仍被挡（/robots.txt 200；
 * /sitemap.xml 200）」——两个 200 却说被挡。模型据此认为业务面没拿到，回头去爬静态路径。
 */
describe("引水：有一个文件 ok 就是已到手，不能被另一个文件的抖动拖成失败", () => {
  it("sitemap ok + robots 耗尽 → completed，理由写明部分交付", () => {
    const f = fixture();
    f.db.addBlackboxEvidence(f.pid, f.sid, {
      kind: "tool-result", source: "http.request", summary: "GET /sitemap.xml",
      data: { task_id: "T_SITE_DECLARATION", ok: true, status: 200 },
    });
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    let state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 200, bytes: 1923, at: past - 3 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past - 2 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past - SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: state };
      progress.state.tasks.T_SITE_DECLARATION = { status: "pending", target: TARGET, reason: "引水" };
      progress.state.forced_focus = { task_id: "T_SITE_DECLARATION", kind: "site_declaration", at: Date.now() };
    });
    expect(r.task?.status).toBe("completed");
    expect(String(r.task?.outcome_reason)).toContain("已交付 /sitemap.xml");
    // 不能把「已交付」写成「仍被挡」
    expect(String(r.task?.outcome_reason)).not.toContain("仍被挡");
    expect(r.focus).toBeUndefined();
    expect(r.events).toContain("site-declaration-done");
  });

  it("sitemap ok + robots 耗尽但缺本任务证据 → blocked，理由说清已交付什么", () => {
    const f = fixture();
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    let state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 200, bytes: 1923, at: past - 3 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past - 2 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past - SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: state };
      progress.state.tasks.T_SITE_DECLARATION = { status: "pending", target: TARGET, reason: "引水" };
    });
    expect(r.task?.status).toBe("blocked");
    expect(String(r.task?.outcome_reason)).toContain("已交付 /sitemap.xml");
    expect(String(r.task?.outcome_reason)).toContain("没有属于本任务的成功证据");
  });
});

/**
 * 任务从没建出来（2026-11-05 实测会话 bd2b519a4f5037c5）。
 *
 * 模型自己在 45s 冷却边界上重打，控制面每次检查都落在 cooldown，
 * attempts 冲到 5 都没有 T_SITE_DECLARATION。旧代码在终态分支直接 return，
 * 模型既收不到"已到手"也收不到"别再打"。
 */
describe("引水：任务没建出来也要播报结论，且只播一次", () => {
  it("无任务 + 已交付 → 写 site-declaration-settled，并记 settled_at", () => {
    const f = fixture();
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    let state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: past - 3 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 200, bytes: 1923, at: past - 2 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 0, at: past - SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 0, at: past });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: state };
    });
    expect(r.task).toBeUndefined();
    expect(r.events).toContain("site-declaration-settled");
    expect(r.progress.state.site_declaration?.[HOST]?.settled_at).toBeTypeOf("number");
  });

  it("已经播过就不再重复播（避免每轮一条事件）", () => {
    const f = fixture();
    const past = Date.now() - SITE_DECLARATION_COOLDOWN_MS - 1_000;
    let state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 200, bytes: 1923, at: past - 2 * SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past - SITE_DECLARATION_COOLDOWN_MS });
    state = recordDeclaration(state, { path: "/robots.txt", status: 403, at: past });
    const r = run(f, progress => {
      progress.state.site_declaration = { [HOST]: { ...state, settled_at: Date.now() - 1_000 } };
    });
    expect(r.events).not.toContain("site-declaration-settled");
  });
});

/**
 * SPA 缴械不许再凭空造第二份任务（2026-11-05）。
 *
 * 事故：`applyProtocolHooks` 认出 SPA 外壳后**无条件新建** `T_SPA_REVERSE_*`，
 * 而主 agent 常常已经建过一条同 host、同目的的任务（"抓首页外壳，提取 .js bundle"）。
 * 两份都占待办额度，强制焦点只锁系统新建的那条，于是证据全归后者，前者永远拿不到
 * 证据、只能被 settle 成 blocked。
 *
 * 实测 fb06499adcf889b5：T1 与 T_SPA_REVERSE_75985252 同 host 同目的，
 * 24 个 turns 全锁在后者，browser 抓到 85 条 XHR 却换不来一条 completed，整场 0 完成。
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

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

const TARGET = "https://wanxiaozhi.aliyun.com/";

/**
 * 一份能通过 spaFingerprint 判定的外壳：200 + html + ≥2KB + id="root" + 打包 chunk。
 * 文本比例必须压到接近 0——塞 `<p>filler</p>` 会被判成 `looks_like_ssr_or_static`
 * （真实 SPA 外壳也确实是空壳 + 一堆脚本）。
 */
const SPA_BODY = `<html><head>`
  + Array.from({ length: 8 }, (_, i) => `<script src="/static/js/chunk-${i}.js"></script>`).join("")
  + `</head><body><div id="root"></div>`
  + `<div class="c"></div>`.repeat(200)
  + `</body></html>`;

type Hooks = (
  pid: string, sid: string, progress: BlackboxProgress,
  input: { tool: string; data: Record<string, unknown>; requestUrl: string; ingested: { newNodes: string[]; candidates?: string[] }; parentUrl: string },
) => void;

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-spa-dedupe-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "spa dedupe", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: TARGET, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), TARGET).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid };
}

function hook(f: ReturnType<typeof fixture>, progress: BlackboxProgress) {
  const desk = new Desk(f.cfg, f.db) as unknown as { applyProtocolHooks: Hooks };
  desk.applyProtocolHooks(f.pid, f.sid, progress, {
    tool: "http.request",
    data: { status: 200, body: SPA_BODY, headers: { "content-type": "text/html; charset=utf-8" } },
    requestUrl: TARGET,
    ingested: { newNodes: [] },
    parentUrl: TARGET,
  });
  return progress.state;
}

describe("SPA 缴械任务查重", () => {
  it("簿子里已有同 host 的「SPA 外壳逆向」任务 → 复用，不新建 T_SPA_REVERSE_*", () => {
    const f = fixture();
    const progress = new BlackboxProgress();
    progress.state.tasks.T1 = {
      status: "pending",
      target: TARGET,
      purpose: "SPA 外壳逆向：抓首页外壳，提取 .js bundle 与其中的 baseURL/接口前缀，落到可打的接口面",
    } as never;

    const state = hook(f, progress);

    const spaTasks = Object.keys(state.tasks).filter(id => id.startsWith("T_SPA_REVERSE_"));
    expect(spaTasks).toEqual([]);
    // 焦点锁在这条已有任务上，而不是一条影子任务上
    expect(state.forced_focus?.task_id).toBe("T1");
    expect(state.spa?.task_id).toBe("T1");
    // 复用时补上交付契约（否则结案判据不成立），但不改写主 agent 写的判据
    const t1 = state.tasks.T1 as unknown as { deliverables?: string[]; purpose: string };
    expect(t1.deliverables).toEqual(expect.arrayContaining(["api_endpoints"]));
    expect(t1.purpose).toContain("bundle");
  });

  it("簿子里没有对应任务 → 仍然新建并锁焦点（原行为不变）", () => {
    const f = fixture();
    const progress = new BlackboxProgress();
    progress.state.tasks.T9 = { status: "pending", target: TARGET, purpose: "取回 robots.txt" } as never;

    const state = hook(f, progress);

    const spaTasks = Object.keys(state.tasks).filter(id => id.startsWith("T_SPA_REVERSE_"));
    expect(spaTasks).toHaveLength(1);
    expect(state.forced_focus?.task_id).toBe(spaTasks[0]);
    expect(state.tasks[spaTasks[0]!]?.status).toBe("pending");
  });

  it("复用的任务已经终态 → 不锁焦点（它给过结论了，锁住只会饿死下一件事）", () => {
    const f = fixture();
    const progress = new BlackboxProgress();
    progress.state.tasks.T1 = {
      status: "completed",
      target: TARGET,
      purpose: "SPA 外壳逆向：抓首页外壳与接口面",
      evidence_ids: ["ev-x"],
    } as never;

    const state = hook(f, progress);

    expect(Object.keys(state.tasks).filter(id => id.startsWith("T_SPA_REVERSE_"))).toEqual([]);
    expect(state.forced_focus?.task_id).not.toBe("T1");
  });
});

/**
 * 假设任务僵尸清理（2026-11-04）。
 *
 * 背景：`occupied`（同 kind 同 host 只留一条在办）只看任务状态，不看假设是否还活着。
 * 实测 d59f5a15a4ea26aa 里 `H_auth_wall_f9aa4097` 创建于 11-03 11:09、一直 pending 到
 * 11-04 04:07（17 小时），其假设早已不在池里，把当天 3 条新 auth_wall 假设全挡在门外。
 * 这组测试盯的就是"名额能不能流转回来"。
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
import { applyHypotheses, graphState, ingestToolResult, type AttackGraphState } from "../src/blackbox/graph/index.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-hyp-prune-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "prune", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: "https://t.example/", source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), "https://t.example/").id);
  const progress = new BlackboxProgress();
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: progress.state });
  const desk = new Desk(cfg, db);
  return { cfg, db, pid, sid, progress, desk };
}

type Enqueue = (pid: string, sid: string, progress: BlackboxProgress, graph: AttackGraphState) => number;
const enqueueOf = (desk: Desk): Enqueue => (desk as unknown as { enqueueHypothesisTasks: Enqueue }).enqueueHypothesisTasks.bind(desk);

/** 造一个带 403 鉴权墙端点的图（wallStillStands 要求 blocked_streak>0）。 */
function wallGraph(): AttackGraphState {
  const graph = graphState(undefined);
  for (const path of ["/admin", "/backup"]) {
    ingestToolResult(graph, {
      tool: "http.request",
      identity: "auth",
      endpoints: [{ url: `https://t.example${path}`, status_code: 403, auth_required: true, blocked: true }],
    });
  }
  applyHypotheses(graph, [
    { id: "auth_wall:ep:t.example/admin", kind: "auth_wall", text: "带凭证重打 /admin", nodes: ["ep:t.example/admin", "id:auth"], severity: "high", created_at: 1 },
    { id: "auth_wall:ep:t.example/backup", kind: "auth_wall", text: "带凭证重打 /backup", nodes: ["ep:t.example/backup", "id:auth"], severity: "high", created_at: 1 },
  ], 1);
  return graph;
}

describe("假设任务僵尸清理", () => {
  it("假设已不在池内的 H_ 任务被作废，不再占名额", () => {
    const { db, pid, sid, progress, desk } = fixture();
    progress.state.tasks = {
      H_auth_wall_dead: { status: "pending", target: "https://t.example/", hypothesis_id: "auth_wall:ep:t.example/", source: "hypothesis", created_at: 1 },
    } as never;
    const graph = wallGraph();
    const n = enqueueOf(desk)(pid, sid, progress, graph);

    // 僵尸被收掉，同时腾出的名额立刻被真假设用上。
    expect(String(progress.state.tasks.H_auth_wall_dead!.status)).toBe("blocked");
    expect(String(progress.state.tasks.H_auth_wall_dead!.closed_reason)).toContain("不在池内");
    expect(n).toBeGreaterThan(0);
    const fresh = Object.entries(progress.state.tasks).filter(([id, task]) => id.startsWith("H_") && id !== "H_auth_wall_dead" && task!.status === "pending");
    expect(fresh.length).toBeGreaterThan(0);
  });

  it("假设已归档的 H_ 任务被作废", () => {
    const { db, pid, sid, progress, desk } = fixture();
    const graph = wallGraph();
    graph.hypotheses = graph.hypotheses.map(item => ({ ...item, status: "archived" as const, archivedReason: "dependency_invalidated" as const }));
    progress.state.tasks = {
      H_auth_wall_open: { status: "pending", target: "https://t.example/admin", hypothesis_id: "auth_wall:ep:t.example/admin", source: "hypothesis", created_at: 1 },
    } as never;
    enqueueOf(desk)(pid, sid, progress, graph);
    expect(String(progress.state.tasks.H_auth_wall_open!.status)).toBe("blocked");
    expect(String(progress.state.tasks.H_auth_wall_open!.closed_reason)).toContain("假设已收口");
  });

  it("假设仍活跃的 H_ 任务保留，不被误清", () => {
    const { db, pid, sid, progress, desk } = fixture();
    const graph = wallGraph();
    progress.state.tasks = {
      H_auth_wall_live: { status: "pending", target: "https://t.example/admin", hypothesis_id: "auth_wall:ep:t.example/admin", source: "hypothesis", created_at: 1 },
    } as never;
    enqueueOf(desk)(pid, sid, progress, graph);
    expect(String(progress.state.tasks.H_auth_wall_live!.status)).toBe("pending");
  });

  it("同 host 同 kind 仍只留一条在办（occupied 未被削弱）", () => {
    const { db, pid, sid, progress, desk } = fixture();
    const graph = wallGraph();
    progress.state.tasks = {
      H_auth_wall_live: { status: "pending", target: "https://t.example/admin", hypothesis_id: "auth_wall:ep:t.example/admin", source: "hypothesis", created_at: 1 },
    } as never;
    const n = enqueueOf(desk)(pid, sid, progress, graph);
    // 另一条 /backup 同 host 同 kind：已有在办，不该再派。
    expect(n).toBe(0);
  });

  it("已完成/失败的历史任务不参与清理", () => {
    const { db, pid, sid, progress, desk } = fixture();
    const graph = wallGraph();
    progress.state.tasks = {
      H_auth_wall_done: { status: "completed", target: "https://t.example/", hypothesis_id: "auth_wall:ep:gone/", source: "hypothesis", created_at: 1 },
    } as never;
    enqueueOf(desk)(pid, sid, progress, graph);
    expect(String(progress.state.tasks.H_auth_wall_done!.status)).toBe("completed");
  });
});

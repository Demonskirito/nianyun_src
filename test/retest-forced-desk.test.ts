/**
 * 硬出路段 3 的 desk 层：第四态节点被死胡同拒收时强制派一次补测任务。
 *
 * 这里直接调 `forceRetestTask`（private，测试里按内部 API 用），因为要验的是
 * "派单/去重/防无限循环"这段逻辑，而不是整个 Agent 循环——后者由黑盒会话覆盖。
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
import { graphState, upsertNode, type GraphNode } from "../src/blackbox/graph/index.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-retest-forced-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "retest", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: "https://t.example/", source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), "https://t.example/").id);
  db.updateBlackboxSession(pid, sid, { status: "paused", environment: { ready: true }, checkpoint: new BlackboxProgress().state });
  return { cfg, db, pid, sid };
}

type Forced = { forceRetestTask: (pid: string, sid: string, progress: BlackboxProgress, node: GraphNode) => boolean };

function nodeWith(properties: Record<string, unknown>, status: "testing" | "dead_end" = "testing"): { progress: BlackboxProgress; node: GraphNode } {
  const progress = new BlackboxProgress();
  const graph = graphState(progress.state.graph);
  upsertNode(graph, { id: "ep:t.example/api/user/{id}", type: "endpoint", status, properties });
  return { progress, node: graph.nodes["ep:t.example/api/user/{id}"]! };
}

describe("desk：第四态节点被死胡同拒收时强制补测", () => {
  it("派出补测任务，判据是状态码，且点名别用原来那个工具", () => {
    const f = fixture();
    const { progress, node } = nodeWith({ origin: "request", status_unknown: true, probed_by: "nuclei" });
    const desk = new Desk(f.cfg, f.db) as unknown as Forced;

    expect(desk.forceRetestTask(f.pid, f.sid, progress, node)).toBe(true);
    const ids = Object.keys(progress.state.tasks as Record<string, unknown>);
    expect(ids).toHaveLength(1);
    expect(ids[0]).toContain("retest_for_status");
    const task = (progress.state.tasks as Record<string, Record<string, unknown>>)[ids[0]!]!;
    expect(task.deliverables).toEqual(["status_code:number"]);
    expect(String(task.purpose)).toContain("nuclei");
    expect(String(task.completion_criteria)).toContain("状态码");
    // 留痕：事件流里能看见"为什么派了这条"
    const saved = f.db.getBlackboxSession(f.pid, f.sid)!;
    const events = (saved.events || []) as Array<{ kind: string }>;
    expect(events.some(event => event.kind === "retest-forced")).toBe(true);
  });

  it("每个节点只强制一次（补测再失败不再无限派）", () => {
    const f = fixture();
    const { progress, node } = nodeWith({ origin: "request", status_unknown: true, probed_by: "nuclei" });
    const desk = new Desk(f.cfg, f.db) as unknown as Forced;
    expect(desk.forceRetestTask(f.pid, f.sid, progress, node)).toBe(true);
    expect(desk.forceRetestTask(f.pid, f.sid, progress, node)).toBe(false);
    expect(Object.keys(progress.state.tasks as Record<string, unknown>)).toHaveLength(1);
  });

  it("已经拿到状态码的节点不派（不是第四态）", () => {
    const f = fixture();
    const { progress, node } = nodeWith({ origin: "request", status_code: 200, status_unknown: false }, "dead_end");
    const desk = new Desk(f.cfg, f.db) as unknown as Forced;
    expect(desk.forceRetestTask(f.pid, f.sid, progress, node)).toBe(false);
    expect(Object.keys(progress.state.tasks as Record<string, unknown>)).toHaveLength(0);
  });
});

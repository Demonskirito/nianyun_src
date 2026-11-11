import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Desk } from "../src/control/console/desk.js";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import type { BlackboxProgress } from "../src/blackbox/progress.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

function fixture(target: string) {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-order-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, {
    BLACKBOX_AGENT_BASE_URL: "https://agent.test/v1", BLACKBOX_AGENT_MODEL: "test", BLACKBOX_AGENT_API_KEY: "secret",
    BLACKBOX_AGENT_TURN_BUDGET: "1", BURP_PROXY_REQUIRED: "false",
    BLACKBOX_RULES_DOCUMENT: JSON.stringify({ budgets: { agent_turns: 2, tool_calls: 10 }, focus_lock: { on: false } }),
  });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Order", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: target, source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), target).id);
  db.updateBlackboxSession(pid, sid, { status: "ready", environment: { ready: true } });
  return { cfg, db, pid, sid, target, desk: new Desk(cfg, db) };
}

const answer = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });

describe("tool batches follow playbook priority", () => {
  it("runs the unauthenticated probe before the low-priority xss task", async () => {
    const hits: string[] = [];
    const server: Server = createServer((req, res) => { hits.push(String(req.url)); res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const f = fixture(`${base}/`);
      const network = vi.fn()
        .mockResolvedValueOnce(answer({
          summary: "两个入口：先未授权再 xss",
          required_tasks: [
            { id: "scan_xss", target: `${base}/low`, purpose: "反射点验证", reason: "低优先级", completion_criteria: "看到弹窗", playbook: "xss" },
            { id: "scan_unauth", target: `${base}/high`, purpose: "未授权接口", reason: "先打未授权", completion_criteria: "接口直接返回数据", playbook: "unauth_exposure" },
          ],
          // 模型把低优先级的写在前面：执行顺序必须被重新排序
          tool_requests: [
            { tool: "http.request", task_id: "scan_xss", input: { url: `${base}/low` } },
            { tool: "http.request", task_id: "scan_unauth", input: { url: `${base}/high` } },
          ],
        }))
        .mockResolvedValue(answer({ summary: "等待观察", required_tasks: [] }));
      vi.stubGlobal("fetch", network);
      await f.desk.runProjectBlackboxAgents(f.pid, f.sid);
      expect(hits).toEqual(["/high", "/low"]);
      const checkpoint = (f.db.getBlackboxSession(f.pid, f.sid)!.checkpoint as BlackboxProgress["state"]);
      const runs = checkpoint.playbook_runs || {};
      expect(runs.unauth_exposure?.calls).toBe(1);
      expect(runs.unauth_exposure?.ok).toBe(1);
      expect(runs.xss?.calls).toBe(1);
      expect(Object.keys(runs.unauth_exposure?.steps || {}).length).toBeGreaterThan(0);
      const coverage = (f.db.getBlackboxSession(f.pid, f.sid)!.events as Array<{ kind: string; data?: Record<string, unknown> }>)
        .filter(event => event.kind === "playbook-coverage");
      expect(coverage.length).toBeGreaterThan(0);
    } finally {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });
});
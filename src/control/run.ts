#!/usr/bin/env node
/**
 * 一条命令跑完一个 URL。
 *
 *   nianyun run https://example.com/
 *
 * 它把控制台里点四次的流程（建项目 → 导入候选 → 环境检查 → 跑会话 → 出报告）
 * 折成一次调用，产物落在 workspace/<项目>/ 下：
 *
 *   report.md      黑盒会话报告（任务覆盖 + 候选发现 + 复核结论）
 *   summary.json   同一份报告的结构化版本
 *   run.json       本次 run 的元信息（项目/会话/停止原因/耗时）
 *
 * 为什么要它：控制台的交互面是给"人在看"的，脚本、CI、离线验收要的是"跑完就走"。
 * 规划层在无模型时会自动落到 src/blackbox/local_plan.ts，因此没有模型凭证也能跑完整场。
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureDirs, loadConfig } from "../shared/config.js";
import { Database } from "../shared/db.js";
import { clearProxyEnv } from "../shared/network-env.js";
import { Desk } from "./console/desk.js";
import * as workspace from "./console/workspace.js";
import { importAssetCandidates } from "../asset/candidates.js";

export type RunUrlOptions = {
  repo?: string;
  configPath?: string;
  projectName?: string;
  /** 指定已存在的项目 id：把这次 run 落到控制台里正在看的那个项目上。 */
  projectId?: string;
  /** 强制新开会话（默认复用同候选的既有会话）。 */
  fresh?: boolean;
  timeoutMs?: number;
};

function hostOf(url: string): string {
  try { return new URL(url).host.replace(/[^a-z0-9.\-:]/gi, "_"); } catch { return "target"; }
}

function findProjectByName(cfg: Parameters<typeof workspace.listProjects>[0], name: string): Record<string, unknown> | undefined {
  return workspace.listProjects(cfg).find(project => String(project.name || "") === name);
}

export async function runUrl(rawUrl: string, options: RunUrlOptions = {}): Promise<number> {
  if (process.env.NIANYUN_KEEP_PROXY !== "1") clearProxyEnv(process.env);
  const repo = options.repo || process.env.NIANYUN_REPO_ROOT || process.cwd();
  const cfg = loadConfig(options.configPath, repo);
  ensureDirs(cfg);
  const db = new Database(cfg.db_path);
  const desk = new Desk(cfg, db);

  let target: URL;
  try { target = new URL(rawUrl); } catch { throw new Error(`不是合法的 URL：${rawUrl}`); }
  if (!["http:", "https:"].includes(target.protocol)) throw new Error("只支持 http/https 目标");

  const startedAt = Date.now();
  const projectName = options.projectName || `auto-${target.host}`;
  // --project-id 优先：落到控制台里已经在看的项目上，而不是另起一个孤立项目。
  const pinned = options.projectId ? workspace.getProject(cfg, options.projectId) : undefined;
  if (options.projectId && !pinned) throw new Error(`项目不存在：${options.projectId}`);
  const project = pinned || findProjectByName(cfg, projectName) || workspace.createProject(cfg, projectName, `nianyun run ${target.toString()}`);
  const projectId = String(project.id || "");
  if (!projectId) throw new Error("项目创建失败");

  // 候选：同一 URL 复用，避免每次 run 都堆一条。
  const imported = importAssetCandidates(db, projectId, [{ kind: "url", value: target.toString(), source: "cli-run" }]);
  const candidateId = String(imported.accepted[0]?.id || "");
  if (!candidateId) throw new Error(`候选导入失败：${JSON.stringify(imported.rejected).slice(0, 400)}`);

  const created = desk.createProjectBlackboxSession(projectId, options.fresh ? { candidate_id: candidateId, force: true } : { candidate_id: candidateId });
  if (created.ok !== true) throw new Error(`会话创建失败：${String(created.error || "")}`);
  const sessionId = String((created.session as Record<string, unknown> | undefined)?.id || "");
  if (!sessionId) throw new Error("会话创建失败：缺少 session id");

  const environment = await desk.checkProjectBlackboxEnvironment(projectId, sessionId);
  const env = (environment.environment || {}) as Record<string, unknown>;
  const burp = (env.burp || {}) as Record<string, unknown>;
  const probe = (env.target || {}) as Record<string, unknown>;
  if (environment.ok !== true || env.ready !== true) {
    // Burp 通了但目标死了是一类新的失败：以前这里只会打印 Burp 的错误，于是"代理正常"
    // 会把人引到工具链上排查（2026-11-06 ce01b328599615a7 的实际经过）。
    const reason = String(environment.error
      || (burp.reachable === true ? probe.reason : "")
      || burp.error || probe.reason || "environment not ready");
    console.error(`环境检查未通过：${reason}`);
    console.error("提示：纯直连场景（没有 Burp）请在 tools.env.yaml 设 BURP_PROXY_REQUIRED: false 并把 BURP_PROXY_URL 置空；"
      + "模型出口另由 BLACKBOX_AGENT_PROXY_URL / 标准 HTTPS_PROXY 决定，不会跟着 Burp 一起断。");
    return 3;
  }

  const run = await desk.runProjectBlackboxAgents(projectId, sessionId);
  if (run.ok !== true && run.error) console.error(`run 返回：${String(run.error)}`);

  // 一次调用只推进一步：遇到"等复核/等预算"这类非终态停止原因就再来一轮，
  // 直到收敛（终态或没有新进展）。这是脚本化运行必须有的收敛循环。
  // 注意：stalled 不算终态——本地规划器可能只是本轮没派活，下一轮就能收口。
  const terminal = new Set(["tasks_completed", "failed", "blocked", "operator_cancelled", "tool_budget_exhausted", "agent_turn_budget_exhausted", "time_budget_exhausted"]);
  let rounds = 1;
  for (; rounds < 12; rounds += 1) {
    const current = desk.projectBlackboxSession(projectId, sessionId);
    const session = (current.session || {}) as Record<string, unknown>;
    const checkpoint = (session.checkpoint || {}) as Record<string, unknown>;
    const stop = String(checkpoint.stopReason || "");
    if (terminal.has(stop)) break;
    const status = String(session.status || "");
    if (status === "cancelled") break;
    const again = await desk.runProjectBlackboxAgents(projectId, sessionId);
    if (again.ok !== true) {
      if (again.error) console.error(`续跑停止：${String(again.error)}`);
      break;
    }
  }

  const report = desk.projectBlackboxReport(projectId, sessionId);
  const projectDir = workspace.ensureProjectDir(cfg, projectId);
  const md = typeof report.markdown === "string" ? report.markdown : "";
  const json = (report.json || {}) as Record<string, unknown>;
  // 验收门禁通过时统一呈现为 tasks_completed：报告里仍然逐条列出受阻的边角任务，
  // 但"能不能交付"这一层结论不该被一条系统自建任务（SPA 缴械等）压成 blocked。
  const acceptance = (report.acceptance || {}) as Record<string, unknown>;
  const rawStop = String(json.stop_reason || "");
  const stopReason = acceptance.ready === true && rawStop !== "failed" ? "tasks_completed" : rawStop;
  writeFileSync(join(projectDir, "report.md"), md || "(无报告正文)", "utf8");
  writeFileSync(join(projectDir, "summary.json"), JSON.stringify(json, null, 2), "utf8");
  const meta = {
    target: target.toString(),
    project_id: projectId,
    session_id: sessionId,
    stop_reason: stopReason,
    raw_stop_reason: rawStop,
    acceptance_ready: acceptance.ready === true,
    status: json.status,
    findings: Array.isArray(json.findings) ? json.findings.length : 0,
    tasks: Array.isArray(json.tasks) ? json.tasks.length : 0,
    duration_ms: Date.now() - startedAt,
    planner: "local-rules",
    artifacts: ["report.md", "summary.json"],
  };
  writeFileSync(join(projectDir, "run.json"), JSON.stringify(meta, null, 2), "utf8");

  console.log(JSON.stringify({ ok: true, ...meta, project_dir: projectDir }, null, 2));
  return 0;
}

export { hostOf };
#!/usr/bin/env node
import { ensureDirs, loadConfig } from "../shared/config.js";
import { Database } from "../shared/db.js";
import { serveConsole } from "./console/http.js";
import * as workspace from "./console/workspace.js";
import { clearProxyEnv } from "../shared/network-env.js";

function parseArgs(argv: string[]): { cmd: string; flags: Record<string, string | boolean>; rest: string[] } {
  let cmd = "";
  const flags: Record<string, string | boolean> = {};
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--config" || a === "-c") {
      flags.config = argv[++i] || "";
      continue;
    }
    if (a === "-v" || a === "--verbose") {
      flags.verbose = true;
      continue;
    }
    if (a.startsWith("--") && argv[i + 1] && !argv[i + 1]!.startsWith("-")) {
      flags[a.slice(2)] = argv[++i]!;
      continue;
    }
    if (a.startsWith("--")) {
      flags[a.slice(2)] = true;
      continue;
    }
    if (!cmd) cmd = a;
    else rest.push(a);
  }
  return { cmd, flags, rest };
}

async function main(): Promise<number> {
  // Default is proxy-free egress. NIANYUN_KEEP_PROXY=1 keeps the deployment proxy for the whole
  // process, which is required on networks where direct connections are dropped and where the
  // container must reach the model API / FOFA / target pages through it.
  if (process.env.NIANYUN_KEEP_PROXY !== "1") clearProxyEnv(process.env);
  const { cmd, flags, rest } = parseArgs(process.argv.slice(2));
  const repo = process.env.NIANYUN_REPO_ROOT || process.cwd();
  const cfg = loadConfig(typeof flags.config === "string" ? flags.config : undefined, repo);
  if (cmd === "inspect") {
    console.log(JSON.stringify({ execution: cfg.execution, database_opened: false, service_started: false }));
    return 0;
  }
  if (!cmd || cmd === "help" || flags.help) {
    console.log("nianyun console [--listen 127.0.0.1:8700] | run <url> [--project name] [--project-id id] | status | inspect | help");
    return 0;
  }
  if (cmd === "run") {
    // 一条命令跑完一个 URL：建项目 → 导入候选 → 环境检查 → 跑会话 → 落报告。
    const target = rest[0] || (typeof flags.url === "string" ? flags.url : "");
    if (!target) {
      console.error("usage: nianyun run <url> [--project name] [--project-id id] [--config path]");
      return 2;
    }
    const { runUrl } = await import("./run.js");
    return runUrl(target, {
      repo,
      configPath: typeof flags.config === "string" ? flags.config : undefined,
      projectName: typeof flags.project === "string" ? flags.project : undefined,
      projectId: typeof flags["project-id"] === "string" ? flags["project-id"] : undefined,
      fresh: flags.fresh === true || flags.fresh === "true",
    });
  }
  ensureDirs(cfg);
  const db = new Database(cfg.db_path);
  if (cmd === "console") {
    await serveConsole(cfg, db, String(flags.listen || "127.0.0.1:8700"));
    return 0;
  }
  if (cmd === "status") {
    const projects = workspace.listProjects(cfg);
    let candidates = 0;
    let sessions = 0;
    let findings = 0;
    for (const project of projects) {
      const pid = String(project.id || "");
      candidates += db.listAssetCandidates(pid, { limit: 5000 }).length;
      sessions += db.listBlackboxSessions(pid, 500).length;
      findings += db.listFindings(pid, { limit: 1000 }).length;
    }
    console.log(JSON.stringify({ execution: cfg.execution, projects: projects.length, candidates, sessions, findings, database: cfg.db_path }, null, 2));
    return 0;
  }
  console.error(`unknown command ${cmd}`);
  return 2;
}

if (process.argv[1]) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}

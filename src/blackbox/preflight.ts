/**
 * 冒烟校验（preflight）：环境检查之后再确认"每个工具真的能干活"。
 *
 * 起因：nuclei 镜像里没模板时，调用是"成功"的（exit 0，0 命中），整轮预算白烧；
 * 浏览器没装时每轮都在 browser.open 上撞 "browser is not available"。
 * 这里在会话开跑前跑一次空跑校验，结果写进 checkpoint，执行器据此提前拒绝。
 */

import { spawn } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export type PreflightEntry = { tool: string; ok: boolean; detail: string; /** 是否在执行层硬拦（装了但用不了才拦）。 */ gate?: boolean };
export type PreflightReport = { ok: boolean; checked_at: number; entries: PreflightEntry[]; failed: string[]; skipped: string[] };

type Probe = {
  tool: string; env: string; args: string[];
  /** 探活时要覆盖的环境变量：semgrep 这类 CLI 会顺手回连厂商服务，容器里全是代理出站，会挂到超时。 */
  envOverride?: Record<string, string>;
  validate?: () => string | undefined;
};

/** 需要本地二进制的工具：env 变量名与探活参数。 */
const BINARY_PROBES: Probe[] = [
  { tool: "recon.nuclei", env: "NUCLEI_PATH", args: ["-version"] },
  { tool: "recon.secrets", env: "TRUFFLEHOG_PATH", args: ["--version"] },
  {
    tool: "recon.sast", env: "SEMGREP_PATH", args: ["--version"],
    // 实测：容器内 `semgrep --version` 打开版本检查时 >60s 不返回（走代理回连 semgrep.dev），
    // 关掉版本检查与指标上报后 1.1s 返回。探活必须带着这两个变量，否则永远"探活超时"。
    envOverride: { SEMGREP_ENABLE_VERSION_CHECK: "0", SEMGREP_SEND_METRICS: "off" },
  },
  { tool: "recon.graphql", env: "GRAPHQL_COP_PATH", args: ["--help"] },
  { tool: "recon.cms", env: "WPSCAN_PATH", args: ["--version"] },
  { tool: "katana.crawl", env: "KATANA_PATH", args: ["-version"] },
  { tool: "recon.content_discovery", env: "FFUF_PATH", args: ["-V"] },
  { tool: "recon.sql", env: "SQLMAP_PATH", args: ["--version"] },
  { tool: "recon.xss", env: "DALFOX_PATH", args: ["--version"] },
  { tool: "recon.tls", env: "TESTSSL_PATH", args: ["--version"] },
  { tool: "recon.ports", env: "NAABU_PATH", args: ["-version"] },
  { tool: "recon.api_routes", env: "SUBJS_PATH", args: ["-h"] },
];

/** 模板/字典这类"装了但可能是空壳"的东西。 */
function checkNucleiTemplates(values: Record<string, string>, dataDir?: string): string | undefined {
  const configured = String(values.NUCLEI_TEMPLATES_PATH || process.env.NUCLEI_TEMPLATES_PATH || "").trim();
  const defaultDir = dataDir ? join(dataDir, "nuclei-templates") : "";
  // 什么都没配置：不判定（nuclei 自己会报 "no templates provided"，比在这里猜更准）
  if (!configured && !(defaultDir && existsSync(defaultDir))) return undefined;
  const dir = configured || defaultDir;
  if (!existsSync(dir)) return `nuclei 模板目录不存在：${dir}`;
  let count = 0;
  const walk = (current: string, depth: number) => {
    if (count > 0 || depth > 3) return;
    let entries: string[] = [];
    try { entries = readdirSync(current); } catch { return; }
    for (const entry of entries.slice(0, 200)) {
      const full = join(current, entry);
      let stat; try { stat = statSync(full); } catch { continue; }
      if (stat.isDirectory()) walk(full, depth + 1);
      else if (/\.ya?ml$/i.test(entry)) { count += 1; return; }
    }
  };
  walk(dir, 0);
  return count > 0 ? undefined : `nuclei 模板目录为空：${dir}（跑起来也是 0 命中）`;
}

/** semgrep 规则：recon.sast 用本地规则集，规则目录空了等于扫不出东西。 */
function checkSemgrepRules(values: Record<string, string>, dataDir?: string): string | undefined {
  const configured = String(values.SEMGREP_RULES_PATH || process.env.SEMGREP_RULES_PATH || "").trim();
  const candidates = [configured, join(process.cwd(), "resources", "semgrep"), "/opt/nianyun/resources/semgrep", dataDir ? join(dataDir, "semgrep-rules") : ""]
    .map(item => String(item || "").trim()).filter(Boolean);
  const found = candidates.find(item => existsSync(item));
  // 一个都没有：不判定 —— 执行器会带着具体参数报错，比这里猜更准
  if (!found) return undefined;
  let count = 0;
  try {
    const walk = (current: string, depth: number) => {
      if (count > 0 || depth > 2) return;
      for (const entry of readdirSync(current)) {
        const full = join(current, entry);
        let stat; try { stat = statSync(full); } catch { continue; }
        if (stat.isDirectory()) walk(full, depth + 1);
        else if (/\.ya?ml$/i.test(entry)) { count += 1; return; }
      }
    };
    if (statSync(found).isDirectory()) walk(found, 0);
    else count = 1;
  } catch { return undefined; }
  return count > 0 ? undefined : `semgrep 规则为空：${found}（扫起来也是 0 命中）`;
}

function probeBinary(probe: Probe, values: Record<string, string>, timeoutMs = 8000): Promise<PreflightEntry> {
  const binary = String(values[probe.env] || process.env[probe.env] || probe.tool.split(".").pop() || "").trim();
  return new Promise((resolve) => {
    let settled = false;
    const done = (entry: PreflightEntry) => { if (!settled) { settled = true; resolve(entry); } };
    try {
      const child = spawn(binary, probe.args, { stdio: ["ignore", "pipe", "pipe"], env: probe.envOverride ? { ...process.env, ...probe.envOverride } : process.env });
      const timer = setTimeout(() => { child.kill(); done({ tool: probe.tool, ok: false, detail: `${probe.env}=${binary} 探活超时（${timeoutMs}ms）` }); }, timeoutMs);
      child.on("error", (error) => { clearTimeout(timer); done({ tool: probe.tool, ok: false, detail: `${probe.env}=${binary} 无法执行：${String(error.message).slice(0, 160)}` }); });
      child.on("close", (code) => {
        clearTimeout(timer);
        // 很多 CLI 用 -h 退出码 1，只要进程跑起来就算可用
        done(code === null ? { tool: probe.tool, ok: false, detail: `${probe.env}=${binary} 无退出码` } : { tool: probe.tool, ok: true, detail: `${probe.env}=${binary} 可执行（exit ${code}）` });
      });
    } catch (error) {
      done({ tool: probe.tool, ok: false, detail: `${probe.env}=${binary} 启动失败：${String(error instanceof Error ? error.message : error).slice(0, 160)}` });
    }
  });
}

/** 浏览器：只查可执行文件在不在，不启动（启动太贵且会污染会话）。 */
async function checkBrowser(): Promise<PreflightEntry> {
  try {
    const { chromium } = await import("playwright");
    const executable = chromium.executablePath();
    if (!executable || !existsSync(executable)) return { tool: "browser.open", ok: false, detail: `Chromium 未安装：${executable || "(empty)"}` };
    return { tool: "browser.open", ok: true, detail: `Chromium 就绪：${executable}` };
  } catch (error) {
    return { tool: "browser.open", ok: false, detail: `playwright 不可用：${String(error instanceof Error ? error.message : error).slice(0, 160)}` };
  }
}

let cached: PreflightReport | undefined;

export function setPreflight(report: PreflightReport): PreflightReport {
  cached = { ...report, failed: [...report.failed] };
  return cached;
}

export function getPreflight(): PreflightReport | undefined {
  return cached;
}

/**
 * 执行器硬拦的判定：只拦"装了但用不了"（模板为空、探活超时）。
 * 二进制根本不存在时不拦，交给执行器原来的 `XXX_PATH` 报错——那条错误信息更具体，也避免
 * 在测试/临时环境里把整条链路提前掐死。浏览器不进硬拦集合（Chromium 路径检查会误伤）。
 */
/** 执行器用：这个工具是否已被判定为不可用。 */
export function toolBlockedReason(tool: string): string | undefined {
  const entry = cached?.entries.find(item => item.tool === tool && !item.ok && item.gate);
  return entry ? entry.detail : undefined;
}

const inflight = new Map<string, Promise<PreflightReport>>();
const MEMO_MS = 60_000;

/**
 * 同一套配置 60s 内只真跑一次：并发的 desk run（双 worker 抢同一 review）不该各跑一遍探活，
 * 否则一场 12 个二进制的探活会被算两次，把本来 2s 的用例拖到超时。
 */
function preflightKey(values: Record<string, string>, dataDir?: string): string {
  const envs = BINARY_PROBES.map(probe => `${probe.env}=${values[probe.env] || process.env[probe.env] || ""}`);
  return JSON.stringify({ dataDir: dataDir || "", envs, templates: values.NUCLEI_TEMPLATES_PATH || process.env.NUCLEI_TEMPLATES_PATH || "", semgrep_rules: values.SEMGREP_RULES_PATH || process.env.SEMGREP_RULES_PATH || "" });
}

export async function runPreflight(values: Record<string, string>, options: { dataDir?: string; timeoutMs?: number; force?: boolean } = {}): Promise<PreflightReport> {
  const key = preflightKey(values, options.dataDir);
  if (!options.force && cached && cached.ok !== undefined && Date.now() - cached.checked_at < MEMO_MS && cachedKey === key) return cached;
  const running = inflight.get(key);
  if (running) return running;
  const task = executePreflight(values, options).then(report => { cachedKey = key; return report; }).finally(() => { inflight.delete(key); });
  inflight.set(key, task);
  return task;
}

let cachedKey = "";

async function executePreflight(values: Record<string, string>, options: { dataDir?: string; timeoutMs?: number }): Promise<PreflightReport> {
  const timeoutMs = options.timeoutMs ?? 8000;
  const entries: PreflightEntry[] = [];
  const duration = await Promise.all(BINARY_PROBES.map(probe => probeBinary(probe, values, timeoutMs)));
  entries.push(...duration);
  const templates = checkNucleiTemplates(values, options.dataDir);
  if (templates) {
    const index = entries.findIndex(entry => entry.tool === "recon.nuclei");
    const detail = entries[index]?.ok ? templates : `${entries[index]?.detail || ""}；${templates}`;
    if (index >= 0) entries[index] = { tool: "recon.nuclei", ok: false, detail, gate: true };
    else entries.push({ tool: "recon.nuclei", ok: false, detail: templates, gate: true });
  }
  const rules = checkSemgrepRules(values, options.dataDir);
  if (rules) {
    const index = entries.findIndex(entry => entry.tool === "recon.sast");
    const detail = entries[index]?.ok ? rules : `${entries[index]?.detail || ""}；${rules}`;
    if (index >= 0) entries[index] = { tool: "recon.sast", ok: false, detail, gate: true };
    else entries.push({ tool: "recon.sast", ok: false, detail, gate: true });
  }
  entries.push(await checkBrowser());
  const failed = entries.filter(entry => !entry.ok).map(entry => entry.tool);
  const skipped = BINARY_PROBES.filter(probe => !String(values[probe.env] || process.env[probe.env] || "").trim()
    && !entries.some(entry => entry.tool === probe.tool)).map(probe => probe.tool);
  const report: PreflightReport = { ok: failed.length === 0, checked_at: Date.now(), entries, failed, skipped };
  return setPreflight(report);
}
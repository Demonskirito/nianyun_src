import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { chromium, request as playwrightRequest, type Browser, type BrowserContext, type Cookie, type Page } from "playwright";
import type { Config } from "../shared/config.js";
import type { Database } from "../shared/db.js";
import { checkTcp, proxyEndpoint } from "./environment.js";
import { acquire, onAbort } from "./cancellation.js";
import { canonicalTool } from "./aliases.js";
import { loadSeedsForHost, hostMatches } from "./authseed.js";
import { blackboxRules } from "./rules.js";
import { toolLayer } from "./routing.js";
import { runSandboxTool, type SandboxToolDeps } from "./sandbox_tools.js";
import { fireRace, type RaceRequest } from "./race.js";
import { analyzeTraffic, trafficSummaryLine } from "./traffic.js";
import { sandboxRpcDeps } from "./sandbox_rpc_io.js";
import { toolBlockedReason } from "./preflight.js";
import { foldTopLevelParams, TOOL_PARAMS } from "./tool-params.js";
import { cookieHeaderFor, cookiesForUrl, parseCookieHeader, parseSetCookie, type CookieRecord } from "./cookies.js";
import { applyDefaultUserAgent, hasUserAgent } from "./ua.js";
import { bodySimilarity, charNgramSimilarity, diffResponses } from "./diff.js";
import { proxyErrorPage, proxyErrorSummary } from "./proxy-error.js";
import { captureTokens, normalizeAuthInput } from "./authinput.js";
import { snapshotCredential } from "./credential.js";
import {
  fsGrep, fsList, fsRead, listWordlists, readScanProfile, recordRun, resolveApprovedAsset, resolveInsideRoots,
  runSandbox, templateRoots, wordlistRoots, writeScanProfile, type ScanProfile,
} from "./workspace.js";

// diff 核心已移到 ./diff.ts（结构化 + 时间维度）；这里保留再导出，旧调用点与测试无需改 import。
export { bodySimilarity, charNgramSimilarity, diffResponses };
import { requireExecution } from "../shared/execution.js";

export const BLACKBOX_TOOL_NAMES = [
  "browser.open", "browser.screenshot", "browser.close", "evidence.read", "http.request", "http.diff", "burp.check", "burp.request",
  "burp.history", "burp.sitemap", "burp.entry", "burp.issues", "burp.ws_history", "burp.scope", "burp.intercept",
  "burp.decoder", "burp.send", "burp.repeater", "burp.organizer", "burp.collab_generate", "burp.collab_poll",
  "burp.scan", "burp.scan_status", "burp.scan_stop",
  "burp.info", "burp.control", "burp.options", "burp.cookies", "burp.storage",
  "burp.sitemap_issues", "burp.sitemap_add", "burp.scope_edit", "burp.send_batch",
  "burp.crawl", "burp.scan_issues", "burp.scan_report", "burp.intruder",
  "burp.intruder_send", "burp.compare", "burp.convert", "burp.proxy_rule", "burp.websocket", "burp.bchecks",
  "katana.crawl",
  "recon.subdomains", "recon.dns", "recon.http_probe", "recon.ports", "recon.historical_urls",
  "recon.content_discovery", "recon.nuclei", "recon.interactsh",
  "recon.parameters", "recon.js_endpoints", "recon.tls", "recon.api_routes",
  "recon.xss", "recon.sql", "recon.jwt", "recon.graphql", "recon.cms", "recon.secrets", "recon.sast",
  // 协商 + 沙箱 + 工作区：让 Agent 能自己看字典、自己调扫描参数、自己写 POC 验证。
  "recon.wordlists", "recon.scan_profile", "recon.race_condition", "recon.traffic_diff", "exec.python", "exec.bash",
  "fs.list", "fs.read", "fs.grep", "browser.storage", "browser.tab", "browser.network",
] as const;

export type BlackboxToolName = typeof BLACKBOX_TOOL_NAMES[number];
/**
 * A request the executor refuses before touching the network or spawning a process:
 * missing configuration, a denied argument, or input the model can fix. It is not a
 * failure and must not consume the tool-call or retry budget.
 *
 * 定义已移到 ./tool-errors.ts（sandbox_tools.ts 也要用，避免循环 import），这里再导出。
 */
export { ToolRejected } from "./tool-errors.js";
import { reject, ToolRejected } from "./tool-errors.js";
export type BlackboxToolRequest = {
  tool: string;
  task_id?: string;
  reason?: string;
  input?: Record<string, unknown>;
  /** Deprecated: accepted from older model output and ignored. Tools execute directly. */
  requires_confirmation?: boolean;
};
export type BlackboxArtifact = { kind: "screenshot" | "tool-output" | "target-list"; path: string; media_type: string };
export type BlackboxToolResult = {
  tool: string;
  ok: boolean;
  summary: string;
  data: Record<string, unknown>;
  artifacts: BlackboxArtifact[];
  duration_ms: number;
};
export type BlackboxToolContext = {
  cfg: Config;
  db: Database;
  projectId: string;
  sessionId: string;
  target: string;
  values: Record<string, string>;
  deadline?: number;
  signal?: AbortSignal;
  /**
   * 历程图快照提供者（只读）。
   *
   * 单向同步：控制面把图写进 /state/graph_snapshot.json 供特种兵看，
   * 沙箱**不能**改图——所有更新必须经 RPC 回传、由 builder.ingestToolResult 统一落账，
   * 保证图状态单一事实来源（Single Source of Truth）。
   */
  graphContext?: () => Record<string, unknown>;
};

function remainingTimeout(ctx: BlackboxToolContext, timeout: number): number {
  ctx.signal?.throwIfAborted();
  if (ctx.deadline === undefined) return timeout;
  const remaining = ctx.deadline - Date.now();
  if (remaining <= 0) throw stageTimeoutError();
  // Cap one call at a share of the stage: nuclei used to take 300s of a 600s stage and leave the
  // agent no room to act on whatever it found.
  const share = Math.max(30_000, Math.floor(remaining * 0.6));
  return Math.max(1, Math.min(timeout, remaining, share));
}

/** Marks a deadline hit so callers do not bill it as a tool failure. */
function stageTimeoutError(): Error {
  const error = new Error("tool stage timeout");
  (error as Error & { timedOut: boolean }).timedOut = true;
  return error;
}

const MAX_EXTERNAL_ITEMS = 2000;
const MAX_EXTERNAL_FINDINGS = 500;
/**
 * Exit codes each tool uses to mean "ran fine, nothing to report". Without this
 * list a successful but empty scan (ffuf exits 1 with no matches) looks like a
 * crash and burns the retry budget.
 */
const ACCEPTED_EXIT_CODES: Record<string, number[]> = {
  "recon.content_discovery": [1],
  "recon.api_routes": [1],
  "recon.xss": [1],
  "recon.tls": [1],
  "recon.cms": [1],
  "recon.sast": [1], "recon.traffic_diff": [0],
  "recon.graphql": [1],
  "recon.parameters": [1],
};
export function toolExitAccepted(tool: string, code: number): boolean {
  return code === 0 || (ACCEPTED_EXIT_CODES[tool] || []).includes(code);
}
/** Per-tool lower bound: do not start a tool when the batch has less time left. */
const MIN_TOOL_SECONDS: Record<string, number> = {
  "recon.sql": 90, "recon.sast": 90, "recon.tls": 60, "recon.nuclei": 40,
  "recon.api_routes": 45, "recon.xss": 45, "recon.cms": 45, "recon.graphql": 30,
  "recon.secrets": 30, "recon.parameters": 30, "recon.js_endpoints": 20,
  "recon.ports": 20, "recon.content_discovery": 20, "recon.interactsh": 10,
  "katana.crawl": 10, "recon.subdomains": 15, "recon.dns": 15, "recon.http_probe": 15,
  "recon.historical_urls": 20, "recon.jwt": 5, "http.diff": 5,
};
export function blackboxToolMinDurationMs(tool: string): number {
  const normalized = canonicalTool(tool);
  return (MIN_TOOL_SECONDS[normalized] ?? 5) * 1000;
}
const BLOCKED_REQUEST_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding", "upgrade", "proxy-connection", "expect", "te", "trailer"]);
const SENSITIVE_HEADER = /cookie|authorization|proxy-authorization|token|api[-_]?key|secret|session/i;
const SENSITIVE_FIELD = /password|passwd|token|secret|api[-_]?key|authorization|cookie|session/i;
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function boolValue(value: string | undefined, fallback: boolean): boolean {
  if (value == null || !String(value).trim()) return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).trim().toLowerCase());
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function httpUrl(raw: unknown, fallback: string): string {
  const value = String(raw || fallback).trim();
  if (!value || value.length > 4096) throw reject("tool URL is missing or too long");
  let url: URL;
  try { url = new URL(value); } catch { throw reject("tool URL is invalid"); }
  if (!["http:", "https:"].includes(url.protocol)) throw reject("only HTTP(S) targets are supported");
  if (url.username || url.password) throw reject("target URL must not contain credentials");
  url.hash = "";
  return url.toString();
}

function proxy(ctx: BlackboxToolContext, required = false): string | undefined {
  const raw = String(ctx.values.BURP_PROXY_URL || "").trim();
  if (!raw && (required || boolValue(ctx.values.BURP_PROXY_REQUIRED, true))) throw reject("Burp proxy is required but not configured");
  return raw ? proxyEndpoint(raw).url : undefined;
}

function artifactDirectory(ctx: BlackboxToolContext): { absolute: string; relative: string } {
  const relative = join("blackbox-artifacts", ctx.projectId, ctx.sessionId);
  const absolute = resolve(join(ctx.cfg.data_dir, relative));
  const root = resolve(join(ctx.cfg.data_dir, "blackbox-artifacts"));
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) throw reject("invalid artifact directory");
  mkdirSync(absolute, { recursive: true });
  return { absolute, relative };
}

function artifactPath(ctx: BlackboxToolContext, extension: string): { absolute: string; relative: string } {
  const dir = artifactDirectory(ctx);
  const name = `${Date.now()}-${randomBytes(4).toString("hex")}.${extension}`;
  return { absolute: join(dir.absolute, name), relative: join(dir.relative, name).replaceAll("\\", "/") };
}

function optionalProxy(ctx: BlackboxToolContext): string | undefined {
  const raw = String(ctx.values.BURP_PROXY_URL || "").trim();
  return raw ? proxyEndpoint(raw).url : undefined;
}

type ExternalFlags = {
  /** Repeatable header flag, e.g. `-H` or `--headers`. */
  header?: string;
  /**
   * 多个头怎么塞进 `header`：
   * - `repeat`（默认）：每个头一条 `-H`，httpx/nuclei/katana/dalfox/ffuf 都是这个语义；
   * - `lines`：合成一条 `--headers`，值用换行分隔——sqlmap 的 `--headers` 只取一个值，
   *   重复传会让前面的头被静默丢掉（实测：默认 UA + 模型自带的 Cookie 一起传时，
   *   只剩最后一条生效，看起来像"目标不认凭证"）。
   */
  headerStyle?: "repeat" | "lines";
  /** Cookie flag; with `cookieStyle: "header"` the value keeps its `Cookie:` prefix. */
  cookie?: string;
  cookieStyle?: "header" | "raw";
  /** Proxy flag. The proxy itself always comes from operator config, never from the model. */
  proxy?: string;
};

/**
 * 高危参数分两档（对应 §10 的"专业改法"）：
 * - interactive：需要 Operator 明确打开 `BLACKBOX_ALLOW_INTERACTIVE_EXEC=true` 才放行，
 *   且只放行"单次命令、有输出"的形态（--os-cmd / --sql-query / --file-read / --file-write）。
 * - 永久禁止：持续性交互 shell（--os-shell / --sql-shell / --os-pwn）、本地命令执行
 *   （--eval / --input-cmd / --code）——它们给的是"一个挂着的 shell"，不适合自动化账本。
 * 目标覆盖（-u/-l/-host…）仍然禁止：目标由调度器持有。
 */
const DENIED_ARG_TOKENS: Record<string, string> = {
  "--os-shell": "interactive OS shell", "--sql-shell": "interactive SQL shell", "--os-pwn": "interactive OS shell",
  "--os-smbrelay": "interactive OS shell",
  "--eval": "script evaluation", "--input-cmd": "local command execution", "-input-cmd": "local command execution",
  "-code": "code templates", "--code": "code templates", "-enable-code": "code templates", "--enable-code": "code templates",
  "--autofix": "source rewriting",
  // Target overrides: the scheduler owns the target, a tool call may not move it.
  "-u": "target override", "--url": "target override", "-host": "target override", "--host": "target override",
  "-d": "target override", "--domain": "target override", "-target": "target override", "--target": "target override",
  "-l": "target list override", "-list": "target list override", "--list": "target list override",
  // File writes and local file reads.
  "-o": "output file", "--output": "output file", "-oj": "output file", "-oJ": "output file", "-od": "output file",
  "--output-dir": "output file", "--log": "log file", "--logfile": "log file", "--json-out": "output file",
  "--sarif-export": "output file", "--report": "output file", "-of": "output file", "-c": "config file",
  "--config": "config file", "-r": "request file", "--request": "request file", "--rawfile": "request file",
  "--payload-file": "payload file", "--custom-payload": "payload file",
};

/** 需要 Operator 打开交互式执行才允许的参数：单命令、有输出，不是挂着的 shell。 */
const INTERACTIVE_ARG_TOKENS: Record<string, string> = {
  "--os-cmd": "single OS command execution",
  "--sql-query": "arbitrary SQL query",
  "--file-read": "target file read", "--file-write": "target file write", "--file-dest": "target file write",
};

/** 会被改写成 Operator 代理的 token：SRC 必须允许 Agent 自己指定代理，但出口始终走内部 MITM。 */
const PROXY_ARG_TOKENS = new Set(["-proxy", "--proxy", "-x", "--http-proxy", "-http-proxy", "--socks5"]);

export type ExtraArgOptions = {
  allowCredentialAttack?: boolean;
  /** 交互式执行开关：来自 BLACKBOX_ALLOW_INTERACTIVE_EXEC。 */
  interactive?: boolean;
  /** 只读字典根目录：-w/--wordlist 的值必须落在其中之一。 */
  wordlistRoots?: string[];
  /** 只读模板根目录：-t/--templates 的值必须落在其中之一。 */
  templateRoots?: string[];
  /** Operator 配置的代理：任何代理参数都会被改写成它。 */
  proxyUrl?: string;
  /** 回传"被改写/被丢弃"的说明，最终写进结果里让模型知道发生了什么。 */
  onNote?: (note: string) => void;
};

/** Model-supplied CLI arguments, with the dangerous tokens removed and the rest negotiated. */
export function extraToolArgs(tool: string, raw: unknown, options: ExtraArgOptions = {}): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw reject("input.args must be an array of strings");
  if (raw.length > 40) throw reject("input.args supports at most 40 arguments");
  const resolveInside = (value: string, roots: string[] | undefined, label: string): string => {
    try {
      return resolveInsideRoots(value, roots || [], label, "; call recon.wordlists first");
    } catch (error) {
      throw reject(error instanceof Error ? error.message : String(error));
    }
  };
  const args: string[] = [];
  for (let index = 0; index < raw.length; index += 1) {
    const item = raw[index];
    if (typeof item !== "string") throw reject("input.args entries must be strings");
    const value = item.trim();
    if (!value || value.length > 512) throw reject("input.args entries must be 1 to 512 characters");
    if (/[\u0000\r\n]/.test(value)) throw reject("input.args entries must not contain control characters");
    const token = value.split("=")[0]!.toLowerCase();
    const inline = value.includes("=") ? value.slice(value.indexOf("=") + 1) : "";
    const takeValue = (): string => {
      if (inline) return inline;
      const next = raw[index + 1];
      if (typeof next !== "string" || !next.trim()) throw reject(`${tool} argument ${token} requires a value`);
      index += 1;
      return next.trim();
    };
    const interactiveReason = INTERACTIVE_ARG_TOKENS[token];
    if (interactiveReason) {
      if (options.interactive !== true) {
        throw reject(`${tool} argument ${token} is not allowed in automated mode (${interactiveReason}); an operator can enable BLACKBOX_ALLOW_INTERACTIVE_EXEC=true for a supervised interactive run`);
      }
      args.push(value);
      // 操作员开一次、整场可用（不做 per-call 确认）；但每次放行都留一条 note 进 tool-result，
      // 报告里能看到"哪条高危命令、在哪一轮被用过"。
      options.onNote?.(`高危参数已放行：${token}（${interactiveReason}；BLACKBOX_ALLOW_INTERACTIVE_EXEC=true）`);
      continue;
    }
    const reason = DENIED_ARG_TOKENS[token];
    if (reason) throw reject(`${tool} argument ${token} is not allowed (${reason})`);
    // 代理：允许 Agent 自己指定（SRC 深度依赖 Burp/ZAP 重放），但出口一律改写成 Operator 的内部 MITM。
    if (PROXY_ARG_TOKENS.has(token)) {
      const requested = inline || (typeof raw[index + 1] === "string" ? String(raw[index + 1]).trim() : "");
      if (!inline && requested) index += 1;
      if (!options.proxyUrl) {
        options.onNote?.(`${token} 已忽略：未配置内部代理（BURP_PROXY_URL）`);
        continue;
      }
      args.push(token, options.proxyUrl);
      options.onNote?.(`${token} 已改写为内部 MITM 代理 ${options.proxyUrl}（出站流量统一留痕）`);
      continue;
    }
    // 字典/模板：不再一刀切禁用，改为"只能指向只读挂载目录里的文件"。
    if (token === "-w" || token === "--wordlist") {
      args.push(token, resolveInside(takeValue(), options.wordlistRoots, "wordlist"));
      continue;
    }
    if (token === "-t" || token === "--templates") {
      args.push(token, resolveInside(takeValue(), options.templateRoots, "template"));
      continue;
    }
    if (token === "--passwords" || token === "--usernames") {
      // Credential attacks are off by default: they cause lockouts and traffic spikes that a
      // scan does not. The rules document can switch them on per tool, and the password list
      // must still live inside the approved wordlist directory.
      if (options.allowCredentialAttack !== true) {
        throw reject(`${tool} argument ${token} is not allowed (credential attack is disabled; set tools["${tool}"].allow_credential_attack=true to enable it)`);
      }
      const listFile = resolveInside(takeValue(), options.wordlistRoots, "wordlist");
      args.push(token, listFile);
      continue;
    }
    args.push(value);
  }
  return args;
}

/**
 * Auth, cookie and proxy wiring every external tool needs to match a hand-run command:
 * the project cookie jar and the configured Burp proxy are injected automatically, and
 * explicit `input.headers` are forwarded as the tool's native header flag.
 */
export function commonToolArgs(spec: { tool: string; flags?: ExternalFlags }, input: Record<string, unknown>, ctx: BlackboxToolContext, target: string): string[] {
  const args: string[] = [];
  const flags = spec.flags;
  if (!flags) return args;
  const headers = requestHeaders(input.headers);
  /**
   * 外部扫描器（httpx/nuclei/katana/dalfox/sqlmap/wpscan/ffuf）默认会亮出自己的工具名 UA，
   * 这在遇到"只放行浏览器"的网关时等于自报家门——实测被统一 403/7155B 打回，
   * 一整场扫描拿不到一条真正文。这里统一补浏览器身份，显式 `headers["user-agent"]` 仍然优先。
   */
  applyDefaultUserAgent(headers, ctx.values);
  if (flags.header) {
    if (flags.headerStyle === "lines") {
      // 单值 flag（sqlmap）：多行合成一个参数，否则后传的头会把前面的挤掉。
      const lines = Object.entries(headers).map(([name, value]) => `${name}: ${value}`);
      if (lines.length) args.push(flags.header, lines.join("\n"));
    } else {
      for (const [name, value] of Object.entries(headers)) args.push(flags.header, `${name}: ${value}`);
    }
  }
  if (flags.cookie && !headers.cookie) {
    const jar = ctx.db && typeof ctx.db.getProjectCookies === "function" ? ctx.db.getProjectCookies(ctx.projectId) : [];
    const cookie = cookieHeaderFor(jar, target);
    if (cookie) args.push(flags.cookie, flags.cookieStyle === "raw" ? cookie : `Cookie: ${cookie}`);
  }
  const proxyUrl = optionalProxy(ctx);
  if (flags.proxy && proxyUrl) args.push(flags.proxy, proxyUrl);
  return args;
}

/** nuclei JSONL keeps severity/template metadata; a bare URL loses what makes it actionable. */
export function parseNucleiLine(line: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    const info = (parsed.info && typeof parsed.info === "object" ? parsed.info : {}) as Record<string, unknown>;
    const matched = String(parsed["matched-at"] || parsed.url || parsed.host || parsed.input || "").trim();
    if (!matched) return null;
    return {
      url: matched.slice(0, 4096),
      template_id: String(parsed["template-id"] || "").slice(0, 200),
      name: String(info.name || "").slice(0, 300),
      severity: String(info.severity || "").toLowerCase(),
      type: String(parsed.type || "").slice(0, 60),
      host: String(parsed.host || "").slice(0, 300),
      matcher: String(parsed["matcher-name"] || "").slice(0, 200),
      tags: Array.isArray(info.tags) ? info.tags.map(String).slice(0, 20) : [],
      extracted: Array.isArray(parsed["extracted-results"]) ? parsed["extracted-results"].map(String).slice(0, 20) : [],
    };
  } catch { return null; }
}

/** httpx JSONL keeps status, title and technology, which discovery needs downstream. */
export function parseHttpxLine(line: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    const url = String(parsed.url || parsed.input || parsed.host || "").trim();
    if (!url) return null;
    return {
      url: url.slice(0, 4096),
      status_code: Number(parsed.status_code || 0) || null,
      title: String(parsed.title || "").slice(0, 300),
      webserver: String(parsed.webserver || "").slice(0, 200),
      tech: Array.isArray(parsed.tech) ? parsed.tech.map(String).slice(0, 20) : [],
      content_length: Number(parsed.content_length || 0) || null,
      final_url: String(parsed.final_url || "").slice(0, 4096),
    };
  } catch { return null; }
}

/**
 * 过滤受限请求头，并把被丢掉的名字一并带出来。
 *
 * 这里原本是静默丢弃：`host` 在 BLOCKED_REQUEST_HEADERS 里，模型以为发了
 * `Host: evil.example`，执行器把它删了，进度记录（progress.ts identity）记的也是
 * 过滤后的头，于是证据里只剩 user-agent。模型只能看到"响应没变"，就一遍遍重发，
 * Host 头注入这类任务会在"请求没变→响应没变"的循环里空转到会话结束。
 * 所以丢弃必须可见：谁被丢了、为什么丢、该换哪个工具。
 */
export function requestHeadersWithDropped(input: unknown): { headers: Record<string, string>; dropped: string[] } {
  const headers: Record<string, string> = {};
  const dropped: string[] = [];
  if (!input || typeof input !== "object" || Array.isArray(input)) return { headers, dropped };
  for (const [rawName, rawValue] of Object.entries(input as Record<string, unknown>).slice(0, 100)) {
    const name = rawName.trim().toLowerCase();
    const value = String(rawValue ?? "").trim();
    if (!HEADER_NAME.test(name) || BLOCKED_REQUEST_HEADERS.has(name) || !value || value.length > 8192 || /[\r\n]/.test(value)) {
      dropped.push(name || rawName);
      continue;
    }
    headers[name] = value;
  }
  return { headers, dropped };
}

export function requestHeaders(input: unknown): Record<string, string> {
  return requestHeadersWithDropped(input).headers;
}

/** 被丢弃的头的统一提示语：告诉模型"这条路不通"，而不是让它继续重发。 */
export function droppedHeaderNote(dropped: string[]): string {
  if (!dropped.length) return "";
  const hostlike = dropped.filter(name => ["host", "connection", "expect"].includes(name));
  const tail = hostlike.length
    ? "；Host 类变体请改用 burp.send（原始报文可自定义 Host）"
    : "";
  return ` ⚠ 已忽略受限头 ${dropped.join(", ")}（传输层保留头，工具不允许改写）${tail}`;
}


export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    output[name] = SENSITIVE_HEADER.test(name) ? "[redacted]" : value.slice(0, 512);
  }
  return output;
}

function maskSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(maskSecrets);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [
    key, SENSITIVE_FIELD.test(key) ? "[redacted]" : maskSecrets(item),
  ]));
}

function redactPayload(value: unknown, kind: "body" | "json" | "form" | "multipart"): unknown {
  if (kind === "multipart") {
    if (!Array.isArray(value)) return "[redacted]";
    return value.map((item) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) return "[redacted]";
      const record = item as Record<string, unknown>;
      const content = String(record.content_base64 || "");
      return {
        name: String(record.name || "").slice(0, 100),
        ...(content ? { file_bytes: Math.floor(content.length * 3 / 4) } : { value: SENSITIVE_FIELD.test(String(record.name || "")) ? "[redacted]" : String(record.value || "").slice(0, 2048) }),
        ...(record.filename ? { filename: String(record.filename).slice(0, 255) } : {}),
        ...(record.content_type ? { content_type: String(record.content_type).slice(0, 255) } : {}),
      };
    }).slice(0, 50);
  }
  if (kind === "form") {
    if (!value || typeof value !== "object" || Array.isArray(value)) return "[redacted]";
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key, SENSITIVE_FIELD.test(key) ? "[redacted]" : String(item).slice(0, 2048),
    ]));
  }
  if (kind === "json") return maskSecrets(value);
  const text = String(value ?? "");
  try {
    return maskSecrets(JSON.parse(text));
  } catch {
    return text.slice(0, 8192);
  }
}

function bodySize(body: { data?: string | Buffer; form?: Record<string, unknown>; multipart?: Record<string, unknown> }): number {
  if (body.data !== undefined) return Buffer.byteLength(body.data);
  if (body.form) return Buffer.byteLength(new URLSearchParams(Object.entries(body.form).map(([k, v]) => [k, String(v)] as [string, string])).toString());
  if (body.multipart) {
    return Object.values(body.multipart).reduce<number>((total, part) => {
      if (!part || typeof part !== "object") return total + Buffer.byteLength(String(part ?? ""));
      const payload = part as Record<string, unknown>;
      if (Buffer.isBuffer(payload.buffer)) return total + payload.buffer.length;
      return total + Buffer.byteLength(String(payload.value ?? ""));
    }, 0);
  }
  return 0;
}

function requestBody(
  input: Record<string, unknown>,
  method: string,
  headers: Record<string, string>,
  maxBytes: number,
): { data?: string | Buffer; form?: Record<string, string | number | boolean>; multipart?: Record<string, unknown> } {
  const kinds = ["body", "body_base64", "json", "form", "multipart"].filter((key) => input[key] !== undefined);
  if (method === "HEAD" && kinds.length) throw reject("HEAD requests cannot carry a body");
  if (kinds.length > 1) throw reject("use only one of body, body_base64, json, form, multipart");
  if (!kinds.length) return {};
  let body: { data?: string | Buffer; form?: Record<string, string | number | boolean>; multipart?: Record<string, unknown> };
  if (input.body_base64 !== undefined) {
    try {
      body = { data: Buffer.from(String(input.body_base64), "base64") };
    } catch {
      throw reject("body_base64 is not valid base64");
    }
  } else if (input.body !== undefined) {
    body = { data: String(input.body) };
    if (!headers["content-type"]) headers["content-type"] = "application/octet-stream";
  } else if (input.json !== undefined) {
    body = { data: JSON.stringify(input.json) };
    if (!headers["content-type"]) headers["content-type"] = "application/json";
  } else if (input.form !== undefined) {
    if (!input.form || typeof input.form !== "object" || Array.isArray(input.form)) throw reject("form must be an object");
    body = { form: input.form as Record<string, string | number | boolean> };
    if (!headers["content-type"]) headers["content-type"] = "application/x-www-form-urlencoded";
  } else {
    const parts = Array.isArray(input.multipart) ? input.multipart : [];
    if (!parts.length) throw reject("multipart must be a non-empty array");
    const converted: Record<string, unknown> = {};
    for (const raw of parts) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw reject("multipart item must be an object");
      const item = raw as Record<string, unknown>;
      const name = String(item.name || "").trim();
      if (!name) throw reject("multipart item requires name");
      if (item.content_base64 !== undefined) {
        converted[name] = {
          name: String(item.filename || name),
          mimeType: String(item.content_type || "application/octet-stream"),
          buffer: Buffer.from(String(item.content_base64), "base64"),
        };
      } else {
        converted[name] = String(item.value ?? "");
      }
    }
    body = { multipart: converted };
    delete headers["content-type"];
  }
  const size = bodySize(body);
  if (size > maxBytes) throw reject(`request body exceeds ${maxBytes} bytes`);
  return body;
}

/** Free-form CLI arguments can carry `-H "Authorization: ..."`: mask the values, keep the shape. */
export function redactArgs(value: unknown): unknown {
  if (!Array.isArray(value)) return "[invalid]";
  const HEADER_FLAG = /^--?(h|header|headers|cookie|cookies)$/i;
  let previous = "";
  return value.slice(0, 40).map((item) => {
    const text = String(item ?? "").slice(0, 512);
    const masked = text.replace(/\b(authorization|cookie|set-cookie|token|secret|password|api[-_]?key)\s*([:=])\s*.*$/gi, "$1$2[redacted]");
    const row = HEADER_FLAG.test(previous) ? masked.replace(/^([^:]+):.*$/, "$1: [redacted]") : masked;
    previous = text;
    return row;
  });
}

function ledgerInput(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>).slice(0, 40)) {
    if (key === "headers") output[key] = redactHeaders(requestHeaders(value));
    else if (key === "body_base64") output[key] = `[base64 ${String(value ?? "").length} chars]`;
    else if (key === "body" || key === "json" || key === "form" || key === "multipart") {
      output[key] = redactPayload(value, key === "json" ? "json" : key === "multipart" ? "multipart" : key === "form" ? "form" : "body");
    }
    else if (key === "args") output.args = redactArgs(value);
    else if (key === "params") {
      // `sqlmap --data` is a request body: keep the knob list, redact the payload.
      const bag = value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
      output.params = Object.fromEntries(Object.entries(bag).slice(0, 32).map(([name, item]) =>
        [name, name === "data" ? redactPayload(item, "body") : typeof item === "string" ? item.slice(0, 512) : item]));
    }
    else if (/token|secret|password|authorization|cookie|api[_-]?key/i.test(key)) output[key] = "[redacted]";
    else if (typeof value === "string") output[key] = value.slice(0, 4096);
    else if (typeof value === "number" || typeof value === "boolean" || value == null) output[key] = value;
    else output[key] = JSON.stringify(value).slice(0, 4096);
  }
  return output;
}

function responseHeaders(headers: Record<string, string>): Record<string, string> {
  const names = [
    "content-type", "content-length", "location", "server", "x-powered-by", "www-authenticate",
    "allow", "set-cookie", "strict-transport-security", "content-security-policy", "x-frame-options",
    "access-control-allow-origin", "access-control-allow-credentials", "vary", "cache-control", "pragma",
  ];
  return Object.fromEntries(names.flatMap((name) => headers[name] ? [[name, headers[name]!]] : []));
}

type PlaywrightCookieParam = {
  name: string;
  value: string;
  url?: string;
  domain?: string;
  path?: string;
  expires?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
};

function toPlaywrightCookie(cookie: CookieRecord, target: string): PlaywrightCookieParam {
  const base: PlaywrightCookieParam = {
    name: cookie.name,
    value: cookie.value,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    expires: cookie.expires ?? -1,
    ...(cookie.sameSite ? { sameSite: (cookie.sameSite[0]!.toUpperCase() + cookie.sameSite.slice(1)) as PlaywrightCookieParam["sameSite"] } : {}),
  };
  if (cookie.hostOnly) {
    const url = new URL(target);
    url.pathname = cookie.path || "/";
    url.search = "";
    url.hash = "";
    return { ...base, url: url.toString() };
  }
  return { ...base, domain: cookie.domain, path: cookie.path || "/" };
}

function fromPlaywrightCookie(cookie: Cookie, now = Date.now() / 1000): CookieRecord | null {
  const name = String(cookie.name || "");
  const value = String(cookie.value || "");
  const domain = String(cookie.domain || "").toLowerCase().replace(/^\./, "");
  if (!name || !domain) return null;
  const expires = Number(cookie.expires);
  const sameSite = String(cookie.sameSite || "").toLowerCase();
  return {
    name,
    value,
    domain,
    path: String(cookie.path || "/"),
    hostOnly: !String(cookie.domain || "").startsWith("."),
    secure: cookie.secure === true,
    httpOnly: cookie.httpOnly === true,
    ...(sameSite === "strict" || sameSite === "lax" || sameSite === "none" ? { sameSite } : {}),
    expires: Number.isFinite(expires) && expires > 0 ? Math.floor(expires) : expires === -1 ? null : Math.floor(now + 86400),
  };
}

type BrowserNetworkEntry = {
  at: number;
  method: string;
  url: string;
  resource_type: string;
  status?: number;
  post_data?: string;
};

type BrowserSession = {
  browser: Browser; context: BrowserContext;
  pages: Page[]; page: Page;
  lastUsed: number; key: string;
  /** 渲染期真实发出的请求（browser.network 的数据源）。 */
  network: BrowserNetworkEntry[];
};
const browserSessions = new Map<string, BrowserSession>();
const BROWSER_NETWORK_MAX = 800;

/**
 * 渲染期网络捕获（2026-10-31 补的能力缺口）。
 *
 * 2026-10-31 的 m.ctrip.com 会话里，主 Agent 5 次尝试用 `exec.python` 拿渲染期的 XHR，
 * 全部因为 `code` 不在输入 schema 里变成空 `input:{}`；`browser.open` 只回截图与 DOM，
 * 于是 SPA 的真实接口一条都没进图。这里在 page 上挂 request/response 监听，
 * 让"页面实际调了哪些接口"变成一次 `browser.network` 就能取回的事实。
 */
function attachNetwork(page: Page, session: BrowserSession): void {
  // 增益能力，必须对"残缺 page"（测试替身、被取消的导航）免疫：挂不上监听就跳过，
  // 绝不能让 browser.open 因为记录网络而失败。
  const hook = page as unknown as { on?: unknown };
  if (typeof hook?.on !== "function") return;
  session.network ||= [];
  const pending = new WeakMap<object, BrowserNetworkEntry>();
  try {
    page.on("request", (request) => {
      try {
        const url = request.url();
        if (!/^https?:/i.test(url)) return;
        const entry: BrowserNetworkEntry = {
          at: Date.now(),
          method: request.method(),
          url,
          resource_type: request.resourceType() || "other",
          ...(request.postData() ? { post_data: String(request.postData()).slice(0, 4000) } : {}),
        };
        session.network.push(entry);
        if (session.network.length > BROWSER_NETWORK_MAX) session.network.splice(0, session.network.length - BROWSER_NETWORK_MAX);
        pending.set(request as unknown as object, entry);
      } catch { /* 监听器出错不能影响页面 */ }
    });
    page.on("response", (response) => {
      try {
        const entry = pending.get(response.request() as unknown as object);
        if (entry) entry.status = response.status();
      } catch { /* ignore */ }
    });
  } catch { /* 监听挂载失败只影响 browser.network，不影响浏览器主流程 */ }
}

/** 同注册域判定（ctrip.com 与 m.ctrip.com / vacations.ctrip.com 视为同域）。 */
function sameRegistrableDomain(a: string, b: string): boolean {
  const tail = (host: string) => host.split(".").filter(Boolean).slice(-2).join(".");
  return Boolean(a) && Boolean(b) && tail(a) === tail(b);
}
/** Untouched sessions are closed after this long; the model can also call browser.close. */
// SPA / 复杂登录流程 5s 加载不完、tab 5 个不够用：放宽到 12 tab、30 分钟闲置。
const BROWSER_IDLE_MS = 30 * 60_000;
const BROWSER_MAX_TABS = 12;
const BROWSER_LAUNCH_MS = 45_000;

function browserKey(ctx: BlackboxToolContext): string { return `${ctx.projectId}:${ctx.sessionId}`; }

/** Close one session (or every session of a project); used by cancel, shutdown and browser.close. */
export async function closeBrowserSessions(projectId?: string, sessionId?: string): Promise<number> {
  let closed = 0;
  for (const [key, session] of [...browserSessions]) {
    const [pid] = key.split(":");
    if (projectId && pid !== projectId) continue;
    if (sessionId && key !== `${projectId}:${sessionId}`) continue;
    browserSessions.delete(key);
    closed += 1;
    await session.browser.close().catch(() => {});
  }
  return closed;
}

async function sweepBrowserSessions(): Promise<void> {
  const now = Date.now();
  for (const [key, session] of [...browserSessions]) {
    if (now - session.lastUsed < BROWSER_IDLE_MS) continue;
    browserSessions.delete(key);
    await session.browser.close().catch(() => {});
  }
}

async function browserTool(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  await sweepBrowserSessions();
  const key = browserKey(ctx);
  const explicitUrl = input.url === undefined ? "" : httpUrl(input.url, ctx.target);
  const headers = requestHeaders(input.headers);
  const explicitCookie = headers.cookie;
  delete headers.cookie;
  let jar = ctx.db.getProjectCookies(ctx.projectId);
  const cookieBase = explicitUrl || ctx.target;
  let seededHost: string | undefined;
  if (explicitCookie) {
    jar = ctx.db.mergeProjectCookies(ctx.projectId, parseCookieHeader(explicitCookie, cookieBase));
  }
  // One browser per session: login state, localStorage and open tabs survive across calls,
  // which is what makes a multi-step flow possible without replaying it every time.
  let session = browserSessions.get(key);
  // Operator cancel/pause aborts the run signal: release the browser so nothing keeps
  // running. A stage deadline does not abort the signal, so the session survives those.
  const stop = onAbort(ctx.signal, () => { void closeBrowserSessions(ctx.projectId, ctx.sessionId); });
  try {
    if (!session) {
      const proxyUrl = proxy(ctx);
      // 阶段预算太紧时不要硬启动浏览器：之前实测出现过 "launch: Timeout 5115ms exceeded"，
      // 因为把剩余阶段时间当成了启动超时。这里给启动一个独立下限，剩余不足就明确拒绝。
      const remaining = ctx.deadline === undefined ? BROWSER_LAUNCH_MS : ctx.deadline - Date.now();
      if (remaining < 8_000) throw reject(`stage deadline is too tight to start a browser (${Math.max(0, Math.round(remaining / 1000))}s left); run browser steps in an earlier round`);
      const browser = await chromium.launch({ headless: true, timeout: Math.min(BROWSER_LAUNCH_MS, Math.max(8_000, remaining)), ...(proxyUrl ? { proxy: { server: proxyUrl } } : {}) })
        .catch((cause: unknown) => { throw reject(`browser is not available: ${cause instanceof Error ? cause.message : String(cause)}`); });
      const context = await browser.newContext({
        ignoreHTTPSErrors: boolValue(ctx.values.BURP_IGNORE_HTTPS_ERRORS, false),
        viewport: { width: 1440, height: 900 },
        extraHTTPHeaders: headers,
      });
      const first = await context.newPage();
      browser.on?.("disconnected", () => { if (browserSessions.get(key)?.browser === browser) browserSessions.delete(key); });
      session = { browser, context, pages: [first], page: first, lastUsed: Date.now(), key, network: [] };
      browserSessions.set(key, session);
      attachNetwork(first, session);
    } else if (input.new_tab === true) {
      const tab = await session.context.newPage();
      session.pages.push(tab);
      session.page = tab;
      attachNetwork(tab, session);
      while (session.pages.length > BROWSER_MAX_TABS) {
        const oldest = session.pages.find((candidate) => candidate !== session!.page);
        if (!oldest) break;
        await oldest.close().catch(() => {});
        session.pages = session.pages.filter((candidate) => candidate !== oldest);
      }
    }
    session.lastUsed = Date.now();
    if (input.headers !== undefined) await session.context.setExtraHTTPHeaders(headers).catch(() => {});
    const stored = cookiesForUrl(jar, cookieBase).map((cookie) => toPlaywrightCookie(cookie, cookieBase));
    if (stored.length) await session.context.addCookies(stored).catch(() => {});
    // 认证种子注入：人工在真实浏览器登录后导出的 storageState，按主机名自动注入，
    // agent 开局即已登录，无需自己走登录流程（避免卡验证码 / MFA / SSO）。
    const seedHost = new URL(cookieBase).hostname;
    const seed = loadSeedsForHost(seedHost);
    if (seed && seed.cookies.length) {
      const pwCookies = seed.cookies
        .filter((c) => hostMatches(seedHost, String(c.domain ?? "")))
        .map((c) => {
          const rec = c as Record<string, unknown>;
          const sameSite = rec.sameSite;
          return {
            name: rec.name,
            value: rec.value,
            domain: rec.domain,
            path: rec.path || "/",
            expires: typeof rec.expires === "number" ? rec.expires : undefined,
            httpOnly: rec.httpOnly === true,
            secure: rec.secure === true,
            sameSite: sameSite === "Strict" || sameSite === "Lax" || sameSite === "None" ? sameSite : undefined,
          } as Cookie;
        })
        .filter((c) => Boolean(c.name));
      if (pwCookies.length) {
        await session.context.addCookies(pwCookies).catch(() => {});
        const records = pwCookies.map((c) => fromPlaywrightCookie(c)).filter((c): c is CookieRecord => Boolean(c));
        if (records.length) ctx.db.mergeProjectCookies(ctx.projectId, records);
        seededHost = seedHost;
      }
    }
    const page = session.page;
    const pageUrl = () => { try { return page.url(); } catch { return ""; } };
    // `browser.open` without a url on a live session just re-describes the current page.
    const target = explicitUrl || (pageUrl() === "about:blank" ? httpUrl(undefined, ctx.target) : "");
    let response: { status(): number } | null = null;
    if (target && target !== pageUrl()) {
      response = await page.goto(target, { waitUntil: "domcontentloaded", timeout: remainingTimeout(ctx, boundedInteger(input.timeout_ms, 30_000, 1000, 60_000)) });
      // 现代 SPA 不能靠死等固定时间：优先按元素/网络空闲等，等不到才回落。
      const waitSelector = String(input.wait_for_selector || "").trim();
      if (waitSelector) {
        await page.waitForSelector(waitSelector, { timeout: remainingTimeout(ctx, boundedInteger(input.wait_timeout_ms, 20_000, 500, 60_000)), state: "attached" }).catch(() => {});
      } else if (input.wait_until === "networkidle") {
        await page.waitForLoadState("networkidle", { timeout: remainingTimeout(ctx, 20_000) }).catch(() => {});
      }
      const extraWait = boundedInteger(input.wait_ms, 500, 0, 30_000);
      if (extraWait) await page.waitForTimeout(extraWait);
      /**
       * 代理错误页在浏览器侧同样会"加载成功"。
       *
       * 目标不可达时 Burp 用自己的错误页顶替响应，Chromium 拿到的是 200 的 HTML，
       * `browser.open` 会把它报成渲染成功——实测 wxmc 那场里 browser.open 就这么过了，
       * 之后 `browser.network` 抓到的也是错误页自己的请求，整条 SPA 逆向链全是空转。
       */
      const rendered = await page.content().catch(() => "");
      const proxiedPage = rendered ? proxyErrorPage({ status: response?.status(), body: rendered.slice(0, 64 * 1024) }) : undefined;
      if (proxiedPage) {
        return {
          tool, ok: false,
          summary: proxyErrorSummary(proxiedPage, { method: "BROWSER", url: target, status: response?.status(), bytes: rendered.length }),
          data: {
            proxy_error: true, proxy_vendor: proxiedPage.vendor, proxy_marker: proxiedPage.marker,
            ...(proxiedPage.detail ? { proxy_detail: proxiedPage.detail } : {}),
            url: target, status: response?.status() ?? null, html_bytes: rendered.length,
            hint: "浏览器加载的是代理错误页，不是目标页面。换可达主机或修好出网代理再渲染。",
          },
          artifacts: [],
        };
      }
    }
    // 种子来源地的 localStorage / sessionStorage 也一并灌入（很多 SPA 用 token 而非 cookie 鉴权）。
    if (seed && seed.origins.length) {
      for (const o of seed.origins) {
        let originHost = "";
        try {
          originHost = new URL(o.origin).hostname;
        } catch {
          continue;
        }
        if (!hostMatches(seedHost, originHost)) continue;
        const local = (o.localStorage || []).slice(0, 200);
        const sess = (o.sessionStorage || []).slice(0, 200);
        if (local.length) {
          const payload = JSON.stringify(local.slice(0, 200).map((it) => [String(it.name), String(it.value)]));
          await page
            .evaluate(`(() => { const items = ${payload}; for (const [k, v] of items) { try { localStorage.setItem(k, v); } catch {} } })()`)
            .catch(() => {});
        }
        if (sess.length) {
          const payload = JSON.stringify(sess.slice(0, 200).map((it) => [String(it.name), String(it.value)]));
          await page
            .evaluate(`(() => { const items = ${payload}; for (const [k, v] of items) { try { sessionStorage.setItem(k, v); } catch {} } })()`)
            .catch(() => {});
        }
      }
    }
    // Scripted interaction: the agent drives the page the way an operator would, then the
    // usual DOM snapshot and screenshot describe where it ended up.
    const performed: Array<Record<string, unknown>> = [];
    const scripted = Array.isArray(input.actions) ? input.actions.slice(0, 20) : [];
    for (const raw of scripted) {
      const action = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
      const type = String(action.type || "");
      const selector = String(action.selector || "");
      const value = String(action.value ?? "");
      try {
        if (type === "wait") {
          const wait = boundedInteger(action.wait_ms, 1000, 0, 10_000);
          await page.waitForTimeout(wait);
          performed.push({ type, wait_ms: wait, ok: true });
          continue;
        }
        if (type === "scroll") {
          const distance = boundedInteger(value, 800, 0, 20_000);
          await page.mouse.wheel(0, distance);
          performed.push({ type, distance, ok: true });
          continue;
        }
        if (!selector) throw new Error("selector is required");
        const locator = page.locator(selector).first();
        if (type === "click") await locator.click({ timeout: 10_000 });
        else if (type === "fill") await locator.fill(value, { timeout: 10_000 });
        else if (type === "press") await locator.press(value || "Enter", { timeout: 10_000 });
        else if (type === "select") await locator.selectOption(value, { timeout: 10_000 });
        else if (type === "check") await locator.check({ timeout: 10_000 });
        else if (type === "uncheck") await locator.uncheck({ timeout: 10_000 });
        else if (type === "hover") await locator.hover({ timeout: 10_000 });
        else throw new Error(`unknown action ${type}`);
        performed.push({ type, selector, ok: true });
      } catch (cause) {
        // A broken selector is information, not a reason to lose the snapshot.
        performed.push({ type, selector, ok: false, error: (cause instanceof Error ? cause.message : String(cause)).slice(0, 300) });
      }
    }
    if (scripted.length) await page.waitForTimeout(300);
    let evaluated: unknown;
    const script = typeof input.evaluate === "string" ? input.evaluate.trim() : "";
    if (script) {
      try {
        const fn = new Function(`return (${script}\n);`) as (...args: never[]) => unknown;
        evaluated = await page.evaluate(fn as never);
      } catch (first) {
        try {
          const fn = new Function(script) as (...args: never[]) => unknown;
          evaluated = await page.evaluate(fn as never);
        } catch {
          evaluated = { error: (first instanceof Error ? first.message : String(first)).slice(0, 300) };
        }
      }
    }
    const finalUrl = pageUrl();
    const details = await page.evaluate<Record<string, unknown>>(`(() => ({
      title: document.title.slice(0, 500),
      text: (document.body?.innerText || "").replace(/\\s+/g, " ").trim().slice(0, 20000),
      links: Array.from(document.querySelectorAll("a[href]")).slice(0, 200).map((node) => ({ text: (node.textContent || "").trim().slice(0, 200), href: node.href })),
      forms: Array.from(document.forms).slice(0, 50).map((form) => ({ method: form.method, action: form.action, inputs: Array.from(form.elements).slice(0, 100).map((item) => ({ name: item.name, type: item.type })) })),
    }))()`);
    const screenshot = artifactPath(ctx, "png");
    await page.screenshot({ path: screenshot.absolute, fullPage: tool === "browser.screenshot" ? input.full_page === true : false });
    const browserCookies = await session.context.cookies();
    if (browserCookies.length) {
      jar = ctx.db.mergeProjectCookies(ctx.projectId, browserCookies.map((cookie) => fromPlaywrightCookie(cookie)).filter((cookie): cookie is CookieRecord => Boolean(cookie)));
    }
    // 全局 Token 罐：把 evaluate 里捞到的 Bearer 存起来，后续 http.request 自动挂 Authorization。
    // 模型不需要"正确地"引用 token——罐子先装满，认证链才有机会走通。
    let capturedTokens: ReturnType<typeof captureTokens> = [];
    try {
      const host = new URL(finalUrl).host;
      capturedTokens = captureTokens(
        { evaluate: typeof evaluated === "string" ? evaluated.slice(0, 20000) : evaluated, links: details.links, forms: details.forms },
        host,
      );
      if (capturedTokens.length) ctx.db.mergeProjectTokens(ctx.projectId, capturedTokens);
    } catch { capturedTokens = []; }
    return {
      tool, ok: true,
      summary: `${tool} ${response?.status() || 0} ${details.title || finalUrl}${capturedTokens.length ? ` ｜ 已捕获 ${capturedTokens.length} 个 Token 进全局罐` : ""}${seededHost ? ` ｜ 已注入种子身份 ${seededHost}` : ""}`.slice(0, 8000),
      data: { requested_url: target || finalUrl, final_url: finalUrl, status: response?.status() || 0, ...details, cookie_count: jar.length, ...(seededHost ? { seeded_host: seededHost } : {}), tab_count: session.pages.length, ...(capturedTokens.length ? { tokens_captured: capturedTokens.map(token => `${token.name}@${token.host}`) } : {}), ...(performed.length ? { actions: performed } : {}), ...(evaluated === undefined ? {} : { evaluate: typeof evaluated === "string" ? evaluated.slice(0, 20000) : evaluated }) },
      artifacts: [{ kind: "screenshot", path: screenshot.relative, media_type: "image/png" }],
    };
  } catch (cause) {
    // A dead browser must not poison the map: drop the session so the next call relaunches.
    if (/has been closed|Target closed|browser has disconnected|Protocol error|browser closed/i.test(String(cause))) browserSessions.delete(key);
    throw cause;
  } finally { stop(); }
}

/**
 * 会话注入与持久化：SRC 的核心是"身份保持"。模型可以把 Cookie / localStorage /
 * sessionStorage 灌进当前浏览器上下文，也能读出来带走；状态同时写进项目 Cookie 罐，
 * 后续 http.request 自动带 Cookie。
 */
async function browserStorageTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const session = browserSessions.get(browserKey(ctx));
  if (!session) throw reject("browser.storage requires a live browser: call browser.open first");
  const base = httpUrl(input.url, ctx.target);
  const rawCookies = Array.isArray(input.cookies) ? input.cookies : [];
  const injected: string[] = [];
  const cookieRecords: CookieRecord[] = [];
  for (const raw of rawCookies.slice(0, 100)) {
    const item = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    const name = String(item.name || "").trim();
    const value = String(item.value ?? "");
    if (!name) continue;
    const domain = String(item.domain || "").trim() || new URL(base).hostname;
    const record: CookieRecord = {
      name, value, domain,
      path: String(item.path || "/") || "/",
      secure: item.secure === true,
      httpOnly: item.httpOnly === true,
      sameSite: ["Strict", "Lax", "None"].includes(String(item.sameSite)) ? String(item.sameSite) as CookieRecord["sameSite"] : undefined,
      expires: Number(item.expires) > 0 ? Number(item.expires) : undefined,
    } as CookieRecord;
    cookieRecords.push(record);
    const playwrightCookie = toPlaywrightCookie(record, base);
    await session.context.addCookies([playwrightCookie]).then(() => injected.push(name)).catch(() => {});
  }
  if (cookieRecords.length) ctx.db.mergeProjectCookies(ctx.projectId, cookieRecords);
  const read = async (expression: string) => {
    try { return await session.page.evaluate(expression) as Record<string, string>; } catch { return {}; }
  };
  const localPatch = input.local_storage && typeof input.local_storage === "object" && !Array.isArray(input.local_storage)
    ? input.local_storage as Record<string, unknown> : {};
  const sessionPatch = input.session_storage && typeof input.session_storage === "object" && !Array.isArray(input.session_storage)
    ? input.session_storage as Record<string, unknown> : {};
  if (Object.keys(localPatch).length) {
    const payload = JSON.stringify(Object.fromEntries(Object.entries(localPatch).slice(0, 200).map(([key, value]) => [key, String(value)])));
    await read(`(() => { const patch = ${payload}; for (const [k, v] of Object.entries(patch)) localStorage.setItem(k, v); return {}; })()`);
  }
  if (Object.keys(sessionPatch).length) {
    const payload = JSON.stringify(Object.fromEntries(Object.entries(sessionPatch).slice(0, 200).map(([key, value]) => [key, String(value)])));
    await read(`(() => { const patch = ${payload}; for (const [k, v] of Object.entries(patch)) sessionStorage.setItem(k, v); return {}; })()`);
  }
  if (input.clear === true) await session.context.clearCookies().catch(() => {});
  const local = input.read === false ? {} : await read(`(() => { const out = {}; for (let i = 0; i < Math.min(localStorage.length, 200); i += 1) { const k = localStorage.key(i); out[k] = String(localStorage.getItem(k)).slice(0, 2000); } return out; })()`);
  const stored = input.read === false ? {} : await read(`(() => { const out = {}; for (let i = 0; i < Math.min(sessionStorage.length, 200); i += 1) { const k = sessionStorage.key(i); out[k] = String(sessionStorage.getItem(k)).slice(0, 2000); } return out; })()`);
  const jar = ctx.db.getProjectCookies(ctx.projectId);
  return {
    tool: "browser.storage", ok: true,
    summary: `browser.storage: 注入 ${injected.length} 个 Cookie，localStorage ${Object.keys(local).length} 项，sessionStorage ${Object.keys(stored).length} 项（项目 Cookie 罐共 ${jar.length}）`,
    data: { url: base, cookies_injected: injected, local_storage: local, session_storage: stored, cookie_jar_size: jar.length, cleared: input.clear === true || undefined },
    artifacts: [],
  };
}

/** 页签管理：多身份并行（受害者/攻击者/后台）时，Agent 需要自己开、切、关页签。 */
async function browserTabTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const session = browserSessions.get(browserKey(ctx));
  if (!session) throw reject("browser.tab requires a live browser: call browser.open first");
  const action = String(input.action || "list").toLowerCase();
  const indexOfUrl = (needle: string) => session!.pages.findIndex(page => page.url().includes(needle));
  if (action === "new") {
    if (session.pages.length >= BROWSER_MAX_TABS) throw reject(`browser.tab is at the ${BROWSER_MAX_TABS}-tab limit; close one first`);
    const tab = await session.context.newPage();
    session.pages.push(tab);
    session.page = tab;
    const url = String(input.url || "").trim();
    if (url) await tab.goto(httpUrl(url, ctx.target), { waitUntil: "domcontentloaded", timeout: remainingTimeout(ctx, 30_000) }).catch(() => undefined);
  } else if (action === "close") {
    const wanted = input.index === undefined ? session.pages.length - 1 : boundedInteger(input.index, session.pages.length - 1, 0, Math.max(0, session.pages.length - 1));
    const target = session.pages[wanted];
    if (!target) throw reject(`no tab at index ${wanted}`);
    if (session.pages.length === 1) throw reject("cannot close the last tab; use browser.close to dispose the session");
    await target.close().catch(() => {});
    session.pages = session.pages.filter(page => page !== target);
    if (session.page === target) session.page = session.pages[0]!;
  } else if (action === "switch") {
    const byUrl = input.url ? indexOfUrl(String(input.url)) : -1;
    const index = byUrl >= 0 ? byUrl : boundedInteger(input.index, 0, 0, Math.max(0, session.pages.length - 1));
    const target = session.pages[index];
    if (!target) throw reject(`no tab at index ${index}`);
    session.page = target;
    await target.bringToFront().catch(() => {});
  } else if (action !== "list") {
    throw reject('browser.tab.action must be one of list, new, close, switch');
  }
  session.lastUsed = Date.now();
  const tabs = session.pages.map((page, index) => ({ index, url: page.url().slice(0, 400), active: page === session!.page }));
  return {
    tool: "browser.tab", ok: true,
    summary: `browser.tab ${action}: ${tabs.length} 个页签（当前 #${tabs.findIndex(tab => tab.active)}）`,
    data: { action, tabs, limit: BROWSER_MAX_TABS },
    artifacts: [],
  };
}

/**
 * 渲染期真实请求清单（SPA 逆向的入口）。
 *
 * 返回两类事实：`requests` 是原始网络事件（含 status / resource_type），
 * `api_endpoints` 是去重后的 method+URL（这才是下一轮该打的接口）。
 * 没有这个工具时，SPA 目标只能靠猜 bundle 路径。
 */
async function browserNetworkTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  await sweepBrowserSessions();
  const session = browserSessions.get(browserKey(ctx));
  if (!session) throw reject("browser.network requires a live browser: open the page with browser.open first");
  session.lastUsed = Date.now();
  const hostFilter = String(input.host || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const typeFilter = String(input.resource_type || "").trim().toLowerCase();
  const since = boundedInteger(input.since_ms, 0, 0, 86_400_000);
  const cutoff = since > 0 ? Date.now() - since : 0;
  const pattern = String(input.url_regex || "").trim();
  let regex: RegExp | undefined;
  if (pattern) {
    try { regex = new RegExp(pattern, "i"); } catch { throw reject("browser.network url_regex is not a valid regular expression"); }
  }
  const includePost = input.include_post_data === true;
  const limit = boundedInteger(input.limit, 200, 1, BROWSER_NETWORK_MAX);
  const matches = session.network.filter(entry => {
    if (entry.at < cutoff) return false;
    if (typeFilter) {
      const type = entry.resource_type.toLowerCase();
      if (type !== typeFilter && !(typeFilter === "xhr" && type === "fetch")) return false;
    }
    if (regex && !regex.test(entry.url)) return false;
    if (hostFilter) {
      try {
        const host = new URL(entry.url).hostname.toLowerCase();
        if (host !== hostFilter && !host.endsWith(`.${hostFilter}`) && !sameRegistrableDomain(host, hostFilter)) return false;
      } catch { return false; }
    }
    return true;
  });
  const picked = matches.slice(-limit);
  const api = picked.filter(entry => entry.resource_type === "xhr" || entry.resource_type === "fetch");
  const unique = new Map<string, BrowserNetworkEntry>();
  for (const entry of api) {
    try {
      const parsed = new URL(entry.url);
      const key = `${entry.method} ${parsed.origin}${parsed.pathname}`;
      if (!unique.has(key)) unique.set(key, entry);
    } catch { /* 非法 URL 跳过 */ }
  }
  return {
    tool: "browser.network", ok: true,
    summary: `browser.network: ${picked.length}/${matches.length} 条请求（XHR/fetch ${api.length} 条，去重接口 ${unique.size} 个）`.slice(0, 8000),
    data: {
      count: picked.length,
      total: session.network.length,
      api_count: api.length,
      requests: picked.map(entry => ({
        method: entry.method, url: entry.url, resource_type: entry.resource_type,
        ...(entry.status !== undefined ? { status: entry.status } : {}),
        ...(includePost && entry.post_data ? { post_data: entry.post_data } : {}),
      })),
      api_endpoints: [...unique.values()].map(entry => ({
        method: entry.method, url: entry.url,
        ...(entry.status !== undefined ? { status: entry.status } : {}),
        ...(includePost && entry.post_data ? { post_data: entry.post_data } : {}),
      })),
      hint: api.length
        ? "把这些 api_endpoints 直接作为下一轮 http.request / burp.send 的目标（method 与参数照抄），不要再去猜 bundle 路径"
        : "没有捕获到 XHR：用 browser.open 带 wait_until=networkidle 重新加载，或先做一次页面交互（actions）再调用本工具",
    },
    artifacts: [],
  };
}

async function browserCloseTool(ctx: BlackboxToolContext): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const closed = await closeBrowserSessions(ctx.projectId, ctx.sessionId);
  return {
    tool: "browser.close", ok: true,
    summary: closed ? `browser.close closed ${closed} session` : "browser.close: no live browser session",
    data: { closed }, artifacts: [],
  };
}

/** Read the full artifact behind a bounded result: the model can page past the 2000-line window. */
async function evidenceReadTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const evidenceId = String(input.evidence_id || "").trim();
  const source = canonicalTool(String(input.tool || "").trim());
  const offset = boundedInteger(input.offset, 0, 0, 5_000_000);
  const limit = boundedInteger(input.limit, 500, 1, 1000);
  const width = boundedInteger(input.width, 4096, 100, 65536);
  if (!evidenceId && !source) throw reject("evidence.read requires tool or evidence_id");
  const row = evidenceId ? ctx.db.getBlackboxArtifact(ctx.projectId, ctx.sessionId, evidenceId) : ctx.db.latestBlackboxArtifact(ctx.projectId, ctx.sessionId, source);
  if (!row) throw reject(evidenceId ? `evidence not found: ${evidenceId}` : `no artifact recorded for ${source}`);
  const relative = String(row.artifact_path || "").trim();
  if (!relative) {
    // 不再是死路：非 artifact 的证据（工具结果本身）直接把结构化记录交回去，
    // 让"观察-推理"闭环不被 artifact 限制打断。
    const record = (row.data && typeof row.data === "object" ? row.data : {}) as Record<string, unknown>;
    const text = JSON.stringify(record, null, 1);
    const lines = text.split("\n");
    const window = lines.slice(offset, offset + limit);
    return {
      tool: "evidence.read", ok: true,
      summary: `evidence.read ${evidenceId || source} (非 artifact，返回结构化记录 ${window.length}/${lines.length} 行)`,
      data: {
        evidence_id: row.id, kind: row.kind, source: row.source, summary: row.summary, confidence: row.confidence,
        artifact: null, offset, returned: window.length, total_lines: lines.length,
        next_offset: offset + window.length < lines.length ? offset + window.length : null,
        truncated: window.length < limit, lines: window.map(line => line.slice(0, width)),
      },
      artifacts: [],
    };
  }
  const root = resolve(ctx.cfg.data_dir);
  const absolute = resolve(join(root, relative));
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) throw reject("invalid artifact path");
  if (!existsSync(absolute)) throw reject(`artifact file is missing: ${relative}`);
  const text = readFileSync(absolute, "utf8");
  if (text.length > 50_000_000) throw reject("artifact is too large to page (over 50MB)");
  const lines = text.split(/\r?\n/);
  const window = lines.slice(offset, offset + limit);
  const output: string[] = [];
  let bytes = 0;
  for (const line of window) {
    if (bytes >= 200_000) break;
    output.push(line.slice(0, width));
    bytes += line.length;
  }
  const next = offset + output.length < lines.length ? offset + output.length : null;
  return {
    tool: "evidence.read", ok: true,
    summary: `evidence.read ${relative} lines ${offset}-${offset + output.length} of ${lines.length}${next === null ? "" : ` (next ${next})`}`,
    data: { artifact: relative, offset, returned: output.length, total_lines: lines.length, next_offset: next, truncated: output.length < window.length, lines: output },
    artifacts: [{ kind: "tool-output", path: relative, media_type: "text/plain" }],
  };
}

async function httpTool(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const rules = blackboxRules(ctx.values);
  // 协议宽容层：模型把 token 写在顶层也要能用（顶层 token → Authorization；cookies → Cookie）。
  // 原地改写 input，使后续证据记录的就是真正发出去的请求头。
  const authNormalized = normalizeAuthInput(input);
  for (const key of Object.keys(input)) delete input[key];
  Object.assign(input, authNormalized.input);
  const authNotes = [...authNormalized.notes];
  // 匿名模式：未授权/鉴权绕过类证据必须能发出"真的不带凭证"的请求，
  // 否则全局罐一装满，匿名基线就再也测不出来了。
  const anonymous = input.anonymous === true || input.no_auth === true || input.use_jar === false;
  delete input.anonymous; delete input.no_auth; delete input.use_jar;
  const method = String(input.method || "GET").toUpperCase();
  if (!rules.request.methods.includes(method)) throw reject(`HTTP method ${method} is not allowed by the active rules`);
  let url = httpUrl(input.url, ctx.target);
  const headerReport = requestHeadersWithDropped(input.headers);
  const baseHeaders = headerReport.headers;
  const headerNote = droppedHeaderNote(headerReport.dropped);
  /**
   * 浏览器身份兜底（实测表见 ua.ts）。
   *
   * 旧实现把 UA 完全交给调用方，结果是 `http.request` 带着 Playwright 的默认 UA 出门，
   * 被"只放行浏览器"的网关统一打回 403 + 7155B 挑战页；而那张页面是合法 JSON、
   * 状态码是 403、长度固定，非常容易被当成"目标在正常回话"，于是整场朝着假墙推阶梯。
   * 显式 `headers["user-agent"]` 仍然优先——故意裸 UA 做差异对照是合法打法。
   */
  const uaInjected = applyDefaultUserAgent(baseHeaders, ctx.values);
  const uaNote = uaInjected ? "（未指定 UA，已使用默认浏览器 UA）" : "";
  const explicitCookie = baseHeaders.cookie;
  delete baseHeaders.cookie;
  let jar = ctx.db.getProjectCookies(ctx.projectId);
  if (explicitCookie) {
    jar = ctx.db.mergeProjectCookies(ctx.projectId, parseCookieHeader(explicitCookie, url));
    if (anonymous) {
      baseHeaders.cookie = explicitCookie;
    }
  }
  if (anonymous) {
    jar = [];
    authNotes.push("anonymous：跳过全局 Cookie/Token 罐（只发显式传入的凭证）");
  }
  // 全局 Token 罐：登录后抓到的 Bearer 自动挂上，等效"登录一次、后面发包自动带凭证"。
  const hasAuthHeader = Object.keys(baseHeaders).some(key => key.toLowerCase() === "authorization");
  if (!hasAuthHeader && !anonymous) {
    const host = new URL(url).host;
    const stored = ctx.db.getTokenForHost(ctx.projectId, host);
    if (stored) {
      baseHeaders.authorization = `${stored.scheme || "Bearer"} ${stored.value}`;
      authNotes.push(`全局 Token 罐命中 ${stored.host} → Authorization: ${stored.scheme || "Bearer"} …`);
    }
  }
  const initialBody = requestBody(input, method, baseHeaders, rules.request.max_request_body_bytes);
  // 重定向默认不跟随（见下方 3xx 分支）；显式传 follow_redirects:true 才走旧行为。
  const follow = input.follow_redirects === true;
  let currentMethod = method;
  let currentBody = initialBody;
  const proxyUrl = proxy(ctx, tool === "burp.request");
  const api = await acquire(playwrightRequest.newContext({
    ...(proxyUrl ? { proxy: { server: proxyUrl } } : {}),
    ignoreHTTPSErrors: boolValue(ctx.values.BURP_IGNORE_HTTPS_ERRORS, false),
  }), ctx.signal, api => api.dispose());
  const redirects: Array<{ status: number; from: string; to: string }> = [];
  const unsubscribe = onAbort(ctx.signal, () => api.dispose());
  const timer = ctx.deadline === undefined ? undefined : setTimeout(() => { void api.dispose().catch(() => {}); }, Math.max(1, ctx.deadline - Date.now()));
  try {
    for (let count = 0; count <= rules.request.max_redirects; count += 1) {
      const requestHeadersForHop = { ...baseHeaders };
      const cookie = cookieHeaderFor(jar, url);
      if (cookie) requestHeadersForHop.cookie = cookie;
      const options: Record<string, unknown> = {
        method: currentMethod,
        headers: requestHeadersForHop,
        failOnStatusCode: false,
        maxRedirects: 0,
        timeout: remainingTimeout(ctx, boundedInteger(input.timeout_ms, 30_000, 1000, rules.request.max_timeout_ms)),
      };
      if (currentBody.data !== undefined) options.data = currentBody.data;
      else if (currentBody.form) options.form = currentBody.form;
      else if (currentBody.multipart) options.multipart = currentBody.multipart;
      const response = await api.fetch(url, options as Parameters<typeof api.fetch>[1]);
      const status = response.status();
      const responseHeaderMap = response.headers();
      const headerList = await response.headersArray();
      const additions = headerList
        .filter((header) => header.name.toLowerCase() === "set-cookie")
        .map((header) => parseSetCookie(header.value, url))
        .filter((cookie): cookie is CookieRecord => Boolean(cookie));
      if (additions.length) {
        jar = ctx.db.mergeProjectCookies(ctx.projectId, additions);
      }
      const location = responseHeaderMap.location;
      if (location && [301, 302, 303, 307, 308].includes(status)) {
        const next = new URL(location, url).toString();
        redirects.push({ status, from: url, to: next });
        // 默认**不跟随**：只有看到原始 301/302（和它的 Location），才可能意识到
        // "全站统一跳转"本身就是攻击面（Host 头注入 / 开放重定向 / 子域接管）。
        // 跟随会把它变成一次平淡的 200，POST 还会被降级成 GET、body 直接丢失。
        if (!follow) {
          const rawBody = currentMethod === "HEAD" ? Buffer.alloc(0) : await response.body();
          const body = rawBody.subarray(0, rules.request.max_body_bytes).toString("utf8");
          return {
            tool, ok: true,
            summary: `${currentMethod} ${url} returned HTTP ${status} → ${next}（未跟随重定向；需要跟随就传 follow_redirects:true）${headerNote}${uaNote}`,
            data: {
              method: currentMethod, url, status, location: next, redirect_not_followed: true,
              headers: responseHeaders(responseHeaderMap), body,
              body_bytes: rawBody.length, body_truncated: rawBody.length > rules.request.max_body_bytes,
              request_body_bytes: bodySize(initialBody), redirects, cookie_count: jar.length,
              ...(headerReport.dropped.length ? { headers_dropped: headerReport.dropped } : {}),
            },
            artifacts: [],
          };
        }
        if (count === rules.request.max_redirects) throw new Error("redirect limit exceeded");
        url = next;
        // 只有 303 才按语义把方法降成 GET；301/302 上保留原方法与 body，
        // 否则"POST 过去被重定向"这类证据会被客户端自己吃掉。
        if (status === 303) {
          currentMethod = "GET";
          currentBody = {};
        }
        continue;
      }
      const raw = currentMethod === "HEAD" ? Buffer.alloc(0) : await response.body();
      const body = raw.subarray(0, rules.request.max_body_bytes).toString("utf8");
      /**
       * 代理错误页必须判失败，不能当目标响应。
       *
       * 实测 wxmc.topsec.com.cn：目标不可达时 Burp 用它自己的错误页顶替响应，状态码仍是
       * 200、长度恒为 1381B。旧实现照单全收，于是 7 条路径"都是 200/1381B"→ 触发
       * `uniform_body` 异常 → 派发 Host 头注入等三条任务，整场朝假信号打。
       * 这里返回 ok:false，让它落成 tool-error：`recordAnomaly` 第一行就 `if (!result.ok) return`，
       * 假信号自然不再产生，证据也不会被当成目标正文。
       */
      const proxied = proxyErrorPage({ status, headers: responseHeaderMap, body });
      if (proxied) {
        return {
          tool, ok: false,
          summary: proxyErrorSummary(proxied, { method: currentMethod, url, status, bytes: raw.length }),
          data: {
            proxy_error: true, proxy_vendor: proxied.vendor, proxy_marker: proxied.marker,
            ...(proxied.detail ? { proxy_detail: proxied.detail } : {}),
            method: currentMethod, url, status, body_bytes: raw.length,
            body: body.slice(0, 2000),
            hint: "请求没到目标。换可达主机、或确认出网代理后重试；不要基于这张页面下任何结论。",
          },
          artifacts: [],
        };
      }
      return {
        tool, ok: true,
        summary: `${currentMethod} ${url} returned HTTP ${status}${authNotes.length ? ` ｜ ${authNotes.join("；")}` : ""}${headerNote}${uaNote}`.slice(0, 8000),
        data: {
          method: currentMethod, url, status, headers: responseHeaders(responseHeaderMap), body,
          body_bytes: raw.length, body_truncated: raw.length > rules.request.max_body_bytes,
          request_body_bytes: bodySize(initialBody), redirects, cookie_count: jar.length,
          ...(uaInjected ? { ua_defaulted: true } : {}),
          ...(authNotes.length ? { auth_applied: authNotes } : {}),
          ...(headerReport.dropped.length ? { headers_dropped: headerReport.dropped } : {}),
        },
        artifacts: [],
      };
    }
    throw new Error("redirect limit exceeded");
  } finally { unsubscribe(); clearTimeout(timer); await api.dispose().catch(() => {}); }
}

async function httpDiffTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const variant = (input.variant || {}) as Record<string, unknown>;
  const baselineInput: Record<string, unknown> = {
    method: input.method, url: input.url, headers: input.headers, cookie: input.cookie,
    body: input.body, body_base64: input.body_base64, multipart: input.multipart, timeout_ms: input.timeout_ms,
    // 匿名开关必须透传：否则全局罐一装满，基线也会自动带凭证，"匿名 vs 带凭证"的对比就失效了。
    ...(input.anonymous === true ? { anonymous: true } : {}),
    ...(input.no_auth === true ? { no_auth: true } : {}),
    ...(input.use_jar === false ? { use_jar: false } : {}),
    // 顶层 token/cookies 也要透传给基线（模型常把公共凭证写在顶层）
    ...(input.token === undefined ? {} : { token: input.token }),
    ...(input.jwt === undefined ? {} : { jwt: input.jwt }),
    ...(input.cookies === undefined ? {} : { cookies: input.cookies }),
  };
  const variantInput: Record<string, unknown> = { ...baselineInput, ...variant, url: variant.url || input.variant_url || input.url };
  if (!baselineInput.url || !variantInput.url) throw reject("http.diff requires url (and optionally variant.url)");
  const timed = async (payload: Record<string, unknown>) => {
    const started = Date.now();
    const result = await httpTool(ctx, "http.request", payload);
    const data = (result.data || {}) as Record<string, unknown>;
    return {
      status: Number(data.status || 0),
      body: String(data.body || ""),
      body_bytes: Number(data.body_bytes || 0),
      duration_ms: Date.now() - started,
      // httpTool 已把代理错误页判成 ok:false；这里必须把标记透上来，否则 diff 会拿
      // 两张代理错误页算出"similarity≈1"的假结论（wxmc 那 4 次 diff 全是这么来的）。
      proxy_error: data.proxy_error === true,
      proxy_vendor: String(data.proxy_vendor || ""),
      proxy_url: String(payload.url || ""),
    };
  };
  const left = await timed(baselineInput);
  const right = await timed(variantInput);
  const proxied = left.proxy_error ? left : right.proxy_error ? right : undefined;
  if (proxied) {
    return {
      tool: "http.diff", ok: false,
      summary: `http.diff 未成立：${proxied.proxy_url} 的请求没到目标，${proxied.proxy_vendor || "代理"}返回了自己的错误页。`
        + "两张错误页之间的差异（或「高度相似」）都不是目标的行为，不能用来判定 WAF/鉴权/参数效果。",
      data: {
        proxy_error: true, proxy_vendor: proxied.proxy_vendor, proxy_url: proxied.proxy_url,
        baseline: { status: left.status, body_bytes: left.body_bytes },
        variant: { status: right.status, body_bytes: right.body_bytes },
        hint: "换可达主机或修好出网代理后重做这条对照；不要把这轮 diff 写进任务结论。",
      },
      artifacts: [],
    };
  }
  const diff = diffResponses(left, right, { timingThresholdMs: Number(input.timing_threshold_ms || 0) || undefined });
  const changedFields = Object.keys(variant);
  const authOnly = changedFields.length > 0 && changedFields.every(field => ["headers", "cookie"].includes(field));
  const delta = diff.delta;
  const timing = diff.timing;
  return {
    tool: "http.diff",
    ok: true,
    summary: `http.diff ${diff.verdict}（相似度 ${delta.similarity}，状态 ${left.status}→${right.status}，耗时 ${timing.delta_ms >= 0 ? "+" : ""}${timing.delta_ms}ms）${timing.suspect ? " ⚠时间维度异常" : ""}`,
    data: { ...diff, url: String(baselineInput.url), variant_url: String(variantInput.url), changed_fields: changedFields, auth_only_change: authOnly },
    artifacts: [],
  };
}

async function burpCheck(ctx: BlackboxToolContext): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const endpoint = proxyEndpoint(proxy(ctx, true)!);
  await checkTcp(endpoint.host, endpoint.port, remainingTimeout(ctx, 3000), ctx.signal);
  return { tool: "burp.check", ok: true, summary: `Burp proxy is reachable at ${endpoint.url}`, data: { proxy_url: endpoint.url, reachable: true }, artifacts: [] };
}

function burpBridgeBase(values: Record<string, string>): { baseUrl: string; token: string } {
  const raw = String(values.BURP_BRIDGE_URL || "http://host.docker.internal:8765").trim();
  let url: URL;
  try { url = new URL(raw); } catch { throw reject("Burp Bridge URL is invalid"); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw reject("Burp Bridge URL must be a credential-free HTTP(S) base URL");
  }
  if (url.pathname !== "/" && url.pathname !== "") throw reject("Burp Bridge URL must not contain a path");
  const token = String(values.BURP_BRIDGE_TOKEN || "").trim();
  if (!token) throw reject("Burp Bridge token is not configured");
  return { baseUrl: url.origin, token };
}

async function readBoundedResponse(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = maxBytes - size;
      if (remaining <= 0) { await reader.cancel(); throw new Error("Burp Bridge response exceeded the size limit"); }
      const chunk = value.subarray(0, remaining);
      chunks.push(chunk);
      size += chunk.byteLength;
      if (chunk.byteLength < value.byteLength) { await reader.cancel(); throw new Error("Burp Bridge response exceeded the size limit"); }
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

/** Header input is normalised once so every action endpoint sees the same "Name: value" lines. */
function burpHeaderLines(input: Record<string, unknown>): string[] {
  const raw = input.headers;
  const lines: string[] = [];
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
      if (value === undefined || value === null) continue;
      const text = String(value).trim();
      if (!text) continue;
      if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(name)) throw reject(`invalid header name: ${name}`);
      lines.push(`${name}: ${text.replace(/[\r\n]+/g, " ").slice(0, 4096)}`);
    }
  } else if (Array.isArray(raw)) {
    for (const item of raw) {
      const match = String(item).match(/^([^:]{1,64}):\s*(.*)$/s);
      if (!match) throw reject("header entries must look like Name: value");
      lines.push(`${match[1]!.trim()}: ${match[2]!.trim().slice(0, 4096)}`);
    }
  }
  if (lines.length > 32) throw reject("at most 32 request headers are supported");
  return lines;
}

/**
 * 2026-11-03 解除 scope：这里原本硬性要求 url 主机等于会话目标主机，会把跨域后端
 * （如 SPA 外壳同族/第三方 API 宿主）全部拒掉，等于自断攻击面。现在只校验 URL 形状，
 * 任意主机放行；是否越界由操作员在 Burp / 授权范围侧控制。
 */
function requireTargetHost(url: string, _host: string): void {
  try {
    new URL(url);
  } catch {
    throw reject(`not an absolute URL: ${url.slice(0, 120)}`);
  }
}

function burpTargetUrl(input: Record<string, unknown>, fallback: string): string {
  const raw = String(input.url || "").trim();
  return raw ? httpUrl(raw, fallback) : fallback;
}

async function burpBridgeCall(
  ctx: BlackboxToolContext,
  call: { path: string; method?: "GET" | "POST"; params?: Record<string, string>; headers?: string[]; body?: string; timeoutMs?: number },
): Promise<Record<string, unknown>> {
  const { baseUrl, token } = burpBridgeBase(ctx.values);
  const query = new URLSearchParams(call.params || {});
  for (const header of call.headers || []) query.append("h", header);
  const target = `${baseUrl}${call.path}${query.toString() ? `?${query.toString()}` : ""}`;
  const timeoutMs = remainingTimeout(ctx, call.timeoutMs ?? 20_000);
  const signal = AbortSignal.any([AbortSignal.timeout(timeoutMs), ...(ctx.signal ? [ctx.signal] : [])]);
  const response = await fetch(target, {
    method: call.method || "GET",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json", "Content-Type": "text/plain; charset=utf-8" },
    body: call.method === "POST" ? (call.body || "") : undefined,
    redirect: "error",
    signal,
  });
  const body = await readBoundedResponse(response, 512 * 1024);
  let data: Record<string, unknown> | null = null;
  try {
    const parsed = JSON.parse(body) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) data = parsed as Record<string, unknown>;
  } catch { data = null; }
  if (!response.ok) throw new Error(`Burp Bridge returned HTTP ${response.status}${typeof data?.error === "string" ? `: ${data.error.slice(0, 300)}` : ""}`);
  if (!data) throw new Error("Burp Bridge returned invalid JSON");
  if (data.ok !== true) throw new Error(String(data.error || "Burp Bridge request failed").slice(0, 500));
  return data;
}

/**
 * 控制面替模型启动一次 Burp 审计（不占工具预算：这不是模型的一次动作，是环境的准备）。
 *
 * 失败一律不抛：Burp Community 没有 Scanner，`api.scanner()` 会直接抛，桥返回 500。
 * 那是"这台 Burp 没这能力"，不是会话的错——记一条警告、不再重试即可。
 */
export async function burpArmAudit(
  ctx: BlackboxToolContext,
  url: string,
  mode: "passive" | "active",
): Promise<{ ok: boolean; audit_id?: string; mode?: string; insertion_points?: number; error?: string }> {
  try {
    const data = await burpBridgeCall(ctx, {
      path: "/scan/audit", method: "POST", timeoutMs: 30_000,
      params: { host: `https://${new URL(url).hostname}`, url, mode },
    });
    return {
      ok: true,
      ...(data.audit_id ? { audit_id: String(data.audit_id) } : {}),
      mode: String(data.mode || mode),
      ...(typeof data.insertion_points === "number" ? { insertion_points: data.insertion_points } : {}),
    };
  } catch (cause) {
    return { ok: false, mode, error: (cause instanceof Error ? cause.message : String(cause)).slice(0, 400) };
  }
}

/** 读 site map 里的 Scanner 问题清单（被动扫描从代理流量里攒出来的那些）。同样不抛。 */
export async function burpReadIssues(
  ctx: BlackboxToolContext,
  host: string,
  limit = 100,
): Promise<{ ok: boolean; total: number; issues: Array<{ name: string; severity: string; confidence?: string; base_url?: string; detail?: string }>; error?: string }> {
  try {
    const data = await burpBridgeCall(ctx, {
      path: "/issues", timeoutMs: 15_000,
      params: { host: `https://${host}`, limit: String(Math.max(1, Math.min(100, limit))), offset: "0" },
    });
    const raw = Array.isArray(data.issues) ? data.issues : [];
    const issues = raw.map((item) => {
      const row = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
      return {
        name: String(row.name || "").slice(0, 200),
        severity: String(row.severity || "").slice(0, 20),
        ...(row.confidence ? { confidence: String(row.confidence).slice(0, 20) } : {}),
        ...(row.base_url ? { base_url: String(row.base_url).slice(0, 500) } : {}),
        ...(row.detail ? { detail: String(row.detail).slice(0, 600) } : {}),
      };
    }).filter(issue => issue.name);
    return { ok: true, total: typeof data.total === "number" ? data.total : issues.length, issues };
  } catch (cause) {
    return { ok: false, total: 0, issues: [], error: (cause instanceof Error ? cause.message : String(cause)).slice(0, 400) };
  }
}

/** 把桥返回的一行 issue 归一：`/issues` 用 base_url，`/scan/issues` 用 url，两个都认。 */
function normalizeBurpIssue(item: unknown): { name: string; severity: string; confidence?: string; base_url?: string; detail?: string } | undefined {
  const row = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
  const name = String(row.name || "").trim();
  if (!name) return undefined;
  const url = row.base_url || row.url;
  return {
    name: name.slice(0, 200),
    severity: String(row.severity || "").slice(0, 20),
    ...(row.confidence ? { confidence: String(row.confidence).slice(0, 20) } : {}),
    ...(url ? { base_url: String(url).slice(0, 500) } : {}),
    ...(row.detail ? { detail: String(row.detail).slice(0, 600) } : {}),
  };
}

/**
 * 读「审计对象自己产出的问题」（`/scan/issues`，可带 audit_id）。
 *
 * 和 {@link burpReadIssues} 的区别不是细节，是两条不同的线：
 *   - `/issues` 读 site map 的汇总：所有流经代理的响应被**被动扫描**审出来的，不依赖 Scanner 审计对象，
 *     Community 版也有；
 *   - `/scan/issues` 只返回某次审计（开局 `burpArmAudit` 起的那个）**自己发出的请求**换来的问题，
 *     active 模式下才有真实注入结论。
 *
 * 只读前者等于"审计白起了"——这正是 21 场里 `burp.scan_issues` 0 次调用留下的坑。
 * 这里失败一律返回 ok:false，绝不把异常抛进主循环（Burp Community 根本没有 Scanner）。
 */
export async function burpReadScanIssues(
  ctx: BlackboxToolContext,
  auditId?: string,
  limit = 100,
): Promise<{ ok: boolean; total: number; issues: Array<{ name: string; severity: string; confidence?: string; base_url?: string; detail?: string }>; error?: string }> {
  try {
    const data = await burpBridgeCall(ctx, {
      path: "/scan/issues", timeoutMs: 20_000,
      params: auditId ? { id: String(auditId).slice(0, 64) } : {},
    });
    const raw = Array.isArray(data.issues) ? data.issues : [];
    const issues = raw.map(normalizeBurpIssue)
      .filter((issue): issue is NonNullable<typeof issue> => Boolean(issue))
      .slice(0, Math.max(1, Math.min(200, limit)));
    return { ok: true, total: typeof data.total === "number" ? data.total : issues.length, issues };
  } catch (cause) {
    return { ok: false, total: 0, issues: [], error: (cause instanceof Error ? cause.message : String(cause)).slice(0, 400) };
  }
}

async function burpBridgeTool(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {  const rules = blackboxRules(ctx.values);
  // 2026-10-31：host 过滤原来被硬编码成会话 target，模型传 `host` 会被 schema 摘掉，
  // 于是 `burp.history` 永远只能读目标主域、读不到子域流量（T1_history_baseline 就是这么空的）。
  // 现在接受同注册域内的显式 host，越界值回落到 target。
  const targetHost = new URL(httpUrl(ctx.target, ctx.target)).hostname.toLowerCase();
  const requestedHost = String(input.host || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/\/.*$/, "").split(":")[0] || "";
  // 2026-11-03 解除 scope：任意显式 host 放行（跨域 pivot），未指定才回落会话主目标。
  const host = requestedHost || targetHost;
  // Bridge v1 parsed the host filter as a URI and rejected a bare hostname ("host filter is
  // required"); a scheme-prefixed value works on v1 and v2, so reads stay compatible during a
  // rolling extension reload.
  const hostParam = `https://${host}`;
  const paged = (): Record<string, string> => ({
    host: hostParam,
    limit: String(boundedInteger(input.limit, tool === "burp.history" ? 50 : tool === "burp.ws_history" ? 30 : 50, 1, 100)),
    offset: String(boundedInteger(input.offset, 0, 0, 100_000)),
  });

  switch (tool) {
    case "burp.history": {
      const data = await burpBridgeCall(ctx, { path: "/proxy/history", params: paged() });
      const entries = Array.isArray(data.entries) ? data.entries as Record<string, unknown>[] : [];
      // 默认做一次被动分析：Agent 看"信号"比看 50 条原始记录有效得多（docs §19）。
      if (input.analyze === false) {
        return { tool, ok: true, summary: `burp.history returned ${entries.length} entries for ${host}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
      }
      const analysis = analyzeTraffic(entries as never);
      return {
        tool, ok: true,
        summary: `burp.history ${trafficSummaryLine(analysis)}`,
        data: { ...data, host, source: "Burp Suite", analysis },
        artifacts: [],
      };
    }
    case "burp.sitemap": {
      const data = await burpBridgeCall(ctx, { path: "/sitemap", params: paged() });
      const count = Array.isArray(data.entries) ? data.entries.length : 0;
      return { tool, ok: true, summary: `burp.sitemap returned ${count} entries for ${host}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.issues": {
      const data = await burpBridgeCall(ctx, { path: "/issues", params: paged() });
      const count = Array.isArray(data.issues) ? data.issues.length : 0;
      return { tool, ok: true, summary: `burp.issues returned ${count} issues for ${host}`, data: { ...data, host, source: "Burp Suite", unverified: true }, artifacts: [] };
    }
    case "burp.ws_history": {
      const data = await burpBridgeCall(ctx, { path: "/ws/history", params: paged() });
      const count = Array.isArray(data.entries) ? data.entries.length : 0;
      return { tool, ok: true, summary: `burp.ws_history returned ${count} WebSocket messages for ${host}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.entry": {
      const entryId = String(input.entry_id || "").trim();
      if (!/^(?:proxy|sitemap):[a-f0-9]{16}$/.test(entryId)) throw reject("Burp entry_id must come from burp.history or burp.sitemap");
      const data = await burpBridgeCall(ctx, { path: "/proxy/entry", params: { host: hostParam, id: entryId } });
      return {
        tool, ok: true,
        summary: `Read one redacted Burp ${data.entry_id ? String(data.entry_id).split(":")[0] : "history"} entry for ${host}`,
        data: { ...data, host, source: "Burp Suite", redacted: data.redacted === true || undefined },
        artifacts: [],
      };
    }
    case "burp.scope": {
      const url = burpTargetUrl(input, ctx.target);
      const data = await burpBridgeCall(ctx, { path: "/scope", params: { url } });
      return { tool, ok: true, summary: `${data.in_scope ? "in" : "out of"} Burp scope: ${url}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.intercept": {
      const requested = input.enabled;
      if (requested === undefined) {
        const data = await burpBridgeCall(ctx, { path: "/intercept" });
        return { tool, ok: true, summary: `Burp intercept is ${data.enabled ? "ON" : "off"}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      const enabled = requested === true;
      const data = await burpBridgeCall(ctx, { path: "/intercept", method: "POST", params: { enabled: String(enabled) } });
      return { tool, ok: true, summary: `Burp intercept is now ${data.enabled ? "ON" : "off"}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.decoder": {
      const operation = String(input.operation || "").trim().toLowerCase();
      const allowed = ["base64_encode", "base64_decode", "url_encode", "url_decode", "html_encode", "html_decode", "hex_encode", "hex_decode", "sha256", "uuid"];
      if (!allowed.includes(operation)) throw reject(`decoder operation must be one of: ${allowed.join(", ")}`);
      const value = String(input.value ?? "");
      if (value.length > 256 * 1024) throw reject("decoder value exceeds 256KB");
      const data = await burpBridgeCall(ctx, { path: "/decoder", method: "POST", params: { op: operation }, body: value });
      return {
        tool, ok: true,
        summary: `burp.decoder ${operation}: ${String(data.result || "").length} output characters`,
        data: { ...data, source: "Burp Suite" }, artifacts: [],
      };
    }
    case "burp.send": {
      const url = burpTargetUrl(input, ctx.target);
      // raw_method：WAF 常按方法分流，标准七动词之外的原生动词只能走原始报文通道。
      const method = String(input.raw_method || input.method || "GET").toUpperCase();
      const body = input.body === undefined ? "" : typeof input.body === "string" ? input.body : JSON.stringify(input.body);
      if (body.length > 256 * 1024) throw reject("request body exceeds 256KB");
      const data = await burpBridgeCall(ctx, {
        path: "/http/send", method: "POST", timeoutMs: 60_000,
        params: { host: hostParam, url, method, redirect: input.follow_redirects === true ? "always" : "never" },
        headers: burpHeaderLines(input), body,
      });
      return {
        tool, ok: true,
        summary: `Burp sent ${method} ${url} → ${data.status} in ${data.elapsed_ms}ms (${data.response_bytes} bytes)`,
        data: { ...data, host, source: "Burp Suite", redacted: true },
        artifacts: [],
      };
    }
    case "burp.repeater": {
      const url = burpTargetUrl(input, ctx.target);
      const method = String(input.raw_method || input.method || "GET").toUpperCase();
      const body = input.body === undefined ? "" : typeof input.body === "string" ? input.body : JSON.stringify(input.body);
      const data = await burpBridgeCall(ctx, {
        path: "/repeater", method: "POST",
        params: { host: hostParam, url, method, ...(input.tab ? { tab: String(input.tab).slice(0, 64) } : {}) },
        headers: burpHeaderLines(input), body: body.slice(0, 256 * 1024),
      });
      return { tool, ok: true, summary: `Sent ${method} ${url} to Burp Repeater`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.organizer": {
      const url = burpTargetUrl(input, ctx.target);
      const method = String(input.raw_method || input.method || "GET").toUpperCase();
      const body = input.body === undefined ? "" : typeof input.body === "string" ? input.body : JSON.stringify(input.body);
      const data = await burpBridgeCall(ctx, {
        path: "/organizer", method: "POST",
        params: { host: hostParam, url, method },
        headers: burpHeaderLines(input), body: body.slice(0, 256 * 1024),
      });
      return { tool, ok: true, summary: `Sent ${method} ${url} to Burp Organizer`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.collab_generate": {
      const data = await burpBridgeCall(ctx, { path: "/collab/generate", method: "POST" });
      return { tool, ok: true, summary: `Generated Burp Collaborator payload ${data.payload}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.collab_poll": {
      const data = await burpBridgeCall(ctx, { path: "/collab/poll", params: { limit: String(boundedInteger(input.limit, 30, 1, 100)) } });
      const count = Array.isArray(data.interactions) ? data.interactions.length : 0;
      return { tool, ok: true, summary: `Burp Collaborator returned ${count} interactions`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.scan": {
      const url = burpTargetUrl(input, ctx.target);
      const mode = String(input.mode || "passive").toLowerCase() === "active" ? "active" : "passive";
      if (mode === "active" && rules.tools["burp.scan"]?.allow_active_scan !== true) {
        throw reject("active Burp scans are disabled; enable tools[\"burp.scan\"].allow_active_scan in the rules document first");
      }
      const data = await burpBridgeCall(ctx, {
        path: "/scan/audit", method: "POST", timeoutMs: 30_000,
        params: { host: hostParam, url, mode }, headers: burpHeaderLines(input),
      });
      return {
        tool, ok: true,
        summary: `Started Burp ${mode} audit ${data.audit_id} for ${url}`,
        data: { ...data, host, source: "Burp Suite", unverified: true },
        artifacts: [],
      };
    }
    case "burp.scan_status": {
      const data = await burpBridgeCall(ctx, { path: "/scan/status", params: input.audit_id ? { id: String(input.audit_id) } : {} });
      const count = Array.isArray(data.audits) ? data.audits.length : 0;
      return { tool, ok: true, summary: `burp.scan_status returned ${count} audits`, data: { ...data, host, source: "Burp Suite", unverified: true }, artifacts: [] };
    }
    case "burp.scan_stop": {
      const auditId = String(input.audit_id || "").trim();
      if (!auditId) throw reject("audit_id is required (from burp.scan)");
      const data = await burpBridgeCall(ctx, { path: "/scan/stop", method: "POST", params: { id: auditId } });
      return { tool, ok: true, summary: `Stopped Burp audit ${auditId}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }

    // ---- full-surface routes (Burp control, Intruder, analysis, conversion) ----
    case "burp.info": {
      const data = await burpBridgeCall(ctx, { path: "/info" });
      return {
        tool, ok: true,
        summary: `Burp ${data.burp_version} · project ${data.project} · task engine ${data.task_engine} · intercept ${data.intercept ? "on" : "off"}`,
        data: { ...data, source: "Burp Suite" }, artifacts: [],
      };
    }
    case "burp.control": {
      const action = String(input.action || "").toLowerCase();
      const allowed = ["task_engine", "options_import", "log", "decoder_send", "shutdown", "unload"];
      if (!allowed.includes(action)) throw reject(`burp.control action must be one of: ${allowed.join(", ")}`);
      const data = await burpBridgeCall(ctx, { path: "/control", method: "POST", timeoutMs: 30_000, body: JSON.stringify(input) });
      const detail = action === "task_engine" ? String(data.state) : action === "shutdown" || action === "unload" ? String(data[action] ?? "done") : "ok";
      return { tool, ok: true, summary: `burp.control ${action}: ${detail}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.options": {
      const scope = String(input.scope || "project").toLowerCase() === "user" ? "user" : "project";
      const data = await burpBridgeCall(ctx, { path: "/options/export", params: { scope } });
      return {
        tool, ok: true,
        summary: `Exported Burp ${scope} options (${String(data.options || "").length} chars${data.truncated ? ", truncated" : ""})`,
        data: { ...data, source: "Burp Suite" }, artifacts: [],
      };
    }
    case "burp.cookies": {
      const action = String(input.action || "list").toLowerCase();
      if (action === "set") {
        const data = await burpBridgeCall(ctx, { path: "/cookies", method: "POST", body: JSON.stringify(input) });
        return { tool, ok: true, summary: `Set Burp cookie ${data.name} for ${data.domain}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      const data = await burpBridgeCall(ctx, { path: "/cookies" });
      const count = Array.isArray(data.cookies) ? data.cookies.length : 0;
      return { tool, ok: true, summary: `Burp cookie jar holds ${count} cookies (values stay in Burp)`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.storage": {
      const action = String(input.action || "list").toLowerCase();
      if (action === "list") {
        const data = await burpBridgeCall(ctx, { path: "/storage" });
        const keys = Array.isArray(data.keys) ? data.keys.length : 0;
        return { tool, ok: true, summary: `Bridge storage holds ${keys} keys`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      if (action === "get") {
        const key = String(input.key || "").trim();
        if (!key) throw reject("storage get needs a key");
        const data = await burpBridgeCall(ctx, { path: "/storage", params: { key } });
        return { tool, ok: true, summary: `Read storage key ${key} (${String(data.value || "").length} chars)`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      if (action !== "set" && action !== "delete") throw reject("storage action must be list, get, set or delete");
      const data = await burpBridgeCall(ctx, { path: "/storage", method: "POST", body: JSON.stringify({ action, key: input.key, value: input.value }) });
      return { tool, ok: true, summary: `Storage ${action} ${data.key}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.sitemap_issues": {
      const data = await burpBridgeCall(ctx, { path: "/sitemap/issues", params: { host: hostParam } });
      const count = Array.isArray(data.issues) ? data.issues.length : 0;
      return { tool, ok: true, summary: `Site map holds ${count} Burp issues for ${host} (candidates only)`, data: { ...data, host, source: "Burp Suite", unverified: true }, artifacts: [] };
    }
    case "burp.sitemap_add": {
      const url = burpTargetUrl(input, ctx.target);
      requireTargetHost(url, host);
      const data = await burpBridgeCall(ctx, {
        path: "/sitemap/add", method: "POST", timeoutMs: 60_000,
        body: JSON.stringify({ url, method: String(input.method || "GET").toUpperCase(), headers: input.headers, body: input.body, template: input.template }),
      });
      return { tool, ok: true, summary: `Added ${data.url} to the Burp site map (status ${data.status})`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.scope_edit": {
      const action = String(input.action || "").toLowerCase();
      if (action !== "include" && action !== "exclude") throw reject("scope action must be include or exclude");
      const url = String(input.url || "").trim();
      if (!url) throw reject("scope edit needs url (a URL or Burp scope pattern)");
      const data = await burpBridgeCall(ctx, { path: "/scope/edit", method: "POST", body: JSON.stringify({ action, url }) });
      return { tool, ok: true, summary: `Burp scope ${action}d ${url} (in scope: ${data.in_scope})`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.send_batch": {
      const raw = Array.isArray(input.requests) ? input.requests : [];
      if (raw.length === 0) throw reject("send_batch needs requests: [{url, method, headers, body}]");
      if (raw.length > 50) throw reject("at most 50 requests per batch");
      const requests = raw.map((item, index) => {
        if (!item || typeof item !== "object" || Array.isArray(item)) throw reject(`requests[${index}] must be an object`);
        const spec = item as Record<string, unknown>;
        const url = burpTargetUrl(spec, ctx.target);
        requireTargetHost(url, host);
        return { url, method: String(spec.method || "GET").toUpperCase(), headers: spec.headers, body: spec.body };
      });
      const data = await burpBridgeCall(ctx, { path: "/http/send_batch", method: "POST", timeoutMs: 120_000, body: JSON.stringify({ requests }) });
      return { tool, ok: true, summary: `Burp sent ${data.sent} requests in one batch`, data: { ...data, host, source: "Burp Suite", redacted: true }, artifacts: [] };
    }
    case "burp.crawl": {
      if (String(input.action || "start").toLowerCase() === "status") {
        const data = await burpBridgeCall(ctx, { path: "/crawl/status", params: input.crawl_id ? { id: String(input.crawl_id) } : {} });
        const count = Array.isArray(data.crawls) ? data.crawls.length : 0;
        return { tool, ok: true, summary: `burp.crawl status: ${count} crawls`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      const seeds = Array.isArray(input.seeds) ? input.seeds.map(value => burpTargetUrl({ url: String(value) }, ctx.target)) : [burpTargetUrl(input, ctx.target)];
      for (const seed of seeds) requireTargetHost(seed, host);
      let data: Record<string, unknown>;
      try {
        data = await burpBridgeCall(ctx, { path: "/crawl", method: "POST", timeoutMs: 60_000, body: JSON.stringify({ seeds }) });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // Burp 2024.7.3 ships Scanner.startCrawl as an unimplemented stub; name the limitation
        // instead of leaving a raw API exception in the transcript.
        if (/UnsupportedOperationException/.test(message) && /crawl/i.test(message)) {
          throw reject("this Burp build does not implement Scanner.startCrawl; use katana.crawl for crawling or start it from Burp's Dashboard");
        }
        throw error;
      }
      return { tool, ok: true, summary: `Started Burp crawl ${data.crawl_id} over ${seeds.length} seed(s)`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.scan_issues": {
      const params: Record<string, string> = {};
      if (input.audit_id) params.id = String(input.audit_id);
      const data = await burpBridgeCall(ctx, { path: "/scan/issues", params });
      const count = Array.isArray(data.issues) ? data.issues.length : 0;
      return { tool, ok: true, summary: `burp.scan_issues returned ${count} issues`, data: { ...data, source: "Burp Suite", unverified: true }, artifacts: [] };
    }
    case "burp.scan_report": {
      const path = String(input.path || "").trim();
      if (!path) throw reject("path is required: a file path on the Burp host, e.g. C:/Users/operator/report.html");
      const data = await burpBridgeCall(ctx, {
        path: "/scan/report", method: "POST", timeoutMs: 120_000,
        body: JSON.stringify({ audit_id: input.audit_id, format: String(input.format || "HTML").toUpperCase(), path }),
      });
      return { tool, ok: true, summary: `Burp wrote a ${data.format} report with ${data.issues} issues to ${data.path}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.intruder": {
      const action = String(input.action || "run").toLowerCase();
      if (action === "status") {
        const data = await burpBridgeCall(ctx, { path: "/intruder/status", params: input.attack_id ? { id: String(input.attack_id) } : {} });
        return {
          tool, ok: true,
          summary: `Attack ${data.attack_id}: ${data.sent}/${data.planned} sent, ${data.matched} matched, ${data.errors} errors, done=${data.done}`,
          data: { ...data, source: "Burp Suite", unverified: true }, artifacts: [],
        };
      }
      if (action === "list") {
        const data = await burpBridgeCall(ctx, { path: "/intruder" });
        const count = Array.isArray(data.attacks) ? data.attacks.length : 0;
        return { tool, ok: true, summary: `${count} attacks recorded`, data: { ...data, source: "Burp Suite", unverified: true }, artifacts: [] };
      }
      if (action === "stop") {
        const data = await burpBridgeCall(ctx, { path: "/intruder/stop", method: "POST", params: input.attack_id ? { id: String(input.attack_id) } : {} });
        return { tool, ok: true, summary: `Stop requested for attack ${data.attack_id}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      const template = String(input.template || "");
      if (!template.includes("\u00a7")) throw reject("template must contain at least one \u00a7marker\u00a7 position");
      const url = input.url ? burpTargetUrl(input, ctx.target) : "";
      if (url) requireTargetHost(url, host);
      const data = await burpBridgeCall(ctx, {
        path: "/intruder", method: "POST", timeoutMs: 60_000,
        body: JSON.stringify({ ...input, url: url || input.url, host }),
      });
      return {
        tool, ok: true,
        summary: `Started ${String(input.type || "sniper")} attack ${data.attack_id} against ${host}`,
        data: { ...data, host, source: "Burp Suite", unverified: true }, artifacts: [],
      };
    }
    case "burp.intruder_send": {
      const url = burpTargetUrl(input, ctx.target);
      requireTargetHost(url, host);
      const data = await burpBridgeCall(ctx, {
        path: "/intruder/send", method: "POST",
        body: JSON.stringify({ url, method: String(input.method || "GET").toUpperCase(), headers: input.headers, body: input.body, template: input.template, tab: input.tab }),
      });
      return { tool, ok: true, summary: `Sent ${data.url} to Burp Intruder${data.tab ? ` (${data.tab})` : ""}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.compare": {
      const mode = String(input.mode || "diff").toLowerCase();
      const allowed = ["diff", "keywords", "variations", "ui"];
      if (!allowed.includes(mode)) throw reject(`compare mode must be one of: ${allowed.join(", ")}`);
      const data = await burpBridgeCall(ctx, { path: "/compare", method: "POST", timeoutMs: 60_000, body: JSON.stringify({ ...input, mode }) });
      const summary = mode === "diff"
        ? `diff: +${data.added} -${data.removed} (=${data.unchanged})`
        : mode === "ui"
          ? "sent both payloads to Burp Comparer"
          : `${mode}: sampled ${String(data.sampled)} responses, ${String((data.variant_keywords ?? data.variant_attributes ?? []) instanceof Array ? ((data.variant_keywords ?? data.variant_attributes) as unknown[]).length : 0)} variant signals`;
      return { tool, ok: true, summary: `burp.compare ${summary}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.convert": {
      const operation = String(input.op || input.operation || "").trim();
      if (!operation) throw reject("op is required: base64_encode, base64_decode, url_encode, url_decode, html_encode, html_decode, hex_encode, hex_decode, digest, compress, decompress, random, number, json, jwt_decode");
      const data = await burpBridgeCall(ctx, { path: "/convert", method: "POST", timeoutMs: 30_000, body: JSON.stringify({ ...input, op: operation }) });
      const result = String(data.result ?? data.result_base64 ?? "");
      return { tool, ok: true, summary: `burp.convert ${operation}: ${result.length} chars`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.proxy_rule": {
      const action = String(input.action || "list").toLowerCase();
      // 2026-11-03 解除 scope：原这里要求 url_regex 里的字面 host 必须等于会话目标，
      // 跨域 pivot 时无法对 API 宿主下发 rewrite 规则。现在任意 host 都放行。
      const data = await burpBridgeCall(ctx, { path: "/rules", method: "POST", timeoutMs: 30_000, body: JSON.stringify({ ...input, action }) });
      if (action === "list") {
        const rules = Array.isArray(data.rules) ? data.rules : [];
        const active = rules.filter(rule => rule.enabled !== false).length;
        return { tool, ok: true, summary: `${rules.length} rewrite rules (${active} enabled)`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      if (action === "test") {
        const matched = Array.isArray(data.matched) ? data.matched : [];
        return { tool, ok: true, summary: `rule test: ${matched.length} matched${data.blocked ? " (would block)" : ""}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
      }
      const rule = data.rule as Record<string, unknown> | undefined;
      return { tool, ok: true, summary: `rewrite rule ${action}: ${rule ? String(rule.id) : action}`, data: { ...data, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.websocket": {
      const action = String(input.action || "list").toLowerCase();
      const body: Record<string, unknown> = { ...input, action };
      if (action === "open") {
        const raw = String(input.url || ctx.target);
        const probe = raw.replace(/^wss:/i, "https:").replace(/^ws:/i, "http:");
        requireTargetHost(probe, host);
        body.url = raw.replace(/^https:/i, "wss:").replace(/^http:/i, "ws:");
      }
      const data = await burpBridgeCall(ctx, { path: "/websocket", method: "POST", timeoutMs: 60_000, body: JSON.stringify(body) });
      if (action === "open") return { tool, ok: true, summary: `websocket open ${String(data.session_id)} -> ${String(data.url)}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
      if (action === "send") return { tool, ok: true, summary: `websocket sent ${String(data.sent)} (${String(data.bytes)} bytes)`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
      if (action === "messages") {
        const messages = Array.isArray(data.messages) ? data.messages : [];
        return { tool, ok: true, summary: `${messages.length} new frames (${String(data.total)} total)`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
      }
      if (action === "close") return { tool, ok: true, summary: `websocket closed ${String(data.session_id)}`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
      if (action !== "list") throw reject("websocket action must be open, send, messages, close or list");
      const sessions = Array.isArray(data.sessions) ? data.sessions : [];
      return { tool, ok: true, summary: `${sessions.length} websocket sessions`, data: { ...data, host, source: "Burp Suite" }, artifacts: [] };
    }
    case "burp.bchecks": {
      const script = String(input.bcheck || input.json || "");
      if (!script.trim()) throw reject("bcheck is required: send the .bcheck JSON content");
      const data = await burpBridgeCall(ctx, { path: "/bchecks", method: "POST", timeoutMs: 30_000, body: JSON.stringify({ ...input, bcheck: script }) });
      const errors = Array.isArray(data.errors) ? data.errors : [];
      return {
        tool, ok: true,
        summary: `Burp bcheck import: ${String(data.status)}${errors.length ? ` (${errors.length} errors)` : ""}`,
        data: { ...data, source: "Burp Suite" }, artifacts: [],
      };
    }
    default:
      throw reject(`unsupported Burp Bridge tool: ${tool}`);
  }
}

export function runKatana(path: string, args: string[], timeoutMs: number, signal?: AbortSignal, maxOutputBytes = 2 * 1024 * 1024, env?: Record<string, string>): Promise<{ code: number; stdout: Buffer; stderr: string; truncated: boolean; timed_out: boolean }> {
  signal?.throwIfAborted();
  return new Promise((resolvePromise, reject) => {
    const child = spawn(path, args, { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: env ? { ...process.env, ...env } : process.env });
    const chunks: Buffer[] = [];
    let size = 0;
    let truncated = false;
    let timedOut = false;
    let stderr = "";
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    const unsubscribe = onAbort(signal, () => { child.kill("SIGKILL"); });
    child.stdout.on("data", (chunk: Buffer) => {
      if (size >= maxOutputBytes) { truncated = true; return; }
      const kept = chunk.subarray(0, maxOutputBytes - size);
      chunks.push(kept); size += kept.length;
      if (kept.length < chunk.length) truncated = true;
    });
    child.stderr.on("data", (chunk: Buffer) => { stderr = (stderr + chunk.toString("utf8")).slice(-16_000); });
    child.once("error", (error) => { unsubscribe(); clearTimeout(timer); reject(error); });
    child.once("close", (code) => { unsubscribe(); clearTimeout(timer); if (signal?.aborted) reject(signal.reason); else resolvePromise({ code: code ?? -1, stdout: Buffer.concat(chunks), stderr, truncated, timed_out: timedOut }); });
  });
}

function externalTarget(input: Record<string, unknown>, fallback: string): string {
  const target = httpUrl(input.url, fallback);
  return target.replace(/\/+$/, "");
}

function externalHost(target: string): string {
  return new URL(target).hostname;
}

export type ToolOptions = { values: Record<string, string>; notes?: string[] };

const NO_PARAM_TOOLS = new Set(["browser.open", "browser.screenshot", "browser.close", "browser.storage", "evidence.read", "http.request", "burp.check", "burp.request", "burp.history", "burp.sitemap", "burp.entry", "burp.issues", "burp.ws_history", "burp.scope", "burp.intercept", "burp.decoder", "burp.send", "burp.repeater", "burp.organizer", "burp.collab_generate", "burp.collab_poll", "burp.scan", "burp.scan_status", "burp.scan_stop", "burp.info", "burp.control", "burp.options", "burp.cookies", "burp.storage", "burp.sitemap_issues", "burp.sitemap_add", "burp.scope_edit", "burp.send_batch", "burp.crawl", "burp.scan_issues", "burp.scan_report", "burp.intruder", "burp.intruder_send", "burp.compare", "burp.convert", "katana.crawl", "recon.interactsh", "recon.wordlists", "recon.scan_profile", "recon.race_condition", "exec.python", "exec.bash", "fs.list", "fs.read", "fs.grep", "browser.tab", "browser.network"]);

/** Validate `input.params` against the tool allowlist and return the values that will be applied. */
function toolOptions(tool: string, input: Record<string, unknown>): ToolOptions {
  const raw = input.params;
  if (raw === undefined) return { values: {} };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw reject("input.params must be an object");
  const rules = TOOL_PARAMS[tool];
  if (!rules) throw reject(NO_PARAM_TOOLS.has(tool)
    ? `tool ${tool} does not accept input.params`
    : `tool ${tool} accepts no input.params; supported tools: ${Object.keys(TOOL_PARAMS).join(", ")}`);
  const entries = Object.entries(raw as Record<string, unknown>);
  const allowed = Object.keys(rules).join(", ");
  const values: Record<string, string> = {};
  for (const [key, value] of entries) {
    const rule = rules[key];
    if (!rule) throw reject(`unknown parameter "${key}" for ${tool}; allowed: ${allowed}`);
    if (rule.kind === "int") {
      const number = typeof value === "number" ? value : Number(String(value).trim());
      if (!Number.isInteger(number) || number < rule.min || number > rule.max) throw reject(`${tool}.params.${key} must be an integer between ${rule.min} and ${rule.max}`);
      values[key] = String(number);
      continue;
    }
    if (rule.kind === "choice") {
      const choice = String(value).trim().toUpperCase();
      if (!rule.values.includes(choice)) throw reject(`${tool}.params.${key} must be one of ${rule.values.join(", ")}`);
      values[key] = choice;
      continue;
    }
    if (rule.kind === "tokens") {
      const items = String(value).split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
      if (!items.length || items.length > rule.maxItems) throw reject(`${tool}.params.${key} must contain 1 to ${rule.maxItems} comma-separated values`);
      for (const item of items) if (!rule.pattern.test(item) || item.length > rule.maxLength) throw reject(`${tool}.params.${key} has an invalid value: ${item}`);
      values[key] = items.join(",");
      continue;
    }
    const text = String(value);
    if (!text || text.length > rule.maxLength) throw reject(`${tool}.params.${key} must be 1 to ${rule.maxLength} characters`);
    if (!rule.pattern.test(text)) throw reject(`${tool}.params.${key} has an invalid value`);
    if (rule.noTraversal && (text.includes("..") || text.startsWith("/") || text.includes("\\"))) throw reject(`${tool}.params.${key} must be a relative path without ".."`);
    values[key] = text;
  }
  return { values };
}

type ExternalSpec = {
  tool: string; env: string;
  args: (target: string, input: Record<string, unknown>, ctx: BlackboxToolContext, options: ToolOptions) => string[];
  /** Build the flags for a pipeline run: the targets come from a file, not one URL. */
  listArgs?: (list: string, input: Record<string, unknown>, options: ToolOptions) => string[];
  maxSeconds: number;
  flags?: ExternalFlags;
  output?: "nuclei" | "httpx";
  /** The CLI requires the target as its final argument (testssl.sh: "URI comes last"). */
  targetLast?: boolean;
};
const externalDefaults: Record<string, string> = {
  SUBFINDER_PATH: "/usr/local/bin/subfinder",
  DNSX_PATH: "/usr/local/bin/dnsx",
  HTTPX_PATH: "/usr/local/bin/httpx",
  NAABU_PATH: "/usr/local/bin/naabu",
  GAU_PATH: "/usr/local/bin/gau",
  FFUF_PATH: "/usr/local/bin/ffuf",
  NUCLEI_PATH: "/usr/local/bin/nuclei",
  INTERACTSH_CLIENT_PATH: "/usr/local/bin/interactsh-client",
  ARJUN_PATH: "/usr/local/bin/arjun", SUBJS_PATH: "/usr/local/bin/subjs", TESTSSL_PATH: "/usr/local/bin/testssl.sh",
  KITERUNNER_PATH: "/usr/local/bin/kiterunner", DALFOX_PATH: "/usr/local/bin/dalfox", SQLMAP_PATH: "/usr/local/bin/sqlmap",
  JWT_TOOL_PATH: "/usr/local/bin/jwt_tool", GRAPHQL_COP_PATH: "/usr/local/bin/graphql-cop", WPSCAN_PATH: "/usr/local/bin/wpscan",
  TRUFFLEHOG_PATH: "/usr/local/bin/trufflehog", SEMGREP_PATH: "/usr/local/bin/semgrep",
};

type InteractshRuntime = {
  child: ReturnType<typeof spawn>;
  output: string;
  payload?: string;
  started_at: number;
};
const interactshRuntimes = new Map<string, InteractshRuntime>();

const externalSpecs: Record<string, ExternalSpec> = {
  "recon.subdomains": { tool: "recon.subdomains", env: "SUBFINDER_PATH", args: (target) => ["-d", externalHost(target), "-silent"], maxSeconds: 90 },
  "recon.dns": { tool: "recon.dns", env: "DNSX_PATH", listArgs: (list) => ["-l", list, "-silent", "-resp", "-a", "-cname"], args: (target) => ["-d", externalHost(target), "-silent", "-resp", "-a", "-cname"], maxSeconds: 90 },
  "recon.http_probe": { tool: "recon.http_probe", env: "HTTPX_PATH", output: "httpx", flags: { header: "-H", proxy: "-http-proxy" }, listArgs: (list, _input, options) => {
    const args = ["-l", list, "-silent", "-json", "-status-code", "-title", "-tech-detect", "-follow-redirects"];
    if (options.values.ports) args.push("-ports", options.values.ports);
    if (options.values.threads) args.push("-threads", options.values.threads);
    return args;
  }, args: (target, _input, _ctx, options) => {
    const args = ["-u", target, "-silent", "-json", "-status-code", "-title", "-tech-detect", "-follow-redirects"];
    if (options.values.ports) args.push("-ports", options.values.ports);
    if (options.values.threads) args.push("-threads", options.values.threads);
    return args;
  }, maxSeconds: 120 },
  "recon.ports": { tool: "recon.ports", env: "NAABU_PATH", listArgs: (list, _input, options) => {
    const args = ["-list", list, "-silent"];
    if (options.values.ports) args.push("-p", options.values.ports);
    args.push("-rate", options.values.rate ?? "100");
    return args;
  }, args: (target, _input, _ctx, options) => {
    const args = ["-host", externalHost(target), "-silent"];
    if (options.values.ports) args.push("-p", options.values.ports);
    args.push("-rate", options.values.rate ?? "100");
    return args;
  }, maxSeconds: 180 },
  "recon.historical_urls": { tool: "recon.historical_urls", env: "GAU_PATH", flags: { header: "--headers", headerStyle: "lines" }, args: (target) => [externalHost(target)], maxSeconds: 120 },
  "recon.content_discovery": { tool: "recon.content_discovery", env: "FFUF_PATH", flags: { header: "-H", proxy: "-x" }, args: (target, input, ctx, options) => {
    const wordlist = approvedWordlist(input, ctx, "recon.content_discovery");
    // -ac 自动校准：目标对任意路径都返回 301/200（catch-all）时，ffuf 会把整本字典
    // 都当命中 —— 实测 note.yun 那轮一次 content_discovery 就产出 224 条“发现”，
    // 全是同一个 301，图被灌成 241 个节点、agent 之后再也没看过它们。
    // -ac 先打一个随机路径做基线，把与它同形（长度/字数/行数）的响应滤掉；
    // -mc 再收窄到“有意义的状态码”。
    // 412/418 必须保留：它们是云 WAF 的阻断码（securityfs 就是 412）。
    // 把它们排除掉，字典撞墙时结果是"0 发现"，整堵墙在账本里彻底消失，
    // 于是 waf_escalation 永远不成立、战例库也永远不会被调用（2026-10-30 qwen 那轮）。
    const args = ["-u", `${target.replace(/\/$/, "")}/FUZZ`, "-w", wordlist, "-s", "-ac",
      "-mc", "200,201,202,204,206,301,302,303,307,308,401,403,405,412,418,500",
      "-rate", options.values.rate ?? "10", "-maxtime", "120"];
    if (options.values.threads) args.push("-t", options.values.threads);
    if (options.values.method) args.push("-X", options.values.method);
    if (options.values.extensions) args.push("-e", options.values.extensions);
    return args;
  }, maxSeconds: 180 },
  "recon.nuclei": { tool: "recon.nuclei", env: "NUCLEI_PATH", output: "nuclei", flags: { header: "-H", cookie: "-H", cookieStyle: "header", proxy: "-proxy" }, listArgs: (list, _input, options) => {
    const args = ["-l", list, "-jsonl", "-silent", "-disable-update-check",
      "-retries", options.values.retries ?? "0", "-timeout", options.values.timeout_s ?? "8",
      "-rate-limit", options.values.rate_limit ?? "30", "-bulk-size", "25", "-concurrency", options.values.concurrency ?? "10"];
    args.push("-severity", options.values.severity || "critical,high,medium");
    if (options.values.tags) args.push("-tags", options.values.tags);
    if (options.values.templates) args.push("-t", options.values.templates);
    return args;
  }, args: (target, _input, _ctx, options) => {
    const args = ["-u", target, "-jsonl", "-silent", "-disable-update-check",
      "-retries", options.values.retries ?? "0", "-timeout", options.values.timeout_s ?? "8",
      "-rate-limit", options.values.rate_limit ?? "30", "-bulk-size", "25", "-concurrency", options.values.concurrency ?? "10"];
    args.push("-severity", options.values.severity || "critical,high,medium");
    if (options.values.tags) args.push("-tags", options.values.tags);
    if (options.values.templates) args.push("-t", options.values.templates);
    return args;
  }, maxSeconds: 300 },
  "recon.parameters": { tool: "recon.parameters", env: "ARJUN_PATH", args: (target) => ["-u", target, "--stable"], maxSeconds: 180 },
  "recon.js_endpoints": { tool: "recon.js_endpoints", env: "SUBJS_PATH", args: (target) => ["-i", target], maxSeconds: 120 },
  "recon.tls": { tool: "recon.tls", env: "TESTSSL_PATH", flags: { proxy: "--proxy" }, targetLast: true, listArgs: (list, _input, options) => {
    const args = ["--warnings", "batch", "--quiet", "--file", list];
    if (options.values.severity) args.push("--severity", options.values.severity);
    return args;
  }, args: (_target, _input, _ctx, options) => {
    const args = ["--warnings", "batch", "--quiet"];
    if (options.values.severity) args.push("--severity", options.values.severity);
    return args;
  }, maxSeconds: 150 },
  "recon.api_routes": { tool: "recon.api_routes", env: "KITERUNNER_PATH", flags: { header: "-H" }, args: (target, input, ctx) => ["scan", approvedWordlist(input, ctx, "recon.api_routes"), "-A=probe", target, "--fail-status-codes", "404", "--rate-limit", "5"], maxSeconds: 300 },
  "recon.xss": { tool: "recon.xss", env: "DALFOX_PATH", flags: { header: "-H", cookie: "-H", cookieStyle: "header", proxy: "--proxy" }, args: (target) => ["url", target, "--silence", "--skip-bav", "--worker", "1"], maxSeconds: 240 },
  "recon.sql": { tool: "recon.sql", env: "SQLMAP_PATH", flags: { header: "--headers", headerStyle: "lines", cookie: "--cookie", cookieStyle: "raw", proxy: "--proxy" }, args: (target, _input, _ctx, options) => {
    const args = ["-u", target, "--batch", "--smart", `--level=${options.values.level ?? "1"}`, `--risk=${options.values.risk ?? "1"}`, "--threads=1"];
    if (options.values.technique) args.push(`--technique=${options.values.technique}`);
    if (options.values.dbms) args.push(`--dbms=${options.values.dbms}`);
    if (options.values.data) args.push("--data", options.values.data);
    if (options.values.param) args.push("-p", options.values.param);
    return args;
  }, maxSeconds: 600 },
  "recon.jwt": { tool: "recon.jwt", env: "JWT_TOOL_PATH", args: (_target, input) => {
    const token = String(input.token || "").trim();
    if (!token) throw reject("jwt-tool requires input.token");
    return [token, "-d"];
  }, maxSeconds: 90 },
  "recon.graphql": { tool: "recon.graphql", env: "GRAPHQL_COP_PATH", args: (target) => ["-t", target], maxSeconds: 150 },
  "recon.cms": { tool: "recon.cms", env: "WPSCAN_PATH", flags: { header: "--headers", headerStyle: "lines", cookie: "--cookie", cookieStyle: "raw", proxy: "--proxy" }, args: (target) => ["--url", target, "--no-update", "--format", "json", "--plugins-detection", "passive"], maxSeconds: 300 },
  "recon.secrets": { tool: "recon.secrets", env: "TRUFFLEHOG_PATH", args: (_target, input) => ["filesystem", String(input.path || "").trim(), "--json", "--no-update"], maxSeconds: 300 },
  "recon.sast": { tool: "recon.sast", env: "SEMGREP_PATH", args: (_target, input, ctx) => ["scan", "--json", "--quiet", "--metrics", "off", "--config", semgrepRulesPath(ctx), String(input.path || ".")], maxSeconds: 600 },
};

export function approvedFilePath(file: string, configuredRoot?: string, label = "file"): string {
  const root = resolve(configuredRoot || process.env.NIANYUN_WORDLIST_ROOT || ".");
  const absolute = resolve(file);
  if (absolute !== root && !absolute.startsWith(`${root}${sep}`)) throw reject(`${label} must be inside the approved wordlist directory (${root})`);
  return file;
}

/** Bundled wordlists per tool: a missing input.wordlist must not disable the tool. */
const DEFAULT_WORDLISTS: Record<string, string> = { "recon.content_discovery": "paths.txt" };

function defaultWordlist(tool: string, configuredRoot: string): string {
  const file = DEFAULT_WORDLISTS[tool];
  if (!file) return "";
  const roots = [configuredRoot, process.env.NIANYUN_WORDLIST_ROOT || "", join(process.cwd(), "resources", "wordlists"), "/opt/nianyun/resources/wordlists"]
    .map(root => String(root || "").trim()).filter(Boolean);
  for (const root of roots) {
    const candidate = root.endsWith(file) ? root : join(root, file);
    if (existsSync(candidate)) return candidate;
  }
  return "";
}

/**
 * nuclei 二进制不含模板：优先 NUCLEI_TEMPLATES_PATH，否则用数据卷里的 nuclei-templates。
 * 目录不存在时返回空串，让调用方保留原来的行为（用户自己给 -t）。
 */
function defaultNucleiTemplates(ctx: BlackboxToolContext): string {
  const configured = String(ctx.values?.NUCLEI_TEMPLATES_PATH || process.env.NUCLEI_TEMPLATES_PATH || "").trim();
  if (configured && existsSync(configured)) return configured;
  // Test doubles and partial contexts have no cfg: fall through to "no default".
  const dataDir = String(ctx.cfg?.data_dir || "").trim();
  if (!dataDir) return "";
  const volume = join(dataDir, "nuclei-templates");
  return existsSync(volume) ? volume : "";
}

/**
 * 单主机跑全量 15k 模板在阶段时限内跑不完（300s 一到就“超时且无结果”）。
 * 默认只打高价值目录，模型仍可用 params.templates / params.tags 扩大范围。
 */
const NUCLEI_DEFAULT_SCOPES = [
  "http/cves", "http/vulnerabilities", "http/exposures", "http/cnvd",
  "http/misconfiguration", "http/takeovers", "http/default-logins", "http/exposed-panels",
];

function nucleiScopeDirs(root: string): string[] {
  return NUCLEI_DEFAULT_SCOPES.map(scope => join(root, scope)).filter(dir => existsSync(dir));
}

/** 需要本地文件的工具：给 URL 一律在执行器拦下，别让 trufflehog 去 lstat("http://…")。 */
const LOCAL_PATH_TOOLS = new Set(["recon.secrets", "recon.sast"]);

function localPathOf(tool: string, input: Record<string, unknown>): string {
  const raw = String(input.path || "").trim();
  if (!raw) throw reject(`${tool} requires input.path (a local directory or file), not a URL`);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith("//")) {
    throw reject(`${tool}: expected a local path, got URL (${raw.slice(0, 120)}). Use recon.js_endpoints / http.request for URLs; download the file first, then point path at it.`);
  }
  return raw;
}

/**
 * recon.sast 的规则来源：`--config auto` 必须回连 semgrep 注册表，控制面容器全部出站走代理，
 * 注册表请求不返回也不报错（实测 `semgrep --version` 就 >60s 挂住）。所以默认用随镜像分发的
 * 本地规则集，`SEMGREP_RULES_PATH` 可指向自备规则目录。
 */
/** stdout 可能被截断或混入日志：解析失败就当作"没有结构化输出"，不要抛。 */
function safeJsonObject(text: string): Record<string, unknown> | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{")) return null;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch { return null; }
}

function semgrepRulesPath(ctx?: BlackboxToolContext): string {
  const configured = String(ctx?.values.SEMGREP_RULES_PATH || process.env.SEMGREP_RULES_PATH || "").trim();
  const dataDir = ctx?.cfg.data_dir ? String(ctx.cfg.data_dir) : "";
  const candidates = [configured, join(process.cwd(), "resources", "semgrep", "nianyun-src.yml"), join(process.cwd(), "resources", "semgrep"), "/opt/nianyun/resources/semgrep/nianyun-src.yml", "/opt/nianyun/resources/semgrep", dataDir ? join(dataDir, "semgrep-rules") : ""]
    .map(item => String(item || "").trim()).filter(Boolean);
  const found = candidates.find(item => existsSync(item));
  if (!found) throw reject("recon.sast needs a local semgrep ruleset: set SEMGREP_RULES_PATH (—config auto requires the semgrep registry, which this deployment cannot reach)");
  return found;
}

function approvedWordlist(input: Record<string, unknown>, ctx?: BlackboxToolContext, tool = ""): string {
  const requested = String(input.wordlist || "").trim();
  if (!ctx) {
    if (!requested) throw reject(`${tool || "this tool"} requires input.wordlist`);
    return approvedFilePath(requested, String(input.wordlist_root || "").trim() || process.env.NIANYUN_WORDLIST_ROOT || ".");
  }
  // 字典不再"必须先知道路径"：没给值就按类别挑一个已挂载的默认字典。
  // 显式给了 input.wordlist_root 时优先用它（兼容旧调用与单测）。
  const extraRoot = String(input.wordlist_root || "").trim();
  const roots = extraRoot ? [extraRoot, ...wordlistRoots(ctx)] : wordlistRoots(ctx);
  const category = tool === "recon.api_routes" ? "api" : "path";
  return resolveApprovedAsset(ctx, requested, { roots, label: "wordlist", category });
}

function interactshServer(input: Record<string, unknown>, ctx: BlackboxToolContext): string {
  const raw = String(input.server || ctx.values.INTERACTSH_URL || process.env.INTERACTSH_URL || "").trim();
  if (!raw) throw reject("Interactsh server is not configured (INTERACTSH_URL)");
  const parsed = new URL(raw);
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) throw reject("Interactsh server must be a credential-free HTTP(S) URL");
  return parsed.toString().replace(/\/$/, "");
}

function interactshPayload(output: string): string | undefined {
  for (const line of output.split(/\r?\n/)) {
    const value = line.trim();
    if (!value) continue;
    try {
      const parsed = JSON.parse(value) as Record<string, unknown>;
      const candidate = String(parsed.url || parsed.correlation_id || parsed["correlation-id"] || "").trim();
      if (candidate) return candidate;
    } catch { /* client may emit a plain payload before JSON events */ }
    const candidate = value.match(/(?:https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?/i)?.[0];
    if (candidate) return candidate;
  }
  return undefined;
}

async function interactshTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const action = String(input.action || "start").toLowerCase();
  const runtimeId = String(input.runtime_id || `${ctx.projectId}:${ctx.sessionId}`).slice(0, 200);
  const waitSeconds = boundedInteger(input.wait_seconds, action === "start" ? 8 : 3, 0, 30);
  const bundledPath = externalDefaults.INTERACTSH_CLIENT_PATH || "";
  const path = String(ctx.values.INTERACTSH_CLIENT_PATH || process.env.INTERACTSH_CLIENT_PATH || "").trim() || (bundledPath && existsSync(bundledPath) ? bundledPath : "");
  if (!path) throw reject("Interactsh client is not configured (INTERACTSH_CLIENT_PATH)");
  if (action === "start") {
    const existing = interactshRuntimes.get(runtimeId);
    if (existing) throw reject("Interactsh runtime already exists; use poll or stop");
    const server = interactshServer(input, ctx);
    const args = ["-server", server, "-json", "-silent"];
    const token = String(input.token || ctx.values.INTERACTSH_TOKEN || process.env.INTERACTSH_TOKEN || "").trim();
    if (token) args.push("-token", token);
    const child = spawn(path, args, { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const runtime: InteractshRuntime = { child, output: "", started_at: Date.now() };
    interactshRuntimes.set(runtimeId, runtime);
    child.stdout.on("data", (chunk: Buffer) => { runtime.output = (runtime.output + chunk.toString("utf8")).slice(-128_000); runtime.payload ||= interactshPayload(runtime.output); });
    child.stderr.on("data", (chunk: Buffer) => { runtime.output = (runtime.output + chunk.toString("utf8")).slice(-128_000); });
    const unsubscribe = onAbort(ctx.signal, () => { child.kill("SIGKILL"); });
    await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.max(0, waitSeconds * 1000)));
    unsubscribe();
    return { tool: "recon.interactsh", ok: true, summary: runtime.payload ? "Interactsh listener ready with a callback payload" : "Interactsh listener started; poll for a callback payload", data: { action, runtime_id: runtimeId, payload: runtime.payload || null, output: runtime.output.slice(-16_000), running: runtime.child.exitCode === null, started_at: runtime.started_at }, artifacts: [] };
  }
  const runtime = interactshRuntimes.get(runtimeId);
  if (!runtime) throw reject("Interactsh runtime not found; start it first");
  if (action === "poll") {
    const unsubscribe = onAbort(ctx.signal, () => { runtime.child.kill("SIGKILL"); });
    await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.max(0, waitSeconds * 1000)));
    unsubscribe();
    return { tool: "recon.interactsh", ok: true, summary: runtime.payload ? "Interactsh callback evidence received" : "No Interactsh callback observed yet", data: { action, runtime_id: runtimeId, payload: runtime.payload || null, output: runtime.output.slice(-16_000), running: runtime.child.exitCode === null, started_at: runtime.started_at }, artifacts: [] };
  }
  if (action === "stop") {
    runtime.child.kill("SIGTERM");
    interactshRuntimes.delete(runtimeId);
    return { tool: "recon.interactsh", ok: true, summary: "Interactsh listener stopped", data: { action, runtime_id: runtimeId, output: runtime.output.slice(-16_000), running: false }, artifacts: [] };
  }
  throw reject("Interactsh action must be start, poll, or stop");
}

/** Resolve the argument vector for an external tool without spawning it (also used by tests). */
/** Pull the URLs a tool actually discovered out of its full output, not the bounded result. */
export function urlsFromText(text: string, limit = 20_000): string[] {
  const seen = new Set<string>();
  const urls: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const value = line.trim();
    if (!value) continue;
    let candidate = "";
    if (value.startsWith("{")) {
      try {
        const parsed = JSON.parse(value) as Record<string, unknown>;
        for (const key of ["url", "endpoint", "matched-at", "final_url", "input", "host"]) {
          const raw = parsed[key];
          if (typeof raw === "string" && raw.trim()) { candidate = raw.trim(); break; }
        }
      } catch { /* line-oriented output */ }
    }
    if (!candidate) {
      const match = /https?:\/\/[^\s"'<>,;]+/.exec(value);
      candidate = match ? match[0] : "";
    }
    if (!candidate || candidate.length > 4096 || seen.has(candidate)) continue;
    seen.add(candidate);
    urls.push(candidate);
    if (urls.length >= limit) break;
  }
  return urls;
}

export type PipelineSource = { targets: string[]; tool?: string; evidence_id?: string; total_lines?: number };

/** Resolve `input.source` to a target list: latest result of a tool, or one explicit evidence id. */
export function resolvePipelineSource(ctx: BlackboxToolContext, raw: unknown): PipelineSource {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw reject("input.source must be an object");
  const source = raw as Record<string, unknown>;
  const evidenceId = String(source.evidence_id || "").trim();
  const tool = canonicalTool(String(source.tool || "").trim());
  const limit = boundedInteger(source.limit, 500, 1, 20_000);
  if (!evidenceId && !tool) throw reject("input.source requires tool or evidence_id");
  const result = evidenceId
    ? ctx.db.getBlackboxArtifact(ctx.projectId, ctx.sessionId, evidenceId)
    : ctx.db.latestBlackboxToolResult(ctx.projectId, ctx.sessionId, tool);
  if (!result) throw reject(`pipeline source not found: ${tool || evidenceId}`);
  const artifact = tool ? ctx.db.latestBlackboxArtifact(ctx.projectId, ctx.sessionId, tool) : result;
  let text = "";
  let totalLines: number | undefined;
  const relative = String(artifact?.artifact_path || result.artifact_path || "").trim();
  if (relative) {
    const root = resolve(ctx.cfg.data_dir);
    const absolute = resolve(join(root, relative));
    if (absolute === root || absolute.startsWith(`${root}${sep}`)) {
      if (existsSync(absolute)) {
        text = readFileSync(absolute, "utf8");
        totalLines = text.split(/\r?\n/).length;
      }
    }
  }
  if (!text) {
    const items = (result.data as Record<string, unknown> | undefined)?.items;
    text = Array.isArray(items) ? items.map(String).join("\n") : "";
  }
  const targets = urlsFromText(text, limit);
  if (!targets.length) throw reject(`pipeline source ${tool || evidenceId} produced no targets`);
  return { targets, ...(tool ? { tool } : {}), ...(evidenceId ? { evidence_id: evidenceId } : {}), ...(totalLines === undefined ? {} : { total_lines: totalLines }) };
}

function writeTargetList(ctx: BlackboxToolContext, targets: string[]): { absolute: string; relative: string } {
  const artifact = artifactPath(ctx, "txt");
  writeFileSync(artifact.absolute, targets.join("\n"));
  return artifact;
}

export function externalToolCommand(tool: string, target: string, input: Record<string, unknown>, ctx: BlackboxToolContext, listPath?: string): { args: string[]; options: ToolOptions } {
  const spec = externalSpecs[tool];
  if (!spec) throw reject(`unsupported external reconnaissance tool: ${tool}`);
  // 动态参数协商：scan_profile 里的值作为默认，模型显式 params 仍然优先。
  const profile = readScanProfile(ctx);
  const rawParams = input.params;
  const paramsIsObject = rawParams !== undefined && typeof rawParams === "object" && rawParams !== null && !Array.isArray(rawParams);
  const explicit = paramsIsObject ? rawParams as Record<string, unknown> : {};
  const profileDefaults: Record<string, unknown> = tool === "recon.nuclei"
    ? { timeout_s: profile.timeout_s, rate_limit: profile.rate_limit, retries: profile.retries }
    : {};
  // 顶层别名（threads…）先折进 params 再合并：模型写在哪一层都能生效，
  // 否则 schema 摘掉它、执行器用默认值，"调了并发"其实是没调。
  const merged = foldTopLevelParams(tool, input, { ...profileDefaults, ...explicit });
  // 只有真的有参数时才加 params 键：否则会误伤那些"不接受 params"的工具。
  // 但格式错误的 params（字符串/数组）必须原样透传，让 toolOptions 报错而不是被静默丢掉。
  const effectiveInput = rawParams !== undefined && !paramsIsObject
    ? input
    : Object.keys(merged).length ? { ...input, params: merged } : input;
  const options = toolOptions(tool, effectiveInput);
  const rules = blackboxRules(ctx.values);
  const extraNotes: string[] = [];
  // Base flags (single target or a pipeline list), then auth/proxy wiring, then model extras:
  // a human running this by hand would pass all three, and extras last still override a default.
  if (LOCAL_PATH_TOOLS.has(tool)) localPathOf(tool, input);
  /**
   * dnsx 的 `-d` 是"对域做子域爆破"，**必须再给 `-w wordlist`**，否则直接 FTL：
   * `missing wordlist(w) flag required with domain(d) input`。
   * 实跑 090e71cc2732165e（im.ctrip.com，2026-11-02）里模型调 `recon.dns` 解析
   * 证书 SAN 里的几个域名，输入是空的（目标取自会话资产），于是走 `-d` 分支当场 exit 1，
   * 一条 DNS 证据都没拿到，任务被判"工具失败"。
   *
   * 单主机场景真正该用的是列表输入（= 主机名本身），所以这里把目标写成一行列表走 `-l`。
   */
  if (tool === "recon.dns" && !listPath && ctx.cfg?.data_dir) {
    const host = externalHost(target);
    if (host) listPath = writeTargetList(ctx, [host]).absolute;
  }
  const base = listPath && spec.listArgs ? spec.listArgs(listPath, input, options) : spec.args(target, input, ctx, options);
  const args = [
    ...base,
    ...commonToolArgs(spec, input, ctx, target),
    ...extraToolArgs(tool, input.args, {
      allowCredentialAttack: rules.tools[tool]?.allow_credential_attack === true,
      interactive: boolValue(ctx.values.BLACKBOX_ALLOW_INTERACTIVE_EXEC, false),
      wordlistRoots: wordlistRoots(ctx),
      templateRoots: templateRoots(ctx),
      proxyUrl: optionalProxy(ctx),
      onNote: note => extraNotes.push(note),
    }),
  ];
  if (extraNotes.length) options.notes = [...(options.notes || []), ...extraNotes];
  // nuclei 没有模板就会以 "no templates provided" 整体失败；数据卷里已放好模板。
  if (tool === "recon.nuclei" && !args.includes("-t")) {
    const templates = defaultNucleiTemplates(ctx);
    if (templates) {
      const scopes = nucleiScopeDirs(templates);
      if (scopes.length) for (const dir of scopes) args.push("-t", dir);
      else args.push("-t", templates);
    }
  }
  // testssl.sh aborts with "URI comes last" when any flag follows the target.
  if (spec.targetLast) args.push(target);
  return { args, options };
}

/** Per-tool wall clock: the spec cap, raised by an explicit `timeout_seconds` within the stage budget. */
export function externalToolTimeoutMs(tool: string, input: Record<string, unknown>): number {
  const spec = externalSpecs[tool];
  const cap = (spec?.maxSeconds ?? 120) * 1000;
  const requested = boundedInteger(input.timeout_seconds, 0, 0, 900) * 1000;
  return Math.min(900_000, Math.max(cap, requested));
}

/**
 * External CLIs split diagnostics between streams: katana prints flag errors to stdout,
 * wpscan prints its JSON abort reason to stdout and leaves stderr empty. Quote both so a
 * failure is diagnosable from the ledger instead of reading "exited with code 2:".
 */
export function externalFailureDetail(run: { stdout: Buffer; stderr: string }): string {
  const stderr = run.stderr.trim();
  const stdout = run.stdout.toString("utf8").trim();
  return (stderr || stdout).replace(/\s+/g, " ").trim().slice(-1200);
}

/** wpscan exits 4 both for "not WordPress" (a result) and for a missing database (a config problem). */
export function wpscanAbort(stdout: Buffer): { kind: "not_wordpress" | "missing_database" | "other"; reason: string } | null {
  const match = stdout.toString("utf8").match(/"scan_aborted"\s*:\s*"([^"]*)"/);
  if (!match) return null;
  const reason = match[1]!;
  if (/not seem to be running WordPress/i.test(reason)) return { kind: "not_wordpress", reason };
  if (/database|update required/i.test(reason)) return { kind: "missing_database", reason };
  return { kind: "other", reason };
}

async function externalReconTool(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const rules = blackboxRules(ctx.values);
  const spec = externalSpecs[tool];
  if (!spec) throw reject(`unsupported external reconnaissance tool: ${tool}`);
  const providerPath = tool === "recon.historical_urls" && String(input.provider || "").toLowerCase() === "waybackurls"
    ? String(ctx.values.WAYBACKURLS_PATH || process.env.WAYBACKURLS_PATH || "").trim()
    : "";
  const configured = providerPath || String(ctx.values[spec.env] || process.env[spec.env] || "").trim();
  const defaultPath = externalDefaults[spec.env];
  const path = configured || (defaultPath && existsSync(defaultPath) ? defaultPath : "");
  if (!path) throw reject(`${tool} is not configured (${spec.env})`);
  const target = externalTarget(input, ctx.target);
  // `input.source` turns one call into a pipeline stage: the previous tool's full artifact is
  // the input list, so katana -> httpx -> nuclei needs no manual URL copying.
  let listPath: string | undefined;
  let sourceArtifact: { absolute: string; relative: string } | undefined;
  let sourceData: Record<string, unknown> = {};
  if (input.source !== undefined) {
    if (!spec.listArgs) {
      const capable = Object.entries(externalSpecs).filter(([, item]) => item.listArgs).map(([name]) => name).join(", ");
      throw reject(`${tool} cannot consume input.source (pipeline-capable: ${capable})`);
    }
    const resolved = resolvePipelineSource(ctx, input.source);
    sourceArtifact = writeTargetList(ctx, resolved.targets);
    listPath = sourceArtifact.absolute;
    sourceData = { source: { ...resolved, count: resolved.targets.length }, source_file: sourceArtifact.relative };
  }
  const { args, options } = externalToolCommand(tool, target, input, ctx, listPath);
  const applied = Object.keys(options.values).length ? { params: options.values } : {};
  // 参数层的"改写/放行"说明（代理改写、字典解析、高危参数放行）必须进证据，而不是只活在日志里。
  const argNotes = options.notes?.length ? { arg_notes: options.notes } : {};
  const appliedArgs = Array.isArray(input.args) && input.args.length ? { extra_args: input.args.length } : {};
  const ceiling = externalToolTimeoutMs(tool, input);
  const timeout = remainingTimeout(ctx, Math.min(ceiling, boundedInteger(input.timeout_ms, ceiling, 1000, 900_000)));
  // wpscan keeps its metadata database under $HOME/.wpscan; point it at the data volume so a
  // prepared database survives container recreations instead of aborting every scan with
  // "Update required ... database file is missing".
  let toolEnv: Record<string, string> | undefined;
  if (tool === "recon.cms") {
    const home = join(String(ctx.cfg.data_dir), "tool-home");
    mkdirSync(home, { recursive: true });
    toolEnv = { HOME: home };
  }
  // semgrep 的版本检查/指标上报会回连厂商服务：容器里出站走代理，注册表请求不返回也不报错，
  // 实测 `semgrep --version` 就 >60s、一次 scan 98s。这两个变量是 recon.sast 能跑的前提。
  if (tool === "recon.sast") {
    toolEnv = { ...(toolEnv || {}), SEMGREP_ENABLE_VERSION_CHECK: "0", SEMGREP_SEND_METRICS: "off" };
  }
  const run = await runKatana(path, args, timeout, ctx.signal, rules.request.max_output_bytes, toolEnv);
  const raw = run.stdout.toString("utf8");
  const items: string[] = [];
  const findings: Record<string, unknown>[] = [];
  let truncated = false;
  // semgrep 的 `--json` 是**一整块** JSON，不是行式输出：按行切会得到"1 行结果、0 命中"，
  // 报告里就成了"扫了但什么都没有"。这里单独解析 results[]，再跳过行式循环。
  const sastJson = tool === "recon.sast" ? safeJsonObject(raw) : null;
  if (sastJson) {
    const results = Array.isArray(sastJson.results) ? sastJson.results as Record<string, unknown>[] : [];
    for (const hit of results) {
      if (findings.length >= MAX_EXTERNAL_FINDINGS) { truncated = true; break; }
      const extra = (hit.extra && typeof hit.extra === "object" ? hit.extra : {}) as Record<string, unknown>;
      const start = (hit.start && typeof hit.start === "object" ? hit.start : {}) as Record<string, unknown>;
      const file = String(hit.path || "");
      const line = Number(start.line || 0);
      findings.push({
        tool: "recon.sast",
        // --config 传路径时 semgrep 会把路径前缀拼进 check_id（resources.semgrep.xxx），只留规则名。
        rule: String(hit.check_id || "").split(".").pop() || "",
        severity: String(extra.severity || "WARNING"),
        path: file,
        line,
        message: String(extra.message || "").slice(0, 500),
        url: `${file}:${line}`,
      });
      if (items.length < MAX_EXTERNAL_ITEMS) items.push(`${file}:${line}`);
    }
  }
  for (const line of (sastJson ? "" : raw).split(/\r?\n/)) {
    const value = line.trim();
    if (!value) continue;
    if (value.length > 4096) truncated = true;
    let parsedFinding: Record<string, unknown> | null = null;
    if (spec.output === "nuclei") parsedFinding = parseNucleiLine(value);
    else if (spec.output === "httpx") parsedFinding = parseHttpxLine(value);
    if (parsedFinding && findings.length < MAX_EXTERNAL_FINDINGS) findings.push(parsedFinding);
    let candidate = String(parsedFinding?.url || value);
    if (!parsedFinding) {
      try {
        const parsed = JSON.parse(value) as Record<string, unknown>;
        candidate = String(parsed.url || parsed.host || parsed.input || parsed.matched_at || value);
      } catch { /* line-oriented output */ }
    }
    if (items.length < MAX_EXTERNAL_ITEMS) items.push(candidate.slice(0, 4096)); else truncated = true;
  }
  const structured = findings.length ? { findings } : {};
  // Persist whatever the tool managed to print before it was killed or failed.
  const artifact = artifactPath(ctx, "jsonl");
  writeFileSync(artifact.absolute, run.stdout);
  const artifacts: BlackboxArtifact[] = [...(sourceArtifact ? [{ kind: "target-list" as const, path: sourceArtifact.relative, media_type: "text/plain" }] : []), { kind: "tool-output", path: artifact.relative, media_type: "application/x-ndjson" }];
  if (run.timed_out) return {
    tool, ok: false,
    summary: `${tool} timed out after ${Math.round(timeout / 1000)}s with ${items.length} partial result lines`,
    data: { target, items, count: items.length, timed_out: true, timeout_ms: timeout, output_truncated: run.truncated, stderr: run.stderr, ...applied, ...appliedArgs, ...argNotes, ...structured, ...sourceData, ...(truncated ? { items_truncated: true } : {}) },
    artifacts,
  };
  if (!toolExitAccepted(tool, run.code)) {
    if (tool === "recon.cms") {
      const abort = wpscanAbort(run.stdout);
      if (abort?.kind === "not_wordpress") return {
        tool, ok: true,
        summary: `wpscan: target does not appear to be WordPress (${abort.reason})`,
        data: { target, wordpress: false, scan_aborted: abort.reason, items, count: items.length, exit_code: run.code, ...applied, ...appliedArgs, ...sourceData },
        artifacts,
      };
      if (abort?.kind === "missing_database") throw reject(`wpscan database is missing or out of date (${abort.reason}); run "wpscan --update" once and retry`);
    }
    throw new Error(`${tool} exited with code ${run.code}: ${externalFailureDetail(run)}`);
  }
  return {
    tool, ok: true, summary: findings.length ? `${tool} returned ${items.length} results (${findings.length} findings)` : `${tool} returned ${items.length} bounded result lines`,
    data: { target, items, count: items.length, exit_code: run.code, output_truncated: run.truncated, stderr: run.stderr, ...applied, ...appliedArgs, ...argNotes, ...structured, ...sourceData, ...(truncated ? { items_truncated: true } : {}) },
    artifacts,
  };
}

async function katanaTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const rules = blackboxRules(ctx.values);
  const path = String(ctx.values.KATANA_PATH || process.env.KATANA_PATH || "").trim();
  if (!path) throw reject("Katana is not configured");
  const url = httpUrl(input.url, ctx.target);
  // 深度/时长不再写死 3/60：规格说 katana depth≤3"绝对不够"，改为按 scan_profile 协商。
  const profile = readScanProfile(ctx);
  const depth = boundedInteger(input.depth, profile.katana_depth, 1, 8);
  const duration = boundedInteger(input.duration_seconds, profile.katana_duration_s, 5, 300);
  const maxRps = 1;
  const proxyUrl = proxy(ctx);
  const args = ["-u", url, "-d", String(depth), "-silent", "-jsonl", "-timeout", "10", "-crawl-duration", `${duration}s`, "-rl", String(maxRps)];
  if (proxyUrl) args.push("-proxy", proxyUrl);
  const run = await runKatana(path, args, remainingTimeout(ctx, Math.min(rules.request.max_timeout_ms, (duration + 25) * 1000)), ctx.signal, rules.request.max_output_bytes);
  const output = run.stdout.toString("utf8");
  const artifact = artifactPath(ctx, "jsonl");
  writeFileSync(artifact.absolute, run.stdout);
  const discovered = new Set<string>();
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let candidate = line.trim();
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      candidate = String(parsed.request && typeof parsed.request === "object" ? (parsed.request as Record<string, unknown>).endpoint || "" : parsed.url || parsed.endpoint || "");
    } catch { /* Katana may emit plain URLs despite jsonl mode. */ }
    if (/^https?:\/\//i.test(candidate) && discovered.size < 500) discovered.add(candidate);
  }
  if (run.timed_out) return {
    // A partial crawl is still usable work: the URLs are persisted, so the next round can
    // continue from them instead of the model re-running the same crawl.
    tool: "katana.crawl", ok: false,
    summary: `Katana timed out with ${discovered.size} partial URLs`,
    data: { target: url, depth, duration_seconds: duration, urls: [...discovered], items: [...discovered], count: discovered.size, partial: true, timed_out: true, output_truncated: run.truncated, stderr: run.stderr },
    artifacts: [{ kind: "tool-output", path: artifact.relative, media_type: "application/x-ndjson" }],
  };
  if (run.code !== 0) throw new Error(`Katana exited with code ${run.code}: ${externalFailureDetail(run)}`);
  return {
    tool: "katana.crawl", ok: true, summary: `Katana discovered ${discovered.size} URLs`,
    data: { target: url, depth, duration_seconds: duration, urls: [...discovered], items: [...discovered], count: discovered.size, output_truncated: run.truncated, stderr: run.stderr },
    artifacts: [{ kind: "tool-output", path: artifact.relative, media_type: "application/x-ndjson" }],
  };
}

/** subjs reads files: "-i <url>" was the bug that made every call die with ENOENT. */
export function subjsArgs(listPath: string): string[] {
  return ["-i", listPath];
}

/** JavaScript URLs referenced by a page, so subjs gets a list instead of an HTML document. */
export function jsUrlsFromHtml(html: string, base: string): string[] {
  const found = new Set<string>();
  /**
   * 2026-11-01：加**无引号**属性形态。实测 business.oppo.com 的外壳是压缩过的
   * `<script src=/static/js/office.xxxx.js>`（属性值不带引号），旧正则只认 `src="..."`，
   * 于是 37 个真实 bundle 被判成 `no_script_references`——一个假阴性把整条 SPA 逆向线堵死。
   * 无引号形态放在最前面：`src="a.js"` 不会命中它（`=` 后面是引号），靠 Set 去重不会双记。
   */
  for (const pattern of [
    /<script[^>]+src\s*=\s*([^\s"'>]+)/gi,
    /<script[^>]+src\s*=\s*["']([^"']+)["']/gi,
    /["']([^"'\s]+\.js(?:\?[^"'\s]*)?)["']/gi,
  ]) {
    for (const match of html.matchAll(pattern)) {
      const value = String(match[1] || "").trim();
      if (!value || /^javascript:/i.test(value)) continue;
      try {
        const url = new URL(value, base);
        if (["http:", "https:"].includes(url.protocol)) found.add(url.toString());
      } catch { /* relative value that cannot be resolved */ }
      if (found.size >= 200) return [...found];
    }
  }
  return [...found];
}

async function pageScriptUrls(target: string, signal?: AbortSignal): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  const relay = () => controller.abort();
  signal?.addEventListener("abort", relay);
  try {
    const response = await fetch(target, { redirect: "follow", signal: controller.signal, headers: { "user-agent": "nianyun-blackbox/1.0" } });
    return jsUrlsFromHtml(await response.text(), response.url || target);
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", relay);
  }
}

/**
 * subjs reads a *list* of JavaScript files. The old spec passed the page URL to `-i`, so every
 * call died with "Could not open input file: open <url>". Resolve real .js URLs first: from an
 * explicit list, from a pipeline source, or by parsing the page's script tags.
 */
async function jsEndpointsTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const rules = blackboxRules(ctx.values);
  const spec = externalSpecs["recon.js_endpoints"]!;
  const path = String(ctx.values[spec.env] || process.env[spec.env] || "").trim() || externalDefaults[spec.env] || "";
  if (!path) throw reject("subjs is not configured (SUBJS_PATH)");
  const target = externalTarget(input, ctx.target);
  let jsUrls: string[] = [];
  let sourceData: Record<string, unknown> = {};
  if (input.source !== undefined) {
    const resolved = resolvePipelineSource(ctx, input.source);
    jsUrls = resolved.targets;
    sourceData = { source: { ...resolved, count: resolved.targets.length } };
  } else if (Array.isArray(input.urls)) {
    jsUrls = input.urls.slice(0, 500).map((item) => httpUrl(item, target));
  }
  if (!jsUrls.length) jsUrls = /\.js(\?|$)/i.test(target) ? [target] : await pageScriptUrls(target, ctx.signal);
  if (!jsUrls.length) return {
    tool: "recon.js_endpoints", ok: true,
    summary: `${target} 页面未引用可分析的 JavaScript 文件`,
    data: { target, items: [], count: 0, js_files: 0, reason: "no_script_references", ...sourceData },
    artifacts: [],
  };
  const list = writeTargetList(ctx, jsUrls);
  const timeout = remainingTimeout(ctx, Math.min(spec.maxSeconds * 1000, boundedInteger(input.timeout_ms, 90_000, 1000, 300_000)));
  const run = await runKatana(path, subjsArgs(list.absolute), timeout, ctx.signal, rules.request.max_output_bytes);
  const raw = run.stdout.toString("utf8");
  const items: string[] = [];
  let truncated = false;
  for (const line of raw.split(/\r?\n/)) {
    const value = line.trim();
    if (!value || value.startsWith("Error running subjs")) continue;
    if (value.length > 2048) truncated = true;
    if (items.length < MAX_EXTERNAL_ITEMS) items.push(value.slice(0, 2048)); else truncated = true;
  }
  const artifact = artifactPath(ctx, "txt");
  writeFileSync(artifact.absolute, run.stdout);
  const artifacts: BlackboxArtifact[] = [
    { kind: "target-list" as const, path: list.relative, media_type: "text/plain" },
    { kind: "tool-output" as const, path: artifact.relative, media_type: "text/plain" },
  ];
  const data = { target, js_files: jsUrls.length, endpoints: items, items, count: items.length, exit_code: run.code, stderr: run.stderr, ...(truncated ? { items_truncated: true } : {}), ...sourceData };
  if (run.timed_out) return { tool: "recon.js_endpoints", ok: false, summary: `subjs timed out after ${Math.round(timeout / 1000)}s with ${items.length} endpoints`, data: { ...data, partial: true, timed_out: true }, artifacts };
  if (run.code !== 0) throw new Error(`recon.js_endpoints exited with code ${run.code}: ${externalFailureDetail(run)}`);
  return { tool: "recon.js_endpoints", ok: true, summary: `subjs extracted ${items.length} endpoints from ${jsUrls.length} JavaScript files`, data, artifacts };
}

/** 字典/模板清单：模型先看到"有什么"，再决定传哪个路径，避免对着文件系统猜。 */
function wordlistsTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Omit<BlackboxToolResult, "duration_ms"> {
  const category = String(input.category || "").trim();
  const listed = listWordlists(ctx, category);
  return {
    tool: "recon.wordlists", ok: true,
    summary: `recon.wordlists: ${listed.wordlists.length} 个字典、${listed.templates.length} 个模板目录（分类 ${category || "全部"}）`,
    data: {
      wordlist_roots: listed.roots,
      wordlists: listed.wordlists.map(item => ({ name: item.name, path: item.path, bytes: item.bytes })),
      template_roots: templateRoots(ctx),
      template_dirs: listed.templates,
      usage: "调用 recon.wordlists 先看清单；把这些 path 传给对应工具的 input.wordlist / input.args 里的 -w、-t；也可用 exec.python 现场生成自定义字典写到 workspace 再引用。",
    },
    artifacts: [],
  };
}

/** 动态扫描参数协商：把"慢目标打不出东西"的旋钮交给模型，但有硬边界。 */
function scanProfileTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Omit<BlackboxToolResult, "duration_ms"> {
  const before = readScanProfile(ctx);
  const patch: Record<string, unknown> = {};
  for (const key of ["timeout_s", "rate_limit", "katana_depth", "katana_duration_s", "retries"] as const) {
    if (input[key] !== undefined) patch[key] = input[key];
  }
  if (input.reset === true) patch.reset = true;
  const after = Object.keys(patch).length ? writeScanProfile(ctx, patch) : before;
  return {
    tool: "recon.scan_profile", ok: true,
    summary: Object.keys(patch).length
      ? `recon.scan_profile 已更新：timeout ${after.timeout_s}s / rate ${after.rate_limit} / katana 深度 ${after.katana_depth} / 时长 ${after.katana_duration_s}s / retries ${after.retries}`
      : `recon.scan_profile 当前：timeout ${after.timeout_s}s / rate ${after.rate_limit} / katana 深度 ${after.katana_depth} / 时长 ${after.katana_duration_s}s / retries ${after.retries}`,
    data: { before, effective: after, bounds: { timeout_s: [5, 60], rate_limit: [5, 150], katana_depth: [1, 8], katana_duration_s: [15, 300], retries: [0, 3] } },
    artifacts: [],
  };
}

/** 代码沙箱：发现逻辑 → 写 POC → 验证 的闭环，产物全部落到 workspace。 */
/**
 * 竞态/TOCTOU 的一次性发射（控制面裸 socket，不经 Burp）。
 * 沙箱里用 asyncio 发 20 条经过代理会退化成串行，所以并发必须是控制面的一等能力。
 */
async function raceConditionTool(ctx: BlackboxToolContext, input: Record<string, unknown>): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  // 2026-11-03 解除 scope：竞态发包不再强制锁在会话目标主机，允许对跨域后端发起并发。
  const url = httpUrl(input.url, ctx.target);
  const base = new URL(url);
  const specs = Array.isArray(input.requests) ? input.requests as Record<string, unknown>[] : [];
  const count = Math.max(2, Math.min(Number(input.count || (specs.length || 20)) || 20, 50));
  const requests: RaceRequest[] = specs.length
    ? specs.slice(0, 50).map((spec) => ({
      method: String(spec.method || "GET").toUpperCase(),
      path: String(spec.path || `${base.pathname}${base.search}`),
      headers: spec.headers && typeof spec.headers === "object" ? spec.headers as Record<string, string> : undefined,
      body: spec.body === undefined ? undefined : String(spec.body),
    }))
    : Array.from({ length: count }, () => ({
      method: String(input.method || "GET").toUpperCase(),
      path: `${base.pathname}${base.search}`,
      headers: input.headers && typeof input.headers === "object" ? input.headers as Record<string, string> : undefined,
      body: input.body === undefined ? undefined : String(input.body),
    }));
  // 控制面容器没有直连出口（实测 443 握手被掐断），默认走 Burp 的 CONNECT 隧道；
  // via=direct 保留给"控制面本身能直连"的部署。
  const via = String(input.via || "burp").toLowerCase();
  const proxyValue = String(ctx.values.BURP_PROXY_URL || "").trim();
  const endpoint = via === "direct" || !proxyValue ? undefined : new URL(proxyEndpoint(proxyValue).url);
  const outcome = await fireRace(
    { host: base.hostname, port: Number(base.port || (base.protocol === "https:" ? 443 : 80)), tls: base.protocol === "https:", servername: base.hostname },
    requests,
    {
      concurrency: Number(input.concurrency || requests.length), timeoutMs: Number(input.timeout_ms || 15_000),
      ...(endpoint ? { proxy: { host: endpoint.hostname, port: Number(endpoint.port || 8080) } } : {}),
    },
  );
  const statusText = Object.entries(outcome.statuses).map(([code, n]) => `${code}×${n}`).join("/");
  return {
    tool: "recon.race_condition", ok: outcome.errors === 0,
    summary: `recon.race_condition ${outcome.requests} 发（并发 ${outcome.concurrency}，${outcome.batches} 批）｜ 发送跨度 ${outcome.spread_ms}ms ｜ 用时 ${outcome.elapsed_ms}ms ｜ 状态 ${statusText} ｜ body 变体 ${outcome.distinct_bodies}${outcome.errors ? ` ｜ 错误 ${outcome.errors}` : ""}${outcome.timed_out ? ` ｜ 超时 ${outcome.timed_out}` : ""}（via=${outcome.via}）`,
    data: { ...outcome },
    artifacts: [],
  };
}
/** 工作区文件系统：像 cat/grep 一样翻自己的历史记录与产物。 */
function fsTool(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>): Omit<BlackboxToolResult, "duration_ms"> {
  const requested = String(input.path || "").trim();
  try {
    return fsToolInner(ctx, tool, input, requested);
  } catch (error) {
    // 路径越界 / 文件不存在都是模型可自纠的输入错误：rejected，不烧预算。
    throw reject(error instanceof Error ? error.message : String(error));
  }
}

function fsToolInner(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>, requested: string): Omit<BlackboxToolResult, "duration_ms"> {
  if (tool === "fs.list") {
    const listed = fsList(ctx, requested, Number(input.depth || 1));
    return {
      tool, ok: true,
      summary: `fs.list ${listed.root}: ${listed.entries.length} 项`,
      data: { root: listed.root, entries: listed.entries },
      artifacts: [],
    };
  }
  if (tool === "fs.read") {
    const read = fsRead(ctx, requested, Number(input.max_bytes || 0) || undefined);
    return {
      tool, ok: true,
      summary: `fs.read ${read.path}: ${read.bytes} 字节${read.truncated ? "（已截断）" : ""}`,
      data: { ...read },
      artifacts: [],
    };
  }
  const grepped = fsGrep(ctx, String(input.pattern || ""), requested, Number(input.max_matches || 0) || undefined);
  return {
    tool, ok: true,
    summary: `fs.grep /${grepped.pattern}/ 命中 ${grepped.matches.length} 行${grepped.truncated ? "（结果已截断）" : ""}`,
    data: { ...grepped },
    artifacts: [],
  };
}

export async function executeBlackboxTool(ctx: BlackboxToolContext, request: BlackboxToolRequest): Promise<BlackboxToolResult> {
  requireExecution(ctx.cfg, "blackbox tool");
  ctx.signal?.throwIfAborted();
  const rules = blackboxRules(ctx.values);
  const started = Date.now();
  const rawRequest = request as BlackboxToolRequest & { name?: string };
  const tool = String(request.tool || rawRequest.name || "").trim();
  const normalized = canonicalTool(tool);
  if (!(BLACKBOX_TOOL_NAMES as readonly string[]).includes(normalized)) throw reject(`unsupported blackbox tool: ${tool || "(empty)"}`);
  // 冒烟校验判死的工具直接拒绝：nuclei 无模板、Chromium 未安装这类"调用成功但 0 产出"最烧预算。
  const blocked = toolBlockedReason(normalized);
  if (blocked) throw reject(`${normalized} unavailable (preflight): ${blocked}`);
  const input = request.input && typeof request.input === "object" && !Array.isArray(request.input) ? request.input : {};
  if (input.params !== undefined && !TOOL_PARAMS[normalized]) throw reject(`tool ${normalized} does not accept input.params`);
  // `args` feeds external CLIs, `actions`/`evaluate` drive the browser; elsewhere they are not
  // silently ignored, because a model that believes it set them draws the wrong conclusion.
  if (input.args !== undefined && !externalSpecs[normalized]) throw reject(`tool ${normalized} does not accept input.args (it is an external CLI tool option)`);
  if ((input.actions !== undefined || input.evaluate !== undefined) && !["browser.open", "browser.screenshot"].includes(normalized)) {
    throw reject(`tool ${normalized} does not accept input.actions or input.evaluate (browser.open and browser.screenshot only)`);
  }
  /**
   * 身份快照必须在任何工具执行**之前**做：`httpTool` 会原地清空 input 并 delete anonymous，
   * 事后读 request.input 永远拿不到标记（2026-11-07 匿名闸失效的根因）。
   * 这里传的是浅拷贝快照，与原 input 后续被改写互不影响。
   */
  const credential = snapshotCredential(normalized, { ...(input as Record<string, unknown>) },
    ctx.db.getProjectCookies(ctx.projectId).length > 0);
  let result: Omit<BlackboxToolResult, "duration_ms">;
  if (normalized === "browser.open" || normalized === "browser.screenshot") result = await browserTool(ctx, normalized, input);
  else if (normalized === "browser.close") result = await browserCloseTool(ctx);
  else if (normalized === "browser.storage") result = await browserStorageTool(ctx, input);
  else if (normalized === "browser.tab") result = await browserTabTool(ctx, input);
  else if (normalized === "browser.network") result = await browserNetworkTool(ctx, input);
  else if (normalized === "evidence.read") result = await evidenceReadTool(ctx, input);
  else if (normalized === "recon.wordlists") result = wordlistsTool(ctx, input);
  else if (normalized === "recon.scan_profile") result = scanProfileTool(ctx, input);
  else if (normalized === "recon.race_condition") result = await raceConditionTool(ctx, input);
  else if (normalized === "exec.python" || normalized === "exec.bash") result = await runSandboxTool(ctx, normalized, input, sandboxRpcDeps(ctx));
  else if (normalized === "fs.list" || normalized === "fs.read" || normalized === "fs.grep") result = fsTool(ctx, normalized, input);
  else if (normalized === "http.request" || normalized === "burp.request") result = await httpTool(ctx, normalized, input);
    else if (normalized === "http.diff") result = await httpDiffTool(ctx, input);
  else if (normalized === "burp.check") result = await burpCheck(ctx);
  else if (normalized.startsWith("burp.") && normalized !== "burp.check" && normalized !== "burp.request") result = await burpBridgeTool(ctx, normalized, input);
  else if (normalized === "katana.crawl") result = await katanaTool(ctx, input);
  else if (normalized === "recon.js_endpoints") result = await jsEndpointsTool(ctx, input);
  else if (normalized === "recon.interactsh") result = await interactshTool(ctx, input);
  else result = await externalReconTool(ctx, normalized, input);
  // 分层标签：报告里能看出这次会话是"控制面为主"还是"沙箱为主"（三层漏斗用量）。
  // credential_mode/source 是撞墙判定与审计的唯一权威身份来源（不再读被改写的 input）。
  return { ...result, data: { ...result.data, layer: toolLayer(normalized),
    credential_mode: credential.mode, credential_source: credential.source }, duration_ms: Date.now() - started };
}

export async function executeAndRecordBlackboxTool(ctx: BlackboxToolContext, request: BlackboxToolRequest): Promise<BlackboxToolResult> {
  requireExecution(ctx.cfg, "blackbox evidence execution");
  const rawRequest = request as BlackboxToolRequest & { name?: string };
  const rawTool = String(request.tool || rawRequest.name || "").trim();
  const tool = canonicalTool(rawTool) || "(empty)";
  const normalizedRequest: BlackboxToolRequest = { ...request, tool };
  const requestEvidence = ctx.db.addBlackboxEvidence(ctx.projectId, ctx.sessionId, {
    kind: "tool-request", source: "main-agent", summary: `${tool}: ${String(request.reason || "tool request").slice(0, 1000)}`,
    confidence: "high", data: { tool, task_id: request.task_id, reason: String(request.reason || "").slice(0, 2000), input: ledgerInput(request.input) },
  });
  ctx.db.addBlackboxEvent(ctx.projectId, ctx.sessionId, "agent", "tool-request", `${tool} 已提交执行。`, { evidence_id: requestEvidence?.id, tool });
  const started = Date.now();
  try {
    const result = await executeBlackboxTool(ctx, normalizedRequest);
    ctx.signal?.throwIfAborted();
    const evidence = ctx.db.addBlackboxEvidence(ctx.projectId, ctx.sessionId, {
      kind: "tool-result", source: tool, summary: result.summary.slice(0, 8000), confidence: "high", data: { ...result.data, task_id: request.task_id, url: request.input?.url || ctx.target, ok: result.ok, duration_ms: result.duration_ms, request_evidence_id: requestEvidence?.id },
    });
    for (const artifact of result.artifacts) ctx.db.addBlackboxEvidence(ctx.projectId, ctx.sessionId, {
      kind: "artifact", source: tool, summary: `${artifact.kind}: ${artifact.path}`, confidence: "high", data: { media_type: artifact.media_type, result_evidence_id: evidence?.id }, artifactPath: artifact.path,
    });
    // 统一工作区留档：模型之后可以用 fs.grep/fs.read 翻自己的运行记录。
    const recorded = recordRun(ctx, tool, { ok: true, evidence_id: evidence?.id, task_id: request.task_id, summary: result.summary, data: result.data });
    ctx.db.addBlackboxEvent(ctx.projectId, ctx.sessionId, "system", "tool-result", result.summary, { evidence_id: evidence?.id, tool, ok: true, workspace_record: recorded });
    return result;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    const cancelled = ctx.signal?.aborted === true;
    const rejected = cause instanceof ToolRejected;
    const errorName = String((cause as { name?: string })?.name || "");
    const markedTimeout = (cause as { timedOut?: boolean })?.timedOut === true;
    // Playwright reports its request timeout as a plain Error, and killing the API context at
    // the deadline surfaces as "context disposed". Both mean "out of time", not "tool broken".
    const deadlineHit = ctx.deadline !== undefined && Date.now() >= ctx.deadline - 250;
    const timeoutMessage = /\b(timeout|timed out|request timed out|context (?:or browser )?(?:was )?closed|context disposed|killed)\b/i.test(message);
    // A deadline hit is not a tool failure: it must not consume retries or fail the task.
    const timedOut = !cancelled && !rejected && (markedTimeout || errorName === "TimeoutError" || (deadlineHit && timeoutMessage));
    const result: BlackboxToolResult = { tool, ok: false,
      summary: `${tool} ${rejected ? "rejected" : timedOut ? "timed out" : "failed"}: ${message}`,
      data: { error: message, cancelled, rejected: rejected || undefined, timed_out: timedOut || undefined }, artifacts: [], duration_ms: Date.now() - started };
    const evidence = ctx.db.addBlackboxEvidence(ctx.projectId, ctx.sessionId, {
      kind: "tool-error", source: tool, summary: result.summary.slice(0, 8000), confidence: "high", data: { ...result.data, task_id: request.task_id, url: request.input?.url || ctx.target, ok: false, duration_ms: result.duration_ms, request_evidence_id: requestEvidence?.id },
    });
    ctx.db.addBlackboxEvent(ctx.projectId, ctx.sessionId, "system", rejected ? "tool-rejected" : timedOut ? "tool-timeout" : "tool-error", result.summary,
      { evidence_id: evidence?.id, tool, ok: false, rejected: rejected || undefined, timed_out: timedOut || undefined });
    return result;
  }
}



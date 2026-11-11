/**
 * 工作区文件系统 + 代码沙箱 + 扫描参数档 + 字典清单。
 *
 * 设计要点（对应 docs/agent-constraints-audit.md §10）：
 * - 所有工具产物、沙箱输出、运行记录都落到 workspace/<project>/<session>/ 下，
 *   模型可以像人一样 list/read/grep 自己的历史记录，而不是被 evidence.read 的
 *   artifact 限制卡住"观察-推理"闭环。
 * - exec.python / exec.bash 每次都在一次性目录里跑：空环境变量、独立 cwd、CPU/内存/文件
 *   句柄 rlimit、硬超时、输出截断；容器里有 Docker 套接字时自动升级为一次性容器
 *   （--rm --network none -m 512m），没有就用进程级 jail，并在结果里如实标注隔离级别。
 * - 扫描参数（nuclei timeout / rate、katana depth / duration）由 Agent 用
 *   recon.scan_profile 协商后持久化在 workspace 里，默认值保持保守。
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import type { BlackboxToolContext } from "./tools.js";
import { execInSandboxService, sandboxStateClear, sandboxStateFile } from "../sandbox/client.js";

const MAX_READ_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_SCAN_FILES = 2000;
const MAX_GREP_MATCHES = 200;
const TEXT_EXTENSIONS = /\.(txt|json|jsonl|log|md|py|sh|csv|tsv|xml|html?|js|css|sql|yaml|yml|conf|ini)$/i;

export type SandboxLang = "python" | "bash";

export type ScanProfile = {
  /** nuclei -timeout（秒/请求）。 */
  timeout_s: number;
  /** nuclei -rate-limit（请求/秒）。 */
  rate_limit: number;
  /** katana -d 最大深度。 */
  katana_depth: number;
  /** katana -crawl-duration（秒）。 */
  katana_duration_s: number;
  /** nuclei -retries。 */
  retries: number;
};

export const DEFAULT_SCAN_PROFILE: ScanProfile = { timeout_s: 10, rate_limit: 50, katana_depth: 3, katana_duration_s: 60, retries: 0 };

function clamp(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

/** 工作区根目录：<data_dir>/workspace/<projectId>/<sessionId>。 */
export function workspaceRoot(ctx: Pick<BlackboxToolContext, "cfg" | "projectId" | "sessionId">): string {
  const base = resolve(join(String(ctx.cfg.data_dir || "."), "workspace", ctx.projectId, ctx.sessionId));
  mkdirSync(base, { recursive: true });
  return base;
}

/** 把相对路径钉死在根目录内：`..`、绝对路径逃逸、符号链接跳出去一律拒绝。 */
export function jailPath(root: string, requested: string): string {
  const cleaned = String(requested || "").replace(/^[\\/]+/, "");
  const absolute = resolve(join(root, cleaned));
  const normalizedRoot = resolve(root);
  if (absolute !== normalizedRoot && !absolute.startsWith(`${normalizedRoot}${sep}`)) {
    throw new Error(`path escapes the workspace: ${requested}`);
  }
  return absolute;
}

export function ensureWorkspaceLayout(root: string): { artifacts: string; runs: string; sandbox: string } {
  const layout = { artifacts: join(root, "artifacts"), runs: join(root, "runs"), sandbox: join(root, "sandbox") };
  for (const dir of Object.values(layout)) mkdirSync(dir, { recursive: true });
  return layout;
}

/** 每个工具结果都留一份可 grep 的记录：这是"观察-推理"闭环的证据底座。 */
export function recordRun(ctx: BlackboxToolContext, tool: string, payload: Record<string, unknown>): string | undefined {
  try {
    const root = workspaceRoot(ctx);
    const runs = ensureWorkspaceLayout(root).runs;
    const name = `${Date.now()}-${randomBytes(3).toString("hex")}-${tool.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;
    const absolute = join(runs, name);
    let text = JSON.stringify({ tool, at: new Date().toISOString(), ...payload }, null, 1);
    if (text.length > 1_000_000) text = `${text.slice(0, 1_000_000)}\n...[truncated]"}`;
    writeFileSync(absolute, text);
    return relative(root, absolute).replaceAll("\\", "/");
  } catch {
    return undefined;
  }
}

export type FsEntry = { path: string; type: "file" | "dir"; bytes?: number };

export function fsList(ctx: BlackboxToolContext, requested: string, depth = 1): { root: string; entries: FsEntry[] } {
  const root = workspaceRoot(ctx);
  const start = jailPath(root, requested || ".");
  if (!existsSync(start)) return { root: relative(root, start) || ".", entries: [] };
  const entries: FsEntry[] = [];
  const walk = (dir: string, level: number) => {
    if (level > Math.min(4, Math.max(1, depth)) || entries.length >= 400) return;
    for (const item of readdirSync(dir, { withFileTypes: true })) {
      const absolute = join(dir, item.name);
      const listed = relative(root, absolute).replaceAll("\\", "/");
      if (item.isDirectory()) {
        entries.push({ path: listed, type: "dir" });
        walk(absolute, level + 1);
      } else if (item.isFile()) {
        try { entries.push({ path: listed, type: "file", bytes: statSync(absolute).size }); } catch { /* raced */ }
      }
    }
  };
  walk(start, 1);
  return { root: relative(root, start).replaceAll("\\", "/") || ".", entries };
}

export function fsRead(ctx: BlackboxToolContext, requested: string, maxBytes = MAX_READ_BYTES): { path: string; bytes: number; truncated: boolean; text: string } {
  const root = workspaceRoot(ctx);
  const absolute = jailPath(root, requested);
  if (!existsSync(absolute)) throw new Error(`no such file in workspace: ${requested}`);
  const stat = statSync(absolute);
  if (!stat.isFile()) throw new Error(`${requested} is not a file`);
  const size = Math.min(MAX_READ_BYTES, Math.max(1024, Number(maxBytes) || MAX_READ_BYTES));
  const buffer = readFileSync(absolute);
  const truncated = buffer.length > size;
  return {
    path: relative(root, absolute).replaceAll("\\", "/"),
    bytes: buffer.length,
    truncated,
    text: buffer.subarray(0, size).toString("utf8"),
  };
}

export function fsGrep(ctx: BlackboxToolContext, pattern: string, requested = "", maxMatches = MAX_GREP_MATCHES): { pattern: string; matches: Array<{ path: string; line: number; text: string }>; truncated: boolean } {
  const root = workspaceRoot(ctx);
  const source = typeof pattern === "string" ? pattern : String(pattern ?? "");
  if (!source.trim()) throw new Error("fs.grep requires a non-empty pattern");
  const limit = Math.min(MAX_GREP_MATCHES, Math.max(1, Number(maxMatches) || MAX_GREP_MATCHES));
  let expression: RegExp;
  try { expression = new RegExp(source, "i"); } catch { throw new Error(`invalid regular expression: ${source}`); }
  const start = jailPath(root, requested || ".");
  const matches: Array<{ path: string; line: number; text: string }> = [];
  let scanned = 0;
  let truncated = false;
  const scanFile = (absolute: string) => {
    if (matches.length >= limit || scanned >= MAX_SCAN_FILES) { truncated = true; return; }
    if (!TEXT_EXTENSIONS.test(absolute) && !/\.json\.?/i.test(absolute)) return;
    let text: string;
    try { text = readFileSync(absolute, "utf8"); } catch { return; }
    scanned += 1;
    const lines = text.split("\n");
    for (let index = 0; index < lines.length && matches.length < limit; index += 1) {
      const line = lines[index]!;
      if (expression.test(line)) matches.push({ path: relative(root, absolute).replaceAll("\\", "/"), line: index + 1, text: line.slice(0, 400) });
    }
  };
  const walk = (absolute: string) => {
    if (matches.length >= limit || scanned >= MAX_SCAN_FILES) { truncated = true; return; }
    const stat = existsSync(absolute) ? statSync(absolute) : undefined;
    if (!stat) return;
    if (stat.isFile()) { scanFile(absolute); return; }
    for (const item of readdirSync(absolute, { withFileTypes: true })) {
      const child = join(absolute, item.name);
      if (item.isDirectory()) walk(child); else scanFile(child);
    }
  };
  walk(start);
  return { pattern: source, matches, truncated };
}

function scanProfilePath(ctx: BlackboxToolContext): string {
  return join(workspaceRoot(ctx), ".scan-profile.json");
}

export function readScanProfile(ctx: BlackboxToolContext): ScanProfile {
  try {
    const raw = JSON.parse(readFileSync(scanProfilePath(ctx), "utf8")) as Partial<ScanProfile>;
    return {
      timeout_s: clamp(raw.timeout_s, DEFAULT_SCAN_PROFILE.timeout_s, 5, 60),
      rate_limit: clamp(raw.rate_limit, DEFAULT_SCAN_PROFILE.rate_limit, 5, 150),
      katana_depth: clamp(raw.katana_depth, DEFAULT_SCAN_PROFILE.katana_depth, 1, 8),
      katana_duration_s: clamp(raw.katana_duration_s, DEFAULT_SCAN_PROFILE.katana_duration_s, 15, 300),
      retries: clamp(raw.retries, DEFAULT_SCAN_PROFILE.retries, 0, 3),
    };
  } catch {
    return { ...DEFAULT_SCAN_PROFILE };
  }
}

export function writeScanProfile(ctx: BlackboxToolContext, patch: Record<string, unknown>): ScanProfile {
  const current = readScanProfile(ctx);
  const next: ScanProfile = patch.reset === true ? { ...DEFAULT_SCAN_PROFILE } : {
    timeout_s: clamp(patch.timeout_s, current.timeout_s, 5, 60),
    rate_limit: clamp(patch.rate_limit, current.rate_limit, 5, 150),
    katana_depth: clamp(patch.katana_depth, current.katana_depth, 1, 8),
    katana_duration_s: clamp(patch.katana_duration_s, current.katana_duration_s, 15, 300),
    retries: clamp(patch.retries, current.retries, 0, 3),
  };
  writeFileSync(scanProfilePath(ctx), JSON.stringify(next, null, 1));
  return next;
}

/** 字典/模板只读根目录：模型只能在这些目录里挑文件。 */
export function wordlistRoots(ctx: BlackboxToolContext): string[] {
  const configured = [
    String(ctx.values?.SECLISTS_DIR || "").trim(),
    String(ctx.values?.NIANYUN_WORDLIST_ROOT || "").trim(),
    String(ctx.values?.WORDLIST_DIR || "").trim(),
    resolve(join(String(ctx.cfg?.data_dir || "."), "wordlists")),
    resolve(join(process.cwd(), "resources", "wordlists")),
  ].filter(Boolean);
  return [...new Set(configured.filter(dir => existsSync(dir)))];
}

export function templateRoots(ctx: BlackboxToolContext): string[] {
  const configured = [
    String(ctx.values?.NUCLEI_TEMPLATES_PATH || "").trim(),
    resolve(join(String(ctx.cfg?.data_dir || "."), "nuclei-templates")),
  ].filter(Boolean);
  return [...new Set(configured.filter(dir => existsSync(dir)))];
}

export type WordlistEntry = { name: string; path: string; bytes: number; root: string };

export function listWordlists(ctx: BlackboxToolContext, category = ""): { roots: string[]; wordlists: WordlistEntry[]; templates: string[] } {
  const wanted = String(category || "").toLowerCase();
  const matchesCategory = (name: string) => !wanted || name.toLowerCase().includes(wanted);
  const wordlists: WordlistEntry[] = [];
  for (const root of wordlistRoots(ctx)) {
    for (const item of readdirSync(root, { withFileTypes: true })) {
      if (!item.isFile() || !/\.txt$/i.test(item.name) || !matchesCategory(item.name)) continue;
      const absolute = join(root, item.name);
      try { wordlists.push({ name: item.name, path: absolute, bytes: statSync(absolute).size, root }); } catch { /* raced */ }
    }
  }
  const templates: string[] = [];
  for (const root of templateRoots(ctx)) {
    for (const item of readdirSync(root, { withFileTypes: true })) {
      if (item.isDirectory() && (!wanted || item.name.toLowerCase().includes(wanted))) templates.push(join(root, item.name));
    }
  }
  return { roots: wordlistRoots(ctx), wordlists: wordlists.sort((a, b) => a.name.localeCompare(b.name)), templates: templates.sort().slice(0, 60) };
}

/**
 * 把模型给的路径解析成绝对路径，并确认它确实落在只读根目录内。
 * 允许绝对路径、相对某个根的路径、相对进程 cwd 的项目内路径（例如 resources/wordlists/sqli.txt）。
 */
export function resolveInsideRoots(value: string, roots: string[], label: string, hint = ""): string {
  const usable = roots.filter(Boolean);
  if (!usable.length) throw new Error(`no ${label} directory is mounted (set NIANYUN_WORDLIST_ROOT / SECLISTS_DIR)${hint}`);
  const requested = String(value || "").trim();
  if (!requested) throw new Error(`${label} path is empty`);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(requested)) throw new Error(`${label} must be a local path, got URL: ${requested}`);
  const candidates: string[] = [];
  if (requested.startsWith("/") || /^[A-Za-z]:[\\/]/.test(requested)) candidates.push(resolve(requested));
  else candidates.push(...usable.map(root => resolve(join(root, requested))), resolve(requested));
  for (const candidate of candidates) {
    for (const root of usable) {
      const normalizedRoot = resolve(root);
      if (candidate !== normalizedRoot && !candidate.startsWith(`${normalizedRoot}${sep}`)) continue;
      if (existsSync(candidate)) return candidate;
    }
  }
  throw new Error(`${label} ${requested} is not inside the approved roots (${usable.join(", ")})${hint}`);
}

/**
 * 把模型给的字典/模板路径解析成绝对路径并校验确实在只读根目录内；
 * 没给值时按类别挑默认（例如 api → api.txt/paths.txt）。
 */
export function resolveApprovedAsset(ctx: BlackboxToolContext, requested: string, options: { roots: string[]; label: string; category?: string }): string {
  const roots = options.roots;
  const value = String(requested || "").trim();
  const hint = "; call recon.wordlists first";
  if (value) return resolveInsideRoots(value, roots, options.label, hint);
  // 没给值时按类别挑默认；类别没有匹配就退回任意可用字典（宁可少打，也不要直接拒）。
  const listed = listWordlists(ctx, options.category || "").wordlists;
  const fallback = listed.length ? listed : listWordlists(ctx).wordlists;
  if (!fallback.length) throw new Error(`no ${options.label} available${hint}`);
  return fallback[0]!.path;
}

export type SandboxResult = {
  ok: boolean;
  exit_code: number | null;
  timed_out: boolean;
  isolation: "microvm" | "container" | "process-jail";
  /** service = sidecar 沙箱服务；local-docker = 本机容器（仅开发机）；local-jail = 进程级 jail。 */
  mode: "service" | "local-docker" | "local-jail";
  egress: string;
  stdout: string;
  stderr: string;
  duration_ms: number;
  workdir: string;
  stdout_artifact: string;
  stderr_artifact: string;
  truncated: boolean;
  requirements?: string[];
  run_id?: string;
  files?: Array<{ path: string; bytes: number; truncated: boolean; stored: string }>;
  /** 跨调用持久目录 /state 的会话视图（配额、命中文件、工作区镜像）。 */
  state?: {
    key: string;
    files: number;
    bytes: number;
    pruned: number;
    /** 其中来自 auth/（受保护带）的个数。 */
    pruned_protected?: number;
    /** 各命名空间用量：volatile(poc/tmp) / normal(recon) / protected(auth) / pinned(rpc)。 */
    bands?: Record<string, { files: number; bytes: number }>;
    /** 裁完仍超配额（只剩 pinned 文件）。 */
    over_quota?: boolean;
    /** 镜像到工作区的相对目录（模型可以用 fs.read 读）。 */
    mirror?: string;
    entries: Array<{ path: string; bytes: number; stored?: string }>;
    truncated: boolean;
  };
};

function dockerAvailable(): boolean {
  return existsSync("/var/run/docker.sock") || Boolean(String(process.env.DOCKER_HOST || "").trim());
}

function sandboxImage(ctx: BlackboxToolContext): string {
  return String(ctx.values?.EXEC_SANDBOX_IMAGE || process.env.EXEC_SANDBOX_IMAGE || "").trim();
}

function minimalEnv(workdir: string): Record<string, string> {
  const env: Record<string, string> = {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: workdir,
    TMPDIR: workdir,
    LANG: "C.UTF-8",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1",
  };
  // 出口代理要透传，否则 POC 打不到需要代理的资产；其余密钥一律不传。
  for (const key of ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"]) {
    const value = String(process.env[key] || "").trim();
    if (value) env[key] = value;
  }
  return env;
}

function runProcess(command: string, args: string[], options: { cwd: string; timeoutMs: number }): Promise<{ code: number | null; stdout: Buffer; stderr: Buffer; timedOut: boolean }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, { cwd: options.cwd, env: minimalEnv(options.cwd), shell: false, windowsHide: true });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, options.timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => { if (stdout.reduce((sum, item) => sum + item.length, 0) < 2_000_000) stdout.push(chunk); });
    child.stderr.on("data", (chunk: Buffer) => { if (stderr.reduce((sum, item) => sum + item.length, 0) < 2_000_000) stderr.push(chunk); });
    child.on("error", (error) => { clearTimeout(timer); rejectPromise(error); });
    child.on("close", (code) => { clearTimeout(timer); resolvePromise({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), timedOut }); });
  });
}

/**
 * 控制面这一侧的沙箱入口。
 *
 * 优先走 Sidecar Sandbox Service（`SANDBOX_URL` + `SANDBOX_TOKEN`）：控制面容器里没有
 * Docker 套接字，代码在独立服务的一次性容器/microVM 里跑，出口强制走 MITM 代理。
 * 只有显式没有配置服务地址时才退化成本机 jail，并在结果里标 `mode` 与 `isolation`，
 * 绝不把"进程级 jail"说成"容器隔离"。
 */
export async function runSandbox(ctx: BlackboxToolContext, options: {
  lang: SandboxLang;
  code: string;
  requirements?: string[];
  timeout_s?: number;
  memory_mb?: number;
  network?: boolean;
}): Promise<SandboxResult> {
  const serviceUrl = String(ctx.values?.SANDBOX_URL || process.env.SANDBOX_URL || "").trim();
  if (serviceUrl) return runServiceSandbox(ctx, serviceUrl, options);
  const local = await runLocalSandbox(ctx, options);
  return {
    ...local,
    mode: local.isolation === "container" ? "local-docker" : "local-jail",
  };
}

/** 会话状态键：同一 project/session 的每次 exec 都落在同一个 /state 子目录。 */
export function sandboxStateKey(ctx: Pick<BlackboxToolContext, "projectId" | "sessionId">): string {
  const raw = `${ctx.projectId || "project"}-${ctx.sessionId || "session"}`;
  return raw.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 96) || "session";
}

/** 会话结束/取消时清掉 /state：不把"短期记忆"留成长期数据。失败只记日志，不影响收尾。 */
export async function clearSandboxState(values: Record<string, string> | undefined, projectId: string, sessionId: string): Promise<boolean> {
  const serviceUrl = String(values?.SANDBOX_URL || process.env.SANDBOX_URL || "").trim();
  if (!serviceUrl) return false;
  const token = String(values?.SANDBOX_TOKEN || process.env.SANDBOX_TOKEN || "").trim();
  const key = sandboxStateKey({ projectId, sessionId });
  try {
    const result = await sandboxStateClear({ url: serviceUrl, token, signal: AbortSignal.timeout(10_000) }, key);
    return result.removed;
  } catch {
    return false;
  }
}

async function runServiceSandbox(ctx: BlackboxToolContext, serviceUrl: string, options: {
  lang: SandboxLang;
  code: string;
  requirements?: string[];
  timeout_s?: number;
  memory_mb?: number;
  network?: boolean;
}): Promise<SandboxResult> {
  const root = workspaceRoot(ctx);
  const layout = ensureWorkspaceLayout(root);
  const started = Date.now();
  const token = String(ctx.values?.SANDBOX_TOKEN || process.env.SANDBOX_TOKEN || "").trim();
  const result = await execInSandboxService({ url: serviceUrl, token, signal: ctx.signal, timeoutS: Number(options.timeout_s || 60) }, {
    lang: options.lang,
    code: options.code,
    requirements: options.requirements,
    timeout_s: options.timeout_s,
    memory_mb: options.memory_mb,
    network: options.network,
    state_key: sandboxStateKey(ctx),
  });
  const stamp = `${Date.now()}-${randomBytes(4).toString("hex")}`;
  const runDir = join(layout.sandbox, `run-${result.run_id || stamp}`);
  mkdirSync(runDir, { recursive: true });
  const stdoutArtifact = join(layout.artifacts, `${stamp}-stdout.txt`);
  const stderrArtifact = join(layout.artifacts, `${stamp}-stderr.txt`);
  writeFileSync(stdoutArtifact, result.stdout.slice(0, 2_000_000));
  writeFileSync(stderrArtifact, result.stderr.slice(0, 2_000_000));
  const toRelative = (absolute: string) => relative(root, absolute).replaceAll("\\", "/");
  // 沙箱里产生的文件（dump、字典、截图）落在工作区，模型可以用 fs.read/fs.grep 接着分析。
  const files: Array<{ path: string; bytes: number; truncated: boolean; stored: string }> = [];
  for (const file of result.files) {
    const safe = String(file.path || "").replace(/^[\\/]+/, "").replaceAll("..", "_");
    if (!safe) continue;
    const absolute = join(runDir, safe);
    try {
      mkdirSync(join(absolute, ".."), { recursive: true });
      writeFileSync(absolute, Buffer.from(file.content_base64, "base64"));
      files.push({ path: safe, bytes: file.bytes, truncated: file.truncated, stored: toRelative(absolute) });
    } catch { /* 单个文件写失败不影响主结果 */ }
  }
  // /state 镜像：容器里的持久目录在控制面也要能读（fs.read / grep_file / 报告截图）。
  let state: SandboxResult["state"];
  if (result.state) {
    const mirror = join(layout.sandbox, "state", result.state.key.replace(/[^A-Za-z0-9_.-]/g, "-"));
    const entries: NonNullable<SandboxResult["state"]>["entries"] = [];
    for (const entry of result.state.entries) {
      const record: { path: string; bytes: number; stored?: string } = { path: entry.path, bytes: entry.bytes };
      if (entry.bytes <= 512 * 1024) {
        try {
          const file = await sandboxStateFile({ url: serviceUrl, token, signal: ctx.signal }, result.state.key, entry.path);
          const target = join(mirror, entry.path.replaceAll("..", "_"));
          mkdirSync(join(target, ".."), { recursive: true });
          writeFileSync(target, file.content !== undefined ? Buffer.from(file.content, "utf8") : Buffer.from(file.content_base64 || "", "base64"));
          record.stored = toRelative(target);
        } catch { /* 单个文件读失败忽略 */ }
      }
      entries.push(record);
    }
    state = {
      key: result.state.key, files: result.state.files, bytes: result.state.bytes,
      pruned: result.state.pruned, entries, truncated: result.state.truncated,
      ...(typeof result.state.pruned_protected === "number" ? { pruned_protected: result.state.pruned_protected } : {}),
      ...(result.state.bands ? { bands: result.state.bands } : {}),
      ...(typeof result.state.over_quota === "boolean" ? { over_quota: result.state.over_quota } : {}),
      ...(entries.some(item => item.stored) ? { mirror: toRelative(mirror) } : {}),
    };
  }
  return {
    ok: result.ok,
    exit_code: result.exit_code,
    timed_out: result.timed_out,
    isolation: result.isolation,
    mode: "service",
    egress: result.egress,
    stdout: result.stdout.slice(0, MAX_OUTPUT_BYTES),
    stderr: result.stderr.slice(0, MAX_OUTPUT_BYTES),
    duration_ms: result.duration_ms || Date.now() - started,
    workdir: toRelative(runDir),
    stdout_artifact: toRelative(stdoutArtifact),
    stderr_artifact: toRelative(stderrArtifact),
    truncated: result.truncated,
    ...(result.run_id ? { run_id: result.run_id } : {}),
    ...(options.requirements?.length ? { requirements: options.requirements } : {}),
    ...(files.length ? { files } : {}),
    ...(state ? { state } : {}),
  };
}

/** 本机路径（dev/CI）。没有 sidecar 时才用，隔离级别如实标注。 */
async function runLocalSandbox(ctx: BlackboxToolContext, options: {
  lang: SandboxLang;
  code: string;
  requirements?: string[];
  timeout_s?: number;
  memory_mb?: number;
  network?: boolean;
}): Promise<SandboxResult> {
  const code = String(options.code || "");
  if (!code.trim()) throw new Error("code must not be empty");
  if (code.length > 200_000) throw new Error("code exceeds 200KB");
  // protocol.ts 已允许 900s，mcp.ts 只允许 300，这里又 clamp 到 300：
  // 三处不一致时模型看到的是最大值，实际被静默砍掉。深挖一条签名/加密链 300s 不够。
  const timeoutS = clamp(options.timeout_s, 60, 5, 900);
  const memoryMb = clamp(options.memory_mb, 512, 128, 4096);
  const requirements = (options.requirements || []).map(item => String(item).trim()).filter(Boolean);
  if (requirements.length > 8) throw new Error("at most 8 requirements per run");
  for (const requirement of requirements) {
    if (!/^[A-Za-z0-9._+-]{1,64}(?:\[[A-Za-z0-9,._-]{1,64}\])?(?:[<>=!~]=?[0-9A-Za-z.*+]{1,32})?$/.test(requirement)) {
      throw new Error(`invalid requirement name: ${requirement}`);
    }
  }

  const root = workspaceRoot(ctx);
  const layout = ensureWorkspaceLayout(root);
  const stamp = `${Date.now()}-${randomBytes(4).toString("hex")}`;
  const workdir = join(layout.sandbox, stamp);
  mkdirSync(workdir, { recursive: true });
  const started = Date.now();
  const extension = options.lang === "python" ? "py" : "sh";
  const scriptPath = join(workdir, `main.${extension}`);
  const timeoutMs = timeoutS * 1000;
  const image = sandboxImage(ctx);
  const useContainer = Boolean(image) && dockerAvailable();
  const egress = options.network === false ? "none" : useContainer ? "container-default" : "control-container-egress";

  const prelude = options.lang === "python"
    ? `import resource as _r\n_r.setrlimit(_r.RLIMIT_AS, (${memoryMb * 1024 * 1024}, ${memoryMb * 1024 * 1024}))\n_r.setrlimit(_r.RLIMIT_CPU, (${timeoutS}, ${timeoutS + 1}))\n_r.setrlimit(_r.RLIMIT_FSIZE, (268435456, 268435456))\n`
    : `ulimit -v ${memoryMb * 1024} 2>/dev/null || true\nulimit -t ${timeoutS} 2>/dev/null || true\nulimit -f 262144 2>/dev/null || true\n`;
  writeFileSync(scriptPath, `${prelude}${code}`, "utf8");

  // 依赖安装：只在 python 且显式给了 requirements 时做，装到 jail 内的 site 目录，
  // 不污染控制面镜像；容器模式下由容器内 pip 处理。
  let siteDir: string | undefined;
  let setupError: string | undefined;
  if (options.lang === "python" && requirements.length) {
    siteDir = join(workdir, "site");
    mkdirSync(siteDir, { recursive: true });
    try {
      const install = await runProcess("python3", ["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--target", siteDir, ...requirements], { cwd: workdir, timeoutMs: Math.min(timeoutMs, 120_000) });
      if (install.code !== 0) setupError = install.stderr.toString("utf8").slice(-800) || `pip exited with ${install.code}`;
    } catch (error) {
      setupError = error instanceof Error ? error.message : String(error);
    }
  }

  const childEnv = { ...minimalEnv(workdir), ...(siteDir ? { PYTHONPATH: siteDir } : {}) };
  let code_ = null as number | null;
  let stdoutText = "";
  let stderrText = setupError ? `[requirements] ${setupError}\n` : "";
  let timedOut = false;
  if (setupError) {
    // 依赖装不上就别浪费时间跑主代码：直接把原因交回模型。
    code_ = 1;
  } else if (useContainer) {
    const dockerArgs = ["run", "--rm", "--network", options.network === false ? "none" : "bridge",
      "-m", `${memoryMb}m`, "--cpus", "1", "--pids-limit", "256", "-v", `${workdir}:/work`, "-w", "/work", image,
      options.lang === "python" ? "python3" : "bash", `/work/main.${extension}`];
    try {
      const run = await runProcess("docker", dockerArgs, { cwd: workdir, timeoutMs });
      code_ = run.code; timedOut = run.timedOut;
      stdoutText = run.stdout.toString("utf8"); stderrText += run.stderr.toString("utf8");
    } catch (error) {
      setupError = error instanceof Error ? error.message : String(error);
      code_ = 1;
    }
  } else {
    // Windows 开发机只有 python.exe：优先 python3，回落到 python。
    const [command, args] = options.lang === "python" ? [process.platform === "win32" ? "python" : "python3", ["-I", "-B", scriptPath]] : ["bash", ["--noprofile", "--norc", scriptPath]];
    try {
      const run = await new Promise<{ code: number | null; stdout: Buffer; stderr: Buffer; timedOut: boolean }>((resolvePromise, rejectPromise) => {
        const child = spawn(command as string, args as string[], { cwd: workdir, env: childEnv, shell: false, windowsHide: true });
        const stdout: Buffer[] = [];
        const stderr: Buffer[] = [];
        let killed = false;
        const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, timeoutMs);
        child.stdout.on("data", (chunk: Buffer) => { if (stdout.reduce((sum, item) => sum + item.length, 0) < 2_000_000) stdout.push(chunk); });
        child.stderr.on("data", (chunk: Buffer) => { if (stderr.reduce((sum, item) => sum + item.length, 0) < 2_000_000) stderr.push(chunk); });
        child.on("error", (error) => { clearTimeout(timer); rejectPromise(error); });
        child.on("close", (value) => { clearTimeout(timer); resolvePromise({ code: value, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), timedOut: killed }); });
      });
      code_ = run.code; timedOut = run.timedOut;
      stdoutText = run.stdout.toString("utf8"); stderrText += run.stderr.toString("utf8");
    } catch (error) {
      setupError = error instanceof Error ? error.message : String(error);
      code_ = 1;
    }
  }

  const truncated = stdoutText.length > MAX_OUTPUT_BYTES || stderrText.length > MAX_OUTPUT_BYTES;
  const stdoutArtifact = join(layout.artifacts, `${stamp}-stdout.txt`);
  const stderrArtifact = join(layout.artifacts, `${stamp}-stderr.txt`);
  writeFileSync(stdoutArtifact, stdoutText.slice(0, 2_000_000));
  writeFileSync(stderrArtifact, stderrText.slice(0, 2_000_000));
  const toRelative = (absolute: string) => relative(root, absolute).replaceAll("\\", "/");
  return {
    ok: !timedOut && code_ === 0,
    exit_code: code_,
    timed_out: timedOut,
    isolation: useContainer ? "container" : "process-jail",
    mode: useContainer ? "local-docker" : "local-jail",
    egress,
    stdout: stdoutText.slice(0, MAX_OUTPUT_BYTES),
    stderr: stderrText.slice(0, MAX_OUTPUT_BYTES),
    duration_ms: Date.now() - started,
    workdir: toRelative(workdir),
    stdout_artifact: toRelative(stdoutArtifact),
    stderr_artifact: toRelative(stderrArtifact),
    truncated,
    ...(requirements.length ? { requirements } : {}),
    ...(setupError ? { stdout: `${stdoutText.slice(0, MAX_OUTPUT_BYTES)}` } : {}),
  };
}

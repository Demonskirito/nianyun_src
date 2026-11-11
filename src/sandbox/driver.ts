/**
 * 沙箱执行驱动。
 *
 * 两种驱动，同一个返回结构：
 * - docker：一次性 job 容器（`--rm`+`--init`+cap-drop+no-new-privileges+只读根+tmpfs /tmp），
 *   网络挂在专用网络（默认 internal，只能到沙箱服务上的出口代理），gVisor 通过 `--runtime runsc`。
 * - process：无 Docker 时的降级路径（本机开发/CI），仍是独立目录 + 空环境变量 + rlimit + 硬超时。
 *   返回里如实标 `isolation: "process-jail"`，绝不冒充容器隔离。
 */
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join, relative, sep } from "node:path";
import { egressHeaderPolicy } from "./proxy.js";

export type SandboxLang = "python" | "bash";

export type SandboxRequest = {
  lang: SandboxLang;
  code: string;
  requirements?: string[];
  timeout_s?: number;
  memory_mb?: number;
  network?: boolean;
};

export type SandboxFile = { path: string; bytes: number; content_base64: string; truncated: boolean };

export type SandboxResult = {
  ok: boolean;
  run_id: string;
  exit_code: number | null;
  timed_out: boolean;
  isolation: "microvm" | "container" | "process-jail";
  egress: string;
  stdout: string;
  stderr: string;
  duration_ms: number;
  truncated: boolean;
  files: SandboxFile[];
};

export type SandboxDriverConfig = {
  driver: "docker" | "process";
  image: string;
  runtime?: string;
  network?: string;
  jobsDir: string;
  proxyUrl?: string;
  /** 额外只读挂载（`src:dst[:ro]`）：字典/模板卷之类，job 容器里可见但不可写。 */
  mounts: string[];
  /** 授权实验环境下的 TLS 兜底：MITM 自签证书不该把 POC 全堵死（默认关闭）。 */
  tlsInsecure: boolean;
  /** MITM 的 CA 文件（宿主机路径）：给了就挂进 job 并让 requests/pip 真正校验。 */
  caPem?: string;
  /** 跨调用持久卷：每个会话一个 subpath，挂到 job 的 /state（/work 仍是一次性的）。 */
  stateVolume: string;
  /** 卷在 sandbox 服务容器里的挂载点：服务从这里度量/裁剪/读回，控制面经 API 取。 */
  stateRoot: string;
  /** /state 配额：总字节与文件数，超了按最旧文件裁。 */
  stateMaxMb: number;
  stateMaxFiles: number;
  /** 会话结束后 /state 目录的清理时限（小时）。 */
  stateTtlH: number;
  timeoutMaxS: number;
  memoryMaxMb: number;
  outputBytes: number;
  fileBytes: number;
  filesMax: number;
};

export const DEFAULT_DRIVER_CONFIG: Omit<SandboxDriverConfig, "jobsDir"> = {
  driver: "docker",
  image: "nianyun:sandbox",
  mounts: [],
  tlsInsecure: false,
  stateVolume: "nianyun-sandbox-state",
  stateRoot: "/var/lib/nianyun-sandbox/state",
  stateMaxMb: 50,
  stateMaxFiles: 100,
  stateTtlH: 12,
  timeoutMaxS: 300,
  memoryMaxMb: 4096,
  outputBytes: 64 * 1024,
  fileBytes: 512 * 1024,
  filesMax: 24,
};

const MIN_TIMEOUT_S = 5;

function clamp(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

export type NormalizedSandboxRequest = Required<Pick<SandboxRequest, "lang" | "code" | "timeout_s" | "memory_mb" | "network">> & {
  requirements: string[];
  state_key?: string;
};

/** 会话状态键：project/session → 一个安全的目录名（volume subpath 只接受相对安全路径）。 */
export function normalizeStateKey(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const text = String(raw).trim();
  if (!text) return undefined;
  // 先拒绝任何 `..`（不管后面怎么清洗），再做字符归一化：状态目录是安全边界，不做"看起来像路径"的宽容处理。
  if (text.split(/[\\/]/).some(part => part === ".." ) || text.includes("..")) return undefined;
  const key = text.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 96);
  if (!key) return undefined;
  if (key === "." || key === ".." || key.includes("..")) return undefined;
  return key;
}

export function normalizeRequest(input: unknown, cfg: Pick<SandboxDriverConfig, "timeoutMaxS" | "memoryMaxMb">): NormalizedSandboxRequest {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("request body must be an object");
  const raw = input as Record<string, unknown>;
  const lang = String(raw.lang || "").toLowerCase();
  if (lang !== "python" && lang !== "bash") throw new Error('lang must be "python" or "bash"');
  const code = String(raw.code ?? "");
  if (!code.trim()) throw new Error("code must not be empty");
  if (code.length > 200_000) throw new Error("code exceeds 200KB");
  const requirements = Array.isArray(raw.requirements) ? raw.requirements.map(item => String(item).trim()).filter(Boolean) : [];
  const stateKey = normalizeStateKey(raw.state_key);
  if (requirements.length > 8) throw new Error("at most 8 requirements per run");
  for (const requirement of requirements) {
    if (!/^[A-Za-z0-9._+-]{1,64}(?:\[[A-Za-z0-9,._-]{1,64}\])?(?:[<>=!~]=?[0-9A-Za-z.*+]{1,32})?$/.test(requirement)) {
      throw new Error(`invalid requirement name: ${requirement}`);
    }
  }
  return {
    lang, code, requirements,
    timeout_s: clamp(raw.timeout_s, 60, MIN_TIMEOUT_S, cfg.timeoutMaxS),
    memory_mb: clamp(raw.memory_mb, 512, 128, cfg.memoryMaxMb),
    network: raw.network !== false,
    ...(stateKey ? { state_key: stateKey } : {}),
  };
}

function pythonPrelude(timeoutS: number, memoryMb: number, enforceMemory: boolean): string {
  // Windows 开发机上没有 resource 模块：rlimit 由容器/宿主侧兜，这里只保证可运行。
  if (process.platform === "win32") return "";
  return [
    "import resource as _r",
    ...(enforceMemory ? [`_r.setrlimit(_r.RLIMIT_AS, (${memoryMb * 1024 * 1024}, ${memoryMb * 1024 * 1024}))`] : []),
    `_r.setrlimit(_r.RLIMIT_CPU, (${timeoutS}, ${timeoutS + 1}))`,
    "_r.setrlimit(_r.RLIMIT_FSIZE, (268435456, 268435456))",
    "_r.setrlimit(_r.RLIMIT_NPROC, (256, 256))",
    "",
  ].join("\n");
}

/**
 * HTTPS 侧的头兜底（2026-11-07，策略经 egress-probe 实测修正）。
 *
 * egress 代理对 HTTPS 走 CONNECT 隧道，看不到明文头，代理层补头只覆盖明文 HTTP，
 * 所以在 job 代码之前 patch `requests.Session.request`，让脚本自动继承同一套头。
 *
 * 实测修正：默认**不伪装浏览器 UA**。developer.aliyun.com 上裸 python-requests UA 是
 * 200/213809B，浏览器 UA 反而是 403/7155B 的 attestation 钓身份页（要求提交本机账号
 * 与 git 邮箱）；同一 JA3 下结果相反，排除 TLS 指纹。默认只补中性的 Accept 类头，
 * 需要浏览器 UA 时用 SANDBOX_EGRESS_UA_POLICY=browser 显式开启。
 *
 * 用户显式传的 headers 优先；带 `X-Nianyun-No-UA` 的请求一个字都不补，
 * 保留「裸 UA vs 浏览器 UA」对照打法。requests 缺失/版本不同时静默跳过。
 * 这只是补头，**不改 TLS/JA3 指纹**——那部分由 egress 日志记录后另行分析。
 */
export function browserHeadersPrelude(env: NodeJS.ProcessEnv = process.env): string {
  const { headers, disabled } = egressHeaderPolicy(env);
  if (disabled) return "";
  return [
    "try:",
    "    import requests as _heim_req",
    `    _HEIM_DEFAULTS = ${JSON.stringify(headers)}`,
    "    _heim_orig_request = _heim_req.sessions.Session.request",
    "    def _heim_request(self, method, url, *a, **k):",
    "        _supplied = k.get('headers') or {}",
    "        if not any(str(_n).lower() == 'x-nianyun-no-ua' for _n in _supplied):",
    "            _merged = dict(_HEIM_DEFAULTS)",
    "            _merged.update(_supplied)",
    "            k['headers'] = _merged",
    "        return _heim_orig_request(self, method, url, *a, **k)",
    "    _heim_req.sessions.Session.request = _heim_request",
    "except Exception:",
    "    pass",
    "",
  ].join("\n");
}

/** MITM 兜底（第二层）：requests 用自带 certifi，sitecustomize 管不到；这里把默认 verify 降级。 */
export function tlsPrelude(tlsInsecure: boolean): string {
  if (!tlsInsecure) return "";
  return [
    "try:",
    "    import requests as _rq, urllib3 as _u3",
    "    _u3.disable_warnings()",
    "    _orig_request = _rq.sessions.Session.request",
    "    def _request_no_verify(self, *a, **k):",
    "        k.setdefault('verify', False)",
    "        return _orig_request(self, *a, **k)",
    "    _rq.sessions.Session.request = _request_no_verify",
    "except Exception:",
    "    pass",
    "",
  ].join("\n");
}
/** 依赖自举：pip install --target 到 /work/site，再插到 sys.path 最前（容器内一次跑完，无需跨步骤挂载）。 */
export function requirementsPrelude(requirements: string[]): string {
  if (!requirements.length) return "";
  const list = requirements.map(item => JSON.stringify(item)).join(", ");
  return [
    "import subprocess as _sp, sys as _sys, os as _os",
    `_reqs = [${list}]`,
    "_site = '/work/site'",
    "_os.makedirs(_site, exist_ok=True)",
    // pip 自带 vendored urllib3，sitecustomize 管不到它；MITM 自签证书要靠 --trusted-host。",
    "_extra = ['--trusted-host', 'pypi.org', '--trusted-host', 'files.pythonhosted.org'] if _os.environ.get('SANDBOX_TLS_INSECURE') == '1' else []",
    "_done = _sp.run([_sys.executable, '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--target', _site, *_extra, *_reqs], capture_output=True, text=True)",
    "if _done.returncode != 0:",
    "    _sys.stderr.write('[requirements] pip failed: ' + (_done.stderr or _done.stdout)[-800:])",
    "    raise SystemExit(2)",
    "_sys.path.insert(0, _site)",
    "",
  ].join("\n");
}
function bashPrelude(timeoutS: number, memoryMb: number, enforceMemory: boolean): string {
  // 容器里不能加 `ulimit -v`：Go 写的扫描器（nuclei/katana/ffuf/httpx…）要预留一大片虚拟
  // 地址空间，限了会直接 fatal error；真内存上限交给 docker --memory（cgroup）。
  return [
    ...(enforceMemory ? [`ulimit -v ${memoryMb * 1024} 2>/dev/null || true`] : []),
    `ulimit -t ${timeoutS} 2>/dev/null || true`,
    `ulimit -f 262144 2>/dev/null || true`,
    "ulimit -u 256 2>/dev/null || true",
    "",
  ].join("\n");
}

function jobEnvironment(proxyUrl: string | undefined): Record<string, string> {
  // NO_PROXY 明确置空：任何"本地直连"的短路都会绕过 MITM 审计。
  const env: Record<string, string> = {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: "C.UTF-8",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1",
    NO_PROXY: "",
    no_proxy: "",
  };
  if (proxyUrl) {
    Object.assign(env, {
      HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl,
      http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl,
      // pip 也要走同一个出口，否则"装依赖"本身就是一条绕过审计的通道。
      PIP_INDEX_URL: "https://pypi.org/simple",
      PIP_PROXY: proxyUrl,
      PIP_DISABLE_PIP_VERSION_CHECK: "1",
    });
  }
  return env;
}

function spawnCollect(command: string, args: string[], options: {
  cwd: string; env: Record<string, string>; timeoutMs: number; input?: string;
}): Promise<{ code: number | null; stdout: Buffer; stderr: Buffer; timedOut: boolean; error?: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env, shell: false });
    if (options.input !== undefined) {
      // 代码走 stdin：docker run -i 的 stdin 直达 job 进程，不必在宿主机上落文件。
      child.stdin.on("error", () => { /* job 提前退出时管道会断，忽略 */ });
      child.stdin.end(options.input);
    } else {
      child.stdin.end();
    }
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let killed = false;
    let settled = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, options.timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => { if (out.length < 4096) out.push(chunk); });
    child.stderr.on("data", (chunk: Buffer) => { if (err.length < 4096) err.push(chunk); });
    child.on("error", (error: Error) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      resolvePromise({ code: null, stdout: Buffer.concat(out), stderr: Buffer.concat(err), timedOut: killed, error: error.message });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      resolvePromise({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err), timedOut: killed });
    });
  });
}

/** 采集 job 目录里"除脚本以外"的新文件：POC 打印不了的东西（dump、截图、字典）靠这条路带回来。 */
function collectFiles(jobDir: string, scriptNames: Set<string>, cfg: SandboxDriverConfig): SandboxFile[] {
  const files: SandboxFile[] = [];
  const walk = (dir: string) => {
    if (files.length >= cfg.filesMax) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const absolute = join(dir, entry.name);
      if (entry.isDirectory()) { walk(absolute); continue; }
      const listed = relative(jobDir, absolute).replaceAll(sep, "/");
      if (scriptNames.has(listed)) continue;
      if (files.length >= cfg.filesMax) return;
      const stat = statSync(absolute);
      const truncated = stat.size > cfg.fileBytes;
      const content = readFileSync(absolute).subarray(0, cfg.fileBytes);
      files.push({ path: listed, bytes: stat.size, content_base64: content.toString("base64"), truncated });
    }
  };
  try { walk(jobDir); } catch { /* job dir already gone */ }
  return files;
}

export async function runInDocker(req: NormalizedSandboxRequest, cfg: SandboxDriverConfig): Promise<SandboxResult> {
  const started = Date.now();
  const runId = `${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
  const jobDir = join(cfg.jobsDir, runId);
  mkdirSync(jobDir, { recursive: true });

  const network = req.network === false ? "none" : (cfg.network || "bridge");
  const name = `nianyun-sandbox-${runId}`;
  // 不能加 -I：它同时等于 -E，会忽略 PYTHONPATH，把 TLS 兜底的 sitecustomize 一起丢掉。
  const program = req.lang === "python" ? ["python3", "-s", "-B", "-"] : ["/bin/bash", "--noprofile", "--norc", "-s"];
  // 代码走 stdin（`-`/`-s`），不 bind-mount：job 目录在服务容器里，宿主机 daemon 看不到它。
  // 文件回传靠 `docker cp` 从容器可写层取出，再一次 `docker rm -f` 清干净。
  const args = [
    "run", "-i", "--init", "--name", name,
    "--network", network,
    "--memory", `${req.memory_mb}m`, "--cpus", "1", "--pids-limit", "256",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    // 不挂 --read-only：/work 要落在容器可写层，docker cp 才能在退出后取出文件。
    // 隔离靠：一次性容器 + cap-drop ALL + no-new-privileges + 非 root + rm -f。
    "--tmpfs", "/tmp:rw,size=64m,noexec,nosuid",
    // 只读资料卷（字典、nuclei 模板）；默认只读，写不进去。
    ...(cfg.mounts || []).flatMap(spec => ["-v", spec]),
    // MITM CA：给了就挂成只读文件并让 python/pip 走真实校验。
    ...(cfg.caPem ? ["-v", `${cfg.caPem}:/opt/certs/proxy-ca.pem:ro`] : []),
    // 跨调用持久化：同一个卷的不同 subpath 挂到 /state（/work 仍随容器销毁）。
    // volume-subpath 需要 Docker Engine ≥ 26（本机 29.x / API 1.56 已验证）。
    ...(req.state_key ? ["--mount", `type=volume,source=${cfg.stateVolume},target=/state,volume-subpath=${req.state_key}`] : []),
    ...(req.state_key ? ["-e", "NIANYUN_STATE_DIR=/state"] : []),
    "-w", "/work",
    "-e", "NO_PROXY=", "-e", "no_proxy=",
    "-e", "HOME=/work", "-e", "TMPDIR=/tmp",
    ...(cfg.tlsInsecure ? ["-e", "SANDBOX_TLS_INSECURE=1"] : []),
    ...(cfg.caPem ? ["-e", "REQUESTS_CA_BUNDLE=/opt/certs/proxy-ca.pem", "-e", "SSL_CERT_FILE=/opt/certs/proxy-ca.pem", "-e", "PIP_CERT=/opt/certs/proxy-ca.pem", "-e", "CURL_CA_BUNDLE=/opt/certs/proxy-ca.pem", "-e", "NODE_EXTRA_CA_CERTS=/opt/certs/proxy-ca.pem"] : []),
    ...(req.network === false || !cfg.proxyUrl ? [] : ["-e", `HTTP_PROXY=${cfg.proxyUrl}`, "-e", `HTTPS_PROXY=${cfg.proxyUrl}`, "-e", `ALL_PROXY=${cfg.proxyUrl}`, "-e", `http_proxy=${cfg.proxyUrl}`, "-e", `https_proxy=${cfg.proxyUrl}`]),
    ...(cfg.runtime ? ["--runtime", cfg.runtime] : []),
    "--label", "nianyun.sandbox=1", "--label", `nianyun.sandbox.run=${runId}`,
    cfg.image,
    ...program,
  ];
  const run = await spawnCollect("docker", args, {
    cwd: jobDir,
    env: jobEnvironment(undefined),
    timeoutMs: req.timeout_s * 1000 + 5_000,
    input: (req.lang === "python"
      ? pythonPrelude(req.timeout_s, req.memory_mb, false) + requirementsPrelude(req.requirements) + tlsPrelude(cfg.tlsInsecure) + browserHeadersPrelude()
      : bashPrelude(req.timeout_s, req.memory_mb, false)) + req.code,
  });
  const outDir = join(jobDir, "out");
  if (cfg.filesMax > 0) {
    mkdirSync(outDir, { recursive: true });
    // 超时也会先尝试取一次文件：被打断的 job 往往正好留下了半成品 dump。
    await spawnCollect("docker", ["cp", `${name}:/work/.`, outDir], { cwd: jobDir, env: jobEnvironment(undefined), timeoutMs: 20_000 });
  }
  await spawnCollect("docker", ["rm", "-f", name], { cwd: jobDir, env: jobEnvironment(undefined), timeoutMs: 20_000 });
  const stdout = run.stdout.toString("utf8");
  const stderr = run.stderr.toString("utf8") + (run.error ? `\n[sandbox] ${run.error}` : "");
  const files = collectFiles(outDir, new Set(), cfg);
  try { rmSync(jobDir, { recursive: true, force: true }); } catch { /* best effort */ }
  return {
    ok: !run.timedOut && run.code === 0,
    run_id: runId,
    exit_code: run.code,
    timed_out: run.timedOut,
    isolation: cfg.runtime === "runsc" ? "microvm" : "container",
    egress: req.network === false ? "none" : `proxy:${cfg.proxyUrl || "unset"} via network:${network}`,
    stdout: stdout.slice(0, cfg.outputBytes),
    stderr: stderr.slice(0, cfg.outputBytes),
    duration_ms: Date.now() - started,
    truncated: stdout.length > cfg.outputBytes || stderr.length > cfg.outputBytes,
    files,
  };
}

export async function runInProcess(req: NormalizedSandboxRequest, cfg: SandboxDriverConfig): Promise<SandboxResult> {
  const started = Date.now();
  const runId = `${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
  const jobDir = join(cfg.jobsDir, runId);
  mkdirSync(jobDir, { recursive: true });
  const script = join(jobDir, req.lang === "python" ? "main.py" : "main.sh");
  writeFileSync(script, (req.lang === "python" ? pythonPrelude(req.timeout_s, req.memory_mb, true) + browserHeadersPrelude() : bashPrelude(req.timeout_s, req.memory_mb, true)) + req.code, "utf8");
  try { chmodSync(script, 0o755); } catch { /* windows dev box */ }
  const base = jobEnvironment(req.network === false ? undefined : cfg.proxyUrl);
  // 本机降级路径要沿用宿主 PATH（容器内两者等价）。
  const env: Record<string, string> = { ...base, PATH: process.env.PATH || base.PATH || "/usr/local/bin:/usr/bin:/bin", HOME: jobDir, TMPDIR: jobDir };
  // Windows 开发机没有 python3：回落到 python，保持 process 驱动在本地可测。
  const pythonBin = process.platform === "win32" ? "python" : "python3";
  const run = await spawnCollect(req.lang === "python" ? pythonBin : "bash", req.lang === "python" ? ["-I", "-B", script] : ["--noprofile", "--norc", script], {
    cwd: jobDir, env, timeoutMs: req.timeout_s * 1000,
  });
  const stdout = run.stdout.toString("utf8");
  const stderr = run.stderr.toString("utf8") + (run.error ? `\n[sandbox] ${run.error}` : "");
  const files = collectFiles(jobDir, new Set(["main.py", "main.sh"]), cfg);
  try { rmSync(jobDir, { recursive: true, force: true }); } catch { /* best effort */ }
  return {
    ok: !run.timedOut && run.code === 0,
    run_id: runId,
    exit_code: run.code,
    timed_out: run.timedOut,
    isolation: "process-jail",
    egress: req.network === false ? "none" : `proxy:${cfg.proxyUrl || "unset"} (process-level)`,
    stdout: stdout.slice(0, cfg.outputBytes),
    stderr: stderr.slice(0, cfg.outputBytes),
    duration_ms: Date.now() - started,
    truncated: stdout.length > cfg.outputBytes || stderr.length > cfg.outputBytes,
    files,
  };
}

export async function runSandboxJob(req: NormalizedSandboxRequest, cfg: SandboxDriverConfig): Promise<SandboxResult> {
  return cfg.driver === "docker" ? runInDocker(req, cfg) : runInProcess(req, cfg);
}

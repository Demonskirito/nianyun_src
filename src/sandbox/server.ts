/**
 * Sidecar Sandbox Service。
 *
 * 架构约束（对应 docs/agent-constraints-audit.md §11）：
 * - 控制面容器**不挂** Docker 套接字；只有本服务持有。
 * - Agent 的代码通过 `POST /sandbox/exec` 提交，每次一个一次性 job 容器（或 gVisor/runsc）。
 * - Job 容器挂 `--internal` 网络，物理上只能连本服务；本服务在该网络上开链式代理，
 *   把出口串到 BURP_PROXY_URL —— 于是"Agent 写的攻击流量"必然经过 MITM。
 * - 每个请求有超时/内存/输出/文件上限；响应里如实回报 isolation 与 egress。
 *
 * 运行：`nianyun-sandbox`（bin 包装 dist/sandbox/server.js）。
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { DEFAULT_DRIVER_CONFIG, normalizeRequest, normalizeStateKey, runSandboxJob, type SandboxDriverConfig, type SandboxResult } from "./driver.js";
import { clearState, ensureStateDir, measureState, stateFilePath, sweepState } from "./state.js";
import { EGRESS_NO_INJECT_HEADER, egressHeaderPolicy, startChainedProxy, type ChainedProxy, type EgressEntry } from "./proxy.js";

export type SandboxServiceConfig = SandboxDriverConfig & {
  host: string;
  port: number;
  token: string;
  allowAnon: boolean;
  maxConcurrency: number;
  maxQueue: number;
  proxyListenHost: string;
  proxyListenPort: number;
  proxyForJobs?: string;
  egressDeny: string[];
  upstreamProxy?: string;
  /** 明文 HTTP 出口补的浏览器头；false = 关闭（HTTPS 隧道本就看不到头，见 proxy.ts）。 */
  egressInjectHeaders: Record<string, string> | false;
};

export type SandboxService = {
  server: Server;
  config: SandboxServiceConfig;
  proxy?: ChainedProxy;
  close: () => Promise<void>;
};

function boolValue(raw: unknown, fallback: boolean): boolean {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const value = String(raw).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(value)) return true;
  if (["0", "false", "no", "off"].includes(value)) return false;
  return fallback;
}

/** 与 job prelude 共用同一策略：空=中性默认头（不补 UA）、0/false=关闭、JSON=自定义、UA_POLICY=browser=追加浏览器 UA。 */
function egressHeadersOf(env: NodeJS.ProcessEnv): Record<string, string> | false {
  const { headers, disabled } = egressHeaderPolicy(env);
  return disabled ? false : headers;
}

function numberValue(raw: unknown, fallback: number, min: number, max: number): number {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

export function sandboxServiceConfig(env: NodeJS.ProcessEnv = process.env): SandboxServiceConfig {
  const driver = String(env.SANDBOX_DRIVER || "docker").trim().toLowerCase() === "process" ? "process" : "docker";
  const upstreamProxy = String(env.SANDBOX_UPSTREAM_PROXY || env.BURP_PROXY_URL || "").trim() || undefined;
  const proxyForJobs = String(env.SANDBOX_PROXY_FOR_JOBS || "").trim()
    || (upstreamProxy ? `http://127.0.0.1:${numberValue(env.SANDBOX_PROXY_PORT, 8899, 1, 65535)}` : "");
  return {
    ...DEFAULT_DRIVER_CONFIG,
    driver,
    image: String(env.SANDBOX_IMAGE || DEFAULT_DRIVER_CONFIG.image).trim(),
    runtime: String(env.SANDBOX_RUNTIME || "").trim() || undefined,
    network: String(env.SANDBOX_NETWORK || "").trim() || undefined,
    jobsDir: String(env.SANDBOX_JOBS_DIR || "/var/lib/nianyun-sandbox/jobs").trim(),
    proxyUrl: proxyForJobs || undefined,
    mounts: String(env.SANDBOX_MOUNTS || "").split(",").map(item => item.trim()).filter(Boolean),
    tlsInsecure: boolValue(env.SANDBOX_TLS_INSECURE, false),
    stateVolume: String(env.SANDBOX_STATE_VOLUME || DEFAULT_DRIVER_CONFIG.stateVolume).trim(),
    stateRoot: String(env.SANDBOX_STATE_ROOT || DEFAULT_DRIVER_CONFIG.stateRoot).trim(),
    stateMaxMb: numberValue(env.SANDBOX_STATE_MAX_MB, DEFAULT_DRIVER_CONFIG.stateMaxMb, 1, 1024),
    stateMaxFiles: numberValue(env.SANDBOX_STATE_MAX_FILES, DEFAULT_DRIVER_CONFIG.stateMaxFiles, 1, 5000),
    stateTtlH: numberValue(env.SANDBOX_STATE_TTL_H, DEFAULT_DRIVER_CONFIG.stateTtlH, 1, 720),
    ...(String(env.SANDBOX_CA_PEM || "").trim() ? { caPem: String(env.SANDBOX_CA_PEM).trim() } : {}),
    timeoutMaxS: numberValue(env.SANDBOX_TIMEOUT_MAX_S, 300, 5, 1800),
    memoryMaxMb: numberValue(env.SANDBOX_MEMORY_MAX_MB, 4096, 128, 16384),
    outputBytes: numberValue(env.SANDBOX_OUTPUT_BYTES, 64 * 1024, 4096, 1024 * 1024),
    fileBytes: numberValue(env.SANDBOX_FILE_BYTES, 512 * 1024, 4096, 8 * 1024 * 1024),
    filesMax: numberValue(env.SANDBOX_FILES_MAX, 24, 0, 200),
    host: String(env.SANDBOX_HOST || "0.0.0.0").trim(),
    port: numberValue(env.SANDBOX_PORT, 8790, 0, 65535),
    token: String(env.SANDBOX_TOKEN || "").trim(),
    allowAnon: boolValue(env.SANDBOX_ALLOW_ANON, false),
    maxConcurrency: numberValue(env.SANDBOX_MAX_CONCURRENCY, 4, 1, 64),
    maxQueue: numberValue(env.SANDBOX_MAX_QUEUE, 16, 0, 512),
    proxyListenHost: String(env.SANDBOX_PROXY_LISTEN_HOST || "0.0.0.0").trim(),
    proxyListenPort: numberValue(env.SANDBOX_PROXY_PORT, 8899, 0, 65535),
    proxyForJobs: proxyForJobs || undefined,
    egressDeny: String(env.SANDBOX_EGRESS_DENY || "").split(",").map(item => item.trim()).filter(Boolean),
    egressInjectHeaders: egressHeadersOf(env),
    upstreamProxy,
  };
}

/** 简单的并发闸：超出 maxConcurrency 排队，队列也满就 503（不把宿主机拖死）。 */
function createLimiter(maxConcurrency: number, maxQueue: number) {
  let active = 0;
  const waiters: Array<() => void> = [];
  return {
    stats: () => ({ active, queued: waiters.length }),
    acquire: async (): Promise<boolean> => {
      if (active < maxConcurrency) { active += 1; return true; }
      if (waiters.length >= maxQueue) return false;
      await new Promise<void>(resolvePromise => waiters.push(resolvePromise));
      active += 1;
      return true;
    },
    release: () => { active = Math.max(0, active - 1); const next = waiters.shift(); if (next) next(); },
  };
}

function json(res: ServerResponse, status: number, body: unknown) {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

async function readJson(req: IncomingMessage, limitBytes = 1_000_000): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > limitBytes) throw new Error("request body too large");
    chunks.push(buffer);
  }
  if (!total) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function authorized(req: IncomingMessage, cfg: SandboxServiceConfig): boolean {
  if (!cfg.token) return cfg.allowAnon;
  const header = String(req.headers.authorization || "");
  const provided = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : String(req.headers["x-sandbox-token"] || "").trim();
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(cfg.token);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function startSandboxService(overrides: Partial<SandboxServiceConfig> = {}): Promise<SandboxService> {
  const config: SandboxServiceConfig = { ...sandboxServiceConfig(), ...overrides };
  if (!config.token && !config.allowAnon) throw new Error("SANDBOX_TOKEN is not configured (set it, or SANDBOX_ALLOW_ANON=true for a dev box)");
  mkdirSync(config.jobsDir, { recursive: true });
  mkdirSync(config.stateRoot, { recursive: true });
  const limiter = createLimiter(config.maxConcurrency, config.maxQueue);
  const startedAt = Date.now();
  let completed = 0;

  // 出口代理：只有配置了上游（Burp）才启动；没有上游时宁可让 job 无网络，也不给直连。
  let proxy: ChainedProxy | undefined;
  if (config.upstreamProxy && config.driver === "docker") {
    proxy = await startChainedProxy({
      upstream: config.upstreamProxy,
      host: config.proxyListenHost,
      port: config.proxyListenPort,
      deny: config.egressDeny,
      injectHeaders: config.egressInjectHeaders,
    });
    console.log(`[sandbox] egress proxy on :${proxy.port} -> ${config.upstreamProxy}`);
  } else if (!config.upstreamProxy) {
    console.warn("[sandbox] no SANDBOX_UPSTREAM_PROXY/BURP_PROXY_URL: job containers get no network egress");
  }

  const server = createServer(async (req, res) => {
    const url = String(req.url || "");
    const path = url.split("?")[0] || "/";
    try {
      if (path === "/health") {
        json(res, 200, {
          ok: true, service: "nianyun-sandbox", driver: config.driver, image: config.image,
          runtime: config.runtime || "runc", network: config.network || (config.driver === "docker" ? "bridge" : "process"),
          egress_proxy: proxy ? `:${proxy.port} -> ${config.upstreamProxy}` : (config.proxyForJobs || "none"),
          isolation: config.runtime === "runsc" ? "microvm" : config.driver === "docker" ? "container" : "process-jail",
          limits: { timeout_s: [5, config.timeoutMaxS], memory_mb: [128, config.memoryMaxMb], output_bytes: config.outputBytes, files: config.filesMax },
          mounts: config.mounts,
          tls: config.caPem ? "verified via mounted CA" : config.tlsInsecure ? "insecure (SANDBOX_TLS_INSECURE=1)" : "strict",
          state: { volume: config.stateVolume, root: config.stateRoot, max_mb: config.stateMaxMb, max_files: config.stateMaxFiles, ttl_h: config.stateTtlH },
          concurrency: { ...limiter.stats(), max: config.maxConcurrency, queue: config.maxQueue },
          completed, uptime_s: Math.round((Date.now() - startedAt) / 1000),
        });
        return;
      }
      if (!authorized(req, config)) { json(res, 401, { ok: false, error: "unauthorized" }); return; }
      if (path === "/sandbox/capabilities") {
        json(res, 200, {
          ok: true, languages: ["python", "bash"],
          limits: { code_bytes: 200_000, timeout_s: [5, config.timeoutMaxS], memory_mb: [128, config.memoryMaxMb], requirements: 8, output_bytes: config.outputBytes, files: config.filesMax, file_bytes: config.fileBytes },
          isolation: config.runtime === "runsc" ? "microvm" : config.driver === "docker" ? "container" : "process-jail",
          egress: proxy ? "proxy-only (internal network)" : config.proxyForJobs || "none",
          // 如实申报能力边界：CONNECT 隧道看不到明文头，别让上层误以为 HTTPS 也被补过头。
          egress_headers: {
            plaintext_http: config.egressInjectHeaders === false ? "off" : "neutral-defaults",
            // 如实申报：默认不伪装 UA（浏览器 UA 在实测资产上会触发 attestation 钓身份页）。
            user_agent_injected: config.egressInjectHeaders !== false
              && Object.keys(config.egressInjectHeaders).includes("user-agent"),
            https_tunnel: "not-visible (job-side prelude shares the same policy)",
            opt_out_header: EGRESS_NO_INJECT_HEADER,
            ja3_capture: true,
            ja3_simulation: false,
          },
          state: { mount: "/state", persistent: true, max_mb: config.stateMaxMb, max_files: config.stateMaxFiles, ttl_h: config.stateTtlH },
        });
        return;
      }
      if (path === "/sandbox/egress-log") {
        const limit = Math.min(200, Math.max(1, Number(new URL(url, "http://x").searchParams.get("limit") || 50)));
        json(res, 200, { ok: true, entries: (proxy?.entries || []).slice(-limit) as EgressEntry[] });
        return;
      }
      if (path === "/sandbox/state") {
        const params = new URL(url, "http://x").searchParams;
        const key = normalizeStateKey(params.get("key"));
        if (!key) { json(res, 400, { ok: false, error: "key is required" }); return; }
        if (req.method === "DELETE") { json(res, 200, { ok: true, ...clearState(config, key) }); return; }
        if (req.method !== "GET") { json(res, 405, { ok: false, error: "GET or DELETE required" }); return; }
        try { json(res, 200, { ok: true, ...measureState(config, key, false) }); }
        catch (error) { json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }); }
        return;
      }
      if (path === "/sandbox/state/file") {
        if (req.method === "PUT") {
          // 控制面写回 /state 的唯一口子：RPC cursor、以及"把工具结果塞回给脚本"。
          const params = new URL(url, "http://x").searchParams;
          const key = normalizeStateKey(params.get("key"));
          const file = String(params.get("path") || "");
          if (!key || !file) { json(res, 400, { ok: false, error: "key and path are required" }); return; }
          let body: unknown;
          try { body = await readJson(req, config.fileBytes + 4096); }
          catch (error) { json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }); return; }
          const content = typeof (body as { content?: unknown })?.content === "string" ? String((body as { content: string }).content) : "";
          if (Buffer.byteLength(content) > config.fileBytes) { json(res, 413, { ok: false, error: `content exceeds ${config.fileBytes} bytes` }); return; }
          let target: string;
          try { target = stateFilePath(config, key, file); }
          catch (error) { json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }); return; }
          try {
            mkdirSync(dirname(target), { recursive: true });
            writeFileSync(target, content);
            json(res, 200, { ok: true, key, path: file, bytes: Buffer.byteLength(content) });
          } catch (error) { json(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) }); }
          return;
        }
        if (req.method !== "GET") { json(res, 405, { ok: false, error: "GET or PUT required" }); return; }
        const params = new URL(url, "http://x").searchParams;
        const key = normalizeStateKey(params.get("key"));
        const file = String(params.get("path") || "");
        if (!key || !file) { json(res, 400, { ok: false, error: "key and path are required" }); return; }
        let target: string;
        try { target = stateFilePath(config, key, file); }
        catch (error) { json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }); return; }
        let raw: Buffer;
        try { raw = readFileSync(target); }
        catch { json(res, 404, { ok: false, error: "not found" }); return; }
        const clipped = raw.subarray(0, config.fileBytes);
        const text = clipped.toString("utf8");
        json(res, 200, {
          ok: true, key, path: file, bytes: raw.length, truncated: raw.length > clipped.length,
          is_text: !text.includes("\uFFFD"),
          ...(text.includes("\uFFFD") ? { content_base64: clipped.toString("base64") } : { content: text }),
        });
        return;
      }
      if (path !== "/sandbox/exec") { json(res, 404, { ok: false, error: "not found" }); return; }
      if (req.method !== "POST") { json(res, 405, { ok: false, error: "POST required" }); return; }
      let request;
      try {
        request = normalizeRequest(await readJson(req), config);
      } catch (error) {
        json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
        return;
      }
      const admitted = await limiter.acquire();
      if (!admitted) {
        json(res, 503, { ok: false, error: `sandbox saturated (${config.maxConcurrency} active, ${config.maxQueue} queued)` });
        return;
      }
      try { sweepState(config); } catch { /* 清理失败不影响执行 */ }
      // volume-subpath 必须先存在；否则 docker 会在挂载阶段直接失败。
      if (request.state_key) {
        try { ensureStateDir(config, request.state_key); }
        catch (error) { json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }); limiter.release(); return; }
      }
      let result: SandboxResult;
      try {
        result = await runSandboxJob(request, config);
        completed += 1;
      } finally {
        limiter.release();
      }
      const state = request.state_key ? measureState(config, request.state_key) : undefined;
      json(res, 200, { ...result, ok: result.ok, ...(state ? { state } : {}) });
    } catch (error) {
      json(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error), run_id: randomBytes(4).toString("hex") });
    }
  });

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(config.port, config.host, () => resolvePromise());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : config.port;
  console.log(`[sandbox] listening on ${config.host}:${port} driver=${config.driver} image=${config.image} isolation=${config.runtime === "runsc" ? "microvm" : config.driver === "docker" ? "container" : "process-jail"}`);

  return {
    server,
    config: { ...config, port },
    proxy,
    close: async () => {
      await proxy?.close();
      await new Promise<void>((resolvePromise) => { server.closeAllConnections?.(); server.close(() => resolvePromise()); });
    },
  };
}

if (process.argv[1] && new URL(import.meta.url).pathname === new URL(`file://${process.argv[1].replace(/\\/g, "/")}`).pathname) {
  startSandboxService().catch((error) => {
    console.error(`[sandbox] failed to start: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}

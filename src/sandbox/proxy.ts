/**
 * 沙箱侧出口代理（chained proxy）。
 *
 * 为什么要有它：Job 容器跑在 `--internal` 网络上，除了沙箱服务谁也连不上；
 * 沙箱服务同时在这个网络上开一个转发代理，把 CONNECT/HTTP 请求**串到 Burp**。
 * 于是 Agent 写的 Python 脚本打出去的每一个连接都满足两个条件：
 *   1) 物理上只能到代理（没有其它路由）；
 *   2) 语义上被 MITM 审计（上游是 BURP_PROXY_URL）。
 *
 * 这是"出站强制走 MITM"的执行点，不是文档承诺。
 */
import { createServer as createHttpServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import { URL } from "node:url";
import { parseClientHello } from "./ja3.js";

export type EgressEntry = {
  at: number;
  kind: "connect" | "http";
  target: string;
  allowed: boolean;
  reason?: string;
  /** 本次明文 HTTP 请求被代理补上的头名（不含被显式豁免的请求）。 */
  injected_headers?: string[];
  /** CONNECT 隧道里观察到的 ClientHello 指纹（只记录，不模拟）。 */
  ja3?: string;
  ja3_hash?: string;
  sni?: string;
  tls_version?: number;
};

export type ChainedProxy = {
  server: Server;
  port: number;
  entries: EgressEntry[];
  close: () => Promise<void>;
};

const MAX_ENTRIES = 500;
const IDLE_MS = 30_000;
const MAX_CONCURRENT = 64;

/** 默认拒绝云元数据与回环：这两类是 Agent 代码最容易"顺手"打到的非目标地址。 */
const DEFAULT_DENY = ["169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost", "::1"];

/**
 * 明文 HTTP 出口补头。2026-11-07 实测（scripts/runtime/egress-probe.mjs，developer.aliyun.com）：
 *
 *   裸 python-requests UA → 200 / 213809B
 *   浏览器 UA（任何变体，含豁免头）→ 403 / 7155B，正文是 CLIENT_UNCLASSIFIED 的
 *     "analysis proxy requires a client attestation payload"，要求提交
 *     principal{username,email} / origin / provenance / delegation（本机账号、git 邮箱）。
 *   同机其它主机与 CDN 带浏览器 UA 仍 200；同一 JA3 指纹下两种 UA 结果相反 → 排除 TLS/JA3。
 *
 * 结论：**浏览器 UA 不是解药，是触发器**（而且那张 403 是钓身份页，waf-ledger 已判
 * identity_wall 并禁止提交）。所以默认只补中性的 Accept/Accept-Language，**不伪装 UA**；
 * 需要浏览器 UA 的资产用 SANDBOX_EGRESS_UA_POLICY=browser 或显式 JSON 头 opt-in。
 *
 * 边界不变：HTTPS 走 CONNECT 隧道，代理看不到明文头；那一层由 job 侧 prelude 负责
 * （driver.ts），两边共用同一个 egressHeaderPolicy，不会一层补 UA 一层不补。
 */
export const BROWSER_UA_EGRESS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";

/** 默认补头：刻意不含 user-agent。 */
export const NEUTRAL_EGRESS_HEADERS: Record<string, string> = {
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
};

export const DEFAULT_EGRESS_HEADERS = NEUTRAL_EGRESS_HEADERS;

/**
 * 代理层与 job prelude 的唯一策略入口。
 * - SANDBOX_EGRESS_INJECT_HEADERS: 空=默认；0/false/no/off=完全关闭；JSON=自定义/追加头。
 * - SANDBOX_EGRESS_UA_POLICY=browser: 把浏览器 UA 加回默认头（显式 opt-in）。
 */
export function egressHeaderPolicy(env: NodeJS.ProcessEnv = process.env): { headers: Record<string, string>; disabled: boolean } {
  const raw = String(env.SANDBOX_EGRESS_INJECT_HEADERS ?? "").trim();
  if (["0", "false", "no", "off"].includes(raw.toLowerCase())) return { headers: {}, disabled: true };
  const browser = String(env.SANDBOX_EGRESS_UA_POLICY || "").trim().toLowerCase() === "browser";
  const base: Record<string, string> = browser
    ? { "user-agent": BROWSER_UA_EGRESS, ...NEUTRAL_EGRESS_HEADERS }
    : { ...NEUTRAL_EGRESS_HEADERS };
  if (!raw) return { headers: base, disabled: false };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const custom = Object.fromEntries(Object.entries(parsed as Record<string, unknown>)
        .map(([key, value]) => [key.toLowerCase(), String(value)]));
      return { headers: { ...base, ...custom }, disabled: false };
    }
  } catch { /* 非法配置退回默认，不让沙箱起不来 */ }
  return { headers: base, disabled: false };
}

/** 显式豁免：模型要做「裸 UA vs 浏览器 UA」对照时加这个头，代理一个字都不补。 */
export const EGRESS_NO_INJECT_HEADER = "x-nianyun-no-ua";

/** 只补缺失的头；注入逻辑本身出错时原样透传，绝不能把请求带挂。 */
export function injectBrowserHeaders(
  original: Record<string, unknown>,
  defaults: Record<string, string>,
): { headers: Record<string, unknown>; injected: string[] } {
  const headers = { ...original };
  const lower = new Set(Object.keys(headers).map(key => key.toLowerCase()));
  if (lower.has(EGRESS_NO_INJECT_HEADER)) return { headers, injected: [] };
  const injected: string[] = [];
  for (const [key, value] of Object.entries(defaults)) {
    if (lower.has(key.toLowerCase())) continue;
    headers[key] = value;
    injected.push(key);
  }
  return { headers, injected };
}

export async function startChainedProxy(options: {
  upstream: string;
  host?: string;
  port?: number;
  deny?: string[];
  onEntry?: (entry: EgressEntry) => void;
  /** false / 空对象 = 关闭补头；缺省用 DEFAULT_EGRESS_HEADERS。 */
  injectHeaders?: Record<string, string> | false;
}): Promise<ChainedProxy> {
  const upstreamUrl = new URL(options.upstream);
  if (!["http:", "https:"].includes(upstreamUrl.protocol)) throw new Error("upstream proxy must be http(s)");
  const upstreamPort = Number(upstreamUrl.port || (upstreamUrl.protocol === "https:" ? 443 : 80));
  const deny = new Set([...(options.deny ?? []), ...DEFAULT_DENY].map(item => item.trim().toLowerCase()).filter(Boolean));
  const injectHeaders = options.injectHeaders === false ? {} : (options.injectHeaders ?? DEFAULT_EGRESS_HEADERS);
  const entries: EgressEntry[] = [];
  let active = 0;

  const record = (entry: EgressEntry) => {
    entries.push(entry);
    if (entries.length > MAX_ENTRIES) entries.splice(0, entries.length - MAX_ENTRIES);
    options.onEntry?.(entry);
  };
  const denied = (host: string): string | undefined => {
    const normalized = host.replace(/^\[|\]$/g, "").toLowerCase();
    if (deny.has(normalized)) return "denied by egress policy";
    if (/^10\./.test(normalized) || /^192\.168\./.test(normalized) || /^172\.(1[6-9]|2\d|3[01])\./.test(normalized)) {
      // 内网目标是 SRC 的常态，放行但留下记录：审计靠这份日志，不靠拒绝。
      return undefined;
    }
    return undefined;
  };

  const server = createHttpServer();
  server.on("request", (req: IncomingMessage, res: ServerResponse) => {
    const target = String(req.url || "");
    if (active >= MAX_CONCURRENT) {
      record({ at: Date.now(), kind: "http", target, allowed: false, reason: "proxy saturated" });
      res.writeHead(503).end("sandbox egress proxy saturated");
      return;
    }
    let parsed: URL;
    try { parsed = new URL(target); } catch { res.writeHead(400).end("absolute URI required"); return; }
    const reason = denied(parsed.hostname);
    // 补头失败不能变成出口故障：任何异常都退回原样透传。
    let forwarded: Record<string, unknown> = req.headers as Record<string, unknown>;
    let injectedHeaders: string[] = [];
    try {
      const injection = injectBrowserHeaders(forwarded, injectHeaders);
      forwarded = injection.headers;
      injectedHeaders = injection.injected;
    } catch { /* 原样透传 */ }
    record({ at: Date.now(), kind: "http", target, allowed: !reason, ...(reason ? { reason } : {}),
      ...(injectedHeaders.length ? { injected_headers: injectedHeaders } : {}) });
    if (reason) { res.writeHead(403).end(reason); return; }
    active += 1;
    const upstream = httpRequest({
      host: upstreamUrl.hostname, port: upstreamPort, method: req.method, path: target,
      headers: { ...forwarded, host: parsed.host },
      timeout: IDLE_MS,
      ...(upstreamUrl.protocol === "https:" ? { protocol: "https:" } : {}),
    }, upstreamResponse => {
      res.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
      upstreamResponse.pipe(res);
    });
    upstream.on("error", (error) => { res.writeHead(502).end(`sandbox egress failed: ${error.message}`); });
    upstream.on("close", () => { active = Math.max(0, active - 1); });
    req.pipe(upstream);
  });

  server.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
    const target = String(req.url || "");
    const [host, rawPort] = target.split(":");
    const port = Number(rawPort || 443);
    const reason = denied(String(host || ""));
    const entry: EgressEntry = { at: Date.now(), kind: "connect", target, allowed: !reason, ...(reason ? { reason } : {}) };
    record(entry);
    if (reason) { clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
    if (active >= MAX_CONCURRENT) { clientSocket.end("HTTP/1.1 503 Service Unavailable\r\n\r\n"); return; }
    // ClientHello 可能随 CONNECT 一起到（head），也可能在 200 之后的第一包。
    // 只做旁听：额外监听器不消费数据，pipe 仍照常转发，解析失败也不影响隧道。
    const captureHello = (chunk: Buffer) => {
      try {
        const fingerprint = parseClientHello(chunk);
        if (!fingerprint) return;
        entry.ja3 = fingerprint.ja3;
        entry.ja3_hash = fingerprint.ja3_hash;
        if (fingerprint.sni) entry.sni = fingerprint.sni;
        if (fingerprint.tls_version) entry.tls_version = fingerprint.tls_version;
      } catch { /* 指纹是观测项，不是转发前置条件 */ }
    };
    if (head.length) captureHello(head);
    else clientSocket.once("data", captureHello);
    active += 1;
    const upstream = netConnect({ host: upstreamUrl.hostname, port: upstreamPort });
    upstream.setTimeout(IDLE_MS, () => upstream.destroy());
    let established = false;
    upstream.on("connect", () => {
      upstream.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });
    upstream.on("data", function onHeader(chunk: Buffer) {
      if (established) return;
      const text = chunk.toString("latin1");
      if (!text.includes("\r\n\r\n")) return;
      established = true;
      upstream.removeListener("data", onHeader);
      const status = Number(text.split(" ")[1] || 502);
      if (status !== 200) { clientSocket.end(`HTTP/1.1 ${status} Upstream Proxy Error\r\n\r\n`); upstream.destroy(); return; }
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      const rest = chunk.subarray(text.indexOf("\r\n\r\n") + 4);
      if (rest.length) clientSocket.write(rest);
      if (head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    const cleanup = () => { active = Math.max(0, active - 1); upstream.destroy(); clientSocket.destroy(); };
    upstream.on("error", () => { clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); cleanup(); });
    upstream.on("close", cleanup);
    clientSocket.on("error", cleanup);
    clientSocket.on("close", cleanup);
  });

  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(options.port ?? 0, options.host ?? "0.0.0.0", () => resolvePromise());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return {
    server,
    port,
    entries,
    close: () => new Promise<void>((resolvePromise) => { server.closeAllConnections?.(); server.close(() => resolvePromise()); }),
  };
}
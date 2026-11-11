import { request as httpRequest, type ClientRequest, type IncomingMessage } from "node:http";
import { Agent, request as httpsRequest } from "node:https";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import type { Socket } from "node:net";

/**
 * 握手预算（2026-11-09）。
 *
 * 现场分层压测（N=30）：容器经宿主 7897 到模型域名，TCP 30/30、CONNECT 30/30 全通，
 * 但 **TLS 握手有 13% 概率卡死不返回**（宿主侧更高，约 33%）；同一时刻成功的握手只要
 * 200ms–3s。也就是说失败不是"慢"，是"这一条连接被上游吞了"，换一条立即就好。
 *
 * 旧实现只给 15s 一次机会，一次卡死就等于整场 agent_error 停摆（现场 event 6856、6879）。
 * 现在改成 25s 预算 + 最多 2 次重试。重试**只覆盖握手阶段**：请求体一旦发出就不再重复，
 * 否则模型侧会收到两条相同请求。
 */
const HANDSHAKE_TIMEOUT_MS = 25_000;
const HANDSHAKE_ATTEMPTS = 3;
const HANDSHAKE_BACKOFF_MS = 250;

type ProxyResponse = { ok: boolean; status: number; text: () => Promise<string>; json: () => Promise<unknown> };
type ProxiedResponse = ProxyResponse;
type HandshakeError = Error & { handshake?: boolean };

/** CONNECT 隧道或 TLS 层的瞬时故障：换一条连接重来即可，不涉及已发出的请求体。 */
function markHandshake(error: Error): Error {
  (error as HandshakeError).handshake = true;
  return error;
}

function handshakeFailure(message: string): Error {
  return markHandshake(new Error(message));
}

function sleepUnlessAborted(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal.aborted) { reject(new Error("模型请求已取消")); return; }
    const wait = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(wait);
      reject(new Error(signal.reason?.name === "TimeoutError" ? "模型响应超时（已达到配置的请求时限）" : "模型请求已取消"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** 一次传输尝试。握手失败的 Error 带 `handshake: true`，由外层决定是否重来。 */
function attemptThroughProxy(url: string, body: string, headers: Record<string, string>, proxyUrl: string, rejectUnauthorized: boolean, signal: AbortSignal): Promise<ProxyResponse> {
  const target = new URL(url);
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    let settled = false;
    let tunnel: Socket | undefined;
    let secure: TLSSocket | undefined;
    let request: ClientRequest | undefined;
    let connector: ClientRequest | undefined;
    let agent: Agent | undefined;
    /** 只有握手阶段的故障才允许整条重试；请求体发出后出错一律直接抛。 */
    let handshaking = true;
    const timer = setTimeout(() => fail(handshaking ? handshakeFailure("模型代理握手超时（TCP / CONNECT / TLS）") : new Error("模型代理握手超时（TCP / CONNECT / TLS）")), HANDSHAKE_TIMEOUT_MS);
    const cleanup = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      request?.destroy();
      connector?.destroy();
      secure?.destroy();
      tunnel?.destroy();
      agent?.destroy();
    };
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    /** 握手期故障：打上可重试标记。 */
    const failHandshake = (error: unknown) => {
      if (error instanceof Error && handshaking) markHandshake(error);
      fail(error);
    };
    const abort = () => fail(new Error(signal.reason?.name === "TimeoutError" ? "模型响应超时（已达到配置的请求时限）" : "模型请求已取消"));
    const receive = (response: IncomingMessage) => {
      handshaking = false;
      const chunks: Buffer[] = [];
      response.on("error", fail);
      response.on("aborted", () => fail(new Error("模型响应提前中断")));
      response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        if (settled) return;
        const raw = Buffer.concat(chunks).toString("utf8");
        const status = response.statusCode || 0;
        settled = true;
        cleanup();
        resolve({ ok: status >= 200 && status < 300, status, text: async () => raw, json: async () => JSON.parse(raw) as unknown });
      });
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) { abort(); return; }
    const proxyAuth = proxy.username || proxy.password
      ? { "Proxy-Authorization": `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}` }
      : {};
    const proxyRequest = proxy.protocol === "https:" ? httpsRequest : httpRequest;
    const proxyOptions = { hostname: proxy.hostname, port: proxy.port || (proxy.protocol === "https:" ? 443 : 80), ...(proxy.hostname === "host.docker.internal" ? { family: 4 } : {}) };
    const requestHeaders = { ...headers, "Content-Length": String(Buffer.byteLength(body)), "Accept-Encoding": "identity" };
    if (target.protocol === "http:") {
      request = proxyRequest({ ...proxyOptions, method: "POST", path: target.href, headers: { ...requestHeaders, ...proxyAuth, Host: target.host }, agent: false }, receive);
      request.on("socket", socket => socket.once(proxy.protocol === "https:" ? "secureConnect" : "connect", () => clearTimeout(timer)));
      request.on("error", fail);
      request.end(body);
      return;
    }
    const authority = `${target.hostname}:${target.port || 443}`;
    connector = proxyRequest({ ...proxyOptions, method: "CONNECT", path: authority, headers: { Host: authority, ...proxyAuth }, agent: false });
    connector.on("error", failHandshake);
    // 代理明确拒绝（407/403）重试也没用，按普通失败抛出。
    connector.on("response", response => { response.resume(); fail(new Error(`模型代理 CONNECT 失败：HTTP ${response.statusCode}`)); });
    connector.on("connect", (response, socket, head) => {
      tunnel = socket;
      if (settled) { socket.destroy(); return; }
      if (response.statusCode !== 200) { fail(new Error(`模型代理 CONNECT 失败：HTTP ${response.statusCode}`)); return; }
      if (head.length) socket.unshift(head);
      secure = tlsConnect({ socket, servername: target.hostname, rejectUnauthorized, ALPNProtocols: ["http/1.1"] });
      secure.on("error", failHandshake);
      secure.once("secureConnect", () => {
        if (settled) return;
        handshaking = false;
        clearTimeout(timer);
        agent = new Agent({ keepAlive: false });
        agent.createConnection = () => secure!;
        request = httpsRequest(target, { method: "POST", headers: requestHeaders, agent }, receive);
        request.on("error", fail);
        request.end(body);
      });
    });
    connector.end();
  });
}

/**
 * CONNECT has its own deadline; model generation uses the caller's full request deadline.
 *
 * 握手故障重试 HANDSHAKE_ATTEMPTS - 1 次，仅针对握手阶段。取消与超时立即透传，不重试。
 */
export async function requestThroughProxy(url: string, body: string, headers: Record<string, string>, proxyUrl: string, rejectUnauthorized: boolean, signal: AbortSignal): Promise<ProxiedResponse> {
  const target = new URL(url);
  const proxy = new URL(proxyUrl);
  if (!["http:", "https:"].includes(target.protocol) || !["http:", "https:"].includes(proxy.protocol)) {
    throw new Error("模型及代理地址必须使用 HTTP 或 HTTPS");
  }
  let lastError: unknown;
  for (let attempt = 1; attempt <= HANDSHAKE_ATTEMPTS; attempt++) {
    try {
      return await attemptThroughProxy(url, body, headers, proxyUrl, rejectUnauthorized, signal);
    } catch (error) {
      lastError = error;
      const retryable = error instanceof Error && (error as HandshakeError).handshake === true;
      if (!retryable || signal.aborted || attempt === HANDSHAKE_ATTEMPTS) throw error;
      await sleepUnlessAborted(HANDSHAKE_BACKOFF_MS * attempt, signal);
    }
  }
  throw lastError;
}

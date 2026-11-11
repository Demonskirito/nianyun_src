import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import type { Socket } from "node:net";

/**
 * Outbound HEAD request used by asset probing.
 *
 * Two properties matter here and neither is available from global fetch:
 *  - an explicit HTTP proxy (CONNECT tunnel), because this deployment's direct egress is dropped;
 *  - certificate-tolerant TLS, because probing an IP endpoint whose certificate names a domain is
 *    still a successful reachability signal.
 */
export type HeadResult = { status: number; headers: Headers; finalUrl: string; tls: Record<string, unknown> | null };

export function proxyFromEnv(): string {
  return String(process.env.HTTPS_PROXY || process.env.HTTP_PROXY || process.env.https_proxy || process.env.http_proxy || "").trim();
}

/**
 * Cheap liveness check for the configured egress proxy. When the proxy app is closed (host reboot,
 * VPN client stopped) every page.goto / HEAD otherwise burns its full timeout and a 400-asset queue
 * fails silently after hours; this turns it into one immediate, readable error instead.
 */
export function probeProxy(proxy: string, timeoutMs = 4000): Promise<string | null> {
  if (!proxy) return Promise.resolve(null);
  let target: URL;
  try { target = new URL(proxy); } catch { return Promise.resolve(`代理地址无法解析：${proxy}`); }
  const port = target.port ? Number(target.port) : 80;
  return new Promise((resolve) => {
    const socket = net.connect({ host: target.hostname, port });
    const done = (message: string | null): void => { socket.destroy(); resolve(message); };
    socket.setTimeout(timeoutMs, () => done(`出网代理不可达：${target.hostname}:${port} 连接超时（${timeoutMs}ms），请确认代理软件已启动`));
    socket.once("connect", () => done(null));
    socket.once("error", (error: NodeJS.ErrnoException) => done(`出网代理不可达：${target.hostname}:${port} ${error.code || error.message}，请确认代理软件已启动`));
  });
}

function tunnel(proxy: URL, host: string, port: number, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: proxy.hostname,
      port: proxy.port ? Number(proxy.port) : 80,
      method: "CONNECT",
      path: `${host}:${port}`,
      timeout: timeoutMs,
      ...(proxy.username
        ? { headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}` } }
        : {}),
    });
    request.on("connect", (response, socket) => {
      if (response.statusCode !== 200) { socket.destroy(); reject(new Error(`proxy CONNECT ${response.statusCode}`)); return; }
      resolve(socket);
    });
    request.on("timeout", () => request.destroy(new Error(`proxy timeout after ${timeoutMs}ms`)));
    request.on("error", reject);
    request.end();
  });
}

function collect(stream: http.IncomingMessage, status: number, finalUrl: string, socket: Socket | null): HeadResult {
  const headers = new Headers();
  for (const [name, value] of Object.entries(stream.headers)) {
    if (typeof value === "string") headers.set(name, value);
    else if (Array.isArray(value)) headers.set(name, value.join(", "));
  }
  let tlsInfo: Record<string, unknown> | null = null;
  if (socket) {
    const secure = socket as import("node:tls").TLSSocket;
    const certificate = secure.getPeerCertificate?.() as unknown as Record<string, unknown> | undefined;
    tlsInfo = {
      protocol: secure.getProtocol?.() || null,
      authorized: secure.authorized ?? false,
      authorization_error: secure.authorizationError || null,
      certificate: certificate && Object.keys(certificate).length ? {
        subject: certificate.subject || null,
        issuer: certificate.issuer || null,
        valid_from: certificate.valid_from || null,
        valid_to: certificate.valid_to || null,
        fingerprint256: certificate.fingerprint256 || null,
        subject_alt_name: certificate.subjectaltname || null,
      } : null,
    };
  }
  stream.resume();
  return { status, headers, finalUrl, tls: tlsInfo };
}

export function headRequest(url: string, options: { timeoutMs?: number; proxy?: string } = {}): Promise<HeadResult> {
  const target = new URL(url);
  const secure = target.protocol === "https:";
  const port = target.port ? Number(target.port) : secure ? 443 : 80;
  const timeoutMs = options.timeoutMs ?? 8000;
  const path = `${target.pathname}${target.search}`;
  const proxy = options.proxy || "";

  const run = (socket?: Socket): Promise<HeadResult> => new Promise((resolve, reject) => {
    const request = secure
      ? https.request({
          host: target.hostname, port, path, method: "HEAD",
          rejectUnauthorized: false,
          servername: target.hostname,
          ...(socket ? { createConnection: () => tls.connect({ socket, servername: target.hostname, rejectUnauthorized: false }) } : {}),
        })
      : http.request({ host: target.hostname, port, path, method: "HEAD", ...(socket ? { createConnection: () => socket } : {}) });
    request.setTimeout(timeoutMs, () => request.destroy(new Error(`timeout after ${timeoutMs}ms`)));
    request.on("response", (response) => {
      const peer = secure ? (response.socket as Socket) : null;
      resolve(collect(response, response.statusCode || 0, url, peer));
    });
    request.on("error", reject);
    request.end();
  });

  if (!proxy) return run();
  return tunnel(new URL(proxy), target.hostname, port, timeoutMs).then((socket) => run(socket));
}
/**
 * 竞态/TOCTOU 的底层发射器（控制面专用）。
 *
 * 为什么不能在沙箱里跑并发：job 容器出站只有 `sandbox:8899 → Burp` 一条链，
 * 代理层排队 + 逐个 TLS 握手会把"并发"抹平成串行；一个 asyncio.gather 20 发，
 * 到达顺序和间隔完全由代理决定，测出来的"竞态"是假的。
 *
 * 这里改在控制面用裸 socket 做：
 *   1. 先把 N 条连接全部建好（TCP + TLS 握手完成，什么都不发）；
 *   2. 屏障：所有连接就绪后，在同一轮事件循环里连续 write（跨度通常 0–2ms）；
 *   3. 各自读到 EOF，解析状态行/头/体，回一个数组。
 * 代价是这条路径不经过 Burp（Burp history 里看不到），所以结果要当成证据记录，
 * 并显式标注 via=direct。
 */
import { createHash } from "node:crypto";
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";

export type RaceTarget = { host: string; port: number; tls: boolean; servername: string };
/** 控制面容器没有直连出口（实测 443 被掐断），只有 host.docker.internal:8080 的 Burp。 */
export type RaceProxy = { host: string; port: number };

export type RaceRequest = {
  method: string;
  /** 路径（含 query），例如 `/api/coupon?code=X`。 */
  path: string;
  headers?: Record<string, string>;
  body?: string;
};

export type RaceResponse = {
  index: number;
  status: number | null;
  bytes: number;
  body_sha256: string;
  sent_at: number;
  done_at: number;
  headers: Record<string, string>;
  preview: string;
  error?: string;
};

export type RaceOutcome = {
  via?: "direct" | "burp-proxy";
  target: string;
  requests: number;
  concurrency: number;
  batches: number;
  spread_ms: number;
  elapsed_ms: number;
  statuses: Record<string, number>;
  distinct_bodies: number;
  responses: RaceResponse[];
  errors: number;
  timed_out: number;
};

/** 把一条请求序列化成裸 HTTP/1.1 文本（不依赖任何客户端库，避免隐式排队）。 */
export function buildRawRequest(request: RaceRequest, hostHeader: string): string {
  const headers = { ...(request.headers || {}) };
  const body = request.body ?? "";
  const lower = new Map(Object.keys(headers).map(key => [key.toLowerCase(), key]));
  if (!lower.has("host")) headers["Host"] = hostHeader;
  if (!lower.has("connection")) headers["Connection"] = "close";
  if (!lower.has("accept")) headers["Accept"] = "*/*";
  if (body && !lower.has("content-length")) headers["Content-Length"] = String(Buffer.byteLength(body));
  const lines = [`${request.method.toUpperCase()} ${request.path} HTTP/1.1`];
  for (const [key, value] of Object.entries(headers)) lines.push(`${key}: ${value}`);
  return `${lines.join("\r\n")}\r\n\r\n${body}`;
}

function parseResponse(raw: Buffer, index: number, sentAt: number): RaceResponse {
  const split = raw.indexOf("\r\n\r\n");
  const head = split >= 0 ? raw.subarray(0, split).toString("latin1") : raw.toString("latin1");
  const body = split >= 0 ? raw.subarray(split + 4) : Buffer.alloc(0);
  const [statusLine = "", ...headerLines] = head.split("\r\n");
  const statusMatch = statusLine.match(/^HTTP\/1\.[01] (\d{3})/);
  const headers: Record<string, string> = {};
  for (const line of headerLines) {
    const colon = line.indexOf(":");
    if (colon > 0) headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  return {
    index, status: statusMatch ? Number(statusMatch[1]) : null, bytes: raw.byteLength,
    body_sha256: createHash("sha256").update(body).digest("hex").slice(0, 16),
    sent_at: sentAt, done_at: Date.now(), headers,
    preview: body.subarray(0, 300).toString("utf8").replace(/\s+/g, " ").trim(),
  };
}

/** 读代理对 CONNECT 的响应头（到空行为止）。 */
function readConnectReply(socket: Socket, timeoutMs: number): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    let buffer = "";
    const timer = setTimeout(() => { socket.destroy(); rejectPromise(new Error("connect reply timed out")); }, timeoutMs);
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("latin1");
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return;
      socket.off("data", onData);
      clearTimeout(timer);
      const status = buffer.slice(0, end).split("\r\n")[0] || "";
      if (!/^HTTP\/1\.[01] 200/.test(status)) { socket.destroy(); rejectPromise(new Error(`proxy refused CONNECT: ${status.slice(0, 80)}`)); return; }
      resolvePromise();
    };
    socket.on("data", onData);
    socket.once("error", (error) => { clearTimeout(timer); rejectPromise(error); });
  });
}

function openSocket(target: RaceTarget, timeoutMs: number, proxy?: RaceProxy): Promise<Socket> {
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => { socket.destroy(); rejectPromise(new Error("connect timed out")); }, timeoutMs);
    const fail = (error: Error) => { clearTimeout(timer); rejectPromise(error); };
    if (proxy) {
      // 走 Burp：每条连接先建隧道（握手完成），屏障之后再写请求——
      // 这样"同时发出"只取决于我们这一侧的 write 循环，代理只负责转发。
      const raw = netConnect({ host: proxy.host, port: proxy.port });
      raw.once("error", fail);
      raw.once("connect", () => {
        raw.write(`CONNECT ${target.host}:${target.port} HTTP/1.1\r\nHost: ${target.host}:${target.port}\r\nProxy-Connection: keep-alive\r\n\r\n`);
        readConnectReply(raw, timeoutMs).then(() => {
          if (!target.tls) { clearTimeout(timer); resolvePromise(raw); return; }
          const secure = tlsConnect({ socket: raw, servername: target.servername, rejectUnauthorized: false });
          secure.once("secureConnect", () => { clearTimeout(timer); resolvePromise(secure); });
          secure.once("error", fail);
        }).catch(fail);
      });
      return;
    }
    const socket = target.tls
      ? tlsConnect({ host: target.host, port: target.port, servername: target.servername, rejectUnauthorized: false })
      : netConnect({ host: target.host, port: target.port });
    const readyEvent = target.tls ? "secureConnect" : "connect";
    socket.once(readyEvent, () => { clearTimeout(timer); resolvePromise(socket); });
    socket.once("error", fail);
  });
}

function readAll(socket: Socket, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => { socket.destroy(); rejectPromise(new Error("response timed out")); }, timeoutMs);
    socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    socket.once("end", () => { clearTimeout(timer); resolvePromise(Buffer.concat(chunks)); });
    socket.once("close", () => { clearTimeout(timer); resolvePromise(Buffer.concat(chunks)); });
    socket.once("error", (error) => { clearTimeout(timer); rejectPromise(error); });
  });
}

/**
 * 发一轮：先把 concurrency 条连接全建好，再在同一轮里连续写。
 * count 大于 concurrency 时分批，每批都做一次屏障，批次之间不等待。
 */
export async function fireRace(
  target: RaceTarget,
  requests: RaceRequest[],
  options: { concurrency?: number; timeoutMs?: number; proxy?: RaceProxy } = {},
): Promise<RaceOutcome> {
  const started = Date.now();
  const concurrency = Math.max(1, Math.min(Number(options.concurrency || requests.length) || requests.length, requests.length, 64));
  const timeoutMs = Math.max(1000, Number(options.timeoutMs || 15_000));
  const hostHeader = target.tls && target.port !== 443 ? `${target.servername}:${target.port}` : target.port === 80 || target.port === 443 ? target.servername : `${target.servername}:${target.port}`;
  const responses: RaceResponse[] = [];
  let errors = 0;
  let timedOut = 0;
  let spread = 0;
  let batches = 0;

  for (let offset = 0; offset < requests.length; offset += concurrency) {
    const batch = requests.slice(offset, offset + concurrency);
    batches += 1;
    const sockets: Array<Socket | undefined> = new Array(batch.length).fill(undefined);
    const ready: boolean[] = new Array(batch.length).fill(false);
    // 1) 预建连接：握手完成但一个字都不发。
    await Promise.all(batch.map(async (_, index) => {
      try { sockets[index] = await openSocket(target, timeoutMs, options.proxy); ready[index] = true; }
      catch (error) {
        errors += 1;
        responses.push({
          index: offset + index, status: null, bytes: 0, body_sha256: "", sent_at: 0, done_at: Date.now(), headers: {},
          preview: "", error: error instanceof Error ? error.message : String(error),
        });
      }
    }));

    // 2) 屏障：同一轮事件循环里把整批请求写出去，记录各自的发送时刻。
    const readers: Array<Promise<void>> = [];
    const sendTimes: number[] = [];
    for (let index = 0; index < batch.length; index += 1) {
      const socket = sockets[index];
      if (!socket || !ready[index]) continue;
      const payload = buildRawRequest(batch[index]!, hostHeader);
      const sentAt = Date.now();
      sendTimes.push(sentAt);
      socket.write(payload);
      readers.push(readAll(socket, timeoutMs).then(
        (raw) => { responses.push(parseResponse(raw, offset + index, sentAt)); },
        (error) => {
          if (String(error && (error as Error).message).includes("timed out")) timedOut += 1; else errors += 1;
          responses.push({
            index: offset + index, status: null, bytes: 0, body_sha256: "", sent_at: sentAt, done_at: Date.now(), headers: {},
            preview: "", error: error instanceof Error ? error.message : String(error),
          });
        },
      ).finally(() => { socket.destroy(); }));
    }
    if (sendTimes.length) spread = Math.max(spread, Math.max(...sendTimes) - Math.min(...sendTimes));
    await Promise.all(readers);
  }

  responses.sort((a, b) => a.index - b.index);
  const statuses: Record<string, number> = {};
  for (const item of responses) {
    const key = item.status === null ? "error" : String(item.status);
    statuses[key] = (statuses[key] || 0) + 1;
  }
  return {
    target: `${target.tls ? "https" : "http"}://${target.servername}:${target.port}`,
    via: options.proxy ? "burp-proxy" : "direct",
    requests: requests.length, concurrency, batches, spread_ms: spread,
    elapsed_ms: Date.now() - started, statuses,
    distinct_bodies: new Set(responses.map(item => item.body_sha256).filter(Boolean)).size,
    responses, errors, timed_out: timedOut,
  };
}
import { createServer, type Server } from "node:http";
import { afterEach, expect, it } from "vitest";
import { requestThroughProxy } from "../src/blackbox/model-proxy.js";

const servers: Server[] = [];
async function listen(server: Server): Promise<string> {
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing port");
  return `http://127.0.0.1:${address.port}`;
}
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

it("allows model generation beyond the handshake deadline and decodes chunked UTF-8", async () => {
  const proxy = await listen(createServer((req, res) => {
    expect(req.url).toBe("http://model.test/v1/chat/completions");
    req.resume();
    setTimeout(() => {
      res.writeHead(200, { "Content-Type": "application/json" });
      const raw = Buffer.from(JSON.stringify({ message: "模型响应中文" }));
      for (const byte of raw) res.write(Buffer.from([byte]));
      res.end();
    }, 15_200);
  }));
  const response = await requestThroughProxy("http://model.test/v1/chat/completions", "{}", {}, proxy, true, AbortSignal.timeout(20_000));
  expect(response.ok).toBe(true);
  expect(await response.json()).toEqual({ message: "模型响应中文" });
}, 25_000);

it("rejects a failed CONNECT with the HTTP status", async () => {
  const server = createServer();
  server.on("connect", (_req, socket) => socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"));
  const proxy = await listen(server);
  await expect(requestThroughProxy("https://model.test/v1", "{}", {}, proxy, true, AbortSignal.timeout(2000))).rejects.toThrow("HTTP 407");
});

it("retries a dropped CONNECT handshake once, then surfaces the definitive failure", async () => {
  // 现场故障形态：上游偶发吞掉隧道（13–33%），换一条连接立即就好。
  // 第一次直接断 socket（可重试），第二次明确 407（不可重试）——只允许重试一次。
  let connects = 0;
  const server = createServer();
  server.on("connect", (_req, socket) => {
    connects += 1;
    if (connects === 1) { socket.destroy(); return; }
    socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
  });
  const proxy = await listen(server);
  await expect(requestThroughProxy("https://model.test/v1", "{}", {}, proxy, true, AbortSignal.timeout(10_000))).rejects.toThrow("HTTP 407");
  expect(connects).toBe(2);
}, 15_000);

it("cancels an unfinished handshake and closes the socket", async () => {
  let closed!: Promise<void>;
  const controller = new AbortController();
  const server = createServer();
  server.on("connect", (_req, socket) => {
    closed = new Promise(resolve => socket.on("end", () => { socket.destroy(); resolve(); }));
    controller.abort();
  });
  const proxy = await listen(server);
  await expect(requestThroughProxy("https://model.test/v1", "{}", {}, proxy, true, controller.signal)).rejects.toThrow("模型请求已取消");
  await closed;
});

it("distinguishes model response timeout from proxy handshake failure", async () => {
  const proxy = await listen(createServer(req => req.resume()));
  await expect(requestThroughProxy("http://model.test/v1", "{}", {}, proxy, true, AbortSignal.timeout(100))).rejects.toThrow("模型响应超时");
});

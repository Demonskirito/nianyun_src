import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { buildRawRequest, fireRace } from "../src/blackbox/race.js";

describe("竞态发射器", () => {
  it("序列化请求时补齐 Host/Connection/Content-Length", () => {
    const raw = buildRawRequest({ method: "post", path: "/api/x?a=1", body: "a=1" }, "example.com");
    expect(raw.startsWith("POST /api/x?a=1 HTTP/1.1\r\n")).toBe(true);
    expect(raw).toContain("Host: example.com");
    expect(raw).toContain("Connection: close");
    expect(raw).toContain("Content-Length: 3");
    expect(raw.endsWith("\r\n\r\na=1")).toBe(true);
    // 显式头优先，不被默认值覆盖
    const kept = buildRawRequest({ method: "GET", path: "/", headers: { host: "h.example", connection: "keep-alive" } }, "ignored");
    expect(kept).toContain("host: h.example");
    expect(kept).toContain("connection: keep-alive");
    expect(kept).not.toContain("Host: ignored");
  });

  it("20 发在本地服务器上真正同时到达（跨度 < 100ms）", async () => {
    const arrivals: number[] = [];
    const server = createServer((request, response) => {
      arrivals.push(Date.now());
      request.resume();
      request.on("end", () => { response.writeHead(200, { "content-type": "text/plain" }); response.end("ok"); });
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const outcome = await fireRace(
        { host: "127.0.0.1", port, tls: false, servername: "127.0.0.1" },
        Array.from({ length: 20 }, () => ({ method: "GET", path: "/race" })),
        { concurrency: 20, timeoutMs: 8000 },
      );
      expect(outcome.responses).toHaveLength(20);
      expect(outcome.statuses["200"]).toBe(20);
      expect(outcome.errors).toBe(0);
      // 发送跨度：同一轮事件循环连续 write，实测个位数毫秒。
      expect(outcome.spread_ms).toBeLessThan(100);
      // 服务端看到的到达跨度同样应该很小，否则"并发"是假的。
      const arrivalSpread = Math.max(...arrivals) - Math.min(...arrivals);
      expect(arrivals).toHaveLength(20);
      expect(arrivalSpread).toBeLessThan(200);
      expect(outcome.distinct_bodies).toBe(1);
      // eslint-disable-next-line no-console
      console.log("RACE_MEASURED", JSON.stringify({ send_spread_ms: outcome.spread_ms, arrival_spread_ms: arrivalSpread, elapsed_ms: outcome.elapsed_ms }));
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });

  it("分批：concurrency 小于总数时按批屏障", async () => {
    const server = createServer((request, response) => { request.resume(); request.on("end", () => response.end("ok")); });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const outcome = await fireRace(
        { host: "127.0.0.1", port, tls: false, servername: "127.0.0.1" },
        Array.from({ length: 10 }, (_, index) => ({ method: "GET", path: `/r/${index}` })),
        { concurrency: 5, timeoutMs: 8000 },
      );
      expect(outcome.batches).toBe(2);
      expect(outcome.statuses["200"]).toBe(10);
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });
});
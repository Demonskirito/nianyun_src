import { createServer, request as httpRequest, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_EGRESS_HEADERS, EGRESS_NO_INJECT_HEADER, egressHeaderPolicy, injectBrowserHeaders,
  startChainedProxy, type ChainedProxy,
} from "../src/sandbox/proxy.js";
import { parseClientHello } from "../src/sandbox/ja3.js";
import { browserHeadersPrelude } from "../src/sandbox/driver.js";
import { sandboxServiceConfig } from "../src/sandbox/server.js";

const open: Array<{ close: () => Promise<void> }> = [];
afterEach(async () => { await Promise.all(open.splice(0).map(item => item.close())); });

function listen(server: Server): Promise<number> {
  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolvePromise(typeof address === "object" && address ? address.port : 0);
    });
  });
}

/** 一个最小的 ClientHello：含 GREASE、supported_groups、ec_point_formats 和 SNI。 */
function clientHello(): Buffer {
  const sni = Buffer.from("a.test", "utf8");
  // server_name_list: list_len(2) + type(1) + name_len(2) + name
  const serverName = Buffer.concat([
    Buffer.from([(3 + sni.length) >> 8, (3 + sni.length) & 0xff, 0x00, sni.length >> 8, sni.length & 0xff]), sni,
  ]);
  const groups = Buffer.from([0x00, 0x04, 0x00, 0x1d, 0x0a, 0x0a]);
  const formats = Buffer.from([0x01, 0x00]);
  const ext = (type: number, body: Buffer) => Buffer.concat([
    Buffer.from([type >> 8, type & 0xff, body.length >> 8, body.length & 0xff]), body,
  ]);
  const extensions = Buffer.concat([ext(0x0000, serverName), ext(0x000a, groups), ext(0x000b, formats)]);
  const handshakeBody = Buffer.concat([
    Buffer.from([0x03, 0x03]), Buffer.alloc(32), Buffer.from([0x00]),
    Buffer.from([0x00, 0x08, 0x13, 0x01, 0x0a, 0x0a, 0x00, 0x2f, 0x00, 0xff]),
    Buffer.from([0x01, 0x00]),
    Buffer.from([extensions.length >> 8, extensions.length & 0xff]), extensions,
  ]);
  const handshake = Buffer.concat([
    Buffer.from([0x01, handshakeBody.length >> 16, (handshakeBody.length >> 8) & 0xff, handshakeBody.length & 0xff]),
    handshakeBody,
  ]);
  return Buffer.concat([
    Buffer.from([0x16, 0x03, 0x01, handshake.length >> 8, handshake.length & 0xff]), handshake,
  ]);
}

describe("egress UA policy (browser UA is opt-in, not the default)", () => {
  it("default headers never spoof a browser UA", () => {
    expect(egressHeaderPolicy({}).headers["user-agent"]).toBeUndefined();
    expect(egressHeaderPolicy({}).headers.accept).toContain("text/html");
    expect(DEFAULT_EGRESS_HEADERS["user-agent"]).toBeUndefined();
  });

  it("SANDBOX_EGRESS_UA_POLICY=browser adds it back explicitly", () => {
    expect(egressHeaderPolicy({ SANDBOX_EGRESS_UA_POLICY: "browser" }).headers["user-agent"]).toContain("Edg/131");
  });

  it("explicit JSON headers are an opt-in too; off switch wins", () => {
    expect(egressHeaderPolicy({ SANDBOX_EGRESS_INJECT_HEADERS: '{"User-Agent":"my-scanner/1"}' }).headers["user-agent"]).toBe("my-scanner/1");
    expect(egressHeaderPolicy({ SANDBOX_EGRESS_INJECT_HEADERS: "0", SANDBOX_EGRESS_UA_POLICY: "browser" }).disabled).toBe(true);
    expect(egressHeaderPolicy({ SANDBOX_EGRESS_INJECT_HEADERS: "{bad json" }).headers.accept).toContain("text/html");
  });
});

describe("plaintext HTTP header injection", () => {
  it("fills missing neutral headers but never overwrites explicit ones", () => {
    const result = injectBrowserHeaders({ "user-agent": "my-scanner/1", "x-custom": "1" }, DEFAULT_EGRESS_HEADERS);
    expect(result.headers["user-agent"]).toBe("my-scanner/1");
    expect(result.headers["x-custom"]).toBe("1");
    expect(result.headers.accept).toContain("text/html");
    expect(result.injected).toEqual(["accept", "accept-language"]);
  });

  it("honours the explicit opt-out so bare-UA comparisons stay possible", () => {
    const result = injectBrowserHeaders({ [EGRESS_NO_INJECT_HEADER]: "1" }, DEFAULT_EGRESS_HEADERS);
    expect(result.injected).toEqual([]);
    expect(result.headers["user-agent"]).toBeUndefined();
  });

  it("a case-insensitive opt-out works too", () => {
    const result = injectBrowserHeaders({ "X-Nianyun-No-UA": "1" }, DEFAULT_EGRESS_HEADERS);
    expect(result.injected).toEqual([]);
  });
});

describe("egress proxy injects headers into the forwarded request", () => {
  it("injects by default, reports it in the entry, and skips opted-out requests", async () => {
    const seen: Array<Record<string, unknown>> = [];
    const upstream = createServer((req, res) => {
      seen.push({ url: req.url, headers: req.headers });
      res.writeHead(200).end("ok");
    });
    const upstreamPort = await listen(upstream);
    open.push({ close: () => new Promise<void>(resolvePromise => upstream.close(() => resolvePromise())) });
    const proxy: ChainedProxy = await startChainedProxy({ upstream: `http://127.0.0.1:${upstreamPort}`, host: "127.0.0.1", port: 0 });
    open.push(proxy);

    const send = (headers: Record<string, string>) => new Promise<void>((resolvePromise, rejectPromise) => {
      const req = httpRequest({ host: "127.0.0.1", port: proxy.port, path: "http://example.test/x", headers },
        res => { res.resume(); res.on("end", () => resolvePromise()); });
      req.on("error", rejectPromise);
      req.end();
    });

    await send({});
    // 默认只补中性头：伪装浏览器 UA 在实测资产上会触发 attestation 钓身份页。
    expect((seen[0]!.headers as Record<string, unknown>)["user-agent"]).toBeUndefined();
    expect(proxy.entries.at(-1)).toMatchObject({ kind: "http", allowed: true, injected_headers: ["accept", "accept-language"] });

    await send({ "user-agent": "python-requests/2.32", [EGRESS_NO_INJECT_HEADER]: "1" });
    expect((seen[1]!.headers as Record<string, unknown>)["user-agent"]).toBe("python-requests/2.32");
    expect(proxy.entries.at(-1)?.injected_headers).toBeUndefined();
  });

  it("can be disabled entirely", async () => {
    const seen: Array<Record<string, unknown>> = [];
    const upstream = createServer((req, res) => { seen.push({ headers: req.headers }); res.writeHead(200).end("ok"); });
    const upstreamPort = await listen(upstream);
    open.push({ close: () => new Promise<void>(resolvePromise => upstream.close(() => resolvePromise())) });
    const proxy = await startChainedProxy({ upstream: `http://127.0.0.1:${upstreamPort}`, host: "127.0.0.1", port: 0, injectHeaders: false });
    open.push(proxy);
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const req = httpRequest({ host: "127.0.0.1", port: proxy.port, path: "http://example.test/x", headers: {} },
        res => { res.resume(); res.on("end", () => resolvePromise()); });
      req.on("error", rejectPromise);
      req.end();
    });
    expect((seen[0]!.headers as Record<string, unknown>)["user-agent"]).toBeUndefined();
    expect(proxy.entries.at(-1)?.injected_headers).toBeUndefined();
  });
});

describe("JA3 capture (record only, no simulation)", () => {
  it("parses a ClientHello, drops GREASE and extracts SNI", () => {
    const hello = clientHello();
    const fp = parseClientHello(hello);
    expect(fp).toBeDefined();
    expect(fp!.tls_version).toBe(771);
    expect(fp!.sni).toBe("a.test");
    expect(fp!.ja3_hash).toMatch(/^[0-9a-f]{32}$/);
    expect(fp!.ja3).toContain("771,");
    expect(fp!.ja3).not.toContain("2570"); // 0x0a0a GREASE
    expect(parseClientHello(hello)!.ja3_hash).toBe(fp!.ja3_hash);
  });

  it("ignores non-TLS / truncated bytes without throwing", () => {
    expect(parseClientHello(Buffer.from("GET / HTTP/1.1\r\n\r\n"))).toBeUndefined();
    expect(parseClientHello(Buffer.from([0x16, 0x03, 0x01]))).toBeUndefined();
    expect(parseClientHello(Buffer.alloc(0))).toBeUndefined();
  });
});

describe("HTTPS-side job prelude", () => {
  it("patches requests.Session.request with neutral defaults (no browser UA)", () => {
    const prelude = browserHeadersPrelude({} as NodeJS.ProcessEnv);
    expect(prelude).toContain("Session.request");
    expect(prelude).toContain("accept-language");
    expect(prelude).toContain("x-nianyun-no-ua");
    expect(prelude).not.toContain("Edg/131");
  });

  it("browser UA is available only via explicit policy", () => {
    expect(browserHeadersPrelude({ SANDBOX_EGRESS_UA_POLICY: "browser" } as NodeJS.ProcessEnv)).toContain("Edg/131");
  });

  it("can be switched off for bare-UA experiments", () => {
    expect(browserHeadersPrelude({ SANDBOX_EGRESS_INJECT_HEADERS: "0" } as NodeJS.ProcessEnv)).toBe("");
  });

  it("accepts custom headers via JSON", () => {
    const prelude = browserHeadersPrelude({ SANDBOX_EGRESS_INJECT_HEADERS: '{"X-Probe":"abc"}' } as NodeJS.ProcessEnv);
    expect(prelude).toContain('"x-probe":"abc"');
    expect(prelude).not.toContain("Edg/131");
  });

  it("service config exposes the same switch and the same UA policy", () => {
    expect(sandboxServiceConfig({ SANDBOX_EGRESS_INJECT_HEADERS: "false" } as NodeJS.ProcessEnv).egressInjectHeaders).toBe(false);
    expect(sandboxServiceConfig({} as NodeJS.ProcessEnv).egressInjectHeaders).toMatchObject({ accept: expect.stringContaining("text/html") });
    expect((sandboxServiceConfig({} as NodeJS.ProcessEnv).egressInjectHeaders as Record<string, string>)["user-agent"]).toBeUndefined();
    expect(sandboxServiceConfig({ SANDBOX_EGRESS_UA_POLICY: "browser" } as NodeJS.ProcessEnv).egressInjectHeaders)
      .toMatchObject({ "user-agent": expect.stringContaining("Edg/131") });
  });
});

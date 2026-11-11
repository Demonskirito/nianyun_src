import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createNetServer, connect as netConnect } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { startSandboxService, sandboxServiceConfig, type SandboxService } from "../src/sandbox/server.js";
import { execInSandboxService, SandboxServiceError } from "../src/sandbox/client.js";
import { startChainedProxy } from "../src/sandbox/proxy.js";

const dirs: string[] = [];
const services: SandboxService[] = [];
const proxies: Array<{ close: () => Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(services.splice(0).map(service => service.close()));
  await Promise.all(proxies.splice(0).map(proxy => proxy.close()));
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

/** 用一个假的"上游 MITM 代理"验证链式转发确实发生了。 */
async function fakeUpstreamProxy(): Promise<{ port: number; seen: string[]; close: () => Promise<void> }> {
  const seen: string[] = [];
  const server = createNetServer((socket) => {
    socket.once("data", (chunk) => {
      const line = chunk.toString("latin1").split("\r\n")[0] || "";
      seen.push(line);
      if (/^CONNECT /i.test(line)) {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        socket.write("upstream-ok\n");
        socket.end();
        return;
      }
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nupstream-ok");
    });
  });
  await new Promise<void>(resolvePromise => server.listen(0, "127.0.0.1", () => resolvePromise()));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return {
    port,
    seen,
    close: () => new Promise<void>((resolvePromise) => { server.close(() => resolvePromise()); }),
  };
}

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

async function startProcessService(overrides: Record<string, unknown> = {}) {
  const jobsDir = tempDir("nianyun-sandbox-jobs-");
  const service = await startSandboxService({
    driver: "process",
    jobsDir,
    token: "test-token",
    allowAnon: false,
    host: "127.0.0.1",
    port: 0,
    maxConcurrency: 2,
    maxQueue: 1,
    proxyListenPort: 0,
    jobsDirOverride: undefined,
    ...overrides,
  } as never);
  services.push(service);
  return service;
}

const hasRuntime = (command: string) => {
  try {
    const probe = require("node:child_process") as typeof import("node:child_process");
    probe.spawnSync(command, ["--version"], { stdio: "ignore" });
    return true;
  } catch { return false; }
};

describe("sidecar sandbox service", () => {
  it("refuses to start without a token unless anonymous access is explicit", async () => {
    await expect(startSandboxService({ driver: "process", jobsDir: tempDir("nianyun-sandbox-"), token: "", allowAnon: false, port: 0 } as never))
      .rejects.toThrow(/SANDBOX_TOKEN/);
  });

  it("reports its isolation level and limits on /health", async () => {
    const service = await startProcessService();
    const response = await fetch(`http://127.0.0.1:${service.config.port}/health`);
    const body = await response.json() as Record<string, unknown>;
    expect(response.ok).toBe(true);
    expect(body.driver).toBe("process");
    // 进程级驱动必须自称 process-jail，不能冒充容器隔离。
    expect(body.isolation).toBe("process-jail");
    expect(body.limits).toMatchObject({ timeout_s: [5, 300] });
    expect(body.concurrency).toMatchObject({ max: 2, queue: 1 });
    expect(Array.isArray(body.mounts)).toBe(true);
  });

  it("requires the bearer token on /sandbox/exec", async () => {
    const service = await startProcessService();
    const base = `http://127.0.0.1:${service.config.port}`;
    const anonymous = await fetch(`${base}/sandbox/exec`, { method: "POST", body: JSON.stringify({ lang: "python", code: "print(1)" }) });
    expect(anonymous.status).toBe(401);
    const wrong = await fetch(`${base}/sandbox/exec`, {
      method: "POST", headers: { authorization: "Bearer nope" }, body: JSON.stringify({ lang: "python", code: "print(1)" }),
    });
    expect(wrong.status).toBe(401);
    const valid = await fetch(`${base}/sandbox/exec`, {
      method: "POST", headers: { authorization: "Bearer test-token" }, body: JSON.stringify({ lang: "bash", code: "printf ok" }),
    });
    expect([200, 500]).toContain(valid.status);
  });

  it("validates requests before spending a job", async () => {
    const service = await startProcessService();
    const base = `http://127.0.0.1:${service.config.port}`;
    const post = (body: unknown) => fetch(`${base}/sandbox/exec`, {
      method: "POST", headers: { authorization: "Bearer test-token", "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await post({ lang: "ruby", code: "x" })).status).toBe(400);
    expect((await post({ lang: "python", code: "" })).status).toBe(400);
    expect((await post({ lang: "python", code: "x", timeout_s: 9999 })).status).toBe(200);
    expect((await post({ lang: "python", code: "x", requirements: ["bad name!"] })).status).toBe(400);
    expect((await post({ lang: "python", code: "x".repeat(200_001) })).status).toBe(400);
  }, 60_000);

  it("claims a timeout instead of hanging the caller", async () => {
    const service = await startProcessService();
    const result = await execInSandboxService({ url: `http://127.0.0.1:${service.config.port}`, token: "test-token", timeoutS: 5 }, {
      lang: "python", code: "import time; time.sleep(30)", timeout_s: 5,
    });
    expect(result.timed_out).toBe(true);
    expect(result.ok).toBe(false);
    expect(result.duration_ms).toBeLessThan(20_000);
  }, 60_000);

  it("maps transport failures to a typed error", async () => {
    await expect(execInSandboxService({ url: "http://127.0.0.1:1", token: "x", timeoutS: 5 }, { lang: "bash", code: "echo hi" }))
      .rejects.toBeInstanceOf(SandboxServiceError);
  });
});

describe("sandbox egress proxy", () => {
  it("chains CONNECT to the upstream MITM and records the target", async () => {
    const upstream = await fakeUpstreamProxy();
    proxies.push(upstream);
    const proxy = await startChainedProxy({ upstream: `http://127.0.0.1:${upstream.port}`, host: "127.0.0.1", port: 0 });
    proxies.push(proxy);
    const received = await new Promise<string>((resolvePromise, rejectPromise) => {
      const socket = netConnect({ host: "127.0.0.1", port: proxy.port });
      socket.setTimeout(5_000, () => rejectPromise(new Error("proxy timeout")));
      let buffer = "";
      socket.on("data", (chunk) => {
        buffer += chunk.toString("latin1");
        if (buffer.includes("upstream-ok")) { socket.end(); resolvePromise(buffer); }
      });
      socket.on("error", rejectPromise);
      socket.write("CONNECT bdev.oppo.com:443 HTTP/1.1\r\nHost: bdev.oppo.com:443\r\n\r\n");
    });
    expect(received).toContain("200 Connection Established");
    expect(upstream.seen.some(line => line.startsWith("CONNECT bdev.oppo.com:443"))).toBe(true);
    expect(proxy.entries.at(-1)).toMatchObject({ kind: "connect", target: "bdev.oppo.com:443", allowed: true });
  });

  it("blocks cloud metadata and loopback by default", async () => {
    const upstream = await fakeUpstreamProxy();
    proxies.push(upstream);
    const proxy = await startChainedProxy({ upstream: `http://127.0.0.1:${upstream.port}`, host: "127.0.0.1", port: 0 });
    proxies.push(proxy);
    const response = await new Promise<string>((resolvePromise, rejectPromise) => {
      const socket = netConnect({ host: "127.0.0.1", port: proxy.port });
      socket.setTimeout(5_000, () => rejectPromise(new Error("proxy timeout")));
      let buffer = "";
      socket.on("data", (chunk) => { buffer += chunk.toString("latin1"); });
      socket.on("end", () => resolvePromise(buffer));
      socket.on("error", rejectPromise);
      socket.write("CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n");
    });
    expect(response).toContain("403");
    expect(upstream.seen).toHaveLength(0);
    expect(proxy.entries.at(-1)).toMatchObject({ allowed: false });
  });
});

describe("sandbox service config", () => {
  it("defaults to the docker driver and forces job egress through the upstream proxy", () => {
    const cfg = sandboxServiceConfig({ SANDBOX_TOKEN: "t", BURP_PROXY_URL: "http://host.docker.internal:8080" } as NodeJS.ProcessEnv);
    expect(cfg.driver).toBe("docker");
    expect(cfg.runtime).toBeUndefined();
    expect(cfg.proxyUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(cfg.upstreamProxy).toBe("http://host.docker.internal:8080");
    // 输入上限来自配置，不是硬编码在调用点上。
    expect(cfg.timeoutMaxS).toBe(300);
    expect(cfg.memoryMaxMb).toBe(4096);
    // 默认不挂任何东西；只读资料卷要显式声明。
    expect(cfg.mounts).toEqual([]);
  });

  it("accepts read-only mount specs for wordlists and templates", () => {
    const cfg = sandboxServiceConfig({
      SANDBOX_TOKEN: "t",
      SANDBOX_MOUNTS: "nianyun-sandbox-templates:/opt/nianyun/data/nuclei-templates:ro, /opt/dicts:/opt/dicts:ro",
    } as NodeJS.ProcessEnv);
    expect(cfg.mounts).toEqual([
      "nianyun-sandbox-templates:/opt/nianyun/data/nuclei-templates:ro",
      "/opt/dicts:/opt/dicts:ro",
    ]);
  });

  it("switches to microvm isolation when gVisor is selected", () => {
    const cfg = sandboxServiceConfig({ SANDBOX_TOKEN: "t", SANDBOX_RUNTIME: "runsc" } as NodeJS.ProcessEnv);
    expect(cfg.runtime).toBe("runsc");
  });
});

// 只在真有 bash 的机器上跑的端到端用例（容器内 CI 会跑；Windows 开发机跳过）。
const hasBash = process.platform !== "win32" && hasRuntime("bash");
describe.skipIf(!hasBash)("sandbox end to end", () => {
  it("runs code in a throwaway directory and returns stdout", async () => {
    const service = await startProcessService();
    const result = await execInSandboxService({ url: `http://127.0.0.1:${service.config.port}`, token: "test-token" }, {
      lang: "bash", code: "echo sandbox-ok; ls -a | head -3",
    });
    expect(result.ok).toBe(true);
    expect(result.stdout).toContain("sandbox-ok");
    expect(result.isolation).toBe("process-jail");
    expect(result.egress).toContain("proxy:");
  });
});
it("bootstraps requirements and MITM-TLS handling inside the service job", async () => {
  const { requirementsPrelude, tlsPrelude } = await import("../src/sandbox/driver.js");
  // sidecar 路径曾经把 requirements 静默丢掉（只有本地 jail 装过包）。
  expect(requirementsPrelude([])).toBe("");
  const deps = requirementsPrelude(["requests", "beautifulsoup4"]);
  expect(deps).toContain("pip', 'install'");
  expect(deps).toContain("--target");
  expect(deps).toContain('"requests"');
  expect(deps).toContain("SANDBOX_TLS_INSECURE");
  // MITM 兜底默认关闭：只有显式打开才降级 requests 的 verify。
  expect(tlsPrelude(false)).toBe("");
  const tls = tlsPrelude(true);
  expect(tls).toContain("setdefault('verify', False)");
  expect(tls).toContain("disable_warnings");
});
it("keeps /state across two calls and enforces the quota", async () => {
  const { normalizeStateKey } = await import("../src/sandbox/driver.js");
  const { measureState, clearState, stateFilePath, sweepState } = await import("../src/sandbox/state.js");
  expect(normalizeStateKey("p_06db586d65-s_9f2")).toBe("p_06db586d65-s_9f2");
  expect(normalizeStateKey("../../etc/passwd")).toBeUndefined();
  expect(normalizeStateKey("a b/c")).toBe("a-b-c");

  const root = mkdtempSync(join(tmpdir(), "sandbox-state-"));
  try {
    const cfg = { stateRoot: root, stateMaxMb: 1, stateMaxFiles: 3, stateTtlH: 12 };
    const key = "proj-sess";
    // 第一次调用写入，第二次调用读到（跨调用不是靠容器，而是靠这个目录）。
    const dir = join(root, key);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "token.json"), JSON.stringify({ token: "abc" }));
    const first = measureState(cfg, key);
    expect(first.files).toBe(1);
    expect(first.bytes).toBeGreaterThan(0);
    expect(JSON.parse(readFileSync(stateFilePath(cfg, key, "token.json"), "utf8")).token).toBe("abc");
    // 越界路径必须被挡住（agent 写 ../ 也读不到外面）。
    expect(() => stateFilePath(cfg, key, "../escape.txt")).toThrow(/escapes/);

    // 配额：文件数超了按最旧裁，体积也一起守住。
    for (const name of ["a.txt", "b.txt", "c.txt", "d.txt"]) writeFileSync(join(dir, name), "x".repeat(10));
    const pruned = measureState(cfg, key);
    expect(pruned.files).toBeLessThanOrEqual(3);
    expect(pruned.pruned).toBeGreaterThan(0);

    // TTL 清理：目录 mtime 超过窗口就整体摘掉。
    expect(sweepState({ ...cfg, stateTtlH: 1 }, Date.now() + 3 * 3600_000)).toBeGreaterThan(0);
    expect(existsSync(dir)).toBe(false);

    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "again.txt"), "y");
    expect(clearState(cfg, key).removed).toBe(true);
    expect(existsSync(dir)).toBe(false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
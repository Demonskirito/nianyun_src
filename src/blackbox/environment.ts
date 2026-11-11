import { createConnection } from "node:net";
import { existsSync } from "node:fs";
import { sandboxServiceHealth } from "../sandbox/client.js";
import { resolveAgentProxy } from "./agent-proxy.js";
// 只取类型：target-probe 反过来要用这里的 proxyEndpoint，值级别的循环导入不值得为一条
// 类型声明引入。
import type { TargetProbe } from "./target-probe.js";

export type BlackboxEnvironment = {
  checked_at: number;
  ready: boolean;
  burp: {
    configured: boolean;
    reachable: boolean;
    required: boolean;
    proxy_url: string;
    error?: string;
    bridge_configured?: boolean;
    bridge_url?: string;
    bridge_reachable?: boolean;
    bridge_error?: string;
  };
  tools: Array<{ id: string; label: string; configured: boolean; value?: string }>;
  /**
   * 目标本身能不能连上（同一条出网代理、同样的 TLS 开关打一次 GET）。
   * 工具链齐全但目标已下线时 `ready` 同样为 false——见 target-probe.ts。
   * 老会话/未探测时为 undefined，前端与 CLI 都要按"没这项信息"处理。
   */
  target?: TargetProbe;
  /** 交互式执行开关（--os-cmd / --sql-query / --file-read / --file-write）：开一次，整场会话有效。 */
  interactive_exec?: boolean;
  /**
   * 模型调用的出口（2026-11-07 与 burp 分列）。Burp 不可达只影响攻击流量，
   * 不再意味着 LLM 会一起挂；这条让 Desk / CLI 能一眼看出模型走的是哪条通道。
   */
  agent_egress?: {
    source: string;
    /** 脱敏的 host:port，直连时为 "direct"。 */
    proxy_url: string;
    /** 恒为 false：契约上不允许再回落到 BURP_PROXY_URL。 */
    burp_coupled: boolean;
  };
  /** Sidecar 沙箱服务状态：只做可见性报告，缺它不会拦住整场 run（exec.* 会降级并如实标注）。 */
  sandbox?: {
    configured: boolean;
    url?: string;
    reachable: boolean;
    isolation?: string;
    driver?: string;
    egress?: string;
    error?: string;
  };
};

function boolValue(value: string | undefined, fallback: boolean): boolean {
  if (value == null || !String(value).trim()) return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).trim().toLowerCase());
}

async function checkBridge(url: string, token: string, timeoutMs = 2500): Promise<void> {
  const base = new URL(url);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error("Burp Bridge URL must be a credential-free HTTP(S) base URL");
  }
  if (base.pathname !== "/" && base.pathname !== "") throw new Error("Burp Bridge URL must not contain a path");
  const response = await fetch(`${base.origin}/health`, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`Burp Bridge returned HTTP ${response.status}`);
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || body.ok !== true) throw new Error("Burp Bridge returned an invalid health response");
}

export function proxyEndpoint(raw: string): { host: string; port: number; url: string } {
  const value = String(raw || "").trim();
  if (!value) throw new Error("Burp proxy is not configured");
  const normalized = value.includes("://") ? value : `http://${value}`;
  const url = new URL(normalized);
  if (!url.hostname) throw new Error("Burp proxy host is required");
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Burp proxy must use http or https");
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Burp proxy port is invalid");
  return { host: url.hostname, port, url: `${url.protocol}//${url.hostname}:${port}` };
}

export function checkTcp(host: string, port: number, timeoutMs = 2500, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host, port });
    const finish = (error?: Error) => {
      signal?.removeEventListener("abort", abort);
      socket.removeAllListeners();
      socket.destroy();
      if (error) reject(error); else resolve();
    };
    const abort = () => finish(new Error("connection cancelled"));
    signal?.addEventListener("abort", abort, { once: true });
    socket.setTimeout(timeoutMs, () => finish(new Error("connection timed out")));
    socket.once("connect", () => finish());
    socket.once("error", (error) => finish(error));
  });
}

export async function checkBlackboxEnvironment(values: Record<string, string>): Promise<BlackboxEnvironment> {
  const rawProxy = String(values.BURP_PROXY_URL || "").trim();
  const required = boolValue(values.BURP_PROXY_REQUIRED, true);
  const bridgeUrl = String(values.BURP_BRIDGE_URL || "http://host.docker.internal:8765").trim();
  const bridgeToken = String(values.BURP_BRIDGE_TOKEN || "").trim();
  const bridgeConfigured = Boolean(bridgeToken);
  let bridgeReachable = false;
  let bridgeError: string | undefined;
  if (bridgeConfigured) {
    try {
      await checkBridge(bridgeUrl, bridgeToken);
      bridgeReachable = true;
    } catch (cause) {
      bridgeError = cause instanceof Error ? cause.message : String(cause);
    }
  } else {
    bridgeError = "Burp Bridge token is not configured";
  }
  let proxyUrl = rawProxy;
  let reachable = false;
  let error: string | undefined;
  if (!rawProxy) {
    error = "Burp proxy is not configured";
  } else {
    try {
      const endpoint = proxyEndpoint(rawProxy);
      proxyUrl = endpoint.url;
      await checkTcp(endpoint.host, endpoint.port);
      reachable = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }
  const bundled: Record<string, string> = {
    KATANA_PATH: "/usr/local/bin/katana", HTTPX_PATH: "/usr/local/bin/httpx", NUCLEI_PATH: "/usr/local/bin/nuclei",
    SUBFINDER_PATH: "/usr/local/bin/subfinder", DNSX_PATH: "/usr/local/bin/dnsx", NAABU_PATH: "/usr/local/bin/naabu",
    GAU_PATH: "/usr/local/bin/gau", FFUF_PATH: "/usr/local/bin/ffuf",
    INTERACTSH_CLIENT_PATH: "/usr/local/bin/interactsh-client",
    ARJUN_PATH: "/usr/local/bin/arjun", SUBJS_PATH: "/usr/local/bin/subjs", TESTSSL_PATH: "/usr/local/bin/testssl.sh",
    KITERUNNER_PATH: "/usr/local/bin/kiterunner", DALFOX_PATH: "/usr/local/bin/dalfox", SQLMAP_PATH: "/usr/local/bin/sqlmap",
    JWT_TOOL_PATH: "/usr/local/bin/jwt_tool", GRAPHQL_COP_PATH: "/usr/local/bin/graphql-cop", WPSCAN_PATH: "/usr/local/bin/wpscan",
    TRUFFLEHOG_PATH: "/usr/local/bin/trufflehog", SEMGREP_PATH: "/usr/local/bin/semgrep",
  };
  const specs = [
    ["browser", "Playwright", "PLAYWRIGHT_BROWSER_PATH"], ["katana", "Katana", "KATANA_PATH"],
    ["httpx", "httpx", "HTTPX_PATH"], ["nuclei", "Nuclei", "NUCLEI_PATH"],
    ["subfinder", "subfinder", "SUBFINDER_PATH"], ["dnsx", "dnsx", "DNSX_PATH"],
    ["naabu", "naabu", "NAABU_PATH"], ["gau", "gau", "GAU_PATH"], ["ffuf", "ffuf", "FFUF_PATH"],
    ["interactsh", "Interactsh 客户端", "INTERACTSH_CLIENT_PATH"],
    ["arjun", "Arjun 参数发现", "ARJUN_PATH"], ["subjs", "subjs JavaScript 分析", "SUBJS_PATH"],
    ["testssl", "testssl.sh TLS 检查", "TESTSSL_PATH"], ["kiterunner", "Kiterunner API 路由", "KITERUNNER_PATH"],
    ["dalfox", "Dalfox XSS 检查", "DALFOX_PATH"], ["sqlmap", "sqlmap 注入检查", "SQLMAP_PATH"],
    ["jwt-tool", "jwt-tool JWT 分析", "JWT_TOOL_PATH"], ["graphql-cop", "graphql-cop GraphQL 检查", "GRAPHQL_COP_PATH"],
    ["wpscan", "WPScan CMS 检查", "WPSCAN_PATH"], ["trufflehog", "TruffleHog 凭据线索", "TRUFFLEHOG_PATH"],
    ["semgrep", "Semgrep 源码分析", "SEMGREP_PATH"],
  ] as const;
  const tools = specs.map(([id, label, key]) => {
    const configured = String(values[key] || process.env[key] || "").trim();
    const value = configured || (bundled[key] && existsSync(bundled[key]) ? bundled[key] : "");
    const interactshReady = id === "interactsh" && Boolean(String(values.INTERACTSH_URL || process.env.INTERACTSH_URL || "").trim());
    return { id, label, configured: id === "browser" || (Boolean(value) && (id !== "interactsh" || interactshReady)), ...(value ? { value } : {}) };
  });
  const agentBase = String(values.BLACKBOX_AGENT_BASE_URL || values.ANTHROPIC_BASE_URL || values.NIANYUN_LOOP_BASE_URL || "").trim();
  const agentProxy = resolveAgentProxy(values, agentBase);
  return {
    checked_at: Date.now() / 1000,
    ready: required ? reachable : true,
    interactive_exec: boolValue(values.BLACKBOX_ALLOW_INTERACTIVE_EXEC, false),
    agent_egress: { source: agentProxy.source, proxy_url: agentProxy.host || "direct", burp_coupled: false },
    sandbox: await checkSandbox(values),
    burp: {
      configured: Boolean(rawProxy), reachable, required, proxy_url: proxyUrl,
      ...(error ? { error } : {}), bridge_configured: bridgeConfigured, bridge_url: bridgeUrl,
      bridge_reachable: bridgeReachable, ...(bridgeError ? { bridge_error: bridgeError } : {}),
    },
    tools,
  };
}

/** 沙箱服务健康：可达就报 isolation/egress，不可达就报原因；从不改 ready。 */
async function checkSandbox(values: Record<string, string>): Promise<NonNullable<BlackboxEnvironment["sandbox"]>> {
  const url = String(values.SANDBOX_URL || process.env.SANDBOX_URL || "").trim();
  if (!url) return { configured: false, reachable: false, error: "sidecar sandbox service is not configured (SANDBOX_URL)" };
  const token = String(values.SANDBOX_TOKEN || process.env.SANDBOX_TOKEN || "").trim();
  try {
    const health = await sandboxServiceHealth(url, token);
    return {
      configured: true,
      url,
      reachable: true,
      isolation: String(health.isolation || "unknown"),
      driver: String(health.driver || "unknown"),
      egress: String(health.egress_proxy || "unknown"),
    };
  } catch (cause) {
    return { configured: true, url, reachable: false, error: cause instanceof Error ? cause.message : String(cause) };
  }
}
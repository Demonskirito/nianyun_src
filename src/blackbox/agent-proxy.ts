/**
 * LLM 出口代理解析（2026-11-07）。
 *
 * 事故背景：旧实现 `BLACKBOX_AGENT_PROXY_URL || BURP_PROXY_URL` 把「模型调用」硬绑到
 * 「攻击流量抓包端口」。宿主 Burp 一关，主 Agent 与 Observer 同时 ECONNREFUSED，整场停摆；
 * 当时只能靠在容器 overlay 里手塞一行运行期配置顶着。
 *
 * 这里把两条通道彻底分开：
 *   - BURP_PROXY_URL 只管攻击流量（tools.ts / target-probe.ts / sandbox），**永不**作为 LLM 出口；
 *   - LLM 出口 = 显式 BLACKBOX_AGENT_PROXY_URL > 标准 env 代理（尊重 NO_PROXY） > 直连。
 *
 * 显式配置要能区分「没配」和「配成空串=强制直连」，所以用 hasOwnProperty，不能用 `||`。
 */

export type AgentProxySource = "explicit" | "environment" | "direct" | "no_proxy";

export type AgentProxyResolution = {
  url: string;
  source: AgentProxySource;
  /** 脱敏后的 host:port，只用于日志与环境报告；不含代理凭证。 */
  host: string;
};

function hostLabel(raw: string): string {
  try {
    const parsed = new URL(raw);
    return `${parsed.hostname.toLowerCase()}:${parsed.port || (parsed.protocol === "https:" ? 443 : 80)}`;
  } catch {
    return "";
  }
}

function ipv4ToInt(ip: string): number | undefined {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return undefined;
  const parts = ip.split(".").map(Number);
  if (parts.some(part => part > 255)) return undefined;
  return parts.reduce((acc, part) => (acc * 256 + part) >>> 0, 0);
}

/** NO_PROXY 匹配：精确 / 后缀 / 前导点 / 通配 / IPv4 CIDR（容器里配了 10.0.0.0/8 这类段）。 */
export function noProxyMatches(host: string, rules: string): boolean {
  const target = String(host || "").trim().toLowerCase().replace(/^\./, "");
  if (!target) return false;
  for (const entry of String(rules || "").split(",")) {
    let rule = entry.trim().toLowerCase();
    if (!rule) continue;
    if (rule === "*") return true;
    rule = rule.split(":")[0]!.replace(/^\./, "");
    if (rule.includes("/")) {
      const [network, bitsRaw] = rule.split("/");
      const bits = Number(bitsRaw);
      const hostInt = ipv4ToInt(target);
      const netInt = ipv4ToInt(String(network || ""));
      if (hostInt === undefined || netInt === undefined || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      if ((hostInt & mask) === (netInt & mask)) return true;
      continue;
    }
    if (target === rule || target.endsWith(`.${rule}`)) return true;
  }
  return false;
}

/**
 * values 来自 tools.env.yaml + Desk overlay（不含 process.env），env 单独传以便测试。
 * baseUrl 用模型服务地址判 NO_PROXY；拿不到 host 时保守不 bypass。
 */
export function resolveAgentProxy(
  values: Record<string, string>,
  baseUrl: string,
  env: NodeJS.ProcessEnv = process.env,
): AgentProxyResolution {
  let targetHost = "";
  try { targetHost = new URL(String(baseUrl || "")).hostname.toLowerCase(); } catch { /* 空 baseUrl 不判 bypass */ }
  const noProxy = String(values.BLACKBOX_AGENT_NO_PROXY || values.NO_PROXY || env.NO_PROXY || env.no_proxy || "").trim();

  // ① 显式配置（含空串=强制直连）优先级最高，且不受 NO_PROXY 影响：配了就是意图。
  if (Object.prototype.hasOwnProperty.call(values, "BLACKBOX_AGENT_PROXY_URL") && values.BLACKBOX_AGENT_PROXY_URL !== undefined) {
    const explicit = String(values.BLACKBOX_AGENT_PROXY_URL || "").trim();
    return explicit
      ? { url: explicit, source: "explicit", host: hostLabel(explicit) }
      : { url: "", source: "direct", host: "" };
  }

  // ② 内网 / 白名单模型服务不走代理，否则 env 代理会把本地 LLM 打挂。
  if (targetHost && noProxyMatches(targetHost, noProxy)) {
    return { url: "", source: "no_proxy", host: "" };
  }

  // ③ 标准 env 代理。这里**刻意不读 BURP_PROXY_URL**。
  const envProxy = String(values.HTTPS_PROXY || env.HTTPS_PROXY || env.https_proxy
    || values.HTTP_PROXY || env.HTTP_PROXY || env.http_proxy || "").trim();
  if (envProxy) return { url: envProxy, source: "environment", host: hostLabel(envProxy) };
  return { url: "", source: "direct", host: "" };
}

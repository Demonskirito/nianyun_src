/**
 * 工具请求的「身份」记账（2026-11-07）。
 *
 * 起因是一处实锤 bug：`httpTool` 在 `tools.ts` 里把 `input` **原地清空并 delete anonymous**，
 * 而 `progress.recordHostBlock()` 事后又去读 `request.input.anonymous`（同一个对象引用）。
 * 于是「匿名基线撞墙不计入整机拉黑」这道闸从上线起就没生效过：对照会话
 * 1dd9ded9ed239711 里 8 发 anonymous:true 的 403 全部被记成 blocked_hosts，
 * hits 从 3 一路涨到 11，waf_escalation / lateral_escape 都建在错误前提上。
 *
 * 修法不是「补一个标记」，而是把身份判定前移到工具分发之前做快照，并让结果自己携带
 * 身份：下游只看 `result.data.credential_mode`，不再依赖被改写的 input。
 */
import { createHash } from "node:crypto";

export type CredentialMode = "seeded" | "anonymous" | "explicit" | "none" | "unknown";
export type CredentialSource = "jar" | "explicit" | "anonymous_optout" | "no_credentials" | "not_applicable";

export type CredentialSnapshot = {
  mode: CredentialMode;
  source: CredentialSource;
  /** 是否为「刻意不带我方凭证」的基线请求。撞墙判定的唯一依据。 */
  anonymous: boolean;
};

/** 三种等价的匿名写法，与 `httpTool` 保持一致；不能再只认 `anonymous === true`。 */
export function anonymousOptOut(input: Record<string, unknown> | undefined): boolean {
  if (!input || typeof input !== "object") return false;
  return input.anonymous === true || input.no_auth === true || input.use_jar === false;
}

/** 顶层 token / cookie 字段或显式头：模型自己指定的凭证，不属于项目罐。 */
export function hasExplicitCredentials(input: Record<string, unknown> | undefined): boolean {
  if (!input || typeof input !== "object") return false;
  const explicitTop = ["token", "jwt", "access_token", "bearer", "cookie", "cookies", "authorization"];
  if (explicitTop.some(key => {
    const value = input[key];
    return typeof value === "string" ? value.trim().length > 0 : Boolean(value);
  })) return true;
  const headers = input.headers;
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return false;
  return Object.keys(headers as Record<string, unknown>).some(key =>
    ["cookie", "authorization", "x-api-key", "x-auth-token"].includes(key.toLowerCase()));
}

/** 会真实向目标发请求的工具。纯本地/只读工具没有「带不带凭证」这个问题。 */
const REQUEST_TOOLS = new Set([
  "http.request", "burp.request", "http.diff",
  "browser.open", "browser.screenshot", "browser.network", "browser.tab", "browser.storage",
  "exec.python", "exec.bash",
  "recon.race_condition", "recon.js_endpoints", "recon.interactsh",
  "recon.content_discovery", "recon.api_routes", "recon.nuclei", "recon.xss", "recon.sql",
  "recon.ports", "recon.secrets", "katana.crawl", "burp.check",
]);

/**
 * 在工具执行**之前**判定身份。必须传一份 input 的浅拷贝/快照，因为 httpTool 会改写它。
 */
export function snapshotCredential(
  tool: string,
  input: Record<string, unknown> | undefined,
  jarHasCookies: boolean,
): CredentialSnapshot {
  if (!REQUEST_TOOLS.has(tool)) {
    return { mode: "none", source: "not_applicable", anonymous: false };
  }
  /**
   * browser.* 的 context 是跨调用持久的（登录态、localStorage、已注入的种子都在里面）。
   * 对这种请求标 `anonymous` 会说谎：即使本次不注入新 cookie，上一轮留下的凭证照发。
   * 想做真正的匿名浏览器对照必须新建独立 context，在那之前一律按带凭证记账。
   */
  const persistentBrowser = /^browser\./.test(tool);
  if (anonymousOptOut(input) && !persistentBrowser) {
    return { mode: "anonymous", source: "anonymous_optout", anonymous: true };
  }
  if (hasExplicitCredentials(input)) {
    return { mode: "explicit", source: "explicit", anonymous: false };
  }
  if (jarHasCookies) {
    return { mode: "seeded", source: "jar", anonymous: false };
  }
  // 沙箱脚本自己发请求，控制面不注入任何凭证；它既不是匿名对照也不是带凭证会话。
  if (tool === "exec.python" || tool === "exec.bash") {
    return { mode: "unknown", source: "no_credentials", anonymous: false };
  }
  return { mode: "none", source: "no_credentials", anonymous: false };
}

/**
 * 撞墙判定用的统一匿名闸。优先信结果自带的身份快照；兼容旧证据/单测里
 * 直接构造 `request.input.anonymous` 的形态。
 */
export function isAnonymousWallRequest(
  request: { input?: Record<string, unknown> } | undefined,
  result?: { data?: Record<string, unknown> } | undefined,
): boolean {
  const mode = String(result?.data?.credential_mode || "");
  if (mode === "anonymous") return true;
  if (mode === "seeded" || mode === "explicit") return false;
  return anonymousOptOut(request?.input);
}

/**
 * 项目 Cookie 罐的稳定指纹。用于把 `seed_health` 结论绑定到「当时的罐」：
 * 罐一变（服务端 Set-Cookie 回写、browser.open 注入种子、自检剔除毒 cookie），
 * 旧结论就作废、需要重检。
 *
 * 只取 domain/name/value 并排序：expires / path / sameSite 这些字段在不同浏览器
 * 序列化里会抖动，但它们不决定「请求实际带什么」。value 必须算进去——
 * 毒 `cna` 与随机 `cna` 名字域名完全一样，差别只在值。
 */
export function cookieJarFingerprint(
  cookies: Array<{ name?: unknown; domain?: unknown; value?: unknown }> | undefined,
): string {
  const parts = (cookies || []).map(cookie =>
    `${String(cookie.domain || "")}|${String(cookie.name || "")}|${String(cookie.value || "")}`).sort();
  return createHash("sha256").update(parts.join("\n")).digest("hex").slice(0, 16);
}

/** 新增到 tool-result 的身份字段是元数据，不该参与「重复请求无新信息」的去重指纹。 */
export const CREDENTIAL_DATA_KEYS = ["credential_mode", "credential_source"] as const;

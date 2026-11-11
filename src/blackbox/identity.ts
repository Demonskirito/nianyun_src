/**
 * 身份接线（2026-10-31）。
 *
 * 图里一直有 `id:` 节点，但它只由 `endpoint.auth_required` 触发、role 恒为模型随手写的
 * `input.identity || "anon"` —— 换句话说，图不知道"我们此刻到底带没带登录态"。
 * 后果有两个：
 *   1. IDOR 假设永远写成"图里只有匿名身份"，即使 Cookie jar 里明明有登录态；
 *   2. 两身份对照（同一对象、身份 A vs 身份 B）没有任何账本可查。
 *
 * 这里把"身份"定义成可核对的事实：显式声明 > Cookie jar 里该 host 的会话类 Cookie > anon。
 * 只做判定，不发请求。
 */
import { cookiesForUrl, type CookieRecord } from "./cookies.js";

export type IdentitySource = "explicit" | "cookie" | "anon";

export type IdentityState = {
  /** 账本里的身份名：显式名 / "auth" / "anon"。 */
  role: string;
  source: IdentitySource;
  host: string;
  /** 支撑这条判定的 Cookie 名（不含值，值永远不进图/进 prompt）。 */
  cookie_names: string[];
};

/** 会话类 Cookie 的特征：名字里带这些词才认为"这是登录态"。 */
const AUTH_COOKIE = /(sess|sid|session|token|auth|ticket|login|passport|tgt|jwt|acct|member)/i;
/**
 * 设备/埋点类 Cookie：即便名字里带 `uid` 也不是登录态。
 * 2026-10-31：`GUID`（携程设备号）会命中 `uid`，把匿名会话误判成 auth ——
 * 一旦误判，IDOR 假设会直接跳到"换身份对照"，而实际根本没有身份。
 */
const DEVICE_COOKIE = /^(?:guid|uuid|_pd|_ga|_gid|_gat|deviceid|device_id|fingerprint|visitor|uqid|_fbp|_uetsid)$/i;

function isSessionCookie(name: string): boolean {
  return AUTH_COOKIE.test(name) && !DEVICE_COOKIE.test(name);
}

function hostOf(target: string): string {
  try {
    return new URL(target).hostname.toLowerCase();
  } catch {
    return String(target || "").toLowerCase().replace(/^[a-z]+:\/\//, "").split("/")[0] || "";
  }
}

/**
 * 解析"这次请求代表的身份"。
 *
 * - `explicit`：调用方明确给了身份（多角色演练时用），原样采用并截断到 40 字符；
 * - `cookie`：目标 host 在 Cookie jar 里有未过期的会话类 Cookie → `auth`；
 * - `anon`：其余情况。
 */
export function resolveIdentity(input: {
  explicit?: string;
  cookies?: CookieRecord[];
  target: string;
  now?: number;
}): IdentityState {
  const host = hostOf(input.target);
  const explicit = String(input.explicit ?? "").trim().slice(0, 40);
  const jar = input.cookies || [];
  const matched = host ? cookiesForUrl(jar, input.target, input.now) : [];
  const authish = matched.filter(cookie => isSessionCookie(cookie.name)).map(cookie => cookie.name).slice(0, 6);
  if (explicit) {
    // 显式身份：把该 host 的全部 Cookie 名列出来当上下文（不限会话类，便于对照）。
    return { role: explicit, source: "explicit", host, cookie_names: matched.map(cookie => cookie.name).slice(0, 6) };
  }
  if (authish.length) {
    return { role: "auth", source: "cookie", host, cookie_names: authish };
  }
  return { role: "anon", source: "anon", host, cookie_names: matched.map(cookie => cookie.name).slice(0, 6) };
}

/** 一行身份摘要（进 prompt / 进事件，最多 120 字符）。 */
export function identityDirective(identity: IdentityState): string {
  if (identity.role === "anon") {
    return `当前身份 anon（${identity.host || "?"} 无会话 Cookie）：IDOR/越权只能先做匿名对照，结论要写明"匿名可读≠越权"。`;
  }
  if (identity.role === "auth") {
    const names = identity.cookie_names.length ? `（Cookie: ${identity.cookie_names.join(",")}）` : "";
    return `当前身份 auth${names}：越权结论必须做**同对象双身份对照**（带登录态 vs 匿名/另一账号），单身份 200 不算证明。`;
  }
  return `当前身份 ${identity.role}${identity.cookie_names.length ? `（Cookie: ${identity.cookie_names.join(",")}）` : ""}：多角色演练时请为每次请求显式标注 input.identity。`;
}
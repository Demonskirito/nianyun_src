/**
 * Token 传递的"协议宽容层"。
 *
 * 现实：LLM 是概率模型，它一定会写出 `{"url": "...", "token": "eyJ..."}` 这种顶层字段。
 * 执行器如果静默丢弃，表现就是"模型以为带了凭证、服务端继续 10403"，认证链永远走不通，
 * 而错误信息里看不出任何线索。所以这里在 http.request / burp.request 入口统一做三件事：
 *
 *   1. 顶层 token / jwt / access_token / bearer / id_token / auth_token → headers.Authorization
 *      （JWT 形态自动补 `Bearer `，显式写了 `Bearer xxx` 就原样保留，其它裸串按原样发）
 *   2. 顶层 cookies 对象 / cookie 串 → 合并进 Cookie 头（不覆盖已有的）
 *   3. 消费掉的字段就删掉：既满足输入的严格校验，也避免 token 被写进证据账本
 *
 * 纯函数，方便单测；调用方负责把返回的 notes 写进 summary，让"自动转换发生过"这件事可见。
 */

const TOKEN_FIELDS = ["token", "jwt", "access_token", "accessToken", "id_token", "auth_token", "bearer"] as const;

export type AuthInputResult = {
  input: Record<string, unknown>;
  /** 人类可读的转换说明，例如 "token → Authorization: Bearer eyJ…"。 */
  notes: string[];
  /** 是否真的动过 input（调用方据此决定要不要提示模型）。 */
  changed: boolean;
};

const JWT_LIKE = /^ey[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\./;
const MASK = (value: string) => (value.length <= 12 ? "***" : `${value.slice(0, 6)}…${value.slice(-4)}`);

function headerKeyOf(headers: Record<string, unknown>, name: string): string | undefined {
  const lower = name.toLowerCase();
  return Object.keys(headers).find(key => key.toLowerCase() === lower);
}

function withScheme(raw: string): string {
  const value = raw.trim();
  if (/^bearer\s+/i.test(value)) return value.replace(/^bearer\s+/i, "Bearer ");
  if (/^(basic|digest|token|negotiate)\s+/i.test(value)) return value;
  if (JWT_LIKE.test(value)) return `Bearer ${value}`;
  return value;
}

export function normalizeAuthInput(source: Record<string, unknown>): AuthInputResult {
  const input: Record<string, unknown> = { ...source };
  const notes: string[] = [];
  let changed = false;
  const headers = { ...((input.headers && typeof input.headers === "object" && !Array.isArray(input.headers))
    ? input.headers as Record<string, unknown>
    : {}) };

  // ── 1. 顶层 token 字段 → Authorization ───────────────────────────────────
  let tokenValue = "";
  let tokenField = "";
  for (const field of TOKEN_FIELDS) {
    const raw = input[field];
    if (typeof raw === "string" && raw.trim()) { tokenValue = raw.trim(); tokenField = field; break; }
  }
  if (tokenValue) {
    const existing = headerKeyOf(headers, "authorization");
    if (existing && String(headers[existing] || "").trim()) {
      notes.push(`${tokenField} 被忽略：headers.${existing} 已存在（不覆盖显式头）`);
    } else {
      const value = withScheme(tokenValue);
      headers.Authorization = value;
      notes.push(`${tokenField} → Authorization: ${value.startsWith("Bearer ") ? "Bearer " : ""}${MASK(value.replace(/^(\w+)\s+/, ""))}`);
    }
    for (const field of TOKEN_FIELDS) delete input[field];
    changed = true;
  }

  // ── 2. 顶层 cookie / cookies → Cookie 头 ────────────────────────────────
  const cookieKeys = Object.keys(input).filter(key => ["cookies", "cookie_jar", "cookieJar"].includes(key));
  const extraCookies: string[] = [];
  for (const key of cookieKeys) {
    const raw = input[key];
    if (typeof raw === "string" && raw.trim()) extraCookies.push(raw.trim());
    else if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
        if (value === null || value === undefined) continue;
        extraCookies.push(`${name}=${String(value)}`);
      }
    } else if (Array.isArray(raw)) {
      for (const item of raw) {
        if (item && typeof item === "object") {
          const record = item as Record<string, unknown>;
          if (record.name) extraCookies.push(`${String(record.name)}=${String(record.value ?? "")}`);
        } else if (typeof item === "string" && item.includes("=")) extraCookies.push(item);
      }
    }
    delete input[key];
    changed = true;
  }
  const cookieHeaderKey = headerKeyOf(headers, "cookie");
  const explicitCookie = typeof input.cookie === "string" ? String(input.cookie).trim() : "";
  const headerCookie = cookieHeaderKey ? String(headers[cookieHeaderKey] || "").trim() : "";
  const merged = [explicitCookie, headerCookie, ...extraCookies].filter(Boolean).join("; ");
  if (merged) {
    const names = merged.split(";").map(part => part.split("=")[0]?.trim()).filter(Boolean);
    headers[cookieHeaderKey || "Cookie"] = merged;
    if (extraCookies.length) notes.push(`${cookieKeys.join("/")} → Cookie: ${names.slice(0, 6).join(", ")}`);
  }

  if (Object.keys(headers).length) input.headers = headers;
  return { input, notes, changed };
}

export type CapturedToken = { host: string; name: string; value: string; scheme: string; source: string };

/**
 * 从 `browser.open` 的 evaluate 结果里捞 Token，写进全局 Token 罐。
 * 依据：登录成功后页面几乎一定会把 token 放进 localStorage / sessionStorage / window 变量 /
 * cookie 字符串里，模型不需要"正确地"引用它——执行器先把罐子装满，后面发包自然就有凭证。
 */
export function captureTokens(evaluate: unknown, host: string, source = "browser.open"): CapturedToken[] {
  const target = String(host || "").trim().toLowerCase();
  if (!target) return [];
  const found = new Map<string, CapturedToken>();
  const KEYS = /^(token|access_?token|id_?token|auth_?token|jwt|bearer|authorization|msToken|sso_?token)$/i;

  const add = (raw: string, name: string): void => {
    const value = String(raw || "").trim().replace(/^["']|["']$/g, "");
    if (!value || value.length < 16) return;
    const bearer = /^bearer\s+(.+)$/i.exec(value);
    const core = bearer ? bearer[1]!.trim() : value;
    if (!JWT_LIKE.test(core) && !/^[A-Za-z0-9._~+/-]{24,}={0,2}$/.test(core)) return;
    const key = `${name}:${core.slice(0, 24)}`;
    if (found.has(key)) return;
    found.set(key, { host: target, name: name.toLowerCase() === "token" ? "bearer" : name.toLowerCase(), value: core, scheme: "Bearer", source });
  };

  const walk = (node: unknown, key: string, depth: number): void => {
    if (depth > 6) return;
    if (typeof node === "string") {
      // evaluate 常常返回 JSON 字符串（模型写 JSON.stringify(...)），先解析再走一遍
      const trimmed = node.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try { walk(JSON.parse(trimmed) as unknown, key, depth + 1); return; } catch { /* 不是合法 JSON，按普通字符串处理 */ }
      }
      if (KEYS.test(key) || JWT_LIKE.test(node)) add(node, KEYS.test(key) ? key : "observed");
      return;
    }
    if (Array.isArray(node)) { for (const item of node) walk(item, key, depth + 1); return; }
    if (node && typeof node === "object") {
      for (const [childKey, value] of Object.entries(node as Record<string, unknown>)) walk(value, childKey, depth + 1);
    }
  };

  walk(evaluate, "", 0);
  return [...found.values()].slice(0, 5);
}
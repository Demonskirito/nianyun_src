export type CookieRecord = {
  name: string;
  value: string;
  domain: string;
  path: string;
  hostOnly: boolean;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "strict" | "lax" | "none";
  /** Unix seconds; null/undefined means a session cookie. */
  expires?: number | null;
};

const MAX_COOKIES = 300;
const MAX_VALUE = 4096;
const MAX_NAME = 256;

function hostOf(url: string): { host: string; protocol: string; path: string } | null {
  try {
    const parsed = new URL(url);
    return { host: parsed.hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, ""), protocol: parsed.protocol, path: parsed.pathname || "/" };
  } catch {
    return null;
  }
}

function defaultPath(path: string): string {
  if (!path.startsWith("/")) return "/";
  const index = path.lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}

function domainMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  const prefix = cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`;
  return requestPath.startsWith(prefix);
}

function normalizeSameSite(value: string): CookieRecord["sameSite"] {
  const normalized = value.trim().toLowerCase();
  return normalized === "strict" || normalized === "lax" || normalized === "none" ? normalized : undefined;
}

export function parseSetCookie(header: string, requestUrl: string, now = Date.now() / 1000): CookieRecord | null {
  const context = hostOf(requestUrl);
  if (!context) return null;
  const parts = String(header || "").split(";");
  const first = parts.shift() || "";
  const index = first.indexOf("=");
  if (index <= 0) return null;
  const name = first.slice(0, index).trim();
  const value = first.slice(index + 1).trim();
  if (!name || name.length > MAX_NAME || value.length > MAX_VALUE) return null;

  let domain = context.host;
  let hostOnly = true;
  let path = "";
  let secure = false;
  let httpOnly = false;
  let sameSite: CookieRecord["sameSite"];
  let expires: number | null = null;
  let maxAge: number | null = null;

  for (const part of parts) {
    const eq = part.indexOf("=");
    const attr = (eq < 0 ? part : part.slice(0, eq)).trim().toLowerCase();
    const raw = eq < 0 ? "" : part.slice(eq + 1).trim();
    if (attr === "domain" && raw) {
      const candidate = raw.toLowerCase().replace(/^\./, "").replace(/\.$/, "");
      if (!candidate || !domainMatches(context.host, candidate)) return null;
      domain = candidate;
      hostOnly = false;
    } else if (attr === "path" && raw.startsWith("/")) {
      path = raw;
    } else if (attr === "secure") {
      secure = true;
    } else if (attr === "httponly") {
      httpOnly = true;
    } else if (attr === "samesite") {
      sameSite = normalizeSameSite(raw);
    } else if (attr === "max-age") {
      const seconds = Number.parseInt(raw, 10);
      if (Number.isFinite(seconds)) maxAge = seconds;
    } else if (attr === "expires") {
      const parsed = Date.parse(raw);
      if (Number.isFinite(parsed)) expires = parsed / 1000;
    }
  }
  if (maxAge !== null) expires = now + maxAge;
  return {
    name,
    value,
    domain,
    path: path || defaultPath(context.path),
    hostOnly,
    secure,
    httpOnly,
    ...(sameSite ? { sameSite } : {}),
    expires: expires === null ? null : Math.floor(expires),
  };
}

export function parseCookieHeader(header: string, requestUrl: string): CookieRecord[] {
  const context = hostOf(requestUrl);
  if (!context) return [];
  const out: CookieRecord[] = [];
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name || name.length > MAX_NAME || value.length > MAX_VALUE) continue;
    out.push({ name, value, domain: context.host, path: "/", hostOnly: true, secure: context.protocol === "https:", httpOnly: false, expires: null });
  }
  return out;
}

function key(cookie: CookieRecord): string {
  return `${cookie.domain}|${cookie.path}|${cookie.name}`;
}

export function mergeCookies(jar: CookieRecord[], additions: CookieRecord[], now = Date.now() / 1000): CookieRecord[] {
  const merged = new Map(jar.map((cookie) => [key(cookie), cookie]));
  for (const cookie of additions) {
    const identity = key(cookie);
    if (cookie.expires !== null && cookie.expires !== undefined && cookie.expires <= now) merged.delete(identity);
    else merged.set(identity, cookie);
  }
  return [...merged.values()]
    .filter((cookie) => cookie.expires == null || cookie.expires > now)
    .slice(-MAX_COOKIES);
}

export function cookiesForUrl(jar: CookieRecord[], target: string, now = Date.now() / 1000): CookieRecord[] {
  const context = hostOf(target);
  if (!context) return [];
  const secure = context.protocol === "https:";
  return jar.filter((cookie) =>
    (cookie.hostOnly ? context.host === cookie.domain : domainMatches(context.host, cookie.domain)) &&
    pathMatches(context.path, cookie.path) &&
    (!cookie.secure || secure) &&
    (cookie.expires == null || cookie.expires > now),
  );
}

export function cookieHeaderFor(jar: CookieRecord[], target: string, now = Date.now() / 1000): string {
  return cookiesForUrl(jar, target, now)
    .sort((a, b) => b.path.length - a.path.length || a.name.localeCompare(b.name))
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

export function cookieSummary(jar: CookieRecord[], now = Date.now() / 1000): Array<{ name: string; domain: string; path: string; expires: number | null }> {
  return jar
    .filter((cookie) => cookie.expires == null || cookie.expires > now)
    .map((cookie) => ({ name: cookie.name, domain: cookie.domain, path: cookie.path, expires: cookie.expires ?? null }))
    .slice(0, 50);
}

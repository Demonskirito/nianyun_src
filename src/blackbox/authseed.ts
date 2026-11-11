import fs from "node:fs";
import path from "node:path";

/**
 * 认证种子（auth seed）加载器。
 *
 * 设计目标：让人工用自己的账号在真实浏览器里登录一次，把登录态导出成一份
 * storageState 文件，黑盒会话启动时按主机名自动注入，agent 开局即已登录，
 * 永远不需要自己走登录流程（避免卡在验证码 / MFA / SSO 跳转）。
 *
 * 种子文件放在 data/auth/ 下（已被 .gitignore 忽略，不会进版本库），命名任意，
 * 但建议用主机名，例如 data/auth/wanxiaozhi.aliyun.com.storageState.json。
 * 格式即 Playwright 的 storageState：
 *   { "cookies": [ { name, value, domain, path, expires, httpOnly, secure, sameSite } ],
 *     "origins": [ { "origin": "https://host",
 *                    "localStorage": [ { name, value } ],
 *                    "sessionStorage": [ { name, value } ] } ] }
 */

export type SeedOrigin = {
  origin: string;
  localStorage?: Array<{ name: string; value: string }>;
  sessionStorage?: Array<{ name: string; value: string }>;
};

export type SeedFile = {
  path: string;
  cookies: Array<Record<string, unknown>>;
  origins: SeedOrigin[];
};

/** 归一化域名：去前导点（`.aliyun.com` → `aliyun.com`）、转小写、去尾点。 */
function normalizeDomain(domain: string): string {
  return (domain || "").toLowerCase().replace(/^\./, "").replace(/\.$/, "");
}

/** 主机名匹配：精确相等，或 host 是 domain 的子域（domain 可带前导点）。 */
export function hostMatches(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const d = normalizeDomain(domain);
  if (!d) return false;
  return h === d || h.endsWith(`.${d}`);
}

function listSeedFiles(rootDir?: string): string[] {
  const root = rootDir ? path.resolve(rootDir) : path.resolve(process.cwd(), "data", "auth");
  if (!fs.existsSync(root)) return [];
  const out: string[] = [];
  const walk = (dir: string): void => {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".storageState.json")) out.push(p);
    }
  };
  walk(root);
  // 排序保证「同分时谁胜」可复现；readdir 顺序随文件系统而变，不能作为优先级依据。
  return out.sort();
}

/**
 * 返回与给定主机匹配的种子文件。匹配规则：任一 cookie 的 domain 或任一 origin
 * 的主机名属于该主机（含子域 / 父域）。
 *
 * 多个种子同时命中时取**最具体**的那份（命中域最长者）。例如目标是
 * `ram.console.aliyun.com` 时，`console.aliyun.com` 的种子胜过 `.aliyun.com` 的种子。
 *
 * 早期实现是「取第一个命中」，于是泛域种子会无条件压住更精确的专用种子——
 * 这正是当年一份 `.aliyun.com` 的旧种子让新导的 whois 种子永不生效的原因。
 * 同一份种子内仍保留全部 cookie，由调用方按目标主机二次过滤。
 */
export function loadSeedsForHost(host: string, rootDir?: string): SeedFile | null {
  let best: { seed: SeedFile; score: number } | null = null;
  for (const file of listSeedFiles(rootDir)) {
    try {
      const data = JSON.parse(fs.readFileSync(file, "utf8"));
      const cookies: Array<Record<string, unknown>> = Array.isArray(data.cookies) ? data.cookies : [];
      const origins: SeedOrigin[] = Array.isArray(data.origins) ? data.origins : [];
      let score = -1;
      for (const c of cookies) {
        const domain = normalizeDomain(String(c.domain ?? ""));
        if (hostMatches(host, domain)) score = Math.max(score, domain.length);
      }
      for (const o of origins) {
        try {
          const originHost = normalizeDomain(new URL(o.origin).hostname);
          if (hostMatches(host, originHost)) score = Math.max(score, originHost.length);
        } catch {
          // 非法 origin 不参与匹配
        }
      }
      if (score < 0) continue;
      if (!best || score > best.score) best = { seed: { path: file, cookies, origins }, score };
    } catch {
      // 跳过不可读 / 格式损坏的种子
    }
  }
  return best ? best.seed : null;
}

// ── 种子管理（控制台上传 / 查看 / 删除）──────────────────────────────────────

function authDir(): string {
  return path.resolve(process.cwd(), "data", "auth");
}

/** 只允许主机名合法字符，杜绝路径穿越（/、..、空格等）。 */
function sanitizeHost(raw: string): string | null {
  const host = (raw || "").trim().toLowerCase();
  if (!host) return null;
  if (!/^[a-z0-9.\-:]+$/.test(host)) return null;
  return host;
}

function seedFileName(host: string): string {
  return `${host}.storageState.json`;
}

export type AuthSeedView = {
  host: string;
  file: string;
  cookies: number;
  origins: number;
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  updated_at: number;
};

export type SaveSeedResult = { ok: true; host: string; file: string } | { ok: false; error: string };
export type DeleteSeedResult = { ok: true; host: string } | { ok: false; error: string };

/** 列出 data/auth 下全部种子及其摘要。 */
export function listAuthSeeds(): AuthSeedView[] {
  const root = authDir();
  if (!fs.existsSync(root)) return [];
  const out: AuthSeedView[] = [];
  for (const name of fs.readdirSync(root)) {
    if (!name.endsWith(".storageState.json")) continue;
    const file = path.join(root, name);
    try {
      const data = JSON.parse(fs.readFileSync(file, "utf8"));
      const cookies: unknown[] = Array.isArray(data.cookies) ? data.cookies : [];
      const origins: Array<{ localStorage?: Array<{ name: string }>; sessionStorage?: Array<{ name: string }> }> =
        Array.isArray(data.origins) ? data.origins : [];
      const localStorageKeys = origins.flatMap((o) => (o.localStorage || []).map((x) => String(x.name)));
      const sessionStorageKeys = origins.flatMap((o) => (o.sessionStorage || []).map((x) => String(x.name)));
      const stat = fs.statSync(file);
      out.push({
        host: name.replace(/\.storageState\.json$/, ""),
        file: name,
        cookies: cookies.length,
        origins: origins.length,
        localStorageKeys,
        sessionStorageKeys,
        updated_at: Math.floor(stat.mtimeMs || 0),
      });
    } catch {
      // 跳过不可读 / 格式损坏的种子
    }
  }
  return out.sort((a, b) => a.host.localeCompare(b.host));
}

/** 保存一份种子（来自控制台粘贴的 storageState JSON）。 */
export function saveAuthSeed(rawHost: string, content: string): SaveSeedResult {
  const host = sanitizeHost(rawHost);
  if (!host) return { ok: false, error: "主机名非法：只能包含字母、数字、. - :，且不能为空" };
  if (!content || !content.trim()) return { ok: false, error: "种子内容为空" };
  let parsed: { cookies?: unknown; origins?: unknown };
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    return { ok: false, error: `不是合法 JSON：${e instanceof Error ? e.message : String(e)}` };
  }
  if (!Array.isArray(parsed.cookies)) {
    return { ok: false, error: "不是有效的 storageState：缺少 cookies 数组" };
  }
  const root = authDir();
  fs.mkdirSync(root, { recursive: true });
  const file = path.join(root, seedFileName(host));
  try {
    fs.writeFileSync(file, JSON.stringify(parsed, null, 2), "utf8");
  } catch (e) {
    return { ok: false, error: `写入失败：${e instanceof Error ? e.message : String(e)}` };
  }
  return { ok: true, host, file: seedFileName(host) };
}

/** 删除一份种子。 */
export function deleteAuthSeed(rawHost: string): DeleteSeedResult {
  const host = sanitizeHost(rawHost);
  if (!host) return { ok: false, error: "主机名非法" };
  const file = path.join(authDir(), seedFileName(host));
  if (!fs.existsSync(file)) return { ok: false, error: "种子不存在" };
  try {
    fs.unlinkSync(file);
  } catch (e) {
    return { ok: false, error: `删除失败：${e instanceof Error ? e.message : String(e)}` };
  }
  return { ok: true, host };
}

export type PruneSeedResult = {
  ok: boolean;
  file?: string;
  backup?: string;
  removed?: string[];
  remaining?: number;
  error?: string;
};

/**
 * 从命中该主机的种子里剔除指定 Cookie（种子自检判定"污染"后调用）。
 *
 * 为什么要动种子文件，而不是只清会话罐：种子每次 `browser.open` 都会被重新注入，
 * 只清罐等于下一轮又把污染项倒回来——2026-11-07 手工修完种子、
 * `http.request` 却仍然 403，就是因为项目罐里还留着那枚 `cna`。
 *
 * 安全措施：改前先写 `.bak-seedcheck-<时间戳>` 备份，写失败就原样留着并报错，
 * 绝不"部分写坏"。删除按 name 匹配（同名不同域的不同 cookie 会一起被删，
 * 这种情况在隔离阶段已经按 domain 打过标记，调用方传的应是精确集合）。
 */
export function pruneSeedCookies(rawHost: string, names: string[]): PruneSeedResult {
  const wanted = new Set((names || []).map(name => String(name || "").trim()).filter(Boolean));
  if (!wanted.size) return { ok: false, error: "没有要剔除的 Cookie" };
  const seed = loadSeedsForHost(rawHost);
  if (!seed) return { ok: false, error: `没有命中 ${rawHost} 的种子文件` };
  let parsed: { cookies?: Array<Record<string, unknown>>; origins?: unknown };
  try {
    parsed = JSON.parse(fs.readFileSync(seed.path, "utf8"));
  } catch (e) {
    return { ok: false, error: `种子文件不可读：${e instanceof Error ? e.message : String(e)}`, file: path.basename(seed.path) };
  }
  const cookies = Array.isArray(parsed.cookies) ? parsed.cookies : [];
  const removed = cookies.filter(cookie => wanted.has(String(cookie?.name || ""))).map(cookie => String(cookie.name));
  if (!removed.length) {
    return { ok: false, error: `种子里没有 ${[...wanted].join("/")}（可能已被清过）`, file: path.basename(seed.path) };
  }
  const kept = cookies.filter(cookie => !wanted.has(String(cookie?.name || "")));
  const backup = `${seed.path}.bak-seedcheck-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}`;
  try {
    fs.copyFileSync(seed.path, backup);
    fs.writeFileSync(seed.path, JSON.stringify({ ...parsed, cookies: kept }, null, 1), "utf8");
  } catch (e) {
    return { ok: false, error: `改写种子失败：${e instanceof Error ? e.message : String(e)}`, file: path.basename(seed.path), backup };
  }
  return { ok: true, file: path.basename(seed.path), backup: path.basename(backup), removed, remaining: kept.length };
}

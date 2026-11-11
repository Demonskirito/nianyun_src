/**
 * 鉴权墙（auth wall）识别与阻断。
 *
 * 真实场景：目标所有接口统一走鉴权网关，未带 Token 一律 `{"code":10403,...}` / 401。
 * 这时继续按 playbook 遍历 URL 是纯浪费——正确动作是停下来，去找登录接口 / Token / 未授权入口。
 *
 * 这里只做机械判断，不做任何模型推理：
 *   - 一次响应是不是"被鉴权拒绝"（状态码 + 业务码 + 短语）；
 *   - 同一主机上连续多少个**不同**入口被同样拒绝 → 判定为鉴权墙；
 *   - 判定之后，剩余同主机的无凭证请求直接拒绝执行，并把任务标 blocked 交 Observer。
 */

export type AuthWallState = {
  /** 触发鉴权墙的主机（host）。 */
  host: string;
  /** 连续被拒绝的请求数（会被一次正常响应清零）。 */
  streak: number;
  /** 不同的入口路径（去重后计数决定是否触发）。 */
  urls: string[];
  /** 最近一次命中的业务码/状态码。 */
  code?: string;
  tripped_at?: number;
  /** 触发时投递的 Observer 建议 id。 */
  advice_id?: string;
  /** 被自动置为 blocked 的任务 id。 */
  blocked_tasks?: string[];
  /** 墙生效期间被放行的请求数（安全路径 / 未授权打法 / 显式 bypass），用于观测墙是否名存实亡。 */
  bypasses?: number;
  /** 最近一次放行的原因。 */
  last_bypass?: { kind: "safe_path" | "unauth_playbook" | "explicit" | "intent"; url: string; at: number };
};

/**
 * 墙生效期间仍可放行的打法：这些打法的目的就是"在没有凭证的情况下找未授权入口"，
 * 被自己的墙挡住等于把正路堵死。
 */
const WALL_BYPASS_PLAYBOOKS = new Set(["unauth_exposure", "jwt_auth"]);

/**
 * 任务意图里出现这些词，说明它就是在做未授权 / 鉴权对照验证。
 *
 * 冲突 6（2026-11-02 审计）：放行通道只认 playbook 字段，而任务常常是自由文本
 * （"验证 /api/order 未授权访问"），没写 playbook 就被墙一律拦下——可提示词同时要求
 * "未授权验证必须匿名"。于是这类任务的合法路径只剩一条：模型什么都不做。
 */
const UNAUTH_INTENT = /未授权|未登录|免登|匿名|越权|鉴权|unauth|unauthorized|no[-_ ]?auth|authz|idor/i;

/** 放行判定的选项（缺省 = 严格执行最老的行为：只认登录路径与凭证）。 */
export type WallOptions = {
  /** 请求所属任务的 playbook id。 */
  playbook?: string;
  /** 请求所属任务的意图文本（purpose + completion_criteria）：没绑打法时用它认"未授权验证"。 */
  taskIntent?: string;
  /** 敏感路径字典（子串匹配），来自 rules.auth_wall.safe_paths。 */
  safePaths?: string[];
  /** 是否允许 unauth_exposure / jwt_auth 打法继续（rules.auth_wall.allow_unauth_playbook）。 */
  allowUnauthPlaybook?: boolean;
  /** 是否允许 input.bypass_auth_wall=true 主动声明（rules.auth_wall.allow_bypass）。 */
  allowBypass?: boolean;
};

export type WallBypassKind = "safe_path" | "unauth_playbook" | "explicit" | "intent";

export type WallVerdict = { blocked: boolean; bypass?: WallBypassKind };

export type DenialVerdict = { denied: boolean; code?: string; reason?: string };

const AUTH_PATH = /(^|\/)(login|signin|sign_in|oauth|authorize|token|sso|passport|logout)(\/|$|\?)/i;

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function codesOf(values: Record<string, string>): string[] {
  const raw = String(values.NIANYUN_AUTH_WALL_CODES || "").trim();
  const source = raw || "10403,10401,10402,401";
  return source.split(",").map(item => item.trim()).filter(Boolean);
}

function phrasesOf(values: Record<string, string>): string[] {
  const raw = String(values.NIANYUN_AUTH_WALL_PHRASES || "").trim();
  const source = raw || "未登录,请先登录,登录已过期,token失效,token已过期,invalid token,unauthorized,not logged in,no permission";
  return source.split(",").map(item => item.trim().toLowerCase()).filter(Boolean);
}

/**
 * 判定一次工具结果是不是"被鉴权拒绝"。
 *
 * 只看 401 与业务码/短语：403 常被 WAF 复用（目标对扫描器一律 403/412），把它算进来会误伤。
 */
export function denialOf(data: Record<string, unknown> | undefined, values: Record<string, string> = {}): DenialVerdict {
  if (!data) return { denied: false };
  const status = Number(data.status || data.status_code || 0);
  if (status === 401) return { denied: true, code: "401", reason: "HTTP 401" };
  const body = text(data.body) || text(data.body_text) || text(data.preview) || text(data.json ? JSON.stringify(data.json) : "");
  const haystack = body.slice(0, 4000);
  const numeric = haystack.match(/"?(?:code|errcode|error_code|errno|ret|retcode|error)"?\s*[:=]\s*"?(-?\d{3,6})/i);
  const numericCode = numeric?.[1];
  const codes = codesOf(values);
  if (numericCode && codes.includes(numericCode)) return { denied: true, code: numericCode, reason: `业务码 ${numericCode}` };
  const bare = haystack.match(/^\s*(?:10403|10401|10402)\s*$/);
  if (bare) return { denied: true, code: bare[0].trim(), reason: `业务码 ${bare[0].trim()}` };
  const lowered = haystack.toLowerCase();
  const phrase = phrasesOf(values).find(item => lowered.includes(item));
  if (phrase) return { denied: true, code: phrase, reason: `响应包含「${phrase}」` };
  if (status >= 200 && status < 300 && codes.some(code => lowered.includes(code))) return { denied: true, code: codes.find(code => lowered.includes(code)), reason: "响应包含鉴权业务码" };
  return { denied: false };
}

export function hostOf(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return "";
  }
}

/** 入口指纹：同路径不同参数算同一个入口，避免把 ?id=1..5 当成五个"不同"接口。 */
export function entryKey(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.host}${parsed.pathname}`;
  } catch {
    return url;
  }
}

/**
 * 记一次拒绝并判断是否触墙。
 * 正常响应会清零 streak（换了凭证能进就不再是墙）。
 */
export function trackDenial(
  state: { auth_wall?: AuthWallState },
  input: { url: string; denied: boolean; code?: string },
  limit: number,
): { state?: AuthWallState; tripped: boolean } {
  const host = hostOf(input.url);
  const current = state.auth_wall;
  if (!input.denied) {
    if (current && current.host === host) state.auth_wall = { ...current, streak: 0 };
    return { state: state.auth_wall, tripped: false };
  }
  if (!host) return { state: current, tripped: false };
  const key = entryKey(input.url);
  const sameHost = current && current.host === host;
  const urls = sameHost ? [...current.urls] : [];
  if (key && !urls.includes(key)) urls.push(key);
  const next: AuthWallState = {
    ...(sameHost ? current : { host, streak: 0, urls: [] }),
    host,
    streak: (sameHost ? current.streak : 0) + 1,
    urls: urls.slice(-40),
    code: input.code || (sameHost ? current.code : undefined),
  };
  state.auth_wall = next;
  const tripped = !next.tripped_at && next.urls.length >= Math.max(1, limit);
  if (tripped) state.auth_wall = { ...next, tripped_at: Date.now() };
  return { state: state.auth_wall, tripped };
}

/** 请求里是否带了凭证（带了就允许继续——这正是"搞到 Token 之后再试"）。 */
export function carriesAuth(input: Record<string, unknown> | undefined): boolean {
  if (!input) return false;
  if (typeof input.cookie === "string" && input.cookie.trim()) return true;
  if (typeof input.token === "string" && input.token.trim()) return true;
  if (typeof input.jwt === "string" && input.jwt.trim()) return true;
  const headers = input.headers;
  if (headers && typeof headers === "object" && !Array.isArray(headers)) {
    const keys = Object.keys(headers as Record<string, unknown>).map(key => key.toLowerCase());
    if (keys.some(key => ["authorization", "cookie", "x-token", "x-auth-token", "token"].includes(key))) return true;
  }
  return false;
}

/**
 * 这条请求是不是"同一个墙"下的无凭证遍历。
 *
 * 只拦已经证明被拒的路径前缀（例如 /api/ 下一片 10403），不拦别的目录：
 * /login、/sso、/actuator、/swagger 这类换 Token 或未授权入口必须放行，
 * 否则"找 Token / 找未授权入口"这条正路也被自己堵死了。
 *
 * 墙的本意是防"换个 id 继续复读"，不是禁止未授权验证。所以除了登录路径，还有三条放行通道：
 *   1. 敏感路径字典（.env/.git/swagger/actuator/druid/nacos/graphql…）；
 *   2. 任务绑定的是 unauth_exposure / jwt_auth 打法；
 *   3. 模型显式写 input.bypass_auth_wall=true（规则允许时）。
 */
/**
 * 这条请求是否命中放行通道（不看墙是否已经触发）。
 *
 * 独立于 wallVerdict 的原因是计数顺序：streak 在 trackDenial 里累加，而 wallVerdict
 * 只在 tripped 之后才被调用。于是"打 .env / /actuator/env / /swagger-ui.html 各一次 401"
 * 这三条本该放行的未授权探测会把 streak 推过阈值，让正在找未授权入口的任务被判 blocked_by_auth。
 */
export function bypassChannelOf(url: string, input: Record<string, unknown> | undefined, options: WallOptions = {}): WallBypassKind | undefined {
  if (AUTH_PATH.test(url)) return "safe_path";
  if (options.allowBypass !== false && input?.bypass_auth_wall === true) return "explicit";
  if (options.allowUnauthPlaybook !== false && options.playbook && WALL_BYPASS_PLAYBOOKS.has(options.playbook)) return "unauth_playbook";
  if (options.allowUnauthPlaybook !== false && !options.playbook && UNAUTH_INTENT.test(String(options.taskIntent || ""))) return "intent";
  const safePaths = options.safePaths || [];
  if (safePaths.length && safePaths.some(item => url.toLowerCase().includes(item.toLowerCase()))) return "safe_path";
  return undefined;
}

export function wallVerdict(state: { auth_wall?: AuthWallState }, url: string, input: Record<string, unknown> | undefined, options: WallOptions = {}): WallVerdict {
  const wall = state.auth_wall;
  if (!wall?.tripped_at) return { blocked: false };
  if (hostOf(url) !== wall.host) return { blocked: false };
  if (AUTH_PATH.test(url)) return { blocked: false };
  if (options.allowBypass !== false && input?.bypass_auth_wall === true) return { blocked: false, bypass: "explicit" };
  if (options.allowUnauthPlaybook !== false && options.playbook && WALL_BYPASS_PLAYBOOKS.has(options.playbook)) return { blocked: false, bypass: "unauth_playbook" };
  // 没绑打法但意图就是未授权验证：同样放行（见 UNAUTH_INTENT 注释）。
  if (options.allowUnauthPlaybook !== false && !options.playbook && UNAUTH_INTENT.test(String(options.taskIntent || ""))) return { blocked: false, bypass: "intent" };
  const safePaths = options.safePaths || [];
  if (safePaths.length && safePaths.some(item => url.toLowerCase().includes(item.toLowerCase()))) return { blocked: false, bypass: "safe_path" };
  const prefixes = deniedPrefixes(wall);
  const path = pathOf(entryKey(url));
  // 精确命中前缀（"/api/order"）或其下任意子路径（"/api/order/x"）。
  const hit = prefixes.some(prefix => path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/"));
  if (!hit) return { blocked: false };
  return { blocked: !carriesAuth(input) };
}

/** 兼容旧签名：只要布尔结论。 */
export function blockedByWall(state: { auth_wall?: AuthWallState }, url: string, input: Record<string, unknown> | undefined, options: WallOptions = {}): boolean {
  return wallVerdict(state, url, input, options).blocked;
}

/** 记录一次放行，便于在上下文/事件里解释"墙为什么没拦住它"。 */
export function recordWallBypass(state: { auth_wall?: AuthWallState }, url: string, kind: WallBypassKind): void {
  const wall = state.auth_wall;
  if (!wall?.tripped_at) return;
  state.auth_wall = { ...wall, bypasses: (wall.bypasses || 0) + 1, last_bypass: { kind, url, at: Date.now() } };
}

/** entryKey 形如 host/path，取出其中的 pathname。 */
function pathOf(key: string): string {
  // 兼容两种写法：entryKey（host/path）和历史 checkpoint 里可能存过的完整 URL。
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(key)) {
    try { return new URL(key).pathname; } catch { return "/"; }
  }
  const slash = key.indexOf("/");
  return slash >= 0 ? key.slice(slash) : "/";
}

/**
 * 已证明被拒路径的"目录前缀"：取两段，例如 host/api/order/list → /api/order/。
 * 只拦这两段，别把整台主机封死——/login、/actuator、/swagger 必须还能试。
 */
export function deniedPrefixes(wall: AuthWallState): string[] {
  const prefixes = new Set<string>();
  for (const entry of wall.urls) {
    const segments = pathOf(entry).split("/").filter(Boolean);
    if (!segments.length) continue;
    prefixes.add("/" + segments.slice(0, 2).join("/"));
    if (segments.length > 2) prefixes.add("/" + segments.slice(0, 2).join("/") + "/");
  }
  return [...prefixes];
}

export type CompletionCheck = { deniedOnly: boolean; evidence: number; denied: number };

/**
 * 判断"这条任务的证据是否全是被鉴权拒绝"。
 * 只看该任务自己的成功 tool-result；一条像样的响应（非拒绝）就让结论放行。
 */
export function completionDenial(
  evidence: Record<string, unknown>[],
  taskId: string,
  evidenceIds: string[],
  values: Record<string, string> = {},
): CompletionCheck {
  const ids = new Set(evidenceIds);
  const scoped = evidence.filter(item => {
    const data = (item.data || {}) as Record<string, unknown>;
    if (String(item.kind || "") !== "tool-result") return false;
    if (String(data.task_id || "") !== taskId) return false;
    return !ids.size || ids.has(String(item.id));
  });
  if (!scoped.length) return { deniedOnly: false, evidence: 0, denied: 0 };
  let denied = 0;
  for (const item of scoped) {
    const data = (item.data || {}) as Record<string, unknown>;
    if (denialOf(data, values).denied) denied += 1;
  }
  return { deniedOnly: denied === scoped.length, evidence: scoped.length, denied };
}
/**
 * 主权转移协议（Sovereignty Transfer）
 *
 * 背景（2026-10-28 note.yun 会话实测）：
 *   15:08:28  `http://note.yun.oppo.com/` → 301 `Location: https://cloud.oppo.com/`
 *   15:08:43  agent 确实去打了一次 cloud.oppo.com（唯一一次有效纵深）
 *   之后的 13 分钟里，它**又对 note.yun 发了 6 次同样的请求**，因为账本里的焦点任务
 *   仍然是 `T1 @ note.yun`，而"目标主机已经换了"这件事只存在于图里的一条边上。
 *
 * 结论：301 不是"一个响应"，是"目标所有权的转移"。让模型自己判断要不要跟跳，
 * 它就会在旧 host 上继续刷幂等请求。所以控制面必须在 ingest 时就替它做决定：
 *   ① 把活跃任务的 target 从旧 host 重写到新 host；
 *   ② 记下 host 锁（旧 host 直接拒收，附带"换 host"的理由）；
 *   ③ 给下一轮注入一条不可协商的指令。
 */

export type RedirectHop = {
  /** 触发跳转的 URL（请求方）。 */
  from: string;
  /** Location 指向的 URL。 */
  to: string;
  code: number;
};

export type SovereigntyState = {
  from_host: string;
  to_host: string;
  from_url: string;
  to_url: string;
  code: number;
  at: number;
  /** 被重写 target 的任务 id（可观测：哪几个任务跟着搬了家）。 */
  rewrites: string[];
};

/**
 * 一次跨主机跳转的候选记录。
 *
 * 为什么不直接升级成主权转移：跨主机 301 有两种完全不同的语义——
 * ① 整站换域（`old.com/about` → `new.com/about`），目标所有权真的转移了；
 * ② 单页迁移（`wanxiaozhi/help/3039522.html` → `help.aliyun.com/zh/document_detail/3039522.html`），
 *    只是这一篇文档搬去了母站，原站其余路径照常是 200。
 *
 * 把 ② 误判成 ① 的代价（2026-11-04 实测会话 d59f5a15a4ea26aa）：
 *   · 8 个非终态任务的 target 被改写到 help.aliyun.com；
 *   · 改写保留原路径，于是造出 `help.aliyun.com/swagger-ui/index.html` 这类**不存在的端点**
 *     （help 上 6 个节点 content_length 全是 7155，同一个 WAF 拦截页）；
 *   · 假设的 nodes 仍指向 `ep:wanxiaozhi.aliyun.com/…`，任务与假设脱锚，
 *     真 403 墙（wanxiaozhi 403/6066）被拿到 help 上 200 的任务"验证"，必错。
 *
 * 所以候选只在**判定为真迁移**时才升级为 SovereigntyState；单页迁移只记账，不改 target、不上锁。
 */
export type RedirectCandidate = { from: string; to: string; code: number; at: number };

/** 候选表上限：一旦某个 (from,to) 凑够 2 条不同路径就升级，不需要长历史。 */
const MAX_REDIRECT_CANDIDATES = 12;

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

function hostOf(url: string): string {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return "";
  }
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "";
  }
}

/** `/a/b/` 与 `/a/b` 是同一条路径；`/` 保持为 `/`。 */
function normalizePath(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  return trimmed || "/";
}

/**
 * 迁移后路径结构是否保持一致（换域不换路径）。
 *
 * 判据是"归一化后的 pathname 完全相等"，**不是深度**：
 * 深度只是路径长度，和"是不是整站迁移"没有必然关系——
 *   · `old.com/about`（深度 1）→ `new.com/about`：真迁移，深度浅；
 *   · `example.com/docs`（深度 1）→ `docs.example.com/`：单页迁移，深度也浅；
 *   · `wanxiaozhi/help/3039522.html`（深度 2）→ `help.aliyun.com/zh/document_detail/3039522.html`：
 *     段数从 2 变 3，结构变了，单页迁移。
 *
 * 判不准一律 false（按单页迁移处理）：判错成整站迁移的代价是锁 host + 改写 target + 造假端点，
 * 判错成单页迁移的代价只是这一页不追、其余路径照常打。宁可漏判。
 */
export function isPathStructurePreserved(fromUrl: string, toUrl: string): boolean {
  const fromPath = pathOf(fromUrl);
  const toPath = pathOf(toUrl);
  // 解析不出来的 URL 不当作"结构一致"的证据。
  if (!fromPath || !toPath) return false;
  return normalizePath(fromPath) === normalizePath(toPath);
}

/**
 * `to_host` 是不是 `from_host` 的**父域门户**。
 *
 * 实测（2026-11-04 10:35，会话 09a67a8a9aa67cec）：`wanxiaozhi.aliyun.com/`、
 * `/robots.txt`、`/sitemap.xml`、`/api/` 在 6 分钟内被同一条临时风控**统一 302 到
 * `https://www.aliyun.com/notfound`**（同一批 URL 6 分钟前是 200，之后又恢复 200）。
 *
 * 这不是"站点搬到 www.aliyun.com"——父域门户是**另一套应用**（阿里云官网），
 * 把它当新主权会：
 *   · 把 8 个任务的 target 全改写到 www.aliyun.com（越出授权范围）；
 *   · 给旧 host 上锁，agent 再也不能重打真正在恢复的目标；
 *   · 上下文里出现"已永久转移"的不可协商指令，把一次临时抖动写成事实。
 *
 * 判据只覆盖"往上走"这一种（`a.b.com` → `b.com` / `www.b.com`）。
 * 真正的换域（`note.yun.oppo.com` → `cloud.oppo.com`）不满足后缀关系，不受影响。
 */
export function isParentPortal(fromHost: string, toHost: string): boolean {
  const bare = String(toHost || "").replace(/^www\./i, "");
  if (!bare || !fromHost || fromHost === bare) return false;
  return fromHost.endsWith("." + bare);
}

/** 跳转目标是"不存在"兜底页（`/notfound`、`/404`、`/error`）。 */
const NOT_FOUND_PATH = /(^|\/)(not[-_]?found|404|not[-_]?exist|error|missing)(\/|$|\.)/i;

export function isNotFoundTarget(url: string): boolean {
  return NOT_FOUND_PATH.test(pathOf(url));
}

/**
 * 为什么这次跳转不算主权转移（`undefined` = 算）。
 *
 * 单独暴露判据是为了**让拒绝可见**：控制面据此落一条事件，
 * 模型才知道"这不是搬家，别跟到父域去、等一会儿重打原 URL"。
 */
export type SovereigntyRejection =
  /** 同 host（路由规范，例如 `/a` → `/a/`）。 */
  | "same_host"
  /** 跳到自己的父域门户（`wanxiaozhi.aliyun.com` → `www.aliyun.com`）。 */
  | "parent_portal"
  /** 跳转目标是 notfound/404 兜底页。 */
  | "notfound_target"
  /** 路径结构变了：单页迁移（`/help/1.html` → `help.example.com/zh/doc/1`）。 */
  | "path_changed"
  /** 结构一致但只见过一条：等第二条不同路径再判。 */
  | "single_path";

export function sovereigntyRejection(hop: RedirectHop, candidates: RedirectCandidate[]): SovereigntyRejection | undefined {
  const fromHost = hostOf(hop.from);
  const toHost = hostOf(hop.to);
  if (!fromHost || !toHost || fromHost === toHost) return "same_host";
  // ⓪ 父域门户 / 兜底页：放在首页判据之前——首页被 302 到 `www.域名/notfound`
  // 恰恰是最容易被误判成"整站搬家"的形态。
  if (isParentPortal(fromHost, toHost)) return "parent_portal";
  if (isNotFoundTarget(hop.to)) return "notfound_target";
  // ① 首页跳转：整站迁移的最强信号，结构如何都不影响结论。
  if (normalizePath(pathOf(hop.from)) === "/") return undefined;
  // ② 结构变了就不是整站迁移（含 wanxiaozhi 那类段数变化的单页迁移）。
  if (!isPathStructurePreserved(hop.from, hop.to)) return "path_changed";
  // ③ 结构一致但只见过这一条：可能是深路径的单页迁移，等第二条不同路径再升级。
  const paths = new Set(
    candidates
      .filter(item => hostOf(item.from) === fromHost && hostOf(item.to) === toHost)
      .map(item => normalizePath(pathOf(item.from))),
  );
  return paths.size >= 2 ? undefined : "single_path";
}

/**
 * 这次跨主机跳转是不是"整站主权转移"。
 *
 * 三个信号，任一充分条件成立即升级（首页跳最强，无需其余两个）：
 *   ① 首页自己跳了（`from` 的 pathname 是 `/`）→ 整站迁移；
 *   ② 路径结构一致 **且** 同一 (from_host → to_host) 已有 ≥2 条不同路径的跳转 → 整站迁移；
 *   ③ 其余 → 单页迁移，不改 target、不上锁。
 *
 * ⓪ 之前还有两道否决：父域门户、notfound 兜底页（见 `sovereigntyRejection`）。
 *
 * 信号 ① 用"本次 hop 的 from 是首页"而不是查图里的 `ep:${fromHost}/` 节点：
 *   `NodeProperties` 不存 `location`，图节点无法回答"首页跳去了哪"；
 *   而首页一旦跳转，那一次 hop 本身就是首页，判定时机天然正确。
 */
export function isRealSovereigntyShift(hop: RedirectHop, candidates: RedirectCandidate[]): boolean {
  return sovereigntyRejection(hop, candidates) === undefined;
}

/** 记一次跳转候选（去重、限长），返回当前候选表。 */
function recordRedirectCandidate(
  state: { redirect_hops?: RedirectCandidate[] },
  hop: RedirectHop,
  at: number,
): RedirectCandidate[] {
  const list = [...(state.redirect_hops || [])];
  if (!list.some(item => item.from === hop.from && item.to === hop.to)) {
    list.push({ from: hop.from, to: hop.to, code: hop.code, at });
  }
  state.redirect_hops = list.slice(-MAX_REDIRECT_CANDIDATES);
  return state.redirect_hops;
}

/**
 * 从一次工具结果里提取"跨主机永久跳转"。
 *
 * 只在 host 变化时返回：同主机内的 301（`/a` → `/a/`）是路由规范，不是主权转移，
 * 把它也当转移会让 host 锁误伤整个站。
 */
export function redirectOf(data: Record<string, unknown>, requestUrl?: string): RedirectHop | undefined {
  const code = Number(data.status ?? 0);
  if (!REDIRECT_CODES.has(code)) return undefined;
  const location = String(data.location ?? (data.headers as Record<string, unknown> | undefined)?.location ?? "");
  if (!location) return undefined;
  const from = String(requestUrl || data.url || "");
  if (!/^https?:\/\//i.test(from)) return undefined;
  let to = location;
  if (!/^https?:\/\//i.test(to)) {
    try {
      to = new URL(location, from).toString();
    } catch {
      return undefined;
    }
  }
  const fromHost = hostOf(from);
  const toHost = hostOf(to);
  if (!fromHost || !toHost || fromHost === toHost) return undefined;
  return { from, to, code };
}

/**
 * 执行主权转移：重写活跃任务的 target，记录状态。
 *
 * 幂等：同一 (from_host → to_host) 只生效一次——重复的 301 不会把 tasks 反复改写，
 * 也不会把 `rewrites` 越滚越长（那会让上下文里的指令看起来像在抽风）。
 *
 * **闸门（2026-11-04 加）**：跨主机 301 不等于整站搬家，先过 `isRealSovereigntyShift`。
 * 单页迁移只记 `redirect_hops` 候选，不动 tasks、不上锁——见 RedirectCandidate 的注释。
 *
 * **只改 tasks、不改 graph.hypotheses 是有意为之**：假设锚定它被创建时的真实端点
 * （`ep:wanxiaozhi.aliyun.com/robots.txt`），任务锚定执行目标。假设跟着任务一起搬，
 * 就会出现"假设说 wanxiaozhi 有墙、任务却去打 help"的脱锚，两边都对不上。
 * 不要"顺手"把假设也改了。
 */
export function applySovereignty(
  state: {
    tasks?: Record<string, { status?: string; target?: string; reason?: string }>;
    sovereignty?: SovereigntyState;
    /** 跨主机跳转的候选记录（判"多路径跳"信号用）。控制面维护，不进模型上下文。 */
    redirect_hops?: RedirectCandidate[];
  },
  hop: RedirectHop,
  at = Date.now(),
): SovereigntyState | undefined {
  const fromHost = hostOf(hop.from);
  const toHost = hostOf(hop.to);
  if (!fromHost || !toHost || fromHost === toHost) return undefined;

  // 先记账再判定：单页迁移虽然不升级，但它仍是"同 host 多路径跳"信号的证据。
  const candidates = recordRedirectCandidate(state, hop, at);

  // 闸门：不是整站迁移就到此为止。
  if (!isRealSovereigntyShift(hop, candidates)) return undefined;

  const previous = state.sovereignty;
  if (previous && previous.from_host === fromHost && previous.to_host === toHost) return undefined;

  const rewrites: string[] = [];
  const tasks = state.tasks || {};
  for (const [id, task] of Object.entries(tasks)) {
    const status = String(task?.status || "pending");
    // 已结案的任务不动：它们的历史结论挂在旧 host 上，改了就是篡改账本。
    if (!["pending", "running", "blocked"].includes(status)) continue;
    const target = String(task?.target || "");
    if (!target) continue;
    if (hostOf(target) !== fromHost) continue;
    // target 可以是逗号分隔的多主机列表：逐段替换，保留其余部分。
    const next = target
      .split(",")
      .map(part => part.trim())
      .map(part => (hostOf(part) === fromHost ? part.replace(originOf(part), originOf(hop.to)) : part))
      .join(" , ");
    if (next === target) continue;
    task.target = next;
    rewrites.push(id);
  }

  const next: SovereigntyState = {
    from_host: fromHost,
    to_host: toHost,
    from_url: hop.from,
    to_url: hop.to,
    code: hop.code,
    at,
    rewrites,
  };
  state.sovereignty = next;
  return next;
}

/** 旧 host 的硬锁：执行前用它拒收请求。 */
export function hostLockOf(state: { sovereignty?: SovereigntyState }): { deny: string; allow: string } | undefined {
  const sovereignty = state.sovereignty;
  if (!sovereignty) return undefined;
  return { deny: sovereignty.from_host, allow: sovereignty.to_host };
}

/** 判断一条 URL 是否落在旧 host 上（该被拒收）。 */
export function violatesSovereignty(state: { sovereignty?: SovereigntyState }, url: string): SovereigntyState | undefined {
  const sovereignty = state.sovereignty;
  if (!sovereignty) return undefined;
  const host = hostOf(url);
  if (!host || host !== sovereignty.from_host) return undefined;
  return sovereignty;
}

/** 写进上下文的不可协商指令。 */
export function sovereigntyDirective(state: { sovereignty?: SovereigntyState }): string | undefined {
  const sovereignty = state.sovereignty;
  if (!sovereignty) return undefined;
  return `【主权转移】${sovereignty.from_host} 已返回 ${sovereignty.code} 永久重定向至 ${sovereignty.to_host}。`
    + `原任务${sovereignty.rewrites.length ? `（${sovereignty.rewrites.slice(0, 4).join("、")}）` : ""}已自动迁移到新 Host。`
    + `严禁再对 ${sovereignty.from_host} 发起任何请求——会被 ${sovereignty.from_host} 域锁直接拒收（sovereignty_moved），白烧预算。`
    + `你现在的目标是 ${sovereignty.to_url}：先把它当新站点重新做基线（状态码/字节数/框架指纹/外部引用），再决定打哪个面。`;
}
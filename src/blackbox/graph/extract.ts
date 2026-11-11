/**
 * 发现物抽取：把「任意工具的结果」翻译成"我们挖到了哪些 URL、它们是从哪挖到的"。
 *
 * 为什么单独立一个文件（2026-10-28 实测事故）：
 * `desk.ts` 原来只用 `evidenceUrls()` 读 `data.url / data.final_url / data.target / data.urls`。
 * 但真实工具的结果长这样：
 *
 *   recon.js_endpoints      → { items: [...], js_files: [...] }
 *   recon.content_discovery → { items: [...] }
 *   browser.open            → { links: [...], forms: [...] }
 *   katana.crawl            → { urls: [...] }（唯一对得上的那个）
 *
 * 于是 11 轮、165 次工具调用之后，历程图里 42 个节点 **37 条边全是 asset→endpoint**，
 * 最长链 2 个节点，`parameter/vuln_state` 各 0 个——图成了"一排由上下到下的节点"，
 * 因为根本没有第三跳。渲染器（dagre rankDir=LR）没毛病，是数据侧只有一跳。
 *
 * 这个模块的契约：
 *   - `selfOf(data)`   ：这次调用作用的 URL（可能是多个），它们是**父节点候选**。
 *   - `discoveryOf()`  ：这次调用**新挖到**的 URL + 原文里带的分类线索。
 *   - `paramsOf()`     ：参数从**请求**里取（query / json / form），不是从响应里猜。
 */

export type FoundUrl = {
  url: string;
  /**
   * 发现方式：决定边类型，也决定**跨站时是否放行**（见 builder 的 inScope）。
   *
   * `link`  导航链接（`<a href>`、列表页条目）：跨站基本是噪声，必须同站点。
   * `form`  表单 action：跨站是真的（登录/支付常指向独立域），放行。
   * `api`   前端代码里的接口调用：跨站是真的（api.example.com），放行。
   * `js`    脚本文件：跨站通常是 CDN，但脚本里能挖接口，放行。
   * `item`  容器里的条目：跟 `link` 同等保守。
   *
   * 2026-11-04 拆出 `form`：此前 `forms` 和 `links` 都被压成 `link`，
   * 于是"导航栏外链"和"表单 action"在 scope 判断上无法区分——
   * 前者该挡（9cb376 里 161 条 *.console.aliyun.com 就是导航外链），
   * 后者该放（跨域登录/支付是真实业务面）。
   */
  kind: "link" | "api" | "item" | "js" | "form";
  method?: string;
  params?: string[];
  /**
   * 站点自己声明的来源（sitemap / robots）。这类 URL 的可信度高于爬取所得：
   * 它是站点主动列出的业务面，不是导航栏里随手放的链接。
   */
  source?: "sitemap" | "robots";
  /**
   * 状态码：burp.sitemap / burp.history 的条目自带 `status`，这是**已验证的观测面**
   * （2026-10-31 实测：100 条 sitemap 条目因为键名 `entries` 不在白名单里全被丢掉，
   * 图停在 29 个节点，假设链断在最前面）。
   */
  status?: number;
  /**
   * 直接父节点：不是本次调用的页面，而是"中间那一层容器"。
   * 例：recon.js_endpoints 返回 `js_files:[bundle.js]` + `items:[/api/x]`，
   * 语义上 /api/x 是从 bundle.js 里挖出来的 → 父是 bundle，不是页面。
   * 有了它，图才有 3 跳以上的链（页面 → bundle → 接口），而不是所有东西挂在页面上。
   */
  via?: string;
};

export type DiscoveryResult = {
  /** 本次调用作用的 URL（与发现物区分：它不新建节点，只作为父节点）。 */
  self: string[];
  /** 本次调用新挖到的 URL。 */
  found: FoundUrl[];
};

const HTTP_URL = /^https?:\/\/[^\s"'<>]+$/i;

/** 允许出现在结果里的 URL 容器键；顺序即优先级。 */
const SELF_KEYS = ["url", "final_url", "requested_url", "target", "request_url", "page_url"];
// 顺序有讲究：js_files 必须排在 items 前面——items 的 via 指向 js 容器，容器要先建节点。
const LINK_KEYS = ["links", "js_files", "urls", "endpoints", "entries", "records", "history", "results", "items", "forms", "api_calls", "redirects", "location", "next"];

function cleanUrl(raw: unknown, base?: string): string | undefined {
  if (typeof raw !== "string") return undefined;
  const text = raw.trim();
  if (!text) return undefined;
  if (HTTP_URL.test(text)) return text;
  // 相对路径要拼到父 URL 上，否则 recon 的相对 item（/api/user/info）会被丢掉。
  if (text.startsWith("/") && base) {
    try { return new URL(text, base).toString(); } catch { return undefined; }
  }
  return undefined;
}

function asArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  return [];
}

/** 从一条"发现物"（字符串或对象）里抠出 URL 与分类线索。 */
function foundFrom(value: unknown, base: string | undefined, fallbackKind: FoundUrl["kind"]): FoundUrl | undefined {
  if (typeof value === "string") {
    const url = cleanUrl(value, base);
    return url ? { url, kind: fallbackKind } : undefined;
  }
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  const raw = record.url ?? record.endpoint ?? record.href ?? record.path ?? record.location ?? record.request_url ?? record.src;
  const url = cleanUrl(raw, base);
  if (!url) return undefined;
  const kindHint = String(record.type ?? record.kind ?? record.source ?? "").toLowerCase();
  const kind: FoundUrl["kind"] = /api|xhr|fetch|graphql/.test(kindHint)
    ? "api"
    : /js|chunk|script|bundle/.test(kindHint)
      ? "js"
      : fallbackKind;
  const method = typeof record.method === "string" ? record.method.toUpperCase() : undefined;
  const params = asArray(record.params ?? record.parameters).map(String).filter(Boolean).slice(0, 12);
  const status = Number(record.status ?? record.status_code ?? 0) || undefined;
  return { url, kind, ...(method ? { method } : {}), ...(params.length ? { params } : {}), ...(status ? { status } : {}) };
}

/**
 * 暴力枚举类工具：它们的 `items` 是**字典命中**，不是"观测到的面"。
 *
 * 2026-10-28 support.oppo.com 实测：一次 `recon.content_discovery` 的 113 条命中
 * 被当成 113 个端点写进图，而它们只有 `discovered_from` 边（不是 WALKABLE），
 * 于是连通分量从 1 块变成 120 块，Observer 连续 8 轮喊"图裂开了，去打 flag.php"。
 *
 * 这些命中在语义上是"待验证的候选路径"：
 *   - 可能是真 200，也可能只是 catch-all 302 到站点的 /404/ 吸收页；
 *   - `-s` 静默模式还不带状态码，连区分都做不到。
 * 所以它们不进图，挂在父节点的 `candidates` 上，等真的发一次请求再由 http.request 建节点。
 */
export const CANDIDATE_TOOLS = new Set([
  "recon.content_discovery",
  "recon.api_routes",
  "recon.wordlists",
  "recon.vhosts",
]);

export function isCandidateTool(tool: string): boolean {
  return CANDIDATE_TOOLS.has(tool);
}

/** 把候选路径归一成 `/path` 形态：上游可能给整条 URL，也可能给相对路径。 */
export function candidatePathOf(url: string, base?: string): string {
  try {
    const parsed = new URL(url, base);
    return parsed.pathname + parsed.search;
  } catch {
    return url;
  }
}
/**
 * 解析站点自报的 sitemap（`<loc>` 清单）。
 *
 * 为什么值得单独解析（2026-11-04）：这是站点**主动声明的业务面**。
 * 爬虫只能爬到导航栏里放出来的链接，而导航栏恰恰是噪声最多的地方
 * （9cb376 会话：首页一次抓取入图 170 条，161 条是 `*.console.aliyun.com` 产品导航外链）；
 * sitemap 里列的才是"这个站点有哪些页面"。
 *
 * 只做一轮 `<loc>` 扫描：`<urlset>`（页面清单）和 `<sitemapindex>`（子 sitemap 清单）
 * 里的 loc 都是值得一打的 URL —— 子 sitemap 打下去还能再拿一批，属于有效的发现跳。
 * 不引入 XML 库：sitemap 是固定格式，正则足够，而且工具结果里的 body 可能被截断，
 * 宽松匹配比严格解析更耐用。
 *
 * 上限 300 条：超大 sitemap 会把图撑爆（见 `MAX_NODES`），剩下的交给后续轮次。
 */
export function parseSitemap(xml: string, baseUrl?: string, limit = 300): string[] {
  if (!xml || typeof xml !== "string") return [];
  if (!/<(urlset|sitemapindex)\b/i.test(xml)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const match of xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
    // XML 实体要先还原，否则 `?a=1&amp;b=2` 这种 URL 会带着 &amp; 入图，等于打错地址。
    const loc = match[1] || "";
    const url = cleanUrl(loc.replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">"), baseUrl);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push(url);
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * 解析 robots.txt 里的 `Disallow` 路径与 `Sitemap` 指令。
 *
 * `Disallow` 是站点自己声明"不想被爬"的路径 —— 恰恰是最值钱的那批
 * （管理后台、接口前缀、备份目录）。这是**零成本的高价值发现源**：
 * 以前 robots.txt 的响应拿到了、也记进了图，但正文从未被看过。
 *
 * 只取 Disallow 不取 Allow：Allow 通常是 Disallow 的例外条款，成对出现，
 * 全收会制造大量重复；而 Disallow 的语义是"这里有不希望外部看到的东西"，指向性更强。
 *
 * 通配处理：`/admin/*` → `/admin/`（去掉 `*` 及其后），只保留可打的前缀路径。
 * 上限 60 条：正常 robots 不会有更多，超出说明是自动生成的噪声。
 */
export function parseRobots(text: string, baseUrl?: string, limit = 60): string[] {
  if (!text || typeof text !== "string") return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (url: string | undefined): boolean => {
    if (!url || seen.has(url)) return out.length >= limit;
    seen.add(url);
    out.push(url);
    return out.length >= limit;
  };
  for (const line of text.split(/\r?\n/)) {
    const sitemap = /^\s*sitemap\s*:\s*(\S+)/i.exec(line);
    if (sitemap) {
      if (push(cleanUrl(sitemap[1], baseUrl))) break;
      continue;
    }
    const rule = /^\s*disallow\s*:\s*(\S*)/i.exec(line);
    if (!rule) continue;
    const raw = ((rule[1] || "").split("*")[0] || "").trim();
    if (!raw || raw === "/" || !raw.startsWith("/")) continue;
    if (push(cleanUrl(raw, baseUrl))) break;
  }
  return out;
}

export function selfOf(data: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of SELF_KEYS) {
    const url = cleanUrl(data[key]);
    if (url && !out.includes(url)) out.push(url);
  }
  return out;
}

/**
 * 一次工具结果里的全部发现物。
 * `base` 是本次调用的主 URL：相对路径靠它补全（recon 系工具大量返回 `/api/x` 这种）。
 */
export function discoveryOf(data: Record<string, unknown>): DiscoveryResult {
  const self = selfOf(data);
  const base = self[0];
  const found: FoundUrl[] = [];
  const seen = new Set(self);
  // 中间容器：js_files 先建，items 就是从中挖出来的（工具语义，不是猜测）。
  const containers: string[] = [];
  for (const raw of asArray(data.js_files)) containers.push(cleanUrl(raw, base) || ""); 
  const via = containers.filter(Boolean)[0];
  const push = (item: FoundUrl | undefined): void => {
    if (!item || seen.has(item.url)) return;
    seen.add(item.url);
    found.push(item);
  };
  // ── 站点自报的业务面（2026-11-04）──
  // 此前 `/sitemap.xml` 和 `/robots.txt` 的正文拿到了也白拿：图里只有那一个节点，
  // 里面声明的 URL 一条都没进（9cb376 会话：目标本体只有 4 个端点、全是静态文件、
  // 业务面为 0，假设只能挂在 robots/sitemap 自己身上）。这两个文件是站点主动声明的
  // URL 清单，可信度高于爬取所得，而且天然同站，不受 scope 污染。
  const bodyText = typeof data.body === "string" ? data.body : "";
  if (bodyText) {
    const probe = base || "";
    if (/\/sitemap[^/?#]*\.xml(?:[?#]|$)/i.test(probe)) {
      for (const url of parseSitemap(bodyText, base)) push({ url, kind: "link", source: "sitemap" });
    } else if (/\/robots\.txt(?:[?#]|$)/i.test(probe)) {
      for (const url of parseRobots(bodyText, base)) push({ url, kind: "link", source: "robots" });
    }
  }
  for (const key of LINK_KEYS) {
    const kind: FoundUrl["kind"] = key === "forms"
      ? "form"
      : key === "links" || key === "redirects" || key === "next" || key === "urls"
      || key === "entries" || key === "records" || key === "history" || key === "results"
      ? "link"
      : key === "endpoints" || key === "api_calls"
        ? "api"
        : key === "js_files"
          ? "js"
          : "item";
    const direct = cleanUrl(data[key], base);
    if (direct) { push({ url: direct, kind }); continue; }
    for (const raw of asArray(data[key])) {
      const item = foundFrom(raw, base, kind);
      // items 挂在 js 容器下面（只在容器确实存在、且不是它自己时）。
      if (item && via && key === "items" && item.url !== via) item.via = via;
      push(item);
      // items 里可能再套一层（既可能被覆盖，也可能不被覆盖，这两种实测都出现过）。
      if (raw && typeof raw === "object") {
        const nested = raw as Record<string, unknown>;
        for (const inner of asArray(nested.items ?? nested.endpoints ?? nested.urls ?? nested.links)) {
          push(foundFrom(inner, base, kind));
        }
      }
    }
  }
  return { self, found };
}

/**
 * 参数：从**请求**里取。
 *
 * 原来 desk 只从响应里读 `data.params`，而没有任何工具的响应带这个键 →
 * 11 轮之后 `parameter` 节点数 = 0，逻辑漏洞连个落脚的节点都没有。
 */
export function paramsOf(input: Record<string, unknown> | undefined, url?: string): string[] {
  const out = new Set<string>();
  const source = input || {};
  const target = String(url || source.url || "");
  if (target) {
    try {
      const parsed = new URL(target.includes("://") ? target : `http://placeholder${target.startsWith("/") ? "" : "/"}${target}`);
      for (const key of parsed.searchParams.keys()) out.add(key);
    } catch { /* 相对 URL 解析失败就跳过，不编 */ }
  }
  const body = source.json ?? source.form ?? source.body_params;
  if (body && typeof body === "object" && !Array.isArray(body)) {
    for (const key of Object.keys(body as Record<string, unknown>)) out.add(key);
  }
  if (Array.isArray(source.params)) for (const key of source.params) if (typeof key === "string" && key) out.add(key);
  return [...out].map(key => key.slice(0, 40)).slice(0, 12);
}
/**
 * WAF / 拦截墙指纹。
 *
 * 为什么需要：2026-10-28 note.yun 那一轮 9 条响应统一是 `412` + 2681B 的
 * `securityfs.oppo.com/waf` 阻断页，但图里全落成 `testing`（"还在打"），
 * `blocked` 计数 0 —— 于是 agent 看不出"这是墙"，也没有换武器的依据，
 * 继续用同一批路径反复撞（43 次调用里 21 次是重复的）。
 *
 * 判据分两层：状态码（412/418/429/1020 这类几乎只出现在拦截场景）+ 正文指纹。
 * 只有状态码或命中指纹时才判墙，避免把正常的 429 限流误当永久墙。
 */
const WALL_STATUS = new Set([412, 418, 429, 1020]);

const WALL_MARKERS: Array<{ kind: string; pattern: RegExp }> = [
  { kind: "waf_oppo", pattern: /securityfs\.oppo\.com\/waf|您的访问被阻断/i },
  { kind: "waf_cloudflare", pattern: /cloudflare|cf-error|Attention Required/i },
  { kind: "waf_akamai", pattern: /akamai|Reference #\d+\.[0-9a-f]+/i },
  /**
   * 阿里云 WAF 的两种封锁形态（2026-11-04 wanxiaozhi 实测）：
   *
   * ① **传统拦截页** `dev.g.alicdn.com/sd/punish/waf_block_deny.html` + `gateway-diagno…` 诊断脚本。
   *    可能返回 HTTP 200，状态码说"通过了"、正文是拦截页。
   *
   * ② **attestation 挑战页**（更隐蔽，也更危险）：403 + JSON，谎称"分析代理需要客户端证明"，
   *    要求把 `attestation` 对象塞进请求体，字段是 `principal`（username/email）、`origin`、
   *    `provenance`、`delegation`、`timestamp`——本质是**钓身份**。
   *    指纹：`server: Tengine` + `access-control-allow-origin` 每次换成随机域名
   *    （实测 n6d7o8.com / zthncu4l0.com）+ 正文 `proxy_authentication_required`。
   *
   * 两者都判墙，但 agent 绝不该"照做"②——那是把探测者身份交出去换一个假放行。
   */
  { kind: "waf_aliyun_attestation", pattern: /proxy_authentication_required|client attestation payload/i },
  { kind: "waf_aliyun", pattern: /waf_block_deny|punish\/waf|gateway-diagno/i },
  { kind: "waf_generic", pattern: /Access Denied|Request blocked|访问被拒绝|非法请求|拦截/i },
];

export type WallInfo = { kind: string; status: number; marker: boolean };

/** 从一次工具结果里判定"这是被墙了"，返回墙的种类；不是墙返回 undefined。 */
export function wallOf(data: Record<string, unknown>): WallInfo | undefined {
  const status = Number(data.status ?? data.status_code ?? 0);
  const body = String(data.body ?? data.body_preview ?? "");
  const marker = body ? WALL_MARKERS.find(item => item.pattern.test(body))?.kind : undefined;
  const statusHit = WALL_STATUS.has(status);
  // 412 单独出现就已经足够强（正常业务几乎不用）；429 必须有指纹才算墙，否则是限流。
  if (!statusHit && !marker) return undefined;
  if (status === 429 && !marker) return undefined;
  return { kind: marker || `waf_${status}`, status: status || 0, marker: Boolean(marker) };
}

/**
 * 网关级"没有这条路由"的指纹。
 *
 * 与 404 页面不同，这些串是**路由层自己**说出来的：它不是"资源不存在"，
 * 而是"这个前缀下根本没有这条路由"。两者的区别决定它值不值得建假设。
 */
const ROUTE_MISSING_MARKERS: RegExp[] = [
  /Not-Found-Route/i,
  /NotFoundRouteException/i,
  /RouteNotFoundException/i,
  /NoHandlerFoundException/i,
  /unknown host/i,
];

/**
 * 判定"这条路径在服务端不存在"。
 *
 * 为什么需要（2026-11-02 m.ctrip.com 实测）：agent 会自己造 `z9probe_notexist/{id}`
 * 这类路径去验 catch-all，网关回 404 信封，图却按 `{id}` 模板把它当成"带对象 id
 * 的接口"，生成 `H_idor` 假设、派出任务、再烧 3 轮证明它是假的。
 *
 * 只在**有证据**时返回 true，不靠路径名猜（`notexist` 这种字样以后可能出现在真接口里）：
 *   ① 正文命中网关路由未命中指纹；② 404/410 且正文极小（空壳响应，没有真实页面）。
 * 被墙（412/418/429 阻断页）不算——那是 `wallOf` 的职责，属性和状态各自记账。
 */
export function routeMissingOf(data: Record<string, unknown>): boolean {
  const status = Number(data.status ?? data.status_code ?? 0);
  const body = String(data.body ?? data.body_preview ?? "");
  if (body && ROUTE_MISSING_MARKERS.some(pattern => pattern.test(body))) return true;
  if (status !== 404 && status !== 410) return false;
  const declared = Number(data.content_length);
  const length = Number.isFinite(declared) && declared >= 0 ? declared : body.length;
  return length < 64;
}
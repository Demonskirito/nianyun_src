/**
 * 证据归因（evidence attribution）——工具结果进图的**唯一**入口。
 *
 * ## 为什么需要这个文件
 *
 * 2026-11-03 取证：`desk.ts` 原来用 `evidenceUrls({ ...data, url: requester })` 取
 * `[url, final_url, target, ...data.urls]`，然后把这一整批无差别地标成
 * `requested: true / origin: "request"`。而 `katana.crawl` 的 `data.urls` 是
 * "爬虫在 HTML 里**看到**的链接"（最多 500 条，含全部跨域外链），`recon.*` 的
 * `data.target` 只是回显的入参。于是：
 *
 *   - 一次 crawl 就让 500 个节点处于"我打过了"的假状态（`builder.ts:344` → testing）；
 *   - `hypotheses.ts:99 cannotLocateObject()` 对 `origin==="request"` 不走被动 404 判据，
 *     跨域 404 节点照样派 IDOR 假设；
 *   - `analyze.ts:165 verified()` 要求 untested，假端点永远进不了"没动过的块"；
 *   - 证据增益被 500 条假新端点灌满，焦点预算被白白续命。
 *
 * 同一个 URL，用 katana 抓就"已请求"，用 browser 抓就被 `inScope` 挡掉——
 * **墙的形状不由语义决定，由工具返回的字段名决定**。这个模块把那层判断收回来：
 * 按工具种类分流，谁有资格产出 `origin: "request"`，写死在表里。
 *
 * ## 契约（由 `assertEvidenceContract()` 强制）
 *
 *   1. `origin === "request"` ⟺ `requested === true`
 *   2. `origin === "request"` 必须带 `status_code`，或显式 `status_unknown: true`
 *      （扫描器确实发了包，但结果 schema 里没有状态码——必须说"不知道"，不许编）
 *
 * 覆盖范围：`BLACKBOX_TOOL_NAMES` 全部 75 个工具都有明确归类，
 * `test/graph-evidence-contract.test.ts` 会断言"表里没有漏项、也没有多余的键"。
 */
import { discoveryOf, selfOf, type FoundUrl } from "./extract.js";
import type { NodeOrigin } from "./types.js";

/** 工具的取证等级。 */
export type ToolEvidenceClass =
  /** 结果就是一次（或两次）真实 HTTP 交互：主 URL 有真实状态码。 */
  | "response"
  /** 工具替我们发了包，但结果 schema 不带单条状态码（扫描器 / 并发发射 / 批量）。 */
  | "probe"
  /** 只是"看到"：爬虫、字典命中、站点地图、JS 抽取、Burp 流量日志。 */
  | "discovery"
  /** 不涉及目标 HTTP 面：开关、状态查询、编解码、文件、沙箱。 */
  | "none";

/** 一条"本 agent 真的发过请求"的证据。 */
export type RequestEvidence = {
  url: string;
  origin: "request";
  requested: true;
  /** 真实响应状态码；工具 schema 不提供时缺省，并置 `status_unknown`。 */
  status_code?: number;
  /** 确实发了包，但拿不到状态码。**存在这个标记才允许缺 status_code**。 */
  status_unknown?: boolean;
  method?: string;
  content_length?: number;
};

export type EvidenceAttribution = {
  tool_class: ToolEvidenceClass;
  /** 本次调用真实发出过请求的目标（origin=request 的唯一来源）。 */
  requests: RequestEvidence[];
  /** 本次结果里"看到"但没请求的 URL。 */
  discovery: { self: string[]; found: FoundUrl[] };
};

/**
 * 结果是一次真实 HTTP 交互的工具。
 *
 * 判据是"结果里能同时拿到 URL 与**这次响应的**状态码"，不是"这个工具会联网"。
 * `browser.open` / `http.request` / `burp.request` 是主力；
 * `http.diff` 发两次（baseline + variant），`recon.http_probe` 对一批主机各发一次，
 * `burp.send` 走原始报文通道，`burp.sitemap_add` 会真的把请求发出去。
 */
export const RESPONSE_TOOLS = new Set([
  "browser.open",
  "browser.screenshot",
  "http.request",
  "burp.request",
  "http.diff",
  "burp.send",
  "burp.sitemap_add",
  "recon.http_probe",
  "recon.race_condition",
]);

/**
 * 工具替我们发了包，但结果 schema 里没有"这条 URL 的响应状态码"。
 *
 * 例：nuclei 的 `matched-at` 是一次真实命中的请求，JSONL 里只有 template-id；
 * dalfox / sqlmap / arjun / testssl 的输出同理；`burp.send_batch` 只回 `sent` 计数。
 * 这类证据进图时标 `status_unknown: true`——状态推进到 testing（确实动过），
 * 但**不许**凭空写一个 200。
 */
export const PROBE_TOOLS = new Set([
  "burp.repeater",
  "burp.send_batch",
  "burp.scan",
  "burp.crawl",
  "burp.intruder_send",
  "burp.websocket",
  "recon.nuclei",
  "recon.parameters",
  "recon.xss",
  "recon.sql",
  "recon.graphql",
  "recon.cms",
  "recon.tls",
]);

/**
 * 只是"看到"的工具：爬虫、字典、站点地图、历史流量、JS 抽取、证书/子域发现。
 *
 * 它们的产物可能带状态码（`burp.sitemap` / `burp.history` 的条目自带 status），
 * 那是**代理观测到的**响应，不是本 agent 打的——所以 `origin` 仍是 discovery，
 * 状态码照抄，但状态停在 untested（`analyze.verified()` 会把它算作观测面）。
 */
export const DISCOVERY_TOOLS = new Set([
  "katana.crawl",
  "burp.history",
  "burp.sitemap",
  "burp.entry",
  "burp.issues",
  "burp.sitemap_issues",
  "burp.scan_issues",
  "burp.ws_history",
  "browser.network",
  "recon.subdomains",
  "recon.dns",
  "recon.historical_urls",
  "recon.js_endpoints",
  "recon.secrets",
  "recon.content_discovery",
  "recon.api_routes",
]);

/** 不涉及目标 HTTP 面：开关/状态/编解码/配置/文件/沙箱/本地分析。 */
export const NETWORKLESS_TOOLS = new Set([
  "browser.close",
  "browser.storage",
  "browser.tab",
  "evidence.read",
  "burp.check",
  "burp.scope",
  "burp.intercept",
  "burp.decoder",
  "burp.organizer",
  "burp.collab_generate",
  "burp.collab_poll",
  "burp.scan_status",
  "burp.scan_stop",
  "burp.info",
  "burp.control",
  "burp.options",
  "burp.cookies",
  "burp.storage",
  "burp.scope_edit",
  "burp.scan_report",
  "burp.intruder",
  "burp.compare",
  "burp.convert",
  "burp.proxy_rule",
  "burp.bchecks",
  "recon.ports",
  "recon.interactsh",
  "recon.jwt",
  "recon.sast",
  "recon.wordlists",
  "recon.scan_profile",
  "recon.traffic_diff",
  "exec.python",
  "exec.bash",
  "fs.list",
  "fs.read",
  "fs.grep",
]);

export function toolEvidenceClass(tool: string): ToolEvidenceClass {
  const name = String(tool || "").trim().toLowerCase();
  if (RESPONSE_TOOLS.has(name)) return "response";
  if (PROBE_TOOLS.has(name)) return "probe";
  if (DISCOVERY_TOOLS.has(name)) return "discovery";
  // 未登记的工具一律按"什么都不产出"处理：宁可少记，不可错记。
  // （`NETWORKLESS_TOOLS` 是显式白名单，测试会检查它和工具清单一致。）
  return "none";
}

/** 契约自检：写错归因表时立刻炸，而不是悄悄污染图。 */
export function assertEvidenceContract(evidence: {
  url: string;
  origin: NodeOrigin;
  requested: boolean;
  status_code?: number;
  status_unknown?: boolean;
}): void {
  const url = String(evidence.url || "<empty>");
  if (evidence.requested && evidence.origin !== "request") {
    throw new Error(`evidence contract violation: requested=true but origin=${evidence.origin} for ${url}`);
  }
  if (evidence.origin === "request" && !evidence.requested) {
    throw new Error(`evidence contract violation: origin=request but requested=false for ${url}`);
  }
  if (evidence.origin === "request" && evidence.status_code === undefined && evidence.status_unknown !== true) {
    throw new Error(`evidence contract violation: origin=request must carry status_code (or status_unknown) for ${url}`);
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function positive(value: unknown): number | undefined {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function httpUrl(value: unknown): string | undefined {
  return typeof value === "string" && /^https?:\/\//i.test(value.trim()) ? value.trim() : undefined;
}

/** 取第一个能用的 URL（跳过空串与相对路径）。 */
function firstUrl(...values: unknown[]): string | undefined {
  for (const value of values) {
    const url = httpUrl(value);
    if (url) return url;
  }
  return undefined;
}

/** 请求里声明的目标：`input.url` 优先，其次 `ctx.target` 形态的 target 字段。 */
function requestedTarget(input: Record<string, unknown>, fallbackUrl?: string): string | undefined {
  return firstUrl(input.url, input.target, fallbackUrl);
}

/** `statuses: { "200": 17, "502": 3 }` → 出现次数最多的那个状态码。 */
function dominantStatus(value: unknown): number | undefined {
  const statuses = asRecord(value);
  let best: { code: number; count: number } | undefined;
  for (const [rawCode, rawCount] of Object.entries(statuses)) {
    const code = positive(rawCode);
    const count = Number(rawCount);
    if (!code || !Number.isFinite(count)) continue;
    if (!best || count > best.count) best = { code, count };
  }
  return best?.code;
}

function pushRequest(out: RequestEvidence[], evidence: RequestEvidence): void {
  assertEvidenceContract(evidence);
  const existing = out.find(item => item.url === evidence.url);
  if (existing) {
    // 同一 URL 在一次结果里出现多次（如 diff 的 baseline 403 → variant 200，
    // 或并发发射的同一目标）：节点描述的是"最新一次响应"，所以后来的状态码覆盖先前的；
    // 但**无状态码不能覆盖有状态码**——不许用"不知道"抹掉已经观测到的事实。
    if (evidence.status_code !== undefined) {
      existing.status_code = evidence.status_code;
      delete existing.status_unknown;
    }
    if (evidence.content_length !== undefined) existing.content_length = evidence.content_length;
    return;
  }
  out.push(evidence);
}

/** 逐工具抽取"真的发过请求"的证据。返回空数组 = 这个工具没有资格产出 request。 */
function requestsFor(
  tool: string,
  data: Record<string, unknown>,
  input: Record<string, unknown>,
  fallbackUrl?: string,
): RequestEvidence[] {
  const out: RequestEvidence[] = [];
  const method = typeof input.method === "string" ? input.method.toUpperCase() : undefined;

  switch (tool) {
    // ── 浏览器：导航到 final_url（跟随重定向后的落点），状态码是那次响应的 ──
    case "browser.open":
    case "browser.screenshot": {
      const url = firstUrl(data.final_url, data.requested_url) || requestedTarget(input, fallbackUrl);
      const status = positive(data.status);
      if (url) pushRequest(out, {
        url, origin: "request", requested: true,
        // 导航失败（DNS/连接被拒/超时）时 Playwright 也回 0 或不回：这是**数据**上的
        // "发了但拿不到状态"，不是契约违规，必须标 status_unknown 而不是抛错——
        // 抛错会被 desk 的工具循环吞成 tool-error，改变整个 stage 的记账（2026-11-03 实测）。
        ...(status !== undefined ? { status_code: status } : { status_unknown: true }),
        // browser 不返回长度；页面体量对判断"空壳页"没意义，宁缺勿编。
      });
      return out;
    }

    // ── 原生 HTTP：data.url 是**最后一跳**的地址，redirects[] 是中间每一跳 ──
    case "http.request":
    case "burp.request": {
      const url = firstUrl(data.url) || requestedTarget(input, fallbackUrl);
      const status = positive(data.status);
      if (url) pushRequest(out, {
        url, origin: "request", requested: true,
        ...(status !== undefined ? { status_code: status } : { status_unknown: true }),
        ...(method || typeof data.method === "string" ? { method: (method || String(data.method)).toUpperCase() } : {}),
        ...(positive(data.body_bytes) !== undefined ? { content_length: positive(data.body_bytes)! } : {}),
      });
      // 重定向链上的每一跳都真的发过，且各自带状态码——不进图就丢掉了
      // "301 到另一个主机"这种主权转移证据（sovereignty.ts 要靠它）。
      for (const hop of asArray(data.redirects)) {
        const record = asRecord(hop);
        const from = firstUrl(record.from);
        const hopStatus = positive(record.status);
        if (!from || hopStatus === undefined) continue;
        pushRequest(out, { url: from, origin: "request", requested: true, status_code: hopStatus });
      }
      return out;
    }

    // ── 差分：一次调用发两次（baseline + variant），两边都带自己的状态码 ──
    case "http.diff": {
      const baseline = asRecord(data.baseline);
      const variant = asRecord(data.variant);
      const left = firstUrl(data.url) || requestedTarget(input, fallbackUrl);
      const statusLeft = positive(baseline.status);
      const lengthLeft = positive(baseline.body_bytes);
      if (left) pushRequest(out, {
        url: left, origin: "request", requested: true,
        ...(statusLeft !== undefined ? { status_code: statusLeft } : { status_unknown: true }),
        ...(lengthLeft !== undefined ? { content_length: lengthLeft } : {}),
      });
      const right = firstUrl(data.variant_url);
      const statusRight = positive(variant.status);
      const lengthRight = positive(variant.body_bytes);
      if (right) pushRequest(out, {
        url: right, origin: "request", requested: true,
        ...(statusRight !== undefined ? { status_code: statusRight } : { status_unknown: true }),
        ...(lengthRight !== undefined ? { content_length: lengthRight } : {}),
      });
      return out;
    }

    // ── Burp 原始报文通道：状态码由 bridge 回传（data.status）──
    case "burp.send":
    case "burp.sitemap_add": {
      const url = firstUrl(data.url) || requestedTarget(input, fallbackUrl);
      const status = positive(data.status);
      if (url) pushRequest(out, {
        url, origin: "request", requested: true,
        ...(status !== undefined ? { status_code: status } : { status_unknown: true }),
        ...(method ? { method } : {}),
        ...(positive(data.response_bytes) !== undefined ? { content_length: positive(data.response_bytes)! } : {}),
      });
      return out;
    }

    // ── httpx：一批主机各发一次，findings[] 里带 url + status_code ──
    case "recon.http_probe": {
      for (const raw of asArray(data.findings)) {
        const finding = asRecord(raw);
        const url = firstUrl(finding.url, finding.final_url);
        if (!url) continue;
        const status = positive(finding.status_code);
        pushRequest(out, {
          url, origin: "request", requested: true,
          ...(status !== undefined ? { status_code: status } : { status_unknown: true }),
          ...(positive(finding.content_length) !== undefined ? { content_length: positive(finding.content_length)! } : {}),
        });
      }
      if (out.length) return out;
      // findings 为空（httpx 静默模式/全部失败）时退回"入参目标"，
      // 但它确实被打过——不能因为没解析出结果就当成没发生。
      const url = requestedTarget(input, fallbackUrl);
      if (url) pushRequest(out, { url, origin: "request", requested: true, status_unknown: true });
      return out;
    }

    // ── 并发发射：一次打 N 条，结果只有状态码分布 ──
    case "recon.race_condition": {
      const url = requestedTarget(input, fallbackUrl);
      const status = dominantStatus(data.statuses);
      if (url) pushRequest(out, {
        url, origin: "request", requested: true,
        ...(status !== undefined ? { status_code: status } : { status_unknown: true }),
        ...(method ? { method } : {}),
      });
      return out;
    }

    default: {
      // probe 家族：一批"发过包但 schema 不带状态码"的工具。
      const urls: string[] = [];
      for (const raw of asArray(data.findings)) {
        const url = firstUrl(asRecord(raw).url);
        if (url && !urls.includes(url)) urls.push(url);
      }
      if (!urls.length) {
        const target = requestedTarget(input, fallbackUrl);
        if (target) urls.push(target);
      }
      for (const url of urls) pushRequest(out, { url, origin: "request", requested: true, status_unknown: true });
      return out;
    }
  }
}

/**
 * 主入口：一次工具结果 → 图证据。
 *
 * 调用方（`desk.ts`）只需要把 `data`、请求入参、本次作用 URL 交进来，
 * 由这里决定"哪些是请求、哪些只是看到"，不再自己拼 `requested: true`。
 */
export function attributeEvidence(args: {
  tool: string;
  data: Record<string, unknown>;
  input?: Record<string, unknown>;
  fallbackUrl?: string;
}): EvidenceAttribution {
  const tool = String(args.tool || "").trim().toLowerCase();
  const data = asRecord(args.data);
  const input = asRecord(args.input || {});
  const toolClass = toolEvidenceClass(tool);

  if (toolClass === "none") {
    return { tool_class: toolClass, requests: [], discovery: { self: selfOf(data), found: [] } };
  }

  const requests = toolClass === "response" || toolClass === "probe"
    ? requestsFor(tool, data, input, args.fallbackUrl)
    : [];
  const discovery = discoveryOf(data);
  // 已经算作"请求过"的 URL 不再重复标成发现：否则同一节点先 request 后 discovery，
  // 属性合并时 origin 会被后写入的 discovery 覆盖（builder 里 props 是浅合并）。
  const requested = new Set(requests.map(item => item.url));
  return {
    tool_class: toolClass,
    requests,
    discovery: { self: discovery.self, found: discovery.found.filter(item => !requested.has(item.url)) },
  };
}

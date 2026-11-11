# 攻击历程图 · 证据契约（2026-11-03）

> 一句话：把「这个 URL **被请求过**」和「这个 URL **在工具结果里出现过**」拆成两件事，
> 并且只允许真正发过包的工具写前者。改完后 `origin === "request"` 是一条**可辩护的事实**，
> 而不是「某个字段名恰好叫 urls」。

---

## 一、旧形状：事实层为什么是假的

改之前 `desk.ts` 只有一条路径，所有工具共用：

```ts
// 旧代码（已删除）
const urls = evidenceUrls({ data: { ...data, url: requester || data.url } });
const graphEndpoints = [
  ...urls.map(url => ({
    url,
    requested: true,          // ← 一律「我打过了」
    origin: "request",
    ...(statusOf(data.status) !== undefined ? { status_code: statusOf(data.status) } : {}),
  })),
  // ...
];
```

而 `facts.ts:9` 的 `evidenceUrls()` 是：

```ts
return [...new Set([data.url, data.final_url, data.target, ...(Array.isArray(data.urls) ? data.urls : [])]
  .filter((v): v is string => typeof v === "string" && /^https?:\/\//i.test(v)))];
```

`katana.crawl` 的结果里 `data.urls` 是「爬虫在 HTML 里**看到**的链接」（最多 500 条，含全部跨域外链），
`recon.*` 的 `data.target` 只是回显入参。于是：

| 发现方式 | 旧行为 |
|---|---|
| `katana.crawl` 的 `urls` | **全部进图**，标 `requested:true / origin:"request"`，绕过 `inScope` |
| `browser.open` 的 `links` | 走发现分支 → 被 `inScope` 拦进 `skipped` |

同一个 URL，用 katana 抓就「已请求过」，用 browser 抓就被丢掉。
**墙的形状不由语义决定，由工具返回的字段名决定。**

### 后果链（都对应到具体代码）

1. `builder.ts:344` 推导状态 → 500 个假端点全部 `testing`（「我打过了」）；
2. `hypotheses.ts:99 cannotLocateObject()` 对 `origin==="request"` 不走被动 404 判据 → 跨域 404 节点照样派 IDOR 假设；
3. `analyze.ts:165 verified()` 要求 `untested` → 这些节点永远进不了「没动过的块」，Observer 的裂图告警失真；
4. `evidence-value` 把 500 条假新端点算成进展 → 焦点预算被白白续命；
5. `skipped` 被静默丢弃（`desk.ts:767` 的入参类型里根本没有这个字段）→ 模型不知道自己错过了什么面。

---

## 二、新契约

`src/blackbox/graph/types.ts` 新增：

```ts
/**
 * 端点证据的来源——图上**事实层**的唯一口径。
 *
 * 之前 `requested:true` 被当成"这个 URL 在工具结果里出现过"，于是 `katana.crawl`
 * 一次返回的 500 条外链、`recon.*` 的 items、`browser.open` 的页脚链接，全部被标成
 * "本次真的请求过"，状态直接推到 testing（见 2026-11-03 的取证：
 * `desk.ts` 的 `evidenceUrls()` 把 `data.urls` 整批塞进 `requested: true`）。
 * 后果是 `cannotLocateObject()`（hypotheses.ts）不再对 404 生成越权假设、
 * `verified()`（analyze.ts）把假端点算进"没动过的块"、证据增益被 500 条假新端点灌满。
 *
 * 现在把两个语义拆开：
 *   - `request`   ：**本 agent 亲手发出了 HTTP 请求**，`status_code` 是这次响应的真实值
 *                   （只有 graph/evidence.ts 的 RESPONSE_TOOLS 能产出）。
 *   - `discovery` ：从工具输出里**看到**了它（爬虫、字典命中、页面链接、Burp 历史…），没请求过。
 *   - `seed`      ：用户给的种子（import / 候选导入）。
 *   - `derived`   ：从 JS / 证书 / robots / 配置文件里推出来的。
 *
 * 不变量（由 `assertEvidenceContract()` 强制）：
 *   1. `origin === "request"` **当且仅当** 证据携带 requested=true；
 *   2. `origin === "request"` 必须带 `status_code`，或显式 `status_unknown`（扫描器类工具
 *      确实发了包，但结果 schema 不含状态码——这种情况必须写明"不知道"，而不是编一个）。
 */
export type NodeOrigin = "request" | "discovery" | "seed" | "derived";

/** 一条证据为什么没进图（跨注册域被挡下）：只落事件，不进节点。 */
export type SkippedReason = "out_of_scope" | "registrable_mismatch" | "blacklisted";

export type SkippedRecord = {
  url: string;
  reason: SkippedReason;
  /** 判定时用的锚点主机（会话目标或本次作用页面）。 */
  anchor: string;
  /** 是谁发现它的（父页面 / 父节点），便于复盘"从哪条链上漏掉的"。 */
  parent?: string;
};
```

不变量由 `assertEvidenceContract()` 强制：

```ts
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
```

---

## 三、75 个工具的归因表

| 等级 | 数量 | 工具 |
|---|---|---|
| `response`（真发过请求，有真实状态码） | 9 | `browser.open`、`browser.screenshot`、`http.request`、`burp.request`、`http.diff`、`burp.send`、`burp.sitemap_add`、`recon.http_probe`、`recon.race_condition` |
| `probe`（发了包，schema 无状态码 → status_unknown） | 13 | `burp.repeater`、`burp.send_batch`、`burp.scan`、`burp.crawl`、`burp.intruder_send`、`burp.websocket`、`recon.nuclei`、`recon.parameters`、`recon.xss`、`recon.sql`、`recon.graphql`、`recon.cms`、`recon.tls` |
| `discovery`（只是看到：爬虫/字典/站点地图/JS 抽取） | 16 | `katana.crawl`、`burp.history`、`burp.sitemap`、`burp.entry`、`burp.issues`、`burp.sitemap_issues`、`burp.scan_issues`、`burp.ws_history`、`browser.network`、`recon.subdomains`、`recon.dns`、`recon.historical_urls`、`recon.js_endpoints`、`recon.secrets`、`recon.content_discovery`、`recon.api_routes` |
| `none`（不碰目标 HTTP 面） | 37 | `browser.close`、`browser.storage`、`browser.tab`、`evidence.read`、`burp.check`、`burp.scope`、`burp.intercept`、`burp.decoder`、`burp.organizer`、`burp.collab_generate`、`burp.collab_poll`、`burp.scan_status`、`burp.scan_stop`、`burp.info`、`burp.control`、`burp.options`、`burp.cookies`、`burp.storage`、`burp.scope_edit`、`burp.scan_report`、`burp.intruder`、`burp.compare`、`burp.convert`、`burp.proxy_rule`、`burp.bchecks`、`recon.ports`、`recon.interactsh`、`recon.jwt`、`recon.sast`、`recon.wordlists`、`recon.scan_profile`、`recon.traffic_diff`、`exec.python`、`exec.bash`、`fs.list`、`fs.read`、`fs.grep` |

设计口径：

- **能产出 `origin:"request"` 的只有 9 个 response 工具 + 13 个 probe 工具**，其余一律不许；
- probe 类（nuclei / dalfox / sqlmap / arjun / testssl / wpscan / graphql-cop / send_batch / repeater /
  scan / crawl / intruder_send / websocket）**确实发了包，但结果 schema 没有状态码**，
  所以显式标 `status_unknown: true` —— 状态推进到 `testing`，但**绝不编一个 200**；
- 未登记的工具按 `none` 处理；测试断言「四个集合的并集 == `BLACKBOX_TOOL_NAMES`（75）」，
  以后加工具忘了归类会立刻变红；
- `burp.sitemap` / `burp.history` 的条目自带 status，那是**代理观测到的**响应，不是本 agent 打的，
  所以 `origin` 仍是 `discovery`（状态码照抄，状态停在 `untested`）。

---

## 四、代码

### 4.1 `src/blackbox/graph/evidence.ts`（新增，全文）

```ts
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
```

### 4.2 `builder.ts`：scope 记录 + 事实层归一

```ts
  const skipped: SkippedRecord[] = [];
  const registrable = (host: string): string => host.split(".").filter(Boolean).slice(-2).join(".");
  const hostOf = (value: string): string => {
    const raw = String(value || "").replace(/^(ep|asset):/, "");
    try { return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname.toLowerCase(); } catch { return ""; }
  };
  const anchorHost = hostOf(String(input.parent || "")) || hostOf(String((input.endpoints || [])[0]?.url || ""));
  const inScope = (url: string): boolean => {
    if (!anchorHost) return true;
    const host = hostOf(url);
    if (!host) return true;
    return host === anchorHost || registrable(host) === registrable(anchorHost);
  };
  // 挡下不等于没发生（2026-11-03）：跨注册域的发现物以前被静默 continue 掉，
  // 事件流、统计、上下文里全都没有它，模型不知道自己错过了什么面。
  // 现在每条都带 reason/anchor/parent 记进返回值，由调用方落事件（不进节点，别撑爆 500 上限）。
  const skip = (url: string, parent?: string): void => {
    if (skipped.length >= 200) return;
    skipped.push({ url, reason: "out_of_scope", anchor: anchorHost, ...(parent ? { parent } : {}) });
  };

  for (const endpoint of input.endpoints || []) {
    // ── 事实层归一（2026-11-03）──
    // `requested` 是"这次真的发出过请求"的硬事实，`origin` 只是它的镜像：
    // 两者冲突时以 requested 为准（旧调用方只传 requested，不能因此炸会话）；
    // 但新调用方一旦显式写了 origin="request"，就必须满足契约（带状态码或 status_unknown）。
    const declared = String(endpoint.origin || "");
    const requested = endpoint.requested === true || declared === "request";
    const origin: NodeOrigin = requested ? "request" : "discovery";
    // 旧值（link/js/api/item）不丢，转存成 discovery_kind，供复盘与漂移巡检的人类视角使用。
    const discoveryKind = String(endpoint.discovery_kind || (declared && declared !== "request" ? declared : "")).slice(0, 16);
    if (declared === "request") {
      assertEvidenceContract({
        url: endpoint.url, origin, requested,
        ...(endpoint.status_code !== undefined ? { status_code: endpoint.status_code } : {}),
        ...(endpoint.status_unknown === true ? { status_unknown: true } : {}),
      });
    }
    // 只有非请求证据才做 scope 过滤：真发过的请求是事实，必须留痕。
    if (origin !== "request" && !inScope(endpoint.url)) {
      skip(endpoint.url, input.parent);
      continue;
    }
    const id = endpointNodeId(endpoint.url);
```

### 4.3 `builder.ts`：状态推导按证据来源，origin 只升不降

```ts
    // 状态推导按**证据来源**，不按"结果里出现过"（2026-11-03）：
    // 之前 `requested` 被 katana 的 urls 批量置真，500 个假端点全部落 testing，
    // 于是"打没打过"在图上不可分辨，假设与漂移巡检同时失真。
    const status: NodeStatus = (endpoint.blocked || wallOfEndpoint) ? "blocked" : origin === "request" ? "testing" : "untested";
    // origin 只升不降：已经真打过的节点，不会被后来的"发现"降级回 discovery。
    const nodeOrigin: NodeOrigin = origin === "request" || state.nodes[id]?.properties.origin === "request" ? "request" : "discovery";
    const props: NodeProperties = {
```

返回值改成带 reason/anchor/parent 的记录：

```ts
export function ingestToolResult(state: AttackGraphState, input: IngestInput): { newNodes: string[]; newEdges: string[]; deadEnds: string[]; candidates: string[]; skipped: SkippedRecord[] } {
```

### 4.4 `desk.ts`：证据归因入口（替代 `evidenceUrls` 批量置真）

```ts
            // ── 证据归因（2026-11-03）───────────────────────────────────────────────
            // 谁能产出 origin="request" 由 graph/evidence.ts 的归因表决定：只有真发了包的
            // 9 个 response 工具（browser.open / http.request / http.diff / burp.send /
            // recon.http_probe / recon.race_condition …）和 13 个 probe 工具（扫描器类，带
            // status_unknown）。以前这里用 evidenceUrls() 把 data.urls（katana 一次 500 条
            // 外链）整批标成 requested:true —— 图的事实层从那一刻起就是假的。
            const attribution = attributeEvidence({
              tool: request.tool, data, input: inputOfRequest, fallbackUrl: requestUrl,
            });
            // 2026-10-28 修正：发现物，任意工具的结果形，统一抽取（见 graph/extract.ts）。
            // 原来只认 data.urls/data.endpoints，于。recon.js_endpoints 。items、browser.open 。links
            // 全都没进。—。165 次调用之后图。42 个节。37 条边仍然全是 asset→endpoint。
            const discovery = attribution.discovery;
            // 请求签名：判"完全相同的一次重。（note.yun 那轮 43 次调用只。22 个唯一请求）。
            // WAF 墙：412/418/1020 或阻断页指纹（见 graph/extract.ts 。wallOf）。
            const wall = wallOf(data);
            // 路由不存在：与 WAF 墙分开记。墙是"挡住了"，这是"根本没这条路由"——
            // 后者绝不能生成越权假设（2026-11-02 m.ctrip.com 的 z9probe_notexist 白烧 3 轮）。
            const routeMissing = routeMissingOf(data);
            const parentUrl = String(requester || discovery.self[0] || data.url || "");
            // 暴力枚举工具（content_discovery/api_routes）的 items 是「字典命中」，不是观测到的端点。
            // catch-all 目标。113 条命中全是同一。302，建节点会让图裂。113 块（2026-10-28 实测）。
            // 它们改挂父节点的 candidates，等真的打过一次再。http.request 建出节点。
            const bruteForce = isCandidateTool(request.tool);
            const candidatePaths = bruteForce
              ? discovery.found.map(item => ({ url: candidatePathOf(item.url, parentUrl || undefined), note: request.tool }))
              : [];
            // 响应级判据（墙 / 路由不存在 / 签名 / 对象值）只对**单次交互**的工具成立：
            // http_probe 一次打 20 台主机、race_condition 一次发 20 条，用同一份 data 给每条
            // 证据盖同一个章，就是把"某一条被墙"说成"全部被墙"。
            const single = attribution.requests.length === 1 ? attribution.requests[0] : undefined;
            const graphEndpoints = [
              // ① 本次真的发出过请求的目标：状态码是**这次响应**的（probe 类显式标 status_unknown）。
              ...attribution.requests.map((item: RequestEvidence) => ({
                url: item.url,
                requested: true,
                origin: "request" as const,
                ...(item.status_unknown === true ? { status_unknown: true } : {}),
                ...(item.method ? { method: item.method } : {}),
                ...(item.status_code !== undefined ? { status_code: item.status_code } : {}),
                ...(item.content_length !== undefined ? { content_length: item.content_length } : {}),
                ...(single && item === single && typeof data.content_type === "string" ? { content_type: data.content_type } : {}),
                // 参数从请求里取：query/json/form 才是参数的真正来源（原来从响应里读，恒为空）。
                ...(paramsOf(inputOfRequest, item.url).length ? { params: paramsOf(inputOfRequest, item.url) } : {}),
                ...(item.status_code === 401 || item.status_code === 403 ? { auth_required: true, blocked: true } : {}),
                ...(single && item === single && wall ? { wall: wall.kind, blocked: true } : {}),
                // 路由不存在（网关 Not-Found-Route / 空壳 404）：只记属性，供假设生成器跳过。
                ...(single && item === single && routeMissing ? { route_missing: true } : {}),
                ...(single && item === single && requestSignature(inputOfRequest, item.url, request.tool)
                  ? { signature: requestSignature(inputOfRequest, item.url, request.tool) }
                  : {}),
                // 对象模型：把这次真实打过的 {id} 值记进图，双身份对照才有"同一对象"。
                ...(this.objectValuesFor(item.url).length ? { object_values: this.objectValuesFor(item.url) } : {}),
              })),
              // ② 本次挖到的端点（被动发现，不带状态码：没请求过就不编）。
              // 暴力枚举的产物不进这里（。candidates），否则就是「把字典当资产」。
              ...(bruteForce ? [] : discovery.found.map(item => ({
                url: item.url,
                origin: "discovery" as const,
                discovery_kind: item.kind,
                ...(item.method ? { method: item.method } : {}),
                ...(item.params?.length ? { params: item.params } : {}),
                ...(item.via ? { via: item.via } : {}),
                // burp.sitemap / burp.history 的条目自带状态码：有了它，被动发现也，已验证的。。
                ...(item.status !== undefined ? { status_code: item.status } : {}),
                ...(this.objectValuesFor(item.url).length ? { object_values: this.objectValuesFor(item.url) } : {}),
              }))),
            ];
```

### 4.5 `desk.ts`：`skipped` 落事件（模型可见，但不撑爆 500 上限）

```ts
            // 被挡下的发现物必须留痕（2026-11-03）：以前它们在 builder 里被静默 continue，
            // 事件流、统计、上下文全无踪影——模型根本不知道自己错过了什么面。
            // 只落事件不进节点：500 上限留给真正打得动的面。
            if (ingested.skipped.length) {
              const byReason: Record<string, number> = {};
              for (const record of ingested.skipped) byReason[record.reason] = (byReason[record.reason] || 0) + 1;
              const sample = ingested.skipped.slice(0, 5).map(record => record.url);
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-skipped",
                `历程：${ingested.skipped.length} 条发现物未入图（${Object.entries(byReason).map(([reason, count]) => `${reason}×${count}`).join("、")}）：${sample.join("、")}${ingested.skipped.length > sample.length ? " …" : ""}`,
                {
                  tool: request.tool, count: ingested.skipped.length, reasons: byReason,
                  sample, anchors: [...new Set(ingested.skipped.map(record => record.anchor))].slice(0, 5),
                });
            }
```

### 4.6 `analyze.ts`：漂移巡检认新的 origin

```ts
  const verified = (nodeId: string): boolean => {
    const node = state.nodes[nodeId];
    if (!node || !nodeId.startsWith("ep:")) return false;
    if (node.status !== "untested") return false;
    const props = node.properties || {};
    // 真发过请求 → 一定有状态码；被动发现（link/js/api）也算观测面。
    // 但 hits 不能当判据：字典命中入库时也会累加 hits（旧图上每条都是 hits=1）。
    if (props.status_code !== undefined) return true;
    const origin = String(props.origin || "");
    // 2026-11-03：`origin` 收敛成 request / discovery / seed / derived 四个值。
    // 旧的 link/js/api/item 仍要认——历史 checkpoint 里的节点带着它们，重建前不能被判成"没观测过"。
    return origin === "request" || origin === "discovery" || origin === "seed" || origin === "derived"
      || origin === "link" || origin === "js" || origin === "api";
  };
```

### 4.7 测试：`test/graph-evidence-contract.test.ts`（新增，全文）

```ts
/**
 * 证据契约（2026-11-03）——攻击历程图的**事实层**。
 *
 * 起因：`desk.ts` 原来把 `[url, final_url, target, ...data.urls]` 整批标成
 * `requested: true / origin: "request"`。而 `katana.crawl` 的 `data.urls` 是爬虫在 HTML 里
 * **看到**的链接（一次最多 500 条，含全部跨域外链）。后果链：
 *   builder 状态推到 testing → `cannotLocateObject()` 不再对 404 生成越权假设 →
 *   `verified()` 把这些节点算成"没动过的块" → 证据增益被假新端点灌满。
 *
 * 这组用例钉住两条不变量：
 *   1. `origin === "request"` ⟺ `requested === true`；
 *   2. `origin === "request"` 必须带 status_code，或显式 status_unknown。
 */
import { describe, expect, it } from "vitest";
import { BLACKBOX_TOOL_NAMES } from "../src/blackbox/tools.js";
import {
  DISCOVERY_TOOLS, NETWORKLESS_TOOLS, PROBE_TOOLS, RESPONSE_TOOLS,
  assertEvidenceContract, attributeEvidence, toolEvidenceClass,
} from "../src/blackbox/graph/evidence.js";
import { endpointNodeId, graphState, ingestToolResult } from "../src/blackbox/graph/builder.js";
import type { AttackGraphState } from "../src/blackbox/graph/types.js";

function fresh(): AttackGraphState {
  return graphState(undefined);
}

/** 复刻 desk 的搬运方式：归因结果原样灌进 builder。 */
function ingestAttribution(
  state: AttackGraphState,
  args: { tool: string; data: Record<string, unknown>; input?: Record<string, unknown>; fallbackUrl?: string; parent?: string },
) {
  const attribution = attributeEvidence({
    tool: args.tool, data: args.data, input: args.input, fallbackUrl: args.fallbackUrl,
  });
  const ingested = ingestToolResult(state, {
    tool: args.tool,
    round: 1,
    ...(args.parent ? { parent: args.parent } : {}),
    endpoints: [
      ...attribution.requests.map(item => ({
        url: item.url, requested: true, origin: "request" as const,
        ...(item.status_unknown === true ? { status_unknown: true } : {}),
        ...(item.status_code !== undefined ? { status_code: item.status_code } : {}),
      })),
      ...attribution.discovery.found.map(item => ({
        url: item.url, origin: "discovery" as const, discovery_kind: item.kind,
        ...(item.status !== undefined ? { status_code: item.status } : {}),
      })),
    ],
    evidence_id: "ev-1",
  });
  return { attribution, ingested };
}

describe("归因表覆盖全部 75 个工具", () => {
  it("四个集合互不重叠，且并集等于工具清单", () => {
    const groups = [RESPONSE_TOOLS, PROBE_TOOLS, DISCOVERY_TOOLS, NETWORKLESS_TOOLS];
    const all = groups.flatMap(group => [...group]);
    expect(new Set(all).size, "同一个工具被归进了两个集合").toBe(all.length);
    expect(new Set(all), "归因表漏了工具或多出了不存在的工具").toEqual(new Set(BLACKBOX_TOOL_NAMES));
    expect(all.length).toBe(75);
  });

  it("每类工具拿到正确的等级", () => {
    expect(toolEvidenceClass("http.request")).toBe("response");
    expect(toolEvidenceClass("katana.crawl")).toBe("discovery");
    expect(toolEvidenceClass("recon.nuclei")).toBe("probe");
    expect(toolEvidenceClass("fs.read")).toBe("none");
    // 未登记的名字一律 none：宁可少记，不可错记。
    expect(toolEvidenceClass("some.future.tool")).toBe("none");
  });
});

describe("katana.crawl 不得产出 requested:true", () => {
  it("urls 全部是 discovery，状态停在 untested，且不复制爬虫元信息", () => {
    const state = fresh();
    const { attribution } = ingestAttribution(state, {
      tool: "katana.crawl",
      data: {
        target: "https://a.test/",
        urls: ["https://a.test/x", "https://a.test/api/user/1", "https://evil.test/z"],
        items: ["https://a.test/x", "https://a.test/api/user/1", "https://evil.test/z"],
        count: 3,
      },
      input: { url: "https://a.test/" },
      parent: endpointNodeId("https://a.test/"),
    });

    expect(attribution.requests).toHaveLength(0);
    for (const id of ["ep:a.test/x", "ep:a.test/api/user/{id}"]) {
      const node = state.nodes[id]!;
      expect(node, id).toBeDefined();
      expect(node.properties.origin, id).toBe("discovery");
      expect(node.status, id).toBe("untested");
      expect(node.properties.status_code, id).toBeUndefined();
    }
    // 跨域外链不进图（不撑 500 上限），但必须留痕。
    expect(state.nodes["ep:evil.test/z"]).toBeUndefined();
    expect(attribution.discovery.found.some(item => item.url === "https://evil.test/z")).toBe(true);
  });
});

describe("browser.open：主页面是请求，链接是发现", () => {
  it("final_url 带真实状态码；links 进图但不叫 requested", () => {
    const state = fresh();
    const { attribution } = ingestAttribution(state, {
      tool: "browser.open",
      data: {
        requested_url: "https://a.test/login",
        final_url: "https://a.test/home",
        status: 200,
        links: [{ text: "order", href: "https://a.test/order" }, { text: "外链", href: "https://other.org/x" }],
        forms: [],
      },
      input: { url: "https://a.test/login" },
      parent: endpointNodeId("https://a.test/login"),
    });

    // 主证据只认 final_url（跟随重定向后的落点），不把 requested_url 也算一次响应。
    expect(attribution.requests.map(item => item.url)).toEqual(["https://a.test/home"]);
    expect(attribution.requests[0]!.status_code).toBe(200);

    const home = state.nodes["ep:a.test/home"]!;
    expect(home.status).toBe("testing");
    expect(home.properties.origin).toBe("request");
    expect(home.properties.status_code).toBe(200);

    const order = state.nodes["ep:a.test/order"]!;
    expect(order.status).toBe("untested");
    expect(order.properties.origin).toBe("discovery");
    expect(order.properties.discovery_kind).toBe("link");
    // 没请求过就不编状态码——这是旧代码最要命的一处。
    expect(order.properties.status_code).toBeUndefined();

    // 跨域链接：被 scope 挡下，但要带 reason/anchor/parent 记进 skipped。
    expect(state.nodes["ep:other.org/x"]).toBeUndefined();
  });

  it("skipped 带 reason / anchor / parent，而不是静默丢弃", () => {
    const state = fresh();
    const { ingested } = ingestAttribution(state, {
      tool: "browser.open",
      data: {
        final_url: "https://a.test/",
        status: 200,
        links: ["https://a.test/ok", "https://other.org/no"],
      },
      input: { url: "https://a.test/" },
      parent: endpointNodeId("https://a.test/"),
    });
    expect(state.nodes["ep:a.test/ok"]).toBeDefined();
    expect(ingested.skipped).toContainEqual(
      expect.objectContaining({ url: "https://other.org/no", reason: "out_of_scope", anchor: "a.test" }),
    );
  });
});

describe("probe 类工具：确实发过包，但拿不到状态码", () => {
  it("recon.nuclei 的 matched-at 是 request + status_unknown，不编 200", () => {
    const state = fresh();
    const { attribution } = ingestAttribution(state, {
      tool: "recon.nuclei",
      data: {
        target: "https://a.test/x?id=1",
        items: ["https://a.test/x?id=1"],
        findings: [{ url: "https://a.test/x?id=1", template_id: "cve-2024-0001", severity: "high" }],
      },
      input: { url: "https://a.test/x?id=1" },
    });

    expect(attribution.requests).toHaveLength(1);
    expect(attribution.requests[0]!.status_unknown).toBe(true);
    expect(attribution.requests[0]!.status_code).toBeUndefined();
    // 已经算作请求的 URL 不再重复标成 discovery。
    expect(attribution.discovery.found.some(item => item.url === "https://a.test/x?id=1")).toBe(false);

    const node = state.nodes["ep:a.test/x"]!;
    expect(node.status).toBe("testing");
    expect(node.properties.origin).toBe("request");
    expect(node.properties.status_code).toBeUndefined();
  });
});

describe("http.diff：两次请求都是真的", () => {
  it("baseline 与 variant 各带自己的状态码", () => {
    const attribution = attributeEvidence({
      tool: "http.diff",
      data: {
        url: "https://a.test/api/order/1",
        variant_url: "https://a.test/api/order/1",
        baseline: { status: 403, body_bytes: 120 },
        variant: { status: 200, body_bytes: 4096 },
        verdict: "different",
      },
      input: { url: "https://a.test/api/order/1" },
    });
    expect(attribution.requests).toHaveLength(1);
    // 同址两次（baseline 403 → variant 200）：节点记**最后一次**响应——
    // 越权对照里有意义的是"换凭证之后"的那次。
    expect(attribution.requests[0]!.status_code).toBe(200);
  });
});

describe("请求失败（超时/连接被拒）不得抛错", () => {
  it("http.request 没有 status 时落 status_unknown，而不是让契约守卫炸掉工具循环", () => {
    // 2026-11-03 实测回归：这条路径一旦抛错，会被 desk 的工具循环吞成 tool-error，
    // 连带把 stage 记账、action-deferred 事件全部改掉（blackbox-tool-access 三条用例当场变红）。
    const attribution = attributeEvidence({
      tool: "http.request",
      data: { url: "https://a.test/slow", headers: {}, body: "", body_bytes: 0 },
      input: { url: "https://a.test/slow" },
    });
    expect(attribution.requests).toHaveLength(1);
    expect(attribution.requests[0]!.status_unknown).toBe(true);

    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: attribution.requests.map(item => ({
        url: item.url, requested: true, origin: "request" as const, status_unknown: true,
      })),
    });
    expect(state.nodes["ep:a.test/slow"]!.status).toBe("testing");
    expect(state.nodes["ep:a.test/slow"]!.properties.status_code).toBeUndefined();
  });

  it("工具结果里没有 URL 时不产出任何证据（不编节点）", () => {
    const attribution = attributeEvidence({
      tool: "http.request",
      data: { error: "connect ECONNREFUSED" },
      input: {},
    });
    expect(attribution.requests).toEqual([]);
  });
});

describe("契约守卫：写错归因会炸，而不是悄悄污染图", () => {  it("requested=true 但 origin=discovery → 抛错", () => {
    expect(() => assertEvidenceContract({
      url: "https://x.test/", origin: "discovery", requested: true,
    })).toThrow(/contract violation/);
  });

  it("origin=request 但 requested=false → 抛错", () => {
    expect(() => assertEvidenceContract({
      url: "https://x.test/", origin: "request", requested: false, status_code: 200,
    })).toThrow(/contract violation/);
  });

  it("origin=request 但没有状态码也没有 status_unknown → 抛错", () => {
    expect(() => assertEvidenceContract({
      url: "https://x.test/", origin: "request", requested: true,
    })).toThrow(/contract violation/);
  });

  it("builder 对新式调用方（显式 origin=request）执行同一套守卫", () => {
    const state = fresh();
    expect(() => ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://a.test/x", origin: "request", requested: true }],
    })).toThrow(/contract violation/);
  });

  it("旧调用方（只传 requested，没有 origin）仍被归一，不炸会话", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "recon.content_discovery",
      endpoints: [{ url: "https://a.test/x", requested: true }],
    });
    expect(state.nodes["ep:a.test/x"]!.status).toBe("testing");
    expect(state.nodes["ep:a.test/x"]!.properties.origin).toBe("request");
  });
});
```

---

## 五、验证

| 项 | 结果 |
|---|---|
| `npx tsc -p tsconfig.json --noEmit` | 0 error |
| `npm run build:server` | 产出 `dist/blackbox/graph/evidence.js`（17,230 B） |
| 归因表校验（从 dist 读） | response 9 / probe 13 / discovery 16 / none 37 = **75** |
| 新增契约测试 | **14 passed** |
| 图相关 11 个测试文件 | **135 passed** |
| 全量回归 | **994 passed / 3 failed / 2 skipped（999）** |

剩下 3 条失败全在 asset / candidate 面（`test/assets`、`test/candidates` ×2），与本次改动无关，
改动前就在红——是「全局 fetch 打桩 + 资产归一」这两处的既有波动。

### 过程中真踩到的坑（值得记住）

第一版写完后 `test/blackbox-tool-access`（2 条）、`test/blackbox.test`、`test/blackbox-lifecycle` 突然变红。
根因：`http.request` **超时 / 连接被拒**时 `data.status` 是 undefined，`assertEvidenceContract`
直接抛错，异常被 desk 的工具循环吞成 `tool-error`，把 stage 记账和 `action-deferred` 事件全改掉了。

结论：**「发了但拿不到状态」是数据，不是契约违规**。response 类工具缺状态码时一律落
`status_unknown: true`，并补了一条回归测试钉住（`http.request 没有 status 时落 status_unknown`）。

---

## 六、刻意没做的

这次只动 `requested` / `origin` 这一个事实层，之前审计列出的其它 P0 一个都没碰：

1. **`registrable()` 取后两段**（`builder.ts:324`、`tools.ts:710`）—— `a.com.cn` 与 `b.com.cn` 被误判同域放行、
   `foo.aliyuncs.com` 与 `aliyun.com` 被误判跨域拦截。要修得引 PSL（`tldts`），是独立一步。
2. **`inScope` 的锚点会漂移** —— 锚点是「本次请求的页面」而不是会话目标，逐跳衰减。
3. **三处节点排序口径不一致**（`prune` / `serialize` / `visual` 各写一份 rank）。
4. **`origin` 仍不在 `serialize.ts` 的 `PROP_KEYS` 里** —— 模型看得见 `status`（untested/testing），
   但看不见判定依据本身。
5. **`skipped` 只落事件，没进累计统计**（`progress.state` 没加字段），Observer 暂时读不到「这一轮挡了多少」。
6. **parked 池 / relation 分级 / infra 后缀**（`aliyuncs.com`、`cloudfront.net` 这类高价值面）—— 策略层，
   排在事实层之后。

按依赖顺序，下一步应该做 1（纯 bug、零策略变更），再考虑 2 和 6。

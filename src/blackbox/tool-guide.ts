/**
 * 工具入参指南：把一次「格式被拒」变成一次「Few-Shot 教学」。
 *
 * 背景（2026-10-28 实测，见 docs/reports/2026-10-28-blackbox-timeline.md §2 R3）：
 * `protocol.ts` 的 `toolInputSchema` 是 `.strict()`，模型写了一个不存在的键
 * （`baseline`/`variant`/`label`、`pattern` 放错层），整条 `tool_request` 被丢弃，
 * 而回执只有一句「Unrecognized key(s)」。模型知道"错了"，但不知道"该写什么"，
 * 于是连撞三轮、三条请求一次都没发出。
 *
 * 这个模块只做一件事：给定工具名 + 被拒的键，返回**该工具真正接受的键**和**一条最小示例**。
 * 键来自执行器实现（tools.ts / workspace.ts），不是猜的：
 *   http.request   → tools.ts httpTool()      （url/method/headers/body/…/anonymous）
 *   http.diff      → tools.ts httpDiffTool()  （url/variant/variant_url/timing_threshold_ms）
 *   burp.send      → tools.ts case "burp.send"（url/method/headers/body/follow_redirects）
 *   fs.list/read/grep → workspace.ts           （path/max_bytes/pattern/max_matches）
 *   evidence.read  → tools.ts evidenceReadTool（evidence_id/tool/offset/limit/width）
 */

import { toolParamHint } from "./tool-params.js";

export type ToolGuide = {
  tool: string;
  /** 该工具 input 里真正被读取的键。 */
  allowed_keys: string[];
  /** 一条最小可用示例（模型可直接照抄改 URL）。 */
  example: Record<string, unknown>;
  /** 额外说明：常见误区、替代工具。 */
  note?: string;
};

const GUIDES: Record<string, Omit<ToolGuide, "tool">> = {
  "http.request": {
    allowed_keys: ["url", "method", "headers", "body", "json", "form", "multipart", "anonymous", "use_jar", "token", "cookies", "follow_redirects", "timeout_ms"],
    example: { url: "https://TARGET/ENDPOINT", method: "GET", headers: { accept: "*/*" }, anonymous: true },
    note: "受限头（host/connection/transfer-encoding…）会被丢弃，结果里带 headers_dropped；Host 改写请用 burp.send。",
  },
  "http.diff": {
    allowed_keys: ["url", "variant", "variant_url", "headers", "method", "cookie", "anonymous", "timing_threshold_ms"],
    example: { url: "https://TARGET/a", method: "GET", variant: { url: "https://TARGET/a", headers: { "x-forwarded-host": "evil.example" } } },
    note: "对照写在 variant 对象里；没有 baseline/variant_url 之外的顶层对照键，playbook 里的 baseline_self/diff_auth 是步骤 id 不是参数。",
  },
  "burp.send": {
    allowed_keys: ["url", "method", "raw_method", "headers", "body", "follow_redirects"],
    example: { url: "http://TARGET/", method: "GET", headers: { Host: "evil.example" } },
    note: "唯一能真正改写 Host 的通道（Burp 原始报文）；标准七动词之外的非常用动词写 raw_method（如 NONSENSE / DEBUG / TRACE），WAF 按方法分流时用它试放行。",
  },
  "burp.repeater": {
    allowed_keys: ["url", "method", "headers", "body", "tab"],
    example: { url: "http://TARGET/", method: "GET", headers: { Host: "evil.example" }, tab: "nianyun" },
  },
  "burp.request": {
    allowed_keys: ["url", "method", "headers", "body", "follow_redirects"],
    example: { url: "http://TARGET/", method: "GET" },
  },
  "fs.list": {
    allowed_keys: ["path"],
    example: { path: "." },
  },
  "fs.read": {
    allowed_keys: ["path", "max_bytes"],
    example: { path: "findings.md", max_bytes: 200000 },
  },
  "fs.grep": {
    allowed_keys: ["pattern", "path", "max_matches"],
    example: { pattern: "api/[a-z0-9_/-]+", path: ".", max_matches: 50 },
    note: "正则写在 pattern（顶层），目录写在 path；不要再塞 pattern 到 params。",
  },
  "evidence.read": {
    allowed_keys: ["evidence_id", "tool", "offset", "limit", "width"],
    example: { evidence_id: "ev-0000000000000000", offset: 0, limit: 500 },
    note: "读已落账证据的完整 body 用它，不要重新发一次请求。",
  },
};

/** 通用兜底：只有这些键是可以安全猜测的，其余要查工具文档。 */
const GENERIC: Omit<ToolGuide, "tool"> = {
  allowed_keys: ["url", "params"],
  example: { url: "https://TARGET/", params: {} },
  note: "外部扫描器（recon.* / katana.* / nuclei）不接受 domain、hostname、record_types 这类自造键：目标用 url（留空则用会话资产），其余参数放进 input.params。**params 只有部分工具支持**（见各工具说明），不支持的工具写了会被拒 unknown parameter。",
};

/**
 * recon.* / katana.* / nuclei.* 的真实入参：按工具逐个写，不再"整族一句话"。
 *
 * 2026-11-06 实测事故（会话 bdd308655a4c65b8）：
 *   模型给 recon.content_discovery 传 `threads`，被 schema 摘掉，回执照旧写
 *   「可用：url, params」+「并发由该工具自身决定」——模型据此得出的确切结论是
 *   "这本字典工具既不能调并发、也没有别的旋钮"，那一轮之后再没碰过它。
 *   同一场给 katana 传 `duration`/`headless`，同样只被告知 url/params。
 * 结果：21 场会话里 recon.content_discovery 只被调用 1 次，其余全是 http.request 手挑路径
 * （而内置 paths.txt 里本来就有 .git/config、.env、druid/index.html）。
 *
 * 原则：**说明书只写执行器真的读的键**；params 的键与取值范围由 `tool-params.ts`
 * 渲染，加参数只改那张表，说明书不会落后于执行器。
 */
type ReconSpec = { keys: string[]; example: Record<string, unknown>; note?: string };

/** 外部 CLI 通用的三个键：目标、管道来源、超时。 */
const BASE = ["url", "source", "timeout_ms"];

const RECON_SPECS: Record<string, ReconSpec> = {
  "recon.content_discovery": {
    keys: [...BASE, "wordlist", "wordlist_root", "headers", "threads"],
    example: { url: "https://TARGET/", wordlist: "paths.txt", params: { extensions: "js,json,php", threads: 20 } },
    note: "路径/目录/后台/备份/接口文档的批量发现就靠这一枪：默认字典是内置 paths.txt（290 条，含 .git/config、.env、actuator、druid、swagger 等）；换字典先 recon.wordlists 看有哪些，再填 wordlist（写文件名即可，不必写绝对路径）；threads 折进 -t，rate 控制每秒请求数。**不要用 http.request 逐条手试字典**。",
  },
  "recon.api_routes": {
    keys: [...BASE, "wordlist", "wordlist_root", "headers"],
    example: { url: "https://TARGET/", wordlist: "paths.txt" },
    note: "kiterunner 打 API 路由，字典按 api 类别挑。已知 /v2/ 这类前缀时把前缀写进 url 更准。",
  },
  "recon.nuclei": {
    keys: [...BASE, "headers"],
    example: { url: "https://TARGET/", params: { severity: "critical,high", tags: "exposure,misconfig", timeout_s: 15 } },
  },
  "nuclei.scan": {
    keys: [...BASE, "headers"],
    example: { url: "https://TARGET/", params: { severity: "critical,high" } },
  },
  "recon.subdomains": {
    keys: [...BASE],
    example: { url: "https://TARGET/" },
    note: "目标取 url 的 host；子域结果可用 input.source 接给 recon.http_probe 批量探活，不必手抄 URL。",
  },
  "recon.dns": {
    keys: [...BASE],
    example: { url: "https://TARGET/" },
    note: "记录类型固定（A/CNAME），不接受 record_types / domain 这类自造键。",
  },
  "recon.http_probe": {
    keys: [...BASE, "headers", "threads"],
    example: { url: "https://TARGET/", params: { ports: "80,443,8080" } },
  },
  "recon.ports": {
    keys: [...BASE, "threads"],
    example: { url: "https://TARGET/", params: { ports: "80,443,8080,8443,9000" } },
  },
  "recon.historical_urls": {
    keys: [...BASE, "provider", "headers"],
    example: { url: "https://TARGET/", provider: "gau" },
    note: "provider 可写 gau 或 waybackurls（后者需配置 WAYBACKURLS_PATH）。历史 URL 常含已下线接口与参数，是并行爬取的补充。",
  },
  "recon.parameters": {
    keys: [...BASE],
    example: { url: "https://TARGET/api/item?id=1" },
    note: "arjun 扫隐藏参数，直接对带参接口用；结果是参数名清单，后续用 http.diff 验证它是否影响响应。",
  },
  "recon.js_endpoints": {
    keys: [...BASE, "urls"],
    example: { url: "https://TARGET/", urls: ["https://TARGET/static/app.js"] },
    note: "不给 urls 时自动解析页面 script 标签；source 可接 katana 的产物。",
  },
  "recon.tls": {
    keys: [...BASE],
    example: { url: "https://TARGET/" },
  },
  "recon.xss": {
    keys: [...BASE, "headers"],
    example: { url: "https://TARGET/search?q=1" },
  },
  "recon.sql": {
    keys: [...BASE, "headers", "cookies"],
    example: { url: "https://TARGET/api/item?id=1", params: { level: 2, risk: 1 } },
    note: "带参 URL 直接给（?id=1）；POST 体用 params.data，指定参数用 params.param。--os-shell 等交互式能力默认关闭。",
  },
  "recon.jwt": {
    keys: [...BASE, "token"],
    example: { url: "https://TARGET/", token: "eyJhbGciOi..." },
    note: "必须给 input.token（从 cookie / Authorization 里取），没有 token 无法分析。",
  },
  "recon.graphql": {
    keys: [...BASE],
    example: { url: "https://TARGET/graphql" },
  },
  "recon.cms": {
    keys: [...BASE, "headers", "cookies"],
    example: { url: "https://TARGET/" },
    note: "只对 WordPress 有意义（wpscan）；非 WP 会返回 not_wordpress，这不是失败。",
  },
  "recon.secrets": {
    keys: ["url", "path"],
    example: { path: "artifacts" },
    note: "扫的是**本地工作区目录**，必须给 input.path（相对会话工作区）；给 URL 会被直接拒。取回 JS 后先用 fs.read 落盘再扫。",
  },
  "recon.sast": {
    keys: ["url", "path", "timeout_ms"],
    example: { path: "." },
    note: "同上：path 是本地目录，不是 URL。",
  },
  "recon.wordlists": {
    keys: [],
    example: {},
    note: "无入参：直接调用就返回已挂载的字典与 nuclei 模板目录（名字/路径/大小/行数）。选字典前先看它，不要猜路径。",
  },
  "recon.scan_profile": {
    keys: ["timeout_s", "rate_limit", "katana_depth", "katana_duration_s", "retries"],
    example: { timeout_s: 30, rate_limit: 20, katana_depth: 5 },
    note: "这些键在**顶层**（不是 params），改一次对后续扫描持续生效；一个键都不传=只读当前值。",
  },
  "katana.crawl": {
    keys: ["url", "source", "depth", "duration_seconds", "timeout_ms"],
    example: { url: "https://TARGET/", depth: 5, duration_seconds: 120 },
    note: "深度用 depth（1-8）、时长用 duration_seconds（5-300）；不写就按 scan_profile 的 katana_depth / katana_duration_s。写成 duration 会被摘掉。",
  },
  "recon.race_condition": {
    keys: ["url", "requests", "count", "method", "headers", "body", "via", "concurrency", "timeout_ms"],
    example: { url: "https://TARGET/api/coupon", method: "POST", count: 20, concurrency: 20 },
    note: "并发发包是控制面一等能力（不经 Burp，via=burp 时走 CONNECT 隧道）；requests 是逐条报文（method/path/headers/body），给它就不用 count。串行 for 循环打 20 次不算竞态。",
  },
  "recon.interactsh": {
    keys: ["action", "server", "token", "wait_seconds", "runtime_id"],
    example: { action: "start" },
    note: "三个动作：start 取 payload（进 evidence 的 url 就是回连地址）、poll 收回连、stop 收尾。无回显类漏洞（SSRF/盲注/RCE）靠它确认。",
  },
};

for (const [tool, spec] of Object.entries(RECON_SPECS)) {
  const hint = toolParamHint(tool);
  GUIDES[tool] = {
    allowed_keys: hint ? [...spec.keys, "params"] : [...spec.keys],
    example: spec.example,
    note: [spec.note, hint
      ? `input.params 只认：${hint}`
      : "该工具不接受 input.params（写了会被拒 unknown parameter）"]
      .filter(Boolean).join("；"),
  };
}

/**
 * 枚举类工作的强制分工。给模型看的不只是"能传什么"，还有"该用谁"：
 * 21 场会话里 67 次手工 http.request 挑出 27 个端点，换一次 content_discovery 就够。
 */
export const ENUMERATION_RULE = "路径/目录/后台/备份/接口文档的枚举**只用 recon.content_discovery**（一枪打完默认 290 条字典），"
  + "子域用 recon.subdomains、API 路由用 recon.api_routes、页面内链接用 katana.crawl；"
  + "严禁用循环 http.request / browser.open 逐条猜路径（每试一条就烧 1 次调用预算，且永远覆盖不全）；"
  + "手工探测只允许「已知 1-2 个具体文件、要确认它还在不在」这种场景。";

// browser.*：实测模型想给 browser.open 传 screenshot、给 browser.storage 传 include/types。
// 浏览器工具的真实键是下面这些，别让它继续撞墙。
GUIDES["browser.open"] = { allowed_keys: ["url", "actions", "evaluate", "new_tab", "wait_until", "wait_timeout_ms", "follow_redirects", "timeout_ms"],
  example: { url: "https://TARGET/", wait_until: "networkidle" }, note: "要截图用 browser.screenshot；要读 storage 用 browser.storage，browser.open 没有 screenshot / include / types 这些键。actions[].type 只能是 click/fill/press/select/check/uncheck/hover/wait/scroll（写别的值整条请求会被拒）" };
GUIDES["browser.screenshot"] = { allowed_keys: ["url", "full_page", "width", "actions", "wait_until", "wait_timeout_ms", "timeout_ms"],
  example: { url: "https://TARGET/", full_page: true } };
GUIDES["browser.storage"] = { allowed_keys: ["url", "read", "key", "value", "clear", "reset", "local_storage", "session_storage", "actions", "wait_until"],
  example: { url: "https://TARGET/", read: true }, note: "读全量用 read:true；写单键用 key/value；清空用 clear:true；没有 include / types" };

/** 该工具的入参指南；未知工具返回通用兜底。 */
export function toolGuide(tool: string, droppedKeys: string[] = []): ToolGuide {
  const name = String(tool || "").trim();
  const guide = GUIDES[name];
  const rejected = droppedKeys.length ? `被拒的键：${droppedKeys.join(", ")}` : "";
  if (!guide) {
    return { tool: name, ...GENERIC, ...(rejected ? { note: `${GENERIC.note} ${rejected} —— 这些键该改写进 params 或干脆不用。` } : {}) };
  }
  return {
    tool: name,
    allowed_keys: guide.allowed_keys,
    example: guide.example,
    ...(guide.note || rejected ? { note: [guide.note, rejected].filter(Boolean).join("；") } : {}),
  };
}

/** 一行可读的教学文本，直接进 summary / 事件 / 下一轮上下文。 */
export function toolGuideText(tool: string, droppedKeys: string[] = []): string {
  const guide = toolGuide(tool, droppedKeys);
  const keys = guide.allowed_keys.join(", ");
  const example = JSON.stringify(guide.example);
  return `${guide.tool || "该工具"} 只接受这些顶层键：${keys}。示例：${example}${guide.note ? `。注意：${guide.note}` : ""}`;
}

/**
 * 非工具字段的形状指南。
 *
 * 2026-10-28 实测：模型把 `task_outcomes[0].deliverables_met` 写成布尔 `true`，
 * 整条 outcome 被丢弃（连带 T_WAF_PROBE 的结案），而回执里只有一句 zod 原文。
 * 这些字段不在工具指南的覆盖范围内，必须单独给形状。
 */
const FIELD_GUIDES: Record<string, { shape: string; example: unknown }> = {
  task_outcomes: {
    shape: "{task_id, reason(必须点名 ev-id), evidence_ids:[…], deliverables_met:[…] 或 true, audit_ids?:[…]}",
    example: { task_id: "T_x", reason: "按 ev-0123456789abcdef 判定为 verified-negative", evidence_ids: ["ev-0123456789abcdef"], deliverables_met: [] },
  },
  required_tasks: {
    shape: "{id, target(URL), purpose, reason, completion_criteria, deliverables?:[字符串], success_criteria?, fallback_strategy?, playbook?}",
    example: { id: "T_x", target: "https://TARGET/", purpose: "取回真实 bundle", reason: "唯一入口", completion_criteria: "看到 /api/ 路径", deliverables: ["js_content"], success_criteria: "至少 1 条 /api/ 路径" },
  },
  findings: {
    shape: "{id, title, severity, …, evidence_ids:[…]}（finding 必须引用已存在证据）",
    example: { id: "F1", title: "示例", severity: "low", evidence_ids: ["ev-0123456789abcdef"] },
  },
  hypotheses: {
    shape: "{text, evidence_ids:[…], confidence}（evidence_ids 必须是账本里已有的 id）",
    example: { text: "示例假设", evidence_ids: ["ev-0123456789abcdef"], confidence: "medium" },
  },
};

/** 该字段的正确形状；未知字段返回 undefined（不硬编）。 */
export function fieldGuide(field: string): string | undefined {
  const guide = FIELD_GUIDES[field];
  if (!guide) return undefined;
  return `${field} 的每一项必须是 ${guide.shape}。示例：${JSON.stringify(guide.example)}`;
}
/** 该字段的最小可用示例（结构化回执的 correct_shape_example 用它）。 */
export function fieldExample(field: string): Record<string, unknown> | undefined {
  const example = FIELD_GUIDES[field]?.example;
  return example && typeof example === "object" ? (example as Record<string, unknown>) : undefined;
}
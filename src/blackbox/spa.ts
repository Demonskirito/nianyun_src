/**
 * SPA 指纹识别 + "步兵缴械"
 *
 * 背景（2026-10-28 note.yun 会话）：
 *   15:08:43 拿到 `https://cloud.oppo.com/` 的 5158B HTML 外壳（nginx + 内联脚本 + `id="root"`），
 *   这是全场唯一的有效纵深。此后 agent 又花了 18 次调用在 301/412/字典上，
 *   对这份外壳只做了 2 次 `recon.js_endpoints`（都返回 `no_script_references`）——
 *   因为**外部 bundle 一个都没引用**，工具按 `<script src>` 找，自然找不到。
 *
 * 结论：对一个纯 SPA 外壳继续上字典和裸 GET，只会得到 catch-all 200 或 WAF 412。
 * 控制面应当认指纹、缴步兵的械，只留"能渲染/能执行"的特种兵：
 *   browser.open（wait_until=networkidle）、exec.python（Playwright 抓 XHR）、
 *   recon.js_endpoints（只在确有 <script src> 时才有意义）。
 */

export type SpaFingerprint = {
  is_spa: boolean;
  /** 命中的特征，写进事件与上下文，便于复盘“为什么判它是 SPA”。 */
  signals: string[];
  bytes: number;
  script_src: number;
  inline_scripts: number;
};

// 挂载点特征写成 [正则, 可读名]：信号会直接进上下文与事件，正则源码对模型没有意义。
const SPA_ROOT_MARKERS: Array<[RegExp, string]> = [
  [/id=["']root["']/i, "mount:#root"],
  [/id=["']app["']/i, "mount:#app"],
  [/id=["']__next["']/i, "mount:#__next"],
  [/__NUXT__/, "mount:__NUXT__"],
  [/window\.__INITIAL_STATE__/, "mount:__INITIAL_STATE__"],
];
const FRAMEWORKS = [/react/i, /vue/i, /angular/i, /svelte/i, /umi/i, /next\.js/i];

/**
 * 判定一个 HTML 响应是不是"空壳 SPA"。
 *
 * 三条同时成立才算：
 *   ① 200 + HTML + 至少 2KB（小页面不是壳，是内容）；
 *   ② 有挂载点（id="root"/"app"/__next__…）或框架特征；
 *   ③ 有脚本，但**外部 `<script src>` 很少**（≤1）——这正是 js_endpoints 失效的原因。
 */
export function spaFingerprint(data: Record<string, unknown>): SpaFingerprint {
  const body = String(data.body ?? data.body_preview ?? "");
  const bytes = Number(data.body_bytes ?? data.content_length ?? body.length ?? 0);
  // 真实 tool-result 的 content-type 在 headers 里（`headers["content-type"]`），
  // 没有顶层 content_type —— 只认顶层的话，线上永远不会触发 SPA 判定。
  // 这个缺口是 2026-10-28 用历史会话回放时发现的（回放 sail 判不出来）。
  const headers = (data.headers && typeof data.headers === "object" ? data.headers : {}) as Record<string, unknown>;
  const headerType = Object.entries(headers)
    .find(([key]) => key.toLowerCase() === "content-type")?.[1];
  const contentType = String(data.content_type ?? data.mime ?? headerType ?? "");
  const status = Number(data.status ?? 0);
  const signals: string[] = [];
  const scriptSrc = (body.match(/<script[^>]+src=/gi) || []).length;
  const inline = (body.match(/<script(?![^>]*src=)/gi) || []).length;

  const html = /html/i.test(contentType) || /<html|<div|<script/i.test(body);
  const bigEnough = bytes >= 2048 || body.length >= 2048;
  if (status !== 200) return { is_spa: false, signals: [`status=${status}`], bytes, script_src: scriptSrc, inline_scripts: inline };
  if (!html) return { is_spa: false, signals: ["not_html"], bytes, script_src: scriptSrc, inline_scripts: inline };
  if (!bigEnough) return { is_spa: false, signals: ["too_small"], bytes, script_src: scriptSrc, inline_scripts: inline };

  const root = SPA_ROOT_MARKERS.find(([pattern]) => pattern.test(body));
  const framework = FRAMEWORKS.find(pattern => pattern.test(body));
  if (root) signals.push(root[1]);
  if (framework) signals.push(`framework:${String(framework).replace(/[\\/]/g, "")}`);
  if (inline > 0) signals.push(`inline_scripts:${inline}`);
  signals.push(`external_scripts:${scriptSrc}`);

  // 打包产物（带 hash 的 chunk）是"业务由前端渲染"的强证据。
  const bundles = (body.match(/<script[^>]+src=[^>]*(chunk|app|main|vendor|runtime)[^>]*>/gi) || []).length;

  // 可见正文占比：把 script/style/tag 全去掉之后还剩多少。
  // 真正的外壳里，HTTP 响应几乎不含业务文字（note.yun 实测：4916 字符 body，
  // 可见正文不足 5%），而 SSR 文章页/文档页这个比例很高。
  const visible = body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, "")
    .length;
  const textRatio = body.length ? visible / body.length : 0;
  signals.push(`text_ratio:${textRatio.toFixed(2)}`);
  if (bundles) signals.push(`bundles:${bundles}`);

  // 判定（任一即可，但都必须落在"小正文"上）：
  //   ① 经典挂载点/框架标记；
  //   ② 至少 2 个打包产物 + 可见正文 < 12%。
  // 旧规则要求 external_scripts <= 1 —— 被真实数据证伪：note.yun 的外壳有 7 个
  // 外部 script，按旧规则永远不会触发缴械（2026-10-28 回放发现）。
  const mountLike = Boolean(root || framework);
  const shellLike = bundles >= 2 && textRatio < 0.12;
  const isSpa = (mountLike || shellLike) && textRatio < 0.35;
  if (!isSpa) signals.push("looks_like_ssr_or_static");
  return { is_spa: isSpa, signals, bytes, script_src: scriptSrc, inline_scripts: inline };
}

/**
 * 被缴械的"步兵"工具：在 SPA 主机上它们只会产出噪声。
 *
 * 2026-10-31 修正：`http.request` **不在**这里。原始 HTTP 不依赖渲染，
 * 缴械它只会把"匿名 baseline + 身份对照"这条唯一能出结论的路堵死——
 * 实测 m.ctrip.com 一场 24 分钟的 run 里 `http.request` 只被放行 1 次，
 * 模型只能拿 burp.send 连打 14 发，还反过来报"清单里没有发原始请求的工具"。
 * 该缴械的是"按静态路由去枚举"的工具：SPA 的每条路由都回同一个外壳，枚举它们纯噪声。
 */
export const INFANTRY_TOOLS = ["recon.content_discovery", "recon.nuclei", "recon.api_routes"] as const;

/** 允许在 SPA 主机上使用的"特种兵"工具。 */
export const SPECIALIST_TOOLS = ["browser.open", "browser.network", "browser.screenshot", "browser.tab", "browser.storage", "exec.python", "exec.bash", "recon.js_endpoints", "burp.send", "burp.scan"] as const;

export type SpaState = { host: string; at: number; bytes: number; signals: string[]; task_id?: string };

export function spaDisarmed(state: { spa?: SpaState }, tool: string, url: string): SpaState | undefined {
  const spa = state.spa;
  if (!spa) return undefined;
  let host = "";
  try {
    host = new URL(url).host.toLowerCase();
  } catch {
    return undefined;
  }
  if (host !== spa.host) return undefined;
  if (!(INFANTRY_TOOLS as readonly string[]).includes(tool)) return undefined;
  return spa;
}

export function spaDirective(state: { spa?: SpaState }): string | undefined {
  const spa = state.spa;
  if (!spa) return undefined;
  return `【步兵缴械】${spa.host} 判定为纯 SPA 外壳（${spa.bytes}B，特征：${spa.signals.slice(0, 3).join("、")}）。`
    + `对该主机的 recon.content_discovery / recon.nuclei / recon.api_routes 已被禁用`
    + `（会被 spa_disarmed 拒收，确需强制时传 input.force_armored=true）。`
    + `注意：http.request 不在缴械清单里——匿名基线与身份对照照常可打，别把它当被禁用。`
    + `改用特种兵：browser.open（wait_until=networkidle）加载页面，然后 browser.network 直接取渲染期真实 XHR`
    + `（含 method/post_data；这是 2026-10-31 新增能力，不要再用 exec.python 手写 Playwright）；`
    + `也可以 exec.python 跑脚本，或从内联脚本里抠 baseURL/.env 常量。`
    + `任务 ${spa.task_id || "T_SPA_REVERSE"} 就是为此生成的，本轮优先给它派活。`;
}
/**
 * 找一条"同一件事"的 SPA 逆向任务：同 host，且 purpose 点名 SPA / 外壳 / 逆向。
 *
 * 为什么需要它：`applyProtocolHooks` 认出外壳后原来**无条件新建** `T_SPA_REVERSE_*`，
 * 而主 agent 常常已经建过一条同 host、同目的的活（"抓首页外壳，提取 .js bundle"）。
 * `duplicateOf` 的文本相似度在这两句话上过不了阈值（一个写 bundle/baseURL，一个写
 * 真实 API/鉴权入口），于是同一件事占两份待办额度，强制焦点只锁系统新建的那条，
 * 已有任务永远拿不到证据，最后只能被 settle 成 blocked。
 *
 * 实测 fb06499adcf889b5：T1 与 T_SPA_REVERSE_75985252 同 host 同目的，24 个 turns
 * 全锁在后者，browser 抓到 85 条 XHR 却换不来一条 completed，整场 0 完成。
 */
export function existingReverseTask(
  tasks: Record<string, { purpose?: unknown; target?: unknown } | undefined>,
  host: string,
): string | undefined {
  const want = String(host || "").toLowerCase();
  if (!want) return undefined;
  for (const [id, task] of Object.entries(tasks || {})) {
    if (!task || id.startsWith("action:") || !String(task.purpose ?? "").trim()) continue;
    let otherHost = "";
    try { otherHost = new URL(String(task.target || "")).host.toLowerCase(); } catch { continue; }
    if (otherHost !== want) continue;
    if (/spa|外壳|逆向/i.test(String(task.purpose))) return id;
  }
  return undefined;
}

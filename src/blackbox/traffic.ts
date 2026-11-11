/**
 * 让 Agent 学会"看 Burp 的脸色"：把 HTTP History 从"一段流水账"压成可行动的信号。
 *
 * 人类黑客看 History 是在找规律：哪个参数每次都在变、哪个路径的 403 长得一模一样（WAF 拦页）、
 * 哪条链路是同一个模板在重复。模型直接读 50 条原始记录既费 token 又容易漏，
 * 所以在工具层先做一次统计，输出 `signals`（每条都带"该怎么办"）。
 *
 * 注意：Bridge 的 history 条目只有 entry_id/url/method/status/timestamp/response_bytes/content_type，
 * 没有响应头——所以"X-WAF-Block: true"这类判断要靠 signals 里给出的 entry_id 再去 burp.entry 看头。
 */

export type HistoryEntry = {
  entry_id?: string;
  url?: string;
  method?: string;
  status?: number;
  timestamp?: number;
  response_bytes?: number;
  content_type?: string;
};

export type TrafficSignal = { code: string; detail: string; action: string };

export type TrafficAnalysis = {
  total: number;
  window?: { from: number; to: number };
  statuses: Record<string, number>;
  methods: Record<string, number>;
  content_types: Record<string, number>;
  templates: Array<{
    template: string;
    count: number;
    statuses: Record<string, number>;
    sizes: { min: number; max: number; distinct: number };
    entries: string[];
  }>;
  volatile_params: Array<{ template: string; name: string; values: string[] }>;
  auth_streak: { code: number; length: number } | null;
  signals: TrafficSignal[];
};

const TRACKING_PARAMS = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "_t", "_", "callback"]);

/** 把 /user/123/orders/9f8a 归一成 /user/{id}/orders/{id}，同模板才能比较。 */
export function pathTemplate(rawPath: string): string {
  return String(rawPath || "/")
    .split("/")
    .map((segment) => {
      if (!segment) return segment;
      if (/^\d+$/.test(segment)) return "{n}";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return "{uuid}";
      if (/^[0-9a-f]{16,}$/i.test(segment)) return "{hex}";
      if (/^[A-Za-z0-9_-]{16,}$/.test(segment) && /\d/.test(segment)) return "{id}";
      return segment;
    })
    .join("/");
}

function median(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)]!;
}

export function analyzeTraffic(entries: HistoryEntry[]): TrafficAnalysis {
  const rows = entries.filter(entry => entry && (entry.url || entry.status !== undefined));
  const statuses: Record<string, number> = {};
  const methods: Record<string, number> = {};
  const contentTypes: Record<string, number> = {};
  const byTemplate = new Map<string, { statuses: Record<string, number>; sizes: number[]; entries: string[]; params: Map<string, Set<string>> }>();
  const ordered = [...rows].sort((a, b) => Number(a.timestamp || 0) - Number(b.timestamp || 0));

  for (const entry of ordered) {
    const status = entry.status === undefined ? "unknown" : String(entry.status);
    statuses[status] = (statuses[status] || 0) + 1;
    const method = String(entry.method || "GET").toUpperCase();
    methods[method] = (methods[method] || 0) + 1;
    const type = String(entry.content_type || "unknown").split(";")[0]!.trim() || "unknown";
    contentTypes[type] = (contentTypes[type] || 0) + 1;

    let url: URL | undefined;
    try { url = new URL(String(entry.url || "")); } catch { url = undefined; }
    const template = url ? pathTemplate(url.pathname) : "/";
    const bucket = byTemplate.get(template) || { statuses: {}, sizes: [], entries: [], params: new Map<string, Set<string>>() };
    bucket.statuses[status] = (bucket.statuses[status] || 0) + 1;
    if (typeof entry.response_bytes === "number") bucket.sizes.push(entry.response_bytes);
    if (entry.entry_id) bucket.entries.push(entry.entry_id);
    if (url) {
      for (const [name, value] of url.searchParams.entries()) {
        if (TRACKING_PARAMS.has(name)) continue;
        const set = bucket.params.get(name) || new Set<string>();
        set.add(value);
        bucket.params.set(name, set);
      }
    }
    byTemplate.set(template, bucket);
  }

  // 401/403 连续段：人类黑客看到"连续被挡"就换策略，这里把它算出来。
  let authStreak: { code: number; length: number } | null = null;
  let current: { code: number; length: number } | null = null;
  for (const entry of ordered) {
    const code = Number(entry.status || 0);
    if (code === 401 || code === 403) {
      if (current && current.code === code) current.length += 1;
      else current = { code, length: 1 };
      if (!authStreak || current.length > authStreak.length) authStreak = { ...current };
    } else current = null;
  }

  const templates = [...byTemplate.entries()].map(([template, bucket]) => ({
    template, count: bucket.entries.length || bucket.sizes.length,
    statuses: bucket.statuses,
    sizes: {
      min: bucket.sizes.length ? Math.min(...bucket.sizes) : 0,
      max: bucket.sizes.length ? Math.max(...bucket.sizes) : 0,
      distinct: new Set(bucket.sizes).size,
    },
    entries: bucket.entries.slice(0, 5),
  })).sort((a, b) => b.count - a.count);

  const volatileParams: Array<{ template: string; name: string; values: string[] }> = [];
  for (const [template, bucket] of byTemplate) {
    for (const [name, values] of bucket.params) if (values.size >= 2) volatileParams.push({ template, name, values: [...values].slice(0, 4) });
  }

  const signals: TrafficSignal[] = [];
  if (authStreak && authStreak.length >= 3) {
    signals.push({
      code: "authwall",
      detail: `${authStreak.length} 条连续 ${authStreak.code}`,
      action: "别再换参数硬刚：先拿凭证（auth_token）或用别的身份，或找未授权入口（unauth_exposure）",
    });
  }
  for (const item of templates) {
    const blocked = (item.statuses["403"] || 0) + (item.statuses["406"] || 0) + (item.statuses["429"] || 0);
    if (blocked >= 3 && item.sizes.distinct === 1) {
      signals.push({
        code: "waf_suspected",
        detail: `${item.template} 上 ${blocked} 条 403/406/429，响应体都是 ${item.sizes.min}B（同一张拦截页）`,
        action: `用 burp.entry 看这些响应头里的 X-WAF-*/Server/CF-Ray 特征，再决定换编码绕过还是走 lateral_escape（同族子域/边缘资产）`,
      });
    }
    if (item.count >= 3 && item.sizes.distinct === 1 && item.sizes.min > 0 && !blocked) {
      signals.push({
        code: "static_response",
        detail: `${item.template} ${item.count} 条响应都是 ${item.sizes.min}B`,
        action: "这是可以拿来做基线的点：用 http.diff 做变体对比（加参数/换身份/改方法），差异才是证据",
      });
    }
    if (item.sizes.distinct >= 2 && item.count >= 2 && item.sizes.max - item.sizes.min > 200) {
      signals.push({
        code: "size_variance",
        detail: `${item.template} 响应大小在 ${item.sizes.min}–${item.sizes.max}B 之间（${item.sizes.distinct} 种）`,
        action: "尺寸方差可能是条件分支（越权看到别人数据、错误信息泄露），优先拿最大/最小的两条做 http.diff",
      });
    }
  }
  for (const param of volatileParams.slice(0, 5)) {
    signals.push({
      code: "volatile_param",
      detail: `${param.template} 的 ${param.name} 每次不同（${param.values.slice(0, 3).join(" / ")}）`,
      action: "这是签名/nonce/时间戳类参数：步兵重放必失败，转特种兵逆算法（或先看它出现在哪个 JS 里）",
    });
  }
  // 软 404：不同路径返回同一张 200 壳页（SPA 通配路由）。真实数据里 /robots.txt 与 / 同大小就是这类，
  // 不点出来，模型会把 ffuf 的 200 全当命中。
  const bySize = new Map<number, string[]>();
  for (const item of templates) {
    if (item.sizes.distinct !== 1 || !item.sizes.min) continue;
    if ((item.statuses["200"] || 0) !== item.count) continue;
    bySize.set(item.sizes.min, [...(bySize.get(item.sizes.min) || []), item.template]);
  }
  for (const [size, paths] of bySize) {
    if (paths.length < 2) continue;
    signals.push({
      code: "soft_404",
      detail: `${paths.length} 个不同路径（${paths.slice(0, 4).join(", ")}）都返回 ${size}B 的 200`,
      action: "这是通配路由/软 404：目录与接口爆破的 200 全是假阳性，改走 recon.js_endpoints / browser 抓真实 XHR，或按 body 哈希去重后再判断",
    });
    break;
  }  if (rows.length >= 5) {
    const time = rows.map(entry => Number(entry.timestamp || 0)).filter(Boolean).sort((a, b) => a - b);
    if (time.length >= 2 && time[time.length - 1]! - time[0]! < 2000) {
      signals.push({ code: "burst", detail: `${time.length} 条流量集中在 ${time[time.length - 1]! - time[0]!}ms 内`, action: "这是并发流量（竞态或批量）：先确认哪些是真并发，再用 recon.race_condition 复现" });
    }
  }
  const htmlSizes = new Set(rows.filter(entry => String(entry.content_type || "").includes("text/html")).map(entry => Number(entry.response_bytes || 0)));
  if (htmlSizes.size === 1 && rows.length >= 3) {
    signals.push({ code: "spa_shell", detail: "所有 HTML 响应大小完全相同", action: "这是前端壳：直接打接口没意义，先用 katana/browser 看它实际调了哪些 XHR（recon.js_endpoints）" });
  }

  const window = rows.length
    ? { from: Math.min(...rows.map(entry => Number(entry.timestamp || 0))), to: Math.max(...rows.map(entry => Number(entry.timestamp || 0))) }
    : undefined;
  return {
    total: rows.length, ...(window && window.from ? { window } : {}),
    statuses, methods, content_types: contentTypes, templates, volatile_params: volatileParams.slice(0, 5),
    auth_streak: authStreak, signals,
  };
}

/** 给 summary 用的一行摘要（信号最多列 3 条，细节留给 data.analysis）。 */
export function trafficSummaryLine(analysis: TrafficAnalysis): string {
  const statuses = Object.entries(analysis.statuses).map(([code, count]) => `${code}×${count}`).join("/");
  const signals = analysis.signals.slice(0, 3).map(signal => `${signal.code}(${signal.detail})`).join("；");
  return `${analysis.total} 条 ｜ 状态 ${statuses || "无"} ｜ 模板 ${analysis.templates.length} 个${signals ? ` ｜ 信号：${signals}` : " ｜ 无异常信号"}`;
}

export { median };
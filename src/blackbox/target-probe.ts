/**
 * 目标可达性前置检查：环境检查里真打一次目标。
 *
 * 起因（2026-11-06 ce01b328599615a7 实测）：`check` 只验工具链（二进制在不在、模板空不空、
 * Burp 端口通不通），**从不验这台目标能不能连上**。目标已经下线时，整场会照常开跑：
 *
 *   - 每次 `http.request` 都由 Burp 用错误页顶替（状态码仍是 200），烧满 25 分钟预算才收口；
 *   - `browser.open` 在同一个代理上等不到响应，一个工具吃掉 5 分钟；
 *   - 更贵的是后果：7 条路径"都是 200/1381B" → `uniform_body` 异常 → 派发 Host 头注入等
 *     三条假任务，整场的作战计划被一个死目标改写。
 *
 * 所以这里在**开跑前**用与工具完全相同的方式（同一个代理、同样的 TLS 忽略开关）发一次 GET：
 * 命中的是代理自己的错误页、连接失败、超时，就判环境不通过，会话停在 environment_check。
 *
 * 判据刻意只用两类**确定性**信号：
 *   1. 代理产品的专有标记（见 proxy-error.ts，不用"200 但很短"这种形状启发式）；
 *   2. 传输层错误（ECONNREFUSED / ENOTFOUND / 超时）。
 * **不用状态码判定**：403/404/500 都说明目标在说话，那是可达的——把它判成不可达会
 * 白白拦掉真实目标（目标 WAF 挡了我们，恰恰是这条会话最该看的东西）。
 */

import { proxyEndpoint } from "./environment.js";
import { proxyErrorPage, type ProxyErrorHit } from "./proxy-error.js";
import { applyDefaultUserAgent } from "./ua.js";

export type TargetProbeCode = "reachable" | "proxy_error" | "network_error" | "timeout" | "invalid_url" | "skipped";

export type TargetProbe = {
  checked_at: number;
  url: string;
  method: string;
  reachable: boolean;
  code: TargetProbeCode;
  status?: number;
  bytes?: number;
  elapsed_ms?: number;
  attempts?: number;
  /** 是否经出网代理（与 http/browser 工具保持同一条路径，否则探活结论不成立）。 */
  via_proxy: boolean;
  proxy_url?: string;
  /** 判为不可达时给人看的一句原因（含处理建议）。 */
  reason?: string;
  proxy_error?: { vendor: ProxyErrorHit["vendor"]; marker: string; detail?: string };
};

export type TargetProbeJudgement = Pick<TargetProbe, "reachable" | "code" | "reason" | "proxy_error">;

const DEFAULT_TIMEOUT_MS = 12_000;
const BODY_LIMIT = 64 * 1024;

/** 失败原因统一收口：先给"为什么"，再给"接下来做什么"——只报错不给出路的提示没人会读。 */
function unreachable(code: TargetProbeCode, why: string, url: string): TargetProbeJudgement {
  const hint = code === "invalid_url"
    ? "处理：这个会话的候选目标不是 HTTP(S) 地址，先在候选池里改成可用的 URL。"
    : "处理：确认该主机从控制面可达（DNS、出网代理、是否已下线），修好后重新执行环境检查，或换一个可达的候选目标。"
      + "不要带着一个连不上的目标开跑：预算会烧完，而且代理错误页会被当成目标响应，派发出假任务。";
  return { reachable: false, code, reason: `${why}（目标：${url}）${hint}` };
}

/**
 * 判决一张"有响应"的结果。纯函数：只吃 status/body，不做 IO，便于用真实页面样本回归。
 * 注意顺序——先认代理错误页，再认"有响应即可达"。
 */
export function judgeTargetResponse(input: { status?: number; body?: string; url?: string }): TargetProbeJudgement {
  const url = String(input.url || "");
  const hit = proxyErrorPage({ status: input.status, body: String(input.body || "") });
  if (hit) {
    return {
      reachable: false,
      code: "proxy_error",
      proxy_error: { vendor: hit.vendor, marker: hit.marker, ...(hit.detail ? { detail: hit.detail } : {}) },
      reason: unreachable(
        "proxy_error",
        `${hit.vendor} 代理回的是它自己的错误页（HTTP ${input.status ?? "?"}${hit.detail ? `：${hit.detail}` : ""}），请求根本没到目标。`,
        url,
      ).reason,
    };
  }
  // 任何 HTTP 状态码都算"目标在说话"。403/404/5xx 是情报，不是故障。
  return { reachable: true, code: "reachable" };
}

/** 判决一次传输层失败。纯函数。 */
export function judgeTargetError(error: unknown, input: { url?: string; timeoutMs?: number } = {}): TargetProbeJudgement {
  const url = String(input.url || "");
  const message = String(error instanceof Error ? error.message : error || "").trim() || "unknown error";
  const timedOut = /timeout|timed out|ETIMEDOUT|Deadline exceeded/i.test(message);
  if (timedOut) {
    const limit = input.timeoutMs ? `${input.timeoutMs}ms` : "限时";
    return { reachable: false, code: "timeout", reason: unreachable("timeout", `目标在 ${limit} 内没有响应（${message.slice(0, 160)}）。`, url).reason };
  }
  return { reachable: false, code: "network_error", reason: unreachable("network_error", `连接目标失败：${message.slice(0, 200)}。`, url).reason };
}

function boolValue(value: string | undefined, fallback: boolean): boolean {
  if (value == null || !String(value).trim()) return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).trim().toLowerCase());
}

function intValue(value: string | undefined, fallback: number, min: number, max: number): number {
  const text = String(value ?? "").trim();
  /**
   * 空串必须当成"没配"，不能落到下面的 Number("")。`Number("") === 0` 是有限数，
   * 于是会被 clamp 到 min——实测后果就是整条检查被压成 1 秒超时：容器里明明没配
   * `BLACKBOX_TARGET_PROBE_TIMEOUT_MS`，探测却在 1000ms 就判"目标没响应"
   * （76c8c8744a4ee1a5 复检时 elapsed_ms=1012，看起来像目标慢，其实是自己把表掐了）。
   */
  if (!text) return fallback;
  const parsed = Number(text);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

/**
 * 探一次目标。返回 `reachable:false` 就会让环境检查不通过。
 *
 * 为什么用 playwright 的 request 而不是 fetch：http/browser 工具就是这么发请求的
 * （同一个 proxy 配置、同一个 `ignoreHTTPSErrors`）。用 fetch 探活会得到"控制面直连能通、
 * 工具经代理不能通"的假结论——正是这类不一致让上一轮的排查跑偏。
 */
export async function probeTarget(input: {
  url: string;
  values?: Record<string, string>;
  timeoutMs?: number;
  retries?: number;
}): Promise<TargetProbe> {
  const values = input.values || {};
  const raw = String(input.url || "").trim();
  const base: TargetProbe = { checked_at: Date.now(), url: raw, method: "GET", reachable: true, code: "reachable", via_proxy: false };

  // 关掉开关时给 reachable:true：跳过检查不该把会话判死（与"检查通过"区分靠 code=skipped）。
  if (!boolValue(values.BLACKBOX_TARGET_PROBE ?? process.env.BLACKBOX_TARGET_PROBE, true)) {
    return { ...base, code: "skipped", reason: "目标可达性检查已关闭（BLACKBOX_TARGET_PROBE=off），未探测目标。" };
  }
  if (!raw) return { ...base, reachable: false, code: "invalid_url", reason: unreachable("invalid_url", "会话没有目标地址。", "(empty)").reason };

  let parsed: URL;
  try {
    parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("only http(s)");
  } catch {
    return { ...base, reachable: false, code: "invalid_url", reason: unreachable("invalid_url", "会话目标不是有效的 HTTP(S) URL。", raw).reason };
  }

  const timeoutMs = input.timeoutMs ?? intValue(values.BLACKBOX_TARGET_PROBE_TIMEOUT_MS ?? process.env.BLACKBOX_TARGET_PROBE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 1000, 60_000);
  const retries = input.retries ?? intValue(values.BLACKBOX_TARGET_PROBE_RETRIES ?? process.env.BLACKBOX_TARGET_PROBE_RETRIES, 1, 0, 3);
  const ignoreHTTPSErrors = boolValue(values.BURP_IGNORE_HTTPS_ERRORS, false);
  let proxyUrl: string | undefined;
  const rawProxy = String(values.BURP_PROXY_URL || "").trim();
  if (rawProxy) {
    try { proxyUrl = proxyEndpoint(rawProxy).url; } catch { proxyUrl = undefined; }
  }

  const { request } = await import("playwright");
  let judgement: TargetProbeJudgement | undefined;
  let status: number | undefined;
  let bytes: number | undefined;
  let elapsed = 0;
  let attempts = 0;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    attempts = attempt + 1;
    // 只对传输层失败重试：代理错误页是确定性结论（同一个代理、同一个死目标，再打一次还是它）。
    if (attempt > 0) await new Promise(resolve => setTimeout(resolve, 300));
    const startedAt = Date.now();
    try {
      const api = await request.newContext({
        ...(proxyUrl ? { proxy: { server: proxyUrl } } : {}),
        ignoreHTTPSErrors,
        timeout: timeoutMs,
      });
      try {
        // 不跟随重定向：301/302 已经证明目标在说话；跟着跳可能跳进另一个死主机，把
        // "目标可达"探成"不可达"。
        //
        // 探活必须带上和工具一致的浏览器身份（见 ua.ts）：只补 accept 不补 UA，
        // 遇到"只放行浏览器"的网关会被判成 403 挑战页——那确实是"目标在说话"，
        // 于是检查照样通过，但接下来每一次工具调用都会撞同一堵墙，白烧一整场预算。
        const probeHeaders: Record<string, string> = { accept: "text/html,application/xhtml+xml,*/*;q=0.8" };
        applyDefaultUserAgent(probeHeaders, values);
        const response = await api.fetch(parsed.toString(), {
          method: "GET", maxRedirects: 0, failOnStatusCode: false, timeout: timeoutMs,
          headers: probeHeaders,
        } as Parameters<typeof api.fetch>[1]);
        status = response.status();
        elapsed = Date.now() - startedAt;
        let body = "";
        try {
          const buffer = await response.body();
          bytes = buffer.length;
          body = buffer.subarray(0, BODY_LIMIT).toString("utf8");
        } catch {
          // 正文被掐断不代表请求没到目标：状态码已经是目标的回答。
          body = "";
        }
        judgement = judgeTargetResponse({ status, body, url: parsed.toString() });
      } finally {
        await api.dispose().catch(() => {});
      }
    } catch (error) {
      elapsed = Date.now() - startedAt;
      judgement = judgeTargetError(error, { url: parsed.toString(), timeoutMs });
    }
    if (judgement.reachable || judgement.code === "proxy_error") break;
  }

  const final = judgement ?? { reachable: false, code: "network_error" as const, reason: "探测未得到任何结果。" };
  return {
    ...base,
    reachable: final.reachable,
    code: final.code,
    ...(final.reason ? { reason: final.reason } : {}),
    ...(final.proxy_error ? { proxy_error: final.proxy_error } : {}),
    ...(status !== undefined ? { status } : {}),
    ...(bytes !== undefined ? { bytes } : {}),
    elapsed_ms: elapsed,
    attempts,
    via_proxy: Boolean(proxyUrl),
    ...(proxyUrl ? { proxy_url: proxyUrl } : {}),
  };
}

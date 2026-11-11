/**
 * 异常响应检测：目标"全站一个样"的时候，按部就班的目录/参数遍历全是浪费，
 * 真正值钱的是这个架构特征本身（catch-all 路由、统一跳转、WAF 壳）。
 *
 * 这里只看最近若干条 http 结果：不同路径、同一跳转目标 → catch_all_redirect；
 * 不同路径、同一响应长度且 200 → uniform_body。命中后由 desk 派发利用型任务。
 */

export type AnomalyObservation = {
  host: string;
  /** 归一化前的原始 pathname，用来判断"确实是不同路径"。 */
  path: string;
  status: number;
  /** 已解析成绝对地址的 Location。 */
  location?: string;
  body_bytes?: number;
};

export type AnomalyAlert = {
  kind: "catch_all_redirect" | "uniform_body";
  host: string;
  paths: string[];
  location?: string;
  body_bytes?: number;
  at: number;
};

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
/**
 * "统一响应体"只在正文足够长时才算证据：`ok`、`404 not found` 这种几十字节的
 * 空壳正文本来就到处都是，按它熔断会把正常扫描误判成 catch-all。
 */
const UNIFORM_MIN_BYTES = 256;

/** 同主机最近 threshold 条、来自不同路径的观测是否"完全同构"。 */
export function detectAnomaly(recent: AnomalyObservation[], threshold = 3, at = Date.now()): AnomalyAlert | undefined {
  if (recent.length < threshold) return undefined;
  const host = recent[recent.length - 1]?.host || "";
  const sameHost = recent.filter(item => item.host === host);
  if (sameHost.length < threshold) return undefined;

  // 每条路径只取最后一次观测，避免同一个路径打十次凑数
  const latest = new Map<string, AnomalyObservation>();
  for (const item of sameHost) latest.set(item.path, item);
  const window = [...latest.values()].slice(-threshold);
  if (window.length < threshold) return undefined;
  const paths = window.map(item => item.path);

  const redirect = window.every(item => REDIRECTS.has(item.status) && item.location);
  if (redirect) {
    const target = window[0]!.location!;
    if (window.every(item => item.location === target)) {
      return { kind: "catch_all_redirect", host, paths, location: target, at };
    }
  }

  const uniform = window.every(item => item.status === 200 && (item.body_bytes || 0) >= UNIFORM_MIN_BYTES)
    && new Set(window.map(item => item.body_bytes)).size === 1;
  if (uniform) {
    return { kind: "uniform_body", host, paths, body_bytes: window[0]!.body_bytes, at };
  }
  return undefined;
}

/** 把一次 http 结果压成观测（location 已解析成绝对地址）。 */
export function observationOf(input: { url: string; status: number; location?: string; body_bytes?: number }): AnomalyObservation | undefined {
  let parsed: URL;
  try { parsed = new URL(input.url); } catch { return undefined; }
  let location: string | undefined;
  if (input.location) {
    try { location = new URL(input.location, parsed).toString(); } catch { location = input.location; }
  }
  return { host: parsed.host, path: parsed.pathname, status: Number(input.status) || 0, ...(location ? { location } : {}), body_bytes: Number(input.body_bytes) || 0 };
}
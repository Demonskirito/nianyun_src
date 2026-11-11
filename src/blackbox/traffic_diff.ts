/**
 * 结构化差分探针（recon.traffic_diff 的判定内核）
 *
 * 背景（2026-10-28 note.yun 会话）：
 *   `burp.history` 被调了 6 次。前 4 次拿到 `total 0/1/2/7`，后 2 次拿到 `total 298/299`
 *   （窗口内 301:30、412:20）。这 299 条里藏着"哪些路径被 WAF 拦了"的完整事实，
 *   但 agent 拿到 `total` 之后什么都没做——它把 history 当成 `ls -l` 式的状态检查，
 *   而不是差分情报源。
 *
 * 对策：不让模型"读列表然后自己比"，而是给它一个**只产出可证伪结论**的工具：
 *   输入 = 两条既有响应（或同一 URL 的基线 + 最新），输出 = { status, diff_score, ... }。
 *   diff_score=0 连续两次就直接触发收益递减止损（见 plateau.ts 的既有逻辑）。
 */

export type DiffSide = {
  evidence_id?: string;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  body_bytes?: number;
  body_length?: number;
  content_length?: number;
  content_type?: string;
  elapsed_ms?: number;
};

export type DiffResult = {
  /** identical / header_drift / body_drift / status_change / auth_change */
  status: "identical" | "header_drift" | "body_drift" | "status_change" | "auth_change" | "insufficient";
  /** 0 = 完全一致；1 = 完全无关。用来做"两次都 0 就止损"的判据。 */
  diff_score: number;
  status_change?: { from: number; to: number };
  header_changes: Record<string, { from?: string; to?: string }>;
  body_len_delta?: number;
  body_len_ratio?: number;
  new_cookies: string[];
  lost_cookies: string[];
  /** 给模型看的一句话结论（不写"可能"，只写观察到的差异）。 */
  verdict: string;
  reason?: string;
};

const NOISE_HEADERS = new Set([
  "date", "etag", "last-modified", "content-length", "connection", "keep-alive",
  "x-request-id", "x-trace-id", "traceparent", "server-timing", "age", "via",
]);

function headersOf(side: DiffSide): Record<string, string> {
  const raw = (side.headers || {}) as Record<string, string>;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    const name = key.toLowerCase();
    if (NOISE_HEADERS.has(name)) continue;
    out[name] = String(value).slice(0, 200);
  }
  return out;
}

function cookiesOf(side: DiffSide): string[] {
  const raw = (side.headers || {}) as Record<string, string>;
  const setCookie = Object.entries(raw).find(([key]) => key.toLowerCase() === "set-cookie")?.[1];
  if (!setCookie) return [];
  return String(setCookie)
    .split(/,(?=[^;]+=)/)
    .map(item => item.split("=")[0]!.trim())
    .filter(Boolean);
}

function bodySize(side: DiffSide): number {
  return Number(side.body_bytes ?? side.body_length ?? side.content_length ?? (side.body ? side.body.length : 0)) || 0;
}

function bodyText(side: DiffSide): string {
  return typeof side.body === "string" ? side.body : "";
}

/**
 * 比较两条响应。
 *
 * 打分口径（透明、可复算）：
 *   状态码变化   +0.5
 *   头部差异     +0.15 × 差异项数（上限 0.3）
 *   body 长度差  +0.4 × min(1, |Δ| / max(len))  （长度差比例）
 *   body 文本不同（同长度时才算，避免大文件全文比对） +0.2
 *   Set-Cookie 增减 +0.1 × 项数（上限 0.2）
 * 上限 1.0。0 表示"逐字段一致"。
 */
export function diffResponses(before: DiffSide | undefined, after: DiffSide | undefined): DiffResult {
  if (!before || !after) {
    return {
      status: "insufficient", diff_score: 0, header_changes: {}, new_cookies: [], lost_cookies: [],
      verdict: "缺一侧响应：需要基线证据 + 当前证据（或同一 URL 的两次请求）才能差分",
      reason: !before ? "baseline_missing" : "current_missing",
    };
  }
  const headerChanges: Record<string, { from?: string; to?: string }> = {};
  const beforeHeaders = headersOf(before);
  const afterHeaders = headersOf(after);
  for (const key of new Set([...Object.keys(beforeHeaders), ...Object.keys(afterHeaders)])) {
    const from = beforeHeaders[key];
    const to = afterHeaders[key];
    if (from === to) continue;
    headerChanges[key] = { ...(from !== undefined ? { from } : {}), ...(to !== undefined ? { to } : {}) };
  }
  const beforeCookies = cookiesOf(before);
  const afterCookies = cookiesOf(after);
  const newCookies = afterCookies.filter(name => !beforeCookies.includes(name));
  const lostCookies = beforeCookies.filter(name => !afterCookies.includes(name));

  const statusFrom = Number(before.status ?? 0);
  const statusTo = Number(after.status ?? 0);
  const sizeBefore = bodySize(before);
  const sizeAfter = bodySize(after);
  const delta = sizeAfter - sizeBefore;
  const ratio = sizeBefore || sizeAfter ? Math.abs(delta) / Math.max(sizeBefore, sizeAfter, 1) : 0;
  const textBefore = bodyText(before);
  const textAfter = bodyText(after);
  const textDiffers = Boolean(textBefore && textAfter && textBefore !== textAfter && ratio === 0);

  let score = 0;
  if (statusFrom !== statusTo) score += 0.5;
  score += Math.min(0.3, 0.15 * Object.keys(headerChanges).length);
  score += 0.4 * Math.min(1, ratio);
  if (textDiffers) score += 0.2;
  score += Math.min(0.2, 0.1 * (newCookies.length + lostCookies.length));
  const diffScore = Math.min(1, Math.round(score * 100) / 100);

  let status: DiffResult["status"] = "identical";
  if (statusFrom !== statusTo) status = "status_change";
  else if (newCookies.length || lostCookies.length || headerChanges["www-authenticate"]) status = "auth_change";
  else if (Object.keys(headerChanges).length) status = "header_drift";
  else if (delta !== 0 || textDiffers) status = "body_drift";

  const verdict = status === "identical"
    ? `完全一致（${statusTo || "?"} / ${sizeAfter}B）：同一身份下这条路径没有变化，不要再用同样请求刷它`
    : status === "status_change"
      ? `状态码 ${statusFrom || "?"} → ${statusTo || "?"}：行为变了，优先看这一条（可能是鉴权/限流/WAF 切换）`
      : status === "auth_change"
        ? `鉴权面变化：新 Cookie ${newCookies.join("、") || "无"}；丢失 ${lostCookies.join("、") || "无"}`
        : status === "header_drift"
          ? `头部漂移 ${Object.keys(headerChanges).slice(0, 4).join("、")}（body ${delta >= 0 ? "+" : ""}${delta}B）`
          : `body 变化 ${delta >= 0 ? "+" : ""}${delta}B（${Math.round(ratio * 100)}%）`;

  return {
    status, diff_score: diffScore,
    ...(statusFrom !== statusTo ? { status_change: { from: statusFrom, to: statusTo } } : {}),
    header_changes: headerChanges, body_len_delta: delta,
    body_len_ratio: Math.round(ratio * 100) / 100,
    new_cookies: newCookies, lost_cookies: lostCookies, verdict,
  };
}

/**
 * 从一组同 URL 的响应里挑"基线"和"当前"：
 *   基线 = 最早的一条非 5xx（最接近"正常业务"的那次）；
 *   当前 = 最后一条。
 * 只有一条时返回 undefined（差分需要两次观测）。
 */
export function pickPair<T extends DiffSide>(rows: T[]): [T, T] | undefined {
  if (rows.length < 2) return undefined;
  const baseline = rows.find(row => Number(row.status ?? 0) < 500) || rows[0]!;
  const current = rows[rows.length - 1]!;
  if (baseline === current) return undefined;
  return [baseline, current];
}
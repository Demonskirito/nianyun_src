import { createHash } from "node:crypto";

/**
 * http.diff 的判定核心。
 *
 * 设计原则（turn 62 P0）：
 *   1. 时间维度是**硬判定**：sleep(5) 的响应体一模一样，只靠文本永远判不出来；
 *   2. 文本相似度不能只有 token 滑窗：中文没有空格，5-token 切分会碎裂，必须走字符 n-gram；
 *   3. JSON 要按结构比，不能按字节比：噪音键（timestamp/requestId…）每轮都变，
 *      但业务字段有没有变才是证据；
 *   4. 长度差异超过 20% 直接判 different，跳过昂贵的文本计算。
 *
 * 结论词表（verdict）：
 *   identical    两者无实质差异（允许噪音键不同）
 *   same_shape   结构/形状一致但取值不同（越权、布尔等值、数据变化都在这里）
 *   different    结构、状态或长度显著不同
 *   timing_delta 响应体相同但耗时异常（时间盲注/命令注入的唯一可用证据）
 */

/** 每轮都会变、且与业务语义无关的键：比对前先剔除。 */
const NOISE_KEY = /^(?:_?ts|_?time|timestamp|server_?time|server_?timestamp|date|now|request_?id|req_?id|trace_?id|span_?id|nonce|random|rand|salt|elapsed|elapsed_?ms|cost|duration|took|_t|sign_?time)$/i;

export type DiffResponse = { status: number; body: string; body_bytes: number; duration_ms: number };

export type JsonShape = {
  same_structure: boolean;
  changed: Array<{ path: string; baseline: string; variant: string }>;
  added: string[];
  removed: string[];
  noise_removed: number;
};

/** 对照结论词表（唯一来源）：谓词判定、上下文注入、报告都用它，不要各自写字面量。 */
export type DiffVerdict = "identical" | "same_shape" | "different" | "timing_delta";

export type DiffResult = {
  baseline: { status: number; body_bytes: number; duration_ms: number; sha256: string };
  variant: { status: number; body_bytes: number; duration_ms: number; sha256: string };
  delta: { status_changed: boolean; body_bytes: number; similarity: number; duration_delta_ms: number; bytes_ratio: number };
  timing: { suspect: boolean; threshold_ms: number; delta_ms: number; baseline_ms: number; variant_ms: number; ratio: number };
  shape: { kind: "json" | "text" | "cjk" | "empty"; json?: JsonShape; metric?: string };
  verdict: DiffVerdict;
  hint: string;
};

const shortHash = (text: string) => createHash("sha256").update(text).digest("hex").slice(0, 16);

/** 单词级 5-token shingle 的 Jaccard：对以空格分词的西文响应有效，对中文无效（保留做兼容与对照）。 */
export function bodySimilarity(a: string, b: string): number {
  if (a === b) return 1;
  if (!a || !b) return 0;
  const shingles = (text: string): Set<string> => {
    const tokens = text.replace(/\s+/g, " ").trim().split(" ");
    const set = new Set<string>();
    for (let index = 0; index + 4 < tokens.length && index < 4000; index += 1) set.add(tokens.slice(index, index + 5).join(" "));
    return set;
  };
  const left = shingles(a);
  const right = shingles(b);
  if (!left.size || !right.size) return a === b ? 1 : 0;
  let shared = 0;
  for (const item of left) if (right.has(item)) shared += 1;
  return shared / (left.size + right.size - shared);
}

/**
 * 字符级 n-gram 的 Jaccard。
 * 中文、压缩后的 HTML、无空格 JSON 都靠这条：`"code":10403` 与 `"code":10200`
 * 在 3-gram 下只差很少几组，而 token 滑窗会把整段当成一个 token（相似度只看 0/1）。
 */
export function charNgramSimilarity(a: string, b: string, n = 3): number {
  if (a === b) return 1;
  if (!a || !b) return 0;
  const width = Math.max(2, Math.min(6, n));
  const grams = (text: string): Set<string> => {
    const set = new Set<string>();
    // 折叠空白并把超长响应截断到 20k 字符：过长的 JS bundle 没必要精确比对
    const clean = text.replace(/\s+/g, " ").slice(0, 20_000);
    for (let index = 0; index + width <= clean.length; index += 1) set.add(clean.slice(index, index + width));
    return set;
  };
  const left = grams(a);
  const right = grams(b);
  if (!left.size || !right.size) return a === b ? 1 : 0;
  let shared = 0;
  for (const item of left) if (right.has(item)) shared += 1;
  return shared / (left.size + right.size - shared);
}

const CJK = /[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]/;

/** 按响应形态选度量：JSON 走结构，含中日韩走字符 3-gram，其余走单词 shingle。 */
export function pickMetric(baseline: string, variant: string): "json" | "cjk" | "text" | "empty" {
  if (!baseline && !variant) return "empty";
  const jsonish = (text: string) => {
    const head = text.trim().slice(0, 1);
    return head === "{" || head === "[";
  };
  if (jsonish(baseline) || jsonish(variant)) return "json";
  if (CJK.test(baseline) || CJK.test(variant)) return "cjk";
  return "text";
}

function parseJson(text: string): unknown {
  try { return JSON.parse(text); } catch { return undefined; }
}

function comparable(value: unknown): string {
  if (typeof value === "string") return value.length > 120 ? `${value.slice(0, 120)}…` : value;
  try { return JSON.stringify(value)?.slice(0, 120) ?? String(value); } catch { return String(value); }
}

/**
 * 递归比对两棵 JSON 树：跳过噪音键，记录新增/缺失键与"同键不同值"的路径。
 * 只要键集合不同就是结构变了（shape），键同值不同才是数据变了（same_shape）。
 */
export function jsonShapeDiff(baseline: unknown, variant: unknown): JsonShape {
  const changed: JsonShape["changed"] = [];
  const added: string[] = [];
  const removed: string[] = [];
  let noise = 0;

  const walk = (left: unknown, right: unknown, path: string): void => {
    const leftArray = Array.isArray(left);
    const rightArray = Array.isArray(right);
    if (leftArray || rightArray) {
      if (!leftArray || !rightArray) { changed.push({ path: path || "$", baseline: comparable(left), variant: comparable(right) }); return; }
      const length = Math.max((left as unknown[]).length, (right as unknown[]).length);
      for (let index = 0; index < length; index += 1) {
        const key = `${path}[${index}]`;
        const hasLeft = index < (left as unknown[]).length;
        const hasRight = index < (right as unknown[]).length;
        if (!hasLeft) { added.push(key); continue; }
        if (!hasRight) { removed.push(key); continue; }
        walk((left as unknown[])[index], (right as unknown[])[index], key);
      }
      return;
    }
    if (left && right && typeof left === "object" && typeof right === "object") {
      const leftKeys = Object.keys(left as Record<string, unknown>);
      const rightKeys = Object.keys(right as Record<string, unknown>);
      for (const key of leftKeys) {
        const childPath = path ? `${path}.${key}` : key;
        if (NOISE_KEY.test(key)) {
          noise += 1;
          if (!rightKeys.includes(key)) noise += 0;
          continue;
        }
        if (!rightKeys.includes(key)) { removed.push(childPath); continue; }
        walk((left as Record<string, unknown>)[key], (right as Record<string, unknown>)[key], childPath);
      }
      for (const key of rightKeys) {
        if (NOISE_KEY.test(key)) { if (!leftKeys.includes(key)) noise += 1; continue; }
        if (!leftKeys.includes(key)) added.push(path ? `${path}.${key}` : key);
      }
      return;
    }
    if (comparable(left) !== comparable(right)) changed.push({ path: path || "$", baseline: comparable(left), variant: comparable(right) });
  };

  walk(baseline, variant, "");
  return {
    same_structure: added.length === 0 && removed.length === 0,
    changed: changed.slice(0, 20),
    added: added.slice(0, 20),
    removed: removed.slice(0, 20),
    noise_removed: noise,
  };
}

const DEFAULT_TIMING_THRESHOLD_MS = 2000;

/**
 * 比较两次响应。这是 未授权/越权/布尔盲注/延时盲注 的确认原语：
 * 一次调用给出状态、长度、结构差、以及**时间维度判定**，不让模型去肉眼比两段长 body。
 */
export function diffResponses(baseline: DiffResponse, variant: DiffResponse, options: { timingThresholdMs?: number } = {}): DiffResult {
  const threshold = Math.max(200, Number(options.timingThresholdMs || DEFAULT_TIMING_THRESHOLD_MS));
  const kind = pickMetric(baseline.body, variant.body);
  const sameBody = baseline.body === variant.body;
  const similarity = kind === "cjk" ? Number(charNgramSimilarity(baseline.body, variant.body).toFixed(4))
    : kind === "empty" ? 1
      : Number(bodySimilarity(baseline.body, variant.body).toFixed(4));
  const statusChanged = baseline.status !== variant.status;
  const bytesDelta = variant.body_bytes - baseline.body_bytes;
  const bytesRatio = baseline.body_bytes === 0 ? (variant.body_bytes === 0 ? 0 : 1) : Math.abs(bytesDelta) / baseline.body_bytes;
  const durationDelta = variant.duration_ms - baseline.duration_ms;
  const timing = {
    suspect: Math.abs(durationDelta) >= threshold,
    threshold_ms: threshold,
    delta_ms: durationDelta,
    baseline_ms: baseline.duration_ms,
    variant_ms: variant.duration_ms,
    ratio: baseline.duration_ms > 0 ? Number((variant.duration_ms / baseline.duration_ms).toFixed(2)) : 0,
  };
  let json: JsonShape | undefined;
  if (kind === "json") {
    const left = parseJson(baseline.body);
    const right = parseJson(variant.body);
    json = left !== undefined && right !== undefined ? jsonShapeDiff(left, right) : undefined;
  }
  const shape: DiffResult["shape"] = {
    kind: kind === "json" && !json ? "text" : kind,
    ...(json ? { json } : {}),
    metric: kind === "cjk" ? "char3gram" : kind === "text" ? "token5shingle" : kind === "json" ? "json_structure" : "none",
  };
  const jsonSame = Boolean(json && json.same_structure && json.changed.length === 0);
  const shapeChanged = Boolean(json && (!json.same_structure || json.changed.some(item => item.path === "$" && item.baseline.length > 90)));
  const lengthBlown = bytesRatio > 0.2 && !jsonSame;

  let verdict: DiffResult["verdict"];
  let hint: string;
  if (statusChanged) {
    verdict = "different";
    hint = variant.status === 200 && baseline.status >= 400 ? "auth_or_guard_bypassed：变体绕过了原本的拦截"
      : `status_changed：${baseline.status} → ${variant.status}，先解释状态变化再看正文`;
  } else if (timing.suspect && (sameBody || jsonSame || similarity >= 0.9)) {
    verdict = "timing_delta";
    hint = `timing_delta：正文无实质差异但耗时差 ${durationDelta}ms（阈值 ${threshold}ms）——时间盲注/命令注入的执行证据`;
  } else if (lengthBlown && !jsonSame) {
    verdict = "different";
    hint = `length_delta：长度差 ${Math.round(bytesRatio * 100)}%（>20% 直接判不同，跳过文本比对）`;
  } else if (json) {
    verdict = jsonSame ? "identical" : json.same_structure ? "same_shape" : "different";
    hint = jsonSame
      ? `json_identical：结构一致、业务字段无差异${json.noise_removed ? `（已剔除 ${json.noise_removed} 处时间戳/请求号噪音）` : ""}`
      : json.same_structure
        ? `json_same_shape：键结构一致但取值不同（${json.changed.map(item => item.path).join(", ") || "数组元素"}），优先核对是否拿到他人数据（越权）`
        : `json_shape_changed：键结构变化（新增 ${json.added.join(",") || "无"}；缺失 ${json.removed.join(",") || "无"}），若只换了身份/参数却读到他人数据，按越权处理`;
  } else if (sameBody || (similarity >= 0.999 && bytesDelta === 0)) {
    verdict = "identical";
    hint = "identical：两者无差异；若只换了凭证，说明该接口缺鉴权";
  } else if (similarity >= 0.9) {
    verdict = "same_shape";
    hint = `same_shape：形状一致、细节不同（${shape.metric} 相似度 ${similarity}）——看具体字段是否属于他人数据`;
  } else {
    verdict = "different";
    hint = "different：结构与内容都不同，先确认是不是换了页面/被 WAF 拦";
  }

  return {
    baseline: { status: baseline.status, body_bytes: baseline.body_bytes, duration_ms: baseline.duration_ms, sha256: shortHash(baseline.body) },
    variant: { status: variant.status, body_bytes: variant.body_bytes, duration_ms: variant.duration_ms, sha256: shortHash(variant.body) },
    delta: { status_changed: statusChanged, body_bytes: bytesDelta, similarity, duration_delta_ms: durationDelta, bytes_ratio: Number(bytesRatio.toFixed(3)) },
    timing,
    shape: shapeChanged ? { ...shape, json: json ? { ...json, same_structure: false } : json } : shape,
    verdict,
    hint,
  };
}
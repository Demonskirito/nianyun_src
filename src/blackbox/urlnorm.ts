/**
 * URL / 响应体归一化：把"路径即 ID"的 RESTful 遍历还原成同一个入口。
 *
 * 起因：熔断按 request URL（含 query）做指纹，`/api/doc/86` 和 `/api/doc/118` 是两个完全不同的
 * 请求身份，于是"换 id 遍历"可以无限打下去。这里把路径里的数字段、UUID、长 hex 换成占位符，
 * 响应体里对应的字面 id 也一起抹掉，这样同一资源族的多次访问会落到同一个 key、同一批指纹上。
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONG_HEX = /^[0-9a-f]{16,}$/i;
const DIGITS = /^\d+$/;
/** 响应体里出现的长数字（时间戳、雪花 id、毫秒）统一抹掉，避免同一资源不同分钟被判成"新指纹"。 */
const LONG_NUMBER = /\b\d{10,}\b/g;
const ISO_TIME = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g;
const UUID_ANY = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

export type NormalizedPath = {
  /** 归一化后的路径，例如 /api/doc/{id}。 */
  path: string;
  /** 被占位符替换掉的原始片段（响应体掩码要用）。 */
  ids: string[];
  /** 是否发生了归一化（纯静态路径为 false）。 */
  dynamic: boolean;
};

/** 单段占位符规则：纯数字 → {id}，UUID → {uuid}，长 hex → {hex}。 */
function segmentPlaceholder(segment: string): string | undefined {
  if (!segment) return undefined;
  if (UUID.test(segment)) return "{uuid}";
  if (DIGITS.test(segment)) return "{id}";
  if (LONG_HEX.test(segment)) return "{hex}";
  return undefined;
}

export function normalizePath(pathname: string): NormalizedPath {
  const clean = String(pathname || "/").split("?")[0] || "/";
  const ids: string[] = [];
  const segments = clean.split("/").map(segment => {
    const placeholder = segmentPlaceholder(segment);
    if (!placeholder) return segment;
    ids.push(segment);
    return placeholder;
  });
  return { path: segments.join("/") || "/", ids, dynamic: ids.length > 0 };
}

/**
 * 抹掉响应体里的"这一族的身份噪音"：
 *   1. 这次请求路径里被替换的原始 id（86 / 118 …）
 *   2. 任意 UUID、ISO 时间、10 位以上长数字
 * 剩下的才是"响应形状"，同一资源族换了 id 之后形状应该一致。
 */
export function normalizeBody(text: string, ids: string[] = []): string {
  let out = String(text || "");
  // 长的先替换，避免 "1" 把 "118" 咬掉一半
  for (const id of [...ids].filter(Boolean).sort((a, b) => b.length - a.length)) {
    out = out.split(id).join("{id}");
  }
  return out.replace(UUID_ANY, "{uuid}").replace(ISO_TIME, "{time}").replace(LONG_NUMBER, "{num}");
}

/** 学习到的路由模板：parent 前缀 → { 位置 → 见过的取值 }。 */
export type RouteMemory = Record<string, Record<string, string[]>>;

const STATIC_SUFFIX = /\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?|json|xml|txt)$/i;
/** 一眼就是"路由名"而不是"对象标识"的段：全大写动作、含下划线的处理器名、常见动词。 */
const ROUTE_WORD = /^(?:list|listall|detail|info|query|search|find|get|add|save|update|edit|delete|remove|del|create|export|import|upload|download|login|logout|refresh|token|config|setting|status|count|menu|tree|all|batch|page|index|home)$/i;

/**
 * 路由模板提取：`/api/users/alice` 与 `/api/users/bob` 折叠成 `/api/users/{p1}`。
 *
 * 纯数字/UUID/hex 由 `normalizePath` 静态识别；这里补的是"看着像名字"的对象标识
 * （alice/bob/slug/订单号后 8 位之类）。判断依据是**同一位置出现过 ≥2 个不同取值**，
 * 单次请求永远折叠不动——所以第一次命中会落到自己的原始路径上，第二次才开始合并。
 * 明显的路由词（list/detail/export…）与静态文件不做变量。
 */
export function routeTemplate(pathname: string, memory: RouteMemory): NormalizedPath {
  const base = normalizePath(pathname);
  const segments = (String(pathname || "/").split("?")[0] || "/").split("/");
  const ids = [...base.ids];
  const out: string[] = [];
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index]!;
    const parent = segments.slice(0, index).join("/");
    if (!segment) { out.push(segment); continue; }
    // 第 0/1 段是命名空间（/api、/static、/v2），永远不折叠：
    // 否则 "/static" 与 "/api" 会在同一位置被当成"两个不同取值"而合并。
    if (index <= 1) { out.push(segment); continue; }
    if (segmentPlaceholder(segment)) { out.push(outPlaceholder(segment)); continue; }
    if (STATIC_SUFFIX.test(segment) || ROUTE_WORD.test(segment) || segment.length > 64) { out.push(segment); continue; }
    const slot = memory[parent] ||= {};
    const values = slot[String(index)] ||= [];
    if (!values.includes(segment)) values.push(segment);
    if (values.length >= 2) {
      // 折叠后统一用位置占位符，并把原始值留给正文掩码
      out.push(`{p${index}}`);
      if (!ids.includes(segment)) ids.push(segment);
      continue;
    }
    out.push(segment);
  }
  const path = out.join("/") || "/";
  // 正文掩码要把"该位置已经见过的所有取值"都抹掉，而不只是本次那一个：
  // 否则 alice 的响应带 "alice"、bob 的带 "{id}"，同一形状会被算成两种指纹。
  for (const [parent, slots] of Object.entries(memory)) {
    if (!path.startsWith(parent === "" ? "/" : `${parent}/`)) continue;
    for (const values of Object.values(slots)) for (const value of values) if (!ids.includes(value)) ids.push(value);
  }
  return { path, ids, dynamic: path !== (String(pathname || "/").split("?")[0] || "/") };
}

function outPlaceholder(segment: string): string {
  return segmentPlaceholder(segment) || segment;
}
/**
 * 端点归一化：`/api/user/1` 与 `/api/user/2` 必须折叠成同一个节点。
 *
 * 不折叠的后果很实在：SRC 目标一次 IDOR 遍历就能在图里塞进上千个节点，
 * 撞上 500 上限后把真正有价值的假设节点挤掉（OOM 之前先"思维爆炸"）。
 *
 * 只折叠**高置信度的动态段**：纯数字、UUID、长 hex、日期、base64-ish 长串。
 * `/api/v2/user` 里的 `v2` 不折叠——那是版本号，折叠了会把不同接口合成一个。
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_LONG = /^[0-9a-f]{16,}$/i;
const NUMERIC = /^\d{1,}$/;
const DATE = /^\d{4}-\d{2}(-\d{2})?$/;
const B64_LONG = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;

/** 看起来像"某个具体对象的 id"而不是"路由的一部分"。 */
export function isDynamicSegment(segment: string): boolean {
  if (!segment) return false;
  if (NUMERIC.test(segment)) {
    // 纯数字但很短也可能是路由（/v2 除外由调用方处理）；这里按 id 处理。
    return true;
  }
  if (UUID.test(segment) || HEX_LONG.test(segment) || DATE.test(segment)) return true;
  // 长串里同时出现字母和数字，才当 token/id；纯字母（user/order）是路由。
  return B64_LONG.test(segment) && /\d/.test(segment) && /[A-Za-z]/.test(segment);
}

/** 从 URL 取路径部分（忽略 query/hash），保留前导斜杠。 */
export function urlPath(url: string): string {
  const raw = String(url || "").trim();
  if (!raw) return "/";
  try {
    const parsed = new URL(raw.includes("://") ? raw : `http://placeholder${raw.startsWith("/") ? "" : "/"}${raw}`);
    return parsed.pathname || "/";
  } catch {
    const withoutScheme = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    const afterHost = withoutScheme.slice(withoutScheme.indexOf("/") >= 0 ? withoutScheme.indexOf("/") : withoutScheme.length);
    return ((afterHost.split(/[?#]/)[0] || "/").replace(/\/+$/, "")) || "/";
  }
}

export function urlHost(url: string): string {
  const raw = String(url || "").trim();
  if (!raw) return "";
  try {
    return new URL(raw.includes("://") ? raw : `http://${raw}`).host.toLowerCase();
  } catch {
    const bare = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    return (bare.split("/")[0] || "").split(/[?#]/)[0]!.toLowerCase();
  }
}

/** `/api/user/1?x=2` → `/api/user/{id}`。 */
export function normalizePath(path: string): string {
  // URL 解析会把路由模板里的 `{id}` 编码成 `%7Bid%7D`，导致同一接口在图里
  // 出现两种节点形态、假设门认不出模板。这里先还原花括号再分段。
  const clean = String((path || "/").split(/[?#]/)[0] ?? "/").replace(/%7B/gi, "{").replace(/%7D/gi, "}");
  const segments = clean.split("/").filter(Boolean).map((segment, index, all) => {
    // 保留版本号段：v1 / v2 / api2 这类不折叠
    if (/^v\d+$/i.test(segment)) return segment;
    // 已经是路由模板（{id} / {userId} / :id）：统一成 {id}，与折叠后的形态对齐。
    if (/^\{[^/{}]+\}$/.test(segment) || /^:[A-Za-z_][\w-]*$/.test(segment)) return "{id}";
    if (isDynamicSegment(segment)) return "{id}";
    // 资源 id 常见形式：user-123、order_456（前缀 + 数字）
    const trailing = /^([A-Za-z][\w-]*?)[-_](\d{2,})$/.exec(segment);
    if (trailing) return `${trailing[1]}/{id}`;
    // 最后一节是 UUID 之外的 hash
    if (index === all.length - 1 && /^[0-9a-f]{8,15}$/i.test(segment)) return "{id}";
    return segment;
  });
  return `/${segments.join("/")}`;
}

/**
 * 从"具体 URL + 它的模板路径"里对齐出真正被观测到的对象值。
 *
 * 语义：图节点是 `/webapp/order/{id}/detail`，但这次请求实际打的是 `.../order/8817263/detail`。
 * 只有把 `8817263` 记下来，两身份对照才有一致的**对象**可比（"同一对象、换身份"），
 * 否则"越权"永远只能靠猜。值只截断保存在图属性里，不进 prompt 的原始列表。
 */
export function objectValuesOf(url: string, templatePath: string): string[] {
  const actual = urlPath(url).split("/").filter(Boolean);
  const template = String(templatePath || "").split("/").filter(Boolean);
  if (!actual.length || actual.length !== template.length) return [];
  const values: string[] = [];
  for (let index = 0; index < template.length; index += 1) {
    if (template[index] !== "{id}") continue;
    const value = actual[index];
    if (value && value !== "{id}" && !/%7B/i.test(value)) values.push(value.slice(0, 64));
  }
  return values.slice(0, 4);
}

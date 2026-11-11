/**
 * 默认浏览器身份（User-Agent）。
 *
 * 起因（2026-11-07 developer.aliyun.com 实测定稿）：
 * 同一个容器、同一条 Burp 出口、同一时刻、同一个 URL，只改 UA 与 cookie 两个变量：
 *
 * | UA | cookie | 结果 |
 * |---|---|---|
 * | 不带 | 无 | 403 / 7155B  CLIENT_UNCLASSIFIED |
 * | 不带 | 31 枚种子 | 403 / 7155B |
 * | 不带 | 31 枚 + 毒 cna | 403 / 7155B |
 * | Edge | 无 | 200 / 213KB |
 * | Edge | 31 枚种子 | 200 / 213KB |
 * | Edge | 31 枚 + 毒 cna | 403 / 7155B |
 *
 * 结论：这堵"身份墙"第一道门问的是"你像不像浏览器"，第二道才问"你的 cookie 干不干净"。
 *
 * 旧实现全链路裸发 UA——`http.request` 用 Playwright APIRequestContext 的默认 UA、
 * `httpx` 用 `httpx/1.x`、`nuclei` 用它自己的标识、`target-probe` 连 accept 都只在最后一刻补。
 * 于是整场 445 次调用 100% 撞墙：77+94 分钟、17M tokens 只换到 2 条中低危，
 * 而墙根本不在目标侧——是我们自己举着一张"我是脚本"的名牌。
 *
 * 设计取舍：
 * - **只补默认值，绝不覆盖显式值**。渗透里"非浏览器客户端"本身就是攻击面
 *   （UA 注入、缓存投毒、差异化审计），模型显式写 `headers["user-agent"]` 时必须原样生效。
 * - 可通过 `BLACKBOX_USER_AGENT` 配成任意值（含空串表示"故意裸发"）。
 */

/** 常见桌面 Edge/Chrome UA：比 HeadlessChrome 更少被风控盯上，也和 browser.open 的画像接近。 */
export const DEFAULT_BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";

/**
 * 解析当前会话该用的 UA。
 *
 * `BLACKBOX_USER_AGENT` 显式设为空串时返回空串——调用方据此**不注入**，
 * 这是"我要用裸 UA 做对照"的合法诉求，不能被默认值悄悄改掉。
 */
export function resolveUserAgent(values?: Record<string, string>): string {
  const configured = values ? values.BLACKBOX_USER_AGENT : undefined;
  if (configured !== undefined) return String(configured).trim();
  return DEFAULT_BROWSER_UA;
}

/** 请求头里是否已有 UA（大小写不敏感）。 */
export function hasUserAgent(headers: Record<string, string>): boolean {
  return Object.keys(headers).some(name => name.toLowerCase() === "user-agent");
}

/**
 * 缺 UA 时补默认浏览器身份：原地改 headers，返回是否注入过。
 *
 * 返回布尔而不是静默处理，是为了让调用方能在证据里写一句「本次用了默认浏览器 UA」——
 * 否则事后复盘会误以为模型真的指定了这个 UA。
 *
 * **只补 UA，不补 accept/accept-language**。实测单独一条 UA 就能过阿里云那堵墙，
 * 而多塞两条头会撞上 sqlmap 这类"`--headers` 只取一个值"的工具，把真正的头挤丢。
 */
export function applyDefaultUserAgent(headers: Record<string, string>, values?: Record<string, string>): boolean {
  if (hasUserAgent(headers)) return false;
  const ua = resolveUserAgent(values);
  if (!ua) return false;
  headers["user-agent"] = ua;
  return true;
}

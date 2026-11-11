/**
 * 工具权重与预算降级。
 *
 * 为什么需要权重：一次 `http.request` 和一个 300 秒的 `nuclei` 扫描在"工具调用次数"上是 1:1，
 * 但后者吃掉的墙钟时间可能是前者的 100 倍。按条数计费会让 Agent 用几十次廉价请求把预算磨光，
 * 或者反过来用一次昂贵扫描顶掉整批工作。这里给每个工具标一个整数权重，预算按权重累计。
 *
 * 为什么需要降级：playbook 的 timebox 是"整条打法的墙钟期望"（sqli 1500s 里大部分时间在 sqlmap）。
 * 如果本次 run 的墙钟预算已经放不下这个 timebox，直接掐断等于永远拿不到结论；正确做法是把打法
 * 降级到"快速探测模式"——只留轻量步骤（算术探测、时间盲注、结构化 diff），把重型扫描器摘掉。
 */

/** 工具默认权重：1 = 一次轻量请求；数字越大越贵。 */
export const TOOL_WEIGHTS: Record<string, number> = {
  "http.request": 1,
  "http.diff": 1,
  "burp.request": 1,
  "burp.send": 1,
  "burp.repeater": 1,
  "burp.compare": 1,
  "burp.convert": 1,
  "burp.decoder": 1,
  "burp.history": 1,
  "burp.sitemap": 1,
  "burp.entry": 1,
  "burp.issues": 1,
  "burp.ws_history": 1,
  "burp.scope": 1,
  "burp.intercept": 1,
  "burp.collab_generate": 1,
  "burp.collab_poll": 1,
  "burp.scan_status": 1,
  "burp.scan_stop": 1,
  "burp.info": 1,
  "burp.control": 1,
  "burp.options": 1,
  "burp.cookies": 1,
  "burp.storage": 1,
  "burp.sitemap_issues": 1,
  "burp.sitemap_add": 1,
  "burp.scope_edit": 1,
  "burp.bchecks": 1,
  "evidence.read": 1,
  "browser.close": 1,
  "browser.screenshot": 1,
  "browser.open": 2,
  "recon.interactsh": 1,
  "recon.jwt": 1,
  "recon.graphql": 1,
  "recon.dns": 1,
  "recon.parameters": 2,
  "recon.js_endpoints": 2,
  "recon.subdomains": 2,
  "recon.http_probe": 2,
  "recon.historical_urls": 2,
  "recon.content_discovery": 3,
  "recon.xss": 3,
  "recon.cms": 3,
  "recon.tls": 3,
  "recon.api_routes": 3,
  "recon.ports": 3,
  "recon.secrets": 3,
  "burp.scan": 3,
  "burp.crawl": 3,
  "burp.send_batch": 3,
  "burp.intruder": 3,
  "burp.intruder_send": 3,
  "burp.scan_issues": 3,
  "burp.scan_report": 3,
  "burp.proxy_rule": 3,
  "burp.websocket": 3,
  "katana.crawl": 5,
  "recon.nuclei": 5,
  "recon.sql": 5,
  "recon.sast": 5,
  "recon.traffic_diff": 1,
  // 协商 / 沙箱 / 工作区：字典清单与参数协商几乎免费；写 POC 跑沙箱介于轻重之间；
  // 翻工作区最便宜（都是本地文件，不打目标）。
  "recon.wordlists": 1,
  "recon.scan_profile": 1,
  // 竞态发射：一次调用打 N 条（≤50），按重型算，但比 nuclei 便宜。
  "recon.race_condition": 4,
  "browser.storage": 1,
  "browser.tab": 1,
  "fs.list": 1,
  "fs.read": 1,
  "fs.grep": 1,
  "exec.python": 3,
  "exec.bash": 3,
};

/** 重型工具：慢、吵、单次就能吃掉整批时间；降级模式下不执行。 */
export const HEAVY_TOOLS: ReadonlySet<string> = new Set([
  "katana.crawl", "recon.nuclei", "recon.sql", "recon.sast",
  "recon.content_discovery", "recon.xss", "recon.cms", "recon.tls",
  "recon.api_routes", "recon.ports", "recon.secrets",
  "burp.scan", "burp.crawl", "burp.intruder", "burp.intruder_send", "burp.scan_report",
]);

export function toolWeight(tool: string, overrides: Record<string, number> = {}): number {
  const custom = overrides[tool];
  if (Number.isFinite(custom) && Number(custom) > 0) return Math.floor(Number(custom));
  return TOOL_WEIGHTS[tool] ?? 1;
}

export function isHeavyTool(tool: string): boolean {
  return HEAVY_TOOLS.has(tool);
}

export type BudgetMode = "full" | "fast";

export type BudgetWindow = {
  /** 剩余墙钟（含工具执行时间）；0 表示不限制。 */
  wallMsLeft: number;
  /** 剩余调度预算（LLM 思考 + 决策）；0 表示不限制。 */
  scheduleMsLeft: number;
  /** 剩余工具权重额度；0 表示不限制。 */
  weightLeft: number;
  /** 当前待推进 playbook 的时间盒（秒）。 */
  timeboxSec: number;
};

/**
 * full：按完整 playbook 推进（含 sqlmap/nuclei/katana 这类重型步骤）。
 * fast：墙钟或权重已经放不下完整时间盒 → 只做轻量步骤，跳过重型扫描器。
 */
/**
 * 一个重型步骤（nuclei / sqlmap / katana）的墙钟期望。
 *
 * 降级只看"还剩不剩得下一次重型步骤"，不再拿整条 playbook 的时间盒当判据：
 * timebox 是"整场打法"的期望（600–1500s），wallMsLeft 是"本次 run 的剩余"（默认 1800s），
 * 两者不可比 —— 跑 sqli（timebox 1500）满 300s 后 wallMsLeft 恒小于 timebox，
 * 于是本 run 剩下的 1500 秒里 sqlmap 永远被判 budget_degraded。
 * 而且 budgetView 取的是 min(timebox)，最紧的那条打法会绑架所有打法。
 */
export const HEAVY_STEP_SEC = 300;

export function budgetMode(window: BudgetWindow): { mode: BudgetMode; reasons: string[] } {
  const reasons: string[] = [];
  if (window.wallMsLeft > 0 && window.wallMsLeft < HEAVY_STEP_SEC * 1000) {
    reasons.push(`墙钟只剩 ${Math.round(window.wallMsLeft / 1000)}s，不够一次重型步骤（约 ${HEAVY_STEP_SEC}s）`);
  }
  if (window.weightLeft > 0 && window.weightLeft < 5) {
    reasons.push(`工具权重只剩 ${window.weightLeft}（重型扫描一次要 3–5）`);
  }
  if (window.scheduleMsLeft > 0 && window.scheduleMsLeft < 60_000) {
    reasons.push(`调度预算只剩 ${Math.round(window.scheduleMsLeft / 1000)}s，只够收尾`);
  }
  return { mode: reasons.length ? "fast" : "full", reasons };
}

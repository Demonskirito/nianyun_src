/**
 * Burp 被动扫描的"收账"逻辑。
 *
 * 背景（21 场会话实测，2026-11-06）：37 个 burp 工具里只用了 6 个，`burp.issues` **0 次**。
 * 也就是说 Burp 只被当成"历史记录阅读器"——所有 HTTP 与浏览器流量都从它肚子里过，
 * 它的被动扫描器早就把这些响应审过一遍了，但没有人去读，那些 issue 就烂在 site map 里。
 *
 * 这里只做三件不需要模型配合的事：
 *   ① 会话开始时替模型**启动**一次被动审计（mode=passive，只审不给目标发攻击流量）；
 *   ② 每几轮去 `/issues` 收一次新问题（site map 里包括被动扫描从代理流量里攒出来的）；
 *   ③ 有新问题就塞一条插话进下一轮上下文，点名"读明细 → 复现 → 或写负向结论"。
 *
 * 判定与文本都在这里（纯函数），网络调用留在 tools.ts，调度留在 desk.ts。
 */

export type BurpIssue = {
  name: string;
  severity: string;
  confidence?: string;
  base_url?: string;
  detail?: string;
};

/** 开始审计的三种口径：off 完全不动；passive 只审已抓到的流量；active 会真发攻击载荷。 */
export type ScanMode = "off" | "passive" | "active";

/**
 * `BLACKBOX_BURP_SCANNER`：默认 passive。
 *
 * 默认开而不是默认关，理由是这个动作对目标零攻击流量、对操作员的 Burp 只有一个审计对象，
 * 成本远小于"整场跑完谁也没读过 scanner 结论"。要静音就写 off。
 * active 必须显式写，且仍受规则文档 `tools["burp.scan"].allow_active_scan` 约束。
 */
export function scanMode(values: Record<string, string> = {}): ScanMode {
  const raw = String(values.BLACKBOX_BURP_SCANNER || "").trim().toLowerCase();
  if (raw === "off" || raw === "false" || raw === "0" || raw === "no") return "off";
  if (raw === "active") return "active";
  return "passive";
}

/** 一个问题在账本里的身份：同名 + 同路径 + 同严重度视为同一条（Burp 会重复报同一处）。 */
export function issueKey(issue: BurpIssue): string {
  // 空白折叠：Burp 的 name 常带换行/多空格，逐字比较会把同一处报成两条。
  const name = String(issue.name || "").replace(/\s+/g, " ").trim().toLowerCase();
  const base = String(issue.base_url || "").trim().replace(/[?#].*$/, "").toLowerCase();
  const severity = String(issue.severity || "").trim().toLowerCase();
  return `${name}|${base}|${severity}`;
}

// Burp 的字典里 info 级写作 "INFORMATION"（见实跑 whois.aliyun.com：12 条 INFORMATION）。
// 漏了它就会被归到默认 0，虽然结论一样（不算可行动），但分布统计会显示成 unknown，看着像解析失败。
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0, information: 0 };

export function severityRank(severity: unknown): number {
  return SEVERITY_RANK[String(severity || "").trim().toLowerCase()] ?? 0;
}

/**
 * 值得占预算的问题。
 *
 * 只取 high/medium：Burp 对任意页面都会报一堆 info（缺 CSP、缺 X-Frame-Options），
 * 全塞给模型只会把预算烧在"补安全头"这种不构成渗透结论的项上。
 */
export function worthActingOn(issues: BurpIssue[]): BurpIssue[] {
  return issues.filter(issue => severityRank(issue.severity) >= 2);
}

/** 以前没见过的（按 issueKey 去重），按严重度从高到低。 */
export function freshIssues(issues: BurpIssue[], seen: Iterable<string>): BurpIssue[] {
  const known = new Set(seen);
  const fresh: BurpIssue[] = [];
  const added = new Set<string>();
  for (const issue of issues) {
    const key = issueKey(issue);
    if (known.has(key) || added.has(key)) continue;
    added.add(key);
    fresh.push(issue);
  }
  return fresh.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

/** 一条插话的正文：说清"是什么、在哪、下一步用哪个工具"。 */
export function digestText(fresh: BurpIssue[], host: string): string {
  const top = fresh.slice(0, 5)
    .map(issue => `${issue.severity}:${issue.name} @ ${String(issue.base_url || host).slice(0, 80)}`)
    .join("；");
  const more = fresh.length > 5 ? `（另有 ${fresh.length - 5} 条）` : "";
  return `Burp 被动扫描在 ${host} 上新增 ${fresh.length} 条候选问题：${top}${more}。`
    + "用 burp.issues 取明细（可带 offset/limit 翻页），逐条用 http.diff / burp.send 复现："
    + "成立就写 finding 并引用复现证据；不成立写 verified_negative 并说明为什么是误报（Burp 的结论是候选，不是结论）。";
}

/**
 * 严重度分布：`[{severity:"low",count:8},{severity:"information",count:12}]`，按严重度降序。
 *
 * 存在的理由很具体：实跑 whois.aliyun.com 那场读回 20 条，全是 INFORMATION 12 / LOW 8，
 * 过滤后 0 条可行动项。没有分布就只能记一个 total——报告里写"Burp 报了 20 条问题"是假话，
 * 那 20 条一条都不能当结论。
 */
export function severityCounts(issues: BurpIssue[]): Array<{ severity: string; count: number }> {
  const tally = new Map<string, number>();
  for (const issue of issues) {
    const key = String(issue.severity || "").trim().toLowerCase() || "unknown";
    tally.set(key, (tally.get(key) || 0) + 1);
  }
  return [...tally.entries()]
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.count - a.count);
}

/** 分布的紧凑写法：`LOW 8 / INFORMATION 12`。 */
export function severityLine(issues: BurpIssue[]): string {
  const counted = severityCounts(issues);
  if (!counted.length) return "无";
  return counted.map(item => `${item.severity.toUpperCase()} ${item.count}`).join(" / ");
}

/**
 * "读到了、但一条 high/medium 都没有"的说明。
 *
 * 这是实测里最常见的结果，也是之前最糟的结果：`fresh.length === 0` 直接 return，
 * 会话里既没有插话也没有事件，从模型视角看和"这个功能根本不存在"完全一样。
 * 这里把它说清楚，让模型知道①已经有人替它读过②这些条目不值得占预算③后面有高价值项会自动提醒。
 */
export function quietDigest(total: number, issues: BurpIssue[], host: string): string {
  return `Burp 被动扫描已审完 ${host} 的 ${total} 条问题，其中没有一条 high/medium（分布：${severityLine(issues)}）。`
    + "这些是缺安全头、响应可缓存、前端组件带已知版本号一类，不构成渗透结论，**不要为它们单独派任务、也不要自己重扫一遍**；"
    + "出现 high/medium 会自动插话提醒。想自己翻明细可以用 burp.issues（可带 offset/limit）。";
}

/**
 * 该不该这一轮去收账。
 *
 * 第 1 轮必收（会话开始前 Burp 里可能已经有历史 issue），之后每 3 轮收一次：
 * 太勤会白烧桥调用，太懒则问题攒到会话结束才出现（那时已没有预算验证）。
 */
export function shouldHarvest(round: number, interval = 3): boolean {
  if (round <= 1) return true;
  return round % interval === 0;
}

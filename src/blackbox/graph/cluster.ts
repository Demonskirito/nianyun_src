/**
 * 字典节点的路径聚类与抽样探针
 *
 * 背景（两轮实测，同一个病）：
 *   gray-push-intl：一次 `recon.content_discovery` → 221 个端点，全 untested；
 *   note.yun      ：一次 `recon.content_discovery` → 224 个端点，全 untested。
 *   两轮里 agent 一次都没有回头请求过这些节点。系统三次点名"另有 224 块没动过"，
 *   它三次都退回到已经知道的入口。
 *
 * 诊断：这不是"懒"，是**选择过载**。224 个平级、无上下文的 URL 会让注意力失效；
 * 而"去看看它们"这种指令本身没给出**先看哪一个**，所以等于没指令。
 *
 * 对策：在图的这一侧就把 224 个折叠成 4-5 个代表（每个类别 1 个），
 * 由控制面合成一个契约明确的任务，并把焦点强制切过去（见 focus.ts 的 forced 分支）。
 * 命中 WAF 的类别整体标灰（泛化拦截），返回 200 的类别才展开。
 */

export type ClusterName = "sensitive" | "admin" | "api_doc" | "static" | "other";

export type ClusterBucket = {
  name: ClusterName;
  /** 该类别全部路径（按字典顺序去重）。 */
  members: string[];
  /** 抽样代表（1 个）。 */
  probe: string;
};

export type ProbePlan = {
  host: string;
  /** 被折叠的总数（原始字典命中数）。 */
  total: number;
  buckets: ClusterBucket[];
  /** 未进入任何 bucket 的路径（理论上为 0，保留给防御性统计）。 */
  unfolded: number;
};

const PATTERNS: Array<{ name: ClusterName; test: RegExp }> = [
  // 敏感文件/备份：命中一个就意味着"配置或源码可能在这"
  { name: "sensitive", test: /(^|\/)(\.env|\.git|\.svn|\.hg|\.ds_store|web\.config|\.htaccess|config\.(php|inc\.php|json|ya?ml)|wp-config\.php|(backup|www|web|html|wwwroot|site|db)\.(zip|tar|tar\.gz|tgz|rar|7z|sql|bak)|index\.php~|\.bak$)/i },
  // 管理后台/运维面板
  { name: "admin", test: /(^|\/)(admin|administrator|manage|manager|console|dashboard|login|signin|wp-admin|phpmyadmin|druid|nacos|actuator|jmx|solr|kibana|grafana)(\/|$|\.|-)/i },
  // 接口文档/调试面
  { name: "api_doc", test: /(^|\/)(swagger|swagger-ui|swagger-resources|v2\/api-docs|v3\/api-docs|api-docs|openapi|graphql|redoc|api\/docs|__swagger__)/i },
  // 静态资源/噪音
  { name: "static", test: /\.(css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webp|avif)$/i },
];

/** 给一条路径归类。顺序即优先级：敏感文件 > 后台 > 文档 > 静态 > 其它。 */
export function classifyPath(path: string): ClusterName {
  const clean = String(path || "").trim();
  if (!clean) return "other";
  for (const rule of PATTERNS) if (rule.test.test(clean)) return rule.name;
  return "other";
}

/** 抽样优先级：先探最可能出事的类别。 */
const ORDER: ClusterName[] = ["sensitive", "api_doc", "admin", "other", "static"];

/**
 * 把 224 个路径折叠成 ≤5 个代表。
 *
 * 抽样规则（确定性，不用随机数）：
 *   · 每类取**最短路径**作代表（最短的那个最可能是真实入口，不做无谓的深层猜测）；
 *   · 每类最多 1 个，总数上限 `maxBuckets`。
 * 确定性很重要：同一份账本重放必须得到同一组探针，否则测试与复盘没法对齐。
 */
export function planProbes(paths: string[], host: string, options: { maxBuckets?: number } = {}): ProbePlan {
  const maxBuckets = Math.max(1, options.maxBuckets ?? 5);
  const unique = Array.from(new Set(paths.map(path => String(path || "").trim()).filter(Boolean)));
  const grouped = new Map<ClusterName, string[]>();
  for (const path of unique) {
    const name = classifyPath(path);
    const list = grouped.get(name) || [];
    list.push(path);
    grouped.set(name, list);
  }
  const buckets: ClusterBucket[] = [];
  for (const name of ORDER) {
    const members = grouped.get(name);
    if (!members?.length) continue;
    const probe = members.slice().sort((a, b) => a.length - b.length || a.localeCompare(b))[0]!;
    buckets.push({ name, members, probe });
    if (buckets.length >= maxBuckets) break;
  }
  const covered = buckets.reduce((sum, bucket) => sum + bucket.members.length, 0);
  return { host, total: unique.length, buckets, unfolded: Math.max(0, unique.length - covered) };
}

/** 抽样任务的 id（带戳，便于一个会话里多次爆破各自成任务，且语义去重不会把它们并成一个）。 */
export function probeTaskId(stamp: string): string {
  return `T_DICT_PROBE_${stamp}`;
}

/**
 * 合成抽样探针任务。
 *
 * 契约是"填空题"而不是"问答题"：deliverables 直接写明要交什么，
 * 这样 closureAudit 有东西可审，模型也知道怎样算完成。
 */
export function probeTask(plan: ProbePlan, stamp: string): {
  id: string; target: string; purpose: string; reason: string; completion_criteria: string;
  deliverables: string[]; success_criteria: string; playbook: string;
} {
  const names = plan.buckets.map(bucket => `${bucket.name}(${bucket.members.length})`).join("、");
  return {
    id: probeTaskId(stamp),
    target: plan.host,
    purpose: `对 ${plan.host} 的 ${plan.buckets.length} 类路径做抽样探针，判定 WAF 粒度与真实存在性`,
    reason: `字典一次产出 ${plan.total} 个端点（${names}），全部未验证；平铺给模型等于没有信息，先抽样 4-${plan.buckets.length} 个定生死`,
    completion_criteria: `对 ${plan.buckets.map(bucket => bucket.probe).join("、")} 各发 1 次匿名请求，按响应归类：`
      + "200/30x=真实存在（展开该类别）、401/403=存在但需身份、412/WAF 指纹=该类整体泛化拦截（整类标灰）、404=该类抽样代表不存在（换该类下一个）",
    deliverables: ["waf_fingerprint", "existing_paths"],
    success_criteria: "至少 1 个类别得到确定结论（展开 / 泛化拦截 / 不存在），且结论附证据 id",
    playbook: "unauth_exposure",
  };
}

/**
 * WAF 泛化：代表节点命中拦截页时，整类一起标灰。
 *
 * 依据是实测的 OPPO WAF 行为——同一主机上所有"敏感路径"返回同一个 2681B 阻断页
 * （`.env`/`.git/config`/`actuator`/`druid`/`nacos` 指纹完全一致）。
 * 继续逐个撞同一类路径是纯浪费，但**换类别**仍然有意义（文档面与静态面是另一条规则）。
 */
export function collapsedByWaf(plan: ProbePlan, probe: string): ClusterBucket | undefined {
  return plan.buckets.find(bucket => bucket.probe === probe);
}
/**
 * 展开规则（Expansion Rules，2026-10-28）。
 *
 * 抽样只解决"先看哪一个"，不解决"看到之后怎么办"：
 *   /graphql 回 200   → 这一类剩下的 3 条值得逐个打（同一套路由规则下它们大概率也在）
 *   /.env 回 412/WAF  → 这一类剩下的**一条都不用打**（OPPO WAF 是按路径类泛化拦截的，
 *                       实测 9 条 412 的响应体字节完全一致：2681B securityfs 阻断页）
 *
 * 返回 `expand`（提升为下一轮强制焦点）与 `collapse`（整类标灰，省掉的次数就是收益）。
 */
export type ProbeOutcome = {
  /** 探针路径（bucket.probe）。 */
  probe: string;
  status?: number;
  /** 命中 WAF/拦截页时为 true（见 extract.ts 的 wallOf）。 */
  blocked?: boolean;
  /** 响应是否与 catch-all 基线同形（同状态 + 同字节）：同形说明这条不代表"存在"。 */
  catch_all?: boolean;
};

export type ExpansionPlan = {
  bucket?: ClusterName;
  verdict: "expand" | "collapse" | "skip";
  expand: string[];
  collapse: string[];
  reason: string;
};

export function expandFromProbe(plan: ProbePlan, outcome: ProbeOutcome, options: { limit?: number } = {}): ExpansionPlan {
  const limit = Math.max(1, options.limit ?? 3);
  const bucket = plan.buckets.find(item => item.probe === outcome.probe);
  if (!bucket) return { verdict: "skip", expand: [], collapse: [], reason: `探针 ${outcome.probe} 不属于任何类别` };
  const others = bucket.members.filter(path => path !== bucket.probe);
  const status = Number(outcome.status ?? 0);
  if (outcome.blocked || status === 412 || status === 418 || status === 1020) {
    return {
      bucket: bucket.name, verdict: "collapse", expand: [], collapse: others,
      reason: `${bucket.name} 的探针 ${bucket.probe} 命中拦截（${status || "WAF"}）：同类剩余 ${others.length} 条按泛化拦截一并不打`,
    };
  }
  if (outcome.catch_all) {
    return {
      bucket: bucket.name, verdict: "collapse", expand: [], collapse: others,
      reason: `${bucket.name} 的探针 ${bucket.probe} 与 catch-all 基线同形：这条路径的存在性无法从响应判断，同类一并标灰`,
    };
  }
  if (status >= 200 && status < 400) {
    return {
      bucket: bucket.name, verdict: "expand", expand: others.slice(0, limit), collapse: [],
      reason: `${bucket.name} 的探针 ${bucket.probe} 返回 ${status}：展开同类下 ${Math.min(limit, others.length)} 条`,
    };
  }
  if (status === 401 || status === 403) {
    return {
      bucket: bucket.name, verdict: "expand", expand: others.slice(0, limit), collapse: [],
      reason: `${bucket.name} 的探针 ${bucket.probe} 返回 ${status}：路径存在但需要身份，先记鉴权墙，再用已认证身份打同类`,
    };
  }
  return {
    bucket: bucket.name, verdict: "skip", expand: [], collapse: [],
    reason: `${bucket.name} 的探针 ${bucket.probe} 返回 ${status || "无状态"}：这一类先放着，换下一个类别的代表`,
  };
}
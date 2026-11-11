/**
 * 证据含金量：一次工具结果到底值多少。
 *
 * "证据条数"是最差的进展指标——10 条 404 也是 10 条证据，指纹照样变，模型就能在一个死端点上
 * 无限刷下去。这里按图谱的结构性变化打分（不引入任何 NLP，只用已经算好的 Attack Graph）：
 *
 *   +3 高价值：新 ENDPOINT（非 catch-all）/ 新 PARAMETER / 新 IDENTITY / 新漏洞态
 *   +1 中价值：已知端点的状态码变化、响应体大小显著变化（>20%）、新增导航/调用边
 *    0 噪音  ：重复 404、与基线一致的 catch-all、已标死胡同的再次命中
 *
 * 只有 tier > 0 的结果才算"这一轮有进展"，`focus_usage.value_score` 才增加。
 */

export type ValueTier = 0 | 1 | 3 | 5;

export type ValueScore = {
  /** 本次增益总分（可含多个高价值发现）。 */
  score: number;
  /** 本次最高档位。 */
  tier: ValueTier;
  high: number;
  medium: number;
  noise: number;
  reasons: string[];
  /** 触发"临界信号"判定的事实（申诉通道用）。 */
  critical: { identity?: string; redirect?: string; hypothesis?: string };
};

export function emptyValue(): ValueScore {
  return { score: 0, tier: 0, high: 0, medium: 0, noise: 0, reasons: [], critical: {} };
}

export function mergeValue(a: ValueScore, b: ValueScore): ValueScore {
  return {
    score: a.score + b.score,
    tier: Math.max(a.tier, b.tier) as ValueTier,
    high: a.high + b.high,
    medium: a.medium + b.medium,
    noise: a.noise + b.noise,
    reasons: [...a.reasons, ...b.reasons].slice(0, 8),
    critical: { ...a.critical, ...b.critical },
  };
}

/** catch-all 判定：任何路径都回同一份内容（状态码 + 长度 + 类型都一致）。 */
export function looksCatchAll(input: { status?: number; contentLength?: number; contentType?: string; baseline?: { status?: unknown; content_length?: unknown; content_type?: unknown } }): boolean {
  const baseline = input.baseline;
  if (!baseline) return false;
  const sameStatus = Number(baseline.status ?? 0) === Number(input.status ?? 0);
  const sameLength = Number(baseline.content_length ?? -1) === Number(input.contentLength ?? -1);
  const sameType = String(baseline.content_type ?? "") === String(input.contentType ?? "");
  return sameStatus && sameLength && sameType && input.status !== undefined;
}

export type IngestValueInput = {
  newNodes: string[];
  newEdges: string[];
  deadEnds: string[];
  /** 请求前的端点状态（无基线 = 首次碰到这个端点）。 */
  before?: { status?: string; code?: unknown; content_length?: unknown; content_type?: unknown };
  after?: { status?: string; code?: unknown; content_length?: unknown; content_type?: unknown };
  /** 响应头里的推进信号。 */
  headers?: Record<string, unknown>;
  /**
   * @deprecated 假设池里「推导出了多少条」不是进展指标。保留仅为兼容旧调用方：
   * 现在只记一句说明，不计分、不写 critical。真实调用请传 newHypothesisTasks。
   */
  newHypotheses?: number;
  /** 本轮真正转成验证任务的假设条数（enqueueHypothesisTasks 的返回值）。 */
  newHypothesisTasks?: number;
  /** 是否为重复命中（repeats ≥ 2）。 */
  repeated?: boolean;
  /** 拓扑势能快照：本轮前后"到最近高价值目标"的最短成本（见 potential.ts）。 */
  potential?: { before?: number; after?: number; improved?: boolean; delta?: number; reason?: string };
  /**
   * 对照结论（http.diff / recon.traffic_diff / burp.compare）。
   *
   * 2026-10-31：SRC 的进展单位是"一条可复现的差异"，不是"一个新节点"。
   * 过去 katana 一次 +377 节点拿 +5 分，而真正定性的对照（identical=false）最多 +1。
   * 这里给"有差异的对照"直接按高价值记，并把结论写进 critical 供申诉/报告使用。
   */
  comparison?: { identical?: boolean; score?: number; field?: string };
};

/** 一次工具结果 → 价值评分。 */
export function scoreIngest(input: IngestValueInput): ValueScore {
  const value = emptyValue();
  const high = (reason: string) => {
    value.high += 1;
    value.score += 3;
    value.tier = 3;
    value.reasons.push(`+3 ${reason}`);
  };
  const medium = (reason: string) => {
    value.medium += 1;
    value.score += 1;
    if (value.tier < 1) value.tier = 1;
    value.reasons.push(`+1 ${reason}`);
  };
  const noise = (reason: string) => {
    value.noise += 1;
    value.reasons.push(`0 ${reason}`);
  };

  // 势能优先：这是唯一"有全局视角"的判据。路径变短 = 真的逼近核心，直接压过一切结构增益。
  if (input.potential?.improved) {
    value.high += 1;
    value.score += 5;
    value.tier = 5;
    value.reasons.unshift(`+5 势能提升（${input.potential.reason || "最短路径变短"}）`);
    return value;
  }
  const newEndpoints = input.newNodes.filter(id => id.startsWith("ep:"));
  const newParams = input.newNodes.filter(id => id.startsWith("param:"));
  const newIdentities = input.newNodes.filter(id => id.startsWith("id:"));
  const newVulns = input.newNodes.filter(id => id.startsWith("vuln:"));

  // 新端点：catch-all 不算（动态路由会把每个随机路径都"发现"一次）。
  const before = input.before;
  const after = input.after;
  const catchAll = looksCatchAll({
    status: Number(after?.code ?? NaN) || undefined,
    contentLength: Number(after?.content_length ?? NaN) || undefined,
    contentType: after?.content_type !== undefined ? String(after.content_type) : undefined,
    baseline: before ? { status: before.code, content_length: before.content_length, content_type: before.content_type } : undefined,
  });
  // 势能视角下，"新端点/新参数"只有让路径变短才算高价值；否则只是边缘探索。
  // 身份与漏洞态不降级：它们本身就是可以横向/复用的战略资产。
  const marginal = input.potential !== undefined && input.potential.improved !== true;
  if (newEndpoints.length && !catchAll && !marginal) high(`新端点 ${newEndpoints.slice(0, 2).join("、")}${newEndpoints.length > 2 ? ` 等 ${newEndpoints.length} 个` : ""}`);
  if (newEndpoints.length && !catchAll && marginal) {
    value.score += 0.5;
    value.reasons.push(`+0.5 边缘探索：新端点 ${newEndpoints.slice(0, 2).join("、")}（未缩短任何通往目标的路径）`);
  }
  if (newEndpoints.length && catchAll) noise("新端点与基线完全一致（catch-all）");
  if (newParams.length && !marginal) high(`新参数 ${newParams.slice(0, 3).join("、")}`);
  if (newParams.length && marginal) {
    value.score += 0.5;
    value.reasons.push(`+0.5 边缘探索：新参数 ${newParams.slice(0, 3).join("、")}（未缩短任何通往目标的路径）`);
  }
  if (newIdentities.length) {
    high(`新身份 ${newIdentities.slice(0, 2).join("、")}`);
    value.critical.identity = newIdentities[0];
  }
  if (newVulns.length) high(`新漏洞态 ${newVulns.slice(0, 2).join("、")}`);

  // 状态迁移：untested → vulnerable/blocked 已经是"结构性变化"，按高价值算。
  if (before && after && before.status !== after.status) {
    if (String(after.status) === "vulnerable" || String(after.status) === "dead_end") high(`节点状态 ${before.status} → ${after.status}`);
  }
  if (before?.code !== undefined && after?.code !== undefined && Number(before.code) !== Number(after.code)) {
    medium(`状态码 ${Number(before.code)} → ${Number(after.code)}`);
  }
  const lengthBefore = Number(before?.content_length ?? 0);
  const lengthAfter = Number(after?.content_length ?? 0);
  if (lengthBefore > 0 && lengthAfter > 0 && Math.abs(lengthAfter - lengthBefore) / lengthBefore > 0.2) {
    medium(`响应体 ${lengthBefore} → ${lengthAfter} 字节（>20%）`);
  }
  if (!newEndpoints.length && !newParams.length && input.newEdges.length && !newIdentities.length) medium(`新增 ${input.newEdges.length} 条图边`);
  /**
   * 假设增益只认「转成任务的条数」（2026-11-07，对照会话 1dd9ded9ed239711）。
   *
   * 旧写法把假设池推导出的条数直接记 medium + 写 critical.hypothesis：每轮固定
   * 「新假设 95 条」给焦点预算续命，而 40 轮实际只沉淀了 8 条假设任务（0.4%）。
   * 池子大小跟"这一步有没有逼近目标"无关；critical 也不再由条数触发，
   * 只保留 comparison-diff 那种真正的定性信号。
   */
  const hypothesisTasks = Math.max(0, Math.trunc(Number(input.newHypothesisTasks ?? 0)) || 0);
  if (hypothesisTasks > 0) medium(`新假设任务 ${hypothesisTasks} 条`);
  else if (input.newHypotheses) value.reasons.push(`（假设池推导 ${input.newHypotheses} 条，未转成任务，不计增益）`);
  if (input.headers) {
    const cookie = headerOf(input.headers, "set-cookie");
    const location = headerOf(input.headers, "location");
    if (cookie) { medium("响应头 Set-Cookie（拿到会话）"); value.critical.identity = value.critical.identity || "set-cookie"; }
    if (location) { medium(`响应头 Location: ${location.slice(0, 60)}`); value.critical.redirect = location.slice(0, 120); }
  }
  if (input.deadEnds.length) noise(`死胡同 ${input.deadEnds.slice(0, 2).join("、")}`);
  // 对照差异：这是"能定性"的证据，优先级高于新节点（新节点可能只是同一个外壳）。
  if (input.comparison && input.comparison.identical === false) {
    high(`对照出现差异${input.comparison.field ? `（${input.comparison.field}）` : ""}${input.comparison.score ? ` diff=${input.comparison.score}` : ""}`);
    value.critical.hypothesis = value.critical.hypothesis || "comparison-diff";
  } else if (input.comparison?.identical === true) {
    // 判否也是结论：一次对照把某个假设排除了，这是**验证进展**，不是噪声。
    //
    // 2026-11-02 m.ctrip.com 实测：整场 50 次 http.request 只配了 4 次 http.diff，
    // 而且这 4 次里没有一次是真正的匿名/跨身份对照。根因之一是账算反了——
    // 对照判否在这里记 noise（0 分）→ 连续 3 轮 no_progress → 触发 focus_stalled，
    // 于是"回来做第一次对照"在评分上永远亏，"去挖第十五个 /api"永远赚。
    // 现在判否给 +1（与 medium 同档，不计 tier，所以不会顶掉真有差异的证据）。
    if (input.repeated) noise("同一对照重复执行，无新结论");
    else medium("对照判否（假设被排除，属验证进展）");
  }
  // 边缘探索：确实是新东西，但没让任何路径变短。给 0.5 分（记账），tier 仍是 0（不让它续命）。
  if (!value.score && !value.noise && input.newNodes.length) {
    value.score += 0.5;
    value.reasons.push("+0.5 边缘探索（新节点但对通往目标的路径无帮助）");
  }
  if (!value.score && !value.noise) {
    if (input.repeated) noise("重复响应，图没有任何变化");
    else noise("图没有结构性变化");
  }
  return value;
}

function headerOf(headers: Record<string, unknown>, name: string): string | undefined {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name && value !== undefined && value !== null && String(value).trim()) {
      return String(Array.isArray(value) ? value.join("; ") : value);
    }
  }
  return undefined;
}

/** 把一轮的价值评分压成一行给模型看（"这轮到底赚了没有"）。 */
export function valueLine(value: ValueScore | undefined): string {
  if (!value) return "";
  const parts = [`+${value.score}`, `高价值 ${value.high}`, `中价值 ${value.medium}`, `噪音 ${value.noise}`];
  const reasons = value.reasons.slice(0, 3).join("；");
  return `本轮证据增益 ${parts.join(" / ")}${reasons ? `：${reasons}` : ""}`;
}

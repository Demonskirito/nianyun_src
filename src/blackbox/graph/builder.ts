/**
 * 图构建器：把工具结果翻译成节点与边。
 *
 * 设计约束（都是被现实逼出来的）：
 *   - **只吃摘要，不吃 body**：`content_length`、`status_code`、参数名进图；响应体留在 evidence ledger。
 *   - **合并优先**：同一端点重复命中只累加 `hits`/`repeats`，不新建节点。
 *   - **上限与裁剪**：节点超上限先丢 `dead_end` 里最久没更新的，`vulnerable` 与 `identity` 永不丢。
 *   - **不猜**：工具没给的信息不编（没有 status 就不写 status_code）。
 */
import { normalizePath, urlHost, urlPath } from "./endpoint.js";
import { assertEvidenceContract } from "./evidence.js";
import { isProbedButUnknown } from "./analyze.js";
import type {
  AttackGraphState, GraphEdge, GraphNode, NodeOrigin, NodeProperties, NodeStatus, NodeType, SkippedReason, SkippedRecord,
} from "./types.js";

/**
 * 节点上限。原来 500：实测一个已挖到 478 个端点的资产会在 306 次工具调用后封顶，
 * 外推到 800 次调用约 70% 的发现被淘汰，而被淘汰的多数是"还没打过"的 untested ——
 * 这等于用容量反过来限制挖掘深度。
 *
 * 提到 1500 后上下文不会跟着涨：prompt 里的图视图固定截到 60 节点，
 * 且 `context.ts` 的 `fitGraphView()` 在 6000 字符内做硬截断（降级而非 omitted）。
 */
export const MAX_NODES = 1500;
export const MAX_EDGES = 1200;
/** 同一端点连续多少次同特征响应判定死胡同。 */
export const DEAD_END_REPEATS = 3;
/**
 * 死链墓碑的冷却轮数（2026-11-10，S2-④）。
 *
 * 50 轮的依据：巡检每 6 轮换一次批，50 轮 ≈ 8 个批次。短于此，死链会在同一批里
 * 复辟；长于此，路径后来上线也补不回来。冷却结束后只允许复探一次。
 */
export const DEAD_MARK_COOLDOWN_ROUNDS = 50;
/** 墓碑容量上限：按写入时间 LRU，防止跨会话累积成第二个图。 */
export const DEAD_MARK_MAX = 500;
/**
 * 发现方式，与 `extract.ts` 的 `FoundUrl.kind` 同义（这里只用于 scope 判断）。
 * 单独声明一份是为了不让 builder 反向依赖 extract（extract 已在 builder 的下游）。
 */
export type DiscoveryKind = "link" | "api" | "item" | "js" | "form";

export function graphState(state: AttackGraphState | undefined): AttackGraphState {
  if (state && state.version === 1 && state.nodes && Array.isArray(state.edges)) return state;
  return { version: 1, nodes: {}, edges: [], hypotheses: [], stats: { nodes: 0, edges: 0, by_type: {}, by_status: {}, pruned: 0, merged: 0 } };
}

/** 墓碑超容量时按写入时间淘汰最旧的一批。只在新增时调用，不在读路径上。 */
function trimDeadMarks(state: AttackGraphState): void {
  const marks = state.deadMarks;
  if (!marks) return;
  const ids = Object.keys(marks);
  if (ids.length <= DEAD_MARK_MAX) return;
  const victims = ids.sort((a, b) => Number(marks[a]?.at || 0) - Number(marks[b]?.at || 0))
    .slice(0, ids.length - DEAD_MARK_MAX);
  for (const id of victims) delete marks[id];
}

function now(): number {
  return Date.now();
}

export function endpointNodeId(url: string): string {
  const host = urlHost(url);
  const path = normalizePath(urlPath(url));
  return host ? `ep:${host}${path}` : `ep:${path}`;
}

export function assetNodeId(url: string): string {
  const host = urlHost(url);
  return host ? `asset:${host}` : "asset:unknown";
}

export function identityNodeId(role: string): string {
  return `id:${String(role || "anon").trim().toLowerCase().replace(/\s+/g, "_")}`;
}

export function parameterNodeId(endpointId: string, param: string): string {
  return `param:${endpointId.replace(/^ep:/, "")}#${param}`;
}

function edgeId(source: string, target: string, type: string): string {
  return `${type}:${source}->${target}`;
}

/**
 * 统计按当前图重算。
 *
 * 原来是增量加减，实测发现状态迁移（blocked → vulnerable）时 by_status 会归零，
 * 面板上就显示"没有 blocked 端点"——明明刚被 403 打过。计数器不可信，快照可信。
 */
export function recount(state: AttackGraphState): void {
  const byType: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const node of Object.values(state.nodes)) {
    byType[node.type] = (byType[node.type] || 0) + 1;
    byStatus[node.status] = (byStatus[node.status] || 0) + 1;
  }
  state.stats.by_type = byType;
  state.stats.by_status = byStatus;
  state.stats.nodes = Object.keys(state.nodes).length;
  state.stats.edges = state.edges.length;
}

function bump(state: AttackGraphState, _node: GraphNode): void {
  recount(state);
}

function dropStats(state: AttackGraphState, _node: GraphNode): void {
  recount(state);
}

/**
 * 属性合并：**事实只升不降**（2026-11-03 实跑暴露）。
 *
 * 起因：`ep:wanxiaozhi.aliyun.com/` 已被 http.request 拿到 200（hits=14），
 * 后来一次 http.request 超时（schema 里没有 status），builder 就把 `status_unknown`
 * 无条件置成 true —— 一个**已知 200** 的端点被重新标成"不知道状态码"。
 * 后果连锁：`hasComparableResponse()=false`（明明有响应却不能做差异对照）、
 * `isProbedButUnknown()=true` → `cannotLocateObject()` 判死 → 该端点永远不生成
 * IDOR 假设。跑了 45 分钟，25 条假设里 0 条 idor。
 *
 * 三条规则（对**所有**字段成立，不只是 status_unknown）：
 *   ① 新值 undefined = "这次没观察到"，保留旧值（绝不能用"没看到"擦掉"看到过"）；
 *   ② status_code 一旦有了就是事实，不能被后来的失败清掉（规则① 的自然结果）；
 *   ③ status_unknown 只有"从有到无"的合法路径：只要还握着状态码，就永远是 false。
 *
 * 不采用"旧 false + 新 true → 保持 false"这种写法：初始节点 `status_unknown`
 * 缺省就是 false，那样会把**首次** probe（合法置位）也一起拦掉。
 * 判断依据只认"有没有状态码"，不认标记本身。
 */
export function mergeProperties(old: NodeProperties, next: NodeProperties): NodeProperties {
  const provided: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(next)) {
    if (value !== undefined) provided[key] = value;
  }
  const merged: NodeProperties = { ...old, ...provided };
  if (merged.status_code !== undefined) {
    merged.status_unknown = false;
    delete merged.probed_by;
  }
  return merged;
}

/** 新增或合并节点。返回是否新建。 */
export function upsertNode(
  state: AttackGraphState,
  input: { id: string; type: NodeType; properties?: NodeProperties; status?: NodeStatus; discovered_by?: string },
  /**
   * 本轮已建、需要一起躲过这次裁剪的节点（调用方累积传入）。
   * 不传时至少保护 `input.id` 自己 —— 那是"刚建完就被自己触发的 prune 删掉"的直接原因。
   */
  protectedIds?: Set<string>,
): boolean {
  const existing = state.nodes[input.id];
  if (existing) {
    existing.updated_at = now();
    existing.properties = mergeProperties(existing.properties, input.properties || {});
    if (input.discovered_by && !existing.discovered_by) existing.discovered_by = input.discovered_by;
    if (input.status) {
      // 状态不降级：vulnerable 不能被后来的 untested 覆盖。
      // dead_end 单列一档（2026-10-28）：它和 testing 原来同为 1 档，于是
      // “重复请求 3 次判死”之后，第 4 次同请求 ingest 又把状态写回 testing，
      // 死胡同标记永远留不住（实测 note.yun 会话 `ep:note.yun.oppo.com/` 就是这样）。
      const rank: Record<NodeStatus, number> = { untested: 0, testing: 1, dead_end: 2, blocked: 2, vulnerable: 3 };
      const sticky = existing.status === "dead_end" && input.status !== "vulnerable";
      if (!sticky && rank[input.status] >= rank[existing.status]) {
        if (existing.status !== input.status) {
          dropStats(state, existing);
          existing.status = input.status;
          bump(state, existing);
        }
      }
    }
    state.stats.merged += 1;
    return false;
  }
  const node: GraphNode = {
    id: input.id,
    type: input.type,
    properties: input.properties || {},
    status: input.status || "untested",
    discovered_by: input.discovered_by || "",
    updated_at: now(),
  };
  state.nodes[input.id] = node;
  bump(state, node);
  // 刚建的节点必须躲过它自己这次 upsert 触发的裁剪。
  const guards = protectedIds ? new Set(protectedIds) : new Set<string>();
  guards.add(input.id);
  prune(state, MAX_NODES, guards);
  return true;
}

/** 新增或升级边（同源同目标同类型只留一条，属性合并、权重取高）。 */
export function upsertEdge(
  state: AttackGraphState,
  input: { source_id: string; target_id: string; type: GraphEdge["type"]; properties?: Record<string, unknown>; rpc_tool?: string; weight?: number },
): boolean {
  if (!input.source_id || !input.target_id) return false;
  const id = edgeId(input.source_id, input.target_id, input.type);
  const existing = state.edges.find(edge => edge.id === id);
  if (existing) {
    existing.properties = { ...existing.properties, ...(input.properties || {}) };
    if (input.weight !== undefined) existing.weight = Math.max(existing.weight, input.weight);
    if (input.rpc_tool && !existing.rpc_tool) existing.rpc_tool = input.rpc_tool;
    state.stats.merged += 1;
    return false;
  }
  state.edges.push({
    id, source_id: input.source_id, target_id: input.target_id, type: input.type,
    properties: input.properties || {}, rpc_tool: input.rpc_tool, weight: input.weight ?? 1,
  });
  if (state.edges.length > MAX_EDGES) {
    // 先丢权重最低、且不连 vulnerable 节点的边。
    const droppable = state.edges
      .map((edge, index) => ({ edge, index }))
      .filter(({ edge }) => state.nodes[edge.target_id]?.status !== "vulnerable")
      .sort((a, b) => a.edge.weight - b.edge.weight);
    const victim = droppable[0];
    if (victim) state.edges.splice(victim.index, 1);
  }
  state.stats.edges = state.edges.length;
  return true;
}

/**
 * 站点根端点（首页）：`ep:<host>/`。
 *
 * 首页是"所有对照的基准面"——基线、匿名 vs 带罐、状态漂移全靠它。
 * 它被封闭的代价不是"少打一条路"，而是**所有验证动作失去参照物**。
 */
export function isSiteRootNodeId(nodeId: string): boolean {
  const match = /^ep:([^/]+)(\/.*)$/.exec(String(nodeId || ""));
  if (!match) return false;
  return normalizePath(match[2]!) === "/";
}

/** 标死胡同：同一端点在参数面上反复换 payload 却没有结构性变化。 */
export function markDeadEnd(state: AttackGraphState, nodeId: string, note?: string, signature?: string): boolean {
  const node = state.nodes[nodeId];
  if (!node) return false;
  if (node.status === "vulnerable" || node.type === "identity") return false;
  /**
   * 首页豁免（2026-11-05）。
   *
   * 实测会话 5b59aa1d059b56da：`ep:wanxiaozhi.aliyun.com/` 因"同一请求已重复 10 次
   * （响应未变化）"被封成 dead_end。此后 `deadEndVerdict` 对同一签名一律拒收——
   * 而首页的"响应未变化"恰恰是这个站最不可信的一条判据：同一批 URL 在 6 分钟内
   * 实测过 200 → 302 到父域 /notfound → 200，风控窗口与缓存都会让"看起来没变"。
   *
   * 所以站点根不封路：重复次数照记，note 照写（逼它换动作，而不是停手），
   * 但状态不改。真正的兜底仍在——zero_entropy_streak / stall / 预算会掐掉纯空转。
   */
  if (isSiteRootNodeId(nodeId)) {
    // 记峰值重复次数，而不是"本函数被调了几次"：调用方只在 streak >= 阈值时才进来，
    // 从第 3 次起每轮调用一次，直接自增会得到 8 而不是真实的 10。
    const repeats = Math.max(
      Number(node.properties.signature_repeats || 0),
      Number(node.properties.site_root_repeats || 0),
    );
    node.properties.site_root_repeats = repeats;
    node.properties.note = `站点根不判死胡同（第 ${repeats} 次同签名重复）：${note || "响应未变化"}。`
      + `首页是基线/匿名对照/状态漂移的唯一参照面，禁止把它封掉；也别停手——换签名（UA/Cookie/身份/加 Cache-Control: no-cache）或等 30–60s 重取一次真实基线。`;
    node.updated_at = now();
    return false;
  }
  // 第四态节点（发了包、没拿到状态码）先给一次"补测宽限"（2026-11-03 硬出路段 3）。
  // 现场：ep:wanxiaozhi.aliyun.com/ 带着 200 却同时标着 status_unknown，被判 dead_end 之后
  // 补测请求被死胡同规则拒收——"要证明它能访问"的唯一动作恰好被"别再打它"挡住。
  // 只宽限一次：补测再失败（retest_grace_used 已置位）就照常封路，不会永远卡在 testing。
  if (isProbedButUnknown(node) && node.properties.retest_grace_used !== true) {
    node.properties.retest_grace_used = true;
    node.properties.note = `第四态未补测（${String(node.properties.probed_by || "无状态码")}）：先用 http.request/browser.open 取一次真实状态码，再判死胡同`;
    node.updated_at = now();
    return false;
  }
  node.status = "dead_end";
  node.properties.note = note || node.properties.note;
  // 记"是哪条签名封的路"：换签名的请求是另一次动作，不该被这条封印拦住（见 deadEndVerdict）。
  const sig = String(signature || "").slice(0, 80);
  if (sig) {
    const sealed = node.properties.dead_signatures || [];
    if (!sealed.includes(sig)) node.properties.dead_signatures = [...sealed, sig].slice(-6);
  }
  node.updated_at = now();
  state.stats.by_status.dead_end = (state.stats.by_status.dead_end || 0) + 1;
  return true;
}

/**
 * 淘汰档位（2026-11-07 分档）：数字越小越先被删。
 *
 * 旧实现把 `testing` 和 `dead_end` 塞进同一档（都返回 10，注释写"最老的先走"），
 * 于是"正在测"和"已判死"同罪受罚。一旦活跃假设把 testing 节点全部引用走（保护分 1000），
 * 可淘汰池里就只剩刚建的新端点 —— 它一进图就被自己的裁剪删掉，调用方写 depth 直接崩。
 *
 * 现在的顺序按"越活越靠后"：
 *   10 从未访问且已判死 → 20 已判死 → 30 未测 → 35 正在测 → 40 被墙 → 90 资产/身份 → 100 漏洞
 * 中间那三档（10/20/35）直接对应"先删没价值的、最后才动正在测的"。
 *
 * 两个更高位：「被活跃假设引用」1000，「本轮刚建」2000 —— 2000 必须是最高，
 * 否则受保护的节点会输给被引用节点，自毁链会以另一种形式回来。
 */
export function evictionRank(
  node: GraphNode,
  referenced: Set<string>,
  protectedIds?: Set<string>,
): number {
  if (protectedIds?.has(node.id)) return 2000;
  if (referenced.has(node.id)) return 1000;
  if (node.status === "vulnerable") return 100;
  if (node.type === "identity" || node.type === "asset") return 90;
  if (node.status === "blocked") return 40;
  if (node.status === "testing") return 35;
  if (node.status === "untested") return 30;
  if (node.status === "dead_end") {
    // "从未访问"按 hits 判定：发现类节点（sitemap/JS 里摘出来的）hits 恒为 0，
    // 它们从没真正发过请求，比"打过很多次才判死"的更没保留价值。
    return Number(node.properties.hits || 0) === 0 ? 10 : 20;
  }
  // 缺 status 的老数据按"未测"处理：保守，别让脏数据获得最高淘汰优先级。
  return 30;
}

/**
 * 裁剪：节点超上限时按"最没用"的顺序丢。
 * 保护顺序：protectedIds（本轮刚建）> vulnerable > identity/asset > current active chain > blocked > untested > dead_end。
 *
 * `protectedIds`（2026-11-07）是为了修一个自毁链：图满 + 假设把 testing 全引用后，
 * 可淘汰池里只剩"刚建的那个端点"，于是一次 upsert 触发的 prune 会把刚建好的节点自己删掉，
 * 调用方随后拿 `state.nodes[id]!` 写 depth 就直接抛 TypeError，整回合记 agent_error。
 * 受保护的节点排到最后，但**不是永不淘汰**：如果超限数量大于可淘汰节点数，
 * 排序仍会走到它们——宁可删，也不能让图无限增长。
 */
export function prune(state: AttackGraphState, maxNodes = MAX_NODES, protectedIds?: Set<string>): number {
  const ids = Object.keys(state.nodes);
  if (ids.length <= maxNodes) return 0;
  /**
   * 正在被假设引用的节点不能删（2026-11-04）。
   *
   * 原 rank 只按节点状态打分，`untested`(30) 排在 `blocked`(40) 之后，
   * 而 `untested` 恰恰是"还没打但已经被假设盯上"的那批 —— 超限时先被淘汰。
   * 节点一删，`isDependencyInvalidated` 立刻判依赖失效，假设跟着归档：
   * 一次裁剪就把正在挖的东西连根拔了，而且看起来像"假设自己失效"。
   *
   * 只认 active / evicted：archived / confirmed 是已经收口的，
   * 不该为了留档把图撑爆。缺 status 的老数据按 active 处理（保守）。
   */
  const referenced = new Set<string>();
  for (const hypothesis of state.hypotheses || []) {
    if (hypothesis.status && hypothesis.status !== "active" && hypothesis.status !== "evicted") continue;
    for (const id of hypothesis.nodes || []) referenced.add(id);
  }
  const rank = (node: GraphNode): number => evictionRank(node, referenced, protectedIds);
  const victims = ids
    .map(id => state.nodes[id]!)
    .sort((a, b) => (rank(a) - rank(b)) || (a.updated_at - b.updated_at))
    .slice(0, ids.length - maxNodes);
  for (const node of victims) {
    dropStats(state, node);
    delete state.nodes[node.id];
    state.edges = state.edges.filter(edge => edge.source_id !== node.id && edge.target_id !== node.id);
    state.stats.pruned += 1;
  }
  recount(state);
  return victims.length;
}

export type IngestInput = {
  /** 这些结果是从哪个端点挖到的（父节点）：决定 discovered_from 边的方向。 */
  parent?: string;
  /** 第几次 run：节点带 round，控制台据此排时间轴。 */
  round?: number;
  tool: string;
  /** 请求里带的身份（角色名或 "anon"）。 */
  identity?: string;
  /** 工具结果里能提取到的端点（URL + 可选元数据）。 */
  endpoints?: Array<{
    url: string;
    method?: string;
    status_code?: number;
    content_length?: number;
    content_type?: string;
    params?: string[];
    auth_required?: boolean;
    blocked?: boolean;
    /** 这个端点是本次真的被请求过（不是被动发现的）：状态据此迁移到 testing。 */
    requested?: boolean;
    /**
     * 确实发了包但拿不到状态码（扫描器类工具）。只有它能豁免
     * `assertEvidenceContract` 的"request 必须带 status_code"。
     */
    status_unknown?: boolean;
    /** 直接父节点（中间容器，如承载接口的 js bundle）：优先于 input.parent。 */
    via?: string;
    /** 同响应特征已重复出现次数（由调用方统计，图只记账）。 */
    repeats?: number;
    /**
     * WAF/拦截墙的种类（`wallOf()` 判定）。有值即视为“这条路被墙挡住”，
     * 状态落 blocked 但**不**记 requires_auth 身份边——412 不是“需要登录”，
     * 把它记成身份墙会让 identity 节点凭空多出来。
     */
    wall?: string;
    /**
     * 路由在服务端不存在（`routeMissingOf()` 判定）：写进节点属性，供假设生成器跳过。
     * 不写状态——死胡同状态是粘的，而"这条路由不存在"是可推翻的（后来真返回 200 就清掉）。
     */
    route_missing?: boolean;
    /**
     * 请求签名（method+url+body/headers 的哈希）：判断“这是不是完全相同的一次重打”。
     * 与 `repeats` 互补——前者判重复动作，后者判重复结果。
     */
    signature?: string;
    /**
     * 这个端点是怎么来的：request（真发过请求）/ link / js / api / item（字典命中）。
     * 漂移巡检只把 request/link/js/api 当“观测到的面”——字典命中不算，否则
     * 113 条命中会变成 113 个「没动过的块」（2026-10-28 实测）。
     *
     * 2026-11-03 收紧：这个字段只剩两个合法值 request / discovery（见 NodeOrigin）。
     * 旧调用方传的 link/js/api/item 会被归一成 discovery，原值转存到 `discovery_kind`。
     */
    origin?: string;
    /** 发现方式（link/api/item/js）。与 origin 分开记，别让一个字段兼职两种语义。 */
    discovery_kind?: string;
    /** 站点自报的来源（`sitemap` / `robots`）：可信度高于爬取所得，落进节点属性供复盘。 */
    source?: "sitemap" | "robots";
    /**
     * 这次请求在 `{id}` 位置上的具体对象值（`objectValuesOf()` 对齐出来的）。
     * 图只存值本身，不存整条 URL：两身份对照要的是"同一对象"，不是"同一字符串"。
     */
    object_values?: string[];
  }>;
  /** 从一个页面跳到另一个页面（katana / browser 链接）。 */
  links?: Array<{ from: string; to: string; kind?: DiscoveryKind; source?: "sitemap" | "robots" }>;
  /** 前端 JS 调用的后端接口。 */
  api_calls?: Array<{ from: string; to: string; kind?: DiscoveryKind }>;
  /** 确认的漏洞：端点 → 漏洞类型。 */
  vulnerabilities?: Array<{ url: string; kind: string }>;
  /**
   * 暴力枚举命中的**候选路径**（不是端点）。
   *
   * 为什么不建节点：命中的是"服务器对这条路径有响应"，不等于"这里有一个端点"。
   * catch-all 目标上 113 条命中全是同一个 302，建节点会让图裂成 113 块（2026-10-28 实测）。
   * 候选挂在父节点的 `candidates` 上；真的打过一次之后，http.request 会建出真节点。
   */
  candidates?: Array<{ url: string; note?: string }>;
  evidence_id?: string;
};

/** 主入口：一次工具结果 → 图增量。返回本次新增的节点与边，便于写事件流。 */
export function ingestToolResult(state: AttackGraphState, input: IngestInput): { newNodes: string[]; newEdges: string[]; deadEnds: string[]; candidates: string[]; skipped: SkippedRecord[]; prunedSameRound: string[] } {
  const newNodes: string[] = [];
  const newEdges: string[] = [];
  /**
   * 本轮建好、又被本轮裁剪删掉的节点。
   *
   * 为什么单独记：图满时"建完即被删"是合法结果（容量总要有人付代价），
   * 但它不能被当成"发现新端点"写进事件流——否则模型会去追一个不存在的节点，
   * 复盘时也分不清"没发现"和"发现了但被丢弃"。
   */
  const prunedSameRound: string[] = [];
  /** 本轮新建且仍需在后续 upsert 的裁剪里受保护的节点。 */
  const protectedThisRound = new Set<string>();

  // ── 候选路径：只记在父节点上，不建节点、不建边 ──
  // 见 IngestInput.candidates 的注释：这类命中是"有响应"，不是"有端点"。
  const acceptedCandidates: string[] = [];
  if (input.candidates?.length) {
    const anchorId = input.parent && state.nodes[input.parent]
      ? input.parent
      : Object.keys(state.nodes).find(id => state.nodes[id]?.type === "asset") || "";
    const anchor = anchorId ? state.nodes[anchorId] : undefined;
    if (anchor) {
      const existing = Array.isArray(anchor.properties.candidates) ? anchor.properties.candidates as string[] : [];
      const merged = [...existing];
      for (const candidate of input.candidates) {
        const path = String(candidate.url || "").slice(0, 512);
        if (!path || merged.includes(path) || merged.length >= 200) continue;
        merged.push(path);
        acceptedCandidates.push(path);
      }
      if (merged.length) {
        anchor.properties.candidates = merged;
        anchor.properties.candidate_count = merged.length;
      }
    }
  }
  const deadEnds: string[] = [];
  const evidence = input.evidence_id || "";
  const identity = input.identity || "anon";
  /**
   * 2026-10-31：跨注册域的"发现物"不再入图。
   *
   * m.ctrip.com 那轮 katana 抓到 277 条 URL，其中 20+ 个是页脚外链（iqiyi / mafengwo /
   * beian.miit.gov.cn …），builder 给每个 host 建了一个 asset 卡片，于是图裂成 54 块。
   * 这里以本次调用作用的页面为锚，只保留同注册域（ctrip.com / trip.com / c-ctrip.com /
   * tripcdn.cn 这类两段域名）的发现物。
   *
   * 2026-11-03：注释写了半年的"记进 skipped 由调用方落事件"其实**从未生效**——
   * `desk.ts:767` 的入参类型里根本没有 skipped 字段，被挡下的 URL 直接蒸发。
   * 现在返回值带 `SkippedRecord[]`，desk 落 `graph-skipped` 事件：不进节点（不撑爆 500 上限），
   * 但模型能在事件流里看见"我看过它，因为 X 被跳过了"。
   */
  const skipped: SkippedRecord[] = [];
  const hostOf = (value: string): string => {
    const raw = String(value || "").replace(/^(ep|asset):/, "");
    try { return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname.toLowerCase(); } catch { return ""; }
  };
  const anchorHost = hostOf(String(input.parent || "")) || hostOf(String((input.endpoints || [])[0]?.url || ""));
  // 站点边界（2026-11-04）：**同 host 或其子域**，不向父域扩张。
  //
  // 原来用 registrable（取 host 后两段）判"同注册域"，在多产品共用注册域的站点上
  // 等于把整个注册域当同站点：`wanxiaozhi.aliyun.com` 首页导航栏里的 161 条
  // `ecs/vpc/oss.console.aliyun.com` 产品控制台链接全部入图，占端点总数 92%，
  // 而目标本体只剩 4 个静态端点 —— 噪声把真攻击面挤没了。
  //
  // 不向上扩张：父域（`aliyun.com`）是另一个站点，不是本目标的上级应用。
  // 保留向下扩张：`admin.example.com` 确实是 `example.com` 的资产，
  // 真实渗透里这是最值钱的一跳，不能一刀切。
  //
  // 顺带修掉 registrable 的另一个问题：`slice(-2)` 对 `a.b.co.uk` 得到 `co.uk`，
  // 会把任意两个 `.co.uk` 站点判成同域（双向误判）。isSameSite 不依赖后缀表。
  const isSameSite = (host: string, anchor: string): boolean => {
    if (!host || !anchor) return true;
    if (host === anchor) return true;
    return host.endsWith("." + anchor);
  };
  /**
   * 跨站也放行的来源：业务面本身就可能落在独立域上。
   *
   * `api`（前端接口）、`form`（表单 action，登录/支付常跨域）、`js`（脚本里能挖接口）
   * 是"这个 URL 参与业务"，跟导航栏外链不是一回事。
   * `link` / `item` 跨站基本是噪声（导航外链、友链、产品矩阵），必须同站点。
   */
  const BUSINESS_KINDS = new Set(["api", "form", "js"]);
  const inScope = (url: string, kind?: string): boolean => {
    if (!anchorHost) return true;
    const host = hostOf(url);
    if (!host) return true;
    if (isSameSite(host, anchorHost)) return true;
    if (kind && BUSINESS_KINDS.has(kind)) return true;
    return false;
  };
  // 挡下不等于没发生（2026-11-03）：跨注册域的发现物以前被静默 continue 掉，
  // 事件流、统计、上下文里全都没有它，模型不知道自己错过了什么面。
  // 现在每条都带 reason/anchor/parent 记进返回值，由调用方落事件（不进节点，别撑爆 500 上限）。
  const skip = (url: string, parent?: string, reason: SkippedReason = "out_of_scope"): void => {
    if (skipped.length >= 200) return;
    skipped.push({ url, reason, anchor: anchorHost, ...(parent ? { parent } : {}) });
  };
  /**
   * `ep:host/path` / `asset:host` / 裸 host → 可解析的相对路径基准 URL。
   *
   * 入参里的 `from` 有两种形态：真实 URL（desk 传的 page url）和节点 id
   * （`input.parent`）。拼相对路径前必须统一，否则 `new URL("/x", "ep:host/")` 不报错，
   * 而是产出 `ep:/x` —— scheme 是 `ep:`、host 为空，正是 `ep:/` 那个畸形节点的成因。
   */
  const baseUrlOf = (value: string): string => {
    const raw = String(value || "").replace(/^(ep|asset):/, "");
    if (!raw) return "";
    if (/^https?:\/\//i.test(raw)) return raw;
    const host = raw.split(/[/?#]/)[0] || "";
    return host.includes(".") ? `https://${raw}` : "";
  };
  /** 绝对 URL 原样返回；相对路径按 base 补全；**host 为空或补不出来**一律返回空串（调用方记 skipped）。 */
  const absoluteOf = (raw: string, base?: string): string => {
    const text = String(raw || "").trim();
    if (!text) return "";
    if (/^https?:\/\//i.test(text)) {
      // `https:///x` 这种"有 scheme 没 host"的串能通过正则，却会退化成 `ep:/x`。
      try { return new URL(text).hostname ? text : ""; } catch { return ""; }
    }
    if (text.startsWith("/") && base) {
      try { const url = new URL(text, base); return url.hostname ? url.toString() : ""; } catch { return ""; }
    }
    return "";
  };

  for (const raw of input.endpoints || []) {
    /**
     * 端点 URL 必须有 host（2026-11-04）。
     *
     * `endpointNodeId` 对空 host 会退化成 `ep:/` / `ep:/api/x`：这种节点没有站点、
     * 跨站同名路径会互相串号，而且永远打不到（拼不出请求）。相对路径按锚点补全，
     * 补不出来就落 skipped —— 让"我看过但没用"可见，而不是造一个假节点。
     */
    const endpointUrl = absoluteOf(raw.url, anchorHost ? `https://${anchorHost}` : "");
    if (!endpointUrl) { skip(String(raw.url || "").slice(0, 512), input.parent, "unresolvable"); continue; }
    const endpoint = { ...raw, url: endpointUrl };
    // ── 事实层归一（2026-11-03）──
    // `requested` 是"这次真的发出过请求"的硬事实，`origin` 只是它的镜像：
    // 两者冲突时以 requested 为准（旧调用方只传 requested，不能因此炸会话）；
    // 但新调用方一旦显式写了 origin="request"，就必须满足契约（带状态码或 status_unknown）。
    const declared = String(endpoint.origin || "");
    const requested = endpoint.requested === true || declared === "request";
    const origin: NodeOrigin = requested ? "request" : "discovery";
    // 旧值（link/js/api/item）不丢，转存成 discovery_kind，供复盘与漂移巡检的人类视角使用。
    const discoveryKind = String(endpoint.discovery_kind || (declared && declared !== "request" ? declared : "")).slice(0, 16);
    if (declared === "request") {
      assertEvidenceContract({
        url: endpoint.url, origin, requested,
        ...(endpoint.status_code !== undefined ? { status_code: endpoint.status_code } : {}),
        ...(endpoint.status_unknown === true ? { status_unknown: true } : {}),
      });
    }
    // 只有非请求证据才做 scope 过滤：真发过的请求是事实，必须留痕。
    // 判 scope 时带上来源 kind —— 表单 action / API 调用 / JS 里的接口跨站是真的，
    // 导航外链跨站基本是噪声。
    if (origin !== "request" && !inScope(endpoint.url, discoveryKind)) {
      skip(endpoint.url, input.parent);
      continue;
    }
    const id = endpointNodeId(endpoint.url);
    const assetId = assetNodeId(endpoint.url);
    if (upsertNode(state, {
      id: assetId, type: "asset", properties: { host: urlHost(endpoint.url) }, status: "untested", discovered_by: evidence,
    }, protectedThisRound)) {
      protectedThisRound.add(assetId);
      newNodes.push(assetId);
    }
    // 状态迁移（2026-10-28 补）：过去只有 blocked/untested/vulnerable 三种落点，
    // 于是 200 的端点永远显示 untested —— 图上看不出"打没打过"，更看不出挖掘进程。
    // 是首次出现还是已知节点：决定"定深度"还是"放松深度"。
    const existingNode = state.nodes[id];
    /**
     * `hits` 的语义是"真的拿到了响应的次数"，不是"被提到过的次数"（2026-11-05 修）。
     *
     * 旧写法无条件 `+1`：sitemap 解析出的 18 个 /help 页走的是 `endpoints` 数组
     * （`requested` 未置、没有状态码），却全被记成 `hits=1`。后果不只是数字错——
     * 图上"打没打过"变得不可分辨，诊断时差一点把"从没访问过"误读成"访问过一次"。
     * 判据用"有没有响应证据"，不用 `requested`：大量旧调用方只传 status_code 不传 requested。
     */
    // 显式 `requested: false` 且没有任何响应痕迹 = "被提到过的 URL"，不是"打过的端点"。
    // sitemap/robots/JS 解析出来的地址都走这条：它们进图是为了排队，不是为了记账。
    const declaredUnrequested = endpoint.requested === false
      && endpoint.status_code === undefined
      && endpoint.status_unknown !== true
      && endpoint.blocked !== true
      && !endpoint.wall;
    const observedResponse = !declaredUnrequested && (endpoint.requested === true
      || endpoint.status_code !== undefined
      || endpoint.status_unknown === true
      || endpoint.blocked === true
      || Boolean(endpoint.wall));
    // WAF 墙（412/418/1020 + 阻断页指纹）也是 blocked，但与 401/403 的身份墙分开记：
    // 2026-10-28 note.yun 那轮 9 条 412 全落成 testing，图上看不出“被墙挡住”。
    const wallOfEndpoint = endpoint.wall ? String(endpoint.wall).slice(0, 40) : "";
    // 状态推导按**证据来源**，不按"结果里出现过"（2026-11-03）：
    // 之前 `requested` 被 katana 的 urls 批量置真，500 个假端点全部落 testing，
    // 于是"打没打过"在图上不可分辨，假设与漂移巡检同时失真。
    const status: NodeStatus = (endpoint.blocked || wallOfEndpoint) ? "blocked" : origin === "request" ? "testing" : "untested";
    // origin 只升不降：已经真打过的节点，不会被后来的"发现"降级回 discovery。
    const nodeOrigin: NodeOrigin = origin === "request" || state.nodes[id]?.properties.origin === "request" ? "request" : "discovery";
    const props: NodeProperties = {
      ...(endpoint.method ? { method: endpoint.method.toUpperCase() } : {}),
      ...(endpoint.status_code !== undefined ? { status_code: endpoint.status_code } : {}),
      ...(endpoint.content_length !== undefined ? { content_length: endpoint.content_length } : {}),
      ...(endpoint.content_type ? { content_type: String(endpoint.content_type).slice(0, 60) } : {}),
      ...(endpoint.auth_required !== undefined ? { auth_required: endpoint.auth_required } : {}),
      ...(endpoint.params?.length ? { params: endpoint.params.slice(0, 12).map(param => String(param).slice(0, 40)) } : {}),
      ...(wallOfEndpoint ? { wall: wallOfEndpoint } : {}),
      ...(endpoint.route_missing === true ? { route_missing: true } : {}),
      origin: nodeOrigin,
      // 「打了但没拿到状态码」必须落进属性，否则消费侧（serialize/analyze/hypotheses）
      // 完全看不到第四态——上一版只在校验里用到它，写完就丢了。
      // 清空动作交给 mergeProperties（事实只升不降）：节点还握着旧状态码时，
      // 这次失败不得把它重新标成 unknown。
      ...(endpoint.status_unknown === true ? { status_unknown: true, probed_by: String(input.tool || "") } : {}),
      // 鉴权墙回池的时基（2026-11-10）：只在真打过时刷新，发现类流量不碰它。
      ...(origin === "request" && input.round ? { last_probe_round: Math.max(1, Number(input.round)) } : {}),
      ...(discoveryKind ? { discovery_kind: discoveryKind } : {}),
      ...(endpoint.source ? { source: endpoint.source } : {}),
      ...(endpoint.object_values?.length ? (() => {
        const merged = [...(state.nodes[id]?.properties.object_ids || [])];
        for (const value of endpoint.object_values) if (value && !merged.includes(value)) merged.push(String(value).slice(0, 64));
        return { object_ids: merged.slice(-6), object_id: merged[merged.length - 1] };
      })() : {}),
      // 不变量（2026-11-05 二次加固，用户要求"requested:false 的节点 hits 永远是 0"）：
      // 发现类不加；如果发现类节点上还留着历史脏 hits（旧版无条件 +1 写的），一并抹平——
      // `origin` 只升不降，能保持 discovery 说明它确实从没被真打过。
      ...(observedResponse
        ? { hits: (state.nodes[id]?.properties.hits || 0) + 1 }
        : (endpoint.requested === false && nodeOrigin === "discovery" ? { hits: 0 } : {})),
    };
    // ── 死链墓碑（2026-11-10，S2-④）──
    // 节点会被 prune 删掉；删掉之后同一个 URL 从页面链接里重新发现，就又成了"新面"，
    // 巡检于是反复推同一条死链（对照会话推了 129 轮）。墓碑挂图不挂节点。
    // 冷却期用**图轮次**而不是墙钟：resume / 长时间挂起后仍然有效。
    if (endpoint.status_code === 404 || endpoint.status_code === 410) {
      state.deadMarks ||= {};
      state.deadMarks[id] = {
        code: Number(endpoint.status_code),
        at: now(),
        until_round: Math.max(0, Number(input.round || 0)) + DEAD_MARK_COOLDOWN_ROUNDS,
      };
      trimDeadMarks(state);
    } else if (endpoint.status_code !== undefined && endpoint.status_code < 400 && state.deadMarks?.[id]) {
      // 复核成功 = 墓碑失效：路径后来上线、或之前是临时故障。不是永久拉黑。
      delete state.deadMarks[id];
    }
    // 被拦连击：寻路的动态权重靠它。一次成功就清零——"曾经难过"不能永远算账。
    const blockedNow = endpoint.blocked === true || Boolean(wallOfEndpoint) || endpoint.status_code === 401 || endpoint.status_code === 403;
    if (blockedNow) {
      props.blocked_streak = (state.nodes[id]?.properties.blocked_streak || 0) + 1;
      props.blocked_at = now();
    } else if (endpoint.status_code !== undefined && endpoint.status_code < 400) {
      props.blocked_streak = 0;
      // 真的拿到 <400 了：之前"路由不存在"的判断被推翻，必须清掉——
      // 否则一次探测性的 404 会永久把这个端点踢出假设范围（m.ctrip.com 那轮就是这样）。
      if (state.nodes[id]?.properties.route_missing) props.route_missing = false;
    }
    const endpointCreated = upsertNode(state, { id, type: "endpoint", properties: props, status, discovered_by: evidence }, protectedThisRound);
    if (endpointCreated) protectedThisRound.add(id);
    // host 卡片必须与自己的端点相连，否则每发现一个 host 就多一块孤立子图
    // （2026-10-31 m.ctrip.com：54 个 host，53 个 degree=0，视觉上就是 54 块）。
    if (upsertEdge(state, { source_id: assetId, target_id: id, type: "discovered_from", weight: 1 })) {
      newEdges.push(edgeId(assetId, id, "discovered_from"));
    }
    // 父节点：优先用"挖到它的那个端点"，没有父才退回 asset。
    // 这是历程图有纵深的关键——原来无条件 asset→endpoint，42 个节点 37 条边全是一个形状。
    const wasKnown = Boolean(existingNode);
    const directParent = endpoint.via ? endpointNodeId(endpoint.via) : "";
    // 直接父（via）优先；它不存在时退回本次调用的页面（input.parent）。
    const preferredParent = directParent && directParent !== id && state.nodes[directParent] ? directParent : (input.parent && input.parent !== id && state.nodes[input.parent] ? input.parent : "");
    const parentId = preferredParent;
    const edgeType: GraphEdge["type"] = parentId && /^ep:/.test(parentId) ? "discovered_from" : "navigates_to";
    const edgeSource = parentId || assetId;
    // 只在"首次发现"时记来源边（或该节点目前只有 asset 星形边时升级一次）。
    // 为什么：A 页里有 B 的链接、B 页里也有 A 的链接，两次都记 discovered_from 就成环，
    // dagre 为了画环会反向边，"从左到右"就乱了；而"谁先挖到它"只需要一条主干边。
    const hasDiscoveryEdge = state.edges.some(edge => edge.target_id === id
      && (edge.type === "discovered_from" || edge.type === "calls_api"));
    if (!wasKnown || !hasDiscoveryEdge) {
      if (upsertEdge(state, { source_id: edgeSource, target_id: id, type: edgeType, weight: 1 })) {
        newEdges.push(edgeId(edgeSource, id, edgeType));
      }
    }
    //   第一次只写"父深度+1、取更小值"，结果每个**被请求**的端点自己在 processed=自身** 时
    //   找不到父，被记成 1 跳；之后再怎么挖也压不回 3 跳 —— 实测 259 节点 max_depth 仍是 2。
    //   现在的口径：
    //     · 节点第一次出现时才定深度：有父 = 父+1，无父 = 1（入口/资产）；
    //     · 已知节点只接受**更短**的路径（取 min，符合"距入口最短跳数"语义）；
    //     · 已有边不重复记，避免同一个星形被反复加固。
    /**
     * 必须重新取一次并判空（2026-11-07）。
     *
     * 上一行的 upsertNode 内部会触发 prune；图满时它可能刚把这个节点删掉。
     * 原来的 `state.nodes[id]!` 里那个 `!` 只骗过类型检查，运行时仍是 undefined，
     * 下一行写 `node.depth` 直接抛 TypeError —— 线上 5 次把整回合记成 agent_error。
     */
    const node = state.nodes[id];
    if (!node) {
      // 建完即被本轮裁剪丢掉：不记"发现新端点"，改走"同轮淘汰"，并把它的边账一并撤销——
      // 否则事件流会显示"+1 节点 +2 边"，而图和实际响应里什么都没有。
      if (endpointCreated) prunedSameRound.push(id);
      const liveEdgeIds = new Set(state.edges.map(edge => edge.id));
      for (let i = newEdges.length - 1; i >= 0; i--) {
        const pendingEdge = newEdges[i];
        if (!pendingEdge || !liveEdgeIds.has(pendingEdge)) newEdges.splice(i, 1);
      }
      continue;
    }
    if (endpointCreated) newNodes.push(id);
    if (!wasKnown) {
      node.depth = parentId ? Math.max(1, Number(state.nodes[parentId]?.depth || 1) + 1) : 1;
    } else if (parentId) {
      const candidateDepth = Math.max(1, Number(state.nodes[parentId]?.depth || 1) + 1);
      if (node.depth === undefined || candidateDepth < node.depth) node.depth = candidateDepth;
    } else if (node.depth === undefined) {
      node.depth = 1;
    }
    if (input.round && node.round === undefined) node.round = input.round;

    // ── 以下三段在 2026-10-28 的批量替换里被误删过一次，这里补回并加断言保护 ──
    // 参数节点：业务逻辑漏洞几乎总是从某个参数开始（order_id、price、role）。
    for (const param of props.params || []) {
      const paramId = parameterNodeId(id, param);
      if (upsertNode(state, { id: paramId, type: "parameter", properties: { note: param }, discovered_by: evidence }, protectedThisRound)) {
        protectedThisRound.add(paramId);
        newNodes.push(paramId);
      }
      if (upsertEdge(state, { source_id: id, target_id: paramId, type: "flows_data_to", weight: 1 })) newEdges.push(edgeId(id, paramId, "flows_data_to"));
    }

    // 鉴权墙：401/403 记 requires_auth 边（从身份指向端点，语义是"这个身份被拒"）。
    // 注意：WAF 墙不算身份墙——412 记 identity 节点会让"匿名被 WAF 挡"看起来像"需要登录"。
    if (!wallOfEndpoint && (endpoint.auth_required || endpoint.status_code === 401 || endpoint.blocked)) {
      const identityId = identityNodeId(identity);
      if (upsertNode(state, { id: identityId, type: "identity", properties: { role: identity }, discovered_by: evidence }, protectedThisRound)) {
        protectedThisRound.add(identityId);
        newNodes.push(identityId);
      }
      const edge = { source_id: identityId, target_id: id, type: "requires_auth" as const, weight: 3, properties: { status_code: endpoint.status_code ?? null } };
      if (upsertEdge(state, edge)) newEdges.push(edgeId(identityId, id, "requires_auth"));
    }

    // 死胡同（两条独立判据）：
    //   ① 同特征响应反复：状态码/长度一直没变（`repeats`）；
    //   ② 同一请求反复：method+url+body/headers 签名一模一样（`signature_repeats`）。
    // ② 是 2026-10-28 补的：note.yun 那一轮 43 次调用只有 22 个唯一请求，
    // 其中 `https://cloud.oppo.com/` 打了 17 次、每次都 200，旧逻辑只统计 blocked，
    // 于是这种"毫无变化的重复"永远不会被判死，白烧一半调用额度。
    const signature = endpoint.signature ? String(endpoint.signature).slice(0, 80) : "";
    /**
     * 这里重新取一次：上面的参数/身份节点 upsert 也会触发裁剪。
     * 节点可能已经不在图里了，裸 `!` 写属性会在同一回合再抛一次同样的错。
     */
    const liveNode = state.nodes[id];
    const lastSignature = String(liveNode?.properties.last_signature || "");
    if (signature && liveNode) {
      const previous = Number(liveNode.properties.signature_repeats || 0);
      const same = signature === lastSignature;
      const streak = same ? previous + 1 : 1;
      liveNode.properties.last_signature = signature;
      // 记峰值而不是当前值：同一条路径常被不同签名的请求交替重打，
      // 当前值会在 1 与 N 之间来回跳（实测显示 sig=1 但 note 写着 5 次），
      // 峰值才说明“这条重复到什么程度”。
      liveNode.properties.signature_repeats = Math.max(previous, streak);
      if (streak >= DEAD_END_REPEATS && markDeadEnd(state, id, `同一请求已重复 ${streak} 次（响应未变化）`, signature)) deadEnds.push(id);
    }
    const repeats = endpoint.repeats ?? (liveNode?.properties.repeats || 0) + (endpoint.blocked ? 1 : 0);
    if (liveNode) liveNode.properties.repeats = repeats;
    if (repeats >= DEAD_END_REPEATS && markDeadEnd(state, id, `同特征响应连续 ${repeats} 次`, signature)) deadEnds.push(id);
  }




  for (const link of input.links || []) {
    const fromUrl = baseUrlOf(link.from);
    // 相对 href 先挂 from，再退回本次作用页面（`input.parent` 是节点 id，需要反解）。
    const base = fromUrl || baseUrlOf(String(input.parent || ""));
    const toUrl = absoluteOf(link.to, base);
    // 拼不出绝对 URL 就不建节点（2026-11-04：`from: ""` 会造出 `ep:/`，
    // 它没有 host、没有状态、没有 origin，却带着 navigates_to 边长期留在图上，
    // 还会被当成"入口页"参与路径规划）。落 skipped，让它可见但不进图。
    if (!toUrl) { skip(String(link.to || "").slice(0, 512), link.from, "unresolvable"); continue; }
    if (!inScope(toUrl, link.kind || "link")) { skip(toUrl, link.from); continue; }
    const from = fromUrl ? endpointNodeId(fromUrl) : "";
    const to = endpointNodeId(toUrl);
    // from 也要建：入口页往往只作为爬取起点出现，不建节点就没有"入口直连高危端点"可推。
    // from 缺失时只建 to、不建边——那条边在语义上就是"不知道从哪发现的"。
    if (from && upsertNode(state, { id: from, type: "endpoint", properties: {}, discovered_by: evidence })) newNodes.push(from);
    if (upsertNode(state, {
      id: to, type: "endpoint",
      properties: link.source ? { source: link.source } : {},
      discovered_by: evidence,
    })) newNodes.push(to);
    if (from && upsertEdge(state, { source_id: from, target_id: to, type: "navigates_to", weight: 1 })) newEdges.push(edgeId(from, to, "navigates_to"));
  }

  for (const call of input.api_calls || []) {
    const fromUrl = baseUrlOf(call.from);
    const base = fromUrl || baseUrlOf(String(input.parent || ""));
    const toUrl = absoluteOf(call.to, base);
    if (!toUrl) { skip(String(call.to || "").slice(0, 512), call.from, "unresolvable"); continue; }
    if (!inScope(toUrl, call.kind || "api")) { skip(toUrl, call.from); continue; }
    const from = fromUrl ? endpointNodeId(fromUrl) : "";
    const to = endpointNodeId(toUrl);
    if (from && upsertNode(state, { id: from, type: "endpoint", properties: {}, discovered_by: evidence })) newNodes.push(from);
    if (upsertNode(state, { id: to, type: "endpoint", properties: {}, discovered_by: evidence })) newNodes.push(to);
    if (from && upsertEdge(state, { source_id: from, target_id: to, type: "calls_api", weight: 2 })) newEdges.push(edgeId(from, to, "calls_api"));
  }

  for (const vuln of input.vulnerabilities || []) {
    const id = endpointNodeId(vuln.url);
    const vulnId = `vuln:${vuln.kind}@${id.replace(/^ep:/, "")}`;
    if (upsertNode(state, { id: vulnId, type: "vuln_state", properties: { note: vuln.kind }, status: "vulnerable", discovered_by: evidence })) newNodes.push(vulnId);
    upsertNode(state, { id, type: "endpoint", status: "vulnerable", discovered_by: evidence });
    if (upsertEdge(state, { source_id: id, target_id: vulnId, type: "exploits", weight: 5, properties: { kind: vuln.kind } })) newEdges.push(edgeId(id, vulnId, "exploits"));
  }

  recount(state);
  /**
   * 返回前统一校验一次账目（2026-11-07）。
   *
   * 参数 / 身份 / 漏洞节点都是在端点之后建的，它们各自的 upsert 也会触发裁剪，
   * 逐个调用点判空容易漏；这里一处兜住所有路径：
   * 仍在图里的才叫"新增节点"，已不在的转成"同轮淘汰"，边也按现存集合过滤。
   */
  const liveIds = new Set(Object.keys(state.nodes));
  const gone = newNodes.filter(nodeId => !liveIds.has(nodeId));
  if (gone.length) {
    for (const nodeId of gone) {
      if (!prunedSameRound.includes(nodeId)) prunedSameRound.push(nodeId);
    }
  }
  const liveEdgeIds = new Set(state.edges.map(edge => edge.id));
  return {
    newNodes: newNodes.filter(nodeId => liveIds.has(nodeId)),
    newEdges: newEdges.filter(edgeId => liveEdgeIds.has(edgeId)),
    deadEnds,
    candidates: acceptedCandidates,
    skipped,
    prunedSameRound,
  };
}

/** 死胡同判定的结果：拒还是放，以及为什么。 */
export type DeadEndVerdict =
  /** 放行。`exempt` 说明是哪条理由打开的口子（对照工具 / 显式 bypass / 换了签名）。 */
  | { blocked: false; exempt?: "control_tool" | "explicit_bypass" | "new_signature"; node?: GraphNode }
  /** 拒收。`reopens` 是当前已重开次数（只对 new_signature 路径有意义）。 */
  | { blocked: true; node: GraphNode; reason: "same_signature" | "unknown_signature" | "reopen_limit"; reopens: number };

/**
 * 换签名重开死胡同的上限：超过就重新封路，避免“每次换个无关 header”变成无限重打。
 * 取 8 是因为 waf_bypass 的阶梯正好 8 档（编码/参数/路径/方法/头/报文/夹带/复刻），
 * 每一档在同一个端点上都会产生一个新签名——上限低于 8 会把阶梯本身掐断。
 */
export const DEAD_END_REOPEN_LIMIT = 8;

/**
 * 某端点上的这次请求要不要按死胡同拒收。
 *
 * 判据是**签名**，不是端点：死胡同的本意是“别再用同一个动作打同一条路”。
 * 2026-11-02 实测会话 b9601629efd1f137 里，`ep:m.ctrip.com/html5` 因重复被封，
 * 随后 `http.diff`（匿名 vs 带罐）被拒、T1 被收口——而这次对照正是
 * `unauth_exposure` 谓词唯一能拿到的证据。端点级封印在这里是**把验证动作杀掉**。
 *
 * 三种放行：
 *   - `control_tool`：`http.diff` / `recon.traffic_diff` 本身就是对照，不是盲重打；
 *     重复的对照另有 `zero_entropy_streak` 兜底（连续两次 diff_score=0 直接判任务 blocked）。
 *   - `explicit_bypass`：模型写了 `input.bypass_dead_end=true`（规则允许，需给理由）。
 *   - `new_signature`：method/url/body/headers/variant 任一变化都算另一次动作。
 *
 * 保守边界：节点被旧版本封过（没有 `dead_signatures`）时无法判断是不是同一个动作，
 * 仍按死胡同拒收，不让历史状态凭空解锁。
 */
export function deadEndVerdict(
  state: AttackGraphState,
  url: string,
  signature: string,
  options: { controlTool?: boolean; bypass?: boolean; reopenLimit?: number } = {},
): DeadEndVerdict {
  const node = state.nodes[endpointNodeId(url)];
  if (!node || node.status !== "dead_end") return { blocked: false };
  if (options.bypass) return { blocked: false, exempt: "explicit_bypass", node };
  if (options.controlTool) return { blocked: false, exempt: "control_tool", node };
  const sealed = node.properties.dead_signatures || [];
  if (!sealed.length || !signature) return { blocked: true, node, reason: "unknown_signature", reopens: Number(node.properties.dead_end_reopens || 0) };
  if (sealed.includes(signature)) return { blocked: true, node, reason: "same_signature", reopens: Number(node.properties.dead_end_reopens || 0) };
  const reopens = Number(node.properties.dead_end_reopens || 0);
  const limit = options.reopenLimit ?? DEAD_END_REOPEN_LIMIT;
  if (reopens >= limit) return { blocked: true, node, reason: "reopen_limit", reopens };
  node.properties.dead_end_reopens = reopens + 1;
  return { blocked: false, exempt: "new_signature", node };
}

/** 某端点是否已被标死胡同（旧接口：不看签名，一律视为封路）。 */
export function deadEndOf(state: AttackGraphState, url: string): GraphNode | undefined {
  const node = state.nodes[endpointNodeId(url)];
  return node && node.status === "dead_end" ? node : undefined;
}

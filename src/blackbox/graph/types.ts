/**
 * Agent 历程图（Attack Graph）—— 类型定义。
 *
 * 目的不是"画图好看"，是三件具体的事：
 *   1. 上下文降噪：用节点/边代替整段 HTTP Body 进 prompt（见 serialize.ts 的容量上限）。
 *   2. 业务逻辑挖掘：身份 × 端点 × 数据流的拓扑，才推得出越权/断链假设（hypotheses.ts）。
 *   3. 停止空转：死胡同在图上标死，执行器直接拒绝再打（见 routing 的 graph 拦截）。
 *
 * 刻意**不**引入 Neo4j：图规模上限 500 节点，一个 Record + 数组足够，
 * 序列化进 checkpoint（JSON）就能跨进程恢复。
 */

export type NodeType = "asset" | "endpoint" | "parameter" | "identity" | "vuln_state";

export type NodeStatus = "untested" | "testing" | "blocked" | "vulnerable" | "dead_end";

/**
 * 端点证据的来源——图上**事实层**的唯一口径。
 *
 * 之前 `requested:true` 被当成"这个 URL 在工具结果里出现过"，于是 `katana.crawl`
 * 一次返回的 500 条外链、`recon.*` 的 items、`browser.open` 的页脚链接，全部被标成
 * "本次真的请求过"，状态直接推到 testing（见 2026-11-03 的取证：
 * `desk.ts` 的 `evidenceUrls()` 把 `data.urls` 整批塞进 `requested: true`）。
 * 后果是 `cannotLocateObject()`（hypotheses.ts）不再对 404 生成越权假设、
 * `verified()`（analyze.ts）把假端点算进"没动过的块"、证据增益被 500 条假新端点灌满。
 *
 * 现在把两个语义拆开：
 *   - `request`   ：**本 agent 亲手发出了 HTTP 请求**，`status_code` 是这次响应的真实值
 *                   （只有 graph/evidence.ts 的 RESPONSE_TOOLS 能产出）。
 *   - `discovery` ：从工具输出里**看到**了它（爬虫、字典命中、页面链接、Burp 历史…），没请求过。
 *   - `seed`      ：用户给的种子（import / 候选导入）。
 *   - `derived`   ：从 JS / 证书 / robots / 配置文件里推出来的。
 *
 * 不变量（由 `assertEvidenceContract()` 强制）：
 *   1. `origin === "request"` **当且仅当** 证据携带 requested=true；
 *   2. `origin === "request"` 必须带 `status_code`，或显式 `status_unknown`（扫描器类工具
 *      确实发了包，但结果 schema 不含状态码——这种情况必须写明"不知道"，而不是编一个）。
 */
export type NodeOrigin = "request" | "discovery" | "seed" | "derived";

/** 一条证据为什么没进图（跨注册域被挡下）：只落事件，不进节点。 */
export type SkippedReason =
  | "out_of_scope"
  | "registrable_mismatch"
  | "blacklisted"
  /**
   * 连 URL 都拼不出来（相对路径没有 base、或 host 为空）。
   *
   * 2026-11-04 实测：9cb376 图里有个 `ep:/` —— `desk` 在结果没带作用 URL 时传
   * `from: ""`，`endpointNodeId("")` 就吐出 `ep:/`，它没有 host、没有状态、没有 origin，
   * 却带着 3 条 navigates_to 边长期挂在图上。这类记录必须显式落 skipped，
   * 而不是悄悄建一个畸形节点。
   */
  | "unresolvable";

export type SkippedRecord = {
  url: string;
  reason: SkippedReason;
  /** 判定时用的锚点主机（会话目标或本次作用页面）。 */
  anchor: string;
  /** 是谁发现它的（父页面 / 父节点），便于复盘"从哪条链上漏掉的"。 */
  parent?: string;
};

export type EdgeType =
  | "navigates_to" // 页面跳转 / 爬取
  | "calls_api" // 前端 JS 调后端
  | "requires_auth" // 访问此节点需要某个 identity
  | "flows_data_to" // A 的输出是 B 的输入
  | "exploits" // 针对某节点的利用动作
  | "bypasses" // 绕过 WAF/鉴权节点
  // 发现来源：A 的响应/页面里挖出了 B。这是"历程"的主干边——
  // 只有它才能把多轮挖掘拉成一条从左到右的链，而不是 asset 到所有端点的星形。
  | "discovered_from";

/** 节点属性只放摘要，绝不放 body。见 §7 避坑指南。 */
export type NodeProperties = {
  method?: string;
  status_code?: number;
  content_length?: number;
  content_type?: string;
  auth_required?: boolean;
  params?: string[];
  host?: string;
  role?: string;
  /**
   * 对象模型：这条 `{id}` 模板端点实际被打过的具体对象值（截断、去重、最多 6 个）。
   * 两身份对照的"同一个对象"就靠它——没有它，越权只能靠猜。
   */
  object_id?: string;
  object_ids?: string[];
  /** 同一特征响应出现次数：用来判定死胡同。 */
  repeats?: number;
  /** 连续被拦（401/403）次数：动态权重据此放大，逼寻路绕道。一次成功清零。 */
  blocked_streak?: number;
  /** 最近一次被拦的时间戳。 */
  blocked_at?: number;
  hits?: number;
  evidence_id?: string;
  note?: string;
  /**
   * WAF/拦截墙种类（`wallOf()`）：有值表示这条路被墙挡住，状态落 blocked。
   * 与 `auth_required` 区分开，否则 412 会被看成"需要登录"。
   */
  wall?: string;
  /**
   * 路由不存在（`routeMissingOf()`）：网关明确回 Not-Found-Route / NotFoundRouteException，
   * 或 404/410 且正文极小。
   *
   * 为什么需要（2026-11-02 m.ctrip.com 实测）：agent 自己造了 `z9probe_notexist/{id}`
   * 这种探测路径去验 catch-all，网关回 404 信封，图却把它当成"带对象 id 的接口"，
   * 于是生成 `H_idor` 假设、又派任务、又烧 3 轮去证明它是假的。
   * 判据是**证据**而不是路径名猜测：只有网关自己说"没这条路由"才置位。
   * 与 `wall` 一样是属性而不是状态——后来真返回 200 时清掉即可，不会像 dead_end 那样粘住。
   */
  route_missing?: boolean;
  /**
   * 最后一次主动打它的图轮次（2026-11-10，S2 第 4 条）。
   *
   * 鉴权墙回池需要"距上次真打过了几轮"：401/403 的端点不能永久留在池外
   * （换身份再打是最高价值的动作），也不能每轮都催（那就是现在 403 被反复推的病）。
   * 没有这个字段就只能拿 `node.round`（发现轮）代替，而发现轮往往比实打轮早得多。
   */
  last_probe_round?: number;
  /** 上一次请求签名（method+url+body 的哈希），用来判"完全相同的一次重打"。 */
  last_signature?: string;
  /** 同一签名连续出现次数：≥3 判死胡同。 */
  signature_repeats?: number;
  /**
   * 把这个端点封成 dead_end 的**具体签名**（最多记 6 条）。
   *
   * 为什么需要（2026-11-02 实测会话 b9601629efd1f137）：`ep:m.ctrip.com/html5`
   * 因为"同一请求重复 3 次"被封，随后 T1 想对它做 `http.diff`（匿名 vs 带罐）
   * 被 `dead_end` 拒收，任务当场被 blocked——**要证明"匿名可达"必须做的对照实验，
   * 恰好被"不要重打"的规则杀掉**。死胡同的本意是"别再用同一个动作打同一条路"，
   * 不是"这条路永远不许再碰"：换身份/换方法/换 body 是**另一次动作**。
   * 所以封路时把签名记下来，只有签名命中才拒（见 `deadEndVerdict`）。
   */
  dead_signatures?: string[];
  /**
   * 换签名重开死胡同的次数。`deadEndVerdict` 超过上限（默认 3）后重新封路，
   * 防止"每次换一个无关 header"变成无限重打。
   */
  dead_end_reopens?: number;
  /**
   * 站点根（`/`）被"同签名重复"命中的次数（2026-11-05）。
   *
   * 首页不判死胡同：它是基线、匿名对照、状态漂移的唯一参照面，
   * 而它的"响应未变化"常是风控窗口/缓存造成的假象。次数照记，用来判断
   * 是不是真在空转（配合 zero_entropy_streak / stall），但状态不跟着变。
   */
  site_root_repeats?: number;
  /**
   * 暴力枚举命中的候选路径（`/path` 形态）。**不是节点**：
   * 命中只说明"服务器对这条路径有响应"，catch-all 目标上全部同形。
   * 只有真的发过请求（http.request）才会建出端点节点。
   */
  candidates?: string[];
  candidate_count?: number;
  /**
   * 端点证据来源（见 NodeOrigin 的不变量）。`request` 是硬事实，`discovery` 只是"看到"。
   * 假设生成器（`cannotLocateObject`）与漂移巡检（`verified`）都按它分档。
   */
  origin?: NodeOrigin;
  /**
   * 站点自己声明的来源（`sitemap` / `robots`）。
   *
   * 为什么要单独记（2026-11-04）：这两类 URL 的可信度**高于**爬取所得 ——
   * 它们是站点主动列出的业务面，不是导航栏里随手放的链接。
   * 但此前 `FoundUrl.source` 在 desk 组装 ingest 入参时被丢掉，图上只剩
   * `discovery_kind: "link"`，跟"首页导航栏里的外链"完全无法区分：
   * 复盘时看不出这 18 个 `/help/*.html` 是 sitemap 声明的还是爬到的。
   */
  source?: "sitemap" | "robots";
  /**
   * 「发了包，但工具 schema 没给状态码」——第四态。
   *
   * 只对 `origin === "request"` 成立：nuclei / dalfox / sqlmap / arjun / testssl /
   * burp.send_batch 这些确实发出了请求，结果里却没有任何状态码字段。
   * 不允许编一个 200（那是伪造事实），也不允许退回 discovery（那是抹掉"动过"），
   * 所以显式记成"不知道"：
   *   - 状态仍然推进到 testing（确实动过，不会重复派首打任务）；
   *   - 但 `hasComparableResponse()` 为 false —— 没有可比响应，不能拿它做差异对照；
   *   - `isProbedButUnknown()` 为 true —— 提示"换个能给状态码的工具重测"。
   */
  status_unknown?: boolean;
  /**
   * 把节点标成 `status_unknown` 的那个工具（probe 类或超时的 response 类）。
   *
   * 补测时必须**换工具**：用同一工具重打只会再得到一次"没状态码"，
   * 于是补测假设永远消不掉（硬出路里的 `retest_attempted` 就是防这件事的）。
   */
  probed_by?: string;
  /**
   * 已经为这个第四态节点强制派过一次补测任务（硬出路段 3 的兜底）。
   * 防止"补测又失败 → 再派 → 再失败"的无限循环：每个节点只强制一次。
   */
  retest_attempted?: boolean;
  /**
   * 封死胡同时给过一次"补测宽限"（硬出路段 3）。只给一次：
   * 补测再失败也必须能封路，否则这条端点会永远卡在 testing 里。
   * 与 `retest_attempted` 分开记是因为触发点不同（这个是 ingest 封路时，
   * 那个是请求被拒收时），合用一个会互相顶掉。
   */
  retest_grace_used?: boolean;
  /**
   * 发现方式：link / api / item / js（`graph/extract.ts` 的 FoundUrl.kind）。
   * 只做展示与复盘用——**不再**让 `origin` 兼职记录它，否则两种语义又混在一起。
   */
  discovery_kind?: string;
};

export type GraphNode = {
  id: string;
  type: NodeType;
  properties: NodeProperties;
  status: NodeStatus;
  /** 关联的 evidence_id（首次发现它的那条）。 */
  discovered_by: string;
  /** 第几次 run 发现的（1 起）。控制台用它做"时间轴"，拓扑断链时也能看出先后。 */
  round?: number;
  /** 距入口的跳数：1 = 首轮资产/入口，n = 第 n 跳。dagre 的 rank 靠它才拉得开。 */
  depth?: number;
  updated_at: number;
};

export type GraphEdge = {
  id: string;
  source_id: string;
  target_id: string;
  type: EdgeType;
  properties: Record<string, unknown>;
  rpc_tool?: string;
  /** 寻路权重：越难打通越高（需要逆向签名/绕过 WAF 的边更贵）。 */
  weight: number;
};

export type HypothesisKind =
  /**
   * `stall` 已停止生成（2026-11-04），保留在枚举里只为读旧 checkpoint。
   *
   * 它原本是"某端点已被请求 N 次仍无状态变化"的提醒，判据 `hits >= 4` 在真实
   * 数据上没有区分度（283 个端点 180 个满足、189 个里 188 个满足），单轮产出
   * 179 条把假设池占满；而 hypothesisTasks 又过滤 stall，于是任务恒为 0、
   * attempts 恒为 0、永不归档 —— 假设机制整体空转（三个会话假设任务数都是 0）。
   *
   * 现在这个信号落在端点属性 `stall_hits` 上（见 serialize 的 slimProps），
   * 消费侧（activeHypotheses / graphContextView / visual）一律过滤 stall。
   */
  | "idor" | "logic_bypass" | "auth_wall" | "data_flow" | "stall" | "object_enum"
  /**
   * 补测假设（2026-11-03 硬出路）：节点处于第四态（发了包、没拿到状态码）。
   *
   * 它没有可比响应，越权/枚举假设根本做不成，所以它自己不产生 IDOR；
   * 但它必须变成一条**任务**——否则 `counts.probed_unknown` 只是一行提示，
   * 实跑证明模型不会因此回头补测（2026-11-03 会话 53a9ff8fca15e361：
   * 探针悬了 27 分钟无人理，最后带病判成 dead_end）。
   */
  | "retest_for_status"
  /**
   * 业务面巡检（2026-11-05）。
   *
   * 事故：站点在 sitemap 里自报了 18 个 `/help/*.html`，全部入图（`source=sitemap`、
   * `status=untested`），但两轮会话各 50 / 46 次工具调用里**一次都没访问过它们**。
   * 原因是 `deriveHypotheses` 的五类规则都要求"有可比响应 / 有 {id} 段 / 被拦 / 有参数"，
   * 普通业务页一条都不满足 —— 它们在图里躺着，但没有任何规则会把它们变成任务。
   *
   * 这一类就是补那个缺口：对**站点自己声明的、还没访问过的**页面生成"去看一眼"的假设。
   * 它不是漏洞假设，是取证假设（找新的接口/表单/敏感信息），所以 severity 只到 medium，
   * 且 attempts 上限 2 —— 看一眼没有新面就放弃，不在这条路上换 payload。
   */
  | "content_review";

/**
 * 假设的生命周期（2026-11-04 状态机重构）。
 *
 * ```
 *             座位满/超配额
 *   active ────────────────→ evicted ── 冷宫超容量 LRU 淘汰 ──→ 出池（可重新推导）
 *     │                        │
 *     │ 验证成立                │ 重新推导 + 有座位
 *     ↓                        ↓
 *  confirmed ←─────────────────┘
 *     │
 *   archived ── 两条路：尝试次数耗尽 / 依赖事实失效
 * ```
 *
 * 关键约定：
 *   - `evicted` **不是死**：它只是没有座位，`deriveHypotheses` 下一轮可以把它捞回来；
 *   - `archived` 才是坟墓，不再复活（除非依赖事实重新成立）；
 *   - `confirmed` 不再占座位，也不再进 prompt（报告里有 vuln_state 与 Kill Chain）。
 *
 * 兼容：旧 checkpoint 里是 `open` / `unreachable`，读入时归一（见 `normalizeHypothesisStatus`）。
 */
export type HypothesisStatus =
  | "active"
  | "evicted"
  | "confirmed"
  | "archived"
  /** @deprecated 旧值，等价于 active；读入即归一。 */
  | "open"
  /** @deprecated 旧值，等价于 archived；读入即归一。 */
  | "unreachable";

export type Hypothesis = {
  id: string;
  kind: HypothesisKind;
  /** 给模型看的结论句（不是图，LLM 不做图计算）。 */
  text: string;
  nodes: string[];
  edges?: string[];
  severity: "high" | "medium";
  created_at: number;
  /** 提出时的轮次，用于收尾统计与去重。 */
  round?: number;
  /**
   * 尝试验证次数。每次照着这条假设去打、结果没有结构性变化就 +1。
   * 上限**按 kind** 不同（见 hypotheses.ts 的 KIND_ATTEMPT_LIMIT）：
   * 一条 idor 值得多试几次，一次 auth_wall 试不动就是试不动。
   */
  attempts?: number;
  /** 生命周期状态（见 HypothesisStatus）。缺省视为 active。 */
  status?: HypothesisStatus;
  /** 降级原因（给报告与复盘用）。 */
  closed_reason?: string;
  // ── 冷宫（evicted）相关 ──
  /** 进冷宫的轮次。只用于报告，不用来判死。 */
  evictedAt?: number;
  /** 最近一次被重新评估的轮次：冷宫 LRU 的排序键。 */
  lastEvaluatedAt?: number;
  // ── 坟墓（archived）相关 ──
  /**
   * 为什么进坟墓。
   * `attempts_exhausted` = 试够了；`dependency_invalidated` = 依赖的节点/事实没了。
   * 两者都不可自动复活（依赖失效的会由 deriveHypotheses 重新生成一条**新**的）。
   */
  archivedReason?: "attempts_exhausted" | "dependency_invalidated";
};

export type GraphStats = {
  nodes: number;
  edges: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  pruned: number;
  merged: number;
};

export type AttackGraphState = {
  /** 版本号：结构变了要能被识别出来（旧 checkpoint 直接重建）。 */
  version: 1;
  nodes: Record<string, GraphNode>;
  edges: GraphEdge[];
  hypotheses: Hypothesis[];
  /**
   * 曾经进过假设池的 id（含已被冷宫 LRU 淘汰的）。
   *
   * 只用于区分「首次出现」与「淘汰后重新推导」：见 hypotheses.ts 的
   * `applyHypotheses`。可选字段，旧 checkpoint 没有时按空集合处理。
   */
  seenHypothesisIds?: string[];
  /**
   * 死链墓碑（2026-11-10，S2-④）。
   *
   * 404/410 不能只靠节点属性记住：节点会被 `prune` 删掉，删掉之后同一个 URL 从页面
   * 链接里重新发现，就又变回"从没打过的新面"，巡检于是反复推同一条死链——对照会话
   * `1dd9ded9ed239711` 里 `/topic/test2023`、`/adc` 被推了 129 轮就是这么来的。
   *
   * 墓碑挂在 graph 上而非节点上，因此不随裁剪消失。冷却期内它不参与任何建议池；
   * 冷却结束后允许复探一次（路径可能是临时故障或后来上线）。拿到 <400 立即清除。
   */
  deadMarks?: Record<string, DeadMark>;
  stats: GraphStats;
};

/** 一条死链墓碑。`until_round` 是图的轮次，不是墙钟：resume 后仍然有效。 */
export type DeadMark = {
  /** 判定死亡时的状态码（404 / 410）。 */
  code: number;
  at: number;
  /** `round < until_round` 期间视为墓碑。 */
  until_round: number;
};

export const EMPTY_GRAPH: AttackGraphState = {
  version: 1,
  nodes: {},
  edges: [],
  hypotheses: [],
  stats: { nodes: 0, edges: 0, by_type: {}, by_status: {}, pruned: 0, merged: 0 },
};

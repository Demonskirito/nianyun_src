/**
 * 假设生成器：从拓扑里推导"下一步该打哪"。
 *
 * 这是这套图和普通扫描器的分界线——扫描器只会"这个 URL 试一下那个 payload"，
 * 图能说出"这两个身份都能到同一个端点，所以越权值得试"这种**结构性**判断。
 *
 * 硬规则：**图计算由 TS 完成，LLM 只读结论**（LLM 做图遍历会幻觉出根本不存在的边）。
 */
import { endpointNodeId, identityNodeId } from "./builder.js";
import { hasComparableResponse, isProbedButUnknown } from "./analyze.js";
import type { AttackGraphState, GraphNode, Hypothesis, HypothesisStatus } from "./types.js";

function now(): number {
  return Date.now();
}

function hypothesisId(kind: string, parts: string[]): string {
  return `${kind}:${parts.slice().sort().join("|")}`;
}

/** 端点节点 id（`ep:host/path`）拆成 host 与 path。 */
function hostPathOf(id: string): { host: string; path: string } {
  const raw = String(id || "").replace(/^ep:/, "");
  const slash = raw.indexOf("/");
  return slash < 0
    ? { host: raw.toLowerCase(), path: "/" }
    : { host: raw.slice(0, slash).toLowerCase(), path: raw.slice(slash) };
}

/** 静态资源扩展名：这里的 `{id}` 是构建指纹，不是对象主键。 */
const STATIC_EXT = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|pdf)(?:$|[?#])/i;
/** 构建产物/静态目录：CDN 与 webpack 输出。 */
const BUILD_SEGMENT = /\/(?:_next|static|statics|assets|js|css|img|images|fonts|NFES)\//i;
/** 有对象语义的接口路径：只有这些才值得生成 IDOR 假设。 */
const API_SEGMENT = /\/(?:api|rest|restapi|h5api|soa2|gateway|webapp|order|orders|booking|book|ticket|train|flight|hotel|user|users|account|member|coupon|promo|pay|payment|passport|message|chat|service|shop|cart)\//i;
/** 静态资源域（CDN / 静态页）：整站都不该产生 IDOR。 */
const STATIC_HOST = /^(?:webresource|static|statics|img|images|assets|cdn|res|file)\./i;
/**
 * 站点声明文件自身：它们是"业务面的目录"，本身不是业务页。
 * 没有这条，`/sitemap.xml`、`/robots.txt` 会在拿到 200 后立刻被派一条巡检任务。
 */
const DECLARATION_SELF = /\/(?:robots\.txt|sitemap(?:_index)?\.xml)(?:$|[?#])/i;
/**
 * 单轮最多生成多少条业务面巡检假设。
 *
 * 真实 sitemap 上限 300 条；全量生成会把 40 个假设座位和每轮 3 个任务名额一起淹掉
 * （这正是当年 `stall` 假设 179 条导致整套机制空转的老路）。12 条 ≈ 4 轮的覆盖量。
 */
const BATCH_REVIEW_LIMIT = 12;
/**
 * 同一目录最多抽几页。
 *
 * 实测（2026-11-05，wanxiaozhi）：sitemap 里的 18 个 `/help/*.html` 现在**全部 301 到
 * `help.aliyun.com/zh/document_detail/…`**（站外）。目录不分样的话，这一轮会派 18 条
 * 巡检任务去逐个确认同一件事，白烧 16 条。
 *
 * 两页足以判断一个目录的形状（静态文章页 / 动态业务页 / 已搬迁），
 * 剩下的交给"发现结果"——真在这个目录里挖到东西，自然会从其它路径再回来。
 */
const BATCH_REVIEW_PER_DIR = 2;

/** 端点路径的一级目录：`/help/3039522.html` → `/help`；根路径归到 `/`。 */
function directoryOf(path: string): string {
  const clean = String(path || "/").split(/[?#]/)[0] || "/";
  const parts = clean.split("/").filter(Boolean);
  return parts.length <= 1 ? "/" : `/${parts[0]}`;
}

function describeIdCandidate(node: GraphNode, hasIdentity: boolean, round?: number): Hypothesis | undefined {
  const { host, path } = hostPathOf(node.id);
  if (STATIC_HOST.test(host)) return undefined;
  if (STATIC_EXT.test(path) || BUILD_SEGMENT.test(path)) return undefined;
  const at = now();
  if (!API_SEGMENT.test(path)) {
    // 页面/活动路径里的 {id} 通常只是活动编号：换 id 拿到的是另一个公开页面，
    // 不存在"归属校验"这回事。降级成一次性的枚举确认，不占 high 权重。
    return {
      id: hypothesisId("object_enum", [node.id]),
      kind: "object_enum",
      nodes: [node.id],
      text: `${node.id} 的 {id} 是页面/活动标识而非对象主键：最多花一发确认相邻 id 是否返回不同内容即可，不要按 IDOR 深挖；把预算留给带 /api /webapp /order 语义的接口。`,
      severity: "medium",
      created_at: at,
      round,
    };
  }
  const observed = (node.properties.object_ids || []).filter(Boolean).slice(-3);
  const objectLine = observed.length
    ? `已观测对象值 ${observed.join("、")}（这些是真实打过的 id，两身份对照必须打同一个）。`
    : "";
  return {
    id: hypothesisId("idor", [node.id, "path_id"]),
    kind: "idor",
    nodes: [node.id],
    text: hasIdentity
      ? `${node.id} 是带对象 id 的接口路径。${objectLine}先用自己身份取 baseline_self，再换相邻 id（±1）与另一身份对照，http.diff 比 baseline_self / diff_id / diff_auth 三组差异。`
      : `${node.id} 是带对象 id 的接口路径，但图里只有匿名身份。${objectLine}先做匿名越权（直接换 id 看是否返回他人数据），命中后再补登录态做归属对照；不要把"匿名能读"直接当 IDOR 下结论。`,
    severity: "high",
    created_at: at,
    round,
  };
}
function identitiesByEndpoint(state: AttackGraphState): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const edge of state.edges) {
    if (edge.type !== "requires_auth") continue;
    const set = map.get(edge.target_id) || new Set<string>();
    set.add(edge.source_id);
    map.set(edge.target_id, set);
  }
  return map;
}

/**
 * 这个端点能不能"定位到对象"？不能的话，任何越权/枚举假设都是空转。
 *
 * 两道判据：
 *  ① `route_missing`：本次会话真的打过，且 `routeMissingOf()` 从正文判定"网关没这条路由"；
 *  ② 被动发现（origin ≠ "request"）且**唯一观测到的状态就是 404/410**。
 *
 * 为什么必须加第 ② 条（2026-11-02 干净 e2e 会话 `b9601629efd1f137` 实测）：
 * 上一轮只在"真打过"的路径上算 `routeMissingOf()`，而 burp.history 这类被动发现
 * 只带 `status_code` 不正文。于是上一场自己造的 `z9probe_notexist/{id}` 仍留在 Burp
 * history 里，本场作为"发现的端点"重新入图（status_code=404、untested、无 route_missing），
 * 又派生了 `H_idor_47aed713` 与 `H_object_enum_0458205c` —— 修好的门一次都没生效。
 *
 * 保守边界：`hasComparableResponse()`（本次真打过、且拿到了状态码）时不在这一层判死，
 * 交给 `routeMissingOf()` 的正文判据，避免把"大正文 404 的软 404 页面"误杀。
 *
 * 2026-11-03：判定从 `origin === "request"` 换成 `hasComparableResponse()`。
 * 原写法把 probe 类（nuclei/sqlmap 命中、但没有状态码）也算成"已确认可访问"，
 * 于是给一条没有任何响应证据的路径派了一轮做不成的越权对照——两边都没有 baseline。
 * 现在第四态（`isProbedButUnknown`）单独处理：没有状态码就没有"这条路由存在"的证据，
 * 不生成越权假设，标记为"先换能给状态码的工具重测"（见 serialize 的 counts.probed_unknown）。
 */
function cannotLocateObject(node: GraphNode): boolean {
  if (node.properties.route_missing === true) return true;
  // 第四态：发了包、但工具没给状态码 → 既不能证明可访问，也不能当噪声。
  // 不做差异对照（没有 baseline），先让 Agent 用 http.request 补一次真实响应。
  if (isProbedButUnknown(node)) return true;
  const status = Number(node.properties.status_code ?? 0);
  if (status !== 404 && status !== 410) return false;
  return !hasComparableResponse(node);
}

/**
 * WAF 挑战/拦截响应的固定字节长度白名单。
 *
 * 7155 = 阿里云 WAF 的 **attestation 挑战响应**长度（2026-11-04 实测：
 * wanxiaozhi.aliyun.com 在 agent 侧返回 403 + JSON，正文 `proxy_authentication_required`，
 * 要求提交 principal/email 等身份字段；`server: Tengine`，
 * `access-control-allow-origin` 每次换成随机域名 n6d7o8.com / zthncu4l0.com）。
 * 同一长度出现在 `/`、`/sitemap.xml`、`/qz7x-probe-*` 多个路径上，说明是统一挑战页。
 *
 * 注意这不是"目标真的拒绝了你"，而是"WAF 要求你先自证身份"——所以对应的处理不是
 * 带凭证重打，而是判墙 + 换武器。别把这个长度当成 help.aliyun.com 独有的拦截页。
 *
 * 为什么用长度：`NodeProperties` 只存摘要不存 body（见 builder.ts 头注释），
 * 图节点上没有正文可比对，长度是唯一零成本可用的指纹。
 *
 * 局限（明确记录）：① 硬编码单站长度，页面改版即失效；② 动态 WAF 每次长度不同，识别不到；
 * ③ 正常页面恰好同长度会误判成墙。误判代价不对称——判成"墙仍在"只是多花 1 次验证
 * （auth_wall 的 attempts 上限 3 兜底），判成"墙已破"是把真墙连同假设一起归档。
 */
const WAF_PAGE_LENGTHS = new Set([7155]);

/**
 * 这个端点当前的响应是不是"WAF 软拦截页"。
 *
 * 存在的理由：部分 WAF（阿里云实测）用 **HTTP 200 + 拦截页** 表达封锁。
 * 状态码说"通过了"，正文却是 `waf_block_deny.html`。`wallStillStands()` 若先看状态码，
 * 就会把真 403 墙在拿到一次 200 软拦截后判成"墙已破"并归档——真墙被自己打穿的那一次误杀。
 *
 * 两个信号，都是 0 成本：
 *   ① `content_length` 命中拦截页长度白名单；
 *   ② `body_preview` 命中拦截页关键词（字段目前不落图，预留给将来 ingest 存摘要时自动生效）。
 */
export function isWafBlockPage(node: GraphNode): boolean {
  const props = node.properties || {};
  if (props.content_length !== undefined && WAF_PAGE_LENGTHS.has(Number(props.content_length))) return true;
  const preview = String((props as Record<string, unknown>).body_preview || "");
  // 两类都要认（2026-11-04）：
  //   waf_block_deny  = 传统拦截页
  //   proxy_authentication_required = attestation 挑战页（伪装成"代理要认证"，
  //     实际要求提交 principal/email，本质是钓身份）。它**也可能用 200 返回**，
  //     不认它就会按 "2xx → 墙已破" 把真墙归档。
  if (preview && /waf_block_deny|punish\/waf|gateway-diagno|proxy_authentication_required|client attestation payload/i.test(preview)) return true;
  return false;
}

/**
 * 鉴权墙还在不在？
 *
 * 这是 auth_wall 假设的**收口判据**，专门避免用瞬时状态判死（2026-11-04）。
 *
 * 反例（不能这么写）：`node.status === "blocked"`。
 * 节点状态会迁移 `blocked → testing`（正在带凭证重打）→ `vulnerable` / `dead_end`，
 * 而 `applyHypotheses` 每次工具结果后都跑一遍。拿 `status === "blocked"` 当谓词，
 * 假设会在"重打进行中"把自己归档——任务还在办，假设已经埋了。
 *
 * 正确信号是 `blocked_streak`：它在 builder 里只在拿到 `<400` 时清零，
 * 是"曾经被拦且没被打破"的持久事实。另外三种情况可以明确判定墙已消失：
 *   ① 已经拿到 `<400`：墙破了（该由 resolveHypotheses 收口，不是"墙还在"）；
 *   ② `route_missing` / 唯一的 404/410 观测：不是墙，是没这条路由；
 *   ③ 节点不存在：无从判断。
 */
export function wallStillStands(node?: GraphNode): boolean {
  if (!node) return false;
  const props = node.properties || {};
  // ⓪ WAF 软拦截页优先于状态码：阿里云会用 200 + 拦截页表达封锁，
  //    先按 "2xx → 墙已破" 判会把真墙误归档。
  if (isWafBlockPage(node)) return true;
  const status = Number(props.status_code ?? 0);
  // ① 拿到 2xx/3xx 且不是拦截页：墙已经破了。
  if (status > 0 && status < 400) return false;
  // ② 路由不存在（含 404/410 的唯一观测）：带凭证重打只会再拿一次 404。
  if (cannotLocateObject(node)) return false;
  // ③ 持久信号：被拦过且没被打破。
  if (Number(props.blocked_streak || 0) > 0) return true;
  if (props.wall) return true;
  // 兜底：当前仍处于 blocked（瞬时，单独看也是证据；不做唯一依据）。
  return node.status === "blocked";
}

/** 入口节点：没有任何入边的端点（爬取/探测发现的第一批）。 */
function entryNodes(state: AttackGraphState): GraphNode[] {
  const targeted = new Set(state.edges.filter(edge => edge.type === "navigates_to" || edge.type === "calls_api").map(edge => edge.target_id));
  return Object.values(state.nodes).filter(node => node.type === "endpoint" && !targeted.has(node.id));
}

export function deriveHypotheses(state: AttackGraphState, round?: number): Hypothesis[] {
  const out: Hypothesis[] = [];
  const at = now();

  // ① 越权（IDOR）：≥2 个身份指向同一端点，或端点带 id 形状的参数段。
  for (const [endpointId, identities] of identitiesByEndpoint(state)) {
    if (identities.size >= 2) {
      const anchorNode = state.nodes[endpointId];
      if (!anchorNode || cannotLocateObject(anchorNode)) continue;
      const ids = [...identities].sort();
      out.push({
        id: hypothesisId("idor", [endpointId, ...ids]), kind: "idor", nodes: [endpointId, ...ids],
        text: `${endpointId} 有 ${ids.length} 个身份被拒（${ids.join("、")}）：用 A 的凭证请求 B 的对象，并在 http.diff 里比 baseline_self 与 diff_auth。`,
        severity: "high", created_at: at, round,
      });
    }
  }
  const hasIdentity = Object.values(state.nodes).some(node => node.type === "identity" && node.id !== identityNodeId("anon"));
  for (const node of Object.values(state.nodes)) {
    if (node.type !== "endpoint") continue;
    if (!node.id.includes("{id}")) continue;
    if (node.status === "vulnerable") continue;
    // 2026-11-02 证据门：定位不到对象的端点不得生成越权假设。
    // m.ctrip.com 那轮 agent 造了 `z9probe_notexist/{id}` 去验 catch-all，
    // 404 信封被模板成"带对象 id 的接口"，于是白派一个 H_idor 任务、烧 3 轮证伪。
    // 判据见 cannotLocateObject()：正文级 route_missing，或被动发现的 404/410 观测。
    if (cannotLocateObject(node)) continue;
    // 2026-10-31 语义门：路径里的 {id} 只有落在"有对象语义的接口"上才是 IDOR；
    // 构建产物（_next/static、NFES、.js/.css）与活动页一律不生成 high 假设
    // （m.ctrip.com 那轮 17/19 条假设都打在这些静态路径上，attempts 全 0）。
    const candidate = describeIdCandidate(node, hasIdentity, round);
    if (candidate) out.push(candidate);
  }

  // ② 鉴权墙：端点是 blocked 但存在活跃身份，值得带凭证重打。
  for (const node of Object.values(state.nodes)) {
    if (node.status !== "blocked" || node.type !== "endpoint") continue;
    // 404 不是鉴权墙：路由根本不存在时，带凭证重打也只会再拿一次 404。
    if (cannotLocateObject(node)) continue;
    const identities = Object.values(state.nodes).filter(item => item.type === "identity" && item.id !== identityNodeId("anon"));
    if (!identities.length) continue;
    out.push({
      id: hypothesisId("auth_wall", [node.id]), kind: "auth_wall", nodes: [node.id, ...identities.map(item => item.id)],
      text: `${node.id} 被拦（${node.properties.status_code ?? "403/401"}），但图上有身份 ${identities.map(item => item.id).join("、")}：带凭证重打一次，再用 anonymous:true 做匿名对照。`,
      severity: "high", created_at: at, round,
    });
  }

  // ②b 业务面巡检（2026-11-05）：站点自己声明过、但从没访问过的页面。
  //
  // 为什么必须有这一条：两轮实测会话（773eae1a2d5b6c0c / bd2b519a4f5037c5）里，
  // sitemap 送进图的 18 个 /help/*.html 全是 `untested`，而 50 / 46 次工具调用中
  // 打这些页的次数是 **0**。它们不满足上面任何一条规则——
  //   · 没有 {id} 段 → 不进 idor；
  //   · 没被拦（压根没请求）→ 不进 auth_wall；
  //   · 没有参数边 → 不进 data_flow；
  //   · 不是"发了包没拿到状态码"→ 不进 retest。
  // 于是它们只能永远躺在图上。这一条把"站点声明的业务面"变成可执行任务。
  const declaredCandidates = Object.values(state.nodes)
    .filter(node => node.type === "endpoint"
      && node.status === "untested"
      && node.properties.origin === "discovery"
      && (node.properties.source === "sitemap" || node.properties.source === "robots")
      && node.properties.status_code === undefined
      && !node.properties.status_unknown
      && !STATIC_EXT.test(node.id)
      && !BUILD_SEGMENT.test(node.id)
      && !DECLARATION_SELF.test(node.id))
    // 浅路径优先：/help/a.html 先于 /help/2024/03/xx/a.html；同深度按 id 稳定排序。
    .sort((a, b) => hostPathOf(a.id).path.split("/").length - hostPathOf(b.id).path.split("/").length
      || a.id.localeCompare(b.id));
  // 同目录抽样：一个目录最多 2 页（见 BATCH_REVIEW_PER_DIR）。
  const perDirectory = new Map<string, number>();
  const declaredPages: GraphNode[] = [];
  for (const node of declaredCandidates) {
    if (declaredPages.length >= BATCH_REVIEW_LIMIT) break;
    const dir = directoryOf(hostPathOf(node.id).path);
    const used = perDirectory.get(dir) || 0;
    if (used >= BATCH_REVIEW_PER_DIR) continue;
    perDirectory.set(dir, used + 1);
    declaredPages.push(node);
  }
  for (const node of declaredPages) {
    out.push({
      id: hypothesisId("content_review", [node.id]),
      kind: "content_review",
      nodes: [node.id],
      text: `${node.id} 是站点自己在 ${String(node.properties.source || "sitemap")} 里声明的页面，`
        + `至今一次都没访问过（hits=0）。取一次真实正文看三类东西：`
        + `① 页面里的 API 路径 / 表单 action / JS 里的接口清单（新攻击面）；`
        + `② 匿名就能看到的数据（越权线索）；③ 版本号 / 调试开关 / 内网地址（信息泄露）。`
        + `只花 1–2 发，别在这条路上换 payload 爆破；被墙就换通道（browser.open / burp.entry）再取一次。`,
      severity: "medium",
      created_at: at,
      round,
    });
  }

  // ③ 数据流（业务逻辑）：两个端点共享同名参数，说明 A 的输出可能是 B 的输入。
  const paramsByEndpoint = new Map<string, Set<string>>();
  for (const edge of state.edges) {
    if (edge.type !== "flows_data_to") continue;
    const target = state.nodes[edge.target_id];
    if (!target || target.type !== "parameter") continue;
    const name = String(target.properties.note || "");
    if (!name) continue;
    const set = paramsByEndpoint.get(name) || new Set<string>();
    set.add(edge.source_id);
    paramsByEndpoint.set(name, set);
  }
  for (const [param, endpoints] of paramsByEndpoint) {
    if (endpoints.size < 2) continue;
    const list = [...endpoints].sort();
    out.push({
      id: hypothesisId("data_flow", [param, ...list]), kind: "data_flow", nodes: list,
      text: `参数 ${param} 出现在 ${list.join(" 与 ")}：把 A 的输出直接喂给 B，验证服务端是否信任客户端传入的 ${param}（改价、越权、状态跳跃都从这里来）。`,
      severity: "medium", created_at: at, round,
    });
  }

  // ④ 断链（逻辑绕过）：入口能直连到"高危"端点，且中间缺少正常业务流节点。
  const entries = entryNodes(state);
  const highValue = Object.values(state.nodes).filter(node => node.type === "endpoint"
    && /pay|order|refund|transfer|admin|internal|withdraw/i.test(node.id));
  for (const entry of entries.slice(0, 8)) {
    for (const target of highValue.slice(0, 8)) {
      if (entry.id === target.id) continue;
      const direct = state.edges.some(edge => edge.source_id === entry.id && edge.target_id === target.id);
      if (!direct) continue;
      out.push({
        id: hypothesisId("logic_bypass", [entry.id, target.id]), kind: "logic_bypass", nodes: [entry.id, target.id],
        text: `${entry.id} 可直接到达 ${target.id}：跳过前置校验节点，按"无购物车直接下单/无支付回调直接改状态"验证状态机是否可跳过。`,
        severity: "high", created_at: at, round,
      });
    }
  }

  // ⑥ 补测（2026-11-03 硬出路段 1）：第四态节点（发了包、没拿到状态码）没有可比响应，
  //    越权/枚举假设做不成——但它不能只是"图上的一行提示"，必须变成任务。
  //    观察依据：会话 53a9ff8fca15e361 里 probe 节点悬了 27 分钟无人补测，
  //    最后带着"200 + status_unknown"的矛盾态被判 dead_end，25 条假设里 0 条 idor。
  //    补测假设优先级最低（见 hypothesis_tasks 的两轮入队），只在任务簿有空位时占位。
  const pendingRetest = Object.values(state.nodes)
    .filter(node => node.type === "endpoint" && isProbedButUnknown(node) && node.status !== "dead_end")
    // {id} 接口优先：它才是"补到状态码就能立刻做越权对照"的那批；
    // 其余按打过的次数排，避免把预算花在只探过一次的边上。
    .sort((a, b) => (b.id.includes("{id}") ? 1 : 0) - (a.id.includes("{id}") ? 1 : 0)
      || Number(b.properties.hits || 0) - Number(a.properties.hits || 0))
    .slice(0, 3);
  for (const node of pendingRetest) {
    const probedBy = String(node.properties.probed_by || "");
    const isIdPath = node.id.includes("{id}");
    out.push({
      id: hypothesisId("retest_for_status", [node.id]),
      kind: "retest_for_status",
      nodes: [node.id],
      text: `${node.id} 打过包但没拿到状态码${probedBy ? `（工具 ${probedBy}）` : ""}：`
        + `用 http.request（或 browser.open）取一次真实状态码，不要再用${probedBy ? ` ${probedBy}` : "同一个工具"}重打——那只会再得到一次"没状态码"。`
        + `拿到状态码后这条${isIdPath ? "带 {id} 的接口" : "端点"}才进得了越权/枚举对照。`,
      severity: "medium",
      created_at: at,
      round,
    });
  }

  // ⑤ 停滞子图不再生成假设（2026-11-04）。
  //
  // 原来的判据是 `hits >= 4` 就产一条 stall 假设，实测这条判据没有区分度：
  // 会话 d8f8350dadeb5441 里 283 个端点有 180 个满足（63%），d59f5a15a4ea26aa
  // 是 189 个里 188 个满足（99%）。于是单轮 derive 出 179–187 条 stall，
  // `applyHypotheses` 的 slice(-40) 把它们全留下、把 idor/auth_wall 全挤掉。
  //
  // 更致命的是它构成了**死锁**：
  //   stall 占满 40 个座位
  //     → hypothesisTasks 过滤掉 stall（它不是待验证目标）
  //     → 假设任务恒为 0
  //     → attempts 恒为 0，`attempts >= 3` 的归档条件永不成立
  //     → stall 永久驻留
  // 三个真实会话（d59f5a15a4ea26aa / d8f8350dadeb5441 / 53a9ff8fca15e361）
  // 的假设任务数都是 0 —— 这套机制一次都没真正转动过。
  //
  // 关键是 stall 表达的并不是"假设"，而是**一个事实**："这个端点已经被打过 N 次"。
  // 事实该留在节点属性上（serialize 输出 `stall_hits`），而不是占假设座位：
  // 假设座位要装"下一步值得试什么"，且它需要 attempts 生命周期才有意义；
  // 而 stall 完全可由 hits 重算，丢了下一轮立刻回来，不需要记忆。
  // 降级为属性后覆盖率还从 13/180 升到全部端点。

  return dedupe(out);
}

// ───────────────────────── 假设池：座位、冷宫、坟墓 ─────────────────────────
//
// 2026-11-04 重构。此前的 `slice(-40)` 有三个结构性问题：
//   ① 不区分品种：谁最后生成谁留下，stall 之类的高产 kind 能把整池占满；
//   ② 满了就**丢**：被挤掉的假设凭空消失，`attempts` 一起没了，下一轮从头再来；
//   ③ 没有"坟墓"：试够次数的和从没试过的混在一起，Agent 会反复重推同一条。

/** 座位数：同时**活跃**的假设上限。 */
export const HYPOTHESIS_MAX_ACTIVE = 40;

/**
 * 冷宫容量。
 *
 * 只收"重算成本高、值得记住 attempts"的品种——配额把每个 kind 压在小数量级，
 * 溢出的都是"这一轮排不上"的候选。实测三个真实会话里非 stall 的溢出量是 0，
 * 给到 100 是给"多身份大站"留余量。超出按 LRU 淘汰（淘汰 ≠ 死，可重新推导）。
 */
export const HYPOTHESIS_MAX_EVICTED = 100;

/**
 * 「见过」日志的容量：只记 id，用来抑制冷宫淘汰 → 重新推导造成的假新增。
 * 4000 条足够覆盖一次长时间会话（实测 24 分钟 / 203 节点 / 31 轮）；
 * 超出后按插入顺序丢最旧的，最坏情况只是某条老假设重新写一次事件。
 */
export const SEEN_HYPOTHESIS_MAX = 4000;

/**
 * 各 kind 的座位配额。
 *
 * **配额是硬上限，不是保底：座位空着就空着。**
 * 这条是刻意的——若"active 不足 40 就从冷宫补满"，被配额挡掉的低价值候选
 * 会立刻补回来，40 个座位又全被占满，等于配额没做。
 * 而且真正决定吞吐的不是座位数，是 `hypothesisTasks` 的 limit（每轮 3 条）。
 */
const KIND_QUOTA: Record<string, number> = {
  idor: 10,
  auth_wall: 6,
  retest_for_status: 6,
  object_enum: 5,
  data_flow: 5,
  logic_bypass: 5,
  // 业务面巡检：sitemap 实测 18 页，给 8 个座位 ≈ 两轮任务量；再多也只是排队。
  content_review: 8,
};
const DEFAULT_QUOTA = 5;

/**
 * 各 kind 的尝试上限。
 *
 * 一条 idor 的负结论很难靠一次尝试得出（要 baseline、换 id、换身份三组对照），
 * 而 auth_wall 一次带凭证重打还是 403 基本就是没了。全局 3 次把这两类拉平，
 * 对前者过早放弃、对后者浪费预算。
 */
const KIND_ATTEMPT_LIMIT: Record<string, number> = {
  idor: 5,
  auth_wall: 3,
  retest_for_status: 2,
  object_enum: 3,
  data_flow: 2,
  logic_bypass: 2,
  // 业务面巡检是取证，不是猜漏洞：看一眼没有新面就结束，别在静态页上反复换 payload。
  content_review: 2,
};

/** @deprecated 按 kind 取上限请用 `attemptLimitOf()`。保留只为兼容外部常量引用。 */
export const HYPOTHESIS_MAX_ATTEMPTS = 3;

export function attemptLimitOf(kind: string): number {
  return KIND_ATTEMPT_LIMIT[kind] ?? HYPOTHESIS_MAX_ATTEMPTS;
}

/** 旧 checkpoint 的 `open` / `unreachable` 归一成新状态机里的 `active` / `archived`。 */
export function normalizeHypothesisStatus(status?: string): HypothesisStatus {
  if (!status || status === "open") return "active";
  if (status === "unreachable") return "archived";
  if (status === "active" || status === "evicted" || status === "confirmed" || status === "archived") return status;
  return "active";
}

/** 还在场上吗：占座位、进 prompt、可派任务。冷宫不算。 */
export function isActiveHypothesis(item: Hypothesis): boolean {
  return normalizeHypothesisStatus(item.status) === "active";
}

/** 已定案：不再复活、不再派活。 */
export function isClosedHypothesis(item: Hypothesis): boolean {
  const status = normalizeHypothesisStatus(item.status);
  return status === "archived" || status === "confirmed";
}

/**
 * 重新校验：这条假设的前提还成立吗？
 *
 * 用**谓词**而不是"事实指纹字符串"（2026-11-04）。三个理由：
 *   ① 前提本来就是谓词——idor 依赖"能不能定位到对象"、auth_wall 依赖"墙还在不在"、
 *      retest 依赖"还是不是第四态"，这些写不成 `node has prop value`；
 *   ② 字符串解析失败时只能默认"仍为真"，错误方向恰好是"该归档的不归档"；
 *   ③ 这套判据本来就存在（原先散在 activeHypotheses 的三段特判里），
 *      这里只是把它提升为状态迁移，让冷宫/坟墓有明确边界。
 *
 * 锚点统一取 `nodes[0]`：所有生成器都把端点放在第一位。
 */
const REVALIDATE: Record<string, (node: GraphNode) => boolean> = {
  idor: node => !cannotLocateObject(node),
  object_enum: node => !cannotLocateObject(node),
  auth_wall: node => wallStillStands(node),
  retest_for_status: node => isProbedButUnknown(node),
  // 数据流/断链依赖的是两个端点之间的关系；锚点还在就先留着，
  // 边被剪掉的情况交给尝试上限兜底。
  data_flow: () => true,
  logic_bypass: () => true,
};

function dependencyInvalidated(item: Hypothesis, state: AttackGraphState): boolean {
  const anchor = state.nodes[item.nodes[0] || ""];
  if (!anchor) return true;
  const check = REVALIDATE[item.kind];
  return check ? !check(anchor) : false;
}

/** 配额排序：高危先、最近评估先、尝试少先、id 兜底保证稳定。 */
function compareHypotheses(a: Hypothesis, b: Hypothesis): number {
  const severity = (item: Hypothesis): number => (item.severity === "high" ? 0 : 1);
  return (severity(a) - severity(b))
    || ((b.lastEvaluatedAt ?? 0) - (a.lastEvaluatedAt ?? 0))
    || ((a.attempts ?? 0) - (b.attempts ?? 0))
    || a.id.localeCompare(b.id);
}

/**
 * 合并并重排假设池。
 *
 * `round` 是当前的 run 编号（历程图横轴同一口径），冷宫 LRU 与"最近评估"都靠它。
 * 不传时按 0 处理——LRU 退化成按插入顺序，但不会误判死任何东西。
 *
 * 返回**本次新增**的假设（供 desk 写 graph-hypothesis 事件）。
 */
export function applyHypotheses(
  state: AttackGraphState,
  items: Hypothesis[],
  round = 0,
): Hypothesis[] {
  const currentRound = Number.isFinite(round) && round > 0 ? Math.floor(round) : 0;

  // ① 迁移清理：stall 已降级为端点属性（见 deriveHypotheses ⑤），旧 checkpoint 里的整池要剔掉。
  if (state.hypotheses.some(item => item.kind === "stall")) {
    state.hypotheses = state.hypotheses.filter(item => item.kind !== "stall");
  }
  for (const item of state.hypotheses) item.status = normalizeHypothesisStatus(item.status);

  // ② 合并 incoming：保留生命周期字段，只更新结论内容。
  const byId = new Map(state.hypotheses.map(item => [item.id, item]));
  /**
   * 「见过」日志：冷宫 ⑥ 会把假设从池里**删掉**（淘汰 ≠ 死，下一轮 derive 会重新生成）。
   * 重新生成时 byId 查不到，原来一律被当成 added —— desk 于是每次工具结果都写 95 条
   * `graph-hypothesis` 事件，`scoreIngest` 也每次 +1「新假设 95 条」给焦点预算续命。
   *
   * 实测（2026-11-07 干净对照会话 1dd9ded9ed239711）：31 轮写了 1916 条假设事件，
   * 占事件总量 72%（07:00-07:06 六分钟 1717 条），而真正沉淀成假设任务的只有 8 条，
   * 转化率 0.4%；连 `evidence.read`（纯读证据、零目标侧请求）都能刷出 95 条「新假设」。
   * 这些假进展把焦点预算顶满，配合 focus-lock 造成 9 个任务连续 29 轮 0 派发。
   *
   * 所以「曾经进过池」与「本次首次出现」必须分开：复活照旧进池、照旧保留 attempts，
   * 但不再计入 added（也就不写事件、不加分）。
   */
  const seen = new Set<string>(state.seenHypothesisIds || []);
  for (const item of state.hypotheses) seen.add(item.id);
  const added: Hypothesis[] = [];
  for (const item of items) {
    const existing = byId.get(item.id);
    if (existing) {
      // 已定案的不覆盖：confirmed 已经进报告，archived 是坟墓。
      if (isClosedHypothesis(existing)) continue;
      existing.text = item.text;
      existing.nodes = item.nodes;
      existing.severity = item.severity;
      // 被重新推导出来 = 重新评估过，刷新 LRU 位次（冷宫里待久的就靠这个翻身）。
      existing.lastEvaluatedAt = currentRound;
      continue;
    }
    const revived = seen.has(item.id);
    const created: Hypothesis = {
      ...item,
      status: "active",
      attempts: item.attempts || 0,
      lastEvaluatedAt: currentRound,
    };
    byId.set(created.id, created);
    state.hypotheses.push(created);
    seen.add(created.id);
    if (!revived) added.push(created);
  }

  // ③ 依赖失效 → 坟墓（第一条路）
  for (const item of byId.values()) {
    if (isClosedHypothesis(item)) continue;
    if (!dependencyInvalidated(item, state)) continue;
    item.status = "archived";
    item.archivedReason = "dependency_invalidated";
    item.closed_reason = item.closed_reason || "依赖的节点已不存在或前提已不成立";
  }

  // ④ 尝试次数耗尽 → 坟墓（第二条路）
  for (const item of byId.values()) {
    if (isClosedHypothesis(item)) continue;
    if ((item.attempts || 0) < attemptLimitOf(item.kind)) continue;
    item.status = "archived";
    item.archivedReason = "attempts_exhausted";
    item.closed_reason = item.closed_reason || `尝试 ${item.attempts} 次无进展，已归档`;
  }

  // ⑤ 分桶配额：按 kind 各取前 quota 进 active，其余进冷宫。
  const buckets = new Map<string, Hypothesis[]>();
  for (const item of byId.values()) {
    if (isClosedHypothesis(item)) continue;
    const list = buckets.get(item.kind) || [];
    list.push(item);
    buckets.set(item.kind, list);
  }
  for (const [kind, list] of buckets) {
    const quota = KIND_QUOTA[kind] ?? DEFAULT_QUOTA;
    list.sort(compareHypotheses);
    list.forEach((item, index) => {
      if (index < quota) {
        item.status = "active";
        delete item.evictedAt;
        return;
      }
      if (normalizeHypothesisStatus(item.status) !== "evicted") item.evictedAt = currentRound;
      item.status = "evicted";
    });
  }

  // ⑤b 总座位上限：各 kind 配额合计可能超过 40（没列进表的 kind 各占 5 个），
  // 这里再按全局优先级截一次。超出的进冷宫，不丢弃。
  const actives = [...byId.values()].filter(item => normalizeHypothesisStatus(item.status) === "active");
  if (actives.length > HYPOTHESIS_MAX_ACTIVE) {
    actives.sort(compareHypotheses);
    for (const item of actives.slice(HYPOTHESIS_MAX_ACTIVE)) {
      if (normalizeHypothesisStatus(item.status) !== "evicted") item.evictedAt = currentRound;
      item.status = "evicted";
    }
  }

  // ⑥ 冷宫容量 + LRU 淘汰（淘汰 ≠ 死：从池里移除，下一轮 derive 能重新生成）
  const evicted = [...byId.values()].filter(item => normalizeHypothesisStatus(item.status) === "evicted");
  if (evicted.length > HYPOTHESIS_MAX_EVICTED) {
    evicted.sort((a, b) => (a.lastEvaluatedAt ?? 0) - (b.lastEvaluatedAt ?? 0));
    for (const dropped of evicted.slice(0, evicted.length - HYPOTHESIS_MAX_EVICTED)) {
      byId.delete(dropped.id);
    }
  }

  // ⑦ 写回：active → evicted → closed（消费侧只认 active，顺序只为可读）
  const rank = (item: Hypothesis): number => {
    const status = normalizeHypothesisStatus(item.status);
    return status === "active" ? 0 : status === "evicted" ? 1 : 2;
  };
  state.hypotheses = [...byId.values()].sort((a, b) => rank(a) - rank(b) || compareHypotheses(a, b));
  state.seenHypothesisIds = [...seen].slice(-SEEN_HYPOTHESIS_MAX);
  return added;
}

function dedupe(items: Hypothesis[]): Hypothesis[] {
  const seen = new Set<string>();
  return items.filter(item => (seen.has(item.id) ? false : (seen.add(item.id), true)));
}

/** 给报告用：从漏洞节点反向走到入口，得到 Kill Chain。 */
export function killChain(state: AttackGraphState, vulnNodeId: string): string[] {
  const parents = new Map<string, string[]>();
  for (const edge of state.edges) {
    if (!["navigates_to", "calls_api", "flows_data_to", "requires_auth", "exploits"].includes(edge.type)) continue;
    const list = parents.get(edge.target_id) || [];
    list.push(edge.source_id);
    parents.set(edge.target_id, list);
  }
  const chain: string[] = [];
  let cursor: string | undefined = vulnNodeId;
  for (let depth = 0; depth < 24 && cursor; depth += 1) {
    chain.push(cursor);
    const next: string | undefined = (parents.get(cursor) || []).find(parent => !chain.includes(parent));
    cursor = next;
  }
  return chain.reverse();
}

/** 端点 node id（供报告/上下文复用）。 */
export function nodeForUrl(state: AttackGraphState, url: string): GraphNode | undefined {
  return state.nodes[endpointNodeId(url)];
}
/**
 * 报告用：给定 finding 的 target URL，返回它的 Kill Chain。
 *
 * 优先沿 `vuln_state` 节点回溯（那才是"漏洞"）；没有漏洞节点时退回端点自身。
 * 返回 null 表示图里没有这条资产——报告不能凭空造路径。
 */
export function killChainForTarget(state: AttackGraphState, url: string): { chain: string[]; node: string } | null {
  const endpointId = endpointNodeId(url);
  const vuln = Object.values(state.nodes).find(node => node.type === "vuln_state" && node.id.endsWith(`@${endpointId.replace(/^ep:/, "")}`));
  const start = vuln?.id || (state.nodes[endpointId] ? endpointId : "");
  if (!start) return null;
  const chain = killChain(state, start);
  return chain.length ? { chain, node: start } : null;
}

/**
 * 记账一次"照着假设打了但没验证成功"。
 *
 * 判定由调用方给出（失败 / 响应无结构性变化 / 仍是同一 fingerprint），
 * 这里只负责计数与降级——图的计算不交给 LLM，也不交给工具实现细节。
 *
 * 返回被降级的假设（供写事件流）。
 */
export function noteHypothesisAttempt(
  state: AttackGraphState,
  endpointId: string,
  options: { failed?: boolean; note?: string; identity?: string } = {},
): Hypothesis[] {
  if (!endpointId) return [];
  const identityId = options.identity ? identityNodeId(String(options.identity)) : "";
  const closed: Hypothesis[] = [];
  for (const hypothesis of state.hypotheses) {
    if (isClosedHypothesis(hypothesis)) continue;
    if (!hypothesis.nodes.includes(endpointId)) continue;
    // auth_wall 的验证动作只有一个：**带上该假设点名的身份**重打。
    // 匿名请求（或别的身份）不是这条假设的验证，不该替它记一次失败。
    //
    // 这是实测确认的误杀源（2026-11-04）：53a9ff8fca15e361 里两条 auth_wall 的
    // attempts 都是 3、判 unreachable，但锚点的 blocked_streak 分别是 16 和 5——
    // 真正发生的是"同一端点上反复被拒"，其中大部分请求是 idor 对照与匿名探测，
    // 没有一次是"带假设点名的身份重打"。计数按端点做，账却记到了假设头上。
    if (hypothesis.kind === "auth_wall" && identityId) {
      const claimed = hypothesis.nodes.filter(node => node.startsWith("id:"));
      if (claimed.length && !claimed.includes(identityId)) continue;
    }
    hypothesis.attempts = (hypothesis.attempts || 0) + 1;
    // 上限按 kind：idor 值得多试几次，auth_wall 试不动就是试不动。
    if (hypothesis.attempts >= attemptLimitOf(hypothesis.kind)) {
      hypothesis.status = "archived";
      hypothesis.archivedReason = "attempts_exhausted";
      hypothesis.closed_reason = options.note
        || `尝试 ${hypothesis.attempts} 次无进展${options.failed ? "（执行失败）" : ""}，已归档`;
      closed.push(hypothesis);
    }
  }
  return closed;
}

/**
 * 活跃假设（在座位池里）；排序、prompt、任务派发都只认这个。
 *
 * 这里保留一次重新校验，是给"没跑过 applyHypotheses"的路径兜底
 * （历史回放、直接读 checkpoint 的场景）。判据与状态机共用 REVALIDATE，
 * 不另写一套——两处口径一旦分叉，就会出现"状态说活着、prompt 说死了"。
 */
export function activeHypotheses(state: AttackGraphState): Hypothesis[] {
  return state.hypotheses.filter(item => {
    if (!isActiveHypothesis(item)) return false;
    // 历史兼容：stall 已降级为端点属性 `stall_hits`（见 deriveHypotheses ⑤ 的说明）。
    if (item.kind === "stall") return false;
    return !dependencyInvalidated(item, state);
  });
}

/**
 * 假设已被验证成立（端点变 vulnerable）：标 confirmed。
 *
 * 2026-11-04 起不再从池里删除，而是改状态。理由：删除等于抹掉"我验证过什么"，
 * 复盘时无法回答"这条假设当时为什么被撤"，报告也只能靠 vuln_state 反推。
 * confirmed 不占座位、不进 prompt（serialize/visual 按状态过滤），
 * 所以留在数组里没有成本。
 */
export function resolveHypotheses(state: AttackGraphState, endpointId: string): Hypothesis[] {
  const resolved = state.hypotheses.filter(item => !isClosedHypothesis(item) && item.nodes.includes(endpointId));
  if (!resolved.length) return [];
  for (const item of resolved) {
    item.status = "confirmed";
    item.closed_reason = "已验证成立";
  }
  return resolved;
}

/**
 * 这次工具结果要不要重算假设池？（2026-11-07，对照会话 1dd9ded9ed239711）
 *
 * 旧行为是「每个工具结果都跑一次全图 deriveHypotheses」，连纯读的 evidence.read
 * 也刷一遍——4502 条事件里 3532 条是 graph-hypothesis。根因（冷宫 LRU 复活被当成新增）
 * 已由 seenHypothesisIds 修掉，这里补的是**调用量**那一半：没信号就别算。
 *
 * 判据刻意保守，回应"只看结构会不会吞掉属性变化"这个质疑：
 *   - 结构：新节点 / 新边 / 死胡同 / 新候选；
 *   - 属性：节点 status、status_code、content_length、content_type 任一变化；
 *   - 身份/重定向：响应头出现 Set-Cookie / Location；
 *   - 对照：identical === false（http.diff / burp.compare 判出差异）；
 *   - 失败或被拒也照跑，避免吞掉依赖失败态的隐式逻辑；
 *   - **只有明确列出的纯读工具**在「成功 + 以上信号全无」时才跳过，其余一律重算。
 *
 * 注意：跳过的是 deriveHypotheses，不是 enqueueHypothesisTasks。假设池没变时任务链照常
 * 从现有池派单，所以它不会让已成立的假设永远等不到执行。
 */
export const HYPOTHESIS_READ_ONLY_TOOLS = new Set([
  "evidence.read", "fs.list", "fs.read", "fs.grep",
  "burp.issues", "burp.history", "burp.sitemap", "burp.sitemap_issues", "burp.info",
  "burp.scan_status", "burp.scan_report", "burp.collab_poll", "burp.cookies",
  "burp.storage", "burp.entry", "burp.ws_history", "burp.organizer", "burp.decoder",
  "burp.convert", "burp.scope", "burp.options",
  "browser.screenshot", "browser.storage", "browser.network", "browser.tab",
  "recon.wordlists",
  // 无差异的对照是纯读；一旦判出差异，comparisonDiff 会先命中重算分支。
  "http.diff", "burp.compare",
]);

export type HypothesisRefreshInput = {
  tool: string;
  ok: boolean;
  rejected?: boolean;
  newNodes?: number;
  newEdges?: number;
  deadEnds?: number;
  candidates?: number;
  /** 节点属性变化（status / 状态码 / 响应体长度 / 内容类型 任一不同）。 */
  propertiesChanged?: boolean;
  /** 响应头出现 Set-Cookie / Location。 */
  signalHeaders?: boolean;
  /** 对照判出差异。 */
  comparisonDiff?: boolean;
};

export function shouldRefreshHypotheses(input: HypothesisRefreshInput): { refresh: boolean; why: string } {
  if (!input.ok || input.rejected) return { refresh: true, why: "工具失败或请求被拒，保守重算" };
  if (Number(input.newNodes) > 0 || Number(input.newEdges) > 0
    || Number(input.deadEnds) > 0 || Number(input.candidates) > 0)
    return { refresh: true, why: "图结构变化（新节点/新边/死胡同/新候选）" };
  if (input.propertiesChanged) return { refresh: true, why: "节点属性变化（状态/状态码/长度/类型）" };
  if (input.signalHeaders) return { refresh: true, why: "响应头出现身份或重定向信号" };
  if (input.comparisonDiff) return { refresh: true, why: "对照判出差异" };
  if (HYPOTHESIS_READ_ONLY_TOOLS.has(String(input.tool || "")))
    return { refresh: false, why: `纯读工具 ${input.tool} 且本轮零结构、零属性变化` };
  return { refresh: true, why: "非纯读工具，保守重算" };
}

/** 单轮 graph-hypothesis 事件的明细上限；超出部分聚合成 1 条汇总事件（单轮最多 limit+1 条）。 */
export const HYPOTHESIS_EVENT_DETAIL = 5;

/**
 * 把一批新假设切成「明细 + 聚合」两段。抽成纯函数是为了能单测锁住事件上限，
 * 不必把 desk 的整条执行链搬进测试。
 */
export function hypothesisEventBatch<T extends { kind: string }>(
  items: T[], limit = HYPOTHESIS_EVENT_DETAIL,
): { shown: T[]; rest: T[]; kinds: Record<string, number> } {
  const cap = Math.max(0, Math.trunc(Number(limit)) || 0);
  const shown = items.slice(0, cap);
  const rest = items.slice(cap);
  const kinds: Record<string, number> = {};
  for (const item of rest) kinds[item.kind] = (kinds[item.kind] || 0) + 1;
  return { shown, rest, kinds };
}
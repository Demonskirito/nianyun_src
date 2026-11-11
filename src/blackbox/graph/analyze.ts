/**
 * 图分析：环路检测与连通分量。
 *
 * 这两件事的价值不在"算法难"，在于它们能回答两个具体问题：
 *   1. Agent 是不是在 `A → B → C → A` 里空转（登录 → 越权失败 → 重新登录）？
 *   2. 图是不是裂成了几块，而 Agent 一直在最小的那块里打转？
 *
 * 500 节点的 DFS 是毫秒级，扔进 Observer 的每次 supervе 也无所谓；
 * 真正贵的是让 Agent 多打 30 轮才发现自己在绕圈。
 */
import type { AttackGraphState, GraphEdge, GraphNode } from "./types.js";

/** 有意义的"行为"边：只看这些判环路，参数/身份边会制造大量假环。 */
const WALKABLE = new Set<GraphEdge["type"]>(["navigates_to", "calls_api", "flows_data_to"]);
/**
 * 连通性口径：比环路宽一档。
 *
 * 2026-10-31 m.ctrip.com：katana 的"页面→链接"边被标成 discovered_from，
 * 而 WALKABLE 不含它，于是 257 个 endpoint 里 256 个在语义图上互不可达
 * （连通分量 310 个，最大分量 2 个节点）。寻路/势能/焦点全都退化成 FIFO。
 * discovered_from 表达的是"这个端点是从哪挖到的"，它同样是结构关系，必须参与连通性；
 * requires_auth 参与是为了让身份图连起来（同一身份被多个端点拒绝 = 一条可走的路）。
 */
const CONNECTED = new Set<GraphEdge["type"]>([...WALKABLE, "discovered_from", "requires_auth"]);

/**
 * ── 节点四态判定（2026-11-03）──────────────────────────────────────────────
 *
 * 事实层（`evidence.ts` → `builder.ts`）只写 `origin` 与 `status_unknown` 两个字段；
 * 这里把"怎么读这两个字段"收敛成三个函数，禁止各处再散落 `if (node.origin === "request")`。
 *
 *   verified()             = 没动过的块（可进"未探索面"统计）
 *   hasComparableResponse()= 有真实响应可比（才能做差异对照 / 越权判定）
 *   isProbedButUnknown()   = 发了包但没拿到状态码（该换工具重测，不是"打过了"）
 *
 * 三者的关系：untested / testing+comparable / testing+unknown / blocked|dead_end|vulnerable。
 * 典型误判都出在把第 2、3 态混为一谈——nuclei 命中一条 `{id}` 路径，既没有状态码
 * 也没有正文，却被当成"已确认可访问"，于是派了一轮根本做不成的越权对照。
 */

/** 观测到的面：历史 checkpoint 里的 link/js/api 仍要认，重建前不能被判成"没看过"。 */
const OBSERVED_ORIGINS = new Set(["request", "discovery", "seed", "derived", "link", "js", "api"]);

/**
 * 真没动过：`untested` 且**看到过真实响应**，但不是我们亲手打的。
 * 用于漂移巡检的 root 候选（覆盖率与「无增益」判定同源）。
 *
 * 2026-11-09 收紧：必须带状态码。
 *
 * 旧实现把裸 `discovery`（页面上的一个 `<a href>`）也算"观测到"，于是任何链接都能
 * 进漂移建议池。对照会话 1dd9ded9ed239711 里，巡检连续 **129 轮**推荐
 * `/topic/test2023` 与 `/adc`——这两个 URL 当天 15:15 就已经被 browser.open 打成 404，
 * 只是那个 404 没回写图节点，节点因此永远停在 `untested`，建议池里也就永远有它。
 * 模型不照做是对的，错的是建议。
 *
 * 现在的口径：有状态码才叫"观测过"；404/410 与 route_missing 是**已知坏面**，
 * 不进"没动过的面"——否则巡检会把已知死链当成待办，无限循环。
 */
export function verified(node?: GraphNode): boolean {
  if (probeState(node) !== "observed_unprobed") return false;
  return OBSERVED_ORIGINS.has(String(node?.properties?.origin || ""));
}

/**
 * ── 可探查面的三态（2026-11-10，S2-①）─────────────────────────────────────
 *
 * `verified()` 回答的是布尔问题，而下游真正需要的是"这块面处在哪个阶段"：
 *
 *   observed_unprobed  被动看到过真实响应（有 status_code），但没亲手打过 —— 巡检当前口径
 *   unprobed           只是"看见了"（页面链接 / JS 接口 / 字典命中），不知道死活
 *   probed             已经发过包（status 推进 / origin=request / 发了包没拿到码）
 *   dead               已知坏面（404 / 410 / route_missing），进墓碑
 *
 * 为什么必须拆开：会话 `1dd9ded9ed239711` 的 524 个端点里，`observed_unprobed`
 * 只有 28 个（5.3%），另有 461 个是 `unprobed`。在布尔口径下后者与"不存在"没有区别
 * ——覆盖率说"未测 489"，巡检却只能在 28 个点里挑，`rotate` 换批自然换无可换。
 * 三态是后续"配额 + 桶轮转"的前提；本函数**不改变** `verified()` 的任何准入。
 */
export type ProbeState = "probed" | "observed_unprobed" | "unprobed" | "dead";

export function probeState(node?: GraphNode): ProbeState {
  if (!node || node.type !== "endpoint") return "unprobed";
  const props = node.properties || {};
  const rawCode = props.status_code;
  const code = rawCode === undefined ? undefined : Number(rawCode);
  // 已知坏面优先：404/410 与 route_missing 是墓碑，不是"待办"。
  if (props.route_missing === true) return "dead";
  if (code === 404 || code === 410) return "dead";
  // 发过包就算动过：主动请求、历史数据兜底、以及"发了包但没拿到状态码"。
  if (String(props.origin || "") === "request") return "probed";
  if (props.status_unknown === true) return "probed";
  if (node.status !== "untested") return "probed";
  return code === undefined ? "unprobed" : "observed_unprobed";
}

/**
 * 墓碑是否仍在冷却期。
 *
 * 独立于节点存在：节点被 `prune` 删掉后墓碑还在，这是防"死链复辟"的唯一手段。
 * `round` 缺省按 0 处理——老 checkpoint 没有轮次时不让墓碑立刻失效。
 */
export function tombstoned(state: AttackGraphState | undefined, nodeId: string, round = 0): boolean {
  const mark = state?.deadMarks?.[nodeId];
  if (!mark) return false;
  return Number(mark.until_round || 0) > Math.max(0, Number(round || 0));
}

/**
 * 面池的实际构成（只读统计，不做准入决定）。
 *
 * 用途是让"图在铺面、巡检只铺点"这件事在数据里可见：`observed_unprobed` 是可建议的
 * 点数，`unprobed` 是尚未被当成面的数量，两者长期相差一个数量级就说明口径有问题。
 */
export type PoolBreakdown = {
  observed_unprobed: number;
  unprobed: number;
  probed: number;
  dead: number;
  /** 仍在冷却期的墓碑条数（含节点已被裁剪掉的）。 */
  tombstoned: number;
  /** 与 `verified()` 同源的可执行 URL 数——即 S2 之前的全部建议池。 */
  ready: number;
  /** S2 之后真正能进池的条数（四档合计，已去掉模板/重复/墓碑冷却）。 */
  pool: number;
  /** 其中"从没人请求过"的条数：铺面的实际存量。 */
  unprobed_ready: number;
  /** 其中鉴权墙回池的条数（401/403 且冷却够久）。 */
  rewall: number;
  /** 其中墓碑到期复探的条数（每批最多 1 条）。 */
  revived: number;
  /** 候选覆盖的桶数：`rotate` 有没有"另一批"可换，看这个数。 */
  buckets: number;
};

export function poolBreakdown(state: AttackGraphState | undefined, round = 0): PoolBreakdown {
  const out: PoolBreakdown = {
    observed_unprobed: 0, unprobed: 0, probed: 0, dead: 0, tombstoned: 0,
    ready: 0, pool: 0, unprobed_ready: 0, rewall: 0, revived: 0, buckets: 0,
  };
  const nodes = state?.nodes || {};
  if (!state) return out;
  const ids: string[] = [];
  for (const [id, node] of Object.entries(nodes)) {
    if (node?.type !== "endpoint") continue;
    out[probeState(node)] += 1;
    ids.push(id);
  }
  const candidates = collectProbeCandidates(state, ids, round);
  const buckets = new Set<string>();
  for (const candidate of candidates) {
    buckets.add(candidate.bucket);
    if (candidate.tier === "observed") out.ready += 1;
    else if (candidate.tier === "unprobed") out.unprobed_ready += 1;
    else out[candidate.tier] += 1;
  }
  out.pool = candidates.length;
  out.buckets = buckets.size;
  const marks = state?.deadMarks || {};
  for (const id of Object.keys(marks)) {
    if (tombstoned(state, id, round)) out.tombstoned += 1;
  }
  return out;
}

/** 有真实响应可比：差异对照 / 越权假设的前提。缺状态码就一律不算。 */
export function hasComparableResponse(node?: GraphNode): boolean {
  if (!node) return false;
  const props = node.properties || {};
  if (String(props.origin || "") !== "request") return false;
  if (props.status_unknown === true) return false;
  return props.status_code !== undefined;
}

/** 第四态：包发出去了，但工具 schema 没给状态码——既不是"打过"，也不是"没打过"。 */
export function isProbedButUnknown(node?: GraphNode): boolean {
  if (!node) return false;
  const props = node.properties || {};
  return String(props.origin || "") === "request" && props.status_unknown === true;
}

export type Cycle = { nodes: string[]; edges: string[] };

/**
 * 检测有向环（DFS + 递归栈）。
 *
 * 只报长度 >= minLength 的环：2 环（A→B→A）在爬虫图里极其常见
 * （导航栏互链），报出来就是噪音。
 */
export function detectCycles(state: AttackGraphState, options: { minLength?: number; maxCycles?: number } = {}): Cycle[] {
  const minLength = Math.max(3, options.minLength ?? 3);
  const maxCycles = Math.max(1, options.maxCycles ?? 8);
  const adjacency = new Map<string, string[]>();
  for (const edge of state.edges) {
    if (!WALKABLE.has(edge.type)) continue;
    const list = adjacency.get(edge.source_id) || [];
    list.push(edge.target_id);
    adjacency.set(edge.source_id, list);
  }

  const cycles: Cycle[] = [];
  const seen = new Set<string>();
  const stack: string[] = [];
  const onStack = new Set<string>();

  const visit = (node: string): void => {
    if (cycles.length >= maxCycles) return;
    stack.push(node);
    onStack.add(node);
    for (const next of adjacency.get(node) || []) {
      if (cycles.length >= maxCycles) break;
      if (onStack.has(next)) {
        const start = stack.indexOf(next);
        // 规范化：旋转到字典序最小的节点开头。
        // 不规范化 → 同一个环每次从不同节点报出来，interrupt 去重失效、事件流刷屏。
        const raw = stack.slice(start);
        const pivot = raw.indexOf([...raw].sort()[0]!);
        const nodes = pivot > 0 ? [...raw.slice(pivot), ...raw.slice(0, pivot)] : raw;
        if (nodes.length >= minLength) {
          const key = [...nodes].sort().join("|");
          if (!seen.has(key)) {
            seen.add(key);
            cycles.push({ nodes: [...nodes], edges: nodes.map((item, index) => `${item}->${nodes[(index + 1) % nodes.length]}`) });
          }
        }
        continue;
      }
      if (stack.includes(next)) continue;
      visit(next);
    }
    stack.pop();
    onStack.delete(node);
  };

  for (const node of Object.keys(state.nodes).sort()) {
    if (cycles.length >= maxCycles) break;
    if (state.nodes[node]?.type !== "endpoint") continue;
    if (!adjacency.has(node)) continue;
    visit(node);
  }
  return cycles;
}

export type Component = { id: string; nodes: string[]; size: number; hasVuln: boolean; hasBlocked: boolean };

/**
 * 无向连通分量。
 *
 * 用无向是因为"能不能到达"这件事在 explorer 视角下是对称的：
 * 从 A 到不了 B，但 B 到得了 A，Agent 依旧被限制在同一块里。
 * `requires_auth` / `exploits` 边：前者参与连通性（同一身份被多处拒绝是一条可走的路），
 * 后者是"结论"不参与。
 */
export function connectedComponents(state: AttackGraphState): Component[] {
  const parent = new Map<string, string>();
  const find = (node: string): string => {
    let cursor = node;
    while (parent.get(cursor) && parent.get(cursor) !== cursor) cursor = parent.get(cursor)!;
    return cursor;
  };
  const union = (a: string, b: string): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  for (const id of Object.keys(state.nodes)) parent.set(id, id);
  for (const edge of state.edges) {
    if (!CONNECTED.has(edge.type)) continue;
    if (!parent.has(edge.source_id) || !parent.has(edge.target_id)) continue;
    union(edge.source_id, edge.target_id);
  }
  const groups = new Map<string, string[]>();
  for (const id of Object.keys(state.nodes)) {
    const root = find(id);
    const list = groups.get(root) || [];
    list.push(id);
    groups.set(root, list);
  }
  return [...groups.entries()]
    .map(([root, nodes]) => ({
      id: `cc:${root.replace(/^[a-z]+:/, "")}`,
      nodes,
      size: nodes.length,
      hasVuln: nodes.some(id => state.nodes[id]?.status === "vulnerable" || state.nodes[id]?.type === "vuln_state"),
      hasBlocked: nodes.some(id => state.nodes[id]?.status === "blocked"),
    }))
    .sort((a, b) => b.size - a.size);
}

export type GraphSignal = { kind: "cycle" | "component_drift" | "graph_no_new_nodes"; severity: "high" | "medium"; text: string; data?: Record<string, unknown> };

/**
 * 图信号的**语义指纹**（2026-11-09，A3/P2）。
 *
 * 只取 kind + roots（排序），不取正文、不取块数/轮数：正文里的数字每轮都在变，
 * 只看 text 判新旧会让同一条提醒每轮都算"新插话"。
 *
 * 插话去重（progress.addInterrupts）和事件门禁（desk 的 graph-signal）都用它，
 * 两处必须同源——各写一份就会出现"插话没变、事件照写"的错位。
 */
export function graphSignalFingerprint(signal: GraphSignal): string {
  const roots = Array.isArray(signal.data?.roots) ? (signal.data!.roots as unknown[]).map(String) : [];
  return `${signal.kind}:${roots.sort().join("|")}`.slice(0, 200);
}

/** 门禁账本（存 checkpoint 的 `graph_signal_gate`）。 */
export type GraphSignalGateState = {
  prints: string[];
  quiet: boolean;
  /**
   * 停摆段号（2026-11-10）。
   *
   * 旧实现里 quiet 只有一个布尔，`graph_no_new_nodes` 的"首次"判定就是 `!previous.quiet`。
   * 问题在**复位**：信号清空时门禁被写成 `{prints: [], quiet: false}`，等于把 quiet 的账
   * 一起抹了；下一轮它再出现，就又是一次"首次"，正文与上一条逐字相同。
   *
   * 现在 quiet 的身份是 `quiet@<段号>`：段号跨复位保留，只有停摆**真断过**（连续两轮
   * 没有 quiet，说明图又长出新节点）才 +1。于是"复位 → 再来"不算新事件，
   * "停摆 → 图长过 → 又停摆"才算——后者是真信息。
   */
  quiet_epoch?: number;
  /** 连续多少轮没有 quiet（复位不清）。单轮缺失算抖动，不清账。 */
  quiet_gap?: number;
  /**
   * 上一次写汇总事件时的**图轮次**（2026-11-10）。
   *
   * 为什么不用 `graph_drift.rounds`：那个计数在采纳时被清零（`graph_drift = undefined`），
   * 于是"每 20 轮留一条审计"在勤采纳的会话里永远到不了点——第 15 轮采纳、下一批从 1 重新数，
   * 永远停在 20 以下，汇总一条都不会有。图轮次是外部的单调时钟，采纳/换批都不动它。
   */
  summary_round?: number;
};

/**
 * 欠账汇总的间隔（**图轮次**）。
 *
 * 2026-11-10：10 → 20 且改按图轮次计。汇总的正文与上一批**逐字相同**，只多一个
 * "催了 N 轮"的数字，10 轮一条在慢节奏会话里就是明显的噪声源（12 轮实测里那唯一
 * 一条"同批重复"就是它）。
 *
 * 为什么按图轮次、不按"欠账连续轮数"：后者会在采纳时清零，于是"每 20 轮必留一条
 * 审计"在勤采纳的会话里永远不成立（第 15 轮采纳 → 下一批从 1 重数 → 永远不到 20）。
 * 图轮次只随 run 前进，采纳、换批、复位都不影响它，汇总因此变成"定期体检"。
 */
export const GRAPH_SIGNAL_SUMMARY_EVERY = 20;

/**
 * graph-signal 事件门禁（2026-11-09，P2；2026-11-10 纳入 quiet 复位与图轮次汇总）。
 *
 * 为什么不能用 `addInterrupts` 的返回值当门禁：它返回的是"插话池里新增了几条"，
 * 而插话池只有 12 格。`graph:*` 被 `focus-auto-handoff` 这类一次性条目挤出去之后，
 * 下一轮重新插入同样会 `added=1`——现场两条正文完全相同的信号（301 字符、同一批 roots）
 * 就是这样重复落账的。门禁必须看**语义**，不看插话池的进出。
 *
 * 规则：
 * ① 拓扑指纹集合变了（换批 / 环路出现 / 漂移消失）→ 写；
 * ② "连续无新节点"每**一段停摆**写一次（`quiet@段号`）。段号跨复位保留；
 *    单轮缺失算抖动不换段，连续两轮缺失才换段（图真长过）；
 * ③ 距上次汇总满 `summaryEvery` 个**图轮次** → 写一条定期体检（不受采纳/换批影响）。
 */
export function graphSignalGate(
  previous: GraphSignalGateState | undefined,
  signals: GraphSignal[],
  options: { graphRound?: number; summaryEvery?: number } = {},
): { emit: boolean; gate: GraphSignalGateState } {
  const prints = [...new Set(signals
    .filter(signal => signal.kind !== "graph_no_new_nodes")
    .map(graphSignalFingerprint))].sort();
  const hasQuiet = signals.some(signal => signal.kind === "graph_no_new_nodes");

  const wasQuiet = previous?.quiet === true;
  const gap = hasQuiet ? 0 : (previous ? Number(previous.quiet_gap || 0) + 1 : 0);
  // 停摆断过：连续两轮没有 quiet。单轮缺失（抖动）不清账，否则"长一个节点又停"会反复播报。
  const broke = wasQuiet && gap >= 2;
  const quietEpoch = Number(previous?.quiet_epoch || 0) + (broke ? 1 : 0);
  // 账本：有 quiet 就一直记账；断过才清；抖动既不清也不重报。
  const quietArmed = hasQuiet ? true : (broke ? false : wasQuiet);

  const topologyChanged = prints.join("\n") !== (previous?.prints || []).join("\n");
  // 同一段停摆只报一次；换段（或复位后账本被清）之后才有资格再报。
  const quietFirst = hasQuiet && !wasQuiet;

  const round = Math.max(0, Math.floor(Number(options.graphRound ?? 0)));
  const summaryEvery = Math.max(1, options.summaryEvery ?? GRAPH_SIGNAL_SUMMARY_EVERY);
  // 首次调用（或老 checkpoint 没有该字段）只上表、不立刻汇总。
  const lastSummary = Number(previous?.summary_round ?? round);
  const summaryDue = round > 0 && round - lastSummary >= summaryEvery;

  return {
    emit: topologyChanged || quietFirst || summaryDue,
    gate: {
      prints, quiet: quietArmed, quiet_epoch: quietEpoch, quiet_gap: gap,
      summary_round: summaryDue ? round : lastSummary,
    },
  };
}

/**
 * 门禁的"静默"复位（2026-11-10）。
 *
 * 只清拓扑指纹，**保留 quiet 账本、段号与上次汇总轮次**：图上的信号消失（漂移暂时不成立）
 * 不代表停摆这段历史没发生过。全清会让 quiet 下一轮重新算"首次"（与旧 bug 同形），
 * 也会让汇总提前到点（复位不该重置体检计时）。
 * "重新播报同一批 roots"的诉求由清空 `prints` 满足。
 */
export function resetGraphSignalGate(previous: GraphSignalGateState | undefined): GraphSignalGateState {
  return {
    prints: [],
    quiet: previous?.quiet === true,
    quiet_epoch: Number(previous?.quiet_epoch || 0),
    quiet_gap: Number(previous?.quiet_gap || 0),
    ...(previous?.summary_round === undefined ? {} : { summary_round: Number(previous.summary_round) }),
  };
}

/**
 * 图节点 id → **可直接执行**的 URL（2026-11-07）。
 *
 * 现场教训：`component_drift` 一直把 `ep:next.api.aliyun.com/document/Vpc/{id}` 这种
 * 节点 id 原样拼进 `http.request GET ...`，模型照抄只会得到无效 URL；同一句提醒发到
 * 第 77 次也没人能执行。带 `{id}` 模板占位符、无 host 的节点一律不进提醒——
 * 宁可少一条提示，也不要一条看似可执行、实际做不到的泛化指令。
 */
export function executableRootUrls(nodeIds: string[], limit = 3): { urls: string[]; skipped: number } {
  const urls: string[] = [];
  let skipped = 0;
  for (const id of nodeIds) {
    const rest = String(id || "").startsWith("ep:") ? String(id).slice(3) : "";
    if (!rest || /[{}]/.test(rest)) { skipped += 1; continue; }
    const candidate = `https://${rest}`;
    try {
      const parsed = new URL(candidate);
      if (!parsed.hostname.includes(".")) { skipped += 1; continue; }
      urls.push(candidate);
    } catch { skipped += 1; }
  }
  return { urls: [...new Set(urls)].slice(0, limit), skipped };
}

/** 节点 id → 建议用的 URL（与 executableRootUrls 同源，反向取回时用）。 */
export function rootUrlOf(nodeId: string): string {
  return String(nodeId || "").startsWith("ep:") ? `https://${String(nodeId).slice(3)}` : "";
}

/** 建议优先级：能直接出结论的排前面。 */
function statusRank(node?: GraphNode): number {
  const code = Number(node?.properties?.status_code);
  if (code === 200) return 0;
  if (code >= 300 && code < 400) return 1;
  if (code === 401 || code === 403) return 2;
  return Number.isFinite(code) ? 3 : 4;
}

/**
 * 漂移 root 的选取顺序（2026-11-09，A2）。
 *
 * 旧实现 `flatMap(...).slice(0, 6)` 取的是**分量数组顺序**的前 6 个：只要图不变，
 * 每轮吐出的就是同 3 条 URL。对照组里这批 URL 已 404，巡检却催了 129 轮。
 *
 * 现在的顺序：① 上一批仍在池里的优先（保证文案稳定，插话才去得掉）→
 * ② 被建议次数少的优先（`suggested` 由控制面持久化，`rotate` 为真时才生效）→
 * ③ 200 优先、3xx 次之、401/403（鉴权墙，值得换身份再打）再次 → ④ id 字典序兜底。
 *
 * `rotate=false` 时②不生效，否则每轮都会因为 0 次 vs 1 次而换批，文案天天变。
 */
export function rankDriftRoots(
  state: AttackGraphState,
  nodeIds: string[],
  options: { suggested?: Record<string, number>; prefer?: string[]; rotate?: boolean } = {},
): string[] {
  const suggested = options.suggested || {};
  const prefer = new Set((options.prefer || []).map(url => String(url || "")).filter(Boolean));
  const times = (id: string): number => Number(suggested[rootUrlOf(id)] || 0);
  return [...new Set(nodeIds)].sort((a, b) => {
    if (options.rotate !== true) {
      const pa = prefer.has(rootUrlOf(a)) ? 0 : 1;
      const pb = prefer.has(rootUrlOf(b)) ? 0 : 1;
      if (pa !== pb) return pa - pb;
    }
    const ta = times(a);
    const tb = times(b);
    if (ta !== tb) return ta - tb;
    const sa = statusRank(state.nodes[a]);
    const sb = statusRank(state.nodes[b]);
    if (sa !== sb) return sa - sb;
    return a.localeCompare(b);
  });
}

/**
 * ── 可探查面的分层与配额（2026-11-10，S2-②③）────────────────────────────
 *
 * 背景：`verified()` 要求"有状态码但没亲手打过"，这只覆盖被动流量。
 * 对照会话 `1dd9ded9ed239711` 的 524 个端点里，`observed_unprobed` 只有 28 个，
 * 另 461 个是 `unprobed`（页面链接 / JS 接口，从没人请求过，所以永远没有状态码）。
 * 布尔口径下这 461 个"面"与不存在等价：覆盖率说未测 489，巡检只在 28 个点里挑，
 * `rotate` 换批换无可换——这就是"图铺面、巡检只铺点"。
 *
 * 这一层的改动只做两件事，**不放宽任何"已知坏面"的准入**：
 *   ① 配额：一批 3 条 = 最多 2 条 `observed` + 1 条"野槽"（`unprobed` / `rewall` 交替）
 *   ② 桶轮转：桶键 = host + 一级路径。计数与轮换从 URL 挪到桶上，
 *      换批才有"另一批"可换（老会话 26 条 URL 只能分出 5–6 个桶）。
 *
 * 墓碑（`deadMarks`）在这里是硬闸门：冷却期内的死链一条都不进池；到期后只给
 * `revived` 一档、并且每批最多 1 条——绝不让整批死链同时回池（那是 129 轮死链的历史）。
 */
export type ProbeTier = "observed" | "unprobed" | "rewall" | "revived";

/** 一批建议的默认条数：与 `executableRootUrls(limit=3)` 同口径。 */
export const PROBE_BATCH_LIMIT = 3;
/** 鉴权墙回池：401/403 的端点距上次真打超过这么多轮，才允许再建议一次（换身份）。 */
export const AUTH_WALL_REPROBE_ROUNDS = 10;

/**
 * 桶键 = `host + 一级路径`。
 *
 * 为什么不是整条 URL：老会话 26 条候选全在 `next.api.aliyun.com` 一个前缀下，
 * 按 URL 轮换永远在同一片里换顺序；按桶分能分出 5–6 组，`rotate` 才有实际意义。
 * 只有主机没有路径时回落到 `host/`——那是资产根，本身就是一个桶。
 */
export function probeBucket(url: string): string {
  try {
    const parsed = new URL(String(url || ""));
    const segment = parsed.pathname.split("/").filter(Boolean)[0] || "";
    return `${parsed.hostname.toLowerCase()}/${segment.slice(0, 40)}`;
  } catch {
    return "";
  }
}

export type ProbeCandidate = {
  id: string;
  url: string;
  bucket: string;
  tier: ProbeTier;
  status?: number;
};

/**
 * 单个端点落在哪一档；`null` = 不进池。
 *
 * 分档判据全部是已有事实，没有任何"猜"：
 *   observed  `verified()` 同源（有状态码、未亲手打、origin 在白名单）
 *   unprobed  `probeState === "unprobed"` 且 origin 在白名单（空 origin 的老脏数据不进）
 *   rewall    已打过、401/403、距上次真打 >= AUTH_WALL_REPROBE_ROUNDS 轮
 *   revived   墓碑存在且已过冷却期（只放 1 条，见 pickProbeBatch）
 */
function probeTier(state: AttackGraphState, nodeId: string, round: number): ProbeTier | null {
  const node = state.nodes[nodeId];
  if (!node || node.type !== "endpoint") return null;
  const phase = probeState(node);
  const now = Math.max(0, Number(round || 0));

  if (phase === "dead") {
    // 没有墓碑的老数据不参与复探：无法判断它冷却了多久，宁可不提。
    if (!state.deadMarks?.[nodeId]) return null;
    return tombstoned(state, nodeId, now) ? null : "revived";
  }
  if (phase === "observed_unprobed") return verified(node) ? "observed" : null;
  if (phase === "unprobed") {
    return OBSERVED_ORIGINS.has(String(node.properties?.origin || "")) ? "unprobed" : null;
  }
  // probed：只有"鉴权墙 + 冷却够久"才回池，其余一律不提（已经打过，再催就是噪音）。
  const code = Number(node.properties?.status_code);
  if (code !== 401 && code !== 403) return null;
  const last = Number(node.properties?.last_probe_round ?? node.round ?? 0);
  return now - last >= AUTH_WALL_REPROBE_ROUNDS ? "rewall" : null;
}

/** 某条候选是否进池（供分量筛选与统计复用，避免两处判据漂移）。 */
export function probeEligible(state: AttackGraphState, nodeId: string, round = 0): boolean {
  return probeTier(state, nodeId, round) !== null;
}

/**
 * 把节点 id 收敛成"可执行候选"：跳过 `{id}` 模板、无 host、重复 URL。
 *
 * 模板路径照样跳过——一条看似可执行、实际做不到的指令，比少一条提示更糟。
 */
export function collectProbeCandidates(
  state: AttackGraphState,
  nodeIds: string[],
  round = 0,
): ProbeCandidate[] {
  const out: ProbeCandidate[] = [];
  const seen = new Set<string>();
  for (const id of nodeIds) {
    const url = rootUrlOf(id);
    if (!url || /[{}]/.test(url)) continue;
    let hostname = "";
    try { hostname = new URL(url).hostname; } catch { continue; }
    if (!hostname.includes(".")) continue;
    const tier = probeTier(state, id, round);
    if (!tier) continue;
    if (seen.has(url)) continue;
    seen.add(url);
    const code = Number(state.nodes[id]?.properties?.status_code);
    out.push({ id, url, bucket: probeBucket(url), tier, ...(Number.isFinite(code) ? { status: code } : {}) });
  }
  return out;
}

/** 同档内的排序权重：能直接出结论的排前面。 */
function tierRank(tier: ProbeTier): number {
  if (tier === "observed") return 0;
  if (tier === "rewall") return 1;
  if (tier === "unprobed") return 2;
  return 3;
}

/**
 * 从候选里挑一批。
 *
 * 三轮优先关系，顺序不能换：
 *   ① `prefer`（上一批）优先——`rotate=false` 时正文必须逐字稳定，否则每轮都是"新插话"；
 *   ② 桶计数少的优先——这才是 A2 的换批依据，计数记在桶上；
 *   ③ 档位、状态码、id 字典序兜底。
 *
 * 配额：前两格给 `observed`，第三格是"野槽"，按轮次奇偶在 `unprobed` / `rewall` 之间交替，
 * 一个档取不到时按 `unprobed → rewall → revived` 顺延。这样 461 条面每次都能拿到一格，
 * 而鉴权墙不会因为"铺面"被永久挤出去；`revived` 每批最多 1 条，防止死链成批复辟。
 */
export function pickProbeBatch(
  candidates: ProbeCandidate[],
  options: { limit?: number; round?: number; suggested?: Record<string, number>; prefer?: string[]; rotate?: boolean } = {},
): { ids: string[]; urls: string[]; buckets: string[]; tiers: ProbeTier[] } {
  const limit = Math.max(1, Math.min(6, Number(options.limit ?? PROBE_BATCH_LIMIT)));
  const round = Math.max(0, Number(options.round || 0));
  const suggested = options.suggested || {};
  const prefer = new Set((options.prefer || []).map(String));
  const times = (candidate: ProbeCandidate): number =>
    Number(suggested[candidate.bucket] || 0) + Number(suggested[candidate.url] || 0);

  const ranked = [...candidates].sort((a, b) => {
    if (options.rotate !== true) {
      const pa = prefer.has(a.url) ? 0 : 1;
      const pb = prefer.has(b.url) ? 0 : 1;
      if (pa !== pb) return pa - pb;
    }
    const ta = times(a);
    const tb = times(b);
    if (ta !== tb) return ta - tb;
    const ra = tierRank(a.tier);
    const rb = tierRank(b.tier);
    if (ra !== rb) return ra - rb;
    const sa = Number.isFinite(a.status) ? Number(a.status) : 999;
    const sb = Number.isFinite(b.status) ? Number(b.status) : 999;
    if (sa !== sb) return sa - sb;
    return a.id.localeCompare(b.id);
  });

  const wildcard: ProbeTier[] = round % 2 === 0
    ? ["unprobed", "rewall", "revived"]
    : ["rewall", "unprobed", "revived"];
  // 序列长度超过 limit：observed 取不到时，后面的条目自然补位。
  const plan: ProbeTier[] = ["observed", "observed", ...wildcard, "observed", "unprobed", "rewall", "revived"];

  // 野槽的"只占 1 格"由 plan 的位置保证（第 3 位之后才轮到补位），不靠配额定死：
  // observed 不足 2 条时必须能用野槽补满，否则一批只剩 1–2 条，深挖直接断粮。
  const quota: Record<ProbeTier, number> = { observed: limit, unprobed: limit, rewall: limit, revived: 1 };
  const picked: ProbeCandidate[] = [];
  const usedBuckets = new Set<string>();
  for (const tier of plan) {
    if (picked.length >= limit) break;
    if (quota[tier] <= 0) continue;
    const pool = ranked.filter(candidate => candidate.tier === tier && !picked.includes(candidate));
    if (!pool.length) continue;
    const fresh = pool.find(candidate => !usedBuckets.has(candidate.bucket));
    const chosen = fresh ?? pool[0];
    if (!chosen) continue;
    picked.push(chosen);
    usedBuckets.add(chosen.bucket);
    quota[tier] -= 1;
  }

  return {
    ids: picked.map(candidate => candidate.id),
    urls: picked.map(candidate => candidate.url),
    buckets: picked.map(candidate => candidate.bucket),
    tiers: picked.map(candidate => candidate.tier),
  };
}

export type GraphSignalOptions = {
  minRounds?: number;
  quietRounds?: number;
  /** 已建议过的 root URL / 桶 → 次数（控制面持久化在 graph_drift.suggested）。 */
  suggested?: Record<string, number>;
  /** 上一批仍在建议的 root，保证同一批的正文逐字一致。 */
  prefer?: string[];
  /** 只在控制面要换批时置真（否则每轮都会因为计数差换批）。 */
  rotate?: boolean;
  /** 图轮次：桶轮转的奇偶与鉴权墙冷却都按它算。 */
  round?: number;
};

/**
 * Observer 用的图巡检：从"最近在打什么"出发判断是否空转。
 *
 * `recent` 是最近若干次请求的端点 node id（由控制面按时间倒序给），
 * 这里只做拓扑判断，不推测意图。
 */
export function graphSignals(state: AttackGraphState, recent: string[], options: GraphSignalOptions = {}): GraphSignal[] {
  const signals: GraphSignal[] = [];
  const minRounds = Math.max(3, options.minRounds ?? 3);
  const recentSet = new Set(recent.filter(Boolean));

  // ① 环路：最近活动落在一条环上的节点数 >= 3 → 报出来。
  for (const cycle of detectCycles(state)) {
    const hit = cycle.nodes.filter(node => recentSet.has(node));
    if (hit.length < 3) continue;
    signals.push({
      kind: "cycle", severity: "high",
      text: `检测到行为环路：${cycle.nodes.join(" → ")} → ${cycle.nodes[0]}。停止在这条环上换 payload，先判断是不是鉴权墙（换身份/带凭证）或换打法。`,
      data: { cycle: cycle.nodes },
    });
    break;
  }

  // ② 分量漂移：最近活动全在一个分量里，而其他分量还有**可探查的面**。
  //
  // 2026-10-28 修正：原来只要"分量的节点 status=untested"就算"没动过的块"，
  // 于是 113 条字典命中（每个节点只有一条 discovered_from 边，不成链）被算成
  // 112 个"没动过的块"，Observer 连续 8 轮催 Agent 去打 flag.php / flag.txt —— 全是字典条目。
  // 2026-11-03：Root 必须是确认观测过的端点（`verified()`）。
  // 2026-11-10（S2-②③）：改成按档判（`probeEligible`）——`observed` 之外的 461 条面
  // 也是面。准入仍由 `probeTier` 把关：死链在墓碑冷却期内一条不进，已打过的只有
  // 鉴权墙冷却够久才回池；一批 3 条 = 2 条 observed + 1 条野槽，桶轮转决定换哪一片。
  const round = Math.max(0, Number(options.round || 0));
  const probeRoot = (nodeId: string): boolean => nodeId.startsWith("ep:") && probeEligible(state, nodeId, round);
  const components = connectedComponents(state);
  if (components.length > 1 && recent.length >= minRounds) {
    const home = components.find(component => component.nodes.some(node => recentSet.has(node)));
    const untestedElsewhere = components.filter(component => component !== home
      && component.nodes.some(node => probeRoot(node)));
    if (home && untestedElsewhere.length) {
      const candidateIds = untestedElsewhere.flatMap(component => component.nodes.filter(node => probeRoot(node)));
      const candidates = collectProbeCandidates(state, candidateIds, round);
      const batch = pickProbeBatch(candidates, {
        limit: PROBE_BATCH_LIMIT, round,
        suggested: options.suggested, prefer: options.prefer, rotate: options.rotate,
      });
      const roots = batch.urls;
      const skipped = Math.max(0, candidateIds.length - candidates.length);
      const componentSummary = components.map(component => ({ id: component.id, size: component.size }));
      if (roots.length) {
        // 整批都是 401/403 时，指令必须换一种：匿名重打一次 403 不会变成 200。
        const allWalled = batch.tiers.every(tier => tier === "rewall");
        const hasUnprobed = batch.tiers.includes("unprobed") || batch.tiers.includes("revived");
        signals.push({
          kind: "component_drift", severity: "medium",
          // 块数 / 当前块大小 / 未测块数一律放 data（2026-11-09，A3）。
          // 这些数字每轮都在变，写进 text 就会让指纹每轮都不同，插话去重失效——
          // 现场因此 13 分钟写了 7 条同义 graph-signal。
          text: `图是裂开的：你一直在同一块里活动，另外几块还没人碰。先打这些 URL：${roots.join("、")}。`
            + (allWalled
              ? `这一批在被动流量里全是 401/403（鉴权墙）：带上凭证或换个身份各打一次，匿名重试不会有新结果。`
              : hasUnprobed
                ? `其中没验证过的那几条是页面里出现过、但从没人请求过的接口：各打一次先确认死活——200/3xx 就继续挖，404 就跳过，401/403 记成鉴权墙等着换身份。`
                : `打过之后要么长出新节点，要么把那一块判死——别继续在原来的块里换 payload。`),
          data: { components: componentSummary, blocks: components.length, home_size: home.size,
            untouched_blocks: untestedElsewhere.length, all_walled: allWalled,
            roots, roots_raw: batch.ids, skipped_template_roots: skipped,
            tiers: batch.tiers, buckets: batch.buckets, has_unprobed: hasUnprobed },
        });
      } else {
        /**
         * 过滤到零 ≠ 没有异常（2026-11-07）。
         *
         * 旧实现这里直接 return：现场三个入口全是 `ep:next.api.aliyun.com/document/xxx/{id}`，
         * 一条可执行 URL 都提不出来，于是"图卡在模板路径上"这件最该说的事彻底静默，
         * graph_drift 也停在部署前的旧值上，面板看起来像巡检坏了。
         *
         * 现在的处理：不伪造 URL，但把"为什么没给 URL"和"下一步能做什么"说清楚——
         * 这才是模板路径场景下唯一可执行的指令。
         */
        signals.push({
          kind: "component_drift", severity: "medium",
          // 同 ③：具体块数/占位符数量放 data，text 保持稳定，避免每轮都算"新插话"。
          text: `图裂成多块，你一直只在其中一块里活动。另有几块没动过，但它们的入口都是模板路径（带 {id} 占位符），照抄只会 404。下一步：先打这些块的父页面或资产根（site.map / robots / 页面里的真实链接），或者从已打通的端点里找一个同族 URL 换成具体实例 ID 再打；拿到真实路径后回到这些模板补实例。`,
          data: { components: componentSummary,
            roots: [], roots_raw: batch.ids, skipped_template_roots: skipped, template_only: true },
        });
      }
    }
  }
  /**
   * ③ 连续无新节点兜底（2026-11-07）。
   *
   * 前两条信号都有前提：环路要有环、漂移要有多块。图卡在单一分量里、反复打同一批 URL 时，
   * 它们一个都不出声——而"没有信号"被当成了"没有问题"。
   * 这里给一条最小的、不依赖拓扑的信号，专门兜住这种静默。
   */
  const quietRounds = Number(options.quietRounds || 0);
  if (quietRounds >= 3) {
    signals.push({
      kind: "graph_no_new_nodes", severity: "medium",
      // 文案必须稳定：把具体轮数写进 text 会让 addInterrupts 的 (id,text) 去重每轮失效，
      // 现场曾经因此把同一句提醒写成 77 条事件。轮数放在 data 里。
      text: `已连续多轮（≥3）没有新节点进图：当前打法在同一批 URL 上重复。换面——换身份（带凭证 / 匿名对照）、换参数、换入口页面，或先回资产根重新枚举，不要继续在同一批端点上改 payload。`,
      data: { quiet_rounds: quietRounds },
    });
  }
  return signals;
}

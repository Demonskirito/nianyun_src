/**
 * 焦点锁（Focus Lock）：一轮只准推进一个任务。
 *
 * 为什么需要它：实测 gray-push 会话一轮发出 5–8 个 tool_request，分属不同任务，
 * 每条都是"浅尝辄止"——bundle 取不到、CORS 没对照、WAF 面没判定，全部停在半路。
 * 任务簿再干净，一轮打八个也等于零个。所以由控制面挑一个焦点，其余的请求直接拒收。
 *
 * 优先级（用户定的，别改顺序）：
 *   1. 上一轮已经开始但没结束的任务（粘性：`state.focus_task_id` 还非终态就继续它）
 *   2. 图谱里离 VULN_STATE / 高危 HYPOTHESIS 最近的任务（Dijkstra 代价最小）
 *   3. 创建最早的任务（FIFO）
 *
 * 选择是纯函数、每轮重算：状态没变就是同一个结果，不需要另存一份"焦点"状态去对账。
 */
import { dijkstra, highValueTargets } from "./graph/pathfind.js";
import { endpointNodeId } from "./graph/builder.js";
import { graphState } from "./graph/builder.js";
import type { AttackGraphState } from "./graph/types.js";
import type { RunCheckpoint } from "./progress.js";

export type FocusReason = "exclusive" | "sticky" | "running" | "advice" | "appeal" | "graph_nearest" | "fifo" | "forced";

export type FocusChoice = {
  task_id: string;
  reason: FocusReason;
  /** 人可读的一句话，直接进上下文与事件。 */
  detail: string;
  /** 图距离（reason=graph_nearest 时有意义）。 */
  distance?: number;
  purpose?: string;
  playbook?: string;
  /** SPA 缴械后的转向提示：被锁任务必须用 browser/exec，不要用被缴械的步兵工具。 */
  spaHint?: string;
};

type TaskLike = { status?: string; purpose?: string; playbook?: string; target?: string; created_at?: number };

const TERMINAL = new Set(["completed", "blocked", "failed"]);

/** 非终态任务（按 checkpoint 里的插入顺序，即创建顺序）。 */
function openTasks(state: RunCheckpoint): Array<[string, TaskLike]> {
  const tasks = (state.tasks || {}) as Record<string, TaskLike>;
  return Object.entries(tasks).filter(([id, task]) => {
    if (!task || typeof task !== "object") return false;
    if (TERMINAL.has(String(task.status || ""))) return false;
    return !id.startsWith("action:"); // 合成的动作伪任务不参与焦点竞争
  });
}

/**
 * 任务到"高价值目标"的图距离。
 *
 * 任务只带 URL，所以先映射到端点节点；端点不在图里（还没打过）返回 undefined，
 * 这种任务不参与第二优先级——宁可 FIFO，也不要拿不存在的位置瞎猜。
 */
function graphDistance(graph: AttackGraphState, task: TaskLike): number | undefined {
  const target = String(task.target || "");
  if (!target) return undefined;
  let nodeId: string;
  try {
    nodeId = endpointNodeId(target);
  } catch {
    return undefined;
  }
  if (!graph.nodes[nodeId]) return undefined;
  const targets = new Set(highValueTargets(graph));
  if (!targets.size) return undefined;
  // 任务自己就指着高价值端点：距离 0，先做它（Dijkstra 不会给起点写非零成本，必须显式判）。
  if (targets.has(nodeId)) return 0;
  // 无向近似：真实图里绝大多数边是 asset → endpoint 的单向入边（爬取时只记录"从哪发现的"），
  // 只按出边走的话每个端点都到不了任何地方，这条优先级会静默退化成 FIFO。
  // 焦点要的是"离高价值目标多近"，不是"请求能不能顺着边走"，所以对称化邻接后再跑。
  const routes = dijkstra(undirected(graph), nodeId);
  let best: number | undefined;
  for (const route of routes.values()) {
    if (!route.hops.length) continue;
    if (!targets.has(route.target)) continue;
    if (best === undefined || route.cost < best) best = route.cost;
  }
  return best;
}

/** 双向邻接副本：不动原图，只给焦点选择用。 */
function undirected(graph: AttackGraphState): AttackGraphState {
  const edges = [...(graph.edges || [])];
  for (const edge of graph.edges || []) {
    if (edge.source_id === edge.target_id) continue;
    edges.push({ ...edge, id: `${edge.id}:rev`, source_id: edge.target_id, target_id: edge.source_id });
  }
  return { ...graph, edges };
}

/** 建议/申诉让位用的最小字段（不引 progress 的完整类型，避免环形依赖）。 */
type AdviceLike = { status?: string; task_ids?: string[]; misses?: number };

/**
 * Observer 建议指向哪个未结案任务（只在"这条建议已被漏过一轮"时才让位）。
 *
 * 让位条件刻意不含"建议本身写得好不好"：评判建议质量是 Observer 的事，焦点锁只管
 * 谁有资格动。模型对建议的处置（accepted/rejected + 理由）才是判断它有没有读的依据。
 */
function adviceFocusTarget(state: RunCheckpoint, byId: Map<string, TaskLike>, exclude = ""): { task_id: string; advice_id: string } | undefined {
  const advice = (state as { advice?: Record<string, AdviceLike> }).advice || {};
  for (const [id, item] of Object.entries(advice)) {
    if (item.status !== "pending" || (item.misses || 0) < 1) continue;
    for (const raw of item.task_ids || []) {
      const taskId = String(raw || "");
      if (!taskId || taskId === exclude) continue;
      const task = byId.get(taskId);
      if (!task || TERMINAL.has(String(task.status || ""))) continue;
      return { task_id: taskId, advice_id: id };
    }
  }
  return undefined;
}

export function computeFocus(state: RunCheckpoint): FocusChoice | undefined {
  const open = openTasks(state);
  if (!open.length) return undefined;
  const byId = new Map(open);

  // ⓪ 控制面强制劫持（2026-10-28 补）：主权转移 / SPA 缴械 / 字典抽样探针。
  //    这三类任务不是"建议"，是代码替模型做的决定：
  //    实测 note.yun 那轮 301 早已跳到 cloud.oppo.com，模型却在 13 分钟里又对旧 host
  //    发了 6 次同样的请求；224 个字典节点被 3 次点名也没有一条被请求。
  //    只要 forced_focus 指向的任务还活着，它就是唯一焦点，sticky 也不能抢。
  const forced = (state as { forced_focus?: { task_id?: string; kind?: string; note?: string } }).forced_focus;
  if (forced?.task_id) {
    const task = byId.get(String(forced.task_id));
    // 已终态的任务不能继续当焦点：否则它永远不结案，其它任务的请求被一律拒收，
    // 调度器连续空转后被判 stalled，整场 run 就死在"强制焦点"上。
    if (task && !TERMINAL.has(String(task.status || ""))) {
      // 让位优先级：forced 是代码替模型做的决定，但它不能变成"模型每次都被自己的调度器拒收"。
      // 2026-11-02 实跑（会话 6ee79b87a797904f）：SPA 缴械把焦点钉在 T_SPA_REVERSE，模型连续
      // 三轮整批请求都投给 T1（11 个请求零放行），appeal 记到 3 票却每轮都被这里抢先 return，
      // 于是 3 次零动作 → stalled，40 次调用只用了 3 次。有整批被拒的硬证据时让位一次，
      // 让位目标结案后 forced 自动恢复（forced_focus 字段不删，suspended 由 desk 清除）。
      const appealNow = (state as { focus_appeal?: { task_id?: string; votes?: number; suspended?: boolean } }).focus_appeal;
      const appealTargetId = String(appealNow?.task_id || "");
      const appealVotes = Number(appealNow?.votes || 0);
      if (appealTargetId && appealTargetId !== String(forced.task_id) &&
          (appealNow?.suspended === true || appealVotes >= 2)) {
        const alt = byId.get(appealTargetId);
        if (alt && !TERMINAL.has(String(alt.status || ""))) {
          return {
            task_id: appealTargetId,
            reason: "appeal",
            detail: `强制焦点 ${forced.task_id}（${forced.kind || "forced"}）暂挂：连续 ${appealVotes} 轮整批请求都指向这条任务且全被拒收，先让它把结论打出来；它结案后强制焦点自动恢复`,
            purpose: alt.purpose,
            playbook: alt.playbook,
          };
        }
      }
      // 释放条件只有一条：被锁任务结案（completed/blocked/failed）——模型真的对它下了 verdict
      // （挖出洞→finding，或确认无洞/无价值→带证据引用的负面结案）。绝不用轮数定时器松手：
      // 那等于把"锚定深挖"的设计撤掉，agent 又散回"东跑西跑"。真正的安全阀是 focus_convergence
      // （连续无增益 / 预算耗尽 → 逼出结案），被无视时主循环代码兜底把任务强制标 blocked，
      // 焦点照常释放，不会永久死锁。
      return {
        task_id: String(forced.task_id),
        reason: "forced",
        detail: forced.note || `控制面强制焦点（${forced.kind || "forced"}）：这条任务不结案，其它打法一律拒收`,
        purpose: task.purpose,
        playbook: task.playbook,
        // SPA 缴械后唯一能出结论的是"能渲染/能执行"的特种兵：把转向提示带进焦点，
        // 否则 agent 继续对被锁任务打字典/裸 GET（会被缴械）或被拒收后不知所措。
        ...(forced.kind === "spa" ? {
          spaHint: `该焦点是 SPA 外壳逆向：必须用 browser.open（wait_until=networkidle）加载页面 + browser.network 取渲染期真实 XHR，或 exec.python 跑 SPA 抓取脚本（控制面已在 spa_mode.kit 给骨架）。不要对该任务用 recon.content_discovery / recon.nuclei / recon.api_routes（会被缴械拒收）；其它任务的请求会被焦点锁拒收，直到本任务结案（completed/blocked/failed），焦点才会释放并顺延到下一个任务。`,
        } : {}),
      };
    }
  }

  // ⓪ 排他任务先于一切：`exclusive_task` 在执行器（progress.begin）里是硬拒绝，
  //    焦点若还停在别的任务上，每一轮请求都会被 skip —— 2026-10-31 m.ctrip.com
  //    就是这么整场空转的（post_surface 排他 vs T_DICT_PROBE 焦点，16 条请求零执行）。
  //    把焦点对齐到排他任务，两个锁就变成同一把锁。
  const exclusiveId = String((state as { exclusive_task?: string }).exclusive_task || "");
  if (exclusiveId) {
    const task = byId.get(exclusiveId);
    if (task && !TERMINAL.has(String(task.status || ""))) {
      return {
        task_id: exclusiveId,
        reason: "exclusive",
        detail: `排他任务 ${exclusiveId} 生效：焦点自动对齐（否则请求会被执行器整批 skip）`,
        purpose: task.purpose,
        playbook: task.playbook,
      };
    }
  }

  // ① 建议让位：Observer 指着别的任务说"这里还缺证据"。
  //
  //    硬互锁（2026-11-02 规则审计）：`focusViolation` 拒收一切非焦点请求，而建议的 next_steps
  //    经常指向另一个任务。模型的合法选择只剩两个——拒绝一条有信息量的建议，或者被拒收 →
  //    miss → 判无进展 → 更快收口。两个都让 run 变差，所以焦点让位。
  //    门槛是"建议已被漏过一轮（misses >= 1）"：新建议第一次仍按原焦点办，不抖焦点；
  //    这样也把"没读建议"和"读了但干不了"分开——只有后者才触发让位。
  const stickyId = String((state as { focus_task_id?: string }).focus_task_id || "");
  const advised = adviceFocusTarget(state, byId, stickyId);
  if (advised) {
    return {
      task_id: advised.task_id,
      reason: "advice",
      detail: `Observer 建议 ${advised.advice_id} 指向这条任务且尚未处置：焦点让位给它，先执行或明确拒绝那条建议`,
      purpose: byId.get(advised.task_id)?.purpose,
      playbook: byId.get(advised.task_id)?.playbook,
    };
  }

  // ①-b 申诉让位：上一轮整批请求都挂在同一条任务上（连续两轮），焦点让位。
  //     只记账不切焦点曾经让 run 空转：实测会话 2b92c7fad2779398 连续三轮"拒收 5/3/4 个、
  //     放行 0 个"，全场只跑 3 次调用。焦点契约不该变成"模型永远不能改主意"。
  const appeal = (state as { focus_appeal?: { task_id?: string; votes?: number } }).focus_appeal;
  const appealTarget = String(appeal?.task_id || "");
  if (appealTarget && appealTarget !== stickyId && Number(appeal?.votes || 0) >= 2) {
    const task = byId.get(appealTarget);
    if (task && !TERMINAL.has(String(task.status || ""))) {
      return {
        task_id: appealTarget,
        reason: "appeal",
        detail: `连续 ${appeal?.votes} 轮整批请求都指向这条任务（此前焦点是 ${stickyId || "无"}）：焦点让位，别再互相拒收`,
        purpose: task.purpose,
        playbook: task.playbook,
      };
    }
  }

  // ② 粘性：上一轮的焦点还没结案就继续它（跨回合连贯性的来源）
  const sticky = stickyId;
  if (sticky) {
    const task = byId.get(sticky);
    if (task && !TERMINAL.has(String(task.status || ""))) {
      return {
        task_id: sticky,
        reason: "sticky",
        detail: `上一轮焦点未结案（${task.status || "pending"}），本轮继续`,
        purpose: task.purpose,
        playbook: task.playbook,
      };
    }
  }

  // ③ 已经启动但没结束的任务：running 优先于 pending
  const running = open.filter(([, task]) => String(task.status || "") === "running");
  if (running.length) {
    const [id, task] = running[0]!;
    return {
      task_id: id,
      reason: "running",
      detail: "本轮焦点：上一轮已启动但未结案的任务",
      purpose: task.purpose,
      playbook: task.playbook,
    };
  }

  // ③ 图距离最近的（离漏洞态 / 高危假设最近的那条路）
  const graph = graphState((state as { graph?: AttackGraphState }).graph);
  let nearest: { id: string; task: TaskLike; distance: number } | undefined;
  for (const [id, task] of open) {
    const distance = graphDistance(graph, task);
    if (distance === undefined) continue;
    if (!nearest || distance < nearest.distance) nearest = { id, task, distance };
  }
  if (nearest) {
    return {
      task_id: nearest.id,
      reason: "graph_nearest",
      detail: `本轮焦点：图距离 ${nearest.distance.toFixed(1)} 可推进到高价值目标（最短）`,
      distance: nearest.distance,
      purpose: nearest.task.purpose,
      playbook: nearest.task.playbook,
    };
  }

  // ④ FIFO：最早创建的那条（checkpoint 的插入顺序就是创建顺序）
  const [id, task] = open[0]!;
  return {
    task_id: id,
    reason: "fifo",
    detail: "本轮焦点：最早创建且未结案的任务（FIFO）",
    purpose: task.purpose,
    playbook: task.playbook,
  };
}

/** 写进 System Prompt 的绝对指令。 */
export function focusDirective(choice: FocusChoice, openCount: number): string {
  const others = Math.max(0, openCount - 1);
  // 让位过来的焦点要说清"为什么会跳"，否则模型会以为焦点随机漂移，又去投递原任务的请求。
  const handoff = choice.reason === "advice"
    ? "本轮焦点是**让位**过来的：Observer 有一条未处置建议指着这条任务。先把建议执行掉或明确拒绝，处置完焦点会自动回到原任务。"
    : choice.reason === "appeal"
    ? "本轮焦点是**申诉交接**过来的：你连续两轮把请求全投给了这条任务，控制面认可这个判断，把它提升为焦点。"
    : "";
  return [
    `【执行纪律】本轮你只能专注于 current_focus_task_id (${choice.task_id})。`,
    handoff,
    `你可以发起多个工具调用来推进这一个任务，但严禁在本轮发起与其他 ${others} 个 pending 任务相关的任何请求。`,
    `直到该任务变为 completed/failed/blocked，才能切换焦点。`,
    `所有 tool_requests[].task_id 必须是 ${choice.task_id}；控制面会把其它 task_id 的请求直接拒收并回一句"焦点锁定在 ${choice.task_id}"（整批全拒时控制面可能溢出放行 1-2 条，但那是兜底，不要把计划建立在溢出上）。`,
    choice.purpose ? `焦点任务的目的：${String(choice.purpose).slice(0, 200)}` : "",
  ].filter(Boolean).join("\n");
}

/**
 * 强制焦点是否已被"结案释放"：其锁定任务进入了终态（completed/blocked/failed）或已不存在。
 *
 * 这是释放的唯一条件——不靠轮数定时器。调用方（desk 主循环）据此清掉 state.forced_focus
 * 字段，避免留存误导（焦点已顺延到下一个任务）。computeFocus 因任务终态本就不再返回它，
 * 这里只是把过期的字段显式抹掉。
 */
export function forcedFocusReleased(state: RunCheckpoint): boolean {
  const ff = (state as { forced_focus?: { task_id?: string } }).forced_focus;
  if (!ff?.task_id) return false;
  const task = (state.tasks || {})[ff.task_id];
  return !task || TERMINAL.has(String(task.status || ""));
}

/** 上下文里给模型的焦点视图（tasks 之外的独立键，避免被裁掉）。 */
export function focusView(state: RunCheckpoint): Record<string, unknown> {
  const choice = computeFocus(state);
  const convergence = state.focus_convergence && state.focus_convergence.task_id === choice?.task_id
    ? state.focus_convergence
    : undefined;
  if (!choice) {
    return {
      current_focus_task_id: "",
      directive: state.macro_interrupt ? state.macro_interrupt.text : "当前没有未结案任务，可以规划新任务。",
    };
  }
  const openCount = openTasks(state).length;
  const usage = state.focus_usage?.task_id === choice.task_id ? state.focus_usage : undefined;
  return {
    current_focus_task_id: choice.task_id,
    reason: choice.reason,
    detail: choice.detail,
    ...(choice.distance !== undefined ? { distance: Math.round(choice.distance * 10) / 10 } : {}),
    ...(choice.purpose ? { purpose: String(choice.purpose).slice(0, 240) } : {}),
    ...(choice.playbook ? { playbook: choice.playbook } : {}),
    others_pending: openCount - 1,
    // 微观预算要让模型自己看得见：看不见消耗就会一直闷头打。
    ...(usage ? {
      budget: {
        turns: usage.turns,
        max_turns: usage.max_turns,
        // 预算按战术点数算：nuclei 5 TP 和 http 1 TP 不该同一个尺度。
        tp: usage.tp,
        max_tp: usage.max_tp,
        tool_calls: usage.tool_calls,
        no_progress_rounds: usage.no_progress_rounds,
        // 证据增益：只有 tier > 0 才算进展，10 条 404 不会让它涨。
        value_score: usage.value_score,
        high_value: usage.high_value,
        noise: usage.noise,
        appeals_used: usage.appeals_used,
      },
    } : {}),
    ...(convergence ? { convergence: { reason: convergence.reason, detail: convergence.detail, appealed: convergence.appealed === true } } : {}),
    // 指令优先级：宏观熔断 > 收口/申诉 > 常规纪律。多句并存模型会挑软的那句听。
    directive: state.macro_interrupt ? state.macro_interrupt.text : (convergence ? convergence.text : focusDirective(choice, openCount)),
  };
}

/**
 * 一条被拒请求的"下一步"建议（2026-11-05 加，改法 1）。
 *
 * 为什么不是"直接切焦点"：实测会话 51f8d006a7192f24 里，模型被拒后**不会**改主意，
 * 它会回到焦点任务把同一发再打一遍（T1 的 `/` 打了 7 次、burp.history 4 次）。
 * 只回一句"已拒收"等于什么都没说；每拒必切焦点又会让焦点抖动。
 * 折中：把另一个任务的 id/target 和两条合法出路摆到模型面前，让它选，焦点本身不动。
 */
export type FocusNextAction = {
  task_id: string;
  target?: string;
  instruction: string;
};

export type FocusRejection = {
  tool: string;
  task_id?: string;
  reason: string;
  next_action?: FocusNextAction;
};

/** 被拒任务的可读信息（desk 从 checkpoint 里取，focus 不依赖 progress）。 */
export type RejectedTaskInfo = { target?: string; purpose?: string; status?: string };

const TERMINAL_TASK = new Set(["completed", "blocked", "failed"]);

/** 一条工具请求是否违反焦点锁。返回拒绝文案或 undefined。 */
export function focusViolation(choice: FocusChoice | undefined, resolvedTaskId: string): string | undefined {
  if (!choice) return undefined;
  if (resolvedTaskId === choice.task_id) return undefined;
  const base = `焦点锁定在 ${choice.task_id}，请先完成它：本轮只允许推进这一个任务，其它任务的请求已拒收。`;
  // SPA 缴械后，agent 常因"该用 browser/exec 却拿不准"而继续对已锁任务打字典/裸 GET，
  // 或把其它任务的请求反复投递被全拒。把转向提示直接写进拒收文案，省一轮空转。
  return choice.spaHint ? `${base}\n${choice.spaHint}` : base;
}

/**
 * 批次准入：只放行焦点任务的请求。
 *
 * 放在调度器（desk）里而不是工具执行器里：执行器看到的是单条请求，不知道"本轮焦点"；
 * 而且被拒的请求不该进证据账本（它什么都没做），只该回一句能纠正模型的话。
 *
 * `taskOf` 是可选钩子：给了就能给每条拒收附上 `next_action`（改投建议）。不给则行为与旧版完全一致。
 */
export function applyFocusLock<T extends { task_id?: string; tool: string }>(
  choice: FocusChoice | undefined,
  requests: T[],
  resolveTaskId: (id: string) => string,
  taskOf?: (id: string) => RejectedTaskInfo | undefined,
): { allowed: T[]; rejected: FocusRejection[] } {
  if (!choice) return { allowed: requests, rejected: [] };
  const allowed: T[] = [];
  const rejected: FocusRejection[] = [];
  for (const request of requests) {
    const resolved = resolveTaskId(String(request.task_id || ""));
    const violation = focusViolation(choice, resolved);
    if (violation) {
      const info = resolved && resolved !== choice.task_id ? taskOf?.(resolved) : undefined;
      const usable = info && !TERMINAL_TASK.has(String(info.status || ""));
      rejected.push({
        tool: request.tool,
        task_id: request.task_id,
        reason: violation,
        ...(usable ? {
          next_action: {
            task_id: resolved,
            ...(info?.target ? { target: info.target } : {}),
            instruction: `当前焦点是 ${choice.task_id}${choice.purpose ? `（${String(choice.purpose).slice(0, 60)}）` : ""}，本条请求属于任务 ${resolved}${info?.target ? `（${info.target}）` : ""}。下一轮你有两个合法选择：① 若焦点任务确实还能推进（有新证据或新面），继续打它，并说明为什么它优先；② 若焦点任务已无新面（同形请求 ≥3 次、连续无新证据），先用 task_outcomes 给它下结论（completed/blocked/failed），焦点释放后立刻做 ${resolved}。不要原样重发这一批——那只会被同样的锁再拒一次。`,
          },
        } : {}),
      });
      continue;
    }
    // 别名请求要改写成焦点任务的真实 id，否则执行器按别名记账会落空。
    allowed.push(resolved === request.task_id ? request : { ...request, task_id: resolved });
  }
  return { allowed, rejected };
}

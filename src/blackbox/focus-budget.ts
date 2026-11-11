import type { RunCheckpoint } from "./progress.js";
import type { ValueScore } from "./evidence-value.js";

/**
 * 焦点微预算：单任务的"止损"机制。
 *
 * 焦点锁（focus.ts）解决的是"一轮只推一件事"，但它不解决"这件事推不动"。这里用三个可量化信号
 * 替代"人类卡住 30 分钟就换方向"的直觉：
 *
 *   ① 战术点数 TP：按执行成本算（nuclei 5+ / browser 4 / http 1），不再按调用次数
 *   ② 进展增益 value_score：只有 tier > 0 的证据才让计分上涨（10 条 404 = 0 分）
 *   ③ 连续无增益轮数：连续 N 轮 value_score 不动就判收益递减
 *
 * 触发后先发指令，模型不听下一轮由代码兜底判 blocked；临界信号（新身份/跳转/新假设）允许申诉 1 轮。
 * 全场景累计收口到达上限则熔断，交回人工。
 */

export type FocusUsage = {
  task_id: string;
  /** 在这条任务上花掉的轮数（每次请求准入算一轮）。 */
  turns: number;
  /** 这条任务上放行执行的工具调用次数（只做展示，预算按 TP 算）。 */
  tool_calls: number;
  /** 战术点数：按工具成本累加（见 tool-cost.ts）。 */
  tp: number;
  /** 证据增益累积分：只有 tier > 0 才算（见 evidence-value.ts）。 */
  value_score: number;
  /** 高/中/噪音证据计数（控制台展示）。 */
  high_value: number;
  medium_value: number;
  noise: number;
  /** 上一轮的 value_score，用来判断"这轮赚了没有"。 */
  last_value_score: number;
  /** 连续几轮 value_score 没有上涨。 */
  no_progress_rounds: number;
  /** 这条任务用掉过几次申诉（只做展示；额度是全局池）。 */
  appeals_used: number;
  /** 轮末的"临界信号"（申诉依据）。 */
  critical?: { identity?: string; redirect?: string; hypothesis?: string };
  /** 当前生效的硬上限，随 usage 落盘，上下文渲染时不需要再拿规则对象。 */
  max_turns: number;
  max_tp: number;
  /** 目标平均延迟（EWMA）：TP 通胀乘数的输入，见 tool-cost.ts。 */
  avg_latency_ms?: number;
};

export type FocusLimits = {
  max_turns_per_task: number;
  max_tp_per_task: number;
  stall_rounds: number;
  /** 整场会话共享的申诉池（不再按任务发）。 */
  appeal_pool: number;
  /** 允许申诉的势能门槛：任务的拓扑势能必须 <= 这个值（越小越接近目标）。 */
  appeal_potential_max: number;
  max_session_convergences: number;
};

export type Convergence = {
  task_id: string;
  reason: "focus_budget_exhausted" | "focus_stalled";
  /** 触发时的消耗描述（"8 轮 / 52 TP"或"连续 3 轮无增益"）。 */
  detail: string;
  text: string;
  rounds: number;
  tp: number;
  /** 已申诉过（下一轮不再宽限）。 */
  appealed?: boolean;
  at: number;
};

/** 会话级熔断：连续在多个任务上碰壁，说明目标选错或资产没攻击面。 */
export type MacroInterrupt = {
  count: number;
  limit: number;
  text: string;
  at: number;
};

/** WAF 绕过阶梯的档位数（① 编码 … ⑦ 负载夹带），见 rules.text["WAF 绕过"]。 */
export const LADDER_RUNGS = 7;

/**
 * 这条任务是不是"多档阶梯"打法，要跑几档。
 *
 * 冲突 3（2026-11-02 规则审计）：`rules.text["WAF 绕过"]` 写着"阶梯没跑满或没有对照不得把
 * 任务记为 blocked"，而单任务预算是 8 轮 / 50 TP——七档、每档 baseline+复刻+diff 至少要
 * 十五轮。两条规则互相拆台：模型跑不满阶梯就被 `focus_convergence` 强制收口，收口后又被
 * 提示词判成"不该 blocked"。所以预算必须按档位缩放，而不是让两条规则各自成立。
 */
export function ladderRungsOf(task?: { playbook?: string; purpose?: string; completion_criteria?: string }): number {
  if (!task) return 0;
  if (String(task.playbook || "") === "waf_bypass") return LADDER_RUNGS;
  const text = `${task.purpose || ""} ${task.completion_criteria || ""}`;
  return /waf|阶梯|绕过|拦截页|bypass/i.test(text) ? LADDER_RUNGS : 0;
}

/**
 * 按任务形态缩放微观预算。
 *
 * 缩放上限是 2 倍：阶梯确实更贵，但不能变成"WAF 任务可以无限打"——那只是把
 * "打不动也不收口"换了个名字。超出 2 倍仍由 focus_convergence 兜底。
 */
export function scaleLimitsForTask(
  limits: FocusLimits,
  task?: { playbook?: string; purpose?: string; completion_criteria?: string },
): FocusLimits {
  const rungs = ladderRungsOf(task);
  if (!rungs) return limits;
  const capped = (base: number, extra: number) => (base > 0 ? Math.min(base * 2, base + extra) : 0);
  return {
    ...limits,
    max_turns_per_task: capped(limits.max_turns_per_task, rungs),
    max_tp_per_task: capped(limits.max_tp_per_task, rungs * 2),
    // 同一档返回同一拦截指纹是阶梯的**正常中间态**（每一档都要留下否定证据），
    // 不该按"连续无增益"收口。放两轮给"取基线 + 复刻"。
    stall_rounds: limits.stall_rounds > 0 ? limits.stall_rounds + 2 : 0,
  };
}

export function emptyUsage(taskId: string, limits: FocusLimits): FocusUsage {
  return {
    task_id: taskId,
    turns: 0,
    tool_calls: 0,
    tp: 0,
    value_score: 0,
    high_value: 0,
    medium_value: 0,
    noise: 0,
    last_value_score: 0,
    no_progress_rounds: 0,
    appeals_used: 0,
    max_turns: limits.max_turns_per_task,
    max_tp: limits.max_tp_per_task,
  };
}

/**
 * 每轮准入时结算一次。
 *
 * 顺序：先看上一轮有没有赚分（value_score > last_value_score），再计入本轮。
 */
/**
 * 一轮焦点结算。
 *
 * `dispatched` = 本轮**实际派给该任务**的执行条数（含溢出放行）。不传视为"派过活"（兼容旧调用）。
 *
 * 2026-11-02 实跑（4f899c3af6c2ac84）暴露：forced 焦点任务（SPA 缴械造的 T_SPA_REVERSE）模型
 * 从没打过一次，`no_progress_rounds` 却按"每轮没涨分"累加，3 轮就把一个**从没被尝试过**的任务
 * 判成"收益递减"并强制 blocked——calls 停在 4/40。语义上这不该算收益递减：收益递减的前提是
 * 试过了没回报；没派过活是"焦点被无视"，交给让位/溢出/轮次上限处理。
 */
export function chargeFocusRound(
  state: RunCheckpoint,
  focusTaskId: string,
  limits: FocusLimits,
  dispatched = 1,
): { usage: FocusUsage; convergence?: Convergence } {
  const previous = state.focus_usage && state.focus_usage.task_id === focusTaskId ? state.focus_usage : undefined;
  const acted = dispatched > 0;
  const usage: FocusUsage = previous
    ? {
      ...previous,
      turns: previous.turns + 1,
      no_progress_rounds: !acted
        ? previous.no_progress_rounds
        : previous.value_score > previous.last_value_score ? 0 : previous.no_progress_rounds + 1,
      last_value_score: previous.value_score,
      max_turns: limits.max_turns_per_task,
      max_tp: limits.max_tp_per_task,
    }
    : { ...emptyUsage(focusTaskId, limits), turns: 1 };
  state.focus_usage = usage;

  // 0 = 不限
  if (limits.max_turns_per_task > 0 && usage.turns > limits.max_turns_per_task) {
    return { usage, convergence: convergenceFor(usage, "focus_budget_exhausted", `${usage.turns} 轮`) };
  }
  if (limits.max_tp_per_task > 0 && usage.tp >= limits.max_tp_per_task) {
    return { usage, convergence: convergenceFor(usage, "focus_budget_exhausted", `${usage.tp} TP`) };
  }
  if (limits.stall_rounds > 0 && usage.no_progress_rounds >= limits.stall_rounds) {
    return {
      usage,
      convergence: convergenceFor(usage, "focus_stalled", `连续 ${usage.no_progress_rounds} 轮没有高价值证据`, pendingIgnoredAdvice(state).map(a => a.id)),
    };
  }
  // 变更①：未处置的 Observer 建议被连续忽略，本身即"无进展"——提前一轮（stall_rounds-1）收口。
  // 仅当"既没进展、又无视建议"时触发：若 agent 真在涨分（value_score 上升），no_progress_rounds 归零，不会误伤。
  const ignored = pendingIgnoredAdvice(state);
  if (ignored.length > 0 && usage.no_progress_rounds >= Math.max(1, limits.stall_rounds - 1)) {
    return {
      usage,
      convergence: convergenceFor(usage, "focus_stalled",
        `连续 ${usage.no_progress_rounds} 轮无高价值证据，且手上有 ${ignored.length} 条未处置的 Observer 建议（${ignored.map(a => a.id).join("、")}）`,
        ignored.map(a => a.id)),
    };
  }
  return { usage };
}

/**
 * 批次准入前的 TP 预算检查：这批请求付得起吗？
 *
 * 返回 true 表示"付不起"——不执行，直接进收口。
 */
export function tpOverBudget(state: RunCheckpoint, taskId: string, batch: number, limits: FocusLimits): boolean {
  if (limits.max_tp_per_task <= 0) return false;
  const usage = state.focus_usage;
  if (!usage || usage.task_id !== taskId) return false;
  // 恰好打满也算超支：45 + nuclei(5) = 50 时不该再放行，否则"预算"就成了摆设。
  return usage.tp + batch >= limits.max_tp_per_task;
}

/** 记一批已放行请求的成本。 */
export function recordFocusCost(state: RunCheckpoint, taskId: string, input: { calls: number; tp: number }): void {
  const usage = state.focus_usage;
  if (!usage || usage.task_id !== taskId) return;
  usage.tool_calls += Math.max(0, input.calls);
  usage.tp += Math.max(0, input.tp);
}

/** 记一次工具结果的证据增益（只有 tier > 0 才涨分）。 */
export function recordFocusValue(state: RunCheckpoint, taskId: string, value: ValueScore): void {
  const usage = state.focus_usage;
  if (!usage || usage.task_id !== taskId) return;
  usage.high_value += value.high;
  usage.medium_value += value.medium;
  usage.noise += value.noise;
  usage.value_score += value.score;
  if (value.critical && (value.critical.identity || value.critical.redirect || value.critical.hypothesis)) {
    usage.critical = { ...(usage.critical || {}), ...value.critical };
  }
}

/** 全局申诉池余量（整场会话共享，见 rules.focus_lock.appeal_pool）。 */
export function appealPoolLeft(state: RunCheckpoint, limits: FocusLimits): number {
  const pool = state.usage?.session_appeals_pool;
  return Math.max(0, (pool === undefined ? limits.appeal_pool : pool));
}

/** 消耗一次全局申诉额度（返回是否成功）。 */
export function spendAppeal(state: RunCheckpoint, limits: FocusLimits): boolean {
  if (!state.usage) return false;
  const left = appealPoolLeft(state, limits);
  if (left <= 0) return false;
  state.usage.session_appeals_pool = left - 1;
  return true;
}

/**
 * 申诉资格：临界信号 × 价值门槛。
 *
 * 只在"这条任务真的接近核心"时才批：有身份的（拿到 Token 就能横向）、势能够低的（在通往高价值目标的
 * 关键跳板上）、或本轮已经拿到高价值证据的。边缘任务上的 Set-Cookie 不批——那只是又一个会话 Cookie。
 */
export function appealWorthy(input: { state: FocusCheckpointView; potential?: number; identity?: boolean }): { ok: boolean; why: string } {
  const usage = input.state.focus_usage;
  if (input.identity) return { ok: true, why: "已掌握身份凭证" };
  // 本轮直接拿到会话/身份（Set-Cookie 或 id: 节点）：这是可复用的战略资产。
  if (usage?.critical?.identity) return { ok: true, why: `本轮拿到身份线索（${usage.critical.identity}）` };
  if (input.potential !== undefined && input.potential <= input.state.appealPotentialMax) {
    return { ok: true, why: `拓扑势能 ${Math.round(input.potential * 10) / 10} ≤ ${input.state.appealPotentialMax}` };
  }
  if ((usage?.value_score || 0) >= 3) return { ok: true, why: `本轮已获高价值证据（增益 ${usage!.value_score}）` };
  return { ok: false, why: input.potential === undefined ? "这条任务离任何高价值目标都不可达" : `拓扑势能 ${Math.round(input.potential * 10) / 10} 过高，属于边缘探索` };
}

/** appealWorthy 只需要这几个字段，单独给它一个窄类型，避免把整个 checkpoint 传进来。 */
export type FocusCheckpointView = { focus_usage?: FocusUsage; appealPotentialMax: number };

/** 是否存在"临界突破信号"（只在这时允许申诉延期）。 */
export function criticalSignal(state: RunCheckpoint, taskId: string): string | undefined {
  const usage = state.focus_usage;
  if (!usage || usage.task_id !== taskId || !usage.critical) return undefined;
  const parts: string[] = [];
  if (usage.critical.identity) parts.push(`新身份 ${usage.critical.identity}`);
  if (usage.critical.redirect) parts.push(`跳转 ${usage.critical.redirect}`);
  if (usage.critical.hypothesis) parts.push(`新假设 ${usage.critical.hypothesis}`);
  return parts.length ? parts.join("、") : undefined;
}

/** 焦点任务结案或换焦点：清掉陈旧账。 */
export function resetFocusUsage(state: RunCheckpoint, keepTaskId = ""): void {
  if (keepTaskId && state.focus_usage?.task_id === keepTaskId) return;
  delete state.focus_usage;
}

/** 未处置且已被本轮漏掉的 Observer 建议（misses≥1 = 这一轮没在 advice_decisions 里认领）。 */
export function pendingIgnoredAdvice(state: RunCheckpoint): { id: string; misses: number }[] {
  const advice = (state as { advice?: Record<string, { status?: string; misses?: number }> }).advice || {};
  return Object.entries(advice)
    .filter(([, a]) => a.status === "pending" && (a.misses || 0) >= 1)
    .map(([id, a]) => ({ id, misses: a.misses || 0 }));
}

function convergenceFor(usage: FocusUsage, reason: Convergence["reason"], detail: string, adviceIds: string[] = []): Convergence {
  const target = usage.task_id;
  const verdict = reason === "focus_stalled"
    ? `你在 ${target} 上${detail}，也没有任何节点状态推进`
    : `你在 ${target} 上已消耗 ${detail}`;
  return {
    task_id: target,
    reason,
    detail,
    rounds: usage.turns,
    tp: usage.tp,
    at: Date.now(),
    // 焦点锁不靠轮数松手：必须真的对 ${target} 下结案 verdict，焦点才释放、才能切下一个任务。
    // 这逼 agent 在一条任务上挖透再判断，而不是浅尝辄止就散开——正是设焦点的初衷。
    text: [
      `【强制收口】${verdict} 且无实质进展。焦点锁不靠轮数松手——你必须对 ${target} 给出明确的结案 verdict，焦点才会释放、才能切下一个任务：`,
      ...(adviceIds.length
        ? [`本轮你手上有 ${adviceIds.length} 条未处置的 Observer 建议（${adviceIds.join("、")}）：要么用对应 tool_requests 执行其 next_steps，要么在 advice_decisions 里逐条拒绝并给理由。无视建议也算无进展，焦点不会因此释放。`]
        : []),
      `① 若已发现漏洞：在 findings 写一份 finding（引用证据 id），把 ${target} 写进 completed_tasks；`,
      // 负向结论必须进 completed：blocked 这条桶不跑结案审计、不进报告结论，
      // 实跑 b7142138263c586d 里模型把 15 条 404 指纹 + 4 组机器对照的 verified-negative
      // 写成了 blocked，整场 113 次调用最后报告里 0 条结论。
      `② 若确认无洞 / 无攻击面 / 目标是 catch-all 兜底这类**负向结论**：这是**结案，不是受阻**——把 ${target} 写进 completed_tasks，reason 以 "verified_negative:" 开头，写清"最后试了什么、跟什么对照、为什么走不通"，并在 evidence_ids 里点 ≥2 条互相印证的证据（必须包含用来对照的那一份）。`,
      `②b blocked_tasks / failed_tasks 只留给"缺凭证、缺权限、等外部回应"这类**真没做完**的情况，同样要在 reason 里点名引用已有证据 id；不要把负向结论塞进这两个数组。`,
      // 模型实测会照抄"在 task_outcomes 标 blocked"这种说法，但 task_outcomes 里根本没有 status 字段，
      // 写了会被 schema 静默丢掉（实跑 768287bceb5e2e01 就是这么白烧两轮的）。这里把口径钉死。
      `注意：状态只由 completed_tasks / blocked_tasks / failed_tasks 三个数组决定，task_outcomes 里没有 status 字段。`,
      `③ 交付物只有部分能兑现时：completed_tasks 照样能写，但要在该条 task_outcomes 的 deliverables_unmet 里逐条写 {"item": 哪一项, "reason": 为什么做不到}——如实申报会被记成"已验证的负向结论"并放行，不会被打回。`,
      `本轮不执行任何新工具请求；先出 verdict，下一轮焦点自动顺延到下一个未结案任务。`,
    ].join("\n"),
  };
}

/** 申诉宽限指令：只在临界信号 + 价值门槛都通过时发出，额度来自全局池。 */
export function appealText(usage: FocusUsage, signal: string, reason: Convergence["reason"], poolLeft = 0): string {
  return [
    `【预算警告】你在 ${usage.task_id} 上已达硬上限（${usage.turns} 轮 / ${usage.tp} TP）。`,
    `但系统检测到你刚拿到临界线索：${signal}，且这条任务在通往高价值目标的关键路径上。允许你额外执行 1 轮，专门用于验证该线索。`,
    `全局申诉池剩余 ${poolLeft} 次。如果本轮仍无高价值进展，将强制标记 blocked (原因: ${reason})。`,
  ].join("\n");
}

/** 会话级熔断指令：整体放弃常规探测，转人工/深交互。 */
export function macroInterruptText(count: number, limit: number): string {
  return [
    `【宏观战略调整】本场会话已在 ${count} 个任务上触发收口（阈值 ${limit}）。`,
    `当前资产可能存在很强的防御，或者没有有效攻击面。立即停止所有常规探测：`,
    `① 用 browser.open 做一次深度人工模拟交互（登录 → 关键业务流），观察有没有自动化看不到的入口；`,
    `② 或者直接产出一份"当前阻碍分析报告"（每个任务试过什么、被什么挡住、还缺什么前提），交给人工接手。`,
  ].join("\n");
}

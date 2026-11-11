/**
 * 焦点仲裁（2026-11-07，② 焦点死锁）。
 *
 * 现状的四个机制——强锁 / 饥饿接管 / 申诉 / 溢出——都基于同一批请求**各自独立改
 * `focus_task_id`、`focus_appeal`、`forced_focus`、interrupts**。对照会话里同一轮出现
 * focus-lock / focus-overflow / focus-appeal / focus-auto-handoff 四条互相矛盾的事件，
 * 9 个任务连续 29 轮 0 派发，强制焦点任务派单后立刻被作废。
 *
 * 这里把「谁有权改状态」收敛成一次决策，并把依据逐条写进日志。优先级是死的，
 * 但**每次决策都必须能回答谁赢、谁被谁压过**，否则又是一条没人看得懂的隐式规则。
 *
 * 注意职责边界：overflow 只改本轮放行集合，不改焦点状态，所以它可以和 winner 并存；
 * 真正互斥的是「写状态」的三类（强锁 / 接管 / 申诉）。
 */
import type { RunCheckpoint } from "./progress.js";
import { releaseFocus } from "./dispatcher.js";
import type { FocusChoice, FocusRejection } from "./focus.js";
import { STARVATION_ROUNDS } from "./task-starvation.js";

export type FocusMechanism = "strong_lock" | "starvation" | "appeal" | "overflow" | "advice" | "none";

/** 优先级从高到低，别在别处另写一份。 */
export const FOCUS_PRIORITY: Array<Exclude<FocusMechanism, "none">> = ["strong_lock", "starvation", "appeal", "overflow", "advice"];

export type FocusDecision = {
  mechanism: FocusMechanism;
  triggered: boolean;
  winner: boolean;
  /** 谁压过了它；未触发的机制记触发门槛没达到的原因。 */
  why: string;
  overridden_by?: FocusMechanism;
};

export type FocusArbitration = {
  winner: FocusMechanism;
  focus_task_id?: string;
  /** 状态写入类机制中，本轮唯一被允许执行的一个。 */
  state_writer: FocusMechanism;
  decisions: FocusDecision[];
  /** 直接可贴进事件正文的一行式摘要。 */
  summary: string;
};

const HARD_LOCK_KINDS = new Set(["spa", "sovereignty", "sovereignty_transfer", "dictionary"]);

/** SPA 缴械 / 主权转移这类硬锁：必须逆出结论才能放，不受零进展安全阀影响。 */
export function isHardFocusLock(state: RunCheckpoint): boolean {
  return HARD_LOCK_KINDS.has(String(state.forced_focus?.kind || ""));
}

export function arbitrateFocus(input: {
  state: RunCheckpoint;
  choice?: FocusChoice;
  requests: Array<{ task_id?: string }>;
  rejected: FocusRejection[];
  resolveTaskId?: (id: string) => string;
  overflowQuota: number;
  starvationRounds?: number;
}): FocusArbitration {
  const { state, choice, requests, rejected, overflowQuota } = input;
  const resolve = input.resolveTaskId || ((id: string) => id);
  const focusId = choice?.task_id;
  const dispatchedToFocus = requests.filter(request => resolve(String(request.task_id || "")) === focusId).length;
  const starvationThreshold = input.starvationRounds ?? STARVATION_ROUNDS;
  const maxStarved = Math.max(0, ...Object.values(state.task_starvation || {}).map(entry => Number(entry?.rounds || 0)));
  const appealVotes = Number(state.focus_appeal?.votes || 0);
  const fullyRejected = dispatchedToFocus === 0 && rejected.length > 0;
  const strongLock = choice?.reason === "forced" || choice?.reason === "exclusive";

  const triggers: Record<Exclude<FocusMechanism, "none">, { on: boolean; why: string }> = {
    strong_lock: {
      on: strongLock,
      why: strongLock ? `焦点 ${focusId} 来自 ${choice?.reason}（代码替模型做的决定）` : `焦点理由为 ${choice?.reason || "无"}，不是强锁`,
    },
    starvation: {
      on: maxStarved >= starvationThreshold && !isHardFocusLock(state),
      why: maxStarved >= starvationThreshold
        ? `最长饥饿 ${maxStarved} 轮 ≥ ${starvationThreshold}${isHardFocusLock(state) ? "，但硬锁豁免" : ""}`
        : `最长饥饿 ${maxStarved} 轮 < ${starvationThreshold}`,
    },
    appeal: {
      on: (fullyRejected || appealVotes >= 2) && Boolean(focusId),
      why: fullyRejected
        ? `焦点 ${focusId} 本轮 0 派发、拒收 ${rejected.length} 条`
        : appealVotes >= 2 ? `申诉票已累计 ${appealVotes}` : `焦点本轮 ${dispatchedToFocus} 条派发、申诉票 ${appealVotes}`,
    },
    overflow: {
      on: requests.length === 0 && rejected.length > 0 && overflowQuota > 0,
      why: requests.length === 0 && rejected.length > 0
        ? `整批 ${rejected.length} 条被拒，溢出配额 ${overflowQuota}`
        : `本轮放行 ${requests.length} 条，无需溢出`,
    },
    advice: {
      on: choice?.reason === "advice",
      why: choice?.reason === "advice" ? `Observer 未处置建议让位给 ${focusId}` : "本轮没有建议让位",
    },
  };

  const winner = FOCUS_PRIORITY.find(mechanism => triggers[mechanism].on) || "none";
  // overflow 只改放行集合；状态写入只能由强锁 / 接管 / 申诉三者之一执行。
  const stateWriter = (["strong_lock", "starvation", "appeal"] as Array<Exclude<FocusMechanism, "none">>)
    .find(mechanism => triggers[mechanism].on) || "none";
  const decisions: FocusDecision[] = FOCUS_PRIORITY.map(mechanism => {
    const entry = triggers[mechanism];
    const isWinner = mechanism === winner;
    const suppressed = entry.on && !isWinner && mechanism !== "overflow";
    return {
      mechanism,
      triggered: entry.on,
      winner: isWinner,
      why: entry.why,
      ...(suppressed ? { overridden_by: winner } : {}),
    };
  });
  const summary = decisions.filter(item => item.triggered)
    .map(item => `${item.mechanism}${item.winner ? "[胜出]" : item.overridden_by ? `[让位给 ${item.overridden_by}]` : "[并存]"}`)
    .join("、") || "无机制触发";
  return { winner, state_writer: stateWriter, focus_task_id: focusId, decisions, summary };
}

/**
 * 零进展释放：焦点连续 N 轮没有任何有增益的工具结果时，别让它把整场钉死。
 * 硬锁（SPA / 主权）豁免——那类任务本来就必须逆出结论，放早了等于撤掉设计。
 */
export function releaseFocusForNoProgress(
  state: RunCheckpoint,
  threshold = 4,
): { released: boolean; rounds: number; reason: string; task_id?: string } {
  const rounds = Number(state.focus_usage?.no_progress_rounds || 0);
  const taskId = String(state.forced_focus?.task_id || state.focus_task_id || "");
  if (rounds < threshold) return { released: false, rounds, reason: `no_progress ${rounds} < ${threshold}` };
  if (isHardFocusLock(state)) return { released: false, rounds, reason: "hard_lock_exempt", task_id: taskId || undefined };
  if (!state.forced_focus && !state.focus_task_id) return { released: false, rounds, reason: "no_active_lock" };
  const released = releaseFocus(state, state.forced_focus?.task_id);
  if (state.focus_task_id) delete state.focus_task_id;
  delete state.focus_appeal;
  return { released: released || Boolean(taskId), rounds, reason: "no_progress_release", task_id: taskId || undefined };
}

/**
 * 强制焦点任务被 hypothesis-tasks-pruned / 结案作废时，**同轮**顺延，
 * 不要等下一轮重抢（对照里「强制焦点任务派单后立刻被作废」就是漏在这里）。
 */
export function releaseFocusForPrunedTasks(state: RunCheckpoint, prunedIds: string[]): boolean {
  const locked = String(state.forced_focus?.task_id || "");
  const sticky = String(state.focus_task_id || "");
  if (!locked && !sticky) return false;
  if (!prunedIds.includes(locked) && !prunedIds.includes(sticky)) return false;
  releaseFocus(state, locked || undefined);
  if (sticky) delete state.focus_task_id;
  delete state.focus_appeal;
  return true;
}

/**
 * 工具超时 / 崩溃的异常路径也要释放锁，避免留下「锁在一条永远跑不完的任务上」的半状态。
 * 单次失败不释放（正常重试），连续失败到阈值才放。
 */
export function releaseFocusOnToolFailure(
  state: RunCheckpoint,
  taskId: string,
  failures: number,
  threshold = 2,
): { released: boolean; reason: string } {
  if (isHardFocusLock(state)) return { released: false, reason: "hard_lock_exempt" };
  const locked = String(state.forced_focus?.task_id || state.focus_task_id || "");
  if (!locked || locked !== taskId) return { released: false, reason: "not_focus_task" };
  if (failures < threshold) return { released: false, reason: `failures ${failures} < ${threshold}` };
  const released = releaseFocus(state, locked);
  if (state.focus_task_id === locked) delete state.focus_task_id;
  delete state.focus_appeal;
  return { released: released || true, reason: "tool_failure_release" };
}

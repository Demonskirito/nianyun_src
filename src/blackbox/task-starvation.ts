/**
 * 任务饥饿接管（2026-11-05，第 3 批后续：焦点锁的第二个洞）。
 *
 * 焦点锁只保证"一轮不散打"，代价是新任务可能永远排队。
 * 实测会话 `51f8d006a7192f24`：图里已经派生出 content_review 任务（target=/help/…），
 * 任务簿里两条 pending 全程没动，37 次请求一条都没落到它们头上——焦点被 sticky 钉在
 * 首页 T1，模型每轮都在首页重发同一发（`http.request|T1|/` 7 次、`burp.history|T1` 4 次）。
 *
 * 这里只做一件事：给每个非终态任务记"连续多少轮 0 派发"，到阈值就把焦点强制交给它。
 * 与"改投建议"（focus.ts 的 next_action）是配套的两层：
 *   改法 1 让模型**知道**有别的任务；这里保证模型**不听也不会饿死**。
 *
 * 为什么阈值是 5：2 轮太短（一次失败的探针就换焦点，模型更晕），10 轮太长（任务直接死）。
 * 5 轮约等于一个"焦点任务深挖 → 确认无进展"的完整周期。
 */
import type { RunCheckpoint } from "./progress.js";
import { lockFocus } from "./dispatcher.js";

export const STARVATION_ROUNDS = 5;

const TERMINAL = new Set(["completed", "blocked", "failed"]);

export type StarvationHandoff = {
  task_id: string;
  target?: string;
  rounds: number;
  previous_focus?: string;
};

/**
 * 记一轮饥饿账，必要时接管焦点。
 *
 * `dispatched` 是"本轮真正放行给各任务"的请求数（已过焦点锁与收口），
 * 不是模型发了多少条——被拒的请求什么都没做，不能算这个任务有进展。
 *
 * 返回 handoff 时，`state.forced_focus` 已被写成 `kind = "starvation"`，
 * 调用方只需负责事件与插话（措辞属于控制面，不属于记账）。
 */
export function noteStarvation(
  state: RunCheckpoint,
  dispatched: Map<string, number>,
  options: { rounds?: number; at?: number } = {},
): StarvationHandoff | undefined {
  const threshold = options.rounds ?? STARVATION_ROUNDS;
  const at = options.at ?? Date.now();
  const ledger = (state.task_starvation ||= {});

  for (const [id, task] of Object.entries(state.tasks || {})) {
    if (!task || typeof task !== "object" || id.startsWith("action:")) continue;
    if (TERMINAL.has(String(task.status || ""))) { delete ledger[id]; continue; }
    if ((dispatched.get(id) || 0) > 0) { delete ledger[id]; continue; }
    const record = ledger[id] || { rounds: 0, first_at: at };
    record.rounds += 1;
    record.last_at = at;
    ledger[id] = record;
  }
  // 已终态/已删除的任务不再占账，否则接管会指向一个不存在的 target。
  for (const id of Object.keys(ledger)) {
    const task = state.tasks[id];
    if (!task || TERMINAL.has(String(task.status || ""))) delete ledger[id];
  }

  const focusId = String(state.focus_task_id || "");
  const existing = state.forced_focus;
  // 更强的锁（主权转移 / SPA 缴械 / 字典探针）还没结案时不抢：抢了只会互相 skip。
  // 这里显式用 preempt:false 走 lockFocus 的 I3，而不是自己判一遍 kind——两套判断必然会分叉。
  if (existing?.task_id && existing.kind !== "starvation") return undefined;

  const [target, record] = Object.entries(ledger)
    .filter(([id, entry]) => id !== focusId && id !== existing?.task_id && entry.rounds >= threshold)
    .sort((a, b) => b[1].rounds - a[1].rounds)[0] || [];
  if (!target || !record) return undefined;

  const task = state.tasks[target];
  if (!task) return undefined;
  const targetUrl = task.target ? String(task.target) : undefined;
  const locked = lockFocus(state, {
    task_id: target,
    kind: "starvation",
    note: `任务 ${target}${targetUrl ? `（${targetUrl}）` : ""} 已连续 ${record.rounds} 轮没有拿到任何请求（焦点一直停在 ${focusId || "无"} 上），控制面已把焦点强制交给它：本轮只做它，直到 completed/blocked/failed。`,
    at,
  });
  // 写不进去（任务被并发结案 / 存在活锁）就不要清申诉票、不要报接管。
  if (!locked) return undefined;
  // 旧申诉票必须清掉：它记的是上一把锁的重心，留着会在新焦点上误触发让位。
  delete state.focus_appeal;
  delete ledger[target];
  return { task_id: target, target: targetUrl, rounds: record.rounds, previous_focus: focusId || undefined };
}

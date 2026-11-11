/**
 * 焦点状态的唯一写入口（2026-11-05，地基重构）。
 *
 * 为什么要有这个文件：`state.forced_focus` 原来被 7 处代码各自赋值——
 * site_declaration / sovereignty / spa / dict_probe / dict_expand / starvation / 零熵熔断——
 * 每处都自己判断"能不能抢"、自己拼 note、自己决定 at。
 * 结果是同一个字段有 7 套语义，出过一次真事故：
 *   `focus.ts` 的 forced 分支拒绝终态任务，但写入方没人检查，于是锁写进去却不生效，
 *   表现为"焦点钉在一个已结案的任务上，所有请求被拒收，整场 run 空转"。
 *
 * 这里的做法不是"再抽一层"，而是把三条不变量写成代码，让写不进去的锁**当场返回 false**：
 *   I1  任务必须存在        —— 否则 computeFocus 拿不到 task，锁静默失效
 *   I2  任务必须非终态      —— 否则锁永远不释放（释放条件只有"结案"）
 *   I3  同一时刻只有一个锁  —— 默认不抢占；要抢必须显式 preempt
 *
 * 优先级的取舍留在调用方（谁先谁后是业务判断），"能不能写"的判断只在这里。
 *
 * 关于"优先级 7 层压到 3 层"：先做了测量（11 场实盘、279 条焦点事件）。
 * forced 51 / sticky 39 / appeal 21 / exclusive 7 是真实流量；
 * graph_nearest 与 fifo 各 0 次，但它们是"没有任何焦点时"的兜底，删掉等于无焦点；
 * advice 0 次但被测试守着。所以层数不是问题，重复的写入点才是——先收敛这里。
 */
import type { RunCheckpoint } from "./progress.js";

const TERMINAL = new Set(["completed", "blocked", "failed"]);

/** 强制焦点的来源。新增来源必须在这里登记，避免第 8 套语义再散落出去。 */
export type FocusLockKind =
  | "sovereignty"   // 301/302 换了 host，必须去新目标
  | "spa"           // 步兵缴械，只能 browser/exec 逆外壳
  | "dict_probe"    // 字典聚类后的抽样代表
  | "dict_expand"   // 聚类展开后的下一批
  | "site_declaration" // robots/sitemap 还没终结
  | "starvation"    // 连续 N 轮 0 派发，防止饿死
  | "graph_drift"   // 图巡检判定分量漂移且建议多轮未被采纳
  | "post_surface"; // POST 面提权

export type FocusLockRequest = {
  task_id: string;
  kind: FocusLockKind;
  /** 写进上下文的说明：必须让模型知道"为什么现在只做这一条"。 */
  note: string;
  /** 覆盖更强的锁。只有"更强的证据出现"才该用，见各调用点的注释。 */
  preempt?: boolean;
  at?: number;
};

/** 当前锁是否仍然有效（任务存在且未结案）。 */
export function focusLockAlive(state: RunCheckpoint): boolean {
  const lock = state.forced_focus;
  if (!lock?.task_id) return false;
  const task = state.tasks?.[lock.task_id];
  return Boolean(task) && !TERMINAL.has(String(task!.status || ""));
}

/**
 * 上锁。返回 false 表示"没写"——调用方据此决定要不要发事件/插话，
 * 而不是像以前那样写完再看 computeFocus 有没有认。
 */
export function lockFocus(state: RunCheckpoint, request: FocusLockRequest): boolean {
  const taskId = String(request.task_id || "");
  if (!taskId) return false;
  // I1：任务必须存在
  const task = state.tasks?.[taskId];
  if (!task) return false;
  // I2：终态任务不能上锁，否则锁永远不释放
  if (TERMINAL.has(String(task.status || ""))) return false;
  // I3：单锁。已有别的活锁时默认不动（强锁优先）；要抢必须显式 preempt
  const current = state.forced_focus;
  if (current?.task_id && current.task_id !== taskId && focusLockAlive(state) && !request.preempt) return false;
  state.forced_focus = {
    task_id: taskId,
    kind: request.kind,
    at: request.at ?? Date.now(),
    note: request.note,
  };
  return true;
}

/**
 * 释放锁。唯一正当理由是"被锁任务进入终态"或"任务消失"，
 * 这正是 `forcedFocusReleased` 判的东西；这里额外提供按 taskId 定向释放，
 * 供引水收口这类"我知道这条线结束了"的场景用。
 */
export function releaseFocus(state: RunCheckpoint, taskId?: string): boolean {
  const current = state.forced_focus;
  if (!current) return false;
  if (taskId && current.task_id !== taskId) return false;
  delete state.forced_focus;
  return true;
}

/** 只有"被锁任务已结案/不存在"才释放——替代散落的 `forcedFocusReleased + delete` 组合。 */
export function releaseFocusIfReleased(state: RunCheckpoint): boolean {
  const lock = state.forced_focus;
  if (!lock?.task_id) return false;
  const task = state.tasks?.[lock.task_id];
  if (task && !TERMINAL.has(String(task.status || ""))) return false;
  delete state.forced_focus;
  return true;
}

/**
 * 系统守护任务的幂等槽位（2026-11-07）。
 *
 * `identity_wall_${timestamp}` / `lateral_escape_${timestamp}` 这类 id 每次撞墙都是新的：
 * 一旦 linkage 去重账被清掉（任务剪枝、resume、DLQ 清理），同一堵墙就会再派一条任务，
 * 任务簿满时直接变成又一条 task_backlog_full，而旧 pending 永远没人消化。
 *
 * 这里按 (kind, host) 找一个「还活着」的槽位复用；全终态时才开新一代（_rN），
 * 保证同一堵墙的一轮攻防里 id 稳定，墙真的复发也不会撞上终态任务被静默吞掉。
 */

export type GuardTaskKind = "identity_wall" | "lateral_escape";

export type GuardTaskSlot = {
  id: string;
  /** true = 复用已有 open 任务，调用方不应再 merge / 再落一次派发事件。 */
  reused: boolean;
  /** 同 host 已终态的守护任务数（新代次序号）。 */
  generation: number;
};

const TERMINAL = new Set(["completed", "blocked", "failed"]);

export function guardTaskSlot(
  tasks: Record<string, { status?: unknown; target?: unknown }> | undefined,
  kind: GuardTaskKind,
  host: string,
): GuardTaskSlot {
  const prefix = `${kind}_`;
  const targetHost = String(host || "").trim().toLowerCase();
  let open = "";
  let terminal = 0;
  for (const [id, task] of Object.entries(tasks || {})) {
    if (!id.startsWith(prefix)) continue;
    const target = String(task?.target || "").toLowerCase();
    // 同 host 才算同一堵墙；老 id 的 target 为空时保守算进来（宁可复用也别再开一条）。
    if (targetHost && target && !target.includes(targetHost)) continue;
    if (TERMINAL.has(String(task?.status || "").toLowerCase())) { terminal += 1; continue; }
    if (!open) open = id;
  }
  if (open) return { id: open, reused: true, generation: terminal };
  const slug = targetHost.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "host";
  return { id: `${prefix}${slug}${terminal ? `_r${terminal + 1}` : ""}`, reused: false, generation: terminal };
}

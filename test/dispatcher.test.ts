/**
 * 焦点锁的写入口不变量（2026-11-05）。
 *
 * 这批断言守的不是"功能"，而是三条曾经被违反过的不变量：
 *   I1 不存在的任务不能上锁     —— 锁写进去但 computeFocus 拿不到 task，表现为"没有焦点"
 *   I2 终态任务不能上锁         —— 锁永远不释放（释放条件只有结案），整场 run 空转
 *   I3 同一时刻只有一个强制焦点 —— 7 处代码各自覆盖，最后写的那处赢，与优先级设计无关
 *
 * 事故背景：`forced_focus` 原来在 desk.ts 有 6 处赋值、task-starvation.ts 有 1 处，
 * 每处自己判断"能不能抢"。会话 6ee79b87a797904f 就是 SPA 锁和一个已结案的任务互相
 * 覆盖，连续 4 轮 11 个请求零放行，40 次调用只用了 3 次。
 */
import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { computeFocus } from "../src/blackbox/focus.js";
import { focusLockAlive, lockFocus, releaseFocus, releaseFocusIfReleased } from "../src/blackbox/dispatcher.js";

function progressOf(specs: Array<{ id: string; status?: string; target?: string }>) {
  const progress = new BlackboxProgress();
  for (const spec of specs) {
    progress.state.tasks[spec.id] = { status: spec.status || "pending", target: spec.target, source: "graph" };
  }
  return progress;
}

describe("lockFocus 的不变量", () => {
  it("正常上锁，且 computeFocus 真的会认", () => {
    const progress = progressOf([{ id: "T1", target: "https://a.example/" }]);
    expect(lockFocus(progress.state, { task_id: "T1", kind: "spa", note: "逆外壳" })).toBe(true);
    expect(progress.state.forced_focus).toMatchObject({ task_id: "T1", kind: "spa", note: "逆外壳" });
    expect(computeFocus(progress.state)?.task_id).toBe("T1");
    expect(computeFocus(progress.state)?.reason).toBe("forced");
  });

  it("I1：任务不存在时不上锁（否则静默失锁）", () => {
    const progress = progressOf([{ id: "T1" }]);
    expect(lockFocus(progress.state, { task_id: "T_NOPE", kind: "spa", note: "x" })).toBe(false);
    expect(progress.state.forced_focus).toBeUndefined();
  });

  it("I2：终态任务不上锁（否则锁永远不释放）", () => {
    const progress = progressOf([{ id: "T1", status: "blocked" }]);
    expect(lockFocus(progress.state, { task_id: "T1", kind: "spa", note: "x" })).toBe(false);
    expect(progress.state.forced_focus).toBeUndefined();
    // 对照：写入成功但任务后来结案，锁会被 releaseFocusIfReleased 摘掉
    const live = progressOf([{ id: "T2" }]);
    lockFocus(live.state, { task_id: "T2", kind: "spa", note: "x" });
    live.state.tasks.T2 = { ...live.state.tasks.T2!, status: "completed" };
    expect(releaseFocusIfReleased(live.state)).toBe(true);
    expect(live.state.forced_focus).toBeUndefined();
  });

  it("I3：已有活锁时不抢，preempt 才覆盖", () => {
    const progress = progressOf([{ id: "T1" }, { id: "T2" }]);
    expect(lockFocus(progress.state, { task_id: "T1", kind: "spa", note: "先" })).toBe(true);
    expect(lockFocus(progress.state, { task_id: "T2", kind: "site_declaration", note: "后" })).toBe(false);
    expect(progress.state.forced_focus?.task_id).toBe("T1");
    expect(lockFocus(progress.state, { task_id: "T2", kind: "sovereignty", note: "抢", preempt: true })).toBe(true);
    expect(progress.state.forced_focus?.task_id).toBe("T2");
  });

  it("旧锁已结案时新锁可以直接上（不算抢占）", () => {
    const progress = progressOf([{ id: "T1", status: "completed" }, { id: "T2" }]);
    progress.state.forced_focus = { task_id: "T1", kind: "spa", at: Date.now(), note: "旧" };
    expect(focusLockAlive(progress.state)).toBe(false);
    expect(lockFocus(progress.state, { task_id: "T2", kind: "dict_probe", note: "新" })).toBe(true);
  });
});

describe("releaseFocus", () => {
  it("定向释放只认自己的 taskId", () => {
    const progress = progressOf([{ id: "T1" }, { id: "T2" }]);
    lockFocus(progress.state, { task_id: "T1", kind: "spa", note: "x" });
    expect(releaseFocus(progress.state, "T2")).toBe(false);
    expect(progress.state.forced_focus?.task_id).toBe("T1");
    expect(releaseFocus(progress.state, "T1")).toBe(true);
    expect(progress.state.forced_focus).toBeUndefined();
  });

  it("无锁时释放是空操作", () => {
    const progress = progressOf([{ id: "T1" }]);
    expect(releaseFocus(progress.state)).toBe(false);
    expect(releaseFocusIfReleased(progress.state)).toBe(false);
  });

  it("活锁不会被 releaseFocusIfReleased 摘掉", () => {
    const progress = progressOf([{ id: "T1" }]);
    lockFocus(progress.state, { task_id: "T1", kind: "spa", note: "x" });
    expect(releaseFocusIfReleased(progress.state)).toBe(false);
    expect(progress.state.forced_focus?.task_id).toBe("T1");
  });
});

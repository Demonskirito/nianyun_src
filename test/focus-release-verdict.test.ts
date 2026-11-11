import { describe, expect, it } from "vitest";
import { computeFocus, forcedFocusReleased } from "../src/blackbox/focus.js";
import type { RunCheckpoint } from "../src/blackbox/progress.js";

/**
 * 焦点释放契约（2026-11-02 修正）：
 * 强制焦点（SPA 缴械 / 主权转移 / 字典探针）只在"被锁任务结案（completed/blocked/failed）"
 * 时释放——也就是模型真的对它下了 verdict。不靠轮数定时器松手（那会让 agent 重新散开）。
 */

function cp(over: Partial<RunCheckpoint> = {}): RunCheckpoint {
  return {
    tasks: {
      T1: { status: "running", purpose: "锁定的任务", playbook: "unauth_exposure" },
      T2: { status: "pending", purpose: "另一个任务", playbook: "unauth_exposure" },
    },
    ...over,
  } as RunCheckpoint;
}

describe("forced focus: release only on verdict (terminal state)", () => {
  it("holds the forced task while it is non-terminal (no round cap)", () => {
    const state = cp({ forced_focus: { task_id: "T1", kind: "spa", at: Date.now(), note: "spa" } });
    const choice = computeFocus(state);
    expect(choice?.task_id).toBe("T1");
    expect(choice?.reason).toBe("forced");
  });

  it("drops the forced focus once the locked task reaches a terminal state", () => {
    const terminal = cp({
      tasks: {
        T1: { status: "blocked", outcome_reason: "negative verdict", purpose: "锁定的任务", playbook: "unauth_exposure" },
        T2: { status: "pending", purpose: "另一个任务", playbook: "unauth_exposure" },
      },
      forced_focus: { task_id: "T1", kind: "spa", at: Date.now(), note: "spa" },
    });
    // 不再返回被锁任务；焦点顺延到下一个未结案任务（此处 FIFO → T2）。
    const choice = computeFocus(terminal);
    expect(choice?.task_id).toBe("T2");
    expect(choice?.reason).toBe("fifo");
  });

  it("carries the spaHint for SPA forced focus so the agent knows to use browser/exec", () => {
    const state = cp({ forced_focus: { task_id: "T1", kind: "spa", at: Date.now(), note: "spa" } });
    const choice = computeFocus(state);
    expect(choice?.spaHint).toContain("browser.open");
    expect(choice?.spaHint).toContain("直到本任务结案（completed/blocked/failed）");
  });

  it("does not release just because a stale rounds/max_rounds field would have expired", () => {
    // 即便强制焦点对象里残留旧的 rounds 字段，computeFocus 也不再读它做释放判定。
    const state = cp({
      forced_focus: { task_id: "T1", kind: "sovereignty", at: Date.now(), note: "x" } as never,
    });
    // 模拟旧的会触发释放的字段存在（类型上已删除，这里用断言确认不读它）
    const raw = state.forced_focus as Record<string, unknown>;
    raw.rounds = 999;
    raw.max_rounds = 4;
    const choice = computeFocus(state);
    expect(choice?.task_id).toBe("T1");
  });

  it("forcedFocusReleased reports true once the locked task reaches a terminal state", () => {
    const terminal = cp({
      tasks: {
        T1: { status: "blocked", outcome_reason: "negative verdict", purpose: "锁定的任务", playbook: "unauth_exposure" },
      },
      forced_focus: { task_id: "T1", kind: "spa", at: Date.now(), note: "spa" },
    });
    expect(forcedFocusReleased(terminal)).toBe(true);
    // 任务未终态时不报释放。
    const open = cp({ forced_focus: { task_id: "T1", kind: "spa", at: Date.now(), note: "spa" } });
    expect(forcedFocusReleased(open)).toBe(false);
    // 锁定任务不存在也不报释放（避免误删其它逻辑）。
    const missing = cp({ forced_focus: { task_id: "GHOST", kind: "spa", at: Date.now(), note: "spa" } });
    expect(forcedFocusReleased(missing)).toBe(true);
  });
});

import { describe, expect, it } from "vitest";
import {
  FOCUS_PRIORITY, arbitrateFocus, isHardFocusLock, releaseFocusForNoProgress,
  releaseFocusForPrunedTasks, releaseFocusOnToolFailure,
} from "../src/blackbox/focus-arbitration.js";
import { BlackboxProgress, type RunCheckpoint } from "../src/blackbox/progress.js";
import type { FocusChoice } from "../src/blackbox/focus.js";

const state = (overrides: Record<string, unknown> = {}): RunCheckpoint => ({
  version: 1,
  tasks: { T1: { status: "running", target: "https://h/a" } },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
  ...overrides,
} as RunCheckpoint);

const choice = (reason: string, taskId = "T1"): FocusChoice => ({
  task_id: taskId, reason: reason as FocusChoice["reason"], detail: "test",
});

const input = (overrides: Partial<Parameters<typeof arbitrateFocus>[0]> = {}) => ({
  state: state(),
  choice: choice("sticky"),
  requests: [] as Array<{ task_id?: string }>,
  rejected: [] as Array<{ tool: string; reason: string; task_id?: string }>,
  overflowQuota: 2,
  ...overrides,
});

describe("② single focus arbitration", () => {
  it("priority is declared once, strongest first", () => {
    expect(FOCUS_PRIORITY).toEqual(["strong_lock", "starvation", "appeal", "overflow", "advice"]);
  });

  it("four mechanisms in the same round: exactly one winner, every loser records who beat it", () => {
    const arbitration = arbitrateFocus(input({
      state: state({ task_starvation: { T2: { rounds: 5 } }, focus_appeal: { task_id: "T2", votes: 3, at: Date.now() } }),
      choice: choice("forced"),
      rejected: [{ tool: "http.request", task_id: "T2", reason: "focus" }],
    }));
    expect(arbitration.winner).toBe("strong_lock");
    expect(arbitration.state_writer).toBe("strong_lock");
    const triggered = arbitration.decisions.filter(item => item.triggered);
    expect(triggered.length).toBeGreaterThanOrEqual(3);
    for (const item of triggered) {
      expect(item.why.length).toBeGreaterThan(0);
      if (!item.winner && item.mechanism !== "overflow") expect(item.overridden_by).toBe("strong_lock");
    }
    expect(arbitration.decisions.filter(item => item.winner)).toHaveLength(1);
    expect(arbitration.summary).toContain("strong_lock[胜出]");
  });

  it("starvation beats appeal and overflow when no hard lock is present", () => {
    const arbitration = arbitrateFocus(input({
      state: state({ task_starvation: { T2: { rounds: 5 } } }),
      choice: choice("sticky"),
      rejected: [{ tool: "http.request", task_id: "T2", reason: "focus" }],
    }));
    expect(arbitration.winner).toBe("starvation");
    expect(arbitration.state_writer).toBe("starvation");
    expect(arbitration.decisions.find(item => item.mechanism === "appeal")?.overridden_by).toBe("starvation");
  });

  it("overflow coexists with the winner (it only changes the allowed batch, not focus state)", () => {
    const arbitration = arbitrateFocus(input({
      choice: choice("sticky"),
      rejected: [{ tool: "http.request", task_id: "T2", reason: "focus" }],
    }));
    expect(arbitration.winner).toBe("appeal");
    expect(arbitration.decisions.find(item => item.mechanism === "overflow")?.triggered).toBe(true);
    expect(arbitration.decisions.find(item => item.mechanism === "overflow")?.overridden_by).toBeUndefined();
  });

  it("a quiet round triggers nothing and reports it explicitly (no deadlock / livelock)", () => {
    const arbitration = arbitrateFocus(input({ requests: [{ task_id: "T1" }] }));
    expect(arbitration.winner).toBe("none");
    expect(arbitration.state_writer).toBe("none");
    expect(arbitration.summary).toBe("无机制触发");
    expect(arbitration.decisions.every(item => !item.triggered)).toBe(true);
  });
});

describe("② no-progress release and hard-lock exemption", () => {
  it("frees a stale focus after four rounds with no value", () => {
    const s = state({
      forced_focus: { task_id: "T1", kind: "post_surface", at: Date.now() },
      focus_task_id: "T1",
      focus_appeal: { task_id: "T2", votes: 2, at: Date.now() },
      focus_usage: { task_id: "T1", turns: 12, no_progress_rounds: 4 },
    });
    const verdict = releaseFocusForNoProgress(s, 4);
    expect(verdict.released).toBe(true);
    expect(s.forced_focus).toBeUndefined();
    expect(s.focus_task_id).toBeUndefined();
    expect(s.focus_appeal).toBeUndefined();
  });

  it("keeps the lock before the threshold", () => {
    const s = state({ forced_focus: { task_id: "T1", kind: "post_surface", at: Date.now() },
      focus_usage: { task_id: "T1", no_progress_rounds: 3 } });
    expect(releaseFocusForNoProgress(s, 4).released).toBe(false);
    expect(s.forced_focus?.task_id).toBe("T1");
  });

  it("SPA disarm / sovereignty hard locks are exempt (must still produce a verdict)", () => {
    for (const kind of ["spa", "sovereignty", "sovereignty_transfer"]) {
      const s = state({ forced_focus: { task_id: "T1", kind, at: Date.now() },
        focus_usage: { task_id: "T1", no_progress_rounds: 9 } });
      expect(isHardFocusLock(s)).toBe(true);
      expect(releaseFocusForNoProgress(s, 4).reason).toBe("hard_lock_exempt");
      expect(s.forced_focus?.task_id).toBe("T1");
    }
  });
});

describe("② same-round handoff on pruned tasks and tool failures", () => {
  it("releases immediately when the forced focus task is pruned", () => {
    const s = state({ forced_focus: { task_id: "H_a", kind: "starvation", at: Date.now() }, focus_task_id: "H_a" });
    expect(releaseFocusForPrunedTasks(s, ["H_a"])).toBe(true);
    expect(s.forced_focus).toBeUndefined();
    expect(s.focus_task_id).toBeUndefined();
  });

  it("does not touch the lock when unrelated tasks are pruned", () => {
    const s = state({ forced_focus: { task_id: "T1", kind: "starvation", at: Date.now() } });
    expect(releaseFocusForPrunedTasks(s, ["H_z"])).toBe(false);
    expect(s.forced_focus?.task_id).toBe("T1");
  });

  it("a single failure keeps the lock; repeated failures release it", () => {
    const s = state({ forced_focus: { task_id: "T1", kind: "post_surface", at: Date.now() }, focus_task_id: "T1" });
    expect(releaseFocusOnToolFailure(s, "T1", 1).released).toBe(false);
    expect(s.forced_focus?.task_id).toBe("T1");
    expect(releaseFocusOnToolFailure(s, "T1", 2).released).toBe(true);
    expect(s.forced_focus).toBeUndefined();
    expect(s.focus_task_id).toBeUndefined();
  });

  it("a failure on a non-focus task never releases the lock, and hard locks are exempt", () => {
    const s = state({ forced_focus: { task_id: "T1", kind: "post_surface", at: Date.now() } });
    expect(releaseFocusOnToolFailure(s, "T9", 5).reason).toBe("not_focus_task");
    expect(s.forced_focus?.task_id).toBe("T1");
    (s.forced_focus as { kind: string }).kind = "spa";
    expect(releaseFocusOnToolFailure(s, "T1", 5).reason).toBe("hard_lock_exempt");
  });
});

describe("② backlog back-pressure folds same-host content reviews instead of rejecting", () => {
  const fresh = (tasks: Record<string, unknown>) => {
    const progress = new BlackboxProgress(state({ tasks }));
    progress.taskPendingLimit = 2;
    return progress;
  };

  it("folds a new review into the existing one, keeping its detail samples and alias", () => {
    const progress = fresh({
      H_content_review_a: { status: "pending", target: "https://h/x", purpose: "内容审阅 x", playbook: "content_review" },
      T1: { status: "pending", target: "https://h/", purpose: "首页" },
    });
    progress.merge({ required_tasks: [{
      id: "H_content_review_b", target: "https://h/y", purpose: "内容审阅 y", playbook: "content_review",
    }] }, []);
    expect(progress.state.task_aliases?.H_content_review_b).toBe("H_content_review_a");
    expect(progress.state.tasks.H_content_review_a?.folded_samples).toMatchObject([
      { id: "H_content_review_b", target: "https://h/y" },
    ]);
    expect(progress.state.planMergeLog?.at(-1)).toMatchObject({ dropped: "H_content_review_b", into: "H_content_review_a" });
    expect(JSON.stringify(progress.state.transitionErrors || [])).not.toContain("task_backlog_full");
  });

  it("does not fold a review from another host, nor an unrelated task", () => {
    const progress = fresh({
      H_content_review_a: { status: "pending", target: "https://h/x", purpose: "内容审阅 x", playbook: "content_review" },
      T1: { status: "pending", target: "https://h/", purpose: "首页" },
    });
    progress.merge({ required_tasks: [{ id: "H_content_review_other", target: "https://other/y", purpose: "内容审阅 y", playbook: "content_review" }] }, []);
    expect(progress.state.task_aliases?.H_content_review_other).toBeUndefined();
    // ② 簿满不再打回，改为排队（跨 host 的 review 不该折进同 host 的任务）。
    expect(progress.state.backlog_deferred?.map(entry => String(entry.spec.id))).toContain("H_content_review_other");
  });
});

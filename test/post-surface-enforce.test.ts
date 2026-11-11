import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";

const state = () => ({
  version: 1,
  tasks: {
    post_surface_1: { status: "pending" },
    T2: { status: "pending", playbook: "idor" },
    auth_login_1: { status: "pending", playbook: "auth_token" },
  },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
  linkage: { post_surface: { task_id: "post_surface_1", ignored_turns: 0 } },
});

const request = (taskId: string) => ({ task_id: taskId, tool: "http.request", reason: "x", input: { url: "https://h/api/x" } } as never);

describe("post_surface enforcement", () => {
  it("counts ignored turns and escalates on the second miss", () => {
    const progress = new BlackboxProgress(state());
    expect(progress.tickPostSurface(false).escalated).toBe(false);
    expect(progress.state.exclusive_task).toBeUndefined();
    const second = progress.tickPostSurface(false);
    expect(second.escalated).toBe(true);
    expect(progress.state.exclusive_task).toBe("post_surface_1");
    expect(progress.state.exclusive_reason?.ignored_turns).toBe(2);
    // 提权后任务仍是可执行状态，只是被标记
    expect(progress.state.tasks.post_surface_1?.reason).toBe("exclusive_until_done");
  });

  it("resets the counter as soon as the task gets work", () => {
    const progress = new BlackboxProgress(state());
    progress.tickPostSurface(false);
    expect(progress.tickPostSurface(true).ignored_turns).toBe(0);
    expect(progress.tickPostSurface(false).ignored_turns).toBe(1);
    expect(progress.state.exclusive_task).toBeUndefined();
  });

  it("blocks every other task while the exclusive lock is held, except the auth chain", () => {
    const progress = new BlackboxProgress(state());
    progress.tickPostSurface(false);
    progress.tickPostSurface(false);
    const other = progress.begin(request("T2"), "https://h/", 2, 2);
    expect(other.blocked).toBe("exclusive_task:post_surface_1");
    const auth = progress.begin(request("auth_login_1"), "https://h/", 2, 2);
    expect(auth.blocked).toBeUndefined();
    const exclusive = progress.begin(request("post_surface_1"), "https://h/", 2, 2);
    expect(exclusive.blocked).toBeUndefined();
  });

  it("a lock rejection does not terminalize the other task", () => {
    const progress = new BlackboxProgress(state());
    progress.tickPostSurface(false);
    progress.tickPostSurface(false);
    expect(progress.begin(request("T2"), "https://h/", 2, 2).blocked).toBe("exclusive_task:post_surface_1");
    expect(progress.state.tasks.T2?.status).toBe("pending");
    progress.state.tasks.post_surface_1 = { status: "completed" };
    const started = progress.begin(request("post_surface_1"), "https://h/", 2, 2);
    progress.finish(request("post_surface_1"), started.key, { ok: true, data: {} } as never, 2);
    expect(progress.state.exclusive_task).toBeUndefined();
    expect(progress.begin(request("T2"), "https://h/", 2, 2).blocked).toBeUndefined();
  });
  it("releases the lock when the exclusive task reaches a terminal state", () => {
    const progress = new BlackboxProgress(state());
    progress.tickPostSurface(false);
    progress.tickPostSurface(false);
    const started = progress.begin(request("post_surface_1"), "https://h/", 2, 2);
    progress.state.tasks.post_surface_1 = { status: "completed" };
    progress.finish(request("post_surface_1"), started.key, { ok: true, data: {} } as never, 2);
    expect(progress.state.exclusive_task).toBeUndefined();
    expect(progress.state.exclusive_reason).toBeUndefined();
  });
});
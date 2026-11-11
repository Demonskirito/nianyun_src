import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { guardTaskSlot } from "../src/blackbox/guard-tasks.js";

const HOST = "developer.aliyun.com";
const TARGET = `https://${HOST}/`;

describe("guard task slots (no timestamp ids)", () => {
  it("is stable, reuses an open task, and opens a new generation only after terminal", () => {
    const tasks: Record<string, { status: string; target: string }> = {};
    const first = guardTaskSlot(tasks, "identity_wall", HOST);
    expect(first.id).toBe("identity_wall_developer_aliyun_com");
    expect(first.reused).toBe(false);

    tasks[first.id] = { status: "pending", target: TARGET };
    const second = guardTaskSlot(tasks, "identity_wall", HOST);
    expect(second).toMatchObject({ id: first.id, reused: true });

    tasks[first.id]!.status = "completed";
    const third = guardTaskSlot(tasks, "identity_wall", HOST);
    expect(third).toMatchObject({ id: "identity_wall_developer_aliyun_com_r2", reused: false, generation: 1 });
  });

  it("reuses legacy timestamp ids from existing checkpoints", () => {
    const tasks = { identity_wall_20261107065139: { status: "pending", target: TARGET } };
    expect(guardTaskSlot(tasks, "identity_wall", HOST)).toMatchObject({
      id: "identity_wall_20261107065139", reused: true,
    });
  });

  it("does not confuse walls on different hosts or different kinds", () => {
    const tasks = {
      identity_wall_other_example_com: { status: "pending", target: "https://other.example.com/" },
      lateral_escape_developer_aliyun_com: { status: "pending", target: TARGET },
    };
    expect(guardTaskSlot(tasks, "identity_wall", HOST).reused).toBe(false);
    expect(guardTaskSlot(tasks, "lateral_escape", HOST).reused).toBe(true);
  });
});

describe("backlog backpressure: queue instead of reject", () => {
  it("clears stale task_backlog_full errors and queues a full-backlog declaration", () => {
    const p = new BlackboxProgress();
    p.taskPendingLimit = 2;
    p.state.tasks.t1 = { status: "pending", target: TARGET };
    p.state.tasks.t2 = { status: "pending", target: TARGET };
    p.state.transitionErrors = ["task_backlog_full:9/8", "task_backlog_full:8/8"];
    p.state.validationErrors = ["task_backlog_full:9/8", "task_backlog_full:8/8"];

    p.merge({ required_tasks: [{ id: "t3", target: `${TARGET}x`, purpose: "probe x", playbook: "idor" }] });

    // 旧账一次性清干净：否则每轮 transition-rejected 都在重播两小时前的错误。
    expect(p.state.transitionErrors).toEqual([]);
    expect(p.state.validationErrors).toEqual([]);
    expect(p.state.backlog_deferred?.map(entry => entry.spec.id)).toEqual(["t3"]);
    expect(p.state.backlog_deferred_seq).toBe(1);
    expect(p.state.tasks.t3).toBeUndefined();
    expect(p.state.backlog_rejects?.at(-1)).toMatchObject({ task_id: "t3", deferred: true });
  });

  it("does not duplicate a re-declared task and drains FIFO when a slot frees", () => {
    const p = new BlackboxProgress();
    p.taskPendingLimit = 2;
    p.state.tasks.t1 = { status: "pending", target: TARGET };
    p.state.tasks.t2 = { status: "pending", target: TARGET };
    const spec = { id: "t3", target: `${TARGET}x`, purpose: "probe x", playbook: "idor" };
    p.merge({ required_tasks: [spec] });
    p.merge({ required_tasks: [spec] });
    expect(p.state.backlog_deferred?.length).toBe(1);
    expect(p.state.backlog_deferred?.[0]!.attempts).toBe(2);

    p.state.tasks.t1!.status = "completed";
    p.merge({});
    expect(p.state.tasks.t3).toBeDefined();
    expect(p.state.backlog_deferred?.length).toBe(0);
    expect(p.state.planMergeLog?.some(entry => entry.fields.includes("backlog_deferred_admitted"))).toBe(true);
  });

  it("folds only whitelisted playbooks on the same host and playbook", () => {
    const p = new BlackboxProgress();
    p.taskPendingLimit = 1;
    p.state.tasks.r1 = { status: "pending", target: `${TARGET}p1`, purpose: "审阅第一页正文", playbook: "content_review" };
    p.merge({ required_tasks: [{ id: "r2", target: `${TARGET}p2`, purpose: "审阅第二页正文", playbook: "content_review" }] });
    expect(p.state.task_aliases?.r2).toBe("r1");
    expect(Object.keys(p.state.tasks)).toEqual(["r1"]);

    const q = new BlackboxProgress();
    q.taskPendingLimit = 1;
    q.state.tasks.i1 = { status: "pending", target: `${TARGET}p1`, purpose: "越权对象 A", playbook: "idor" };
    q.merge({ required_tasks: [{ id: "i2", target: `${TARGET}p2`, purpose: "越权对象 B", playbook: "idor" }] });
    // idor 不可合并：既不折进 i1，也不新增 pending，而是排队。
    expect(q.state.backlog_deferred?.length).toBe(1);
    expect(q.state.tasks.i2).toBeUndefined();
  });
});

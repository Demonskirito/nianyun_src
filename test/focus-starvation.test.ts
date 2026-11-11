/**
 * 焦点锁的两个洞（2026-11-05 第 3 批后续）。
 *
 * 实盘会话 `51f8d006a7192f24`：假设 3 条、任务 2 条（target 都指向 /help 业务页），
 * 37 次请求**一条都没派给它们**。事件流里 focus-lock 原文是
 *   "焦点锁定在 T1：拒收 1 个其它任务的请求，放行 2 个"
 * ——部分拒收，模型既看不到"另一条任务叫什么"，也没有任何机制在它不听时强制换焦点。
 * 于是它回到 T1 打同一发（`http.request|T1|/` 7 次），两轮 zero-action-round。
 *
 * 这里锁三件事：
 *   1. `hits` 只记"真的拿到过响应"——发现类（requested:false）永远是 0；
 *   2. 拒收结果必须带"改投建议"（id + target + 两条合法出路），不是只说"拒了"；
 *   3. 连续 5 轮 0 派发的任务由控制面强制接管焦点，且不抢更强的锁。
 */
import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { applyFocusLock, computeFocus } from "../src/blackbox/focus.js";
import { graphState, ingestToolResult } from "../src/blackbox/graph/builder.js";
import { noteStarvation, STARVATION_ROUNDS } from "../src/blackbox/task-starvation.js";

const HOST = "wanxiaozhi.aliyun.com";

function declare(page: string, requested?: boolean) {
  const state = graphState(undefined);
  ingestToolResult(state, {
    tool: "http.request",
    endpoints: [{ url: `https://${HOST}${page}`, origin: "link", source: "sitemap", ...(requested === undefined ? {} : { requested }) }],
  });
  return state;
}

describe("hits 只记真实响应", () => {
  it("sitemap 发现（requested 未置）不产生 hits", () => {
    const state = declare("/help/3039522.html");
    const node = state.nodes[`ep:${HOST}/help/3039522.html`];
    expect(node?.status).toBe("untested");
    expect(node?.properties.hits ?? 0).toBe(0);
  });

  it("显式 requested:false 同样不产生 hits", () => {
    const state = declare("/help/1.html", false);
    expect(state.nodes[`ep:${HOST}/help/1.html`]?.properties.hits ?? 0).toBe(0);
  });

  it("真打一次才 +1，之后的发现不会把它抬高", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: `https://${HOST}/help/2.html`, origin: "request", requested: true, status_code: 200 }],
    });
    expect(state.nodes[`ep:${HOST}/help/2.html`]?.properties.hits).toBe(1);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: `https://${HOST}/help/2.html`, origin: "link", source: "sitemap", requested: false }],
    });
    expect(state.nodes[`ep:${HOST}/help/2.html`]?.properties.hits).toBe(1);
  });

  it("发现类节点上的历史脏 hits 会被抹平（origin 只升不降，仍是 discovery 说明从没打过）", () => {
    const state = declare("/help/3.html");
    const id = `ep:${HOST}/help/3.html`;
    state.nodes[id]!.properties.hits = 3;
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: `https://${HOST}/help/3.html`, origin: "link", source: "sitemap", requested: false }],
    });
    expect(state.nodes[id]?.properties.hits).toBe(0);
  });
});

describe("拒收带改投建议", () => {
  const choice = { task_id: "T1", reason: "sticky" as const, detail: "继续首页", purpose: "SPA 首页逆向" };
  const tasks: Record<string, { target?: string; status?: string }> = {
    T1: { target: "https://a.example/", status: "pending" },
    T_REVIEW_3: { target: "https://a.example/help/3039522.html", status: "pending" },
  };

  it("被拒的非焦点请求带上目标任务的 id 与 target", () => {
    const result = applyFocusLock(
      choice,
      [{ tool: "http.request", task_id: "T_REVIEW_3" }],
      id => id,
      id => tasks[id],
    );
    expect(result.rejected).toHaveLength(1);
    const action = result.rejected[0]!.next_action;
    expect(action?.task_id).toBe("T_REVIEW_3");
    expect(action?.target).toContain("/help/3039522.html");
    // 两条合法出路都要写出来：要么说明焦点为何优先，要么先结案再转
    expect(action?.instruction).toContain("task_outcomes");
    expect(action?.instruction).toContain("不要原样重发");
  });

  it("目标任务已终态时不给改投建议（否则是在指挥模型去打一个已收口的任务）", () => {
    const result = applyFocusLock(
      choice,
      [{ tool: "http.request", task_id: "T_REVIEW_3" }],
      id => id,
      id => ({ ...tasks[id], status: "blocked" }),
    );
    expect(result.rejected[0]!.next_action).toBeUndefined();
  });

  it("不给 taskOf 时行为与旧版一致（向后兼容）", () => {
    const result = applyFocusLock(choice, [{ tool: "http.request", task_id: "T_REVIEW_3" }], id => id);
    expect(result.rejected[0]!.next_action).toBeUndefined();
    expect(result.rejected[0]!.reason).toContain("焦点锁定在 T1");
  });
});

function progressWithTasks(specs: Array<{ id: string; target?: string; status?: string }>) {
  const progress = new BlackboxProgress();
  for (const spec of specs) {
    progress.state.tasks[spec.id] = { status: spec.status || "pending", target: spec.target, source: "graph" };
  }
  return progress;
}

describe("任务饥饿接管", () => {
  const none = new Map<string, number>();

  it("焦点有活、另一条连续 5 轮 0 派发 → 强制切焦点给它", () => {
    const progress = progressWithTasks([
      { id: "T1", target: `https://${HOST}/` },
      { id: "T_REVIEW_3", target: `https://${HOST}/help/1.html` },
    ]);
    progress.state.focus_task_id = "T1";
    let handoff;
    for (let round = 0; round < STARVATION_ROUNDS; round += 1) {
      handoff = noteStarvation(progress.state, new Map([["T1", 2]]));
    }
    expect(handoff?.task_id).toBe("T_REVIEW_3");
    expect(progress.state.forced_focus?.kind).toBe("starvation");
    expect(progress.state.forced_focus?.note).toContain("5 轮");
    // 下一轮 computeFocus 真的会把它当焦点（不是只写了个字段没人读）
    expect(computeFocus(progress.state)?.task_id).toBe("T_REVIEW_3");
    expect(computeFocus(progress.state)?.reason).toBe("forced");
  });

  it("4 轮还不接管（阈值不能太短，否则焦点抖动）", () => {
    const progress = progressWithTasks([
      { id: "T1", target: `https://${HOST}/` },
      { id: "T_REVIEW_3", target: `https://${HOST}/help/1.html` },
    ]);
    progress.state.focus_task_id = "T1";
    for (let round = 0; round < STARVATION_ROUNDS - 1; round += 1) {
      expect(noteStarvation(progress.state, new Map([["T1", 1]]))).toBeUndefined();
    }
    expect(progress.state.forced_focus).toBeUndefined();
  });

  it("拿到一次派发就清零，不需要连续", () => {
    const progress = progressWithTasks([
      { id: "T1", target: `https://${HOST}/` },
      { id: "T_REVIEW_3", target: `https://${HOST}/help/1.html` },
    ]);
    progress.state.focus_task_id = "T1";
    for (let round = 0; round < STARVATION_ROUNDS - 1; round += 1) noteStarvation(progress.state, new Map([["T1", 1]]));
    expect(noteStarvation(progress.state, new Map([["T1", 1], ["T_REVIEW_3", 1]]))).toBeUndefined();
    expect(progress.state.task_starvation?.T_REVIEW_3).toBeUndefined();
    expect(noteStarvation(progress.state, new Map([["T1", 1]]))).toBeUndefined();
  });

  it("更强的锁（主权转移/SPA）还在时不去抢", () => {
    const progress = progressWithTasks([
      { id: "T1", target: `https://${HOST}/` },
      { id: "T_SPA_REVERSE", target: `https://${HOST}/` },
      { id: "T_REVIEW_3", target: `https://${HOST}/help/1.html` },
    ]);
    progress.state.focus_task_id = "T1";
    progress.state.forced_focus = { task_id: "T_SPA_REVERSE", kind: "spa", at: Date.now() };
    for (let round = 0; round < 6; round += 1) {
      expect(noteStarvation(progress.state, new Map([["T1", 1]]))).toBeUndefined();
    }
    expect(progress.state.forced_focus?.task_id).toBe("T_SPA_REVERSE");
  });

  it("结案的任务不再占账，也不会被接管", () => {
    const progress = progressWithTasks([
      { id: "T1", target: `https://${HOST}/` },
      { id: "T_REVIEW_3", target: `https://${HOST}/help/1.html`, status: "completed" },
    ]);
    progress.state.focus_task_id = "T1";
    for (let round = 0; round < 6; round += 1) {
      expect(noteStarvation(progress.state, new Map([["T1", 1]]))).toBeUndefined();
    }
    expect(progress.state.task_starvation?.T_REVIEW_3).toBeUndefined();
  });
});

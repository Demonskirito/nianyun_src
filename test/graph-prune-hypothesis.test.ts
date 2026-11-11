/**
 * 裁剪保护正在挖的节点（2026-11-04）。
 *
 * `MAX_NODES=500`，而 d8f8350 会话已经到 461 —— 再跑几轮就会触发裁剪。
 * 原 rank 只按节点状态打分：`untested`(30) 低于 `blocked`(40)，
 * 而 `untested` 恰恰是"还没打但已经被假设盯上"的那批，超限时先被淘汰。
 * 节点一删，`isDependencyInvalidated` 立刻判依赖失效，假设跟着归档：
 * 一次裁剪把正在挖的东西连根拔掉，而且看起来像"假设自己失效"。
 */
import { describe, expect, it } from "vitest";
import { graphState, prune } from "../src/blackbox/graph/builder.js";
import type { GraphNode, Hypothesis } from "../src/blackbox/graph/types.js";

function node(id: string, updatedAt: number): GraphNode {
  return { id, type: "endpoint", status: "untested", properties: {}, discovered_by: "t", updated_at: updatedAt };
}

function hypothesis(id: string, nodes: string[], status?: Hypothesis["status"]): Hypothesis {
  return { id, kind: "idor", text: "", nodes, severity: "high", created_at: 1, ...(status ? { status } : {}) };
}

function build(refs: Array<{ id: string; status?: Hypothesis["status"] }>) {
  const state = graphState(undefined);
  state.nodes["ep:a.test/"] = node("ep:a.test/", 1);
  state.nodes["ep:b.test/"] = node("ep:b.test/", 2);
  state.nodes["ep:c.test/"] = node("ep:c.test/", 3);
  state.hypotheses = refs.map((ref, index) => hypothesis(`h${index}`, [ref.id], ref.status));
  return state;
}

describe("prune：被活跃假设引用的节点不参与淘汰", () => {
  it("超限时删的是没被引用的那个，而不是最老的被引用节点", () => {
    // a 最老（本会被删），但被 active 假设盯着 → 留下；b 顶上。
    const state = build([{ id: "ep:a.test/", status: "active" }]);
    expect(prune(state, 2)).toBe(1);
    expect(state.nodes["ep:a.test/"]).toBeTruthy();
    expect(state.nodes["ep:b.test/"]).toBeUndefined();
    expect(state.nodes["ep:c.test/"]).toBeTruthy();
  });

  it("冷宫（evicted）里的引用同样保护（还会被复活）", () => {
    const state = build([{ id: "ep:a.test/", status: "evicted" }]);
    prune(state, 2);
    expect(state.nodes["ep:a.test/"]).toBeTruthy();
  });

  it("已归档的假设不再保护（收口的就该让位）", () => {
    const state = build([{ id: "ep:a.test/", status: "archived" }]);
    prune(state, 2);
    expect(state.nodes["ep:a.test/"]).toBeUndefined();
  });

  it("缺 status 的老 checkpoint 按 active 处理（保守）", () => {
    const state = build([{ id: "ep:a.test/" }]);
    prune(state, 2);
    expect(state.nodes["ep:a.test/"]).toBeTruthy();
  });

  it("没超限时一个都不删", () => {
    const state = build([{ id: "ep:a.test/", status: "active" }]);
    expect(prune(state, 10)).toBe(0);
    expect(Object.keys(state.nodes)).toHaveLength(3);
  });

  it("全部被引用时仍要能收敛（不能因为保护而卡在上限之上）", () => {
    const state = graphState(undefined);
    state.nodes["ep:a.test/"] = node("ep:a.test/", 1);
    state.nodes["ep:b.test/"] = node("ep:b.test/", 2);
    state.hypotheses = [
      hypothesis("h1", ["ep:a.test/"], "active"),
      hypothesis("h2", ["ep:b.test/"], "active"),
    ];
    expect(prune(state, 1)).toBe(1);
    expect(Object.keys(state.nodes)).toHaveLength(1);
  });
});

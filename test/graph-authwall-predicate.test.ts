/**
 * auth_wall 的收口判据（2026-11-04）。
 *
 * 两处误杀，都由"用瞬时状态/端点级计数判断假设价值"引起：
 *
 * ① 谓词误杀：auth_wall 的有效期取决于"墙还在不在"。若拿 `status === "blocked"`
 *    当判据，节点在重打过程中迁移到 `testing` 就会把假设自己归档——任务还在办，
 *    假设已埋。正确信号是 `blocked_streak`（只在拿到 <400 时清零，见 builder.ts:456）。
 *
 * ② 计数污染：`noteHypothesisAttempt` 按端点记账，同端点上的 idor 对照与匿名探测
 *    会把 auth_wall 打到 unreachable。实测 53a9ff8fca15e361：两条 auth_wall 的
 *    attempts=3、判 unreachable，锚点 blocked_streak 却是 16 / 5——账记错了对象。
 */
import { describe, expect, it } from "vitest";
import {
  activeHypotheses, graphState, identityNodeId, noteHypothesisAttempt, wallStillStands,
} from "../src/blackbox/graph/index.js";
import type { GraphNode, Hypothesis } from "../src/blackbox/graph/types.js";

const EP = "ep:t.example/api/admin";

function node(patch: Partial<GraphNode> & { properties?: Record<string, unknown> } = {}): GraphNode {
  return {
    id: EP,
    type: "endpoint",
    status: "blocked",
    properties: { status_code: 403, blocked_streak: 2, ...(patch.properties || {}) },
    discovered_by: "ev-test",
    round: 1,
    depth: 1,
    updated_at: 1,
    ...patch,
  } as GraphNode;
}

function stateWith(anchor: GraphNode | undefined, extra: Hypothesis[] = []) {
  const state = graphState(undefined);
  state.nodes["id:user_a"] = {
    id: identityNodeId("user_a"), type: "identity", status: "testing",
    properties: { role: "user_a" }, discovered_by: "ev-test", updated_at: 1,
  } as GraphNode;
  if (anchor) state.nodes[anchor.id] = anchor;
  state.hypotheses = extra;
  return state;
}

function authWallHypothesis(attempts = 0): Hypothesis {
  return {
    id: "auth_wall:ep:t.example/api/admin",
    kind: "auth_wall",
    nodes: [EP, identityNodeId("user_a")],
    text: "被拦，带凭证重打",
    severity: "high",
    created_at: 1,
    status: "open",
    attempts,
  };
}

describe("wallStillStands：不拿瞬时状态判死", () => {
  it("拿到 <400 → 墙已破", () => {
    expect(wallStillStands(node({ properties: { status_code: 200, blocked_streak: 0 } }))).toBe(false);
  });

  it("状态迁到 testing 但 blocked_streak 还在 → 墙还在（核心：不误杀）", () => {
    expect(wallStillStands(node({ status: "testing", properties: { status_code: 403, blocked_streak: 3 } }))).toBe(true);
  });

  it("状态迁到 dead_end 但 blocked_streak 还在 → 墙还在", () => {
    expect(wallStillStands(node({ status: "dead_end", properties: { status_code: 403, blocked_streak: 16 } }))).toBe(true);
  });

  it("路由不存在（404 + route_missing）→ 不是墙", () => {
    expect(wallStillStands(node({ status: "testing", properties: { status_code: 404, route_missing: true, blocked_streak: 1 } }))).toBe(false);
  });

  it("只观测到 404 且没有可比响应 → 不是墙", () => {
    expect(wallStillStands(node({ status: "untested", properties: { status_code: 404, origin: "discovery" } }))).toBe(false);
  });

  it("节点不存在 → 无从判断，按墙不在处理", () => {
    expect(wallStillStands(undefined)).toBe(false);
  });
});

describe("activeHypotheses：auth_wall 的有效期", () => {
  it("重打中（status=testing，streak 仍在）→ 保留，不自我归档", () => {
    const state = stateWith(node({ status: "testing" }), [authWallHypothesis(1)]);
    expect(activeHypotheses(state).some(item => item.kind === "auth_wall")).toBe(true);
  });

  it("端点拿到 200 → 撤下", () => {
    const state = stateWith(node({ status: "testing", properties: { status_code: 200, blocked_streak: 0 } }), [authWallHypothesis(0)]);
    expect(activeHypotheses(state)).toHaveLength(0);
  });

  it("锚点被裁掉（节点不存在）→ 撤下，不再派打不到的任务", () => {
    const state = stateWith(undefined, [authWallHypothesis(0)]);
    expect(activeHypotheses(state)).toHaveLength(0);
  });

  it("墙已破但停在 dead_end → 撤下", () => {
    const state = stateWith(node({ status: "dead_end", properties: { status_code: 404, route_missing: true } }), [authWallHypothesis(0)]);
    expect(activeHypotheses(state)).toHaveLength(0);
  });
});

describe("noteHypothesisAttempt：账记在正确的假设上", () => {
  it("匿名请求不给 auth_wall 记账", () => {
    const hypothesis = authWallHypothesis(2);
    const state = stateWith(node(), [hypothesis]);
    for (let index = 0; index < 3; index += 1) {
      noteHypothesisAttempt(state, EP, { identity: "anon" });
    }
    // 改动前：3 次匿名请求直接把它打到 unreachable。
    expect(hypothesis.attempts).toBe(2);
    expect(hypothesis.status).toBe("open");
  });

  it("点名身份重打才记账，第 3 次降级", () => {
    const hypothesis = authWallHypothesis(0);
    const state = stateWith(node(), [hypothesis]);
    noteHypothesisAttempt(state, EP, { identity: "user_a" });
    noteHypothesisAttempt(state, EP, { identity: "user_a" });
    expect(hypothesis.attempts).toBe(2);
    const closed = noteHypothesisAttempt(state, EP, { identity: "user_a" });
    expect(closed).toHaveLength(1);
    expect(hypothesis.status).toBe("archived");
  });

  it("别的身份也不算这条假设的账", () => {
    const hypothesis = authWallHypothesis(0);
    const state = stateWith(node(), [hypothesis]);
    noteHypothesisAttempt(state, EP, { identity: "user_b" });
    expect(hypothesis.attempts).toBe(0);
  });

  it("idor 行为不变：任何身份都计数（它不依赖特定凭证）", () => {
    const idor: Hypothesis = {
      id: "idor:ep:t.example/api/admin", kind: "idor", nodes: [EP],
      text: "越权对照", severity: "high", created_at: 1, status: "open", attempts: 0,
    };
    const state = stateWith(node(), [idor]);
    noteHypothesisAttempt(state, EP, { identity: "anon" });
    expect(idor.attempts).toBe(1);
  });

  it("未传 identity 时保持旧行为（兼容不走 desk 的调用方）", () => {
    const hypothesis = authWallHypothesis(0);
    const state = stateWith(node(), [hypothesis]);
    noteHypothesisAttempt(state, EP, {});
    expect(hypothesis.attempts).toBe(1);
  });
});

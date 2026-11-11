/**
 * stall 退出假设池（2026-11-04）。
 *
 * 事故链：`hits >= 4` 就产一条 stall 假设 → 单轮 179 条把 40 个座位全占满 →
 * hypothesisTasks 过滤 stall（它不是待验证目标）→ 假设任务恒为 0 →
 * attempts 恒为 0 → `attempts >= 3` 的归档永不成立 → stall 永久驻留。
 *
 * 三个真实会话（d59f5a15a4ea26aa / d8f8350dadeb5441 / 53a9ff8fca15e361）
 * 的假设任务数都是 0，模型可见的 12 条假设在跨域放开后全是 stall。
 *
 * 改法：stall 从"假设"降级为端点属性 `stall_hits`——它表达的是事实，不是待验证猜想。
 */
import { describe, expect, it } from "vitest";
import {
  activeHypotheses, applyHypotheses, deriveHypotheses, graphContextView, graphState,
  ingestToolResult,
} from "../src/blackbox/graph/index.js";
import { hypothesisTasks } from "../src/blackbox/hypothesis_tasks.js";
import type { Hypothesis } from "../src/blackbox/graph/types.js";

const fresh = () => graphState(undefined);

function legacyStall(id: string): Hypothesis {
  return {
    id: `stall:ep:t.example/${id}`,
    kind: "stall",
    nodes: [`ep:t.example/${id}`],
    text: `ep:t.example/${id} 已被请求 9 次仍无状态变化：停止换 payload，改换攻击面。`,
    severity: "medium",
    created_at: 1,
    status: "open",
    attempts: 0,
  };
}

describe("stall 不再生成", () => {
  it("端点 hits 再高也不产 stall 假设", () => {
    const state = fresh();
    for (let index = 0; index < 9; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/list", status_code: 200 }] });
    }
    expect(deriveHypotheses(state, 1).some(item => item.kind === "stall")).toBe(false);
  });

  it("止损信号仍在：端点带 stall_hits", () => {
    const state = fresh();
    for (let index = 0; index < 9; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/list", status_code: 200 }] });
    }
    const view = graphContextView(state);
    const node = view.nodes.find(item => item.id === "ep:t.example/api/list");
    expect(node?.props?.stall_hits).toBe(9);
    expect(view.field_legend.some(line => line.includes("stall_hits"))).toBe(true);
  });

  it("未达阈值（hits<4）不带 stall_hits", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/once", status_code: 200 }] });
    const view = graphContextView(state);
    const node = view.nodes.find(item => item.id === "ep:t.example/api/once");
    expect(node?.props?.stall_hits).toBeUndefined();
  });
});

describe("历史积压清理", () => {
  it("applyHypotheses 剔除旧 checkpoint 里的 stall", () => {
    const state = fresh();
    state.hypotheses = Array.from({ length: 40 }, (_, index) => legacyStall(`p${index}`));
    applyHypotheses(state, []);
    expect(state.hypotheses.some(item => item.kind === "stall")).toBe(false);
  });

  it("activeHypotheses 过滤 stall（replay 路径未及清理时也挡住）", () => {
    const state = fresh();
    state.hypotheses = [legacyStall("a"), legacyStall("b")];
    expect(activeHypotheses(state)).toHaveLength(0);
  });

  it("graphContextView 不把 stall 计入假设数，也不虚报已关闭数", () => {
    const state = fresh();
    state.hypotheses = [...Array.from({ length: 40 }, (_, index) => legacyStall(`p${index}`))];
    const view = graphContextView(state);
    expect(view.hypotheses).toHaveLength(0);
    expect(view.counts.hypotheses).toBe(0);
    // 关键：40 条 stall 是"不再生成"，不是"已关闭"——不能算进 closed。
    expect(view.counts.hypotheses_closed).toBe(0);
    expect(view.closed_hypotheses).toHaveLength(0);
  });

  it("hypothesisTasks 不会从历史 stall 派任务", () => {
    const state = fresh();
    state.hypotheses = Array.from({ length: 40 }, (_, index) => legacyStall(`p${index}`));
    expect(hypothesisTasks(activeHypotheses(state))).toHaveLength(0);
  });
});

describe("死锁解除回归", () => {
  it("40 条历史 stall 在场时，auth_wall 仍能进池并被派任务", () => {
    const state = fresh();
    // 造一条真假设：被拦截的端点（status 落 blocked 需要显式 blocked 标记，
    // 单给 403 只会留 testing）+ 一个身份，deriveHypotheses 才会产 auth_wall。
    ingestToolResult(state, {
      tool: "http.request",
      identity: "user_a",
      endpoints: [{ url: "https://t.example/api/admin", status_code: 403, blocked: true }],
    });
    // 复现线上状态：池里已经躺着 40 条 stall（旧 checkpoint 的积压）。
    state.hypotheses = Array.from({ length: 40 }, (_, index) => legacyStall(`p${index}`));

    const added = applyHypotheses(state, deriveHypotheses(state, 1));

    // 改动前：slice(-40) 把新增的 auth_wall 直接挤掉，added 里根本没有它。
    const active = activeHypotheses(state);
    expect(active.some(item => item.kind === "auth_wall")).toBe(true);
    expect(active.some(item => item.kind === "stall")).toBe(false);
    // 任务侧：这是"假设 → 任务"链路第一次真的能产出 H_ 任务。
    const tasks = hypothesisTasks(active, { limit: 3 });
    expect(tasks.some(task => task.hypothesis_id.startsWith("auth_wall:"))).toBe(true);
    expect(tasks.some(task => task.id.startsWith("H_stall_"))).toBe(false);
    expect(added.some(item => item.kind === "auth_wall")).toBe(true);
  });
});

/**
 * 硬出路（2026-11-03）：第四态节点必须被驱动去补测，而不是只在 prompt 里提示一句。
 *
 * 背景：会话 53a9ff8fca15e361 里 probe 节点悬了 27 分钟无人补测，
 * 最后带着 `200 + status_unknown` 的矛盾态被判 dead_end，25 条假设里 0 条 idor。
 * 三段：① 假设生成器产出 retest_for_status；② 任务入队低优先级（有空位才占位）；
 * ③ 死胡同拒收时强制派一次补测（兜底，每节点仅一次）。
 */
import { describe, expect, it } from "vitest";
import {
  applyHypotheses, deriveHypotheses, graphState, ingestToolResult,
  isProbedButUnknown, markDeadEnd, upsertNode,
} from "../src/blackbox/graph/index.js";
import { hypothesisTasks } from "../src/blackbox/hypothesis_tasks.js";
import type { AttackGraphState } from "../src/blackbox/graph/types.js";

const fresh = () => graphState(undefined);

function withProbedNode(url = "https://t.example/api/user/1", tool = "nuclei"): AttackGraphState {
  const state = fresh();
  ingestToolResult(state, {
    tool,
    endpoints: [{ url, origin: "request", requested: true, status_unknown: true }],
  });
  return state;
}

describe("段 1：假设生成器产出补测假设", () => {
  it("第四态节点生成 retest_for_status，而不是 IDOR", () => {
    const state = withProbedNode();
    const hypotheses = deriveHypotheses(state, 1);
    const retest = hypotheses.filter(item => item.kind === "retest_for_status");
    expect(retest).toHaveLength(1);
    // 没有状态码 → 没有 baseline → 不能派越权对照
    expect(hypotheses.filter(item => item.kind === "idor")).toHaveLength(0);
    expect(retest[0]!.text).toContain("http.request");
    expect(retest[0]!.text).toContain("nuclei"); // 点名：别用原来那个工具重打
  });

  it("{id} 接口优先：多个第四态节点时先补测带 id 的", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "nuclei",
      endpoints: [
        { url: "https://t.example/robots.txt", origin: "request", requested: true, status_unknown: true },
        { url: "https://t.example/api/user/1", origin: "request", requested: true, status_unknown: true },
      ],
    });
    const retest = deriveHypotheses(state, 1).filter(item => item.kind === "retest_for_status");
    expect(retest[0]!.nodes[0]).toBe("ep:t.example/api/user/{id}");
  });

  it("拿到状态码后补测假设自动收口（不再占任务簿）", () => {
    const state = withProbedNode("https://t.example/x");
    applyHypotheses(state, deriveHypotheses(state, 1));
    // 补测成功
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/x", origin: "request", requested: true, status_code: 200 }],
    });
    applyHypotheses(state, deriveHypotheses(state, 2));
    const retest = state.hypotheses.filter(item => item.kind === "retest_for_status");
    // 收口靠 activeHypotheses 过滤（补到状态码就不再活跃），这里断言节点已不是第四态
    expect(isProbedButUnknown(state.nodes["ep:t.example/x"]!)).toBe(false);
    expect(retest.length).toBeLessThanOrEqual(1);
  });
});

describe("段 2：补测任务低优先级，不挤掉高价值假设", () => {
  const spec = (kind: string, name: string) => ({
    id: `${kind}:${name}`, kind, nodes: [`ep:t.example/${name}`],
    text: `${kind} ${name}`, severity: "medium" as const, created_at: Date.now(),
  });

  it("高价值假设占满名额时，补测任务留在图里（不入队）", () => {
    const specs = hypothesisTasks([
      spec("idor", "a"), spec("idor", "b"), spec("auth_wall", "c"), spec("retest_for_status", "d"),
    ], { limit: 3 });
    expect(specs.map(item => item.hypothesis_id)).toEqual(["idor:a", "idor:b", "auth_wall:c"]);
    expect(specs.map(item => item.hypothesis_id)).not.toContain("retest_for_status:d");
  });

  it("有空位时才入队，且判据是「取状态码」而不是 verdict", () => {
    const specs = hypothesisTasks([spec("retest_for_status", "d")], { limit: 3 });
    expect(specs).toHaveLength(1);
    expect(specs[0]!.deliverables).toEqual(["status_code:number"]);
    expect(specs[0]!.completion_criteria).toContain("状态码");
  });

  it("stall 仍然不占名额（历史行为不回退）", () => {
    const specs = hypothesisTasks([spec("stall", "a"), spec("retest_for_status", "d")], { limit: 3 });
    expect(specs).toHaveLength(1);
    expect(specs[0]!.hypothesis_id).toBe("retest_for_status:d");
  });
});

describe("段 3：死胡同封路给一次补测宽限", () => {
  it("第四态节点第一次封路被拦下，并留下「先补测」的说明", () => {
    const state = withProbedNode("https://t.example/x");
    const node = state.nodes["ep:t.example/x"]!;
    expect(markDeadEnd(state, "ep:t.example/x", "同一请求已重复 3 次")).toBe(false);
    expect(node.status).not.toBe("dead_end");
    expect(String(node.properties.note)).toContain("补测");
    // 只宽限一次：补测再失败必须能封路，不能永远卡在 testing
    expect(markDeadEnd(state, "ep:t.example/x", "同一请求已重复 4 次")).toBe(true);
    expect(node.status).toBe("dead_end");
  });

  it("已经拿到状态码的节点不受影响（正常封路）", () => {
    const state = fresh();
    upsertNode(state, { id: "ep:t.example/x", type: "endpoint", status: "testing", properties: { origin: "request", status_code: 200 } });
    expect(markDeadEnd(state, "ep:t.example/x", "重复 3 次")).toBe(true);
  });
});

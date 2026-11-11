/**
 * 消费侧 #6-2：节点四态的判定口径。
 *
 * 三种节点在图上长得像，含义完全不同：
 *   ① 没动过（untested / discovery）      → 值得派首打
 *   ② 打了且有响应（request + status_code）→ 可做差异对照、可推越权
 *   ③ 打了但没拿到状态（request + status_unknown）→ 既不是①②，得换工具重测
 * 把 ③ 当 ② 会派一轮做不成的对照（两边都没 baseline）；当 ① 会反复重派同一个探针。
 */
import { describe, expect, it } from "vitest";
import {
  deriveHypotheses, graphState, hasComparableResponse, ingestToolResult,
  isProbedButUnknown, upsertNode, verified,
} from "../src/blackbox/graph/index.js";
import type { GraphNode, NodeStatus } from "../src/blackbox/graph/types.js";

const node = (props: Record<string, unknown>, status: NodeStatus = "testing"): GraphNode => ({
  id: "ep:t.example/api/user/{id}",
  type: "endpoint",
  properties: props,
  status,
  discovered_by: "ev-1",
  updated_at: Date.now(),
});

describe("三态判定：verified / hasComparableResponse / isProbedButUnknown", () => {
  it("probe 类：不进未探索面，也不算有可比响应，是第四态", () => {
    const probe = node({ origin: "request", status_unknown: true });
    expect(verified(probe)).toBe(false);
    expect(hasComparableResponse(probe)).toBe(false);
    expect(isProbedButUnknown(probe)).toBe(true);
  });

  it("response 类：有可比响应，不是第四态，也不是未探索", () => {
    const response = node({ origin: "request", status_code: 200 });
    expect(hasComparableResponse(response)).toBe(true);
    expect(isProbedButUnknown(response)).toBe(false);
    expect(verified(response)).toBe(false);
  });

  it("被动发现带状态码：进未探索面，但没有可比响应", () => {
    // 2026-11-09（A1）：裸 discovery（没有状态码的页面链接）不再算"观测面"，
    // 只有被动流量里看到过响应码的才进建议池——否则巡检会反复催两条已知 404。
    const discovery = node({ origin: "discovery", status_code: 200 }, "untested");
    expect(verified(discovery)).toBe(true);
    expect(hasComparableResponse(discovery)).toBe(false);
    expect(isProbedButUnknown(discovery)).toBe(false);
    // 没有状态码 = 只是候选，不是观测面
    expect(verified(node({ origin: "discovery" }, "untested"))).toBe(false);
  });

  it("历史 checkpoint 的 link/js/api 带状态码才算观测面；无 origin 的旧节点不算", () => {
    expect(verified(node({ origin: "link", status_code: 200 }, "untested"))).toBe(true);
    expect(verified(node({ origin: "api", status_code: 200 }, "untested"))).toBe(true);
    // 没有状态码的裸链接：不再是"未探索的块"（A1 收紧）
    expect(verified(node({ origin: "link" }, "untested"))).toBe(false);
    // 404/410 是已知坏面，不进建议池
    expect(verified(node({ origin: "link", status_code: 404 }, "untested"))).toBe(false);
    expect(verified(node({}, "untested"))).toBe(false);
    // 非端点节点（asset/identity/vuln_state）永远不是"未探索的块"。
    expect(verified({ ...node({ origin: "discovery", status_code: 200 }, "untested"), type: "asset" })).toBe(false);
  });
});

describe("假设生成按三态分流（cannotLocateObject）", () => {
  const fresh = () => graphState(undefined);

  it("probe 命中但不带状态码：不生成越权假设（没有 baseline 可对照）", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "nuclei",
      endpoints: [{ url: "https://t.example/api/user/{id}", origin: "request", requested: true, status_unknown: true }],
    });
    expect(state.nodes["ep:t.example/api/user/{id}"]?.properties.status_unknown).toBe(true);
    const hypotheses = deriveHypotheses(state, 1);
    expect(hypotheses.filter(item => item.kind === "idor" || item.kind === "object_enum")).toHaveLength(0);
  });

  it("真拿到 200 的接口：照常生成越权假设", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/api/user/{id}", origin: "request", requested: true, status_code: 200 }],
    });
    const hypotheses = deriveHypotheses(state, 1);
    expect(hypotheses.some(item => item.kind === "idor")).toBe(true);
  });

  it("被动发现且观测状态是 404：仍然判死（原有行为不回退）", () => {
    const state = fresh();
    upsertNode(state, {
      id: "ep:t.example/api/order/{id}",
      type: "endpoint",
      status: "untested",
      properties: { origin: "discovery", status_code: 404 },
    });
    const hypotheses = deriveHypotheses(state, 1);
    expect(hypotheses.filter(item => item.kind === "idor" || item.kind === "object_enum")).toHaveLength(0);
  });
});

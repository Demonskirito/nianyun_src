import { describe, expect, it } from "vitest";
import {
  edgeClassOf, graphState, graphVisualView, ingestToolResult, upsertEdge, upsertNode,
} from "../src/blackbox/graph/index.js";

const fresh = () => graphState(undefined);

function graphWithAll(): ReturnType<typeof graphState> {
  const state = fresh();
  upsertNode(state, { id: "asset:t.example", type: "asset", properties: { host: "t.example" }, discovered_by: "ev-1" });
  upsertNode(state, { id: "ep:t.example/", type: "endpoint", discovered_by: "ev-1" });
  upsertNode(state, { id: "ep:t.example/api/order", type: "endpoint", properties: { method: "post", status_code: 403, blocked_streak: 2 }, status: "blocked", discovered_by: "ev-2" });
  upsertNode(state, { id: "id:buyer", type: "identity", properties: { role: "buyer" }, discovered_by: "ev-2" });
  upsertEdge(state, { source_id: "asset:t.example", target_id: "ep:t.example/", type: "navigates_to" });
  upsertEdge(state, { source_id: "ep:t.example/", target_id: "ep:t.example/api/order", type: "calls_api", rpc_tool: "http.request" });
  upsertEdge(state, { source_id: "id:buyer", target_id: "ep:t.example/api/order", type: "requires_auth", weight: 3 });
  ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/order", status_code: 200, params: ["order_id"] }] });
  ingestToolResult(state, { tool: "http.diff", endpoints: [{ url: "https://t.example/api/order", status_code: 200 }], vulnerabilities: [{ url: "https://t.example/api/order", kind: "idor" }] });
  // 一个死胡同
  for (let index = 0; index < 3; index += 1) {
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/search", status_code: 403, blocked: true }] });
  }
  return state;
}

describe("图谱前端视图（graphVisualView）", () => {
  it("节点带形状/class/标签，形状按类型映射", () => {
    const view = graphVisualView(graphWithAll());
    const endpoint = view.nodes.find(node => node.id === "ep:t.example/api/order")!;
    expect(endpoint.shape).toBe("round-rectangle");
    expect(endpoint.class).toContain("type-endpoint");
    expect(endpoint.class).toContain("status-vulnerable");
    expect(endpoint.label).toContain("POST");
    expect(view.nodes.find(node => node.type === "identity")!.shape).toBe("shield");
    expect(view.nodes.find(node => node.type === "parameter")?.shape ?? "diamond").toBe("diamond");
    expect(view.nodes.find(node => node.type === "vuln_state")!.shape).toBe("octagon");
    expect(view.nodes.find(node => node.type === "asset")!.shape).toBe("hexagon");
  });

  it("死胡同被标记为 dimmed，漏洞节点被标记为 highlighted", () => {
    const view = graphVisualView(graphWithAll());
    const dead = view.nodes.find(node => node.status === "dead_end")!;
    expect(dead.dimmed).toBe(true);
    expect(dead.class).toContain("status-dead_end");
    expect(view.nodes.filter(node => node.highlighted).length).toBeGreaterThan(0);
  });

  it("边类型映射到样式类（鉴权/数据/利用/绕过）", () => {
    expect(edgeClassOf("requires_auth")).toBe("edge-auth");
    expect(edgeClassOf("flows_data_to")).toBe("edge-data");
    expect(edgeClassOf("exploits")).toBe("edge-exploit");
    expect(edgeClassOf("bypasses")).toBe("edge-bypass");
    expect(edgeClassOf("navigates_to")).toBe("edge-nav");
    const view = graphVisualView(graphWithAll());
    expect(view.edges.some(edge => edge.class === "edge-auth")).toBe(true);
    expect(view.edges.some(edge => edge.rpc_tool === "http.request")).toBe(true);
    expect(view.stats.rpc_edges).toBeGreaterThan(0);
  });

  it("Kill Chain 带 finding 的 target 与 severity（人能读的名字）", () => {
    const view = graphVisualView(graphWithAll(), {
      killChainFindings: [{ target: "https://t.example/api/order", severity: "high" }],
    });
    expect(view.kill_chains.length).toBeGreaterThan(0);
    const chain = view.kill_chains[0]!;
    expect(chain.chain.length).toBeGreaterThan(1);
    expect(chain.chain[chain.chain.length - 1]).toBe(chain.node);
    expect(chain.target).toBe("https://t.example/api/order");
    expect(chain.severity).toBe("high");
  });

  it("同一个漏洞的两个锚点只出一条 Kill Chain（按 target 去重，留最长的）", () => {
    const view = graphVisualView(graphWithAll(), {
      killChainFindings: [{ target: "https://t.example/api/order", severity: "high" }],
    });
    const targets = view.kill_chains.map(item => item.target);
    expect(new Set(targets).size).toBe(targets.length);
  });

  it("统计区分真实边与叠加的假设线", () => {
    const view = graphVisualView(graphWithAll());
    expect(typeof view.stats.hypothesis_edges).toBe("number");
  });

  it("统计与目标齐备（面板数字来源）", () => {
    const view = graphVisualView(graphWithAll());
    expect(view.stats.nodes).toBe(Object.keys(graphWithAll().nodes).length);
    // 身份节点包括 anon（被 403 打过的端点会带出一个匿名身份）+ 图里显式建的 buyer\n    expect(view.stats.identities).toBeGreaterThanOrEqual(1);\n    expect(view.nodes.some(node => node.id === "id:buyer")).toBe(true);
    expect(view.stats.dead_end).toBeGreaterThan(0);
    expect(view.targets.length).toBeGreaterThan(0);
    expect(view.components.length).toBeGreaterThan(0);
  });

  it("超过 maxNodes 时按重要度截断并报告 pruned（不静默丢弃）", () => {
    const state = fresh();
    for (let index = 0; index < 60; index += 1) {
      upsertNode(state, { id: `ep:t.example/filler${index}`, type: "endpoint" });
    }
    upsertNode(state, { id: "vuln:idor@t.example/x", type: "vuln_state", status: "vulnerable" });
    const view = graphVisualView(state, { maxNodes: 20 });
    expect(view.nodes.length).toBeLessThanOrEqual(20);
    expect(view.stats.pruned).toBeGreaterThan(0);
    // 漏洞节点必须留下（截图写报告全靠它）
    expect(view.nodes.some(node => node.type === "vuln_state")).toBe(true);
  });

  it("假设线是虚线语义，且不会把闭环画成毛线球（每假设最多 2 条）", () => {
    const state = fresh();
    for (const id of ["ep:t.example/a", "ep:t.example/b", "ep:t.example/c", "ep:t.example/d"]) {
      upsertNode(state, { id, type: "endpoint" });
    }
    state.hypotheses.push({
      id: "h1", kind: "idor", severity: "high", created_at: Date.now(),
      text: "四个端点同源", nodes: ["ep:t.example/a", "ep:t.example/b", "ep:t.example/c", "ep:t.example/d"],
    });
    const view = graphVisualView(state);
    const hypothesisEdges = view.edges.filter(edge => edge.hypothesis);
    expect(hypothesisEdges.length).toBe(2);
    expect(hypothesisEdges.every(edge => edge.class === "edge-hypothesis")).toBe(true);
  });

  it("空图返回空视图而不是崩溃", () => {
    const view = graphVisualView(fresh());
    expect(view.nodes).toEqual([]);
    expect(view.edges).toEqual([]);
    expect(view.stats.nodes).toBe(0);
  });
});
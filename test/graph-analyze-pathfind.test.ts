import { describe, expect, it } from "vitest";
import {
  BLOCK_PENALTY, connectedComponents, detectCycles, dijkstra, dynamicPenalty, graphSignals,
  graphState, highValueTargets, ingestToolResult, planRoutes, routeStale, upsertEdge, upsertNode,
} from "../src/blackbox/graph/index.js";

const fresh = () => graphState(undefined);

function link(state: ReturnType<typeof graphState>, from: string, to: string): void {
  // origin: "link" + status_code —— 2026-11-09（A1）起漂移巡检的 Root 必须"看到过响应"：
  // 只认带状态码的观测面。裸链接（页面上的 <a href>）已经没有资格当 root 了，
  // 因为现场就是这样把两条 404 链接催了 129 轮。字典命中（item）依然不算。
  upsertNode(state, { id: from, type: "endpoint", properties: { origin: "link", status_code: 200 } });
  upsertNode(state, { id: to, type: "endpoint", properties: { origin: "link", status_code: 200 } });
  upsertEdge(state, { source_id: from, target_id: to, type: "navigates_to" });
}

describe("P2-5：环路检测", () => {
  it("识别 A → B → C → A（登录 → 越权失败 → 重新登录）", () => {
    const state = fresh();
    link(state, "ep:t.example/login", "ep:t.example/api/admin");
    link(state, "ep:t.example/api/admin", "ep:t.example/logout");
    link(state, "ep:t.example/logout", "ep:t.example/login");
    const cycles = detectCycles(state);
    expect(cycles).toHaveLength(1);
    expect([...cycles[0]!.nodes].sort()).toEqual([
      "ep:t.example/api/admin", "ep:t.example/login", "ep:t.example/logout",
    ]);
    // 规范化旋转：从字典序最小节点开头，且多次调用结果一致（interrupt 去重要靠这个）
    expect(cycles[0]!.nodes[0]).toBe("ep:t.example/api/admin");
    expect(detectCycles(state)[0]!.nodes).toEqual(cycles[0]!.nodes);
  });

  it("2 环（导航栏互链）不报——那是噪音", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/b", "ep:t.example/a");
    expect(detectCycles(state)).toHaveLength(0);
  });

  it("无环图返回空，且不因自环卡死", () => {
    const state = fresh();
    link(state, "ep:t.example/", "ep:t.example/a");
    link(state, "ep:t.example/a", "ep:t.example/b");
    upsertEdge(state, { source_id: "ep:t.example/b", target_id: "ep:t.example/b", type: "navigates_to" });
    expect(detectCycles(state)).toHaveLength(0);
  });

  it("环路信号要求最近活动确实落在环上（否则不打扰）", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/b", "ep:t.example/c");
    link(state, "ep:t.example/c", "ep:t.example/a");
    link(state, "ep:t.example/other", "ep:t.example/x");
    // 最近只在别处活动 → 不报环路
    expect(graphSignals(state, ["ep:t.example/other", "ep:t.example/x"]).some(signal => signal.kind === "cycle")).toBe(false);
    // 最近落在环上 → 报
    const signals = graphSignals(state, ["ep:t.example/a", "ep:t.example/b", "ep:t.example/c", "ep:t.example/a"]);
    const cycle = signals.find(signal => signal.kind === "cycle");
    expect(cycle).toBeDefined();
    expect(cycle!.text).toContain("行为环路");
    expect(cycle!.severity).toBe("high");
  });
});

describe("P2-5：连通分量", () => {
  it("分裂成多块时给出各块规模与是否含漏洞", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/c", "ep:t.example/d");
    ingestToolResult(state, { tool: "http.diff", endpoints: [{ url: "https://t.example/c", status_code: 200 }],
      vulnerabilities: [{ url: "https://t.example/c", kind: "idor" }] });
    const components = connectedComponents(state);
    expect(components.length).toBeGreaterThanOrEqual(2);
    expect(components.some(component => component.hasVuln)).toBe(true);
  });

  it("Agent 困在小块里 → 给出其他块的 Root", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/c", "ep:t.example/d");
    link(state, "ep:t.example/e", "ep:t.example/f");
    const signals = graphSignals(state, ["ep:t.example/a", "ep:t.example/b", "ep:t.example/a"]);
    const drift = signals.find(signal => signal.kind === "component_drift");
    expect(drift).toBeDefined();
    // ④ 2026-11-07：提醒里不再出现 `ep:` 节点 id / "Root" 这类不可照抄的泛化词，
    // 只给能直接粘进 http.request 的真实 URL。
    expect(drift!.text).toContain("https://t.example/c");
    expect(drift!.text).not.toContain("ep:");
    const roots = drift!.data?.roots as string[];
    expect(roots.length).toBeGreaterThan(0);
    expect(roots.every(url => /^https?:\/\//.test(url) && !/[{}]/.test(url))).toBe(true);
  });

  it("只有一块图时不提示（没有别处可去）", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    expect(graphSignals(state, ["ep:t.example/a", "ep:t.example/b", "ep:t.example/a"]).some(signal => signal.kind === "component_drift")).toBe(false);
  });
});

describe("P2-6：按需 Dijkstra", () => {
  it("从新端点算出通往高危端点的最便宜路径，并给出 Next Hop", () => {
    const state = fresh();
    link(state, "ep:t.example/entry", "ep:t.example/api/order/list");
    link(state, "ep:t.example/api/order/list", "ep:t.example/api/order/pay");
    const routes = planRoutes(state, "ep:t.example/entry");
    expect(routes.length).toBeGreaterThan(0);
    expect(routes[0]!.target).toBe("ep:t.example/api/order/pay");
    expect(routes[0]!.next_hop).toBe("ep:t.example/api/order/list");
    expect(routes[0]!.hops).toHaveLength(2);
  });

  it("死胡同端点不参与寻路（算法不该把 Agent 送回死路）", () => {
    const state = fresh();
    link(state, "ep:t.example/entry", "ep:t.example/dead");
    link(state, "ep:t.example/dead", "ep:t.example/api/order/pay");
    for (let index = 0; index < 3; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/dead", status_code: 403, blocked: true }] });
    }
    const routes = planRoutes(state, "ep:t.example/entry");
    expect(routes.every(route => route.hops.every(hop => hop.to !== "ep:t.example/dead"))).toBe(true);
  });

  it("动态权重：连续 403 的节点出边变贵，算法改走另一条路", () => {
    const state = fresh();
    // 两条路都能到 pay：短的那条经过被拦 3 次的节点
    link(state, "ep:t.example/entry", "ep:t.example/walled");
    link(state, "ep:t.example/walled", "ep:t.example/api/order/pay");
    link(state, "ep:t.example/entry", "ep:t.example/open");
    link(state, "ep:t.example/open", "ep:t.example/api/order/pay");
    for (let index = 0; index < 3; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/walled", status_code: 403, blocked: true }] });
    }
    expect(dynamicPenalty(state, "ep:t.example/walled")).toBeGreaterThan(2);
    const route = planRoutes(state, "ep:t.example/entry")[0]!;
    expect(route.next_hop).toBe("ep:t.example/open");
  });

  it("成功一次就清零（曾经难过不能永远算账）", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/x", status_code: 403, blocked: true }] });
    expect(state.nodes["ep:t.example/x"]!.properties.blocked_streak).toBe(1);
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/x", status_code: 200 }] });
    expect(state.nodes["ep:t.example/x"]!.properties.blocked_streak).toBe(0);
    expect(dynamicPenalty(state, "ep:t.example/x")).toBe(1);
  });

  it("罚分随时间放大但有上限（不会把图算成走不通）", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/y", status_code: 403, blocked: true }] });
    const node = state.nodes["ep:t.example/y"]!;
    node.properties.blocked_streak = 3;
    node.properties.blocked_at = Date.now() - BLOCK_PENALTY.windowMs * 6;
    const penalty = dynamicPenalty(state, "ep:t.example/y");
    expect(penalty).toBeGreaterThan(3);
    expect(penalty).toBeLessThanOrEqual(1 + 3 * BLOCK_PENALTY.cap);
  });

  it("身份节点可作为起点（刚拿到 Token 就能规划路线）", () => {
    const state = fresh();
    upsertNode(state, { id: "id:buyer", type: "identity" });
    link(state, "ep:t.example/entry", "ep:t.example/api/order/pay");
    upsertEdge(state, { source_id: "id:buyer", target_id: "ep:t.example/api/order/pay", type: "requires_auth", weight: 3 });
    const routes = planRoutes(state, "id:buyer");
    expect(routes[0]!.next_hop).toBe("ep:t.example/api/order/pay");
  });

  it("存的路线会过期：推荐的一跳被标死或连续被拦就要重算", () => {
    const state = fresh();
    link(state, "ep:t.example/entry", "ep:t.example/list");
    link(state, "ep:t.example/list", "ep:t.example/api/order/pay");
    const hops = planRoutes(state, "ep:t.example/entry").map(route => route.next_hop);
    expect(hops.length).toBeGreaterThan(0);
    expect(routeStale(state, hops)).toBe(false);

    // 连续两次被拦 → 过期
    for (let index = 0; index < 2; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/list", status_code: 403, blocked: true }] });
    }
    expect(routeStale(state, hops)).toBe(true);

    // 节点被删（图裁剪）也算过期
    expect(routeStale(state, ["ep:t.example/gone"])).toBe(true);
  });

  it("没有目标可去时返回空，而不是编一条路", () => {
    const state = fresh();
    link(state, "ep:t.example/entry", "ep:t.example/plain");
    expect(planRoutes(state, "ep:t.example/entry")).toHaveLength(0);
    expect(highValueTargets(state).some(target => target.includes("plain"))).toBe(false);
    expect(dijkstra(state, "ep:t.example/nonexistent").size).toBe(0);
  });
});
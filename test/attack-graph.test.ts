import { describe, expect, it } from "vitest";
import {
  DEAD_END_REPEATS, MAX_NODES, applyHypotheses, assetNodeId, deadEndOf, deriveHypotheses,
  endpointNodeId, graphContextView, graphMermaid, graphState, identityNodeId, ingestToolResult,
  isDynamicSegment, killChain, normalizePath, prune, upsertNode, urlHost, urlPath,
} from "../src/blackbox/graph/index.js";

const fresh = () => graphState(undefined);

describe("阶段一：端点归一化（图不爆炸的前提）", () => {
  it("折叠动态段：数字 / UUID / 长 hex / 日期 / 资源-id", () => {
    expect(normalizePath("/api/user/1")).toBe("/api/user/{id}");
    expect(normalizePath("/api/user/12345")).toBe("/api/user/{id}");
    expect(normalizePath("/api/order/user-42")).toBe("/api/order/user/{id}");
    expect(normalizePath("/api/item/550e8400-e29b-41d4-a716-446655440000")).toBe("/api/item/{id}");
    expect(normalizePath("/api/log/2024-05-01")).toBe("/api/log/{id}");
    expect(normalizePath("/api/user/1?x=2#frag")).toBe("/api/user/{id}");
  });

  it("保留版本号与普通路由段（折叠了就是把不同接口合成一个）", () => {
    expect(normalizePath("/api/v2/user/7")).toBe("/api/v2/user/{id}");
    expect(normalizePath("/api/user/list")).toBe("/api/user/list");
    expect(normalizePath("/admin/orders")).toBe("/admin/orders");
  });

  it("同一资源的 100 个 id 只产生一个节点", () => {
    const state = fresh();
    for (let index = 1; index <= 100; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: `https://t.example/api/user/${index}`, status_code: 200 }] });
    }
    const endpoints = Object.values(state.nodes).filter(node => node.type === "endpoint");
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0]!.properties.hits).toBe(100);
    expect(state.stats.merged).toBeGreaterThan(90);
  });

  it("isDynamicSegment 不把纯字母路由当 id", () => {
    expect(isDynamicSegment("user")).toBe(false);
    expect(isDynamicSegment("checkout")).toBe(false);
    expect(isDynamicSegment("deadbeef")).toBe(false);
    expect(isDynamicSegment("a1b2c3d4e5f6g7h8i9j0k1l2")).toBe(true);
  });

  it("urlHost / urlPath 容错（没有 scheme、带 query）", () => {
    expect(urlHost("target.example/a/b")).toBe("target.example");
    expect(urlPath("https://target.example/a/b?q=1")).toBe("/a/b");
    expect(urlHost("")).toBe("");
  });
});

describe("阶段二：图构建（只吃摘要，不吃 body）", () => {
  it("http.request 成功 → asset + endpoint 节点 + navigates_to 边", () => {
    const state = fresh();
    const out = ingestToolResult(state, {
      tool: "http.request", evidence_id: "ev-1",
      endpoints: [{ url: "https://t.example/api/orders", method: "post", status_code: 200, content_length: 512, params: ["order_id"] }],
    });
    expect(out.newNodes).toContain("asset:t.example");
    expect(out.newNodes).toContain("ep:t.example/api/orders");
    expect(state.nodes["ep:t.example/api/orders"]!.properties).toMatchObject({ method: "POST", status_code: 200, content_length: 512 });
    // body 不进图：属性里没有响应体字段
    expect(JSON.stringify(state.nodes["ep:t.example/api/orders"]!.properties).length).toBeLessThan(400);
  });

  it("401/403 → blocked 状态 + requires_auth 边（从身份指向端点）", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request", identity: "buyer",
      endpoints: [{ url: "https://t.example/admin/users", status_code: 403, auth_required: true, blocked: true }],
    });
    expect(state.nodes["ep:t.example/admin/users"]!.status).toBe("blocked");
    expect(state.edges.some(edge => edge.type === "requires_auth" && edge.source_id === identityNodeId("buyer"))).toBe(true);
  });

  it("参数 → parameter 节点 + flows_data_to 边", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/api/pay", status_code: 200, params: ["price", "order_id"] }],
    });
    expect(state.nodes["param:t.example/api/pay#price"]).toBeDefined();
    expect(state.edges.filter(edge => edge.type === "flows_data_to")).toHaveLength(2);
  });

  it("katana 链接 → navigates_to；js 接口 → calls_api", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "katana.crawl",
      links: [{ from: "https://t.example/", to: "https://t.example/cart" }],
      api_calls: [{ from: "https://t.example/cart", to: "https://t.example/api/pay" }],
    });
    expect(state.edges.some(edge => edge.type === "navigates_to")).toBe(true);
    expect(state.edges.some(edge => edge.type === "calls_api")).toBe(true);
  });

  it("确认漏洞 → vuln_state 节点 + exploits 边，且端点状态升为 vulnerable", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.diff",
      endpoints: [{ url: "https://t.example/api/orders/7", status_code: 200 }],
      vulnerabilities: [{ url: "https://t.example/api/orders/7", kind: "idor" }],
    });
    const vuln = Object.values(state.nodes).find(node => node.type === "vuln_state")!;
    expect(vuln.status).toBe("vulnerable");
    expect(vuln.id).toContain("idor");
    expect(state.nodes["ep:t.example/api/orders/{id}"]!.status).toBe("vulnerable");
  });

  it("状态不降级：vulnerable 不会被后续 untested 覆盖", () => {
    const state = fresh();
    const id = "ep:t.example/api/x";
    upsertNode(state, { id, type: "endpoint", status: "vulnerable" });
    upsertNode(state, { id, type: "endpoint", status: "untested" });
    expect(state.nodes[id]!.status).toBe("vulnerable");
  });

  it("死胡同：同特征响应达到阈值后标死，且执行器能查到", () => {
    const state = fresh();
    let marked: string[] = [];
    for (let index = 0; index < DEAD_END_REPEATS; index += 1) {
      const out = ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url: "https://t.example/api/search", status_code: 200, blocked: true }],
      });
      marked = out.deadEnds;
    }
    expect(marked).toContain("ep:t.example/api/search");
    expect(deadEndOf(state, "https://t.example/api/search?q=1")?.status).toBe("dead_end");
    // 不同端点不受影响
    expect(deadEndOf(state, "https://t.example/api/other")).toBeUndefined();
  });

  it("裁剪：超上限时先丢 dead_end，vulnerable 与 identity 永不丢", () => {
    const state = fresh();
    upsertNode(state, { id: "vuln:idor@x", type: "vuln_state", status: "vulnerable" });
    upsertNode(state, { id: identityNodeId("admin"), type: "identity" });
    for (let index = 0; index < MAX_NODES + 40; index += 1) {
      upsertNode(state, { id: `ep:t.example/dead/${index}`, type: "endpoint", status: "dead_end" });
    }
    expect(Object.keys(state.nodes).length).toBeLessThanOrEqual(MAX_NODES);
    expect(state.nodes["vuln:idor@x"]).toBeDefined();
    expect(state.nodes[identityNodeId("admin")]).toBeDefined();
    expect(state.stats.pruned).toBeGreaterThan(0);
  });
});

describe("阶段三：假设生成（区别于普通扫描器的地方）", () => {
  it("两个身份指向同一端点 → IDOR 假设", () => {
    const state = fresh();
    for (const role of ["buyer", "seller"]) {
      ingestToolResult(state, {
        tool: "http.request", identity: role,
        endpoints: [{ url: "https://t.example/api/orders/9", status_code: 403, blocked: true }],
      });
    }
    const hypotheses = deriveHypotheses(state, 3);
    const idor = hypotheses.find(item => item.kind === "idor" && item.id.includes("orders"));
    expect(idor).toBeDefined();
    expect(idor!.severity).toBe("high");
    expect(idor!.text).toContain("baseline_self");
  });

  it("路径带 {id} → 直接给相邻 id 越权假设", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/user/12/profile", status_code: 200 }] });
    expect(deriveHypotheses(state).some(item => item.kind === "idor")).toBe(true);
  });

  it("blocked 端点 + 有身份 → 带凭证重打假设", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request", identity: "admin",
      endpoints: [{ url: "https://t.example/internal/panel", status_code: 401, blocked: true }],
    });
    const wall = deriveHypotheses(state).find(item => item.kind === "auth_wall");
    expect(wall).toBeDefined();
    expect(wall!.text).toContain("anonymous:true");
  });

  it("同名参数出现在两个端点 → 数据流假设（业务逻辑入口）", () => {
    const state = fresh();
    for (const url of ["https://t.example/api/cart", "https://t.example/api/pay"]) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url, status_code: 200, params: ["price"] }] });
    }
    const flow = deriveHypotheses(state).find(item => item.kind === "data_flow");
    expect(flow).toBeDefined();
    expect(flow!.text).toContain("price");
  });

  it("入口直连高危端点 → 断链假设", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "katana.crawl",
      links: [{ from: "https://t.example/", to: "https://t.example/api/refund" }],
    });
    expect(deriveHypotheses(state).some(item => item.kind === "logic_bypass")).toBe(true);
  });

  it("反复请求同一端点 → 不产 stall 假设，停滞信号落到端点属性", () => {
    const state = fresh();
    for (let index = 0; index < 5; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/list", status_code: 200 }] });
    }
    // 2026-11-04：stall 不再是假设。它会占满假设池、且不被派任务，导致
    // 假设任务恒为 0 → attempts 恒为 0 → 永不归档（三个真实会话均是 0 条假设任务）。
    expect(deriveHypotheses(state).some(item => item.kind === "stall")).toBe(false);
    // 止损语义保留：端点自己带 stall_hits，覆盖全部高 hits 端点而不是 13 个座位。
    const view = graphContextView(state);
    const node = view.nodes.find(item => item.id === "ep:t.example/api/list");
    expect(node?.props?.stall_hits).toBe(5);
  });

  it("假设去重且分桶限量（不会把自己的推导淹掉）", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/user/1", status_code: 200 }] });
    const added = applyHypotheses(state, deriveHypotheses(state, 1));
    expect(added.length).toBeGreaterThan(0);
    expect(applyHypotheses(state, deriveHypotheses(state, 2))).toHaveLength(0);
    // 2026-11-04：40 是**活跃座位**上限，且按 kind 分桶（idor 10 条）。
    // 溢出进冷宫而不是丢弃——旧断言看数组总长，新状态机里 evicted 必须留池以便复活。
    const endpoint = "ep:t.example/api/user/{id}";
    for (let index = 0; index < 60; index += 1) {
      state.hypotheses.push({ id: `x${index}`, kind: "idor", text: "t", nodes: [endpoint], severity: "high", created_at: Date.now() });
    }
    applyHypotheses(state, [{ id: "final", kind: "idor", text: "final", nodes: [endpoint], severity: "high", created_at: Date.now() }]);
    const active = state.hypotheses.filter(item => item.status === "active");
    const evicted = state.hypotheses.filter(item => item.status === "evicted");
    expect(active.length).toBeLessThanOrEqual(10);
    expect(evicted.length).toBeGreaterThan(0);
    // 一条都没丢：active + 冷宫 = 全部
    expect(active.length + evicted.length).toBe(state.hypotheses.length);
  });
});

describe("阶段四：序列化与裁剪（保护上下文）", () => {
  it("视图带上节点/边/假设/死胡同/身份，并报告截断量", () => {
    const state = fresh();
    for (let index = 0; index < 80; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: `https://t.example/api/res${index}/detail`, status_code: 200, params: ["q"] }] });
    }
    ingestToolResult(state, { tool: "http.diff", endpoints: [{ url: "https://t.example/api/1/1", status_code: 200 }], vulnerabilities: [{ url: "https://t.example/api/1/1", kind: "idor" }] });
    const view = graphContextView(state, { maxNodes: 30, maxEdges: 40 });
    expect(view.nodes.length).toBeLessThanOrEqual(30);
    expect(view.truncated.nodes).toBeGreaterThan(0);
    expect(view.vulns.length).toBeGreaterThan(0);
    expect(view.counts.nodes).toBe(Object.keys(state.nodes).length);
    // 漏洞节点必须排在最前（不能被裁剪掉）
    expect(view.nodes[0]!.status === "vulnerable" || view.nodes[0]!.type === "identity").toBe(true);
  });

  it("视图体积可控：500 节点也压得进 prompt", () => {
    const state = fresh();
    for (let index = 0; index < MAX_NODES; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: `https://t.example/api/res${index}/detail`, status_code: 200, params: ["id", "sign"] }] });
    }
    const size = JSON.stringify(graphContextView(state)).length;
    expect(size).toBeLessThan(20000);
  });

  it("空图返回空壳（老 checkpoint 不炸）", () => {
    const view = graphContextView(fresh());
    expect(view).toMatchObject({ nodes: [], edges: [], hypotheses: [], dead_ends: [] });
    expect(graphState({ version: 2 } as never).version).toBe(1);
  });

  it("Mermaid 可渲染，且把死胡同标灰", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: "https://t.example/a" }] });
    for (let index = 0; index < DEAD_END_REPEATS; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/a", status_code: 403, blocked: true }] });
    }
    const mermaid = graphMermaid(state);
    expect(mermaid.startsWith("graph LR")).toBe(true);
    expect(mermaid).toContain("-->");
    expect(mermaid).toContain("classDef deadEnd");
  });

  it("Kill Chain 从漏洞节点反向走到入口", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: "https://t.example/checkout" }] });
    ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/checkout", to: "https://t.example/api/pay" }] });
    ingestToolResult(state, { tool: "http.diff", endpoints: [{ url: "https://t.example/api/pay", status_code: 200 }], vulnerabilities: [{ url: "https://t.example/api/pay", kind: "logic" }] });
    const vuln = Object.values(state.nodes).find(node => node.type === "vuln_state")!;
    const chain = killChain(state, vuln.id);
    expect(chain.length).toBeGreaterThan(1);
    expect(chain[chain.length - 1]).toBe(vuln.id);
    expect(chain[0]).toContain("t.example");
  });
});
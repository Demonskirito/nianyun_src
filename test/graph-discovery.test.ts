/**
 * 历程图纵深：发现物抽取 + discovered_from 边 + round/depth。
 *
 * 背景（2026-10-28，用户问"为什么攻击历程图还是一排由上到下的节点"）：
 *   实测那个 11 轮会话：42 节点 / 37 边，**全部**是 `navigates_to`，`parameter`/`vuln_state`/`identity` 各 0，
 *   最长链 2 个节点。渲染器没问题（dagre 早就配了 rankDir: LR），是数据侧只有一跳。
 *
 * 这组用例钉住的正是"为什么会只有一跳"的那几个坑。
 */
import { describe, expect, it } from "vitest";
import { discoveryOf, paramsOf, selfOf } from "../src/blackbox/graph/extract.js";
import { endpointNodeId, graphState, ingestToolResult } from "../src/blackbox/graph/builder.js";
import { graphVisualView } from "../src/blackbox/graph/visual.js";
import type { AttackGraphState } from "../src/blackbox/graph/types.js";

describe("发现物抽取：工具结果形状决定图有没有纵深", () => {
  it("recon.js_endpoints 的 items/js_files 被认出来（原来只认 data.urls）", () => {
    const result = discoveryOf({
      url: "https://h.test/",
      items: ["/api/user/info", "/api/push/list"],
      js_files: ["https://h.test/umi.js"],
      count: 2,
    });
    expect(result.self).toEqual(["https://h.test/"]);
    expect(result.found.map(item => item.url)).toEqual([
      "https://h.test/umi.js",
      "https://h.test/api/user/info",
      "https://h.test/api/push/list",
    ]);
    // items 是从 js 文件里抽出来的 → 父节点是 js 文件，不是页面。
    const apiItems = result.found.filter(item => item.kind === "item");
    expect(apiItems.every(item => item.via === "https://h.test/umi.js")).toBe(true);
  });

  it("browser.open 的 links/forms 被认成页面跳转", () => {
    const result = discoveryOf({
      url: "https://h.test/login",
      links: ["https://h.test/home", { href: "https://h.test/order" }],
      forms: [{ url: "https://h.test/api/login", method: "post" }],
    });
    expect(result.found.map(item => item.url)).toContain("https://h.test/home");
    expect(result.found.map(item => item.url)).toContain("https://h.test/order");
    expect(result.found.find(item => item.url === "https://h.test/home")?.kind).toBe("link");
  });

  it("相对路径按本次调用的 URL 补全，绝对 URL 原样保留", () => {
    const result = discoveryOf({ url: "https://h.test/app/", items: ["/flag.php", "https://cdn.test/x.js"] });
    expect(result.found.map(item => item.url)).toEqual(["https://h.test/flag.php", "https://cdn.test/x.js"]);
  });

  it("参数从请求里取（query + json body），不是从响应里猜", () => {
    expect(paramsOf({ url: "https://h.test/api/user?id=1&role=admin" }, "https://h.test/api/user?id=1&role=admin"))
      .toEqual(["id", "role"]);
    expect(paramsOf({ url: "https://h.test/api/user", json: { order_id: 1, price: 2 } })).toEqual(["order_id", "price"]);
  });

  it("selfOf 只认响应里真正作用的 URL，且去重", () => {
    expect(selfOf({ url: "https://h.test/a", final_url: "https://h.test/b", urls: ["https://h.test/c"] }))
      .toEqual(["https://h.test/a", "https://h.test/b"]);
  });
});

describe("ingest：discovered_from 边与深度", () => {
  function fresh(): AttackGraphState {
    return graphState(undefined);
  }

  it("有父节点时生成 discovered_from，而不是把所有端点挂到 asset 上", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "recon.content_discovery",
      round: 1,
      endpoints: [{ url: "https://h.test/", requested: true, status_code: 200 }],
      evidence_id: "ev-1",
    });
    ingestToolResult(state, {
      tool: "recon.content_discovery",
      round: 1,
      parent: endpointNodeId("https://h.test/"),
      endpoints: [{ url: "https://h.test/flag.php" }],
      evidence_id: "ev-2",
    });
    const edges = state.edges.map(edge => `${edge.type}:${edge.source_id}->${edge.target_id}`);
    expect(edges).toContain("discovered_from:ep:h.test/->ep:h.test/flag.php");
    expect(state.nodes["ep:h.test/flag.php"]?.depth).toBe(2);
  });

  it("via（中间容器）优先于本次调用页面：页面 → js → 接口 是三跳", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "browser.open", round: 1, endpoints: [{ url: "https://h.test/", requested: true }] });
    ingestToolResult(state, {
      tool: "recon.js_endpoints",
      round: 2,
      parent: endpointNodeId("https://h.test/"),
      endpoints: [
        { url: "https://h.test/umi.js", via: "https://h.test/" },
        { url: "https://h.test/api/user/info", via: "https://h.test/umi.js" },
      ],
    });
    expect(state.nodes["ep:h.test/umi.js"]?.depth).toBe(2);
    expect(state.nodes["ep:h.test/api/user/info"]?.depth).toBe(3);
    expect(state.nodes["ep:h.test/api/user/info"]?.round).toBe(2);
  });

  it("已请求过的端点不会被后来的 200 打回 depth 1（第一次实现就是在这里翻车）", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "browser.open", round: 1, endpoints: [{ url: "https://h.test/", requested: true }] });
    ingestToolResult(state, {
      tool: "recon.content_discovery",
      round: 2,
      parent: endpointNodeId("https://h.test/"),
      endpoints: [{ url: "https://h.test/api/user/info" }],
    });
    expect(state.nodes["ep:h.test/api/user/info"]?.depth).toBe(2);
    // 之后真的去请求它：只有状态变 testing，深度不许退回 1。
    ingestToolResult(state, {
      tool: "http.request",
      round: 3,
      parent: endpointNodeId("https://h.test/api/user/info"),
      endpoints: [{ url: "https://h.test/api/user/info", requested: true, status_code: 200 }],
    });
    expect(state.nodes["ep:h.test/api/user/info"]?.depth).toBe(2);
    expect(state.nodes["ep:h.test/api/user/info"]?.status).toBe("testing");
  });

  it("状态迁移：请求过 = testing，401 = blocked，漏洞 = vulnerable + vuln_state 节点", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      round: 1,
      endpoints: [{ url: "https://h.test/a", requested: true, status_code: 200 }],
    });
    ingestToolResult(state, {
      tool: "http.request",
      round: 1,
      endpoints: [{ url: "https://h.test/b", requested: true, status_code: 403, blocked: true }],
    });
    ingestToolResult(state, {
      tool: "http.request",
      round: 1,
      endpoints: [{ url: "https://h.test/c", requested: true, status_code: 200 }],
      vulnerabilities: [{ url: "https://h.test/c", kind: "open_redirect" }],
    });
    expect(state.nodes["ep:h.test/a"]?.status).toBe("testing");
    expect(state.nodes["ep:h.test/b"]?.status).toBe("blocked");
    expect(state.nodes["ep:h.test/c"]?.status).toBe("vulnerable");
    expect(Object.keys(state.nodes).some(id => id.startsWith("vuln:open_redirect@"))).toBe(true);
  });

  it("parameter 节点从请求参数来（原来 11 轮 0 个）", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      round: 1,
      endpoints: [{ url: "https://h.test/api/user?id=1", requested: true, status_code: 200, params: ["id"] }],
    });
    expect(state.nodes["param:h.test/api/user#id"]?.type).toBe("parameter");
    expect(state.stats.by_type.parameter).toBe(1);
  });
});

describe("可视化视图带 round/depth 供历程布局使用", () => {
  it("节点输出 round/depth，边输出 edge-discovery 类", () => {
    const state = graphState(undefined);
    ingestToolResult(state, { tool: "browser.open", round: 1, endpoints: [{ url: "https://h.test/", requested: true }] });
    ingestToolResult(state, {
      tool: "recon.content_discovery",
      round: 4,
      parent: endpointNodeId("https://h.test/"),
      endpoints: [{ url: "https://h.test/flag.php" }],
    });
    const view = graphVisualView(state);
    const child = view.nodes.find(node => node.id === "ep:h.test/flag.php")!;
    expect(child.round).toBe(4);
    expect(child.depth).toBe(2);
    expect(view.edges.some(edge => edge.class === "edge-discovery")).toBe(true);
  });
});
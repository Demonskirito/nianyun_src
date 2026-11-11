/**
 * 无 host 的 link 端点（2026-11-04）。
 *
 * 实测背景：9cb376 会话的图里有 `ep:/` 这个节点 —— `properties: {}`、
 * `status: untested`、没有 origin，却带着 3 条边：
 *
 *   ep:/  →  ep:wanxiaozhi.aliyun.com/
 *   ep:/  →  ep:wanxiaozhi.aliyun.com/robots.txt
 *   ep:/  →  ep:wanxiaozhi.aliyun.com/qz7x-probe-nonexistent-9f3a.html
 *
 * 成因是 `desk` 在工具结果没带作用 URL 时传 `from: ""`，而 links 循环无条件
 * `endpointNodeId(link.from)`：`urlHost("")` 为空、`urlPath("")` 退化，
 * 于是产出 `ep:/`。它没有 host，永远打不到，却会被当成"入口页"参与路径规划。
 *
 * 同一段代码的第二个坑：相对 href（`/`、`/help/a.html`）没有按 from 补全，
 * 直接进 endpointNodeId 也是同一个畸形 id。
 */
import { describe, expect, it } from "vitest";
import { graphState, ingestToolResult, type IngestInput } from "../src/blackbox/graph/builder.js";
import { graphContextView } from "../src/blackbox/graph/serialize.js";

function ingest(input: Partial<IngestInput>) {
  const state = graphState(undefined);
  const result = ingestToolResult(state, { tool: "browser.open", ...input });
  return { state, result };
}

describe("links 的 from 为空时不得造出 ep:/", () => {
  it("from 为空只建 to，不建边、不建畸形节点", () => {
    const { state, result } = ingest({
      links: [{ from: "", to: "https://wanxiaozhi.aliyun.com/robots.txt", kind: "link" }],
    });
    expect(state.nodes["ep:/"]).toBeUndefined();
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/robots.txt"]).toBeDefined();
    expect(state.edges.length).toBe(0);
    expect(result.skipped.length).toBe(0);
  });

  it("from 是裸 host 时补全 scheme", () => {
    const { state } = ingest({
      links: [{ from: "wanxiaozhi.aliyun.com/", to: "https://wanxiaozhi.aliyun.com/help/a.html", kind: "link" }],
    });
    expect(state.nodes["ep:/"]).toBeUndefined();
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/help/a.html"]).toBeDefined();
    expect(state.edges.some(edge => edge.source_id === "ep:wanxiaozhi.aliyun.com/")).toBe(true);
  });
});

describe("相对 href 按 base 补全", () => {
  it("to= `/` 补到 from 的 host 根", () => {
    const { state } = ingest({
      links: [{ from: "https://wanxiaozhi.aliyun.com/help/a.html", to: "/", kind: "link" }],
    });
    expect(state.nodes["ep:/"]).toBeUndefined();
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/"]).toBeDefined();
  });

  it("from 为空时退回本次作用页面（parent 是节点 id）", () => {
    const { state } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/sitemap.xml",
      links: [{ from: "", to: "/help/intl/index.html", kind: "link" }],
    });
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/help/intl/index.html"]).toBeDefined();
    expect(state.nodes["ep:/help/intl/index.html"]).toBeUndefined();
  });

  it("既无 from 也无 parent：记 skipped(unresolvable)，不建节点", () => {
    const { state, result } = ingest({
      links: [{ from: "", to: "/help/a.html", kind: "link" }],
    });
    expect(Object.keys(state.nodes).filter(id => id.startsWith("ep:"))).toEqual([]);
    expect(result.skipped).toEqual([{ url: "/help/a.html", reason: "unresolvable", anchor: "" }]);
  });

  it("api_calls 同样不造无 host 节点", () => {
    const { state } = ingest({
      api_calls: [{ from: "", to: "https://api.example-sso.com/login", kind: "api" }],
    });
    expect(state.nodes["ep:/"]).toBeUndefined();
    expect(state.nodes["ep:api.example-sso.com/login"]).toBeDefined();
    expect(state.edges.length).toBe(0);
  });
});

describe("sitemap / robots 的声明来源要进节点属性", () => {
  /**
   * `FoundUrl.source` 此前在 desk 组装 ingest 入参时被丢掉，
   * 图上只剩 `discovery_kind: "link"` —— 复盘时分不清"站点自报的 18 个 /help 页"
   * 和"首页导航栏里的外链"。这条属性是下一轮"业务面入图了没有"的判定依据。
   */
  it("endpoints 上的 source 落到节点属性", () => {
    const { state } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/sitemap.xml",
      endpoints: [{ url: "https://wanxiaozhi.aliyun.com/help/intl/index.html", origin: "link", source: "sitemap" }],
    });
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/help/intl/index.html"]?.properties.source).toBe("sitemap");
  });

  it("links 上的 source 落到 to 节点属性", () => {
    const { state } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/robots.txt",
      links: [{ from: "https://wanxiaozhi.aliyun.com/robots.txt", to: "https://wanxiaozhi.aliyun.com/admin/", kind: "link", source: "robots" }],
    });
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/admin"]?.properties.source).toBe("robots");
  });

  it("模型上下文里能看到 source（否则业务页与导航外链无从区分）", () => {
    const { state } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/sitemap.xml",
      endpoints: [{ url: "https://wanxiaozhi.aliyun.com/help/3039522.html", origin: "link", source: "sitemap" }],
    });
    const view = graphContextView(state, { maxNodes: 60 });
    const node = view.nodes.find(item => item.id === "ep:wanxiaozhi.aliyun.com/help/3039522.html");
    expect(node?.props?.source).toBe("sitemap");
    expect(view.field_legend.some(line => line.startsWith("source:"))).toBe(true);
  });
});

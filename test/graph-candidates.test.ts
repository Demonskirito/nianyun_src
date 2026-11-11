import { describe, expect, it } from "vitest";
import { candidatePathOf, discoveryOf, isCandidateTool } from "../src/blackbox/graph/extract.js";
import { graphSignals, connectedComponents } from "../src/blackbox/graph/analyze.js";
import { ingestToolResult } from "../src/blackbox/graph/builder.js";
import { EMPTY_GRAPH, type AttackGraphState } from "../src/blackbox/graph/types.js";

/**
 * 2026-10-28 support.oppo.com 事故回归：
 * 一次 content_discovery 的 113 条命中被当成 113 个端点写进图，而它们只有
 * `discovered_from` 边（不在 WALKABLE 里），于是连通分量从 1 块变成 120 块，
 * Observer 连续 8 轮催 Agent 去打 flag.php / flag.txt —— 全是字典条目。
 *
 * 契约：暴力枚举的命中是「候选路径」，挂在父节点上；只有真打过才建节点。
 */

const bruteForceResult = (count: number): Record<string, unknown> => ({
  url: "https://support.oppo.com",
  target: "https://support.oppo.com",
  count,
  items: Array.from({ length: count }, (_, index) => `/probe-${index}.bak`),
});

describe("暴力枚举结果不再进图（support.oppo.com 回归）", () => {
  it("识别候选工具", () => {
    expect(isCandidateTool("recon.content_discovery")).toBe(true);
    expect(isCandidateTool("recon.api_routes")).toBe(true);
    expect(isCandidateTool("http.request")).toBe(false);
    expect(isCandidateTool("katana.crawl")).toBe(false);
  });

  it("候选路径归一成 /path", () => {
    expect(candidatePathOf("https://support.oppo.com/.env~")).toBe("/.env~");
    expect(candidatePathOf("/admin.jsp", "https://support.oppo.com/cn/")).toBe("/admin.jsp");
  });

  it("113 条命中写进父节点 candidates，不新建端点节点", () => {
    const graph: AttackGraphState = { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
    // 先建一个真实请求过的父节点
    ingestToolResult(graph, {
      tool: "http.request",
      round: 1,
      endpoints: [{ url: "https://support.oppo.com/", requested: true, status_code: 200 }],
    });
    const before = Object.keys(graph.nodes).length;

    const data = bruteForceResult(113);
    const discovery = discoveryOf(data);
    const ingested = ingestToolResult(graph, {
      tool: "recon.content_discovery",
      round: 2,
      parent: "ep:support.oppo.com/",
      candidates: discovery.found.map(item => ({ url: candidatePathOf(item.url, "https://support.oppo.com/") })),
    });

    expect(discovery.found).toHaveLength(113);
    expect(ingested.newNodes).toHaveLength(0);
    expect(ingested.candidates).toHaveLength(113);
    expect(Object.keys(graph.nodes)).toHaveLength(before);

    const anchor = graph.nodes["ep:support.oppo.com/"]!;
    expect(anchor.properties.candidate_count).toBe(113);
    expect(anchor.properties.candidates![0]).toBe("/probe-0.bak");

    // 连通分量不裂：资产 + 端点仍是一块
    expect(connectedComponents(graph).length).toBe(1);
  });

  it("candidates 去重且有上限（200）", () => {
    const graph: AttackGraphState = { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
    ingestToolResult(graph, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/", requested: true }],
    });
    const ingest = (urls: string[]) => ingestToolResult(graph, {
      tool: "recon.content_discovery",
      parent: "ep:t.example/",
      candidates: urls.map(url => ({ url })),
    });
    ingest(["/a", "/a", "/b"]);
    expect(graph.nodes["ep:t.example/"]!.properties.candidate_count).toBe(2);
    ingest(Array.from({ length: 300 }, (_, index) => `/bulk-${index}`));
    expect(graph.nodes["ep:t.example/"]!.properties.candidate_count).toBe(200);
  });

  it("漂移提醒不再把未验证的候选当 Root", () => {
    const graph: AttackGraphState = { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
    ingestToolResult(graph, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/", requested: true, status_code: 200 }],
    });
    // 造 50 个"没有状态码"的孤立端点：等价于旧行为（命中直接建节点）
    for (let index = 0; index < 50; index++) {
      // parent 是端点 → 只记 discovered_from（不在 WALKABLE 里）→ 自己成一个分量，
      // 与旧行为下"113 条命中各成一块"同构。区别是它们没有状态码（未验证）。
      ingestToolResult(graph, { tool: "manual", parent: "ep:t.example/", endpoints: [{ url: `https://t.example/ghost-${index}` }] });
    }
    // 最近活动都在 home 块
    const signals = graphSignals(graph, ["ep:t.example/", "ep:t.example/", "ep:t.example/"], { minRounds: 3 });
    expect(signals.some(signal => signal.kind === "component_drift")).toBe(false);
  });

  it("验证过但没打的端点仍然算 Root（提醒不能被一起禁掉）", () => {
    const graph: AttackGraphState = { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
    ingestToolResult(graph, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/", requested: true, status_code: 200 }],
    });
    // 2026-10-31：asset 节点现在会与自己的端点连边，同一 host 的端点算一块，
    // "漂移"只在**另一个 host**还有已验证未测面时才提醒。
    ingestToolResult(graph, {
      tool: "manual",
      endpoints: [{ url: "https://other.example/api/users", status_code: 204 }],
    });
    const signals = graphSignals(graph, ["ep:t.example/", "ep:t.example/", "ep:t.example/"], { minRounds: 3 });
    const drift = signals.find(signal => signal.kind === "component_drift");
    expect(drift).toBeDefined();
    // ④ 2026-11-07：root 转成可执行的完整 URL，不再把图节点 id 原样丢给模型照抄。
    expect(drift!.data!.roots).toContain("https://other.example/api/users");
    expect(drift!.data!.roots).not.toContain("ep:other.example/api/users");
  });
});
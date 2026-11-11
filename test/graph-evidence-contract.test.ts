/**
 * 证据契约（2026-11-03）——攻击历程图的**事实层**。
 *
 * 起因：`desk.ts` 原来把 `[url, final_url, target, ...data.urls]` 整批标成
 * `requested: true / origin: "request"`。而 `katana.crawl` 的 `data.urls` 是爬虫在 HTML 里
 * **看到**的链接（一次最多 500 条，含全部跨域外链）。后果链：
 *   builder 状态推到 testing → `cannotLocateObject()` 不再对 404 生成越权假设 →
 *   `verified()` 把这些节点算成"没动过的块" → 证据增益被假新端点灌满。
 *
 * 这组用例钉住两条不变量：
 *   1. `origin === "request"` ⟺ `requested === true`；
 *   2. `origin === "request"` 必须带 status_code，或显式 status_unknown。
 */
import { describe, expect, it } from "vitest";
import { BLACKBOX_TOOL_NAMES } from "../src/blackbox/tools.js";
import {
  DISCOVERY_TOOLS, NETWORKLESS_TOOLS, PROBE_TOOLS, RESPONSE_TOOLS,
  assertEvidenceContract, attributeEvidence, toolEvidenceClass,
} from "../src/blackbox/graph/evidence.js";
import { endpointNodeId, graphState, ingestToolResult } from "../src/blackbox/graph/builder.js";
import type { AttackGraphState } from "../src/blackbox/graph/types.js";

function fresh(): AttackGraphState {
  return graphState(undefined);
}

/** 复刻 desk 的搬运方式：归因结果原样灌进 builder。 */
function ingestAttribution(
  state: AttackGraphState,
  args: { tool: string; data: Record<string, unknown>; input?: Record<string, unknown>; fallbackUrl?: string; parent?: string },
) {
  const attribution = attributeEvidence({
    tool: args.tool, data: args.data, input: args.input, fallbackUrl: args.fallbackUrl,
  });
  const ingested = ingestToolResult(state, {
    tool: args.tool,
    round: 1,
    ...(args.parent ? { parent: args.parent } : {}),
    endpoints: [
      ...attribution.requests.map(item => ({
        url: item.url, requested: true, origin: "request" as const,
        ...(item.status_unknown === true ? { status_unknown: true } : {}),
        ...(item.status_code !== undefined ? { status_code: item.status_code } : {}),
      })),
      ...attribution.discovery.found.map(item => ({
        url: item.url, origin: "discovery" as const, discovery_kind: item.kind,
        ...(item.status !== undefined ? { status_code: item.status } : {}),
      })),
    ],
    evidence_id: "ev-1",
  });
  return { attribution, ingested };
}

describe("归因表覆盖全部 75 个工具", () => {
  it("四个集合互不重叠，且并集等于工具清单", () => {
    const groups = [RESPONSE_TOOLS, PROBE_TOOLS, DISCOVERY_TOOLS, NETWORKLESS_TOOLS];
    const all = groups.flatMap(group => [...group]);
    expect(new Set(all).size, "同一个工具被归进了两个集合").toBe(all.length);
    expect(new Set(all), "归因表漏了工具或多出了不存在的工具").toEqual(new Set(BLACKBOX_TOOL_NAMES));
    expect(all.length).toBe(75);
  });

  it("每类工具拿到正确的等级", () => {
    expect(toolEvidenceClass("http.request")).toBe("response");
    expect(toolEvidenceClass("katana.crawl")).toBe("discovery");
    expect(toolEvidenceClass("recon.nuclei")).toBe("probe");
    expect(toolEvidenceClass("fs.read")).toBe("none");
    // 未登记的名字一律 none：宁可少记，不可错记。
    expect(toolEvidenceClass("some.future.tool")).toBe("none");
  });
});

describe("katana.crawl 不得产出 requested:true", () => {
  it("urls 全部是 discovery，状态停在 untested，且不复制爬虫元信息", () => {
    const state = fresh();
    const { attribution } = ingestAttribution(state, {
      tool: "katana.crawl",
      data: {
        target: "https://a.test/",
        urls: ["https://a.test/x", "https://a.test/api/user/1", "https://evil.test/z"],
        items: ["https://a.test/x", "https://a.test/api/user/1", "https://evil.test/z"],
        count: 3,
      },
      input: { url: "https://a.test/" },
      parent: endpointNodeId("https://a.test/"),
    });

    expect(attribution.requests).toHaveLength(0);
    for (const id of ["ep:a.test/x", "ep:a.test/api/user/{id}"]) {
      const node = state.nodes[id]!;
      expect(node, id).toBeDefined();
      expect(node.properties.origin, id).toBe("discovery");
      expect(node.status, id).toBe("untested");
      expect(node.properties.status_code, id).toBeUndefined();
    }
    // 跨域外链不进图（不撑 500 上限），但必须留痕。
    expect(state.nodes["ep:evil.test/z"]).toBeUndefined();
    expect(attribution.discovery.found.some(item => item.url === "https://evil.test/z")).toBe(true);
  });
});

describe("browser.open：主页面是请求，链接是发现", () => {
  it("final_url 带真实状态码；links 进图但不叫 requested", () => {
    const state = fresh();
    const { attribution } = ingestAttribution(state, {
      tool: "browser.open",
      data: {
        requested_url: "https://a.test/login",
        final_url: "https://a.test/home",
        status: 200,
        links: [{ text: "order", href: "https://a.test/order" }, { text: "外链", href: "https://other.org/x" }],
        forms: [],
      },
      input: { url: "https://a.test/login" },
      parent: endpointNodeId("https://a.test/login"),
    });

    // 主证据只认 final_url（跟随重定向后的落点），不把 requested_url 也算一次响应。
    expect(attribution.requests.map(item => item.url)).toEqual(["https://a.test/home"]);
    expect(attribution.requests[0]!.status_code).toBe(200);

    const home = state.nodes["ep:a.test/home"]!;
    expect(home.status).toBe("testing");
    expect(home.properties.origin).toBe("request");
    expect(home.properties.status_code).toBe(200);

    const order = state.nodes["ep:a.test/order"]!;
    expect(order.status).toBe("untested");
    expect(order.properties.origin).toBe("discovery");
    expect(order.properties.discovery_kind).toBe("link");
    // 没请求过就不编状态码——这是旧代码最要命的一处。
    expect(order.properties.status_code).toBeUndefined();

    // 跨域链接：被 scope 挡下，但要带 reason/anchor/parent 记进 skipped。
    expect(state.nodes["ep:other.org/x"]).toBeUndefined();
  });

  it("skipped 带 reason / anchor / parent，而不是静默丢弃", () => {
    const state = fresh();
    const { ingested } = ingestAttribution(state, {
      tool: "browser.open",
      data: {
        final_url: "https://a.test/",
        status: 200,
        links: ["https://a.test/ok", "https://other.org/no"],
      },
      input: { url: "https://a.test/" },
      parent: endpointNodeId("https://a.test/"),
    });
    expect(state.nodes["ep:a.test/ok"]).toBeDefined();
    expect(ingested.skipped).toContainEqual(
      expect.objectContaining({ url: "https://other.org/no", reason: "out_of_scope", anchor: "a.test" }),
    );
  });
});

describe("probe 类工具：确实发过包，但拿不到状态码", () => {
  it("recon.nuclei 的 matched-at 是 request + status_unknown，不编 200", () => {
    const state = fresh();
    const { attribution } = ingestAttribution(state, {
      tool: "recon.nuclei",
      data: {
        target: "https://a.test/x?id=1",
        items: ["https://a.test/x?id=1"],
        findings: [{ url: "https://a.test/x?id=1", template_id: "cve-2024-0001", severity: "high" }],
      },
      input: { url: "https://a.test/x?id=1" },
    });

    expect(attribution.requests).toHaveLength(1);
    expect(attribution.requests[0]!.status_unknown).toBe(true);
    expect(attribution.requests[0]!.status_code).toBeUndefined();
    // 已经算作请求的 URL 不再重复标成 discovery。
    expect(attribution.discovery.found.some(item => item.url === "https://a.test/x?id=1")).toBe(false);

    const node = state.nodes["ep:a.test/x"]!;
    expect(node.status).toBe("testing");
    expect(node.properties.origin).toBe("request");
    expect(node.properties.status_code).toBeUndefined();
  });
});

describe("http.diff：两次请求都是真的", () => {
  it("baseline 与 variant 各带自己的状态码", () => {
    const attribution = attributeEvidence({
      tool: "http.diff",
      data: {
        url: "https://a.test/api/order/1",
        variant_url: "https://a.test/api/order/1",
        baseline: { status: 403, body_bytes: 120 },
        variant: { status: 200, body_bytes: 4096 },
        verdict: "different",
      },
      input: { url: "https://a.test/api/order/1" },
    });
    expect(attribution.requests).toHaveLength(1);
    // 同址两次（baseline 403 → variant 200）：节点记**最后一次**响应——
    // 越权对照里有意义的是"换凭证之后"的那次。
    expect(attribution.requests[0]!.status_code).toBe(200);
  });
});

describe("请求失败（超时/连接被拒）不得抛错", () => {
  it("http.request 没有 status 时落 status_unknown，而不是让契约守卫炸掉工具循环", () => {
    // 2026-11-03 实测回归：这条路径一旦抛错，会被 desk 的工具循环吞成 tool-error，
    // 连带把 stage 记账、action-deferred 事件全部改掉（blackbox-tool-access 三条用例当场变红）。
    const attribution = attributeEvidence({
      tool: "http.request",
      data: { url: "https://a.test/slow", headers: {}, body: "", body_bytes: 0 },
      input: { url: "https://a.test/slow" },
    });
    expect(attribution.requests).toHaveLength(1);
    expect(attribution.requests[0]!.status_unknown).toBe(true);

    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: attribution.requests.map(item => ({
        url: item.url, requested: true, origin: "request" as const, status_unknown: true,
      })),
    });
    expect(state.nodes["ep:a.test/slow"]!.status).toBe("testing");
    expect(state.nodes["ep:a.test/slow"]!.properties.status_code).toBeUndefined();
  });

  it("工具结果里没有 URL 时不产出任何证据（不编节点）", () => {
    const attribution = attributeEvidence({
      tool: "http.request",
      data: { error: "connect ECONNREFUSED" },
      input: {},
    });
    expect(attribution.requests).toEqual([]);
  });
});

describe("契约守卫：写错归因会炸，而不是悄悄污染图", () => {  it("requested=true 但 origin=discovery → 抛错", () => {
    expect(() => assertEvidenceContract({
      url: "https://x.test/", origin: "discovery", requested: true,
    })).toThrow(/contract violation/);
  });

  it("origin=request 但 requested=false → 抛错", () => {
    expect(() => assertEvidenceContract({
      url: "https://x.test/", origin: "request", requested: false, status_code: 200,
    })).toThrow(/contract violation/);
  });

  it("origin=request 但没有状态码也没有 status_unknown → 抛错", () => {
    expect(() => assertEvidenceContract({
      url: "https://x.test/", origin: "request", requested: true,
    })).toThrow(/contract violation/);
  });

  it("builder 对新式调用方（显式 origin=request）执行同一套守卫", () => {
    const state = fresh();
    expect(() => ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://a.test/x", origin: "request", requested: true }],
    })).toThrow(/contract violation/);
  });

  it("旧调用方（只传 requested，没有 origin）仍被归一，不炸会话", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "recon.content_discovery",
      endpoints: [{ url: "https://a.test/x", requested: true }],
    });
    expect(state.nodes["ep:a.test/x"]!.status).toBe("testing");
    expect(state.nodes["ep:a.test/x"]!.properties.origin).toBe("request");
  });
});

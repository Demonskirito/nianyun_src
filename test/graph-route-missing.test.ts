import { describe, expect, it } from "vitest";
import { routeMissingOf } from "../src/blackbox/graph/extract.js";
import {
  activeHypotheses, applyHypotheses, deriveHypotheses, endpointNodeId, graphState, ingestToolResult,
} from "../src/blackbox/graph/index.js";

/**
 * 2026-11-02 m.ctrip.com 会话（`20770876a584cbc1`）暴露的白跑：
 *
 *   agent 为了验 catch-all，自己造了 `POST /restapi/soa2/z9probe_notexist/1` 与 `/2`，
 *   网关回 `404 {"statusMsg":"Not-Found-Route","cause":"NotFoundRouteException(...)"}`。
 *   两条探测 URL 被模板成 `.../z9probe_notexist/{id}`，图按"带对象 id 的接口"派生了
 *   `H_idor_47aed713`，于是又派任务、又烧 3 轮去证明它是虚构路由。
 *
 * 这里把证据门钉死：**网关自己说没这条路由**的端点不得生成越权/鉴权墙假设；
 * 判据取证据（正文指纹 / 空壳 404），不猜路径名。
 */

const NOT_FOUND_BODY = '{"statusMsg":"Not-Found-Route","cause":"NotFoundRouteException(Not-Found-Route,Can\'t-found-the-route-of-the-request.)","rootMessageId":"100025527-0a7d3707","statusCode":"404"}';

describe("routeMissingOf：路由不存在判定", () => {
  it("网关 Not-Found-Route 信封 = 路由不存在", () => {
    expect(routeMissingOf({ status: 404, body: NOT_FOUND_BODY })).toBe(true);
  });

  it("未知 appid 的 unknown host 也算路由不存在", () => {
    expect(routeMissingOf({ status: 404, body: "unknown host" })).toBe(true);
  });

  it("200 正常响应不是路由不存在", () => {
    expect(routeMissingOf({ status: 200, body: "{\"ok\":true}" })).toBe(false);
  });

  it("空壳 404（正文极小）判为路由不存在", () => {
    expect(routeMissingOf({ status: 404, body: "", content_length: 0 })).toBe(true);
  });

  it("大正文 404 不判（可能是 SPA 软 404 页面，也可能是未登录时故意隐藏的端点）", () => {
    expect(routeMissingOf({ status: 404, body: "<html>" + "x".repeat(2048) + "</html>" })).toBe(false);
  });

  it("401 不是路由不存在（那是鉴权墙的事）", () => {
    expect(routeMissingOf({ status: 401, body: "unauthorized" })).toBe(false);
  });
});

describe("假设生成：路由不存在的 {id} 端点不生成越权假设", () => {
  const url = "https://t.example/restapi/soa2/36018/queryCookieBWList/{id}";

  /** 造一个只有该端点的图；routeMissing 决定要不要带证据标记。 */
  function graphWithProbe(routeMissing: boolean) {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{
        url, requested: true, status_code: 404,
        ...(routeMissing ? { route_missing: true } : {}),
      }],
    });
    return state;
  }

  it("带 route_missing：不派生 idor 假设", () => {
    const state = graphWithProbe(true);
    const hypotheses = deriveHypotheses(state);
    expect(hypotheses.some(item => item.kind === "idor")).toBe(false);
  });

  it("同样 404 但没有路由不存在证据：仍可派生（门是证据驱动，不是状态码驱动）", () => {
    const state = graphWithProbe(false);
    const hypotheses = deriveHypotheses(state);
    expect(hypotheses.some(item => item.kind === "idor")).toBe(true);
  });

  it("已经进 state 的 idor 假设，端点后被证明不存在时不再活跃", () => {
    const state = graphWithProbe(false);
    applyHypotheses(state, deriveHypotheses(state));
    expect(activeHypotheses(state).length).toBeGreaterThan(0);
    // 后来的真实请求证明这条路由不存在
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, requested: true, status_code: 404, route_missing: true }],
    });
    expect(activeHypotheses(state).some(item => item.kind === "idor")).toBe(false);
  });

  it("后来真的返回 200：route_missing 被清掉，假设恢复可能", () => {
    const state = graphWithProbe(true);
    const id = endpointNodeId(url);
    expect(state.nodes[id]?.properties.route_missing).toBe(true);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, requested: true, status_code: 200, content_length: 120 }],
    });
    expect(state.nodes[id]?.properties.route_missing).toBe(false);
    expect(deriveHypotheses(state).some(item => item.kind === "idor")).toBe(true);
  });
});

/**
 * 2026-11-02 干净 e2e（会话 `b9601629efd1f137`）暴露的真缺口：
 *
 * 上一轮只给"本次真打过"的路径算 `routeMissingOf()`，而 burp.history 这类被动发现
 * 只带 `status_code`、没有正文。于是上一场自己造的 `z9probe_notexist/{id}` 仍躺在 Burp
 * history 里，本场作为"发现的端点"重新入图（status_code=404 / untested / 无 route_missing），
 * 修好的门一次都没生效，`H_idor_47aed713`、`H_object_enum_0458205c` 照旧被派生出来。
 *
 * 契约：被动发现（origin≠"request"）且唯一观测就是 404/410 的端点，不得成为越权/枚举假设的锚点；
 * 一旦本次真的打它并拿到 <400，假设恢复可能（`origin` 变成 "request"）。
 */
describe("被动发现的 404 端点：不派生越权假设（burp.history 污染）", () => {
  const url = "https://t.example/restapi/soa2/z9probe_notexist/{id}";

  it("burp.history 灌进来的 404 端点（无正文、无 route_missing）不派生 idor/object_enum", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "burp.history",
      endpoints: [{ url, origin: "link", status_code: 404 }],
    });
    const id = endpointNodeId(url);
    expect(state.nodes[id]?.properties.status_code).toBe(404);
    expect(state.nodes[id]?.properties.route_missing).toBeUndefined();
    const kinds = deriveHypotheses(state).map(item => item.kind);
    expect(kinds).not.toContain("idor");
    expect(kinds).not.toContain("object_enum");
  });

  it("本场真打过且返回 200：同一 {id} 路径恢复派生能力", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "burp.history",
      endpoints: [{ url, origin: "link", status_code: 404 }],
    });
    expect(deriveHypotheses(state).some(item => item.kind === "idor")).toBe(false);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, requested: true, status_code: 200, content_length: 900 }],
    });
    expect(deriveHypotheses(state).some(item => item.kind === "idor")).toBe(true);
  });

  it("被动 403 不受影响：那是鉴权墙，仍可派生", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "burp.sitemap",
      endpoints: [{ url: "https://t.example/api/order/{id}", origin: "link", status_code: 403 }],
    });
    const kinds = deriveHypotheses(state).map(item => item.kind);
    expect(kinds).toContain("idor");
  });
});

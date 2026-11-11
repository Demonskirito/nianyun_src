import { describe, expect, it } from "vitest";
import { analyzeTraffic, pathTemplate, trafficSummaryLine, type HistoryEntry } from "../src/blackbox/traffic.js";

const entry = (patch: Partial<HistoryEntry>): HistoryEntry => ({
  entry_id: `proxy:${String(Math.random()).slice(2, 18)}`,
  url: "https://t/api/x", method: "GET", status: 200, timestamp: 1_700_000_000_000, response_bytes: 100,
  content_type: "application/json", ...patch,
});

describe("Burp History 被动分析", () => {
  it("模板归一化：数字/UUID/长 hex 折叠成占位符", () => {
    expect(pathTemplate("/api/user/123/orders/9f8a1b2c3d4e5f60")).toBe("/api/user/{n}/orders/{hex}");
    expect(pathTemplate("/u/550e8400-e29b-41d4-a716-446655440000/x")).toBe("/u/{uuid}/x");
    expect(pathTemplate("/static/app.js")).toBe("/static/app.js");
  });

  it("识别 WAF 拦截：同模板 ≥3 条 403 且响应体大小完全相同", () => {
    const entries = [1, 2, 3].map(index => entry({ url: `https://t/api/upload?f=${index}`, status: 403, response_bytes: 512 }));
    const analysis = analyzeTraffic(entries);
    const waf = analysis.signals.find(signal => signal.code === "waf_suspected");
    expect(waf).toBeTruthy();
    expect(waf?.action).toMatch(/burp\.entry/);
    expect(waf?.detail).toMatch(/403/);
  });

  it("识别鉴权墙：连续 401 达到 3 条", () => {
    const entries = [1, 2, 3, 4].map(index => entry({ url: `https://t/api/admin/${index}`, status: index <= 3 ? 401 : 200 }));
    const analysis = analyzeTraffic(entries);
    expect(analysis.auth_streak).toEqual({ code: 401, length: 3 });
    expect(analysis.signals.map(signal => signal.code)).toContain("authwall");
  });

  it("识别易变参数（签名/nonce），并指出该转特种兵", () => {
    const entries = ["aaa", "bbb", "ccc"].map(value => entry({ url: `https://t/api/pay?sign=${value}&id=1` }));
    const analysis = analyzeTraffic(entries);
    const volatile = analysis.signals.find(signal => signal.code === "volatile_param");
    expect(volatile?.detail).toMatch(/sign/);
    expect(volatile?.action).toMatch(/特种兵/);
    // 追踪参数不应被当成签名
    const tracking = analyzeTraffic([entry({ url: "https://t/a?utm_source=x" }), entry({ url: "https://t/a?utm_source=y" })]);
    expect(tracking.volatile_params).toHaveLength(0);
  });

  it("识别静态基线点与尺寸方差", () => {
    const staticOnes = [1, 2, 3].map(() => entry({ url: "https://t/api/list", response_bytes: 900 }));
    expect(analyzeTraffic(staticOnes).signals.map(signal => signal.code)).toContain("static_response");
    const varied = [entry({ url: "https://t/api/order", response_bytes: 300 }), entry({ url: "https://t/api/order", response_bytes: 2400 })];
    expect(analyzeTraffic(varied).signals.map(signal => signal.code)).toContain("size_variance");
  });

  it("识别软 404：不同路径返回同一张 200 壳页", () => {
    const entries = [
      entry({ url: "https://t/", response_bytes: 7200, content_type: "text/html" }),
      entry({ url: "https://t/robots.txt", response_bytes: 7200, content_type: "text/html" }),
      entry({ url: "https://t/login", response_bytes: 7200, content_type: "text/html" }),
    ];
    const signal = analyzeTraffic(entries).signals.find(item => item.code === "soft_404");
    expect(signal).toBeTruthy();
    expect(signal?.action).toMatch(/假阳性/);
  });

  it("空历史不炸，摘要可读", () => {
    const analysis = analyzeTraffic([]);
    expect(analysis.total).toBe(0);
    expect(analysis.signals).toHaveLength(0);
    expect(trafficSummaryLine(analysis)).toContain("0 条");
  });

  it("摘要包含状态分布与信号名", () => {
    const entries = [1, 2, 3].map(index => entry({ url: `https://t/api/upload?f=${index}`, status: 403, response_bytes: 512 }));
    const line = trafficSummaryLine(analyzeTraffic(entries));
    expect(line).toContain("403×3");
    expect(line).toContain("waf_suspected");
  });
});
describe("路线清单与实现的漂移守卫", () => {
  it("prompt 里的每一步都来自 route-manifest（前端展示同一份）", async () => {
    const { ROUTE_STEPS, routePrompt, ROUTE_ANTIPATTERNS } = await import("../src/blackbox/route-manifest.js");
    const prompt = routePrompt();
    for (const step of ROUTE_STEPS) {
      expect(prompt).toContain(step.title);
      expect(prompt).toContain(step.detail.slice(0, 40));
    }
    expect(prompt).toContain(ROUTE_ANTIPATTERNS);
  });

  it("清单里承诺的 signal code 分析器必须真的能产出", async () => {
    const { ROUTE_SIGNALS } = await import("../src/blackbox/route-manifest.js");
    const promised = ROUTE_SIGNALS.map(signal => signal.code);
    // 用逐个构造的输入覆盖每个 code，确保 UI 上写的信号不是空头支票。
    const fixtures: Record<string, HistoryEntry[]> = {
      authwall: [1, 2, 3].map(index => entry({ url: `https://t/a/${index}`, status: 401 })),
      waf_suspected: [1, 2, 3].map(index => entry({ url: `https://t/u?f=${index}`, status: 403, response_bytes: 512 })),
      volatile_param: ["a", "b"].map(value => entry({ url: `https://t/p?sign=${value}` })),
      static_response: [1, 2, 3].map(() => entry({ url: "https://t/s", response_bytes: 900 })),
      size_variance: [entry({ url: "https://t/v", response_bytes: 100 }), entry({ url: "https://t/v", response_bytes: 900 })],
      soft_404: [entry({ url: "https://t/", response_bytes: 7200 }), entry({ url: "https://t/x", response_bytes: 7200 })],
      burst: [0, 1, 2, 3, 4].map(offset => entry({ timestamp: 1_700_000_000_000 + offset * 100 })),
      spa_shell: [1, 2, 3].map(index => entry({ url: `https://t/h/${index}`, content_type: "text/html", response_bytes: 7200 })),
    };
    for (const code of promised) {
      const produced = analyzeTraffic(fixtures[code] || []).signals.map(signal => signal.code);
      expect(produced, `signal ${code} 没有实现`).toContain(code);
    }
  });
});
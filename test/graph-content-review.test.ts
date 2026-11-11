/**
 * 业务面巡检假设 content_review（2026-11-05 第 3 批 ①）。
 *
 * 事故：站点在 sitemap 里自报 18 个 `/help/*.html`，全部入图（source=sitemap、untested），
 * 而两轮会话各 50 / 46 次工具调用里**一次都没访问过**。
 *
 * 诊断（用真实 checkpoint 跑 deriveHypotheses）：产出 7 条全是 auth_wall，锚 /help 的 0 条。
 * 不是 origin 过滤、也不是配额挤掉——`deriveHypotheses` 里根本没有"普通业务页"这一类规则：
 *   · 没有 {id} 段 → 不进 idor；
 *   · 没被拦（压根没请求）→ 不进 auth_wall；
 *   · 没有参数边 → 不进 data_flow；
 *   · 不是"发了包没拿到状态码"→ 不进 retest。
 */
import { describe, expect, it } from "vitest";
import { graphState, ingestToolResult } from "../src/blackbox/graph/builder.js";
import { applyHypotheses, deriveHypotheses } from "../src/blackbox/graph/hypotheses.js";
import { hypothesisTasks } from "../src/blackbox/hypothesis_tasks.js";
import type { Hypothesis } from "../src/blackbox/graph/types.js";

const HOST = "wanxiaozhi.aliyun.com";

/** 站点声明文件里解析出来的业务页：discovery + untested + 没有状态码。 */
function declared(page: string, source: "sitemap" | "robots" = "sitemap") {
  const state = graphState(undefined);
  ingestToolResult(state, {
    tool: "http.request",
    endpoints: [{ url: `https://${HOST}${page}`, origin: "link", source }],
  });
  return state;
}

const reviewsOf = (state: ReturnType<typeof graphState>) => deriveHypotheses(state, 1).filter(h => h.kind === "content_review");

describe("content_review：站点声明过、从没访问过的业务页要变成假设", () => {
  it("sitemap 页 → 生成 content_review，锚在该节点上", () => {
    const state = declared("/help/3039522.html");
    const reviews = reviewsOf(state);
    expect(reviews).toHaveLength(1);
    expect(reviews[0]!.nodes).toEqual([`ep:${HOST}/help/3039522.html`]);
    expect(reviews[0]!.severity).toBe("medium");
    // 文案要能指挥模型干活，不能只是"看一眼"
    expect(reviews[0]!.text).toContain("一次都没访问过");
    expect(reviews[0]!.text).toContain("API 路径");
  });

  it("robots 里 Disallow 出来的路径同样算站点声明", () => {
    const reviews = reviewsOf(declared("/admin/", "robots"));
    expect(reviews).toHaveLength(1);
  });

  it("静态资源与声明文件自身不生成（.js/.png/sitemap.xml/robots.txt）", () => {
    for (const page of ["/static/app.js", "/img/logo.png", "/sitemap.xml", "/robots.txt"]) {
      const state = declared(page);
      expect(reviewsOf(state), page).toHaveLength(0);
    }
  });

  it("已经拿到过响应的页面不生成（status_code 存在 = 访问过）", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: `https://${HOST}/help/3039522.html`, status_code: 200, content_length: 8000, origin: "request" }],
    });
    expect(reviewsOf(state)).toHaveLength(0);
  });

  it("普通导航发现（source 缺失）暂不生成——本批只管站点自报的业务面", () => {
    const state = graphState(undefined);
    ingestToolResult(state, { tool: "katana", endpoints: [{ url: `https://${HOST}/somewhere`, origin: "link" }] });
    expect(reviewsOf(state)).toHaveLength(0);
  });

  it("同一目录只抽 2 页（实测 18 个 /help 页全部 301 站外，全派是白烧 16 条）", () => {
    const state = graphState(undefined);
    const pages = Array.from({ length: 18 }, (_, index) => `/help/${3000000 + index}.html`);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: pages.map(page => ({ url: `https://${HOST}${page}`, origin: "link", source: "sitemap" as const })),
    });
    const reviews = reviewsOf(state);
    expect(reviews).toHaveLength(2);
    // 抽到的是浅路径里 id 最小的两页（确定性，不随机）
    expect(reviews.map(item => item.nodes[0])).toEqual([
      `ep:${HOST}/help/3000000.html`,
      `ep:${HOST}/help/3000001.html`,
    ]);
  });

  it("单轮最多 12 条（跨目录时生效，避免 sitemap 300 条全量灌入）", () => {
    const state = graphState(undefined);
    const pages = Array.from({ length: 40 }, (_, index) => `/dir${index}/page.html`);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: pages.map(page => ({ url: `https://${HOST}${page}`, origin: "link", source: "sitemap" as const })),
    });
    expect(reviewsOf(state)).toHaveLength(12);
  });
});

describe("content_review：配额与任务", () => {
  it("配额 8 个座位：12 条候选里 8 active、其余进冷宫（不丢）", () => {
    const state = graphState(undefined);
    const pages = Array.from({ length: 13 }, (_, index) => `/dir${index}/page.html`);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: pages.map(page => ({ url: `https://${HOST}${page}`, origin: "link", source: "sitemap" as const })),
    });
    const derived = deriveHypotheses(state, 1);
    // 单轮上限 12，配额 8
    applyHypotheses(state, derived, 1);
    const reviews = state.hypotheses.filter(item => item.kind === "content_review");
    expect(reviews.filter(item => item.status === "active")).toHaveLength(8);
    expect(reviews.filter(item => item.status === "evicted")).toHaveLength(4);
  });

  it("任务判据是「取正文 + 列新面」，不是越权的「替换 id」", () => {
    const state = declared("/help/3039522.html");
    const active = deriveHypotheses(state, 1);
    const specs = hypothesisTasks(active);
    expect(specs).toHaveLength(1);
    expect(specs[0]!.target).toBe(`https://${HOST}/help/3039522.html`);
    expect(String(specs[0]!.completion_criteria)).toContain("取回该页面真实正文");
    expect(String(specs[0]!.purpose)).not.toContain("替换 id/身份");
    expect(String(specs[0]!.fallback_strategy)).toContain("browser.open");
  });

  it("排在 auth_wall 之前（两轮实测 auth_wall 占满名额却一条没产出）", () => {
    const state = declared("/help/3039522.html");
    // 造一条 auth_wall：blocked 节点 + 活跃身份
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: `https://${HOST}/v2/api-docs`, status_code: 403, blocked: true, origin: "request" }],
    });
    state.nodes["id:analyst"] = { id: "id:analyst", type: "identity", status: "testing", properties: {}, discovered_by: "t", updated_at: 1 };
    const derived = deriveHypotheses(state, 1);
    expect(derived.some(item => item.kind === "auth_wall")).toBe(true);
    const specs = hypothesisTasks(derived, { limit: 1 });
    expect(specs).toHaveLength(1);
    expect(specs[0]!.id.startsWith("H_content_review_")).toBe(true);
  });

  it("同类同主机一批里最多派 2 条（3 个不同目录的候选也只派 2 条）", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [`/d1/a.html`, `/d2/b.html`, `/d3/c.html`].map(page => ({
        url: `https://${HOST}${page}`, origin: "link", source: "sitemap" as const,
      })),
    });
    const derived = deriveHypotheses(state, 1);
    // occupied 只看任务簿、看不到本批：本批必须自己计数，否则一次全派出去
    const tasks = hypothesisTasks(derived, { limit: 3 });
    expect(tasks).toHaveLength(2);
    expect(tasks.every(task => task.id.startsWith("H_content_review_"))).toBe(true);
  });
});

describe("hits：只有真的拿到响应才 +1", () => {
  it("sitemap 发现的页面 hits 不增（否则「没访问过」看起来像「访问过」）", () => {
    const state = declared("/help/3039522.html");
    expect(state.nodes[`ep:${HOST}/help/3039522.html`]!.properties.hits).toBeUndefined();
  });

  it("真发过请求的端点仍然累计", () => {
    const state = graphState(undefined);
    for (let index = 0; index < 3; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: `https://${HOST}/api/x`, status_code: 200 }] });
    }
    expect(state.nodes[`ep:${HOST}/api/x`]!.properties.hits).toBe(3);
  });

  it("发现与请求混在同一批时，只有带响应的那条 +1", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [
        { url: `https://${HOST}/help/a.html`, origin: "link", source: "sitemap" },
        { url: `https://${HOST}/`, status_code: 200 },
      ],
    });
    expect(state.nodes[`ep:${HOST}/help/a.html`]!.properties.hits).toBeUndefined();
    expect(state.nodes[`ep:${HOST}/`]!.properties.hits).toBe(1);
  });
});

describe("回归：不影响既有 kind", () => {
  it("idor 仍按 {id} + 可比响应生成", () => {
    const state = graphState(undefined);
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: `https://${HOST}/api/user/{id}`, status_code: 200, content_length: 900 }],
    });
    const kinds = new Set(deriveHypotheses(state, 1).map((item: Hypothesis) => item.kind));
    expect(kinds.has("content_review")).toBe(false);
  });
});

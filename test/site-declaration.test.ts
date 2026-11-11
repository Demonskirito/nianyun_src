/**
 * 站点声明文件引水（2026-11-05）。
 *
 * 实测背景：会话 5b59aa1d059b56da 的 `/sitemap.xml` 第一次抓取拿到 403，
 * 此后**再没重试**，站点自报的 18 个 `/help/*.html` 业务页整批丢失；
 * 而 09a67a8a9aa67cec 同一文件 200，18 页全部入图。
 *
 * 这个模块只做判定：哪些状态码算结论、什么时候该重试、重试怎么节流。
 * 派任务与钉焦点在 desk（ensureSiteDeclaration）。
 */
import { describe, expect, it } from "vitest";
import {
  classifyDeclaration, declarationNeed, declarationPathOf, declarationTaskSpec,
  recordDeclaration, SITE_DECLARATION_COOLDOWN_MS, SITE_DECLARATION_MAX_ATTEMPTS,
  type DeclarationHostState,
} from "../src/blackbox/site-declaration.js";

describe("declarationPathOf", () => {
  it("只认 robots.txt 与 sitemap.xml（大小写、查询串、index 变体都归一）", () => {
    expect(declarationPathOf("https://x.com/robots.txt")).toBe("/robots.txt");
    expect(declarationPathOf("https://x.com/Robots.TXT")).toBe("/robots.txt");
    expect(declarationPathOf("https://x.com/sitemap.xml")).toBe("/sitemap.xml");
    expect(declarationPathOf("https://x.com/sitemap.xml?ts=1730000000")).toBe("/sitemap.xml");
    expect(declarationPathOf("https://x.com/sitemap_index.xml")).toBe("/sitemap.xml");
  });

  it("别把业务页当声明文件", () => {
    expect(declarationPathOf("https://x.com/help/3039522.html")).toBeUndefined();
    expect(declarationPathOf("https://x.com/")).toBeUndefined();
    expect(declarationPathOf("https://x.com/sitemap.html")).toBeUndefined();
    expect(declarationPathOf("not a url")).toBeUndefined();
  });
});

describe("classifyDeclaration：什么才算结论", () => {
  it("200 且有正文 → ok", () => {
    expect(classifyDeclaration({ status: 200, bytes: 1927 })).toBe("ok");
  });

  it("200 但 sitemap 确实是空正文 → retry（空壳不是 sitemap）", () => {
    expect(classifyDeclaration({ status: 200, bytes: 0, path: "/sitemap.xml" })).toBe("retry");
  });

  it("200 但 robots 确实是空正文 → ok（空 robots 是合法语义：不限制任何路径）", () => {
    expect(classifyDeclaration({ status: 200, bytes: 0, path: "/robots.txt" })).toBe("ok");
  });

  it("200 且正文长度未知 → ok（工具只回头部时不能判成空壳反复重打）", () => {
    expect(classifyDeclaration({ status: 200, path: "/robots.txt" })).toBe("ok");
    expect(classifyDeclaration({ status: 200, path: "/sitemap.xml" })).toBe("ok");
  });

  it("200 但命中墙指纹（7155B attestation 挑战）→ retry，不能当拿到", () => {
    expect(classifyDeclaration({ status: 200, bytes: 7155, wall: "waf_aliyun_attestation" })).toBe("retry");
  });

  it("404 / 410 / 204 → absent（文件确实不存在，是结论）", () => {
    expect(classifyDeclaration({ status: 404 })).toBe("absent");
    expect(classifyDeclaration({ status: 410 })).toBe("absent");
    expect(classifyDeclaration({ status: 204 })).toBe("absent");
  });

  it("401 → auth（匿名拿不到声明文件，是结论）", () => {
    expect(classifyDeclaration({ status: 401 })).toBe("auth");
  });

  it("403 / 412 / 418 / 429 / 5xx / 无响应 → retry（风控抖动不是结论）", () => {
    for (const status of [403, 412, 418, 429, 500, 502, 503, 0]) {
      expect(classifyDeclaration({ status }), `status=${status}`).toBe("retry");
    }
  });
});

describe("recordDeclaration：按轮计次，不按请求计次", () => {
  it("首次记录算第 1 轮，并开 45s 冷却窗口", () => {
    const state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: 1_000 });
    expect(state.attempts).toBe(1);
    expect(state.next_at).toBe(1_000 + SITE_DECLARATION_COOLDOWN_MS);
    expect(state.files["/sitemap.xml"]?.verdict).toBe("retry");
  });

  it("同一冷却窗口内打两个文件只算一轮（否则 3 轮上限被对半砍）", () => {
    const first = recordDeclaration(undefined, { path: "/robots.txt", status: 403, at: 1_000 });
    const second = recordDeclaration(first, { path: "/sitemap.xml", status: 403, at: 2_000 });
    expect(second.attempts).toBe(1);
    expect(second.files["/robots.txt"]?.verdict).toBe("retry");
    expect(second.files["/sitemap.xml"]?.verdict).toBe("retry");
  });

  it("拿到终态后 next_at 归零，下一次就是新的一轮", () => {
    const first = recordDeclaration(undefined, { path: "/robots.txt", status: 200, bytes: 120, at: 1_000 });
    expect(first.files["/robots.txt"]?.verdict).toBe("ok");
    expect(first.next_at).toBe(1_000);
    const second = recordDeclaration(first, { path: "/sitemap.xml", status: 403, at: 2_000 });
    expect(second.attempts).toBe(2);
  });

  it("保留上一轮的文件记录（换文件重试不清账）", () => {
    const first = recordDeclaration(undefined, { path: "/robots.txt", status: 200, bytes: 120, at: 1_000 });
    const second = recordDeclaration(first, { path: "/sitemap.xml", status: 404, at: 2_000 });
    expect(second.files["/robots.txt"]?.status).toBe(200);
    expect(second.files["/sitemap.xml"]?.verdict).toBe("absent");
  });
});

describe("declarationNeed：什么时候该引水", () => {
  it("没有账 → first（从未试过）", () => {
    const need = declarationNeed(undefined, 1_000);
    expect(need.need).toBe(true);
    expect(need.reason).toBe("first");
    expect(need.missing).toEqual(["/robots.txt", "/sitemap.xml"]);
  });

  it("刚被 403、冷却未过 → cooldown（不重试也不结案）", () => {
    const state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: 1_000 });
    const need = declarationNeed(state, 1_000 + 10_000);
    expect(need.need).toBe(false);
    expect(need.reason).toBe("cooldown");
    expect(need.missing).toEqual(["/robots.txt", "/sitemap.xml"]);
  });

  it("冷却过了 → retry", () => {
    const state = recordDeclaration(undefined, { path: "/sitemap.xml", status: 403, at: 1_000 });
    const need = declarationNeed(state, 1_000 + SITE_DECLARATION_COOLDOWN_MS + 1);
    expect(need.need).toBe(true);
    expect(need.reason).toBe("retry");
    expect(need.attempts).toBe(1);
  });

  it("两个文件都拿到终态 → done", () => {
    let state: DeclarationHostState | undefined;
    state = recordDeclaration(state, { path: "/robots.txt", status: 200, bytes: 120, at: 1_000 });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 200, bytes: 1927, at: 1_100 });
    const need = declarationNeed(state, 9_999_999);
    expect(need.need).toBe(false);
    expect(need.reason).toBe("done");
    expect(need.missing).toEqual([]);
  });

  it("404 也算终态（站点确实没有 sitemap）", () => {
    let state: DeclarationHostState | undefined;
    state = recordDeclaration(state, { path: "/robots.txt", status: 404, at: 1_000 });
    state = recordDeclaration(state, { path: "/sitemap.xml", status: 404, at: 1_100 });
    expect(declarationNeed(state, 9_999_999).reason).toBe("done");
  });

  it(`重试 ${SITE_DECLARATION_MAX_ATTEMPTS} 轮仍被挡 → exhausted（不再死磕）`, () => {
    let state: DeclarationHostState | undefined;
    let at = 1_000;
    for (let round = 0; round < SITE_DECLARATION_MAX_ATTEMPTS; round += 1) {
      state = recordDeclaration(state, { path: "/sitemap.xml", status: 403, at });
      at += SITE_DECLARATION_COOLDOWN_MS + 1;
    }
    const need = declarationNeed(state!, at);
    expect(need.need).toBe(false);
    expect(need.reason).toBe("exhausted");
    expect(need.attempts).toBe(SITE_DECLARATION_MAX_ATTEMPTS);
    expect(need.blocked).toContain("/sitemap.xml");
  });
});

describe("declarationTaskSpec：任务描述必须写清「403 不是结论」", () => {
  it("首次引水不含「上一轮」，重试时把上一轮状态码写进去", () => {
    const first = declarationTaskSpec("https://x.com", declarationNeed(undefined, 1_000), undefined);
    expect(first.id).toBe("T_SITE_DECLARATION");
    expect(first.target).toBe("https://x.com/robots.txt");
    expect(first.completion_criteria).toContain("404");
    expect(first.reason).not.toContain("上一轮");

    const state = recordDeclaration(undefined, { path: "/robots.txt", status: 403, at: 1_000 });
    const retry = declarationTaskSpec("https://x.com", declarationNeed(state, 1_000 + SITE_DECLARATION_COOLDOWN_MS + 1), state);
    expect(retry.reason).toContain("403");
    expect(retry.reason).toContain("不是结论");
    // 目标落在还没拿到终态的文件上，别把重试打成同一份
    expect(retry.target).toBe("https://x.com/robots.txt");
  });
});

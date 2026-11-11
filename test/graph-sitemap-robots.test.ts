/**
 * 站点自报的业务面：sitemap / robots 解析（2026-11-04）。
 *
 * 实测背景：9cb376 会话里 `/sitemap.xml` 拿到了（200/1927B），但正文从未被看过 ——
 * 图里只有 sitemap 那一个节点，它声明的业务页面一条都没进。
 * 目标本体最终只有 4 个端点（`/`、`/robots.txt`、`/sitemap.xml`、探针路径），
 * 全是静态文件，假设只能挂在这些东西上，3 次打不穿就归档，池子直接清空。
 *
 * 这两个文件是**零成本的高价值发现源**：站点主动声明了自己有哪些页面、
 * 哪些路径不想被外部看到。比"从导航栏爬到的链接"可信得多，而且天然同站。
 */
import { describe, expect, it } from "vitest";
import { discoveryOf, parseRobots, parseSitemap } from "../src/blackbox/graph/extract.js";

describe("parseSitemap", () => {
  it("urlset 里的 loc 全部取出，XML 实体要还原", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://h.test/help/1.html</loc></url>
        <url><loc>https://h.test/search?q=a&amp;page=2</loc></url>
      </urlset>`;
    expect(parseSitemap(xml)).toEqual([
      "https://h.test/help/1.html",
      "https://h.test/search?q=a&page=2",
    ]);
  });

  it("sitemapindex 的子 sitemap 也要（打下去还能再拿一批）", () => {
    const xml = `<sitemapindex><sitemap><loc>https://h.test/sitemap-1.xml</loc></sitemap></sitemapindex>`;
    expect(parseSitemap(xml)).toEqual(["https://h.test/sitemap-1.xml"]);
  });

  it("相对路径靠 base 补全", () => {
    expect(parseSitemap(`<urlset><url><loc>/a</loc></url></urlset>`, "https://h.test/sitemap.xml"))
      .toEqual(["https://h.test/a"]);
  });

  it("不是 sitemap 就不解析（避免把普通 HTML/XML 当清单）", () => {
    expect(parseSitemap("<html><body><loc>https://h.test/x</loc></body></html>")).toEqual([]);
    expect(parseSitemap("")).toEqual([]);
  });

  it("超大批量要截断，别把图撑爆", () => {
    const xml = `<urlset>${Array.from({ length: 10 }, (_, index) => `<url><loc>https://h.test/${index}</loc></url>`).join("")}</urlset>`;
    expect(parseSitemap(xml, undefined, 3)).toHaveLength(3);
  });

  it("重复 loc 只留一条", () => {
    const xml = `<urlset><url><loc>https://h.test/a</loc></url><url><loc>https://h.test/a</loc></url></urlset>`;
    expect(parseSitemap(xml)).toEqual(["https://h.test/a"]);
  });
});

describe("parseRobots", () => {
  const robots = [
    "User-agent: *",
    "Disallow: /",
    "Disallow: /admin/",
    "Disallow: /api/internal/*.json",
    "Allow: /public/",
    "",
    "Sitemap: https://h.test/sitemap.xml",
  ].join("\n");

  it("取 Disallow 与 Sitemap，排掉根路径与 Allow", () => {
    expect(parseRobots(robots, "https://h.test/robots.txt")).toEqual([
      "https://h.test/admin/",
      "https://h.test/api/internal/",
      "https://h.test/sitemap.xml",
    ]);
  });

  it("通配只保留可打的前缀路径", () => {
    expect(parseRobots("Disallow: /backup/*\n", "https://h.test/robots.txt"))
      .toEqual(["https://h.test/backup/"]);
  });

  it("空正文 / 没有 Disallow 时返回空", () => {
    expect(parseRobots("", "https://h.test/robots.txt")).toEqual([]);
    expect(parseRobots("User-agent: *\nAllow: /\n", "https://h.test/robots.txt")).toEqual([]);
  });
});

describe("discoveryOf：拿到 sitemap / robots 的响应体就要解析", () => {
  it("sitemap.xml 的 loc 变成发现物，并标记来源", () => {
    const result = discoveryOf({
      url: "https://h.test/sitemap.xml",
      status: 200,
      body: `<urlset><url><loc>https://h.test/help/1.html</loc></url><url><loc>https://h.test/help/2.html</loc></url></urlset>`,
    });
    expect(result.found.map(item => item.url)).toEqual([
      "https://h.test/help/1.html",
      "https://h.test/help/2.html",
    ]);
    expect(result.found.every(item => item.source === "sitemap")).toBe(true);
  });

  it("robots.txt 的 Disallow 变成发现物", () => {
    const result = discoveryOf({
      url: "https://h.test/robots.txt",
      status: 200,
      body: "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n",
    });
    expect(result.found.map(item => item.url)).toEqual([
      "https://h.test/admin/",
      "https://h.test/backup/",
    ]);
    expect(result.found[0].source).toBe("robots");
  });

  it("普通页面的 body 不会被当成清单（不误报）", () => {
    const result = discoveryOf({
      url: "https://h.test/",
      status: 200,
      body: "<html><body><loc>https://h.test/x</loc></body></html>",
    });
    expect(result.found).toEqual([]);
  });

  it("forms 与 links 现在能区分开（之前都压成 link，scope 无法分流）", () => {
    const result = discoveryOf({
      url: "https://h.test/login",
      links: ["https://friend.other.test/"],
      forms: [{ url: "https://sso.other.test/oauth/login", method: "post" }],
    });
    expect(result.found.find(item => item.url === "https://friend.other.test/")?.kind).toBe("link");
    expect(result.found.find(item => item.url === "https://sso.other.test/oauth/login")?.kind).toBe("form");
  });
});

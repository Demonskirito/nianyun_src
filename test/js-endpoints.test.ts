import { describe, expect, it } from "vitest";
import { jsUrlsFromHtml, subjsArgs } from "../src/blackbox/tools.js";

describe("recon.js_endpoints input handling", () => {
  it("passes subjs a file path, never a page URL", () => {
    // The old spec ran `subjs -i https://host/page`, which subjs reads as a filename and fails
    // with "Could not open input file: open https://host/page".
    const args = subjsArgs("/data/blackbox-artifacts/p1/s1/js.txt");
    expect(args).toEqual(["-i", "/data/blackbox-artifacts/p1/s1/js.txt"]);
    expect(args.join(" ")).not.toMatch(/^.*-i https?:/);
  });

  it("extracts absolute JavaScript URLs from a page and resolves relative ones", () => {
    const html = [
      '<script src="/static/app.js"></script>',
      '<script src="https://cdn.example.com/vendor.js?v=3"></script>',
      '<script src="//cdn.example.net/lib.js"></script>',
      '<script>var inline = 1;</script>',
      '<a href="javascript:void(0)">x</a>',
      '<script src="/static/app.js"></script>',
    ].join("\n");
    const urls = jsUrlsFromHtml(html, "https://app.example.com/open/home");
    expect(urls).toContain("https://app.example.com/static/app.js");
    expect(urls).toContain("https://cdn.example.com/vendor.js?v=3");
    expect(urls).toContain("https://cdn.example.net/lib.js");
    // Duplicates collapse and non-JS references never reach subjs.
    expect(urls.filter((url) => url.endsWith("/static/app.js"))).toHaveLength(1);
    expect(urls.some((url) => /void\(0\)|javascript:/.test(url))).toBe(false);
  });

  it("keeps the list bounded", () => {
    const html = Array.from({ length: 400 }, (_, index) => `<script src="/js/${index}.js"></script>`).join("");
    expect(jsUrlsFromHtml(html, "https://app.example.com/").length).toBeLessThanOrEqual(200);
  });
});
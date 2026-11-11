import { describe, expect, it } from "vitest";
import { DEFAULT_BROWSER_UA, applyDefaultUserAgent, hasUserAgent, resolveUserAgent } from "../src/blackbox/ua.js";

describe("默认浏览器身份", () => {
  it("缺 UA 时补默认浏览器身份，且只补 UA 一条", () => {
    const headers: Record<string, string> = {};
    expect(applyDefaultUserAgent(headers, {})).toBe(true);
    expect(headers["user-agent"]).toBe(DEFAULT_BROWSER_UA);
    // 刻意不补 accept/accept-language：多塞头会撞上 sqlmap 这类 `--headers` 单值工具，
    // 把调用方真正要传的头挤丢；实测单独一条 UA 就足够过掉网关。
    expect(Object.keys(headers)).toEqual(["user-agent"]);
  });

  it("模型显式指定的 UA 优先，绝不被默认值覆盖", () => {
    const headers: Record<string, string> = { "user-agent": "sqlmap/1.7" };
    expect(applyDefaultUserAgent(headers, {})).toBe(false);
    expect(headers).toEqual({ "user-agent": "sqlmap/1.7" });
  });

  it("UA 已存在但大小写不同，同样算已指定", () => {
    const headers: Record<string, string> = { "User-Agent": "curl/8.0" };
    expect(hasUserAgent(headers)).toBe(true);
    expect(applyDefaultUserAgent(headers, {})).toBe(false);
    expect(Object.keys(headers).filter(name => name.toLowerCase() === "user-agent")).toHaveLength(1);
  });

  it("accept 已存在时只补 UA，不覆盖调用方的 accept", () => {
    const headers: Record<string, string> = { accept: "application/json" };
    applyDefaultUserAgent(headers, {});
    expect(headers.accept).toBe("application/json");
    expect(headers["user-agent"]).toBe(DEFAULT_BROWSER_UA);
  });

  it("BLACKBOX_USER_AGENT 可覆盖默认值", () => {
    const headers: Record<string, string> = {};
    applyDefaultUserAgent(headers, { BLACKBOX_USER_AGENT: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" });
    expect(headers["user-agent"]).toContain("iPhone");
  });

  it("BLACKBOX_USER_AGENT 显式设为空串表示故意裸发，不注入任何东西", () => {
    const headers: Record<string, string> = {};
    expect(applyDefaultUserAgent(headers, { BLACKBOX_USER_AGENT: "" })).toBe(false);
    expect(headers).toEqual({});
    expect(resolveUserAgent({ BLACKBOX_USER_AGENT: "" })).toBe("");
  });

  it("未配置时解析出默认 UA", () => {
    expect(resolveUserAgent({})).toBe(DEFAULT_BROWSER_UA);
    expect(resolveUserAgent(undefined)).toBe(DEFAULT_BROWSER_UA);
  });

  it("默认 UA 必须像真浏览器：含 Mozilla 前缀，且不含 Headless 标记", () => {
    expect(DEFAULT_BROWSER_UA.startsWith("Mozilla/5.0")).toBe(true);
    expect(DEFAULT_BROWSER_UA).not.toMatch(/Headless|Playwright|node-fetch|undici/i);
  });
});

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { hostMatches, loadSeedsForHost } from "../src/blackbox/authseed.js";

// 用独立临时目录，避免仓库 data/auth 下的真实种子（如 wanxiaozhi 的 4 个 cookie）污染断言。
let authDir = "";

const sample = {
  cookies: [
    { name: "sess", value: "abc", domain: "wanxiaozhi.aliyun.com", path: "/", httpOnly: true, secure: true },
    { name: "edge", value: "x", domain: ".aliyun.com", path: "/" },
  ],
  origins: [
    { origin: "https://wanxiaozhi.aliyun.com", localStorage: [{ name: "token", value: "jwt" }] },
  ],
};

beforeAll(() => {
  authDir = fs.mkdtempSync(path.join(os.tmpdir(), "authseed-test-"));
  fs.writeFileSync(path.join(authDir, "_authseed_test.storageState.json"), JSON.stringify(sample));
});

afterAll(() => {
  try {
    fs.rmSync(authDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe("hostMatches", () => {
  it("exact match", () => {
    expect(hostMatches("wanxiaozhi.aliyun.com", "wanxiaozhi.aliyun.com")).toBe(true);
  });
  it("subdomain match", () => {
    expect(hostMatches("wanxiaozhi.aliyun.com", ".aliyun.com")).toBe(true);
  });
  it("parent domain match", () => {
    expect(hostMatches("wanxiaozhi.aliyun.com", "aliyun.com")).toBe(true);
  });
  it("unrelated host does not match", () => {
    expect(hostMatches("evil.com", "aliyun.com")).toBe(false);
  });
});

describe("loadSeedsForHost", () => {
  it("matches by cookie domain (exact)", () => {
    const seed = loadSeedsForHost("wanxiaozhi.aliyun.com", authDir);
    expect(seed).not.toBeNull();
    expect(seed!.cookies.length).toBe(2);
    expect(seed!.origins.length).toBe(1);
  });
  it("matches by parent cookie domain", () => {
    const seed = loadSeedsForHost("other.aliyun.com", authDir);
    expect(seed).not.toBeNull();
  });
  it("returns null when no seed matches", () => {
    expect(loadSeedsForHost("example.com", authDir)).toBeNull();
  });
});

describe("loadSeedsForHost 多份种子共存", () => {
  let dir = "";
  const write = (name: string, cookies: Array<Record<string, unknown>>, origins: unknown[] = []): void => {
    fs.writeFileSync(path.join(dir, name), JSON.stringify({ cookies, origins }));
  };

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "authseed-multi-"));
    // 泛域：一份 .aliyun.com 的票
    write("aliyun.com.storageState.json", [{ name: "broad", value: "1", domain: ".aliyun.com", path: "/" }]);
    // 专用：只覆盖 RAM 控制台
    write("ram.console.aliyun.com.storageState.json", [
      { name: "narrow", value: "2", domain: "ram.console.aliyun.com", path: "/" },
    ]);
  });

  afterAll(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it("更具体的种子优先于泛域种子", () => {
    const seed = loadSeedsForHost("ram.console.aliyun.com", dir);
    expect(seed!.path).toContain("ram.console.aliyun.com.storageState.json");
  });

  it("泛域子域仍回落到泛域种子", () => {
    const seed = loadSeedsForHost("www.aliyun.com", dir);
    expect(seed!.path).toContain("aliyun.com.storageState.json");
  });

  it("泛域种子对任意 aliyun 子域都命中（域名不限文件标签）", () => {
    for (const host of ["oss.console.aliyun.com", "bailian.console.aliyun.com", "whois.aliyun.com"]) {
      expect(loadSeedsForHost(host, dir)).not.toBeNull();
    }
  });

  it("相邻域名不被误判（notaliyun.com / evil-aliyun.com）", () => {
    expect(loadSeedsForHost("notaliyun.com", dir)).toBeNull();
    expect(loadSeedsForHost("evil-aliyun.com", dir)).toBeNull();
  });

  it("同分时结果稳定可复现（按文件名序）", () => {
    const tie = fs.mkdtempSync(path.join(os.tmpdir(), "authseed-tie-"));
    try {
      for (const n of ["b.storageState.json", "a.storageState.json"]) {
        fs.writeFileSync(path.join(tie, n), JSON.stringify({ cookies: [{ name: "x", value: "1", domain: ".aliyun.com" }] }));
      }
      const first = loadSeedsForHost("www.aliyun.com", tie)!.path;
      const second = loadSeedsForHost("www.aliyun.com", tie)!.path;
      expect(first).toBe(second);
      expect(first).toContain("a.storageState.json");
    } finally {
      fs.rmSync(tie, { recursive: true, force: true });
    }
  });
});

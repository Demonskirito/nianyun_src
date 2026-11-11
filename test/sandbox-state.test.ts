import { describe, expect, it } from "vitest";
import { bandUsage, planStatePrune, stateBand, type SandboxStateEntry } from "../src/sandbox/state.js";

const entry = (path: string, bytes: number, mtime_s: number): SandboxStateEntry => ({ path, bytes, mtime_s });
const quota = { maxBytes: 1000, maxFiles: 100 };

describe("/state 命名空间与裁剪优先级", () => {
  it("路径归带：poc/tmp 一次性、auth 受保护、rpc 钉死、其余 normal", () => {
    expect(stateBand("poc/exploit.py")).toBe("volatile");
    expect(stateBand("tmp/body.html")).toBe("volatile");
    expect(stateBand("auth/sign_key.txt")).toBe("protected");
    expect(stateBand("rpc/dispatch.jsonl")).toBe("pinned");
    expect(stateBand("recon/endpoints.json")).toBe("normal");
    expect(stateBand("home.html")).toBe("normal");
    expect(stateBand("/auth/token.json")).toBe("protected");
  });

  it("超配额时先裁 poc/tmp，auth 一个都不动", () => {
    const entries = [
      entry("auth/sign_key.txt", 400, 100),      // 最旧，但受保护
      entry("poc/big1.html", 400, 200),
      entry("poc/big2.html", 400, 300),
      entry("recon/endpoints.json", 100, 400),
    ];
    const plan = planStatePrune(entries, quota); // 1300 > 1000
    expect(plan.drop.every(path => path.startsWith("poc/"))).toBe(true);
    expect(plan.drop).not.toContain("auth/sign_key.txt");
    expect(plan.protected_hits).toBe(0);
    expect(plan.over_quota).toBe(false);
  });

  it("poc 清完还不够才动 normal，最后才动 auth", () => {
    const entries = [
      entry("auth/key.txt", 500, 1),
      entry("recon/a.json", 400, 2),
      entry("recon/b.json", 400, 3),
      entry("poc/x.html", 300, 4),
      entry("poc/y.html", 300, 5),
    ];
    const plan = planStatePrune(entries, { maxBytes: 900, maxFiles: 100 });
    // 先 poc（留最新一个 y），再 normal（留最新一个 b）
    expect(plan.drop).toEqual(["poc/x.html", "recon/a.json"]);
    expect(plan.drop).not.toContain("auth/key.txt");
  });

  it("每带至少保留最新一个文件，刚写的那份不会被自己挤掉", () => {
    const entries = [entry("poc/old.html", 900, 1), entry("poc/new.html", 900, 2)];
    const plan = planStatePrune(entries, { maxBytes: 500, maxFiles: 100 });
    expect(plan.drop).toEqual(["poc/old.html"]);
    expect(plan.over_quota).toBe(true); // 还剩 900 > 500，但没得裁了
  });

  it("rpc 队列永不裁剪，即使超配额", () => {
    const entries = [entry("rpc/dispatch.jsonl", 5000, 1), entry("rpc/dispatch_cursor.json", 100, 2)];
    const plan = planStatePrune(entries, quota);
    expect(plan.drop).toEqual([]);
    expect(plan.over_quota).toBe(true);
  });

  it("文件数超限也按同样的带序裁", () => {
    const entries = [
      entry("auth/k.txt", 10, 1),
      ...Array.from({ length: 5 }, (_, index) => entry(`poc/f${index}.html`, 10, 10 + index)),
    ];
    const plan = planStatePrune(entries, { maxBytes: 1e9, maxFiles: 3 });
    expect(plan.drop).toHaveLength(3);
    expect(plan.drop.every(path => path.startsWith("poc/"))).toBe(true);
  });

  it("bandUsage 按带汇总", () => {
    const usage = bandUsage([entry("auth/a", 10, 1), entry("auth/b", 20, 2), entry("poc/c", 5, 3), entry("recon/d", 7, 4)]);
    expect(usage.protected).toEqual({ files: 2, bytes: 30 });
    expect(usage.volatile).toEqual({ files: 1, bytes: 5 });
    expect(usage.normal).toEqual({ files: 1, bytes: 7 });
    expect(usage.pinned).toEqual({ files: 0, bytes: 0 });
  });

  it("未超配额时不产生任何删除", () => {
    const plan = planStatePrune([entry("auth/a", 10, 1)], quota);
    expect(plan.drop).toEqual([]);
    expect(plan.over_quota).toBe(false);
  });
});
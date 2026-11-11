import { describe, expect, it } from "vitest";
import {
  isAuthRedirect,
  isCleanSample,
  isWallSample,
  isolateTaintedCookies,
  judgeSeedHealth,
  riskCookieIndexes,
} from "../src/blackbox/seedcheck.js";

/**
 * 种子自检的判定规则。
 *
 * 背景（2026-11-07 实测）：种子里的 `cna` 让阿里云整站回 403 + attestation 挑战页，
 * 而同一时刻匿名访问同一 URL 是 200。系统当时把它当"目标身份墙" → 整机拉黑 →
 * 两场 172 分钟 / 17.0M tokens 全打在自己造的墙上。
 * 这些用例锁的就是"能不能分清这堵墙是谁造的"。
 */
describe("judgeSeedHealth", () => {
  const wallBody = "proxy_authentication_required : client attestation payload missing";

  it("says seed_tainted when the seeded request is walled but anonymous is clean", () => {
    const verdict = judgeSeedHealth({ seeded: { status: 403, body: wallBody }, anonymous: { status: 200, body: "<html>ok</html>" } });
    expect(verdict.verdict).toBe("seed_tainted");
    expect(verdict.detail).toContain("带凭证 403");
  });

  it("says host_walled when both are walled", () => {
    expect(judgeSeedHealth({ seeded: { status: 403, body: wallBody }, anonymous: { status: 403, body: wallBody } }).verdict)
      .toBe("host_walled");
  });

  it("says healthy when the seeded request gets real content", () => {
    expect(judgeSeedHealth({ seeded: { status: 200, body: "<html>in</html>" }, anonymous: { status: 200, body: "<html>in</html>" } }).verdict)
      .toBe("healthy");
  });

  it("says seed_stale when both look like 'please log in'", () => {
    expect(judgeSeedHealth({ seeded: { status: 401, body: "unauthorized" }, anonymous: { status: 401, body: "unauthorized" } }).verdict)
      .toBe("seed_stale");
  });

  it("says seed_stale when the seeded request is bounced to a login page", () => {
    const verdict = judgeSeedHealth({
      seeded: { status: 302, location: "https://passport.example.com/login?redirect=..." },
      anonymous: { status: 200, body: "<html>public</html>" },
    });
    expect(verdict.verdict).toBe("seed_stale");
  });

  it("refuses to conclude anything without two samples", () => {
    expect(judgeSeedHealth({ seeded: { status: 403, body: wallBody } }).verdict).toBe("inconclusive");
    expect(judgeSeedHealth({}).verdict).toBe("inconclusive");
  });
});

describe("sample classifiers", () => {
  it("treats identity challenge pages as walls even with a 200 status", () => {
    expect(isWallSample({ status: 200, body: "proxy_authentication_required" })).toBe(true);
    expect(isWallSample({ status: 200, body: "<html>fine</html>" })).toBe(false);
  });

  it("does not call a login redirect 'clean'", () => {
    expect(isAuthRedirect({ status: 302, location: "https://login.example.com" })).toBe(true);
    expect(isCleanSample({ status: 302, location: "https://login.example.com" })).toBe(false);
    expect(isCleanSample({ status: 302, location: "https://example.com/dashboard" })).toBe(true);
  });
});

describe("isolateTaintedCookies", () => {
  const cookies = [{ name: "isg" }, { name: "cna" }, { name: "tfstk" }, { name: "cookie2" }, { name: "atpsida" }];

  /** 墙只在 cna 在场时出现（就是 2026-11-07 的实测形态）。 */
  const probeFor = (culprits: string[]) => async (remove: number[]): Promise<boolean> => {
    const kept = cookies.filter((_, index) => !remove.includes(index));
    return kept.some(cookie => culprits.includes(cookie.name));
  };

  it("finds the single culprit by removal, keeping every other cookie in play", async () => {
    const result = await isolateTaintedCookies({ cookies, probe: probeFor(["cna"]) });
    expect(result.names).toEqual(["cna"]);
    expect(result.complete).toBe(true);
    expect(result.probes).toBeLessThanOrEqual(6);
  });

  it("scales logarithmically instead of trying every cookie", async () => {
    const many = Array.from({ length: 32 }, (_, index) => ({ name: `c${index}` }));
    many[21] = { name: "cna" };
    const probe = async (remove: number[]): Promise<boolean> =>
      many.filter((_, index) => !remove.includes(index)).some(cookie => cookie.name === "cna");
    const result = await isolateTaintedCookies({ cookies: many, probe, maxProbes: 12 });
    expect(result.names).toEqual(["cna"]);
    expect(result.complete).toBe(true);
    // 32 枚逐枚试要 32 发；分组测试应该在 10 发上下收工。
    expect(result.probes).toBeLessThanOrEqual(12);
  });

  it("reports every culprit when more than one cookie is enough to trip the wall", async () => {
    const result = await isolateTaintedCookies({ cookies, probe: probeFor(["cna", "tfstk"]) });
    expect(result.names.sort()).toEqual(["cna", "tfstk"]);
  });

  it("admits failure instead of guessing when the budget runs out", async () => {
    const result = await isolateTaintedCookies({ cookies, probe: probeFor(["cna"]), maxProbes: 1 });
    expect(result.complete).toBe(false);
    expect(result.indexes).toEqual([]);
  });

  it("admits failure when no cookie subset clears the wall", async () => {
    const result = await isolateTaintedCookies({ cookies, probe: async () => true });
    expect(result.complete).toBe(false);
    expect(result.reason).toBeTruthy();
  });
});

describe("riskCookieIndexes", () => {
  it("only points at known risk-control cookies, never at the session ones", () => {
    const indexes = riskCookieIndexes([{ name: "login_aliyunid_ticket" }, { name: "cna" }, { name: "ISG" }]);
    expect(indexes).toEqual([1, 2]);
  });
});

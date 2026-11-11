import { describe, expect, it } from "vitest";
import {
  anonymousOptOut, cookieJarFingerprint, isAnonymousWallRequest, snapshotCredential,
} from "../src/blackbox/credential.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";

const state = () => ({
  version: 1,
  tasks: { T1: { status: "running", target: "https://h/api/doc/86" } },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
});

const wallResult = (credentialMode?: string) => ({
  tool: "http.request", ok: true, summary: "blocked",
  data: { status: 403, body: "Blocked by WAF security policy", ...(credentialMode ? { credential_mode: credentialMode } : {}) },
});

const wallRequest = (input: Record<string, unknown> = { url: "https://h/api/doc" }) => ({
  task_id: "T1", tool: "http.request", reason: "probe", input,
});

describe("credential identity snapshot", () => {
  it("recognises all three anonymous spellings used by httpTool", () => {
    expect(anonymousOptOut({ anonymous: true })).toBe(true);
    expect(anonymousOptOut({ no_auth: true })).toBe(true);
    expect(anonymousOptOut({ use_jar: false })).toBe(true);
    expect(anonymousOptOut({ anonymous: "true" })).toBe(false);
    expect(anonymousOptOut({})).toBe(false);
    expect(anonymousOptOut(undefined)).toBe(false);
  });

  it("classifies jar / explicit / anonymous / local tools", () => {
    expect(snapshotCredential("http.request", {}, true)).toMatchObject({ mode: "seeded", source: "jar", anonymous: false });
    expect(snapshotCredential("http.request", {}, false)).toMatchObject({ mode: "none", anonymous: false });
    expect(snapshotCredential("http.request", { anonymous: true }, true)).toMatchObject({ mode: "anonymous", anonymous: true });
    expect(snapshotCredential("http.request", { headers: { Authorization: "Bearer x" } }, true))
      .toMatchObject({ mode: "explicit", source: "explicit" });
    expect(snapshotCredential("evidence.read", {}, true)).toMatchObject({ mode: "none", source: "not_applicable" });
    expect(snapshotCredential("exec.python", {}, false)).toMatchObject({ mode: "unknown", source: "no_credentials" });
  });

  it("never labels a persistent browser context as anonymous (its cookies survive across calls)", () => {
    expect(snapshotCredential("browser.open", { anonymous: true }, true))
      .toMatchObject({ mode: "seeded", anonymous: false });
  });

  it("jar fingerprint is order-independent, stable, and sensitive to cookie values", () => {
    const a = [{ domain: ".aliyun.com", name: "cna", value: "poison" }, { domain: "h", name: "s", value: "1" }];
    const b = [{ domain: "h", name: "s", value: "1" }, { domain: ".aliyun.com", name: "cna", value: "poison" }];
    expect(cookieJarFingerprint(a)).toBe(cookieJarFingerprint(b));
    // Same name/domain, different value: the poison cna vs a random benign cna must diverge.
    expect(cookieJarFingerprint(a)).not.toBe(cookieJarFingerprint([{ ...a[0], value: "random" }, a[1]]));
    expect(cookieJarFingerprint([])).toBe(cookieJarFingerprint(undefined));
  });
});

describe("anonymous wall gate (the deleted-input bug)", () => {
  it("trusts result.data.credential_mode even when httpTool already deleted input.anonymous", () => {
    // This is the exact production shape: input no longer carries the marker.
    expect(isAnonymousWallRequest(wallRequest(), wallResult("anonymous"))).toBe(true);
    expect(isAnonymousWallRequest(wallRequest(), wallResult("seeded"))).toBe(false);
    expect(isAnonymousWallRequest(wallRequest({ anonymous: true }), wallResult("seeded"))).toBe(false);
  });

  it("still accepts legacy requests that only carry input.anonymous", () => {
    expect(isAnonymousWallRequest(wallRequest({ anonymous: true }), wallResult())).toBe(true);
    expect(isAnonymousWallRequest(wallRequest({ no_auth: true }), wallResult())).toBe(true);
    expect(isAnonymousWallRequest(wallRequest({ use_jar: false }), wallResult())).toBe(true);
    expect(isAnonymousWallRequest(wallRequest(), wallResult())).toBe(false);
  });

  it("anonymous single-shot 403s never accumulate blocked_hosts / waf_escalation / lateral_escape", () => {
    const progress = new BlackboxProgress(state());
    for (let index = 0; index < 8; index += 1) {
      progress.recordHostBlock(wallRequest() as never, wallResult("anonymous") as never);
    }
    expect(progress.state.blocked_hosts).toBeUndefined();
    expect(progress.state.waf_escalation).toBeUndefined();
    expect(progress.state.lateral_escape).toBeUndefined();
    expect(progress.state.seed_probe).toBeUndefined();
  });

  it("seeded 403s still accumulate (the gate is not a blanket bypass)", () => {
    const progress = new BlackboxProgress(state());
    for (let index = 0; index < 3; index += 1) {
      progress.recordHostBlock(wallRequest() as never, wallResult("seeded") as never);
    }
    expect(progress.state.blocked_hosts?.["h"]?.hits).toBe(3);
    expect(progress.state.waf_escalation?.host).toBe("h");
  });

  it("an anonymous dictionary sweep is not a host-level WAF", () => {
    const progress = new BlackboxProgress(state());
    progress.recordHostBlock(
      { task_id: "T1", tool: "recon.content_discovery", reason: "sweep", input: { url: "https://h/" } } as never,
      { tool: "recon.content_discovery", ok: true, summary: "sweep",
        data: { items: [{ url: "https://h/a", status: 403 }, { url: "https://h/b", status: 403 }, { url: "https://h/c", status: 403 }],
          credential_mode: "anonymous" } } as never);
    expect(progress.state.blocked_hosts).toBeUndefined();
    expect(progress.state.waf_escalation).toBeUndefined();
  });
});

describe("seed health bound to cookie jar", () => {
  const health = { verdict: "healthy" as const, seeded: 200, anonymous: 200, at: Date.now() };

  it("stamps the current jar fingerprint onto the verdict", () => {
    const progress = new BlackboxProgress(state());
    progress.state.seed_jar_fingerprint = "fp-A";
    expect(progress.noteSeedHealth("h", health)).toBe(true);
    expect(progress.state.seed_health?.h.jar_fingerprint).toBe("fp-A");
  });

  it("keeps the verdict while the jar is unchanged", () => {
    const progress = new BlackboxProgress(state());
    progress.state.seed_jar_fingerprint = "fp-A";
    progress.noteSeedHealth("h", health);
    expect(progress.requestSeedProbe("h", "https://h/", "wall")).toBe(false);
    expect(progress.state.seed_probe).toBeUndefined();
  });

  it("invalidates and re-queues a probe when the jar changes after the cooldown", () => {
    const progress = new BlackboxProgress(state());
    progress.state.seed_jar_fingerprint = "fp-A";
    progress.state.seed_probe_cooldown_ms = 0;
    progress.noteSeedHealth("h", { ...health, at: Date.now() - 10_000 });
    progress.state.seed_jar_fingerprint = "fp-B";
    expect(progress.requestSeedProbe("h", "https://h/", "jar changed")).toBe(true);
    expect(progress.state.seed_probe?.host).toBe("h");
    expect(progress.state.seed_health?.h).toBeUndefined();
    expect(progress.state.seed_health_stale?.h).toMatchObject({ previous_verdict: "healthy", old_fingerprint: "fp-A", new_fingerprint: "fp-B" });
  });

  it("respects the cooldown so a jittering dev jar does not reprobe every round", () => {
    const progress = new BlackboxProgress(state());
    progress.state.seed_jar_fingerprint = "fp-A";
    progress.state.seed_probe_cooldown_ms = 300_000;
    progress.noteSeedHealth("h", health);
    progress.state.seed_jar_fingerprint = "fp-B";
    expect(progress.requestSeedProbe("h", "https://h/", "jar changed")).toBe(false);
    expect(progress.state.seed_health?.h.verdict).toBe("healthy");
  });

  it("legacy verdicts without a fingerprint stay valid until one is stamped", () => {
    const progress = new BlackboxProgress(state());
    progress.noteSeedHealth("h", { ...health, jar_fingerprint: undefined });
    progress.state.seed_jar_fingerprint = "fp-B";
    expect(progress.requestSeedProbe("h", "https://h/", "jar changed")).toBe(false);
  });
});

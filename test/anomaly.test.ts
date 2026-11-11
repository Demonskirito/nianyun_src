import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { detectAnomaly, observationOf } from "../src/blackbox/anomaly.js";
import { anomalyTasks, crossDomainTasks } from "../src/blackbox/playbooks.js";

const state = () => ({
  version: 1,
  tasks: { T1: { status: "running", target: "https://h/a" }, T2: { status: "running", target: "https://h/b" } },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
});
const obs = (path: string, status: number, extra: { location?: string; body_bytes?: number } = {}) =>
  observationOf({ url: `https://h${path}`, status, ...extra })!;

describe("catch-all detection", () => {
  it("trips when three distinct paths share one redirect target", () => {
    expect(detectAnomaly([obs("/a", 302, { location: "/login" }), obs("/b", 302, { location: "/login" })])).toBeUndefined();
    const alert = detectAnomaly([obs("/a", 302, { location: "/login" }), obs("/b", 302, { location: "/login" }), obs("/c", 301, { location: "/login" })]);
    expect(alert?.kind).toBe("catch_all_redirect");
    expect(alert?.location).toBe("https://h/login");
    expect(alert?.paths).toEqual(["/a", "/b", "/c"]);
  });

  it("trips on identical body length, and ignores mixed or trivially small bodies", () => {
    const alert = detectAnomaly([obs("/a", 200, { body_bytes: 1200 }), obs("/b", 200, { body_bytes: 1200 }), obs("/c", 200, { body_bytes: 1200 })]);
    expect(alert?.kind).toBe("uniform_body");
    expect(detectAnomaly([obs("/a", 200, { body_bytes: 1200 }), obs("/b", 200, { body_bytes: 1201 }), obs("/c", 200, { body_bytes: 1200 })])).toBeUndefined();
    // "ok" / "404 not found" 这种空壳正文不算 catch-all（否则正常扫描会被误熔断）
    expect(detectAnomaly([obs("/a", 200, { body_bytes: 2 }), obs("/b", 200, { body_bytes: 2 }), obs("/c", 200, { body_bytes: 2 })])).toBeUndefined();
  });

  it("does not let one path repeating count as different paths", () => {
    expect(detectAnomaly([obs("/a", 302, { location: "/x" }), obs("/a", 302, { location: "/x" }), obs("/a", 302, { location: "/x" })])).toBeUndefined();
  });
});

describe("anomaly wired into progress", () => {
  it("records the alert from http results and issues the three exploit tasks", () => {
    const progress = new BlackboxProgress(state());
    for (const path of ["/a", "/b", "/c"]) {
      progress.recordAnomaly(
        { task_id: "T1", tool: "http.request", reason: "map", input: { url: `https://h${path}` } } as never,
        { tool: "http.request", ok: true, summary: "", data: { status: 302, location: "/login", body_bytes: 0 } } as never);
    }
    expect(progress.state.anomaly_alert?.kind).toBe("catch_all_redirect");
    const specs = anomalyTasks(progress.state.anomaly_alert!, "S");
    expect(specs.map(item => item.id)).toEqual(["host_header_injection_S", "open_redirect_S", "takeover_check_S"]);
    expect(specs[0]?.purpose).toContain("X-Forwarded-Host");
    expect(specs[2]?.target).toBe("https://h/login");
  });

  it("keeps POST method and body out of the redirect decision (no silent downgrade)", () => {
    // httpTool 默认不跟随：这条用例锁定"看得到原始 301"这一契约所依赖的数据形状
    const progress = new BlackboxProgress(state());
    progress.recordAnomaly(
      { task_id: "T1", tool: "http.request", reason: "post", input: { url: "https://h/api/doc" } } as never,
      { tool: "http.request", ok: true, summary: "", data: { status: 301, location: "https://h/api/doc/", body_bytes: 0, redirect_not_followed: true } } as never);
    expect(progress.state.anomaly?.recent[0]?.location).toBe("https://h/api/doc/");
  });
});

describe("nuclei zero-output handling", () => {
  it("warns after two zero-output runs but never disables the tool", () => {
    const progress = new BlackboxProgress(state());
    const empty = { tool: "recon.nuclei", ok: true, summary: "nuclei returned 0 findings", data: { findings: [], items: [] } } as never;
    progress.recordToolHealth("recon.nuclei", empty);
    expect(progress.state.tool_health?.["recon.nuclei"]?.disabled).toBeUndefined();
    progress.recordToolHealth("recon.nuclei", empty);
    // 会话内禁用会把"换个模板 tag 就能命中"的能力永久拿走；这里只留提示与明细。
    expect(progress.state.tool_health?.["recon.nuclei"]?.disabled).toBeUndefined();
    expect(progress.state.tool_health?.["recon.nuclei"]?.detail).toContain("换模板");
    expect((progress.state.interrupts || []).some(item => item.kind === "tool_health")).toBe(true);
    const request = { task_id: "T1", tool: "recon.nuclei", reason: "scan", input: { target: "https://h/" } } as never;
    const begin = progress.begin(request, "https://h/", 2, 2);
    expect(begin.blocked).toBeUndefined();
    expect(progress.state.tasks.T1?.status).toBe("running");
  });

  it("resets the counter on real output and ignores rejected calls", () => {
    const progress = new BlackboxProgress(state());
    progress.recordToolHealth("recon.nuclei", { tool: "recon.nuclei", ok: true, summary: "", data: { findings: [] } } as never);
    progress.recordToolHealth("recon.nuclei", { tool: "recon.nuclei", ok: false, summary: "recon.nuclei is not configured (NUCLEI_PATH)" } as never);
    expect(progress.state.tool_health?.["recon.nuclei"]?.zeros).toBe(1);
    progress.recordToolHealth("recon.nuclei", { tool: "recon.nuclei", ok: true, summary: "", data: { findings: [{ template: "x" }] } } as never);
    expect(progress.state.tool_health?.["recon.nuclei"]?.zeros).toBe(0);
    expect(progress.state.tool_health?.["recon.nuclei"]?.disabled).toBe(false);
  });
});

describe("cross-domain JS assets", () => {
  it("routes identity domains to auth_token and the rest to unauth_exposure", () => {
    const identity = crossDomainTasks("id.heytap.com", "S")[0]!;
    const other = crossDomainTasks("cdn.example.net", "S")[0]!;
    expect(identity.id).toBe("cross_domain_identity_S");
    expect(identity.playbook).toBe("auth_token");
    expect(identity.reason).toContain("统一认证中心");
    expect(other.id).toBe("cross_domain_asset_S");
    expect(other.playbook).toBe("unauth_exposure");
  });
});
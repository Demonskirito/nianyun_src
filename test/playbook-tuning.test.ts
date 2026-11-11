import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { PLAYBOOKS, recommendPlaybooks, anomalyTasks, playbookIndex, lateralEscapeTask } from "../src/blackbox/playbooks.js";
import { playbookById } from "../src/blackbox/playbooks.js";

const state = () => ({
  version: 1,
  tasks: { T1: { status: "running", target: "https://h/api/doc/86" } },
  actions: {}, seenResults: [], stalledBatches: 0,
  usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
});

describe("recommendPlaybooks signals", () => {
  it("recommends idor from a RESTful path id and from JSON body id fields", () => {
    expect(recommendPlaybooks({ urls: ["https://h/api/doc/86"] }).map(p => p.id)).toContain("idor");
    expect(recommendPlaybooks({ notes: ['{"id": 42, "owner":"a"}'] }).map(p => p.id)).toContain("idor");
    expect(recommendPlaybooks({ urls: ["https://h/api/users/alice"] }).map(p => p.id)).toContain("idor");
  });

  it("recommends auth_token on wider auth-failure semantics", () => {
    for (const text of ["403 Forbidden", "not logged in", "signin required", "MFA 两步验证", "passport.example.com"]) {
      expect(recommendPlaybooks({ notes: [text] }).map(p => p.id)).toContain("auth_token");
    }
  });

  it("recommends ssrf on redirect/next params and cloud on oss hosts", () => {
    expect(recommendPlaybooks({ urls: ["https://h/x?next=/home"] }).map(p => p.id)).toContain("ssrf");
    expect(recommendPlaybooks({ urls: ["https://h/obj?return_url=/a"] }).map(p => p.id)).toContain("ssrf");
    expect(recommendPlaybooks({ urls: ["https://x.oss-cn-hangzhou.aliyuncs.com/"] }).map(p => p.id)).toContain("cloud_supply");
  });
});

describe("idor playbook runs on a single account", () => {
  const steps = playbookById("idor")!.steps.map(step => step.id);
  it("has a self-baseline step, a ±1 blind guess step, and keeps diff as the only confirm evidence", () => {
    expect(steps).toEqual(["own_resource", "baseline_self", "shift_id", "diff_auth", "vertical"]);
    expect(playbookById("idor")!.confirm.evidence).toEqual(["diff_auth"]);
    expect(playbookById("idor")!.confirm.must_show).toContain("baseline_self");
  });
});

describe("sqli playbook probes without quoting first", () => {
  const sqli = playbookById("sqli")!;
  it("leads with arithmetic, then a single quote, then a 2s sleep", () => {
    expect(sqli.steps.map(step => step.id)).toEqual(["arith_probe", "diff_arith", "quote_probe", "time_probe", "sqlmap", "blind_oast", "blind_script"]);
    const arith = JSON.stringify(sqli.steps[0]!.input);
    expect(arith).toContain("2-1");
    expect(arith).not.toContain("'");
    expect(JSON.stringify(sqli.steps[0]!.input)).not.toMatch(/union|select|comment/i);
    expect(sqli.stop.join(" ")).toContain("连续 2 次被 WAF 拦");
  });
});

describe("auth_token playbook recognises gates", () => {
  const auth = playbookById("auth_token")!;
  it("probes for captcha/mfa/slider/sso before submitting", () => {
    const ids = auth.steps.map(step => step.id);
    expect(ids.indexOf("gate_probe")).toBeGreaterThan(ids.indexOf("login_page"));
    expect(ids.indexOf("gate_probe")).toBeLessThan(ids.indexOf("submit_login"));
    expect(JSON.stringify(auth.steps.find(step => step.id === "gate_probe")!.input)).toContain("captcha");
    expect(auth.stop.join(" ")).toContain("auth_gate_");
  });
});

describe("unauth_exposure covers CORS", () => {
  it("has a reflected-Origin probe and a diff to prove it is reflection", () => {
    const unauth = playbookById("unauth_exposure")!;
    expect(unauth.steps.map(step => step.id)).toContain("cors_probe");
    expect(unauth.steps.map(step => step.id)).toContain("cors_verify");
    expect(unauth.confirm.must_show).toContain("ACAO");
  });
});

describe("anomaly tasks require http.diff", () => {
  it("states http.diff in every completion criterion", () => {
    const specs = anomalyTasks({ kind: "catch_all_redirect", host: "h", location: "https://sso.h/login" }, "S");
    for (const spec of specs) expect(spec.completion_criteria).toContain("http.diff");
  });

  it("rejects completion without a http.diff result and keeps the task pending", () => {
    const progress = new BlackboxProgress(state());
    progress.state.tasks.host_header_injection_S = { status: "running", target: "https://h/", completion_criteria: "diff" };
    const evidence = [
      { id: "ev-1", kind: "tool-result", source: "http.request", summary: "forged host", data: { task_id: "host_header_injection_S", ok: true } },
    ];
    const applied = progress.merge(
      { summary: "done", required_tasks: [], completed_tasks: ["host_header_injection_S"], blocked_tasks: [], failed_tasks: [],
        task_outcomes: [{ task_id: "host_header_injection_S", reason: "forged Host changed Location", evidence_ids: ["ev-1"] }],
        advice_decisions: [], evidence_queries: [], hypotheses: [], findings: [], continue: true, tool_requests: [], next_actions: [] } as never,
      evidence as never);
    expect(applied).toBe(false);
    expect(progress.state.tasks.host_header_injection_S?.status).toBe("pending");
    expect(progress.state.taskOutcomeResults?.host_header_injection_S?.issues[0]?.code).toBe("ANOMALY_REQUIRES_DIFF");

    const evidenceWithDiff = [...evidence, { id: "ev-2", kind: "tool-result", source: "http.diff", summary: "diff", data: { task_id: "host_header_injection_S", ok: true } }];
    const second = progress.merge(
      { summary: "done", required_tasks: [], completed_tasks: ["host_header_injection_S"], blocked_tasks: [], failed_tasks: [],
        task_outcomes: [{ task_id: "host_header_injection_S", reason: "diff shows Location change", evidence_ids: ["ev-2"] }],
        advice_decisions: [], evidence_queries: [], hypotheses: [], findings: [], continue: true, tool_requests: [], next_actions: [] } as never,
      evidenceWithDiff as never);
    expect(second).toBe(true);
    expect(progress.state.tasks.host_header_injection_S?.status).toBe("completed");
  });
});

describe("auth gate detection", () => {
  it("blocks the auth task on captcha and records the gate", () => {
    const progress = new BlackboxProgress(state());
    progress.state.tasks.auth_login = { status: "running", playbook: "auth_token" };
    const gated = progress.recordAuthGate("auth_login",
      { task_id: "auth_login", tool: "browser.open", reason: "login", input: { url: "https://h/login" } } as never,
      { tool: "browser.open", ok: true, summary: "page", data: { evaluate: { captcha: true, mfa: false } } } as never);
    expect(gated).toBe(true);
    expect(progress.state.auth_gate?.kind).toBe("captcha");
    expect(progress.state.tasks.auth_login?.status).toBe("blocked");
    expect(progress.state.tasks.auth_login?.outcome_code).toBe("auth_gate");
  });

  it("stays silent on a normal login page", () => {
    const progress = new BlackboxProgress(state());
    expect(progress.recordAuthGate("T1",
      { task_id: "T1", tool: "browser.open", reason: "open", input: { url: "https://h/login" } } as never,
      { tool: "browser.open", ok: true, summary: "page", data: { evaluate: { captcha: false, mfa: false, sso: false, slider: false } } } as never)).toBe(false);
    expect(progress.state.auth_gate).toBeUndefined();
  });
});

describe("playbook inventory stays consistent", () => {
  it("keeps 16 playbooks with unique ids and ascending priorities", () => {
    expect(PLAYBOOKS).toHaveLength(16);
    expect(new Set(PLAYBOOKS.map(p => p.id)).size).toBe(16);
    const priorities = PLAYBOOKS.map(p => p.priority);
    expect([...priorities].sort((a, b) => a - b)).toEqual(priorities);
  });
});

describe("graph playbooks (DAG) render and branch", () => {
  it("race_condition is a graph with a concurrent fanout node", () => {
    const race = playbookById("race_condition")!;
    const fanout = race.steps.find(step => step.id === "fanout")!;
    expect(race.steps.map(step => step.id)).toEqual(["baseline", "lock_state", "fanout", "diff_effect", "confirm_repeat"]);
    expect(fanout.tool).toBe("recon.race_condition");
    expect(fanout.concurrency).toBe(20);
    expect(race.steps.find(step => step.id === "lock_state")!.next).toEqual(["fanout"]);
    expect(race.confirm.evidence).toEqual(["fanout", "diff_effect"]);
  });

  it("renders the graph in the prompt index instead of a flat arrow chain", () => {
    const index = playbookIndex();
    expect(index).toContain("图模式打法 race_condition");
    expect(index).toContain("fanout(recon.race_condition|R)×20 → diff_effect");
    expect(index).toContain("［条件：");
  });
});

describe("logic playbook models the flow instead of rewriting price", () => {
  const logic = playbookById("logic")!;
  it("maps the business chain, then skips / reorders / pollutes state", () => {
    expect(logic.steps.map(step => step.id)).toEqual(["map_flow", "replay_normal", "skip_step", "tamper_state", "reorder", "diff_effect"]);
    expect(logic.steps[0]!.tool).toBe("burp.history");
    const json = JSON.stringify(logic.steps);
    expect(json).not.toContain('"price"');
    expect(logic.confirm.must_show).toContain("非法态");
  });
});

describe("lateral escape (Plan B)", () => {
  it("escalates to the WAF ladder at three blocks before escaping the host", () => {
    const progress = new BlackboxProgress(state());
    for (let index = 0; index < 3; index += 1) {
      progress.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
        { tool: "http.request", ok: true, summary: "blocked", data: { status: 403, body: "Blocked by WAF security policy" } } as never);
    }
    expect(progress.state.blocked_hosts?.["h"]?.hits).toBe(3);
    // WAF 墙先绕：3 次命中先立 waf_bypass 阶梯，阶梯一次没跑不跳横向逃逸。
    expect(progress.state.waf_escalation?.host).toBe("h");
    expect(progress.state.lateral_escape).toBeUndefined();
  });

  it("escapes once the ladder has actually run, or after the wall is verified", () => {
    const withLadder = new BlackboxProgress(state());
    withLadder.recordPlaybookCall("T1", "http.request");
    withLadder.state.playbook_runs = { waf_bypass: { calls: 1, ok: 0, failed: 0 } };
    for (let index = 0; index < 3; index += 1) {
      withLadder.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
        { tool: "http.request", ok: true, summary: "blocked", data: { status: 412, body: "securityfs 您的访问被阻断 /waf" } } as never);
    }
    expect(withLadder.state.lateral_escape?.host).toBe("h");

    // 种子自检确认"两边都被拦"（目标自身的墙）之后，原来的 6 次兜底照旧生效。
    const verified = new BlackboxProgress(state());
    verified.noteSeedHealth("h", { verdict: "host_walled", seeded: 403, anonymous: 403, at: Date.now() });
    for (let index = 0; index < 6; index += 1) {
      verified.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
        { tool: "http.request", ok: true, summary: "blocked", data: { status: 403, body: "Blocked by WAF security policy" } } as never);
    }
    expect(verified.state.lateral_escape?.host).toBe("h");

    // 没验证过自己的凭证就拉黑整机，是 2026-11-07 那两场 17.0M tokens 的直接原因：
    // 门槛翻倍（6 → 12），逼系统先把"墙是不是我方 Cookie 造的"问清楚。
    const stubborn = new BlackboxProgress(state());
    for (let index = 0; index < 6; index += 1) {
      stubborn.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
        { tool: "http.request", ok: true, summary: "blocked", data: { status: 403, body: "Blocked by WAF security policy" } } as never);
    }
    expect(stubborn.state.lateral_escape).toBeUndefined();
    expect(stubborn.state.seed_probe?.host).toBe("h");
    for (let index = 0; index < 6; index += 1) {
      stubborn.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
        { tool: "http.request", ok: true, summary: "blocked", data: { status: 403, body: "Blocked by WAF security policy" } } as never);
    }
    expect(stubborn.state.lateral_escape?.host).toBe("h");
  });

  it("never escalates a wall that turned out to be built by our own cookies", () => {
    const progress = new BlackboxProgress(state());
    progress.noteSeedHealth("h", { verdict: "seed_tainted", seeded: 403, anonymous: 200, tainted: ["cna"], at: Date.now() });
    for (let index = 0; index < 8; index += 1) {
      progress.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
        { tool: "http.request", ok: true, summary: "blocked", data: { status: 403, body: "proxy_authentication_required" } } as never);
    }
    // 一发都不计：这堵墙是我方凭证造的，累计它只会把会话越推越偏。
    expect(progress.state.blocked_hosts?.["h"]).toBeUndefined();
    expect(progress.state.lateral_escape).toBeUndefined();
    expect(progress.state.waf_escalation).toBeUndefined();
  });

  it("does not count anonymous baselines as a host-wide block", () => {
    // 2026-11-07 干净对照：开局自检 healthy，之后 3 发 anonymous:true 的路径探测
    // 撞上阿里云 punish 信封（与毒 cna 假墙同一指纹），仍被记成 blocked_hosts 3 hits。
    const progress = new BlackboxProgress(state());
    progress.noteSeedHealth("h", { verdict: "healthy", seeded: 200, anonymous: 200, at: Date.now() });
    for (let index = 0; index < 5; index += 1) {
      progress.recordHostBlock(
        { task_id: "T1", tool: "http.request", reason: "anonymous baseline", input: { url: "https://h/ecs", anonymous: true } } as never,
        { tool: "http.request", ok: true, summary: "403", data: { status: 403, body: "CLIENT_UNCLASSIFIED proxy_authentication_required attestation" } } as never);
    }
    expect(progress.state.blocked_hosts?.["h"]).toBeUndefined();
    expect(progress.state.waf_escalation).toBeUndefined();
    expect(progress.state.lateral_escape).toBeUndefined();

    // 同一路径带凭证被挡，照常累计：区分的是"请求带不带我方凭证"，不是 URL。
    progress.recordHostBlock(
      { task_id: "T1", tool: "http.request", reason: "seeded", input: { url: "https://h/ecs" } } as never,
      { tool: "http.request", ok: true, summary: "403", data: { status: 403, body: "Blocked by WAF security policy" } } as never);
    expect(progress.state.blocked_hosts?.["h"]?.hits).toBe(1);
  });

  it("stays quiet for a single 403 and for successful responses", () => {
    const progress = new BlackboxProgress(state());
    progress.recordHostBlock(
      { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
      { tool: "http.request", ok: true, summary: "denied", data: { status: 403, body: "no permission" } } as never);
    progress.recordHostBlock(
      { task_id: "T1", tool: "http.request", reason: "probe", input: { url: "https://h/api/doc" } } as never,
      { tool: "http.request", ok: true, summary: "ok", data: { status: 200, body: "fine" } } as never);
    expect(progress.state.blocked_hosts?.["h"]?.hits).toBe(1);
    expect(progress.state.lateral_escape).toBeUndefined();
  });

  it("builds a task that points at subdomains, old versions and mobile prefixes", () => {
    const spec = lateralEscapeTask("h.example.com", "S", { oldVersions: ["/v1/", "/v0/"] });
    expect(spec.id).toBe("lateral_escape_S");
    expect(spec.purpose).toContain("recon.subdomains");
    expect(spec.purpose).toContain("/v1/");
    expect(spec.purpose).toContain("/api/app/");
    expect(spec.playbook).toBe("unauth_exposure");
  });
});
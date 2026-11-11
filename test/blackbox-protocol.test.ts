import { afterEach, describe, expect, it, vi } from "vitest";
import { runBlackboxObserver } from "../src/blackbox/agent.js";
import { mainSchema, observerSchema } from "../src/blackbox/protocol.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evidenceUrls, queryEvidence } from "../src/blackbox/facts.js";

const task = { id: "login", target: "https://app.example.test/login", purpose: "identify login", reason: "discovered link", completion_criteria: "inspect response" };
const evidence = [{ id: "ev-1", kind: "tool-result", data: { task_id: "login", ok: true } }];
describe("blackbox task and evidence protocol", () => {
  it("distinguishes Observer stage acceptance from an explicit safety pause", () => {
    expect(observerSchema.parse({ review: "partial report accepted", decision: "finish", should_continue: false }).decision).toBe("finish");
    expect(observerSchema.safeParse({ review: "pause", decision: "pause" }).success).toBe(false);
    expect(observerSchema.parse({ review: "scope violation", decision: "pause", pause_reason: "task-1 attempted an unauthorized URL" }).decision).toBe("pause");
    expect(observerSchema.safeParse({ review: "conflict", decision: "continue", should_continue: false }).success).toBe(false);
    // 2026-11-10：decision 缺省不再是协议错误——现场 7 次采样里 2 次整份审查死在这条必填上。
    // 缺省语义等于"继续"（desk 的 halt 判据本来也只认 pause / should_continue=false）。
    expect(observerSchema.safeParse({ review: "no decision" }).success).toBe(true);
    expect(observerSchema.parse({ review: "no decision" }).decision).toBeUndefined();
    expect(observerSchema.parse({ review: "legacy safety stop", should_continue: false }).should_continue).toBe(false);
  });
  it("accepts finding reviews that cite nothing, but still refuses a confirmed verdict without evidence", () => {
    // 提示词原文："needs_evidence 不需要新的 evidence_ids"；schema 曾把它写成必填，
    // 于是照规则省略的模型被判协议失败（现场 finding_reviews.0.evidence_ids）。
    const needs = observerSchema.parse({ review: "x", finding_reviews: [{ finding_id: "f1", status: "needs_evidence", reason: "缺一条 diff_auth" }] });
    expect(needs.finding_reviews[0]?.evidence_ids).toEqual([]);
    expect(observerSchema.safeParse({ review: "x", finding_reviews: [{ finding_id: "f1", status: "confirmed", evidence_ids: [] }] }).success).toBe(false);
  });

  it("retrieves old evidence by identity, task and discovered endpoint", () => {
    const old = { id: "ev-old", kind: "tool-result", data: { task_id: "crawl", urls: [task.target] } };
    const all = [...Array.from({ length: 120 }, (_, i) => ({ id: `ev-new-${i}`, data: {} })), old];
    expect(queryEvidence(all, [{ evidence_id: "ev-old" }])).toEqual([old]);
    expect(queryEvidence(all, [{ task_id: "crawl", url: task.target }])).toEqual([old]);
    expect(queryEvidence(all, [{ task_id: "other", evidence_id: "ev-old" }])).toEqual([]);
    expect(evidenceUrls(old)).toEqual([task.target]);
  });
  it("rejects malformed structures and unsupported tool parameters before execution", () => {
    expect(mainSchema.safeParse({ summary: "test", completed_tasks: "all" }).success).toBe(false);
    expect(mainSchema.safeParse({ summary: "test", tool_requests: [{ tool: "http.request", input: { method: "POST", json: { user: "alice" }, headers: { authorization: "Bearer x" } } }] }).success).toBe(true);
    expect(mainSchema.safeParse({ summary: "test", tool_requests: [{ tool: "http.request", input: { method: "TRACE" } }] }).success).toBe(false);
    expect(mainSchema.safeParse({ summary: "test", tool_requests: [{ tool: "http.request", input: { body: "x", json: {} } }] }).success).toBe(false);
      // 未知键不再整条拒绝（2026-10-28：strict 让"工具存在但用不了"）：schema 放行、执行器摘键。
      expect(mainSchema.safeParse({ summary: "test", tool_requests: [{ tool: "http.request", input: { command: "arbitrary" } }] }).success).toBe(true);
    expect(observerSchema.safeParse({ review: "test", should_continue: "yes" }).success).toBe(false);
  });
  it("accepts every registered blackbox tool and its bounded wordlist input", () => {
    const tools = [
      "browser.open", "browser.screenshot", "http.request", "burp.check", "burp.request", "burp.history", "burp.sitemap", "burp.entry", "burp.issues", "katana.crawl",
      "recon.subdomains", "recon.dns", "recon.http_probe", "recon.ports", "recon.historical_urls",
      "recon.content_discovery", "recon.nuclei",
    ];
    const parsed = mainSchema.safeParse({
      summary: "tool coverage",
      tool_requests: tools.map((tool) => ({ tool, input: tool === "recon.content_discovery" ? { wordlist: "/approved/words.txt" } : {} })),
    });
    expect(parsed.success).toBe(true);
  });
  it("exposes every tool to the main agent without a confirmation requirement", () => {
    const parsed = mainSchema.safeParse({
      summary: "no approval gate",
      tool_requests: ["burp.check", "burp.request", "burp.history", "burp.sitemap", "burp.entry", "burp.issues", "recon.nuclei", "recon.sql", "recon.xss"]
        .map(tool => ({ tool, input: {} })),
    });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.tool_requests.every(request => request.requires_confirmation === false)).toBe(true);
  });
  it("requires successful evidence from the same task and a completion explanation", () => {
    const p = new BlackboxProgress();
    p.merge({ required_tasks: [task] });
    expect(p.merge({ completed_tasks: ["login"] }, evidence)).toBe(false);
    const output = { completed_tasks: ["login"], task_outcomes: [{ task_id: "login", reason: "response examined", evidence_ids: ["ev-1"] }] };
    expect(p.merge(output, [{ ...evidence[0]!, data: { task_id: "other" } }])).toBe(false);
    expect(p.merge(output, evidence)).toBe(true);
    expect(p.state.tasks.login).toMatchObject({ status: "completed", purpose: task.purpose, evidence_ids: ["ev-1"], outcome_reason: "response examined" });
    p.merge({ completed_tasks: ["invented"] }, evidence);
    expect(p.state.tasks.invented).toBeUndefined();
    expect(new BlackboxProgress(JSON.parse(JSON.stringify(p.state))).state.tasks.login?.evidence_ids).toEqual(["ev-1"]);
  });
  it("keeps Observer advice separate and records explicit acceptance", () => {
    const p = new BlackboxProgress();
    p.supplement({ supplemental_tasks: [task] }, "ev-advice");
    expect(p.lists().pending_tasks).toEqual([]);
    p.merge({ advice_decisions: [{ advice_id: "ev-advice", accepted: true, reason: "useful", task_ids: ["login"] }] });
    expect(p.state.advice?.["ev-advice"]?.status).toBe("pending");
    p.merge({ required_tasks: [task], advice_decisions: [{ advice_id: "ev-advice", accepted: true, reason: "useful", task_ids: ["login"] }] });
    expect(p.state.advice?.["ev-advice"]).toMatchObject({ status: "accepted", task_ids: ["login"] });
    expect(p.state.planRevision).toBe(1);
    p.merge({ required_tasks: [task] });
    expect(p.state.planRevision).toBe(1);
  });
});

/**
 * Observer 输出的"逐条抢救"（2026-11-10）。
 *
 * 现场采样同一会话 7 次调用：成功 3、失败 4。失败全是 schema 级——一条
 * finding_review 少了 evidence_ids，或整份漏了 decision——但主 Agent 早有
 * "坏一条只丢一条"的抢救，Observer 没有，于是一条毛刺否掉 1600 字审查。
 */
describe("Observer 输出抢救", () => {
  const values = {
    BLACKBOX_AGENT_BASE_URL: "https://api.example.test/v1",
    BLACKBOX_AGENT_MODEL: "probe-model",
    BLACKBOX_AGENT_API_KEY: "k",
    BLACKBOX_AGENT_PROXY_URL: "",
  };
  const session = { id: "s1", target: "https://app.example.test/", checkpoint: {}, evidence: [], events: [] };
  const reply = (output: unknown) => Response.json({ choices: [{ message: { content: JSON.stringify(output) } }] });

  afterEach(() => vi.unstubAllGlobals());

  it("丢掉自造的 next_step，保住整份审查", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => reply({
      review: "本轮三条 root 都已落地真实响应，但缺一条 diff_auth 对照。",
      concerns: ["缺对照"],
      suggestions: ["补一条 http.diff"],
      next_steps: [
        { tool: "http.diff", target: "https://app.example.test/api", input: {}, why: "补对照" },
        { tool: "made.up.tool", target: "https://app.example.test/api", why: "自造工具名" },
      ],
      decision: "continue",
    })));
    const out = await runBlackboxObserver(values, session, {}, { summary: "probe" });
    expect(String(out.review)).toContain("三条 root");
    expect(out.protocol_error).toBeUndefined();
    expect((out.next_steps as unknown[])?.length).toBe(1);
    expect((out._dropped as Array<{ field: string }>)[0]?.field).toBe("next_steps");
  });

  it("finding_reviews 缺 evidence_ids 时按 needs_evidence 放行", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => reply({
      review: "发现 f1 证据不足。",
      finding_reviews: [{ finding_id: "f1", status: "needs_evidence", reason: "缺一条 diff_auth" }],
      decision: "continue",
    })));
    const out = await runBlackboxObserver(values, session, {}, { summary: "probe" });
    expect(out.protocol_error).toBeUndefined();
    expect((out.finding_reviews as Array<{ evidence_ids: string[] }>)[0]?.evidence_ids).toEqual([]);
  });
});

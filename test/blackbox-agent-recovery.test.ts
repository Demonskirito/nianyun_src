import { afterEach, describe, expect, it, vi } from "vitest";
import { runBlackboxMainAgent } from "../src/blackbox/agent.js";

const values = { BLACKBOX_AGENT_BASE_URL: "https://llm.example.test/v1", BLACKBOX_AGENT_MODEL: "m", BLACKBOX_AGENT_API_KEY: "k" };
const session = { id: "s1", target: "https://app.example.test/" };
const candidate = { id: "c1", target: "https://app.example.test/" };

const reply = (content: string) => Response.json({ choices: [{ message: { content } }], usage: { prompt_tokens: 10, completion_tokens: 20 } });
const replyRich = (opts: { content: string; finish?: string; reasoning?: string; tokens?: number; reasoningTokens?: number }) => Response.json({
  choices: [{ message: { content: opts.content, ...(opts.reasoning ? { reasoning_content: opts.reasoning } : {}), }, finish_reason: opts.finish ?? "stop" }],
  usage: {
    prompt_tokens: 10,
    completion_tokens: opts.tokens ?? 20,
    ...(opts.reasoningTokens !== undefined ? { completion_tokens_details: { reasoning_tokens: opts.reasoningTokens } } : {}),
  },
});

afterEach(() => { vi.unstubAllGlobals(); });

describe("main agent recovery", () => {
  it("retries once with a compact-output instruction when the JSON body is truncated", async () => {
    const bodies: string[] = [];
    const fetchMock = vi.fn(async (_url, init) => {
      const body = String((init as RequestInit).body);
      bodies.push(body);
      return bodies.length === 1
        ? reply('{"summary":"plan","required_tasks":[{"id":"t1","target":"https://app.example.test/","purpose":"probe","reason":"r","completion_criteria":')
        : reply('{"summary":"recovered","required_tasks":[{"id":"t1","target":"https://app.example.test/","purpose":"probe","reason":"r","completion_criteria":"c"}],"tool_requests":[]}');
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(bodies[1]).toContain("上一次输出");
    expect(result._recovered).toBe(true);
    expect(result.summary).toBe("recovered");
    expect(result.parse_error).toBeUndefined();
  });

  it("does not retry a complete but malformed answer", async () => {
    const fetchMock = vi.fn(async () => reply('{"summary": 42, "tool_requests": "nope"}'));
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // A schema failure is salvaged into a structured protocol error instead of a parse error.
    expect(result.parse_error).toBeUndefined();
  });

  it("reports a parse error with the truncated flag when the retry is also unusable", async () => {
    const fetchMock = vi.fn(async () => reply('{"summary":"cut'));
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ parse_error: true, truncated: true });
  });
});

/**
 * 2026-11-02 遗留：实跑里出现"模型连续 3 轮空输出"。根因有两层：
 * 1) 空正文被 `|| "{}"` 兜成合法空对象 → 一次空响应伪装成"零动作回合"，事件里看不到原因；
 * 2) 推理模型把 max_tokens 吃在思维链上时 finish_reason=length、正文为空，用同样的参数重试只会再空一次。
 * 这里锁住"分类 + 换参数重试"，防止回退到"闷头重发同一个请求"。
 */
describe("empty-output triage", () => {
  const good = '{"summary":"ok","tool_requests":[]}';

  it("classifies reasoning-exhausted empty content and retries with a bigger budget and no JSON mode", async () => {
    const bodies: string[] = [];
    const fetchMock = vi.fn(async (_url, init) => {
      bodies.push(String((init as RequestInit).body));
      return bodies.length === 1
        ? replyRich({ content: "", finish: "length", reasoning: "想了很久……".repeat(200), tokens: 12000, reasoningTokens: 12000 })
        : replyRich({ content: good, finish: "stop", tokens: 40 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const first = JSON.parse(bodies[0]) as Record<string, unknown>;
    const second = JSON.parse(bodies[1]) as Record<string, unknown>;
    // 第一次仍是 JSON 模式；第二次必须换参数，而不是原样重发。
    expect(first.response_format).toEqual({ type: "json_object" });
    expect(second.response_format).toBeUndefined();
    expect(Number(second.max_tokens)).toBeGreaterThan(Number(first.max_tokens));
    expect(result).toMatchObject({ summary: "ok", _recovered: true, _recovered_kind: "empty:reasoning_exhausted" });
    expect(result.parse_error).toBeUndefined();
  });

  it("treats an empty content with finish_reason=stop as empty_content, not as an empty round", async () => {
    const bodies: string[] = [];
    const fetchMock = vi.fn(async (_url, init) => {
      bodies.push(String((init as RequestInit).body));
      return bodies.length === 1 ? replyRich({ content: "", finish: "stop" }) : replyRich({ content: good });
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.parse(bodies[1]).response_format).toBeUndefined();
    expect(result).toMatchObject({ summary: "ok", _recovered_kind: "empty:empty_content" });
  });

  it("surfaces the empty reason instead of a fake empty JSON object when both attempts are blank", async () => {
    const fetchMock = vi.fn(async () => replyRich({ content: "", finish: "length", tokens: 12000, reasoningTokens: 12000 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ parse_error: true, empty_reason: "reasoning_exhausted" });
    expect(result.summary).toBe("");
    // 关键回归：空正文绝不能被当成"合法的零动作回合"。
    expect(result.protocol_error).toBeUndefined();
    expect((result._diag as Record<string, unknown>).empty_reason).toBe("reasoning_exhausted");
  });

  it("distinguishes reasoning-only output from a genuinely empty response", async () => {
    const fetchMock = vi.fn(async () => replyRich({ content: "", finish: "stop", reasoning: "只有思维链", tokens: 300, reasoningTokens: 300 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await runBlackboxMainAgent(values, session, candidate);
    expect(result).toMatchObject({ parse_error: true, empty_reason: "reasoning_only" });
  });
});
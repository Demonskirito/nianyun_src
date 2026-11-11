import { describe, expect, it } from "vitest";
import { mainSchema, splitToolInput } from "../src/blackbox/protocol.js";

const parse = (input: Record<string, unknown>) => mainSchema.safeParse({ summary: "s", tool_requests: [{ tool: "http.request", reason: "r", input }] });

describe("tool input schema", () => {
  it("accepts the credential controls the executor reads", () => {
    for (const input of [
      { url: "https://h/a", anonymous: true },
      { url: "https://h/a", no_auth: true },
      { url: "https://h/a", use_jar: false },
      { url: "https://h/a", jwt: "ey.x.y" },
      { url: "https://h/a", cookies: { sid: "1" } },
      { url: "https://h/a", cookies: ["sid=1"] },
      { url: "https://h/a", cookie_jar: "sid=1; x=2" },
      { url: "https://h/a", follow_redirects: true },
      { url: "https://h/a", timing_threshold_ms: 1800 },
      { url: "https://h/a", bypass_auth_wall: true },
    ]) {
      const result = parse(input);
      // 之前这些字段被 .strict() 直接拒掉，整条 tool_request 被静默丢弃。
      expect(result.success, JSON.stringify(input)).toBe(true);
      if (result.success) expect(result.data.tool_requests[0]!.input).toMatchObject(input);
    }
  });

  it("strips genuinely unknown fields instead of voiding the request", () => {
    // 2026-10-28：过去这里是 `.strict()` → 多写一个键整条请求消失，模型连着三轮发不出请求。
    // 现在 schema 走 passthrough，由执行器按白名单摘键；"可以用但键没生效"比"整条没了"可救。
    const parsed = parse({ url: "https://h/a", not_a_real_field: 1 });
    expect(parsed.success).toBe(true);
    const split = splitToolInput({ url: "https://h/a", not_a_real_field: 1 });
    expect(split.ignored).toEqual(["not_a_real_field"]);
    expect(split.clean).toEqual({ url: "https://h/a" });
  });

  it("clamps the timing threshold range", () => {
    expect(parse({ url: "https://h/a", timing_threshold_ms: -1 }).success).toBe(false);
    expect(parse({ url: "https://h/a", timing_threshold_ms: 600001 }).success).toBe(false);
  });

  it("通用注释键既不下传执行器、也不算未知参数，而是单独回执（2026-11-07）", () => {
    const split = splitToolInput({ url: "https://h/a", reason: "确认是否 403", note: "别重打", not_a_real_field: 1 });
    expect(split.clean).toEqual({ url: "https://h/a" });
    expect(split.ignored).toEqual(["not_a_real_field"]);
    expect(split.annotations).toEqual(["reason", "note"]);
  });

  it("理由的正确位置是外层 tool_requests[].reason，而不是 input", () => {
    const parsed = mainSchema.parse({ summary: "s", tool_requests: [
      { tool: "http.request", reason: "确认 403", input: { url: "https://h/a" } },
    ] });
    expect(parsed.tool_requests[0]?.reason).toBe("确认 403");
    expect(parsed.tool_requests[0]?.input).not.toHaveProperty("reason");
  });
});

import { describe, expect, it } from "vitest";
import { captureTokens, normalizeAuthInput } from "../src/blackbox/authinput.js";

const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4NiIsImV4cCI6MTc5MDAwMDAwMH0.c2lnbmF0dXJlLXZhbHVl";

describe("顶层 token 自动转 Authorization（协议宽容）", () => {
  it("turns a bare JWT in token into a Bearer header and deletes the field", () => {
    const { input, notes, changed } = normalizeAuthInput({ url: "https://h/api/me", token: jwt });
    expect(changed).toBe(true);
    expect((input.headers as Record<string, string>).Authorization).toBe(`Bearer ${jwt}`);
    expect(input.token).toBeUndefined();
    expect(notes.join(" ")).toContain("Bearer");
    expect(notes.join(" ")).not.toContain(jwt);
  });

  it("accepts jwt / access_token / bearer aliases and keeps explicit schemes", () => {
    for (const field of ["jwt", "access_token", "id_token", "auth_token"]) {
      const { input } = normalizeAuthInput({ url: "https://h/", [field]: jwt });
      expect((input.headers as Record<string, string>).Authorization).toBe(`Bearer ${jwt}`);
    }
    const explicit = normalizeAuthInput({ url: "https://h/", token: `Bearer ${jwt}` });
    expect((explicit.input.headers as Record<string, string>).Authorization).toBe(`Bearer ${jwt}`);
    const opaque = normalizeAuthInput({ url: "https://h/", token: "3f9a1c2b7d4e5f60718293a4b5c6d7e8" });
    expect((opaque.input.headers as Record<string, string>).Authorization).toBe("3f9a1c2b7d4e5f60718293a4b5c6d7e8");
  });

  it("never overrides an explicit Authorization header", () => {
    const { input, notes } = normalizeAuthInput({ url: "https://h/", token: jwt, headers: { authorization: "Bearer REAL" } });
    expect((input.headers as Record<string, string>).authorization).toBe("Bearer REAL");
    expect((input.headers as Record<string, string>).Authorization).toBeUndefined();
    expect(input.token).toBeUndefined();
    expect(notes.join(" ")).toContain("不覆盖");
  });

  it("merges cookies objects/arrays into one Cookie header", () => {
    const fromObject = normalizeAuthInput({ url: "https://h/", cookies: { SESSION: "abc", uid: 86 }, cookie: "a=1" });
    const header = (fromObject.input.headers as Record<string, string>).Cookie;
    expect(header).toContain("a=1");
    expect(header).toContain("SESSION=abc");
    expect(header).toContain("uid=86");
    expect(fromObject.input.cookies).toBeUndefined();

    const fromArray = normalizeAuthInput({ url: "https://h/", cookies: [{ name: "S", value: "1" }, "t=2"] });
    const arrayHeader = (fromArray.input.headers as Record<string, string>).Cookie;
    expect(arrayHeader).toContain("S=1");
    expect(arrayHeader).toContain("t=2");
  });

  it("leaves unrelated inputs untouched", () => {
    const source = { url: "https://h/", headers: { Accept: "application/json" }, body: { a: 1 } };
    const { input, changed } = normalizeAuthInput(source);
    expect(changed).toBe(false);
    expect(input).toEqual(source);
  });
});

describe("从浏览器里捕获 Token", () => {
  it("finds JWTs in evaluate output and keeps only the raw value", () => {
    const tokens = captureTokens({ evaluate: { localStorage: { access_token: jwt }, user: "alice" } }, "bdev.oppo.com");
    expect(tokens).toHaveLength(1);
    expect(tokens[0]).toMatchObject({ host: "bdev.oppo.com", name: "access_token", value: jwt, scheme: "Bearer" });
  });

  it("strips an existing Bearer prefix and ignores short/noise strings", () => {
    const tokens = captureTokens({ token: `Bearer ${jwt}`, other: "short", random: "not-a-token" }, "id.oppo.com");
    expect(tokens.map(token => token.value)).toEqual([jwt]);
  });

  it("parses a JSON string from evaluate before scanning", () => {
    const tokens = captureTokens({ evaluate: JSON.stringify({ ls: { access_token: jwt }, ck: "a=1" }) }, "bdev.oppo.com");
    expect(tokens.map(token => token.value)).toEqual([jwt]);
    expect(tokens[0]?.name).toBe("access_token");
  });

  it("returns nothing when there is no host or no token", () => {
    expect(captureTokens({ token: jwt }, "")).toEqual([]);
    expect(captureTokens({ page: "hello" }, "h")).toEqual([]);
  });
});
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { declaredToolInputKeys, splitToolInput, toolInputSchema } from "../src/blackbox/protocol.js";

/**
 * schema / 执行器漂移守卫。
 *
 * 2026-10-28 两次事故：
 *   ① `.strict()` 挡掉了 48 个执行器真在读的键（variant / pattern / tool …），
 *      工具"存在但用不了"，模型只收到「格式无效」；
 *   ② 改成 `.passthrough()` 之后，未登记的键会被 `splitToolInput()` 静默摘掉——
 *      同样是"工具用不了"，只是不再报错，更隐蔽。
 * 所以守卫的目标从"strict 不拒绝"变成"**执行器读的键必须被 schema 声明**"，
 * 声明了就不会被摘掉。
 */
const SOURCES = ["src/blackbox/tools.ts", "src/blackbox/workspace.ts"];

function keysUsedByExecutors(): string[] {
  const used = new Set<string>();
  for (const path of SOURCES) {
    const text = readFileSync(path, "utf8");
    for (const match of text.matchAll(/\binput\.([a-z_][a-z0-9_]*)\b/g)) used.add(match[1]!);
  }
  return [...used].sort();
}

describe("toolInputSchema 必须覆盖执行器真正读取的键", () => {
  it("没有漂移：执行器读的每个顶层键都被 schema 声明（否则会被 splitToolInput 摘掉）", () => {
    const declared = new Set(declaredToolInputKeys());
    const missing = keysUsedByExecutors().filter(key => !declared.has(key));
    expect(missing).toEqual([]);
  });

  it("核心键能通过 schema（不是被 passthrough 之后再被摘）", () => {
    const cases: Array<Record<string, unknown>> = [
      { variant: { url: "https://a.example.test/x", headers: { "x-forwarded-host": "evil.example" } }, url: "https://a.example.test/x" },
      { variant_url: "https://a.example.test/y" },
      { pattern: "api/[a-z]+", path: ".", max_matches: 20 },
      { evidence_id: "ev-0123456789abcdef", tool: "http.request", offset: 0, limit: 500 },
      { cookie: "a=1", anonymous: true, follow_redirects: false },
      // 枚举类工具的真正常用键：少了这一条，模型写的 threads 会被摘掉，
      // 然后回执只告诉它"可用：url, params"——等于教它"并发不可调"（2026-11-06 实测）。
      { url: "https://a.example.test/", wordlist: "paths.txt", threads: 20 },
      // scan_profile 明说 katana 可以 depth≤8、duration≤300；schema 卡在 3/60 时，
      // 照着规则写 depth=8 会整条请求校验失败（不是摘键，是直接拒）。
      { url: "https://a.example.test/", depth: 8, duration_seconds: 300 },
    ];
    for (const value of cases) {
      expect(toolInputSchema.safeParse(value).success, `${JSON.stringify(value)} 被 schema 拒绝`).toBe(true);
      expect(splitToolInput(value).ignored, `${JSON.stringify(value)} 被当成未知键摘掉`).toEqual([]);
    }
  });

  it("未知键不丢整条请求：只摘键，并回执键名", () => {
    const request = { url: "https://a.example.test/", baseline: "https://a.example.test/", variant_label: "x" };
    expect(toolInputSchema.safeParse(request).success).toBe(true);
    const { clean, ignored } = splitToolInput(request);
    expect(clean).toEqual({ url: "https://a.example.test/" });
    expect(ignored.sort()).toEqual(["baseline", "variant_label"]);
  });

  it("互斥的 body 形态仍然被拦（passthrough 不等于放开约束）", () => {
    expect(toolInputSchema.safeParse({ url: "https://a.example.test/", body: "x", json: { a: 1 } }).success).toBe(false);
  });
});
import { describe, expect, it } from "vitest";
import { bodySimilarity, diffResponses } from "../src/blackbox/tools.js";

const response = (status: number, body: string, duration_ms = 10) => ({ status, body, body_bytes: Buffer.byteLength(body), duration_ms });

describe("http.diff primitives", () => {
  it("calls identical responses identical", () => {
    const diff = diffResponses(response(200, "<h1>same</h1>"), response(200, "<h1>same</h1>"));
    expect(diff.verdict).toBe("identical");
    expect((diff.delta as Record<string, unknown>).similarity).toBe(1);
    expect(String(diff.hint)).toContain("缺鉴权");
  });

  it("separates another user's payload from the same page shape", () => {
    const baseline = response(200, JSON.stringify({ user: "alice", phone: "13800000000", orders: [1, 2, 3] }));
    const other = response(200, JSON.stringify({ user: "bob", phone: "13900000000", orders: [9, 8, 7] }));
    const diff = diffResponses(baseline, other);
    // Same status, different body: the IDOR signature.
    expect(diff.verdict).not.toBe("identical");
    expect((diff.delta as Record<string, unknown>).status_changed).toBe(false);
    expect(String(diff.hint)).toContain("越权");
  });

  it("flags a guard bypass when the variant flips an error into 200", () => {
    const diff = diffResponses(response(403, "forbidden"), response(200, '{"data":"secret"}'));
    expect((diff.delta as Record<string, unknown>).status_changed).toBe(true);
    expect(String(diff.hint)).toContain("bypassed");
  });

  it("exposes a timing delta for blind injection probes", () => {
    const diff = diffResponses(response(200, "ok", 40), response(200, "ok", 5040));
    expect((diff.delta as Record<string, unknown>).duration_delta_ms).toBe(5000);
    // turn 62：时间维度是硬判定，正文相同也必须判 timing_delta，否则 sleep(5) 永远确认不了。
    expect(diff.verdict).toBe("timing_delta");
    expect((diff.timing as Record<string, unknown>).suspect).toBe(true);
  });

  it("scores unrelated bodies as different and similar pages as same_shape", () => {
    expect(bodySimilarity("alpha beta gamma delta epsilon", "one two three four five")).toBe(0);
    const page = Array.from({ length: 60 }, (_, index) => `token${index}`).join(" ");
    expect(bodySimilarity(page, page.replace("token3", "changed"))).toBeGreaterThan(0.8);
    expect(diffResponses(response(200, page), response(200, `${page} extra`)).verdict).toBe("same_shape");
  });
});
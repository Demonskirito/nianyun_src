import { describe, expect, it } from "vitest";
import { charNgramSimilarity, diffResponses, jsonShapeDiff } from "../src/blackbox/diff.js";

const res = (status: number, body: string, duration_ms = 40) => ({ status, body, body_bytes: Buffer.byteLength(body), duration_ms });
const delta = (diff: ReturnType<typeof diffResponses>) => diff.delta as unknown as Record<string, number | boolean>;

describe("时间维度硬判定（时间盲注 / 命令注入）", () => {
  it("flags sleep(5) with an identical body as timing_delta instead of identical", () => {
    const body = '{"code":10403,"msg":"TOKEN 错误","data":null}';
    const diff = diffResponses(res(200, body, 40), res(200, body, 5040));
    expect(diff.verdict).toBe("timing_delta");
    expect(diff.timing.suspect).toBe(true);
    expect(diff.timing.delta_ms).toBe(5000);
    expect(diff.timing.threshold_ms).toBe(2000);
    expect(diff.hint).toContain("时间盲注");
  });

  it("respects a per-call threshold and ignores sub-threshold jitter", () => {
    expect(diffResponses(res(200, "ok", 40), res(200, "ok", 340), { timingThresholdMs: 200 }).verdict).toBe("timing_delta");
    expect(diffResponses(res(200, "ok", 40), res(200, "ok", 190)).verdict).toBe("identical");
    expect(diffResponses(res(200, "ok", 40), res(200, "ok", 5040)).timing.threshold_ms).toBe(2000);
  });

  it("does not let a slow-but-different body hide behind timing", () => {
    const diff = diffResponses(res(200, JSON.stringify({ user: "alice" }), 40), res(200, JSON.stringify({ user: "bob", extra: 1 }), 5040));
    expect(diff.timing.suspect).toBe(true);
    expect(diff.verdict).toBe("different");
  });
});

describe("JSON 结构化比对 + 噪音过滤", () => {
  it("treats timestamp/requestId/traceId churn as identical", () => {
    const base = JSON.stringify({ code: 0, data: { id: 86, name: "张三" }, timestamp: 1, requestId: "a", traceId: "t1" });
    const variant = JSON.stringify({ code: 0, data: { id: 86, name: "张三" }, timestamp: 2, requestId: "b", traceId: "t2" });
    const diff = diffResponses(res(200, base), res(200, variant));
    expect(diff.verdict).toBe("identical");
    expect(diff.shape.kind).toBe("json");
    expect(diff.shape.json?.noise_removed).toBeGreaterThanOrEqual(3);
    expect(diff.shape.json?.changed).toEqual([]);
    expect(diff.hint).toContain("噪音");
  });

  it("reports the changed field paths when the payload belongs to another identity", () => {
    const base = JSON.stringify({ code: 0, data: { id: 86, name: "张三", phone: "138****0000" }, timestamp: 1 });
    const variant = JSON.stringify({ code: 0, data: { id: 90, name: "李四", phone: "139****1111" }, timestamp: 2 });
    const diff = diffResponses(res(200, base), res(200, variant));
    expect(diff.verdict).toBe("same_shape");
    const paths = (diff.shape.json?.changed || []).map(item => item.path);
    expect(paths).toContain("data.id");
    expect(paths).toContain("data.name");
    expect(paths).not.toContain("timestamp");
  });

  it("marks a new key as a structural change", () => {
    const diff = diffResponses(res(200, JSON.stringify({ code: 0, data: { id: 1 } })), res(200, JSON.stringify({ code: 0, data: { id: 1, token: "x" } })));
    expect(diff.verdict).toBe("different");
    expect(diff.shape.json?.added).toContain("data.token");
    expect(diff.shape.json?.same_structure).toBe(false);
  });

  it("handles arrays and nested noise keys", () => {
    const shape = jsonShapeDiff(
      { list: [{ id: 1, ts: 1 }, { id: 2, ts: 2 }], meta: { serverTime: 1, page: 1 } },
      { list: [{ id: 1, ts: 9 }, { id: 2, ts: 8 }], meta: { serverTime: 5, page: 1 } },
    );
    expect(shape.changed).toEqual([]);
    expect(shape.added).toEqual([]);
    expect(shape.noise_removed).toBeGreaterThanOrEqual(3);
    expect(shape.same_structure).toBe(true);
  });
});

describe("中文与长度兜底", () => {
  it("scores near-identical Chinese HTML high where token shingles collapse to 0", () => {
    const page = "<html><body>" + "订单管理后台系统用户权限配置页面".repeat(30) + "</body></html>";
    const near = page.replace("订单管理后台系统", "订单管理前台系统");
    expect(charNgramSimilarity(page, near)).toBeGreaterThan(0.9);
    const diff = diffResponses(res(200, page), res(200, near));
    expect(diff.verdict).toBe("same_shape");
    expect(diff.shape.metric).toBe("char3gram");
  });

  it("treats a 20%+ length difference as different without deep text work", () => {
    const base = "a".repeat(1000);
    const diff = diffResponses(res(200, base), res(200, "a".repeat(1300)));
    expect(diff.verdict).toBe("different");
    expect(delta(diff).bytes_ratio).toBeCloseTo(0.3, 5);
    expect(diff.hint).toContain("20%");
  });

  it("keeps the status-change and guard-bypass semantics", () => {
    const bypass = diffResponses(res(403, "forbidden"), res(200, '{"data":"secret"}'));
    expect(bypass.verdict).toBe("different");
    expect(bypass.hint).toContain("bypassed");
    expect(delta(bypass).status_changed).toBe(true);
  });
});
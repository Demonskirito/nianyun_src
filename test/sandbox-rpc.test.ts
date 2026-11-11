import { describe, expect, it } from "vitest";
import { parseRpcRequests, rpcPythonHelper, RPC_DISPATCH_PATH, RPC_QUEUES, RPC_WHITELIST, RPC_MAX_PER_CALL } from "../src/blackbox/sandbox_rpc.js";

const line = (record: Record<string, unknown>) => JSON.stringify(record);

describe("统一 RPC 协议（dispatch.jsonl）", () => {
  it("只有一个正路队列，其它都是带迁移提示的遗留项", () => {
    expect(RPC_DISPATCH_PATH).toBe("rpc/dispatch.jsonl");
    expect(RPC_QUEUES[0]!.path).toBe(RPC_DISPATCH_PATH);
    expect(RPC_QUEUES[0]!.legacy).toBeUndefined();
    const legacy = RPC_QUEUES.filter(queue => queue.legacy);
    expect(legacy.length).toBeGreaterThan(0);
    for (const queue of legacy) expect(queue.legacy).toMatch(/已废弃/);
  });

  it("mode 缺省 = standard，input 原样透传", () => {
    const parsed = parseRpcRequests(line({ tool: "http.request", input: { url: "https://t/x", method: "POST", headers: { "X-Sign": "abc" } } }), 0);
    expect(parsed.skipped).toEqual([]);
    expect(parsed.requests[0]).toMatchObject({ tool: "http.request", mode: "standard" });
    expect((parsed.requests[0]!.input.headers as Record<string, string>)["X-Sign"]).toBe("abc");
  });

  it("mode=concurrent：threads 收敛成 count，缺 tool 时默认 race 工具", () => {
    const parsed = parseRpcRequests(line({ mode: "concurrent", threads: 20, url: "https://t/api/coupon", method: "POST", input: { body: "{}" } }), 0);
    expect(parsed.skipped).toEqual([]);
    expect(parsed.requests[0]).toMatchObject({ tool: "recon.race_condition", mode: "concurrent" });
    expect(parsed.requests[0]!.input).toMatchObject({ count: 20, url: "https://t/api/coupon", method: "POST", body: "{}" });
  });

  it("threads 越界被夹到 2–50", () => {
    expect(parseRpcRequests(line({ mode: "concurrent", threads: 999 }), 0).requests[0]!.input.count).toBe(50);
    expect(parseRpcRequests(line({ mode: "concurrent", threads: 1 }), 0).requests[0]!.input.count).toBe(2);
  });

  it("mode=concurrent 绑死了竞态工具，别的工具不行", () => {
    const parsed = parseRpcRequests(line({ tool: "http.request", mode: "concurrent", threads: 5 }), 0);
    expect(parsed.requests).toEqual([]);
    expect(parsed.skipped[0]!.why).toMatch(/只能用于 recon\.race_condition/);
  });

  it("废弃字段给出可照做的迁移提示，而不是静默忽略", () => {
    for (const key of ["context_override", "from_state", "state_files"]) {
      const parsed = parseRpcRequests(line({ tool: "http.request", input: { url: "https://t/x" }, [key]: {} }), 0);
      expect(parsed.requests, key).toEqual([]);
      expect(parsed.skipped[0]!.why, key).toContain("已废弃");
      expect(parsed.skipped[0]!.why, key).toContain("input.headers");
    }
  });

  it("白名单之外的工具有明确驳回原因", () => {
    const parsed = parseRpcRequests(line({ tool: "exec.bash", input: { script: "id" } }), 0);
    expect(parsed.requests).toEqual([]);
    expect(parsed.skipped[0]!.why).toMatch(/not RPC-callable/);
    expect(RPC_WHITELIST).toContain("http.request");
  });

  it("每次最多 4 条，cursor 停在消费处", () => {
    const raw = Array.from({ length: 6 }, (_, index) => line({ tool: "http.request", input: { url: `https://t/${index}` } })).join("\n");
    const first = parseRpcRequests(raw, 0);
    expect(first.requests).toHaveLength(RPC_MAX_PER_CALL);
    expect(first.next_cursor).toBe(RPC_MAX_PER_CALL);
    const second = parseRpcRequests(raw, first.next_cursor);
    expect(second.requests).toHaveLength(2);
    expect(second.next_cursor).toBe(6);
  });

  it("坏行逐条跳过，不影响同批其它请求", () => {
    const raw = ["not json", line({ tool: "http.request", input: { url: "https://t/ok" } })].join("\n");
    const parsed = parseRpcRequests(raw, 0);
    expect(parsed.requests).toHaveLength(1);
    expect(parsed.skipped[0]!.why).toBe("invalid JSON");
  });

  it("helper 写 dispatch.jsonl，带 mode 与 threads", () => {
    const helper = rpcPythonHelper();
    expect(helper).toContain("dispatch.jsonl");
    expect(helper).toContain("mode");
    expect(helper).toContain("threads");
    expect(helper).not.toContain("requests.jsonl");
  });
});
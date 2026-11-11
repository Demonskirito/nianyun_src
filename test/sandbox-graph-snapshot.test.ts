import { describe, expect, it } from "vitest";
import { runSandboxTool } from "../src/blackbox/sandbox_tools.js";
import type { BlackboxToolContext } from "../src/blackbox/tools.js";
import { graphContextView, graphState, ingestToolResult } from "../src/blackbox/graph/index.js";

function graphWithTopology(): ReturnType<typeof graphState> {
  const state = graphState(undefined);
  ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: "https://t.example/api/order" }] });
  ingestToolResult(state, { tool: "http.request", identity: "buyer",
    endpoints: [{ url: "https://t.example/api/order", status_code: 403, auth_required: true, blocked: true, params: ["order_id"] }] });
  return state;
}

function minimalContext(overrides: Partial<BlackboxToolContext> = {}): BlackboxToolContext {
  return {
    cfg: { tools_env: { values: {} } },
    db: {} as BlackboxToolContext["db"],
    projectId: "p1", sessionId: "s1", target: "https://t.example/", values: {},
    ...overrides,
  } as BlackboxToolContext;
}

describe("P0-2：沙箱 /state 图快照（只读单向）", () => {
  it("执行前把 graph_snapshot.json 写进 /state，内容带 read_only 标记", async () => {
    const writes: Array<{ path: string; content: string }> = [];
    const deps = {
      state: { read: async () => undefined, write: async (path: string, content: string) => { writes.push({ path, content }); } },
    };
    // 沙箱不可用时 runSandbox 自己返回失败结果；这个测试只关心"执行前快照已经写出去了"。
    await runSandboxTool(
      minimalContext({ graphContext: () => graphContextView(graphWithTopology()) as unknown as Record<string, unknown> }),
      "exec.python", { code: "print(compute_signature('order'))" }, deps,
    ).catch(() => undefined);

    expect(writes).toHaveLength(1);
    expect(writes[0]!.path).toBe("graph_snapshot.json");
    const payload = JSON.parse(writes[0]!.content) as Record<string, unknown>;
    expect(payload.read_only).toBe(true);
    expect(String(payload.generated_at)).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(Array.isArray(payload.nodes)).toBe(true);
    expect(Array.isArray(payload.edges)).toBe(true);
    expect((payload.counts as Record<string, unknown>).nodes).toBeGreaterThan(0);
    // 断言的实质：特种兵读到的就是它要看的那份拓扑
    expect(JSON.stringify(payload)).toContain("ep:t.example/api/order");
  });

  it("写快照失败不阻塞脚本（图是增强信息，不是依赖）", async () => {
    const deps = { state: { read: async () => undefined, write: async () => { throw new Error("state volume full"); } } };
    // 写失败被吞掉，不该把 state 卷的错误抛给模型。
    let rejectedMessage = "";
    await runSandboxTool(
      minimalContext({ graphContext: () => graphContextView(graphWithTopology()) as unknown as Record<string, unknown> }),
      "exec.python", { code: "print(compute_signature('order'))" }, deps,
    ).catch((error: unknown) => { rejectedMessage = String((error as Error)?.message || error); });
    expect(rejectedMessage).not.toContain("state volume full");
  });

  it("没有图提供者时不写文件（不在沙箱里留半截状态）", async () => {
    const writes: string[] = [];
    const deps = { state: { read: async () => undefined, write: async (path: string) => { writes.push(path); } } };
    await runSandboxTool(minimalContext(), "exec.python", { code: "print(compute_signature('order'))" }, deps).catch(() => undefined);
    expect(writes).toHaveLength(0);
  });
});
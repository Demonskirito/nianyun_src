import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { applyFocusLock, computeFocus, focusDirective, focusView, focusViolation } from "../src/blackbox/focus.js";
import { boundedContext } from "../src/blackbox/context.js";
import { endpointNodeId, graphState, upsertNode } from "../src/blackbox/graph/builder.js";

/**
 * 焦点锁：一轮只准推进一个任务。
 *
 * 没有它的时候，一轮发 5–8 个 tool_request 分属不同任务，每条都浅尝辄止：
 * bundle 取不到、CORS 没对照、WAF 面没判定，全部停在半路。任务簿再干净也等于零。
 */
function stateOf(taskSpecs: Array<{ id: string; status?: string; target?: string; purpose?: string }>) {
  const progress = new BlackboxProgress();
  for (const spec of taskSpecs) {
    progress.state.tasks[spec.id] = {
      status: spec.status || "pending",
      target: spec.target,
      purpose: spec.purpose || `${spec.id} 的目的`,
      source: "main-agent",
    };
  }
  return progress;
}

describe("焦点选择", () => {
  it("粘性优先：上一轮焦点还没结案就继续它", () => {
    const progress = stateOf([
      { id: "T1", status: "pending", target: "https://a.example/one" },
      { id: "T2", status: "pending", target: "https://a.example/two" },
    ]);
    progress.state.focus_task_id = "T2";
    const focus = computeFocus(progress.state);
    expect(focus?.task_id).toBe("T2");
    expect(focus?.reason).toBe("sticky");
  });

  it("粘性任务结案后立刻换焦点，不会锁死在已结束的任务上", () => {
    const progress = stateOf([
      { id: "T1", status: "pending" },
      { id: "T2", status: "completed" },
    ]);
    progress.state.focus_task_id = "T2";
    expect(computeFocus(progress.state)?.task_id).toBe("T1");
  });

  it("running 优先于 pending", () => {
    const progress = stateOf([
      { id: "T1", status: "pending" },
      { id: "T2", status: "running" },
    ]);
    const focus = computeFocus(progress.state);
    expect(focus?.task_id).toBe("T2");
    expect(focus?.reason).toBe("running");
  });

  it("其次按图距离：离高价值目标更近的任务先做", () => {
    const farUrl = "https://a.example/far";
    const nearUrl = "https://a.example/pay/order";
    const midUrl = "https://a.example/mid";
    const progress = stateOf([
      { id: "FAR", status: "pending", target: farUrl },
      { id: "NEAR", status: "pending", target: nearUrl },
    ]);
    const graph = graphState(undefined);
    const far = endpointNodeId(farUrl);
    const near = endpointNodeId(nearUrl);
    const mid = endpointNodeId(midUrl);
    // 远端两跳到高危端点，近端一跳：焦点必须选 NEAR
    upsertNode(graph, { id: far, type: "endpoint", status: "untested", properties: {} } as never);
    upsertNode(graph, { id: near, type: "endpoint", status: "untested", properties: {} } as never);
    upsertNode(graph, { id: mid, type: "endpoint", status: "untested", properties: {} } as never);
    upsertNode(graph, { id: "vuln:pay", type: "vuln_state", status: "vulnerable", properties: {} } as never);
    graph.edges.push(
      { id: "e1", type: "calls_api", source_id: far, target_id: mid, weight: 2 } as never,
      { id: "e2", type: "calls_api", source_id: mid, target_id: "vuln:pay", weight: 2 } as never,
      { id: "e3", type: "calls_api", source_id: near, target_id: "vuln:pay", weight: 1 } as never,
    );
    progress.state.graph = graph;
    const focus = computeFocus(progress.state);
    expect(focus?.task_id).toBe("NEAR");
    expect(focus?.reason).toBe("graph_nearest");
    expect(focus?.distance).toBe(0);
  });

  it("图里没有可寻的节点时退回 FIFO（最早创建的那条）", () => {
    const progress = stateOf([
      { id: "FIRST", status: "pending" },
      { id: "SECOND", status: "pending" },
    ]);
    const focus = computeFocus(progress.state);
    expect(focus?.task_id).toBe("FIRST");
    expect(focus?.reason).toBe("fifo");
  });

  it("没有未结案任务时不返回焦点（避免锁在一个不存在的任务上）", () => {
    const progress = stateOf([{ id: "T1", status: "completed" }, { id: "T2", status: "blocked" }]);
    expect(computeFocus(progress.state)).toBeUndefined();
    expect(String(focusView(progress.state).current_focus_task_id)).toBe("");
  });
});

describe("焦点锁的拦截与指令", () => {
  const choice = { task_id: "T_CDN_JS", reason: "fifo" as const, detail: "本轮焦点：最早创建" };

  it("别的任务的请求被拒，理由里点名焦点任务", () => {
    const result = applyFocusLock(choice, [
      { tool: "http.request", task_id: "T_CDN_JS" },
      { tool: "http.request", task_id: "T6_cors_verify" },
      { tool: "browser.open", task_id: "T_CDN_JS" },
    ], id => id);
    expect(result.allowed.map(request => request.tool)).toEqual(["http.request", "browser.open"]);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0].reason).toContain("焦点锁定在 T_CDN_JS");
    expect(result.rejected[0].reason).toContain("请先完成它");
  });

  it("别名请求放行并被改写成焦点任务的真实 id", () => {
    const aliases: Record<string, string> = { T11: "T_CDN_JS" };
    const result = applyFocusLock(choice, [{ tool: "http.request", task_id: "T11" }], id => aliases[id] || id);
    expect(result.allowed).toHaveLength(1);
    expect(result.allowed[0].task_id).toBe("T_CDN_JS");
    expect(result.rejected).toHaveLength(0);
  });

  it("没有焦点时不拦任何请求", () => {
    const result = applyFocusLock(undefined, [{ tool: "http.request", task_id: "T1" }], id => id);
    expect(result.allowed).toHaveLength(1);
    expect(focusViolation(undefined, "T1")).toBeUndefined();
  });

  it("指令里写明任务 id、其它任务数量与切换条件", () => {
    const text = focusDirective(choice, 9);
    expect(text).toContain("current_focus_task_id (T_CDN_JS)");
    expect(text).toContain("其他 8 个 pending 任务");
    expect(text).toContain("completed/failed/blocked");
    expect(text).toContain("严禁");
  });
});

describe("焦点进上下文", () => {
  it("上下文带 current_focus_task_id 与完整指令，且不受 checkpoint 裁剪影响", () => {
    const progress = stateOf([
      { id: "T_CDN_JS", status: "pending", target: "https://gray-push-intl.oppo.com/", purpose: "取得真实 umi 主 bundle" },
      { id: "T6_cors_verify", status: "pending", purpose: "验证 ACAO 反射" },
    ]);
    progress.state.retrievedEvidence = Array.from({ length: 20 }, (_, index) => ({ id: `ev-${index}`, summary: "s".repeat(400) }));
    const context = boundedContext({ id: "s", target: "https://gray-push-intl.oppo.com/", status: "running", phase: "x", checkpoint: progress.state, evidence: [], events: [] }, {});
    const focusLock = context.focus_lock as Record<string, unknown>;
    expect(focusLock.current_focus_task_id).toBe("T_CDN_JS");
    expect(String(focusLock.directive)).toContain("【执行纪律】");
    expect((context.checkpoint as Record<string, unknown>).current_focus_task_id).toBe("T_CDN_JS");
  });
});

describe("图距离（真实图的边是单向入边）", () => {
  it("只有 asset → endpoint 入边时也能算出距离，不会静默退化成 FIFO", () => {
    const nearUrl = "https://a.example/api/user/info";
    const farUrl = "https://a.example/blog";
    const progress = stateOf([
      { id: "FAR", status: "pending", target: farUrl },
      { id: "NEAR", status: "pending", target: nearUrl },
    ]);
    const graph = graphState(undefined);
    const asset = "asset:a.example";
    const near = endpointNodeId(nearUrl);
    const far = endpointNodeId(farUrl);
    // 只建方向为 asset → endpoint 的边（爬取发现时的真实形态）
    upsertNode(graph, { id: asset, type: "asset", status: "untested", properties: {} } as never);
    upsertNode(graph, { id: near, type: "endpoint", status: "vulnerable", properties: {} } as never);
    upsertNode(graph, { id: far, type: "endpoint", status: "untested", properties: {} } as never);
    graph.edges.push(
      { id: "e1", type: "navigates_to", source_id: asset, target_id: near, weight: 1 } as never,
      { id: "e2", type: "navigates_to", source_id: asset, target_id: far, weight: 6 } as never,
    );
    progress.state.graph = graph;
    const focus = computeFocus(progress.state);
    expect(focus?.reason).toBe("graph_nearest");
    expect(focus?.task_id).toBe("NEAR");
    expect(focus?.distance).toBe(0);
  });
});

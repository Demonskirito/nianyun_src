import { describe, expect, it } from "vitest";
import {
  activeHypotheses, applyHypotheses, attemptLimitOf, deriveHypotheses, graphContextView, graphRank, graphState,
  ingestToolResult, noteHypothesisAttempt, resolveHypotheses, sortRequestsByGraph,
} from "../src/blackbox/graph/index.js";
import { playbookPriority } from "../src/blackbox/playbooks.js";

const fresh = () => graphState(undefined);

/** 造一个带假设的图：buyer/admin 撞同一端点 → idor 假设落在该端点上。 */
function graphWithHypothesis(endpoint = "https://t.example/api/order/detail") {
  const state = fresh();
  ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: endpoint }] });
  for (const role of ["buyer", "admin"]) {
    ingestToolResult(state, { tool: "http.request", identity: role,
      endpoints: [{ url: endpoint, status_code: 403, auth_required: true, blocked: true, params: ["order_id"] }] });
  }
  applyHypotheses(state, deriveHypotheses(state));
  return state;
}

const playbookOf = (map: Record<string, string>) => (taskId: string) => map[taskId];

describe("P1-3：图驱动混合排序", () => {
  it("同打法优先级下，命中假设链路的请求排在孤立节点之前", () => {
    const state = graphWithHypothesis();
    const requests = [
      { tool: "http.request", task_id: "t1", input: { url: "https://t.example/api/unrelated/thing" } },
      { tool: "http.request", task_id: "t2", input: { url: "https://t.example/api/order/detail" } },
    ];
    const sorted = sortRequestsByGraph(requests, {
      graph: state, playbookOf: playbookOf({ t1: "idor", t2: "idor" }), playbookPriority,
    });
    expect(sorted.requests[0]!.task_id).toBe("t2");
    expect(sorted.scores[0]!.final).toBeGreaterThan(sorted.scores[1]!.final);
    expect(sorted.scores[0]!.reasons.join("|")).toContain("假设");
  });

  it("死胡同罚分：同打法下死胡同请求排最后", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: "https://t.example/dead" }] });
    for (let index = 0; index < 3; index += 1) {
      ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/dead", status_code: 403, blocked: true }] });
    }
    ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: "https://t.example/alive" }] });
    const requests = [
      { tool: "http.request", task_id: "dead", input: { url: "https://t.example/dead" } },
      { tool: "http.request", task_id: "alive", input: { url: "https://t.example/alive" } },
    ];
    const sorted = sortRequestsByGraph(requests, {
      graph: state, playbookOf: playbookOf({ dead: "idor", alive: "idor" }), playbookPriority,
    });
    expect(sorted.requests[0]!.task_id).toBe("alive");
    expect(sorted.scores[1]!.reasons.join("|")).toContain("死胡同");
    // 罚分 30 分 = 3 档打法基础分：priority 1 的打法仍能压过 priority 4 的死胡同（有意为之：
    // 未授权暴露是最高价值的尝试，值得顶一次罚分；再高就变成"图独占排序"了）
    const weighted = sortRequestsByGraph(requests, {
      graph: state, playbookOf: playbookOf({ dead: "unauth_exposure", alive: "xss" }), playbookPriority,
    });
    expect(weighted.requests[0]!.task_id).toBe("dead");
  });

  it("基础分随打法优先级递减，未知打法兜底 0 分", () => {
    const state = fresh();
    const requests = [
      { tool: "http.request", task_id: "a", input: { url: "https://t.example/x" } },
      { tool: "http.request", task_id: "b", input: { url: "https://t.example/y" } },
      { tool: "http.request", task_id: "c", input: { url: "https://t.example/z" } },
    ];
    const sorted = sortRequestsByGraph(requests, {
      graph: state, playbookOf: playbookOf({ a: "xss", b: "unauth_exposure" }), playbookPriority,
    });
    expect(sorted.requests[0]!.task_id).toBe("b");
    expect(sorted.scores[2]!.final).toBe(0);
    expect(sorted.scores[2]!.reasons).toContain("未绑定打法");
  });

  it("同分时保留模型原本顺序（不打乱它的推理链）", () => {
    const state = fresh();
    const requests = [
      { tool: "http.request", task_id: "t1", input: { url: "https://t.example/a" } },
      { tool: "http.request", task_id: "t2", input: { url: "https://t.example/b" } },
      { tool: "http.request", task_id: "t3", input: { url: "https://t.example/c" } },
    ];
    const sorted = sortRequestsByGraph(requests, {
      graph: state, playbookOf: playbookOf({ t1: "idor", t2: "idor", t3: "idor" }), playbookPriority,
    });
    expect(sorted.requests.map(item => item.task_id)).toEqual(["t1", "t2", "t3"]);
  });

  it("通往漏洞节点的必经之路获得 Bridge 加成", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "katana.crawl", links: [
      { from: "https://t.example/", to: "https://t.example/api/checkout" },
      { from: "https://t.example/api/checkout", to: "https://t.example/api/pay" },
    ] });
    ingestToolResult(state, { tool: "http.diff", endpoints: [{ url: "https://t.example/api/pay", status_code: 200 }],
      vulnerabilities: [{ url: "https://t.example/api/pay", kind: "logic" }] });
    // checkout 不是漏洞端点，但能走到 pay → 必经之路
    const rank = graphRank(state, "https://t.example/api/checkout");
    expect(rank.bonus).toBeGreaterThan(0);
    expect(rank.reasons.join("|")).toMatch(/必经之路|假设/);
  });

  it("参数节点不能把它自己的父端点「顶成」必经之路（假阳性回归）", () => {
    const state = fresh();
    ingestToolResult(state, { tool: "katana.crawl", links: [{ from: "https://t.example/", to: "https://t.example/api/order/detail" }] });
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://t.example/api/order/detail", status_code: 200, params: ["order_id"] }] });
    const rank = graphRank(state, "https://t.example/api/order/detail");
    expect(rank.reasons.join("|")).not.toContain("必经之路");
  });

  it("图里没有该端点时不加分也不崩", () => {
    expect(graphRank(fresh(), "https://t.example/none").final).toBe(0);
    expect(graphRank(undefined, "https://t.example/none").final).toBe(0);
    expect(graphRank(fresh(), "").final).toBe(0);
  });
});

describe("P1-4：假设动态降级", () => {
  it("attempts 按 kind 上限归档，并给出原因", () => {
    const state = graphWithHypothesis();
    const node = "ep:t.example/api/order/detail";
    const idor = state.hypotheses.find(item => item.kind === "idor")!;
    const limit = attemptLimitOf("idor");
    // 设计意图：idor 比 auth_wall 值得多试几次（负结论要 baseline / 换 id / 换身份三组对照）。
    expect(limit).toBeGreaterThan(attemptLimitOf("auth_wall"));

    for (let index = 1; index < limit; index += 1) noteHypothesisAttempt(state, node);
    expect(idor.status).not.toBe("archived");
    const closed = noteHypothesisAttempt(state, node, { failed: true });
    expect(closed.map(item => item.id)).toContain(idor.id);
    expect(idor.status).toBe("archived");
    expect(idor.archivedReason).toBe("attempts_exhausted");
    expect(idor.attempts).toBe(limit);
    expect(idor.closed_reason).toContain("归档");
  });

  it("归档后的假设：上下文隐藏、排序不再加分、不会复活", () => {
    const state = graphWithHypothesis();
    const node = "ep:t.example/api/order/detail";
    for (let index = 0; index < attemptLimitOf("idor"); index += 1) noteHypothesisAttempt(state, node);

    const view = graphContextView(state);
    expect(view.hypotheses.some(item => item.id.includes("order/detail"))).toBe(false);
    expect(view.closed_hypotheses.length).toBeGreaterThan(0);
    expect(view.counts.hypotheses_closed).toBeGreaterThan(0);

    // 排序不再因为"假设落脚点"给分（端点仍是 blocked，所以还有 authWallRetry 那点分）
    const rank = graphRank(state, "https://t.example/api/order/detail");
    expect(rank.reasons.join("|")).not.toContain("假设");

    // 重新推导出同 id 的假设也不能复活（applyHypotheses 只按 id 去重，降级的 id 仍在列表里）
    const again = applyHypotheses(state, deriveHypotheses(state));
    expect(again).toHaveLength(0);
  });

  it("假设被验证成立 → 标 confirmed，不再占活跃名额", () => {
    const state = graphWithHypothesis();
    ingestToolResult(state, { tool: "http.diff", endpoints: [{ url: "https://t.example/api/order/detail", status_code: 200 }],
      vulnerabilities: [{ url: "https://t.example/api/order/detail", kind: "idor" }] });
    const resolved = resolveHypotheses(state, "ep:t.example/api/order/detail");
    expect(resolved.length).toBeGreaterThan(0);
    // 2026-11-04：不再从池里删除，改为标 confirmed——保留"验证过什么"的复盘记录。
    expect(resolved.every(item => item.status === "confirmed")).toBe(true);
    expect(activeHypotheses(state).some(item => item.nodes.includes("ep:t.example/api/order/detail"))).toBe(false);
  });

  it("不相关端点的尝试不会误伤别的假设", () => {
    const state = graphWithHypothesis();
    for (let index = 0; index < attemptLimitOf("idor"); index += 1) noteHypothesisAttempt(state, "ep:t.example/other");
    expect(state.hypotheses.every(item => item.status !== "archived")).toBe(true);
  });
});
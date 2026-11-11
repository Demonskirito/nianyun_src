/**
 * 假设池：分桶配额 / 冷宫 / 坟墓（2026-11-04）。
 *
 * 设计要点（与 #7 原始草案的差异都在这里）：
 *   1. **配额是硬上限，不补满**：草案的"active 不足 40 就从冷宫补满"会立刻把被配额
 *      挡掉的低价值候选补回来，等于配额没做（实测会补回 24 条 stall，回到 40 条全 stall）。
 *   2. **stall 不进冷宫**：它已降级为端点属性 `stall_hits`，可重算，不需要记忆。
 *   3. **冷宫不做"降级"**：冷宫假设不参与调度，降 priority 对行为零影响；
 *      用 LRU（lastEvaluatedAt）表达"待越久越难复活"即可。
 *   4. **坟墓只有两条路**：尝试次数耗尽 / 依赖事实失效。谓词而非字符串指纹。
 */
import { describe, expect, it } from "vitest";
import {
  HYPOTHESIS_EVENT_DETAIL, HYPOTHESIS_MAX_ACTIVE, HYPOTHESIS_MAX_EVICTED, activeHypotheses, applyHypotheses,
  attemptLimitOf, graphState, hypothesisEventBatch, normalizeHypothesisStatus, shouldRefreshHypotheses,
} from "../src/blackbox/graph/index.js";
import { hypothesisTasks } from "../src/blackbox/hypothesis_tasks.js";
import type { GraphNode, Hypothesis } from "../src/blackbox/graph/types.js";

const fresh = () => graphState(undefined);
const EP = "ep:t.example/api/item/{id}";
/** 鉴权墙的锚点：wallStillStands 要求"被拦过且没被打破"（blocked_streak>0）。 */
const EP_WALL = "ep:t.example/api/admin";

function endpoint(id: string, properties: Record<string, unknown> = {}, status = "testing"): GraphNode {
  return {
    id, type: "endpoint", status: status as GraphNode["status"],
    properties: { status_code: 200, ...properties }, discovered_by: "ev-test", updated_at: 1,
  };
}

function hyp(kind: string, id: string, nodes: string[] = [EP], severity: "high" | "medium" = "high"): Hypothesis {
  return { id, kind, text: `${kind} 假设 ${id}`, nodes, severity, created_at: 1, status: "active", attempts: 0 };
}

const active = (state: ReturnType<typeof fresh>) => state.hypotheses.filter(item => item.status === "active");
const evicted = (state: ReturnType<typeof fresh>) => state.hypotheses.filter(item => item.status === "evicted");
const archived = (state: ReturnType<typeof fresh>) => state.hypotheses.filter(item => item.status === "archived");

describe("分桶配额", () => {
  it("idor 溢出时按配额截到 10，auth_wall 的 5 条全部保留", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    state.nodes[EP_WALL] = endpoint(EP_WALL, { status_code: 403, blocked_streak: 2 }, "blocked");
    const incoming = [
      ...Array.from({ length: 50 }, (_, index) => hyp("idor", `idor:${index}`)),
      ...Array.from({ length: 5 }, (_, index) => hyp("auth_wall", `auth_wall:${index}`, [EP_WALL])),
    ];
    applyHypotheses(state, incoming, 1);
    expect(active(state).filter(item => item.kind === "idor")).toHaveLength(10);
    expect(active(state).filter(item => item.kind === "auth_wall")).toHaveLength(5);
  });

  it("溢出进冷宫而不是丢弃", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    applyHypotheses(state, Array.from({ length: 50 }, (_, index) => hyp("idor", `idor:${index}`)), 1);
    expect(evicted(state)).toHaveLength(40);
    expect(active(state).length + evicted(state).length).toBe(50);
  });

  it("配额是硬上限：座位空着不补满", () => {
    const state = fresh();
    state.nodes[EP_WALL] = endpoint(EP_WALL, { status_code: 403, blocked_streak: 2 }, "blocked");
    applyHypotheses(state, Array.from({ length: 3 }, (_, index) => hyp("auth_wall", `auth_wall:${index}`, [EP_WALL])), 1);
    // 只有 3 条候选 → active 就是 3，不会从冷宫/别处凑到 40。
    expect(active(state)).toHaveLength(3);
    expect(evicted(state)).toHaveLength(0);
  });

  it("总活跃不超 HYPOTHESIS_MAX_ACTIVE（未知 kind 各占 DEFAULT_QUOTA 时要兜底）", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    // 12 个未列出的 kind × 5 条 = 60 > 40。
    const incoming: Hypothesis[] = [];
    for (let kind = 0; kind < 12; kind += 1) {
      for (let index = 0; index < 5; index += 1) incoming.push(hyp("custom_k" + kind, `c${kind}-${index}`));
    }
    applyHypotheses(state, incoming, 1);
    expect(active(state).length).toBeLessThanOrEqual(HYPOTHESIS_MAX_ACTIVE);
    expect(active(state).length + evicted(state).length).toBe(60);
  });

  it("高危优先占座", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    const incoming = [
      ...Array.from({ length: 9 }, (_, index) => hyp("idor", `low:${index}`, [EP], "medium")),
      hyp("idor", "high:1", [EP], "high"),
    ];
    applyHypotheses(state, incoming, 1);
    expect(active(state).some(item => item.id === "high:1")).toBe(true);
  });
});

describe("冷宫", () => {
  it("超容量按 LRU 淘汰最久没被评估的", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    // 直接放进池（而非当 incoming）：合并步骤会把新假设的 lastEvaluatedAt 刷成本轮，
    // 那样 160 条的"年龄"全变成 2，LRU 就退化成按 id 排序了。
    state.hypotheses = Array.from({ length: 160 }, (_, index) => ({
      ...hyp("idor", `idor:${index}`), lastEvaluatedAt: index,
    }));
    applyHypotheses(state, [], 2);
    expect(evicted(state)).toHaveLength(HYPOTHESIS_MAX_EVICTED);
    // 被淘汰的是 lastEvaluatedAt 最小的那批；留下来的最小值应 >= 60。
    const ages = evicted(state).map(item => item.lastEvaluatedAt ?? 0).sort((a, b) => a - b);
    expect(ages[0]).toBeGreaterThanOrEqual(160 - HYPOTHESIS_MAX_EVICTED - 10);
  });

  it("冷宫假设不参与调度", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    applyHypotheses(state, Array.from({ length: 50 }, (_, index) => hyp("idor", `idor:${index}`)), 1);
    const tasks = hypothesisTasks(activeHypotheses(state), { limit: 3 });
    // 只从活跃池出任务；冷宫的 40 条一条都不该出现。
    expect(tasks.length).toBeGreaterThan(0);
    expect(tasks.length).toBeLessThanOrEqual(3);
    expect(tasks.every(task => task.id.startsWith("H_idor_"))).toBe(true);
  });

  it("LRU 淘汰后被重新推导的假设不算「新增」（抑制事件与计分写放大）", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    // 160 条全在冷宫，按 lastEvaluatedAt 触发一次 LRU 丢弃。
    state.hypotheses = Array.from({ length: 160 }, (_, index) => ({
      ...hyp("idor", `idor:${index}`), status: "evicted", lastEvaluatedAt: index,
    }));
    expect(applyHypotheses(state, [], 2)).toHaveLength(0);
    const before = state.hypotheses.length;
    expect(before).toBeLessThan(160);

    // derive 下一轮会把被丢掉的那批原样重算出来：它们必须照旧进池，
    // 但绝不能再算 added —— 否则 desk 每轮写 95 条 graph-hypothesis 事件，
    // scoreIngest 也每轮 +1「新假设 95 条」把焦点预算顶满。
    const rediscovered = Array.from({ length: 60 }, (_, index) => hyp("idor", `idor:${index}`));
    expect(applyHypotheses(state, rediscovered, 3)).toHaveLength(0);
    expect(state.seenHypothesisIds?.length).toBeGreaterThanOrEqual(160);

    // 「见过」但不在池里 = 复活：照旧进池、照旧可调度，只是不写"新假设"事件。
    const revived = fresh();
    revived.nodes[EP] = endpoint(EP);
    revived.seenHypothesisIds = ["idor:revived"];
    expect(applyHypotheses(revived, [hyp("idor", "idor:revived")], 1)).toHaveLength(0);
    expect(revived.hypotheses.find(item => item.id === "idor:revived")?.status).toBe("active");

    // 真正第一次见到的 id 仍然要算新增，别把去重做成"永远不许新增"。
    expect(applyHypotheses(state, [hyp("idor", "idor:brand-new")], 4)).toHaveLength(1);
    expect(state.seenHypothesisIds).toContain("idor:brand-new");
  });

  it("冷宫里的假设被重新推导时复活，attempts 保留", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    state.hypotheses = [{ ...hyp("idor", "idor:revive"), status: "evicted", attempts: 3, evictedAt: 1, lastEvaluatedAt: 1 }];
    applyHypotheses(state, [hyp("idor", "idor:revive")], 2);
    const revived = state.hypotheses.find(item => item.id === "idor:revive")!;
    expect(revived.status).toBe("active");
    expect(revived.attempts).toBe(3);
    expect(revived.evictedAt).toBeUndefined();
  });
});

describe("坟墓", () => {
  it("尝试次数耗尽 → archived（按 kind 上限）", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    const limit = attemptLimitOf("idor");
    state.hypotheses = [{ ...hyp("idor", "idor:dead"), attempts: limit }];
    applyHypotheses(state, [], 3);
    const item = state.hypotheses.find(entry => entry.id === "idor:dead")!;
    expect(item.status).toBe("archived");
    expect(item.archivedReason).toBe("attempts_exhausted");
  });

  it("auth_wall 的上限更低（3 次）——负结论更快成立", () => {
    expect(attemptLimitOf("auth_wall")).toBeLessThan(attemptLimitOf("idor"));
  });

  it("依赖节点不存在 → archived(dependency_invalidated)", () => {
    const state = fresh();
    state.hypotheses = [hyp("idor", "idor:orphan", ["ep:t.example/gone/{id}"])];
    applyHypotheses(state, [], 1);
    const item = state.hypotheses[0]!;
    expect(item.status).toBe("archived");
    expect(item.archivedReason).toBe("dependency_invalidated");
  });

  it("鉴权墙已解除 → auth_wall 归档（谓词式校验，不是字符串指纹）", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP, { status_code: 200, blocked_streak: 0 });
    state.hypotheses = [hyp("auth_wall", "auth_wall:open")];
    applyHypotheses(state, [], 1);
    expect(state.hypotheses[0]!.status).toBe("archived");
    expect(activeHypotheses(state)).toHaveLength(0);
  });

  it("墙还在（状态迁到 testing 但 streak 未清零）→ 保留", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP, { status_code: 403, blocked_streak: 4 }, "testing");
    state.hypotheses = [hyp("auth_wall", "auth_wall:alive")];
    applyHypotheses(state, [], 1);
    expect(state.hypotheses[0]!.status).toBe("active");
  });

  it("坟墓里的假设不会被重新推导复活", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    state.hypotheses = [{ ...hyp("idor", "idor:tomb"), status: "archived", archivedReason: "attempts_exhausted", attempts: 5 }];
    const added = applyHypotheses(state, [hyp("idor", "idor:tomb")], 2);
    expect(added).toHaveLength(0);
    expect(state.hypotheses[0]!.status).toBe("archived");
  });
});

describe("已验证", () => {
  it("confirmed 不占座位、不进活跃列表", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    state.hypotheses = [{ ...hyp("idor", "idor:hit"), status: "confirmed" }];
    applyHypotheses(state, [], 1);
    expect(state.hypotheses[0]!.status).toBe("confirmed"); // 不被状态机改写
    expect(activeHypotheses(state)).toHaveLength(0);
  });
});

describe("旧数据兼容", () => {
  it("open/unreachable 读入即归一", () => {
    expect(normalizeHypothesisStatus("open")).toBe("active");
    expect(normalizeHypothesisStatus("unreachable")).toBe("archived");
    expect(normalizeHypothesisStatus(undefined)).toBe("active");
  });

  it("旧 checkpoint 的 unreachable 归一后不会被当成活跃", () => {
    const state = fresh();
    state.nodes[EP] = endpoint(EP);
    state.hypotheses = [{ ...hyp("idor", "idor:legacy"), status: "unreachable" as never }];
    applyHypotheses(state, [], 1);
    expect(activeHypotheses(state)).toHaveLength(0);
    expect(state.hypotheses[0]!.status).toBe("archived");
  });
});

describe("假设推导调用闸 / 事件聚合（2026-11-07 对照会话）", () => {
  const quiet = { tool: "evidence.read", ok: true, newNodes: 0, newEdges: 0, deadEnds: 0, candidates: 0 };

  it("纯读工具 + 零结构零属性变化 → 不跑全图推导（added=0）", () => {
    const verdict = shouldRefreshHypotheses(quiet);
    expect(verdict.refresh).toBe(false);
    expect(verdict.why).toContain("纯读工具");
  });

  it.each([
    { label: "节点属性变化（403→200）", extra: { propertiesChanged: true } },
    { label: "身份/重定向响应头", extra: { signalHeaders: true } },
    { label: "对照判出差异", extra: { comparisonDiff: true } },
    { label: "新节点", extra: { newNodes: 2 } },
    { label: "新边", extra: { newEdges: 1 } },
    { label: "死胡同", extra: { deadEnds: 1 } },
    { label: "新候选", extra: { candidates: 3 } },
  ])("$label 时仍然重算，不吞掉属性/结构变化", ({ extra }) => {
    expect(shouldRefreshHypotheses({ ...quiet, ...extra }).refresh).toBe(true);
  });

  it("失败、被拒、非纯读工具一律保守重算（不吃隐式侧效应）", () => {
    expect(shouldRefreshHypotheses({ ...quiet, ok: false }).refresh).toBe(true);
    expect(shouldRefreshHypotheses({ ...quiet, rejected: true }).refresh).toBe(true);
    expect(shouldRefreshHypotheses({ ...quiet, tool: "http.request" }).refresh).toBe(true);
    expect(shouldRefreshHypotheses({ ...quiet, tool: "browser.open" }).refresh).toBe(true);
  });

  it("单轮 graph-hypothesis 事件 ≤ 6 条：95 条压成 5 明细 + 1 汇总", () => {
    const items = Array.from({ length: 95 }, (_, index) => ({ kind: index % 2 ? "idor" : "auth_wall", id: `h:${index}` }));
    const { shown, rest, kinds } = hypothesisEventBatch(items);
    expect(shown).toHaveLength(HYPOTHESIS_EVENT_DETAIL);
    expect(rest).toHaveLength(90);
    expect(shown.length + (rest.length ? 1 : 0)).toBeLessThanOrEqual(6);
    expect((kinds.idor || 0) + (kinds.auth_wall || 0)).toBe(90);
  });

  it("少于上限时不产生汇总事件", () => {
    const { shown, rest } = hypothesisEventBatch([{ kind: "idor", id: "h:1" }]);
    expect(shown).toHaveLength(1);
    expect(rest).toHaveLength(0);
  });
});

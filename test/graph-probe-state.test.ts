/**
 * S2-① 与 S2-④：可探查面三态 + 死链墓碑。
 *
 * 背景（会话 1dd9ded9ed239711 实测漏斗）：
 *   524 端点 → 489 untested → **28 有 status_code** → 26 可执行。
 *   掉幅全在"要有响应码"这一刀上；剩下 461 个 discovery 面在布尔口径下与"不存在"等价。
 *   三态把这件事变成可读的数字；墓碑负责让已知死链不再复辟。
 */
import { describe, expect, it } from "vitest";
import {
  DEAD_MARK_COOLDOWN_ROUNDS, graphState, ingestToolResult, poolBreakdown, probeState,
  tombstoned, upsertNode, verified,
} from "../src/blackbox/graph/index.js";
import type { GraphNode, NodeStatus } from "../src/blackbox/graph/types.js";

const node = (props: Record<string, unknown>, status: NodeStatus = "untested"): GraphNode => ({
  id: "ep:t.example/api/user",
  type: "endpoint",
  properties: props,
  status,
  discovered_by: "ev-1",
  updated_at: Date.now(),
});

describe("probeState：四态分类", () => {
  it("被动看到响应码但没打过 → observed_unprobed（当前巡检口径）", () => {
    expect(probeState(node({ origin: "discovery", status_code: 200 }))).toBe("observed_unprobed");
  });

  it("只是被看见、没有响应 → unprobed（面，不是点）", () => {
    expect(probeState(node({ origin: "discovery" }))).toBe("unprobed");
    expect(probeState(node({ origin: "link" }))).toBe("unprobed");
    expect(probeState(node({ origin: "js" }))).toBe("unprobed");
  });

  it("发过包 → probed（三种证据都算）", () => {
    expect(probeState(node({ origin: "request", status_code: 200 }, "testing"))).toBe("probed");
    expect(probeState(node({ origin: "request", status_unknown: true }, "testing"))).toBe("probed");
    // 历史图：status 已推进但 origin 没升级
    expect(probeState(node({ origin: "discovery", status_code: 200 }, "blocked"))).toBe("probed");
  });

  it("已知坏面 → dead（优先于 probed，404 不因被打过就变成普通点）", () => {
    expect(probeState(node({ origin: "request", status_code: 404 }, "testing"))).toBe("dead");
    expect(probeState(node({ origin: "discovery", status_code: 410 }))).toBe("dead");
    expect(probeState(node({ origin: "request", status_code: 200, route_missing: true }, "testing"))).toBe("dead");
  });

  it("非端点节点不参与面池", () => {
    expect(probeState({ ...node({}), type: "asset" })).toBe("unprobed");
    expect(probeState(undefined)).toBe("unprobed");
  });
});

describe("verified() 与三态等价（不改变既有准入）", () => {
  it("observed_unprobed 且 origin 在白名单才放行", () => {
    expect(verified(node({ origin: "discovery", status_code: 200 }))).toBe(true);
    expect(verified(node({ origin: "link", status_code: 200 }))).toBe(true);
    // 空 origin 的老数据：三态给 observed_unprobed，但 verified 仍拒绝（保持 A1 口径）
    expect(verified(node({ status_code: 200 }))).toBe(false);
  });

  it("unprobed / probed / dead 一律不放行", () => {
    expect(verified(node({ origin: "discovery" }))).toBe(false);
    expect(verified(node({ origin: "request", status_code: 200 }, "testing"))).toBe(false);
    expect(verified(node({ origin: "discovery", status_code: 404 }))).toBe(false);
  });
});

describe("poolBreakdown：面池构成", () => {
  it("按四态计数，ready 与 verified 同源", () => {
    const state = graphState(undefined);
    upsertNode(state, { id: "ep:t.example/a", type: "endpoint", properties: { origin: "discovery", status_code: 200 }, status: "untested" });
    upsertNode(state, { id: "ep:t.example/b", type: "endpoint", properties: { origin: "discovery" }, status: "untested" });
    upsertNode(state, { id: "ep:t.example/c", type: "endpoint", properties: { origin: "request", status_code: 200 }, status: "testing" });
    upsertNode(state, { id: "ep:t.example/d", type: "endpoint", properties: { origin: "discovery", status_code: 404 }, status: "untested" });
    const pool = poolBreakdown(state, 3);
    expect(pool.observed_unprobed).toBe(1);
    expect(pool.unprobed).toBe(1);
    expect(pool.probed).toBe(1);
    expect(pool.dead).toBe(1);
    expect(pool.ready).toBe(1);
  });

  it("模板路径不计入 ready（照抄会 404）", () => {
    const state = graphState(undefined);
    upsertNode(state, { id: "ep:t.example/a/{id}", type: "endpoint", properties: { origin: "discovery", status_code: 200 }, status: "untested" });
    const pool = poolBreakdown(state, 1);
    expect(pool.observed_unprobed).toBe(1);
    expect(pool.ready).toBe(0);
  });
});

describe("死链墓碑：写入、冷却、清除、抗裁剪", () => {
  const ingest = (state: ReturnType<typeof graphState>, url: string, code: number, round: number) =>
    ingestToolResult(state, { tool: "http.request", round, endpoints: [{ url, status_code: code }] });

  it("404 落墓碑，冷却期按图轮次计算", () => {
    const state = graphState(undefined);
    ingest(state, "https://t.example/gone", 404, 7);
    const id = "ep:t.example/gone";
    expect(state.deadMarks?.[id]?.code).toBe(404);
    expect(state.deadMarks?.[id]?.until_round).toBe(7 + DEAD_MARK_COOLDOWN_ROUNDS);
    expect(tombstoned(state, id, 7)).toBe(true);
    expect(tombstoned(state, id, 56)).toBe(true);
    expect(tombstoned(state, id, 57)).toBe(false);
  });

  it("冷却结束后允许复探，拿到 200 立即清除", () => {
    const state = graphState(undefined);
    ingest(state, "https://t.example/back", 404, 1);
    const id = "ep:t.example/back";
    expect(tombstoned(state, id, 1)).toBe(true);
    // 冷却到期后再打，路径上线了
    ingest(state, "https://t.example/back", 200, 60);
    expect(state.deadMarks?.[id]).toBeUndefined();
    expect(tombstoned(state, id, 60)).toBe(false);
  });

  it("节点被裁剪掉后墓碑仍然存在（防死链复辟的根）", () => {
    const state = graphState(undefined);
    ingest(state, "https://t.example/pruned", 404, 2);
    const id = "ep:t.example/pruned";
    delete state.nodes[id];
    expect(tombstoned(state, id, 2)).toBe(true);
  });

  it("410 也落墓碑；非 4xx 不落", () => {
    const state = graphState(undefined);
    ingest(state, "https://t.example/gone2", 410, 1);
    ingest(state, "https://t.example/ok", 200, 1);
    expect(tombstoned(state, "ep:t.example/gone2", 1)).toBe(true);
    expect(tombstoned(state, "ep:t.example/ok", 1)).toBe(false);
  });
});

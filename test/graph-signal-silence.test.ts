import { describe, expect, it } from "vitest";
import { graphSignals, graphState, upsertEdge, upsertNode } from "../src/blackbox/graph/index.js";

/**
 * 图巡检的"静默"回归（2026-11-07，阶段 3）。
 *
 * 现场：图巡检的三个入口全是 `ep:next.api.aliyun.com/document/xxx/{id}`，
 * 过滤器把它们全部丢掉（因为照抄必然 404），于是 `component_drift` 一条不发，
 * graph_drift 停在部署前的旧值上——图明明卡住了，面板看起来却像"一切正常"。
 *
 * 这组测试锁住三件事：
 * ① 过滤到零时必须出声，且不能伪造可执行 URL；
 * ② 有可执行入口时行为不变（不能被降级分支吃掉）；
 * ③ 连续多轮没有新节点必须兜底，文案稳定（否则插话去重失效）。
 */

const fresh = () => graphState(undefined);

/**
 * 端点节点要带状态码才叫"观测过"（2026-11-09，A1）。
 * 现实里这类节点来自 burp.history / sitemap：看到过响应码，但我们没亲手打过。
 * 裸链接（没有状态码）现在不算，见文件末尾的 A1 用例。
 */
function link(state: ReturnType<typeof graphState>, from: string, to: string): void {
  upsertNode(state, { id: from, type: "endpoint", properties: { origin: "link", status_code: 200 } });
  upsertNode(state, { id: to, type: "endpoint", properties: { origin: "link", status_code: 200 } });
  upsertEdge(state, { source_id: from, target_id: to, type: "navigates_to" });
}

const RECENT = ["ep:t.example/a", "ep:t.example/b", "ep:t.example/a"];

describe("模板路径入口：过滤到零也要出声", () => {
  it("其他块入口全是 {id} 模板 → 出模板信号，且不伪造可执行 URL", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/api/item/{id}", "ep:t.example/api/item/{id}/detail");

    const signals = graphSignals(state, RECENT);
    const drift = signals.find(signal => signal.kind === "component_drift");

    expect(drift).toBeDefined();
    expect(drift!.data?.template_only).toBe(true);
    expect(drift!.data?.roots).toEqual([]);
    // 文案必须说清"为什么没给 URL + 下一步做什么"
    expect(drift!.text).toContain("模板路径");
    expect(drift!.text).toContain("父页面");
    // 也不能把带占位符的假 URL 塞回去
    expect(drift!.text).not.toMatch(/https?:\/\/\S*\{id\}/);
  });

  it("混合入口：有可执行 URL 时走正常分支，不降级", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/api/item/{id}", "ep:t.example/api/item/{id}/detail");
    link(state, "ep:t.example/help", "ep:t.example/help/faq");

    const signals = graphSignals(state, RECENT);
    const drift = signals.find(signal => signal.kind === "component_drift");

    expect(drift).toBeDefined();
    expect(drift!.data?.template_only).toBeUndefined();
    const roots = drift!.data?.roots as string[];
    expect(roots.length).toBeGreaterThan(0);
    expect(roots.every(url => /^https?:\/\//.test(url) && !/[{}]/.test(url))).toBe(true);
    expect(drift!.text).not.toContain("模板路径");
  });

  it("模板信号的文案是稳定的（同状态两次调用逐字一致，插话才能去重）", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/api/item/{id}", "ep:t.example/api/item/{id}/detail");

    const first = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift");
    const second = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift");
    expect(first!.text).toBe(second!.text);
  });
});

describe("连续无新节点兜底", () => {
  it("quietRounds < 3 不发信号", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    const signals = graphSignals(state, RECENT, { quietRounds: 2 });
    expect(signals.some(signal => signal.kind === "graph_no_new_nodes")).toBe(false);
  });

  it("连续 3 轮没有新节点 → 发兜底信号，且文案里不写轮数", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    const signals = graphSignals(state, RECENT, { quietRounds: 3 });
    const quiet = signals.find(signal => signal.kind === "graph_no_new_nodes");

    expect(quiet).toBeDefined();
    expect(quiet!.data?.quiet_rounds).toBe(3);
    // 轮数写进 text 会让 (id,text) 去重每轮失效 —— 现场曾经因此刷出 77 条
    expect(quiet!.text).not.toMatch(/连续\s*3\s*轮/);
    expect(quiet!.text).toContain("换面");
  });

  it("轮数继续增长时文案不变（data 变、text 不变）", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    const at3 = graphSignals(state, RECENT, { quietRounds: 3 }).find(s => s.kind === "graph_no_new_nodes");
    const at9 = graphSignals(state, RECENT, { quietRounds: 9 }).find(s => s.kind === "graph_no_new_nodes");
    expect(at3!.text).toBe(at9!.text);
    expect(at9!.data?.quiet_rounds).toBe(9);
  });

  it("既没有漂移也没有环时，兜底信号仍然会出（这正是静默的缺口）", () => {
    const state = fresh();
    // 单一分量：没有漂移；没有环：没有 cycle。旧实现这里返回空数组。
    link(state, "ep:t.example/a", "ep:t.example/b");
    const signals = graphSignals(state, RECENT, { quietRounds: 3 });
    expect(signals).toHaveLength(1);
    expect(signals[0]!.kind).toBe("graph_no_new_nodes");
  });
});

/**
 * A1（2026-11-09）：漂移 root 必须"看到过真实响应"。
 *
 * 现场对照组 1dd9ded9ed239711：巡检连续 129 轮推荐 `/topic/test2023` 与 `/adc`，
 * 这两个 URL 当天 15:15 就已被 browser.open 打成 404；节点因为没写回状态码，
 * 一直停在 untested，于是永远留在建议池里。模型不照做是对的，错的是建议。
 */
describe("漂移 root 收窄到可打端点（A1）", () => {
  it("没有状态码的裸链接降级成 unprobed：进野槽，且要求先确认死活", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    // 另一个块：只有裸链接，没有任何响应观测（S2 之前整块都不进池）
    upsertNode(state, { id: "ep:t.example/hello", type: "endpoint", properties: { origin: "link" } });
    upsertNode(state, { id: "ep:t.example/hello/x", type: "endpoint", properties: { origin: "link" } });
    upsertEdge(state, { source_id: "ep:t.example/hello", target_id: "ep:t.example/hello/x", type: "navigates_to" });

    const drift = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift");
    // 现在会报（它是"面"）。整块只有面、没有 observed 时允许铺满一批；
    // 一旦有 observed，野槽就只占 1 格（见 graph-probe-pool 的配额用例）。
    expect(drift).toBeDefined();
    const tiers = (drift!.data?.tiers || []) as string[];
    expect(tiers).toContain("unprobed");
    expect(tiers).not.toContain("observed");
    expect(drift!.data?.has_unprobed).toBe(true);
    // 指令必须让模型先去确认死活，而不是把它当已知活接口继续挖。
    expect(drift!.text).toContain("先确认死活");
  });

  it("404 / route_missing 的端点不进建议池", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    upsertNode(state, { id: "ep:t.example/gone", type: "endpoint", properties: { origin: "link", status_code: 404 } });
    upsertNode(state, { id: "ep:t.example/gone/x", type: "endpoint", properties: { origin: "link", status_code: 404 } });
    upsertEdge(state, { source_id: "ep:t.example/gone", target_id: "ep:t.example/gone/x", type: "navigates_to" });

    const drift = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift");
    expect(drift).toBeUndefined();
  });

  it("文案里不再拼块数（数字漂移会让指纹每轮都变）", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/help", "ep:t.example/help/faq");

    const drift = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift");
    expect(drift).toBeDefined();
    expect(drift!.text).not.toMatch(/图裂成\s*\d+\s*块/);
    // 数字仍在 data 里，面板与复盘照旧可读
    expect(typeof drift!.data?.blocks).toBe("number");
    expect(typeof drift!.data?.home_size).toBe("number");
  });
});

/**
 * A2（2026-11-09）：换批有依据，不能永远吐同 3 条。
 */
describe("漂移 root 冷却与轮换（A2）", () => {
  it("rotate=false 时优先沿用上一批（正文稳定才能去重）", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/help", "ep:t.example/help/faq");
    link(state, "ep:t.example/doc", "ep:t.example/doc/intro");

    const first = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift")!;
    const keep = first.data!.roots as string[];
    const again = graphSignals(state, RECENT, { prefer: keep }).find(signal => signal.kind === "component_drift")!;
    expect(again.data!.roots).toEqual(keep);
  });

  it("rotate=true 时换到没被建议过的端点", () => {
    const state = fresh();
    link(state, "ep:t.example/a", "ep:t.example/b");
    link(state, "ep:t.example/help", "ep:t.example/help/faq");
    link(state, "ep:t.example/doc", "ep:t.example/doc/intro");

    const first = graphSignals(state, RECENT).find(signal => signal.kind === "component_drift")!;
    const used = first.data!.roots as string[];
    expect(used.length).toBeGreaterThan(0);

    const suggested = Object.fromEntries(used.map(url => [url, 3]));
    const next = graphSignals(state, RECENT, { suggested, rotate: true }).find(signal => signal.kind === "component_drift")!;
    const fresh2 = (next.data!.roots as string[]).filter(url => !used.includes(url));
    expect(fresh2.length).toBeGreaterThan(0);
  });
});

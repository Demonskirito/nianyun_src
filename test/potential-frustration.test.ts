import { describe, expect, it } from "vitest";
import { EMPTY_GRAPH } from "../src/blackbox/graph/types.js";
import { assetNodeId, endpointNodeId, identityNodeId, upsertEdge, upsertNode } from "../src/blackbox/graph/builder.js";
import { bestPotential, potentialDelta, potentialGoals, potentialMap, potentialOf, potentialView } from "../src/blackbox/potential.js";
import { scoreIngest } from "../src/blackbox/evidence-value.js";
import { frustrationAudit } from "../src/blackbox/frustration.js";
import { DEPRECATED_RULE_KEYS, blackboxRules, blackboxRulesDiagnostics, deprecatedRuleKeys } from "../src/blackbox/rules.js";

function chain(spec: { vuln?: boolean } = {}) {
  const state = structuredClone(EMPTY_GRAPH);
  const asset = assetNodeId("http://a.example.com");
  const hub = endpointNodeId("http://a.example.com/gateway");
  const far = endpointNodeId("http://a.example.com/static/logo.png");
  const vuln = "vuln:idor@a.example.com/admin";
  upsertNode(state, { id: asset, type: "asset", label: "a.example.com" });
  upsertNode(state, { id: hub, type: "endpoint", label: "/gateway" });
  upsertNode(state, { id: far, type: "endpoint", label: "/static/logo.png" });
  upsertNode(state, { id: vuln, type: "vuln_state", label: "idor", ...(spec.vuln ? { status: "vulnerable" as const } : {}) });
  upsertEdge(state, { source_id: asset, target_id: hub, type: "has_endpoint" });
  upsertEdge(state, { source_id: hub, target_id: vuln, type: "vulnerable_at" });
  upsertEdge(state, { source_id: asset, target_id: far, type: "has_endpoint" });
  return { state, asset, hub, far, vuln };
}

describe("拓扑势能", () => {
  it("目标包含漏洞态与高价值端点", () => {
    const { state, vuln } = chain();
    expect(potentialGoals(state)).toContain(vuln);
  });

  it("枢纽节点的势能低于叶子节点；最优就是 0（目标本身）", () => {
    const { state, hub, far, vuln } = chain();
    const map = potentialMap(state);
    expect(map.get(vuln)).toBe(0);
    expect(map.get(hub)!).toBeGreaterThan(0);
    expect(map.get(far)!).toBeGreaterThan(map.get(hub)!);
    expect(bestPotential(state)).toBe(0);
  });

  it("没有目标时势能不可测（undefined）", () => {
    const state = structuredClone(EMPTY_GRAPH);
    upsertNode(state, { id: assetNodeId("http://b.example.com"), type: "asset", label: "b" });
    upsertNode(state, { id: endpointNodeId("http://b.example.com/x"), type: "endpoint", label: "/x" });
    expect(potentialGoals(state)).toHaveLength(0);
    expect(potentialMap(state).size).toBe(0);
    expect(potentialOf(state, endpointNodeId("http://b.example.com/x"))).toBeUndefined();
  });

  it("势能差：下降算提升，横盘/变差都不算", () => {
    expect(potentialDelta(5, 3.5).improved).toBe(true);
    expect(potentialDelta(5, 5).improved).toBe(false);
    expect(potentialDelta(3, 6).improved).toBe(false);
    expect(potentialDelta(undefined, 4).improved).toBe(true);
    expect(potentialDelta(4, undefined).improved).toBe(false);
  });

  it("potentialView 给出目标数、全场最优与焦点势能", () => {
    const { state, hub } = chain();
    const view = potentialView(state, hub);
    expect(view.goals).toBeGreaterThan(0);
    expect(view.best).toBe(0);
    expect(view.focus).toBeGreaterThan(0);
    expect(view.focus_node).toBe(hub);
  });
});

describe("势能接入证据分级", () => {
  it("势能提升压过一切结构增益：+5 / tier 5", () => {
    const value = scoreIngest({
      newNodes: ["ep:x"], newEdges: [], deadEnds: [],
      potential: { before: 5, after: 3.5, improved: true, delta: 1.5, reason: "最短路径成本 5 → 3.5" },
    });
    expect(value.tier).toBe(5);
    expect(value.score).toBe(5);
    expect(value.reasons[0]).toContain("势能提升");
  });

  it("新端点但势能没变：只给 0.5，且 tier 仍是 0（不续命）", () => {
    const value = scoreIngest({
      newNodes: ["ep:static/a.css"], newEdges: [], deadEnds: [],
      potential: { before: 4, after: 4, improved: false, delta: 0, reason: "最短路径成本不变（4）" },
    });
    expect(value.score).toBe(0.5);
    expect(value.tier).toBe(0);
    expect(value.reasons.join()).toContain("边缘探索");
  });

  it("无关的新端点拿不到 +3：结构增益被 0.5 取代", () => {
    const withPotential = scoreIngest({ newNodes: ["ep:static/a.css"], newEdges: [], deadEnds: [], potential: { before: 4, after: 4, improved: false, delta: 0 } });
    const withoutPotential = scoreIngest({ newNodes: ["ep:static/a.css"], newEdges: [], deadEnds: [] });
    expect(withoutPotential.score).toBe(3);
    expect(withPotential.score).toBe(0.5);
  });
});

describe("熔断即交付：阻碍分析报告", () => {
  it("列出阻塞任务、死胡同、拦截边与势能最低点", () => {
    const { state, hub } = chain();
    state.nodes[hub]!.status = "dead_end";
    const report = frustrationAudit({
      tasks: {
        T1: { status: "blocked", target: "http://a.example.com/gateway", outcome_reason: "focus_budget_exhausted", purpose: "打网关" },
        T2: { status: "completed", target: "http://a.example.com/" },
        T3: { status: "pending", target: "http://a.example.com/x" },
      },
      graph: state,
      usage: { session_convergences: 3 },
    }, { session_id: "s1", target: "http://a.example.com", stopReason: "macro_frustration" });

    expect(report.counts.blocked).toBe(1);
    expect(report.counts.pending).toBe(1);
    expect(report.counts.dead_ends).toBeGreaterThanOrEqual(1);
    expect(report.markdown).toContain("阻碍分析与防御测绘");
    expect(report.markdown).toContain("T1");
    expect(report.markdown).toContain("focus_budget_exhausted");
    expect(report.markdown).toContain("```mermaid");
    expect(report.markdown).toContain("classDef dead");
    expect(report.markdown).toContain("下次的入口建议");
  });

  it("没有阻塞任务时不崩，也不编造结论", () => {
    const { state } = chain();
    const report = frustrationAudit({ tasks: {}, graph: state }, { session_id: "s2" });
    expect(report.counts.blocked).toBe(0);
    expect(report.markdown).toContain("（无）");
    expect(report.markdown).toContain("未经人工复核");
  });
});

describe("规则严格模式与迁移守卫", () => {
  const values = (doc: unknown) => ({ BLACKBOX_RULES_DOCUMENT: JSON.stringify(doc) });

  it("识别已废弃的键", () => {
    expect(deprecatedRuleKeys({ focus_lock: { max_tool_calls_per_task: 20 } })).toEqual([
      { key: "focus_lock.max_tool_calls_per_task", hint: DEPRECATED_RULE_KEYS["focus_lock.max_tool_calls_per_task"] },
    ]);
    expect(deprecatedRuleKeys({ focus_lock: { enabled: true } })).toHaveLength(1);
    expect(deprecatedRuleKeys({ focus_lock: { max_tp_per_task: 50 } })).toHaveLength(0);
    expect(deprecatedRuleKeys(null)).toHaveLength(0);
  });

  it("非严格模式下只记 issue，并回退到新键默认值", () => {
    const issues: string[] = [];
    const rules = blackboxRules(values({ focus_lock: { max_tool_calls_per_task: 20 } }), { issues });
    expect(rules.focus_lock.max_tp_per_task).toBe(50);
    expect(issues.join()).toContain("已废弃");
    expect(issues.join()).toContain("max_tp_per_task");
  });

  it("严格模式直接抛错（CI 用来逼迁移）", () => {
    expect(() => blackboxRules(values({ focus_lock: { max_tool_calls_per_task: 20 } }), { strict: true }))
      .toThrow(/Deprecated rule key detected/);
    expect(() => blackboxRules(values({ focus_lock: { max_tp_per_task: 40 } }), { strict: true })).not.toThrow();
  });

  it("诊断里带 deprecated 列表，供控制台横幅使用", () => {
    const diag = blackboxRulesDiagnostics(values({ focus_lock: { appeals_per_task: 2 } }));
    expect(diag.deprecated?.map(item => item.key)).toEqual(["focus_lock.appeals_per_task"]);
    expect(diag.issues.join()).toContain("appeal_pool");
  });
});
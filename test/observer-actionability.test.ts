import { describe, expect, it } from "vitest";
import { executableRootUrls } from "../src/blackbox/graph/analyze.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { planStaleReview } from "../src/blackbox/review-stale.js";
import { coverageChecklist, COVERAGE_DIMENSIONS } from "../src/blackbox/coverage.js";
import { superviseCheckpoint } from "../src/blackbox/supervision.js";

const ACCEPTANCE = { blocking_error_count: 0, unhandled_advice: 0, reason_codes: ["TERMINAL_REVIEW_PENDING"] };

describe("graph drift roots must be executable URLs", () => {
  it("turns endpoint ids into URLs and drops template placeholders / host-less nodes", () => {
    const result = executableRootUrls([
      "ep:developer.aliyun.com/group/aliyunemr",
      "ep:next.api.aliyun.com/document/Vpc/{id}",  // 现场 77 次提醒里的不可执行 root
      "ep:/",
      "asset:developer.aliyun.com",
      "ep:developer.aliyun.com/group/aliyunemr",   // 去重
    ]);
    expect(result.urls).toEqual(["https://developer.aliyun.com/group/aliyunemr"]);
    expect(result.skipped).toBe(3);
  });

  it("caps at three distinct URLs", () => {
    const result = executableRootUrls(["ep:a.test/1", "ep:a.test/2", "ep:a.test/3", "ep:a.test/4"]);
    expect(result.urls).toHaveLength(3);
  });
});

describe("interrupt de-duplication (77 repeats -> one interrupt)", () => {
  const item = { id: "graph:component_drift:component_drift", kind: "component_drift", severity: "high" as const, text: "打 https://a.test/x" };
  it("same id + same text accumulates repeats without adding new interrupts", () => {
    const p = new BlackboxProgress();
    expect(p.addInterrupts([item])).toBe(1);
    expect(p.addInterrupts([item])).toBe(0);
    expect(p.addInterrupts([item])).toBe(0);
    expect(p.state.interrupts).toHaveLength(1);
    expect(p.state.interrupts?.[0]?.repeats).toBe(3);
  });

  it("a genuinely different target counts as new, and a 10-round repeat re-surfaces", () => {
    const p = new BlackboxProgress();
    p.addInterrupts([item]);
    p.takeInterrupts();
    expect(p.addInterrupts([{ ...item, text: "打 https://a.test/y" }])).toBe(1);
    p.takeInterrupts();
    for (let i = 0; i < 8; i += 1) p.addInterrupts([{ ...item, text: "打 https://a.test/y" }]);
    expect(p.takeInterrupts().length).toBe(1); // repeats 到 10 时重新 acknowledged=false
  });

  /**
   * A3（2026-11-09）：只带指纹的语义变化才算新插话。
   *
   * 现场 `component_drift` 的正文写着"图裂成 60/61/62 块、另有 35/36 块没动过"，
   * 数字每轮都变，只看 text 判新旧就每轮都算新插话——13 分钟写了 7 条同义事件。
   */
  it("fingerprint unchanged + drifting numbers in text = not a new interrupt", () => {
    const p = new BlackboxProgress();
    const base = { ...item, fingerprint: "component_drift:https://a.test/x" };
    expect(p.addInterrupts([{ ...base, text: "图裂成 60 块，打 https://a.test/x" }])).toBe(1);
    expect(p.addInterrupts([{ ...base, text: "图裂成 61 块，打 https://a.test/x" }])).toBe(0);
    expect(p.addInterrupts([{ ...base, text: "图裂成 62 块，打 https://a.test/x" }])).toBe(0);
    expect(p.state.interrupts).toHaveLength(1);
    // 正文仍然是最新的，模型看到的是当前数字
    expect(p.state.interrupts?.[0]?.text).toContain("62");
  });

  it("fingerprint changed = a genuinely new interrupt", () => {
    const p = new BlackboxProgress();
    p.addInterrupts([{ ...item, fingerprint: "component_drift:https://a.test/x", text: "x" }]);
    p.takeInterrupts();
    expect(p.addInterrupts([{ ...item, fingerprint: "component_drift:https://a.test/y", text: "x" }])).toBe(1);
  });
});

describe("stale review: warning-only issues no longer hold the gate", () => {
  const warningIssues = [
    { code: "PARTIAL_TASK_OUTCOME", severity: "warning", path: "tasks", task_id: "T3" },
    { code: "TASK_OUTCOME_NO_FACT", severity: "warning", path: "tasks.H_x.outcome", task_id: "H_x" },
  ];
  const current = [...warningIssues, { code: "CLOSURE_DELIVERABLES_WAIVED", severity: "warning", task_id: "T2", path: "x" }];

  it("clears the gate when only warning-level issues remain (the live failure mode)", () => {
    const plan = planStaleReview({ acceptance: ACCEPTANCE, suggestionCount: 6, reviewIssues: warningIssues, currentIssues: current });
    expect(plan.reason).toBe("stale_issues_resolved");
    expect(plan.keepPending).toBe(false);
    expect(plan.halt).toBe(false);
    expect(plan.injectAdvice).toBe(true);
    expect(plan.issuesCompared).toMatchObject({ reviewed: 2, blocking: 0, warning_only: 2 });
  });

  it("still waits when an error-level named issue is unresolved", () => {
    const blocking = [{ code: "FINDING_EVIDENCE_INVALID", severity: "error", path: "findings", task_id: "F1" }];
    const plan = planStaleReview({ acceptance: ACCEPTANCE, suggestionCount: 1,
      reviewIssues: blocking, currentIssues: blocking });
    expect(plan.reason).toBe("stale_blocking");
    expect(plan.keepPending).toBe(true);
  });

  it("degrades after three consecutive stale rounds instead of looping forever", () => {
    const blocking = [{ code: "FINDING_EVIDENCE_INVALID", severity: "error", path: "findings", task_id: "F1" }];
    const base = { acceptance: ACCEPTANCE, suggestionCount: 1, reviewIssues: blocking, currentIssues: blocking };
    expect(planStaleReview({ ...base, staleStreak: 2 }).keepPending).toBe(true);
    expect(planStaleReview({ ...base, staleStreak: 3 })).toMatchObject({ reason: "stale_degraded", keepPending: false, halt: false });
  });
});

describe("0-findings coverage checklist", () => {
  it("reports all four gaps on an empty ledger", () => {
    const result = coverageChecklist({}, []);
    expect(result.gaps).toEqual([...COVERAGE_DIMENSIONS]);
    expect(result.heuristic).toBe(true);
  });

  it("a healthy seeded/anonymous seed probe covers both identity dimensions", () => {
    const state = { seed_health: { "a.test": { verdict: "healthy", seeded: 200, anonymous: 200 } } };
    const result = coverageChecklist(state as never, []);
    expect(result.dimensions.authenticated).toBe(true);
    expect(result.dimensions.anonymous).toBe(true);
    expect(result.gaps).toEqual(["parameter_variant", "cross_identity"]);
  });

  it("http.diff and idor evidence close the remaining gaps", () => {
    const state = { seed_health: { "a.test": { verdict: "healthy", seeded: 200, anonymous: 200 } } };
    const evidence = [
      { tool: "http.diff", summary: "baseline/hit 参数变异对照" },
      { summary: "idor 越权：两身份打同一对象" },
    ];
    expect(coverageChecklist(state as never, evidence).gaps).toEqual([]);
  });

  it("0 findings + open gaps forces one extra Observer instead of silently accepting", () => {
    const p = new BlackboxProgress();
    p.state.tasks.t1 = { status: "blocked", reason: "fixture" }; // 终态且不需要结案证据
    p.state.usage.agentTurns = 100;
    const budget = { timeMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 };
    const first = superviseCheckpoint(p.state, budget, { kind: "checkpoint" }, []);
    expect(first.action).toBe("observer");
    expect(first.reasons).toContain("coverage_gaps");
    expect(p.state.coverage_gaps?.length).toBeGreaterThan(0);

    p.state.usage.agentTurns = 121;
    const second = superviseCheckpoint(p.state, budget, { kind: "checkpoint" }, []);
    expect(second.reasons).toContain("coverage_gaps");
    p.state.supervision.reviewPending = false; // 模拟两次补审都已完成
    p.state.usage.agentTurns = 142;
    const third = superviseCheckpoint(p.state, budget, { kind: "checkpoint" }, []);
    expect(third.reasons).not.toContain("coverage_gaps"); // 最多 2 次，不无限拖延收口
    expect(p.state.supervision?.coverageReviewCount).toBe(2);
  });
});

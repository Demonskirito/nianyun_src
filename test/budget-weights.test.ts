import { describe, expect, it } from "vitest";
import { blackboxRules, blackboxRulesDiagnostics, DEFAULT_BLACKBOX_RULES } from "../src/blackbox/rules.js";
import { budgetMode, isHeavyTool, toolWeight, TOOL_WEIGHTS } from "../src/blackbox/weights.js";
import { playbookById, degradedPlan } from "../src/blackbox/playbooks.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { superviseCheckpoint } from "../src/blackbox/supervision.js";

describe("budget defaults", () => {
  it("separates schedule time from wall clock and raises the weighted call budget", () => {
    expect(DEFAULT_BLACKBOX_RULES.budgets.time_sec).toBe(900);
    expect(DEFAULT_BLACKBOX_RULES.budgets.wall_clock_sec).toBe(1800);
    expect(DEFAULT_BLACKBOX_RULES.budgets.tool_calls).toBe(120);
  });

  it("parses wall clock, weights and wall bypass settings from the rules document", () => {
    const rules = blackboxRules({
      BLACKBOX_RULES_DOCUMENT: JSON.stringify({
        budgets: { time_sec: 600, wall_clock_sec: 2400, tool_calls: 200 },
        tool_weights: { "recon.nuclei": 8, "not-a-tool": 9 },
        auth_wall: { safe_paths: [".env"], allow_bypass: false, allow_unauth_playbook: false },
      }),
    });
    expect(rules.budgets).toMatchObject({ time_sec: 600, wall_clock_sec: 2400, tool_calls: 200 });
    expect(rules.tool_weights).toEqual({ "recon.nuclei": 8 });
    expect(rules.auth_wall.safe_paths).toEqual([".env"]);
    expect(rules.auth_wall.allow_bypass).toBe(false);
    expect(rules.auth_wall.allow_unauth_playbook).toBe(false);
  });

  it("keeps the legacy single-value budget keys dead but reports them", () => {
    // 这些键历史上从没被读取过；让它们生效会静默覆盖规则文档的新默认值，所以只报错不采用。
    const legacy = blackboxRules({ BLACKBOX_AGENT_TURN_BUDGET: "1", BLACKBOX_TOOL_BUDGET: "50" });
    expect(legacy.budgets).toEqual(DEFAULT_BLACKBOX_RULES.budgets);
    const diagnostics = blackboxRulesDiagnostics({ BLACKBOX_AGENT_TURN_BUDGET: "1" });
    expect(diagnostics.valid).toBe(true);
    expect(diagnostics.issues.join(" ")).toContain("BLACKBOX_AGENT_TURN_BUDGET");
  });

  it("reports an invalid weight key instead of failing the whole document", () => {
    const diagnostics = blackboxRulesDiagnostics({
      BLACKBOX_RULES_DOCUMENT: JSON.stringify({ budgets: { wall_clock_sec: 1200 }, tool_weights: { "not-a-tool": 5 } }),
    });
    expect(diagnostics.valid).toBe(true);
    expect(diagnostics.issues.join(" ")).toContain("tool_weights");
  });
});

describe("tool weights", () => {
  it("bills cheap requests at 1 and scanners at 5", () => {
    expect(toolWeight("http.request")).toBe(1);
    expect(toolWeight("http.diff")).toBe(1);
    expect(toolWeight("katana.crawl")).toBe(5);
    expect(toolWeight("recon.nuclei")).toBe(5);
    expect(toolWeight("recon.sql")).toBe(5);
    expect(toolWeight("burp.scan")).toBe(3);
    expect(toolWeight("unknown.tool")).toBe(1);
  });

  it("honours per-tool overrides", () => {
    expect(toolWeight("recon.nuclei", { "recon.nuclei": 2 })).toBe(2);
    expect(toolWeight("recon.nuclei", { "recon.nuclei": 0 })).toBe(TOOL_WEIGHTS["recon.nuclei"]);
  });

  it("marks the long-running scanners as heavy", () => {
    for (const tool of ["recon.sql", "recon.nuclei", "katana.crawl", "recon.content_discovery"]) expect(isHeavyTool(tool)).toBe(true);
    for (const tool of ["http.request", "http.diff", "recon.interactsh", "burp.history"]) expect(isHeavyTool(tool)).toBe(false);
  });
});

describe("degradation mode", () => {
  it("stays full while the wall clock covers the playbook timebox", () => {
    const result = budgetMode({ wallMsLeft: 1_500_000, scheduleMsLeft: 800_000, weightLeft: 100, timeboxSec: 1500 });
    expect(result.mode).toBe("full");
    expect(result.reasons).toEqual([]);
  });

  it("does not degrade just because the playbook timebox exceeds the remaining wall clock", () => {
    // 回归：wall=1200s < sqli 时间盒 1500s，旧判据会在这里切 fast 并永久禁掉 sqlmap。
    const result = budgetMode({ wallMsLeft: 1_200_000, scheduleMsLeft: 800_000, weightLeft: 100, timeboxSec: 1500 });
    expect(result.mode).toBe("full");
    expect(result.reasons).toEqual([]);
  });

  it("degrades only when the wall clock cannot cover a single heavy step", () => {
    const result = budgetMode({ wallMsLeft: 250_000, scheduleMsLeft: 800_000, weightLeft: 100, timeboxSec: 1500 });
    expect(result.mode).toBe("fast");
    expect(result.reasons.join(" ")).toContain("300");
  });

  it("degrades when the weighted tool budget is nearly spent", () => {
    expect(budgetMode({ wallMsLeft: 1_500_000, scheduleMsLeft: 800_000, weightLeft: 3, timeboxSec: 900 }).mode).toBe("fast");
    expect(budgetMode({ wallMsLeft: 1_500_000, scheduleMsLeft: 40_000, weightLeft: 100, timeboxSec: 900 }).mode).toBe("fast");
  });

  it("drops sqlmap from sqli and narrows the confirmation to light steps", () => {
    const sqli = playbookById("sqli")!;
    const full = degradedPlan({ ...sqli, steps: sqli.steps });
    expect(sqli.steps.map(step => step.tool)).toContain("recon.sql");
    expect(full.steps.map(step => step.tool)).not.toContain("recon.sql");
    expect(full.skipped.join(" ")).toContain("recon.sql");
    // 降级后仍要有可用的确认依据，否则任务永远到不了 completed。
    expect(full.confirm.length).toBeGreaterThan(0);
    for (const id of full.confirm) expect(full.steps.map(step => step.id)).toContain(id);
    expect(full.confirm.length).toBeLessThan(sqli.confirm.evidence.length + 1);
  });
});

describe("schedule time ignores tool execution", () => {
  const budget = { timeMs: 900_000, wallClockMs: 1_800_000, toolCalls: 120, agentTurns: 24, tokens: 0, cost: 0, retries: 5 };

  const state = () => {
    const progress = new BlackboxProgress();
    progress.state.usage = { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0, toolMs: 0 };
    return progress.state;
  };

  it("does not warn when the wall clock was spent inside tools", () => {
    const checkpoint = state();
    // 800 秒墙钟，其中 780 秒是 sqlmap 在跑：调度只花了 20 秒，不该触发 budget_warning。
    checkpoint.usage.elapsedMs = 800_000;
    checkpoint.usage.toolMs = 780_000;
    const decision = superviseCheckpoint(checkpoint, budget, { kind: "tool_batch", madeProgress: true, toolCalls: 1, evidenceCount: 1 });
    expect(decision.warnings).not.toContain("budget_warning");
  });

  it("warns when the wall clock itself approaches the hard ceiling", () => {
    const checkpoint = state();
    checkpoint.usage.elapsedMs = 1_500_000;
    checkpoint.usage.toolMs = 1_480_000;
    const decision = superviseCheckpoint(checkpoint, budget, { kind: "tool_batch", madeProgress: true, toolCalls: 1, evidenceCount: 1 });
    expect(decision.warnings).toContain("budget_warning");
  });
});
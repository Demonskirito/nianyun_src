import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { chargeFocusRound, pendingIgnoredAdvice, type FocusLimits } from "../src/blackbox/focus-budget.js";
import { signalActions } from "../src/blackbox/signal-actions.js";

const EVID = "ev-1111111111111111";
const limits: FocusLimits = {
  max_turns_per_task: 8,
  max_tp_per_task: 50,
  stall_rounds: 3,
  appeal_pool: 3,
  appeal_potential_max: 2,
  max_session_convergences: 8,
};

describe("变更①：未处置的 Observer 建议被忽略 → 加速收口", () => {
  it("pendingIgnoredAdvice 只返回本轮被漏掉（misses>=1）的建议", () => {
    const state = {
      advice: {
        "review-kept": { status: "pending", misses: 0 },
        "review-ignored": { status: "pending", misses: 2 },
        "review-done": { status: "accepted", misses: 5 },
      },
    } as unknown as Parameters<typeof pendingIgnoredAdvice>[0];
    expect(pendingIgnoredAdvice(state).map(a => a.id)).toEqual(["review-ignored"]);
  });

  it("正常无进展到 stall_rounds 才收口（baseline）", () => {
    const state = { advice: {}, focus_usage: baseUsage(0) } as any;
    const r = chargeFocusRound(state, "T1", limits);
    expect(r.convergence).toBeUndefined();
  });

  it("忽略建议且 no_progress 达到 stall_rounds-1 即提前一轮收口，且点名 advice_id", () => {
    const state = {
      advice: { "review-abc": { status: "pending", misses: 1 } },
      // no_progress_rounds=1，chargeFocusRound 自增到 2 = stall_rounds-1
      focus_usage: baseUsage(1),
    } as any;
    const r = chargeFocusRound(state, "T1", limits);
    expect(r.convergence).toBeDefined();
    expect(r.convergence!.reason).toBe("focus_stalled");
    expect(r.convergence!.text).toContain("review-abc");
  });

  it("忽略建议但本轮在涨分（no_progress=0）不会误伤", () => {
    const state = {
      advice: { "review-abc": { status: "pending", misses: 1 } },
      focus_usage: { ...baseUsage(0), value_score: 5, last_value_score: 0 },
    } as any;
    const r = chargeFocusRound(state, "T1", limits);
    expect(r.convergence).toBeUndefined();
  });
});

describe("变更②：信号→动作映射", () => {
  it("识别 waf_suspected 并给出阶梯/战例动作", () => {
    const ev = [{ id: "ev-1", kind: "tool-result", summary: "403 blocked by envoy waf on /api", data: {} }];
    const acts = signalActions({}, ev);
    expect(acts.map(a => a.signal)).toContain("waf_suspected");
    expect(acts[0].action).toContain("waf_bypass");
  });

  it("识别 SOA2 异常回显（内部异常类 + 追踪ID）并逼出真实 appid 对照", () => {
    const ev = [{
      id: "ev-2", kind: "tool-result",
      summary: "404 NotFoundRouteException rootMessageId=100025527 statusMsg=Not-Found-Route",
      data: { body: "{\"statusMsg\":\"Not-Found-Route\",\"cause\":\"NotFoundRouteException\"}" },
    }];
    const acts = signalActions({}, ev);
    const soa2 = acts.find(a => a.signal === "soa2_exception_echo");
    expect(soa2).toBeDefined();
    expect(soa2!.action).toContain("appid");
    expect(soa2!.why).toContain("路由分发栈");
  });

  it("无信号时不产出动作", () => {
    expect(signalActions({}, [{ id: "ev-3", summary: "200 OK plain page" }])).toEqual([]);
  });
});

describe("变更③：completed 必须带 verdict（finding 或 verified_negative）", () => {
  it("漏洞确认类任务无 finding 标 completed 被拒，保持 pending", () => {
    const p = new BlackboxProgress();
    p.state.tasks.T1 = { status: "pending", target: "https://a.test/x", purpose: "t", reason: "r", playbook: "idor", contract_required: false };
    p.merge({
      summary: "完成",
      required_tasks: [], completed_tasks: ["T1"], blocked_tasks: [], failed_tasks: [],
      task_outcomes: [{ task_id: "T1", reason: `完成 ${EVID}`, evidence_ids: [EVID] }],
      findings: [],
    }, [{ id: EVID, kind: "tool-result", data: { ok: true, task_id: "T1", url: "https://a.test/x" } }]);
    expect(p.state.tasks.T1.status).toBe("pending");
    expect(p.state.transitionErrors).toContain(`completion_without_verdict:T1`);
  });

  it("漏洞确认类任务：finding + 确认谓词（一次越权对照）都齐才 completed", () => {
    const p = new BlackboxProgress();
    p.state.tasks.T1 = { status: "pending", target: "https://a.test/x", purpose: "t", reason: "r", playbook: "idor", contract_required: false };
    p.merge({
      summary: "完成",
      required_tasks: [], completed_tasks: ["T1"], blocked_tasks: [], failed_tasks: [],
      task_outcomes: [{ task_id: "T1", reason: `确认越权 ${EVID}`, evidence_ids: [EVID] }],
      findings: [{
        id: "F1", title: "IDOR", type: "access-control", target: "https://a.test/x",
        description: "d", impact: "i", severity: "high", reproduction_steps: ["s"],
        evidence_ids: [EVID], remediation: "r", confidence: "high",
      }],
    }, [
      { id: EVID, kind: "tool-result", data: { ok: true, task_id: "T1", url: "https://a.test/x" } },
      { id: "ev-diff", kind: "tool-result", tool: "http.diff", data: { verdict: "same_shape" } },
    ]);
    expect(p.state.tasks.T1.status).toBe("completed");
    expect(p.state.transitionErrors || []).not.toContain(`completion_without_verdict:T1`);
  });

  it("漏洞确认类任务：有 finding 但没对照谓词仍被拒，且点名缺 http.diff", () => {
    const p = new BlackboxProgress();
    p.state.tasks.T1 = { status: "pending", target: "https://a.test/x", purpose: "t", reason: "r", playbook: "idor", contract_required: false };
    p.merge({
      summary: "完成",
      required_tasks: [], completed_tasks: ["T1"], blocked_tasks: [], failed_tasks: [],
      task_outcomes: [{ task_id: "T1", reason: `确认越权 ${EVID}`, evidence_ids: [EVID] }],
      findings: [{
        id: "F1", title: "IDOR", type: "access-control", target: "https://a.test/x",
        description: "d", impact: "i", severity: "high", reproduction_steps: ["s"],
        evidence_ids: [EVID], remediation: "r", confidence: "high",
      }],
    }, [{ id: EVID, kind: "tool-result", data: { ok: true, task_id: "T1", url: "https://a.test/x" } }]);
    // 谓词化之后：写了 finding 也不够，证据必须真的构成对照，否则同一条线索会被
    // 包装成"漏洞"（2026-11-02 之前就是这个状态：匿名 GET 200 即可通过）。
    expect(p.state.tasks.T1.status).toBe("pending");
    expect(p.state.transitionErrors).toContain(`completion_without_verdict:T1`);
    expect(String(p.state.tasks.T1.outcome_reason || "")).toContain("http.diff");
  });

  it("交付型打法（spa_reverse）无 finding 也可 completed", () => {
    const p = new BlackboxProgress();
    p.state.tasks.T1 = { status: "pending", target: "https://a.test/html5", purpose: "t", reason: "r", playbook: "spa_reverse", contract_required: false };
    p.merge({
      summary: "完成",
      required_tasks: [], completed_tasks: ["T1"], blocked_tasks: [], failed_tasks: [],
      task_outcomes: [{ task_id: "T1", reason: `提取 bundle ${EVID}`, evidence_ids: [EVID] }],
      findings: [],
    }, [{ id: EVID, kind: "tool-result", data: { ok: true, task_id: "T1", url: "https://a.test/html5" } }]);
    expect(p.state.tasks.T1.status).toBe("completed");
  });
});

function baseUsage(noProgress: number) {
  return {
    task_id: "T1", turns: noProgress, tool_calls: noProgress, tp: 10, value_score: 0,
    high_value: 0, medium_value: 0, noise: 0, last_value_score: 0,
    no_progress_rounds: noProgress, appeals_used: 0, max_turns: 8, max_tp: 50,
  };
}

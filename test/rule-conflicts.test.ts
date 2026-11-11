/**
 * 规则冲突回归（2026-11-02 审计的 1/2/3/4-5-6/8 条）。
 *
 * 这些用例的共同点：它们不是"某个函数算错了"，而是**两条规则各自成立、合起来把 run 弄死**。
 * 所以断言写的是"互锁解开"这件事的可观测后果（焦点能交出去、建议能被采纳、阶梯预算够跑、
 * 一致性不被当零熵、候选发现不会永久卡住验收、墙对未授权验证留了通道）。
 */
import { describe, expect, it } from "vitest";
import { computeFocus, focusDirective } from "../src/blackbox/focus.js";
import { BlackboxProgress, type RunCheckpoint } from "../src/blackbox/progress.js";
import { chargeFocusRound, ladderRungsOf, scaleLimitsForTask, type FocusLimits } from "../src/blackbox/focus-budget.js";
import { consistencyPlaybookOf } from "../src/blackbox/vuln-predicates.js";
import { bypassChannelOf, wallVerdict } from "../src/blackbox/authwall.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { blackboxRules } from "../src/blackbox/rules.js";

const limits: FocusLimits = {
  max_turns_per_task: 8, max_tp_per_task: 50, stall_rounds: 3, appeal_pool: 3,
  appeal_potential_max: 6, max_session_convergences: 5,
};

function focusState(): RunCheckpoint {
  return {
    tasks: {
      T1: { status: "pending", target: "https://a.test/one", purpose: "深挖 T1 的越权面" },
      T3: { status: "pending", target: "https://a.test/three", purpose: "验证 /api/order 未授权访问" },
    },
    graph: { nodes: {}, edges: [] },
    focus_task_id: "T1",
    usage: { elapsedMs: 0, toolCalls: 0, agentTurns: 0, tokens: 0, cost: 0, retries: 0 },
  } as unknown as RunCheckpoint;
}

function backlog(tasks = 16): BlackboxProgress {
  const progress = new BlackboxProgress();
  for (let index = 0; index < tasks; index += 1) {
    progress.state.tasks[`F${index}`] = { status: "pending", purpose: `填充待办 ${index} 号：只占位不推进` };
  }
  return progress;
}

describe("冲突 1：焦点锁 × Observer 建议", () => {
  it("建议被漏过一轮后，焦点让位给建议指向的任务", () => {
    const state = focusState();
    state.advice = { advice_1: { tasks: [], status: "pending", task_ids: ["T3"], misses: 1 } };
    const choice = computeFocus(state);
    expect(choice?.task_id).toBe("T3");
    expect(choice?.reason).toBe("advice");
    expect(focusDirective(choice!, 2)).toContain("让位");
  });

  it("新建议第一次出现不抖焦点（仍按粘性走原任务）", () => {
    const state = focusState();
    state.advice = { advice_1: { tasks: [], status: "pending", task_ids: ["T3"], misses: 0 } };
    expect(computeFocus(state)?.task_id).toBe("T1");
    expect(computeFocus(state)?.reason).toBe("sticky");
  });

  it("建议指向的就是当前焦点时不让位（否则会自己和自己交接）", () => {
    const state = focusState();
    state.advice = { advice_1: { tasks: [], status: "pending", task_ids: ["T1"], misses: 3 } };
    expect(computeFocus(state)?.reason).toBe("sticky");
  });

  it("建议已处置（accepted/rejected）后焦点自动回原任务", () => {
    const state = focusState();
    state.advice = { advice_1: { tasks: [], status: "accepted", reason: "已办", task_ids: ["T3"], misses: 2 } };
    expect(computeFocus(state)?.task_id).toBe("T1");
  });
});

describe("冲突 1（续）：焦点申诉", () => {
  it("连续两轮整批被拒才交接，第一轮只记账", () => {
    const first = focusState();
    first.focus_appeal = { task_id: "T3", votes: 1, at: 0 };
    expect(computeFocus(first)?.task_id).toBe("T1");

    const second = focusState();
    second.focus_appeal = { task_id: "T3", votes: 2, at: 0 };
    const choice = computeFocus(second);
    expect(choice?.task_id).toBe("T3");
    expect(choice?.reason).toBe("appeal");
  });

  it("申诉目标已经终态时不再交接", () => {
    const state = focusState();
    state.tasks.T3 = { ...state.tasks.T3!, status: "blocked", reason: "done" };
    state.focus_appeal = { task_id: "T3", votes: 5, at: 0 };
    expect(computeFocus(state)?.task_id).toBe("T1");
  });
});

describe("冲突 2：任务簿上限 × 采纳建议须建任务", () => {
  it("承载未处置建议的新任务可以破例入簿（最多 2 条）", () => {
    const progress = backlog();
    progress.state.advice = { advice_1: { tasks: [], status: "pending" } };
    progress.merge({
      required_tasks: [{ id: "T_NEW", purpose: "验证 /api/order 未授权访问", reason: "Observer 要求补证" }],
      advice_decisions: [{ advice_id: "advice_1", accepted: true, reason: "采纳并立任务", task_ids: ["T_NEW"] }],
    });
    expect(progress.state.tasks.T_NEW?.status).toBe("pending");
    expect(progress.state.adviceDecisionResults?.[0]?.status).toBe("applied");
    expect(progress.state.backlog_admissions?.map(item => item.task_id)).toEqual(["T_NEW"]);
    expect(progress.state.transitionErrors || []).not.toContain("task_backlog_full:16/16");
  });

  it("与建议无关的新任务不会破例入簿，改为排队而不是打回", () => {
    const progress = backlog();
    progress.merge({ required_tasks: [{ id: "T_PLAN", purpose: "又一轮无关的重新规划", reason: "随便" }] });
    expect(progress.state.tasks.T_PLAN).toBeUndefined();
    // ② 簿满不再写 transitionErrors，否则 transition-rejected 每轮重播同一条噪声。
    expect(progress.state.transitionErrors || []).not.toContain("task_backlog_full:16/16");
    expect(progress.state.backlog_deferred?.map(entry => String(entry.spec.id))).toEqual(["T_PLAN"]);
    expect(progress.state.backlog_rejects?.at(-1)).toMatchObject({ task_id: "T_PLAN", deferred: true });
  });

  it("建议指向的 id 被语义去重吞成别名时，采纳仍然成立", () => {
    const progress = new BlackboxProgress();
    progress.state.tasks.T6 = { status: "pending", purpose: "验证 CORS 配置是否放开任意源" };
    progress.state.task_aliases = { T20: "T6" };
    progress.state.advice = { advice_2: { tasks: [], status: "pending" } };
    progress.merge({ advice_decisions: [{ advice_id: "advice_2", accepted: true, reason: "采纳", task_ids: ["T20"] }] });
    expect(progress.state.adviceDecisionResults?.[0]?.status).toBe("applied");
    expect(progress.state.advice?.advice_2.task_ids).toEqual(["T6"]);
  });
});

describe("冲突 3：单任务预算 × WAF 阶梯", () => {
  it("waf_bypass 任务按档位缩放轮数/TP，并放宽无增益阈值", () => {
    const scaled = scaleLimitsForTask(limits, { playbook: "waf_bypass" });
    expect(scaled.max_turns_per_task).toBe(15);
    expect(scaled.max_tp_per_task).toBe(64);
    expect(scaled.stall_rounds).toBe(5);
    // 缩放有上限：不能变成"WAF 任务永远不收口"
    expect(scaled.max_turns_per_task).toBeLessThanOrEqual(limits.max_turns_per_task * 2);
  });

  it("普通打法不受影响", () => {
    expect(scaleLimitsForTask(limits, { playbook: "idor" })).toEqual(limits);
    expect(scaleLimitsForTask(limits, undefined)).toEqual(limits);
  });

  it("没绑 playbook 但目的写着阶梯，也按阶梯算", () => {
    expect(ladderRungsOf({ purpose: "按 WAF 阶梯逐档绕过拦截页" })).toBe(7);
    expect(ladderRungsOf({ purpose: "枚举 JS 里的接口" })).toBe(0);
  });
});

describe("冲突 4：零熵判据对一致性打法方向反了", () => {
  it("未授权/鉴权对照类任务被认成「一致性即结论」", () => {
    expect(consistencyPlaybookOf({ playbook: "unauth_exposure" })).toBe("unauth_exposure");
    expect(consistencyPlaybookOf({ playbook: "idor" })).toBe("idor");
    // 自由文本任务也要认：提示词本来就要求未授权验证必须匿名
    expect(consistencyPlaybookOf({ purpose: "验证 /api/order 匿名可读" })).toBe("unauth_free_text");
    expect(consistencyPlaybookOf({ purpose: "枚举 JS 里的接口" })).toBeUndefined();
    expect(consistencyPlaybookOf(undefined)).toBeUndefined();
  });
});

describe("冲突 5：candidate / needs_evidence 卡住终审", () => {
  const evidence = [{ id: "ev-1", kind: "tool-result", summary: "200", data: { ok: true, url: "https://a.test/api/order", task_id: "T1" } }];
  const finding = {
    id: "F1", title: "订单未授权访问", type: "unauth_exposure", target: "https://a.test/api/order",
    description: "匿名可读", impact: "数据泄露", severity: "high",
    reproduction_steps: ["GET /api/order"], evidence_ids: ["ev-1"], remediation: "加鉴权", confidence: "medium",
  };

  function stateWith(status: string, review: { actor: string; reason: string; evidence_ids: string[] } | undefined) {
    return {
      version: 1,
      tasks: { T1: { status: "completed", evidence_ids: ["ev-1"], outcome_reason: "verified_negative ev-1" } },
      findings: { F1: { ...finding, status, review } },
    } as unknown as RunCheckpoint;
  }

  it("遗留 candidate 不再阻止收尾", () => {
    const result = evaluateAcceptance(stateWith("candidate", { actor: "observer", reason: "缺 diff", evidence_ids: [], at: 0 }), evidence);
    expect(result.required_reviews_complete).toBe(true);
    expect(result.reason_codes).not.toContain("TERMINAL_REVIEW_PENDING");
  });

  it("needs_evidence 允许空引用（没有新证据可引就是它的语义）", () => {
    const result = evaluateAcceptance(stateWith("needs_evidence", { actor: "observer", reason: "缺一次 http.diff", evidence_ids: [], at: 0 }), evidence);
    expect(result.issues.some(issue => issue.code === "FINDING_REVIEW_INVALID")).toBe(false);
  });

  it("confirmed 仍然必须引用证据（放宽的只是 needs_evidence）", () => {
    const result = evaluateAcceptance(stateWith("confirmed", { actor: "observer", reason: "可复现", evidence_ids: [], at: 0 }), evidence);
    expect(result.issues.some(issue => issue.code === "FINDING_REVIEW_INVALID")).toBe(true);
  });

  it("从未被评审看过的候选仍然拦收尾（那等于把未裁决的发现混进报告）", () => {
    const result = evaluateAcceptance(stateWith("candidate", undefined), evidence);
    const issue = result.issues.find(item => item.code === "FINDING_CANDIDATE_UNREVIEWED");
    expect(issue?.severity).toBe("warning");
    expect(result.required_reviews_complete).toBe(false);
    expect(result.reason_codes).toContain("TERMINAL_REVIEW_PENDING");
  });
});

describe("冲突 6：鉴权墙对「自由文本未授权验证」留通道", () => {
  // 墙记的是"已被拒绝的入口"，host 用 hostOf 的协议+host 形态，前缀由前两段路径推导。
  const walled = { auth_wall: { host: "https://a.test", streak: 3, urls: ["/api/order/1", "/api/order/2", "/api/order/3"], tripped_at: 1 } };

  it("没有 playbook 但目的写明未授权验证 → 放行", () => {
    expect(wallVerdict(walled, "https://a.test/api/order/9", {}, { taskIntent: "验证 /api/order 未授权访问" }))
      .toMatchObject({ blocked: false, bypass: "intent" });
    expect(bypassChannelOf("https://a.test/api/order/9", {}, { taskIntent: "匿名可读性对照" })).toBe("intent");
  });

  it("意图不像未授权验证时仍然被墙拦下", () => {
    expect(wallVerdict(walled, "https://a.test/api/order/9", {}, { taskIntent: "枚举接口清单" })).toMatchObject({ blocked: true });
  });

  it("绑了别的打法时不走意图通道（明确打法优先于意图猜测）", () => {
    expect(wallVerdict(walled, "https://a.test/api/order/9", {}, { playbook: "sqli", taskIntent: "未授权验证" }))
      .toMatchObject({ blocked: true });
  });
});

/**
 * 冲突 1 的更深一层（2026-11-02 实跑 6ee79b87a797904f 暴露）：
 * forced_focus 在 computeFocus 里排在 appeal 之前，于是"连续多轮整批请求被焦点锁拒收"这条
 * 硬证据也换不来让位——4 轮 11 个请求零放行，40 次调用只用了 3 次。
 * forced 是代码替模型做的决定，但它不能变成"模型每次都被自己的调度器拒收"。
 */
describe("冲突 1-b：强制焦点 × 申诉让位", () => {
  function forcedState(): RunCheckpoint {
    return {
      tasks: {
        T_SPA: { status: "pending", target: "https://a.test/html5/", purpose: "SPA 外壳逆向" },
        T1: { status: "pending", target: "https://a.test/one", purpose: "模型真正想打的未授权面" },
      },
      graph: { nodes: {}, edges: [] },
      focus_task_id: "T1",
      forced_focus: { task_id: "T_SPA", kind: "spa", at: 1 },
    } as unknown as RunCheckpoint;
  }

  it("连续两轮整批被拒（votes>=2）时强制焦点让位", () => {
    const state = forcedState();
    state.focus_appeal = { task_id: "T1", votes: 2, at: 2 };
    const choice = computeFocus(state);
    expect(choice?.task_id).toBe("T1");
    expect(choice?.reason).toBe("appeal");
    expect(focusDirective(choice!, 2)).toContain("T1");
  });

  it("只记了一轮票时不抖强制焦点", () => {
    const state = forcedState();
    state.focus_appeal = { task_id: "T1", votes: 1, at: 2 };
    expect(computeFocus(state)?.reason).toBe("forced");
  });

  it("交接后票归零但挂起标记仍在：不让 forced 抢回去", () => {
    const state = forcedState();
    state.focus_task_id = "T1";
    state.focus_appeal = { task_id: "T1", votes: 0, at: 2, suspended: true, suspended_from: "T_SPA" };
    expect(computeFocus(state)?.task_id).toBe("T1");
  });

  it("让位目标结案后强制焦点自动恢复", () => {
    const state = forcedState();
    (state.tasks as Record<string, { status: string }>).T1.status = "completed";
    state.focus_appeal = { task_id: "T1", votes: 3, at: 2, suspended: true, suspended_from: "T_SPA" };
    const choice = computeFocus(state);
    expect(choice?.task_id).toBe("T_SPA");
    expect(choice?.reason).toBe("forced");
  });
});

/**
 * Observer 降级（2026-11-02 实跑 8a2b134101b62649）：
 * 审查连续失败 → 旧代码 halt("observer_review_failed") 直接停场，39/40 次调用、1 条 finding 的 run
 * 就这么停在最后一格。Observer 是辅助，验收不该被一个挂掉的副驾驶永久卡住。
 */
describe("Observer 降级：审查不可用不等于 run 结束", () => {
  it("reviewUnavailable 时 required_reviews_complete 为真", () => {
    const state = {
      version: 1,
      tasks: { T1: { status: "pending", purpose: "还在打" } },
      findings: {},
      supervision: { observerRuns: 4, reviewPending: true, reviewUnavailable: true, reviewFailures: 3 },
    } as unknown as RunCheckpoint;
    const result = evaluateAcceptance(state, []);
    expect(result.required_reviews_complete).toBe(true);
  });

  it("没降级时仍需等审查跑完", () => {
    const state = {
      version: 1,
      tasks: { T1: { status: "pending", purpose: "还在打" } },
      findings: {},
      supervision: { observerRuns: 1, reviewPending: true, reviewFailures: 1 },
    } as unknown as RunCheckpoint;
    expect(evaluateAcceptance(state, []).required_reviews_complete).toBe(false);
  });
});

/**
 * 焦点溢出（2026-11-02 三场实跑后补）：整批被焦点锁拒收时放行"被拒最多的那一个任务"，
 * 上限 overflow_per_round 条/轮。焦点不动，只是不让一整轮计划全废。
 */
describe("冲突 1-c：焦点溢出的配置面", () => {
  it("默认每轮溢出 2 条，且可以关掉", () => {
    const defaults = blackboxRules({});
    expect(defaults.focus_lock.overflow_per_round).toBe(2);
    const off = blackboxRules({ BLACKBOX_RULES_DOCUMENT: JSON.stringify({ focus_lock: { overflow_per_round: 0 } }) });
    expect(off.focus_lock.overflow_per_round).toBe(0);
  });
});

/**
 * 收益递减的前提是"试过了没回报"（2026-11-02 实跑 4f899c3af6c2ac84）：
 * forced 焦点任务模型一次都没打过，旧算法却按"每轮没涨分"累加，3 轮就把它判成收益递减并
 * 强制 blocked，calls 停在 4/40。没派过活不该算收益递减。
 */
describe("焦点预算：没派过活 ≠ 收益递减", () => {
  function usageState(): RunCheckpoint {
    return {
      tasks: { T1: { status: "pending", target: "https://a.test/x", purpose: "被无视的焦点" } },
      graph: { nodes: {}, edges: [] },
      focus_task_id: "T1",
    } as unknown as RunCheckpoint;
  }

  it("连续 3 轮 0 派活不会触发 focus_stalled", () => {
    const state = usageState();
    let result = chargeFocusRound(state, "T1", limits, 0);
    expect(result.convergence).toBeUndefined();
    result = chargeFocusRound(state, "T1", limits, 0);
    expect(result.convergence).toBeUndefined();
    result = chargeFocusRound(state, "T1", limits, 0);
    expect(result.convergence).toBeUndefined();
    expect(result.usage.no_progress_rounds).toBe(0);
  });

  it("派了活但没涨分，照样按 stall_rounds 收口", () => {
    const state = usageState();
    // 第 1 轮建账（no_progress=0），之后每轮 +1；stall_rounds=3 → 第 4 轮触发。
    let result = chargeFocusRound(state, "T1", limits, 2);
    for (let round = 0; round < 4; round += 1) result = chargeFocusRound(state, "T1", limits, 2);
    expect(result.convergence?.reason).toBe("focus_stalled");
  });
});

import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { blackboxReport } from "../src/blackbox/findings.js";
import { boundedContext } from "../src/blackbox/context.js";
import { mainSchema } from "../src/blackbox/protocol.js";
import {
  partitionBlocking, quarantineFindings, quarantineTaskRefs, quarantineView, repairDigest,
  type IssueLike,
} from "../src/blackbox/quarantine.js";

/**
 * 静默降级 + 显式标记（2026-11-06）。
 *
 * 这几条用例守的是同一个契约：**一条记账错误不该换掉整份报告**，
 * 但被降级的东西必须留下痕迹——报告附录、上下文、验收口径三处都要能查到。
 */

const finding = (id: string, evidenceIds: string[]) => ({
  id, title: "越权读取", type: "idor", target: "https://a.example/api/u/1",
  description: "改了 uid 就能读到别人订单", impact: "越权", severity: "high" as const,
  reproduction_steps: ["带 A 的 cookie 请求 /api/u/1"], evidence_ids: evidenceIds,
  remediation: "服务端校验归属", confidence: "medium" as const,
});

describe("阻塞项分类：哪些能隔离，哪些不能", () => {
  it("发现引用了不存在的证据 → 可隔离，主体从 path 解析", () => {
    const issues: IssueLike[] = [{ code: "FINDING_EVIDENCE_INVALID", severity: "error", path: "findings.f_1.evidence_ids", message: "f_1:候选发现引用了不存在的会话证据" }];
    const { quarantinable, fatal } = partitionBlocking(issues);
    expect(fatal).toEqual([]);
    expect(quarantinable).toEqual([expect.objectContaining({ kind: "finding", id: "f_1", code: "FINDING_EVIDENCE_INVALID" })]);
  });

  it("任务结案没引证据 → 可隔离，主体从 path 解析", () => {
    const issues: IssueLike[] = [{ code: "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE", severity: "error", path: "tasks.T2.outcome_evidence_ids", message: "task_outcome_without_evidence_reference:T2", detail: "名下有 22 条证据却没引" }];
    const { quarantinable } = partitionBlocking(issues);
    expect(quarantinable).toEqual([expect.objectContaining({ kind: "task", id: "T2", reason: "名下有 22 条证据却没引" })]);
  });

  it("结案提交的拒收走 task_outcomes 路径时，用 task_id 定位", () => {
    const issues: IssueLike[] = [{ code: "OUTCOME_WITHOUT_EVIDENCE_REFERENCE", severity: "error", path: "task_outcomes.0.reason", task_id: "T1", message: "outcome_without_evidence_reference:T1" }];
    expect(partitionBlocking(issues).quarantinable[0]).toMatchObject({ kind: "task", id: "T1" });
  });

  it("结论本身站不住的错误绝不进隔离集合（隔离等于洗白）", () => {
    const issues: IssueLike[] = [
      { code: "COMPLETION_ON_DENIED_EVIDENCE", severity: "error", path: "tasks.T3.evidence_ids", task_id: "T3", message: "拿 401 当漏洞证据" },
      { code: "ANOMALY_REQUIRES_DIFF", severity: "error", path: "tasks.T4.evidence_ids", task_id: "T4", message: "异常缺对照" },
    ];
    const { quarantinable, fatal } = partitionBlocking(issues);
    expect(quarantinable).toEqual([]);
    expect(fatal).toHaveLength(2);
  });

  it("同一条错误重复出现只算一次；warning 不参与", () => {
    const issues: IssueLike[] = [
      { code: "TASK_EVIDENCE_MISSING", severity: "error", path: "tasks.T1.evidence_ids", message: "task_evidence_missing:T1" },
      { code: "TASK_EVIDENCE_MISSING", severity: "error", path: "tasks.T1.evidence_ids", message: "task_evidence_missing:T1" },
      { code: "FINDING_EVIDENCE_INVALID", severity: "warning", path: "findings.f_2.evidence_ids", message: "f_2:x" },
    ];
    expect(partitionBlocking(issues).quarantinable).toHaveLength(1);
  });
});

describe("隔离：打标记，不删数据", () => {
  it("发现被标 quarantined，status 原样保留（评审是历史事实）", () => {
    const state = { findings: { f_1: { ...finding("f_1", ["ev-dead"]), status: "confirmed" } as unknown as Record<string, unknown> } };
    const done = quarantineFindings(state, [{ kind: "finding", id: "f_1", code: "FINDING_EVIDENCE_INVALID", reason: "引用了不存在的证据" }]);
    expect(done).toHaveLength(1);
    expect(state.findings.f_1).toMatchObject({ status: "confirmed", quarantined: true, quarantine_reason: "引用了不存在的证据" });
    expect(state.findings.f_1.quarantined_at).toBeTypeOf("number");
  });

  it("任务只摘掉账本里不存在的引用，有效引用保留，原文留档", () => {
    const evidence = [{ id: "ev-good", kind: "tool-result", data: { ok: true, task_id: "T2" } }];
    const state = { tasks: { T2: { status: "blocked", outcome_evidence_ids: ["ev-good", "ev-ghost"] } as Record<string, unknown> } };
    const done = quarantineTaskRefs(state, evidence, [{ kind: "task", id: "T2", code: "TASK_EVIDENCE_INVALID", reason: "引用了不存在的证据" }]);
    expect(state.tasks.T2.outcome_evidence_ids).toEqual(["ev-good"]);
    expect(state.tasks.T2.stripped_refs).toEqual([expect.objectContaining({ field: "outcome_evidence_ids", dropped: ["ev-ghost"] })]);
    // 还有有效引用 → 不能标成"未经证据支撑"，那是另一种谎
    expect(state.tasks.T2.evidence_status).toBeUndefined();
    expect(done[0]?.stripped).toEqual(["ev-ghost"]);
  });

  it("摘完一条不剩 → 标 unverified，并带上原因", () => {
    const state = { tasks: { T2: { status: "blocked", outcome_evidence_ids: ["ev-ghost"] } as Record<string, unknown> } };
    quarantineTaskRefs(state, [], [{ kind: "task", id: "T2", code: "TASK_EVIDENCE_INVALID", reason: "引用不存在" }]);
    expect(state.tasks.T2.outcome_evidence_ids).toEqual([]);
    expect(state.tasks.T2).toMatchObject({ evidence_status: "unverified", evidence_status_reason: "引用不存在" });
  });

  it("『有证据却没引』摘不出东西，但同样标 unverified（结论确实缺支撑）", () => {
    const state = { tasks: { T2: { status: "blocked" } as Record<string, unknown> } };
    quarantineTaskRefs(state, [{ id: "ev-1", data: {} }], [{ kind: "task", id: "T2", code: "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE", reason: "22 条证据一条没引" }]);
    expect(state.tasks.T2).toMatchObject({ evidence_status: "unverified", evidence_status_reason: "22 条证据一条没引" });
  });

  it("quarantineView 同时列出被隔离的发现与未验证的任务", () => {
    const view = quarantineView({
      findings: { f_1: { quarantined: true, title: "越权", quarantine_reason: "引用不存在", quarantine_code: "FINDING_EVIDENCE_INVALID" } },
      tasks: { T2: { evidence_status: "unverified", evidence_status_reason: "没引证据" } },
    });
    expect(view).toEqual([
      { kind: "finding", id: "f_1", title: "越权", reason: "引用不存在", code: "FINDING_EVIDENCE_INVALID" },
      { kind: "task", id: "T2", reason: "没引证据", code: "EVIDENCE_UNVERIFIED" },
    ]);
  });
});

describe("修正提示：必须具体到能照做", () => {
  it("逐条点名 + 给出可抄的证据 id + 第几次机会 + 修不好的后果", () => {
    const text = repairDigest(
      [{ kind: "finding", id: "f_1", code: "FINDING_EVIDENCE_INVALID", reason: "引用了不存在的会话证据" }],
      [{ id: "ev-aaaaaaaaaaaaaaaa", kind: "tool-result", data: { ok: true } }, { id: "ev-failed", kind: "tool-result", data: { ok: false } }],
      1, 2,
    );
    expect(text).toContain("发现 f_1：引用了不存在的会话证据");
    expect(text).toContain("ev-aaaaaaaaaaaaaaaa");
    expect(text).not.toContain("ev-failed");           // 失败的工具结果不能当证据
    expect(text).toContain("第 1/2 次修正机会");
    expect(text).toContain("隔离");
  });

  it("超过三项只列前三项并说明总数", () => {
    const targets = [1, 2, 3, 4, 5].map(n => ({ kind: "task" as const, id: `T${n}`, code: "TASK_EVIDENCE_MISSING", reason: `缺证据 ${n}` }));
    const text = repairDigest(targets, [], 2, 2);
    expect(text).toContain("另有 2 项同类问题");
    expect(text).not.toContain("T4");
  });
});

describe("验收口径：隔离之后不再阻塞，但看得见", () => {
  it("被隔离的发现不再报 FINDING_EVIDENCE_INVALID", () => {
    const state = {
      version: 1 as const,
      tasks: { T1: { status: "blocked" as const, outcome_code: "agent_blocked", outcome_reason: "403 挡住（http.request 两次）", outcome_by: "agent" as const } },
      findings: { f_1: { ...finding("f_1", ["ev-missing"]), status: "candidate" as const, quarantined: true, quarantine_reason: "引用不存在" } },
    };
    const result = evaluateAcceptance(new BlackboxProgress(state).state, []);
    expect(result.issues.some(issue => issue.code === "FINDING_EVIDENCE_INVALID")).toBe(false);
    expect(result.blocking_error_count).toBe(0);
    // 但它确实还在账本里，附录能查到
    expect(quarantineView(state)).toHaveLength(1);
  });

  it("未验证任务的『有证据却没引』降级为 warning，不再卡住交付", () => {
    const evidence = [{ id: "ev-0123456789abcdef", kind: "tool-result", data: { ok: true, task_id: "T2" } }];
    const state = {
      version: 1 as const,
      tasks: { T2: { status: "blocked" as const, outcome_code: "agent_blocked", outcome_reason: "被 WAF 挡在 10403（4 次请求）", outcome_by: "agent" as const, evidence_status: "unverified" as const, evidence_status_reason: "结案没引用名下证据" } },
    };
    const result = evaluateAcceptance(new BlackboxProgress(state).state, evidence);
    const issue = result.issues.find(item => item.code === "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE");
    expect(issue?.severity).toBe("warning");
    expect(result.blocking_error_count).toBe(0);
  });

  it("未隔离时同一条错误仍是 error（降级只对已隔离的生效）", () => {
    const evidence = [{ id: "ev-0123456789abcdef", kind: "tool-result", data: { ok: true, task_id: "T2" } }];
    const state = {
      version: 1 as const,
      tasks: { T2: { status: "blocked" as const, outcome_code: "agent_blocked", outcome_reason: "被 WAF 挡在 10403（4 次请求）", outcome_by: "agent" as const } },
    };
    const result = evaluateAcceptance(new BlackboxProgress(state).state, evidence);
    expect(result.issues.find(item => item.code === "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE")?.severity).toBe("error");
    expect(result.blocking_error_count).toBe(1);
  });
});

describe("结案补引用通道：已 blocked 的任务也能补", () => {
  const evidence = [
    { id: "ev-0123456789abcdef", kind: "tool-result", data: { ok: true, task_id: "T2" } },
    { id: "ev-fedcba9876543210", kind: "tool-result", data: { ok: true, task_id: "T2" } },
  ];
  const blocked = () => {
    const p = new BlackboxProgress();
    p.state.tasks.T2 = { status: "blocked", outcome_code: "agent_blocked", outcome_reason: "被 WAF 挡在 10403（4 次请求）", outcome_by: "agent", completion_criteria: "读到订单页" };
    return p;
  };
  const resubmit = (ids: string[]) => mainSchema.parse({
    summary: "补引用", blocked_tasks: ["T2"],
    task_outcomes: [{ task_id: "T2", reason: "被 WAF 挡在 10403（4 次请求）", evidence_ids: ids }],
  });

  it("任务已 blocked 时补上真实证据 → 落账并清掉 unverified", () => {
    const p = blocked();
    p.state.tasks.T2.evidence_status = "unverified";
    p.merge(resubmit(["ev-0123456789abcdef"]), evidence);
    expect(p.state.tasks.T2.outcome_evidence_ids).toEqual(["ev-0123456789abcdef"]);
    expect(p.state.tasks.T2.evidence_status).toBeUndefined();
    expect(p.state.taskOutcomeResults?.T2).toMatchObject({ status: "applied" });
    expect(evaluateAcceptance(p.state, evidence).blocking_error_count).toBe(0);
  });

  it("只补不覆盖：已有引用不会被后来的提交改写", () => {
    const p = blocked();
    p.state.tasks.T2.outcome_evidence_ids = ["ev-0123456789abcdef"];
    p.merge(resubmit(["ev-fedcba9876543210"]), evidence);
    expect(p.state.tasks.T2.outcome_evidence_ids).toEqual(["ev-0123456789abcdef"]);
  });

  it("补的 id 全不存在 → 拒绝并给出可用候选，别让它以为补上了", () => {
    const p = blocked();
    p.merge(resubmit(["ev-0000000000000000"]), evidence);
    expect(p.state.tasks.T2.outcome_evidence_ids).toBeUndefined();
    expect(p.state.taskOutcomeResults?.T2).toMatchObject({ status: "rejected" });
    expect(p.state.taskOutcomeResults?.T2.issues[0]?.code).toBe("OUTCOME_EVIDENCE_PATCH_REJECTED");
    expect(p.state.taskOutcomeResults?.T2.issues[0]?.valid_ids).toEqual(expect.arrayContaining(["ev-0123456789abcdef"]));
  });
});

describe("报告与上下文：主体干净、附录留痕", () => {
  const session = {
    id: "s1", target: "https://a.example", status: "completed",
    checkpoint: {
      version: 1,
      stopReason: "partial_completed",
      tasks: {
        T1: { status: "completed", outcome_reason: "读到订单页", evidence_ids: ["ev-1"] },
        T2: { status: "blocked", outcome_code: "agent_blocked", outcome_reason: "被 WAF 挡在 10403（4 次请求）", outcome_by: "agent", evidence_status: "unverified", evidence_status_reason: "结案没引用名下 22 条证据" },
      },
      findings: {
        f_good: { ...finding("f_good", ["ev-1"]), status: "confirmed" },
        f_bad: { ...finding("f_bad", ["ev-ghost"]), status: "candidate", quarantined: true, quarantine_reason: "引用了不存在的会话证据", quarantine_code: "FINDING_EVIDENCE_INVALID" },
      },
    },
    evidence: [{ id: "ev-1", kind: "tool-result", data: { ok: true, url: "https://a.example/api/u/1" } }],
  };

  it("报告正文只留证据闭合的发现，被隔离的进附录与 json.quarantined", () => {
    const report = blackboxReport(session);
    const json = report.json as { findings: Array<{ id: string }>; quarantined: Array<{ id: string; kind: string }> };
    expect(json.findings.map(f => f.id)).toEqual(["f_good"]);
    expect(json.quarantined).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "finding", id: "f_bad" }),
      expect.objectContaining({ kind: "task", id: "T2" }),
    ]));
    expect(report.markdown).toContain("## 附录：被自动隔离的结论");
    expect(report.markdown).toContain("不计入本次评估结论");
    expect(report.markdown).toContain("原引用：ev-ghost");
    // 正文段（附录之前）不出现那条被隔离的发现
    const body = report.markdown.split("## 附录")[0]!;
    expect(body).not.toContain("f_bad");
  });

  it("未验证任务在任务行上显式标注，读者不会把它当已验证结论", () => {
    const report = blackboxReport(session);
    expect(report.markdown).toContain("结论未经证据支撑（引用无效，已隔离）");
  });

  it("上下文带 acceptance 明细与隔离清单，模型才知道改什么、别再交什么", () => {
    const context = boundedContext(session, {}) as {
      checkpoint: {
        acceptance: { issues: Array<{ code: string; detail: string }> };
        quarantine: { items: Array<{ id: string }>; note: string };
      };
    };
    expect(context.checkpoint.quarantine.items.map(item => item.id)).toEqual(expect.arrayContaining(["f_bad", "T2"]));
    expect(context.checkpoint.quarantine.note).toContain("不要重复提交原 id");
  });
});

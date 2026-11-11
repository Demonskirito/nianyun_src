import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";

const target = "https://app.example.test/";
const evId = "ev-0123456789abcdef";

/** 建一条由 required_tasks 起的任务（带契约），返回 progress。 */
function seeded(contract: Record<string, unknown> = {}) {
  const p = new BlackboxProgress();
  p.merge({
    required_tasks: [{
      id: "T_cdn", target, purpose: "取回真实 umi bundle 并提取 API 前缀", reason: "主 bundle 是唯一入口",
      completion_criteria: "看到至少一个非 catch-all 的 /api/ 路径", ...contract,
    }],
  });
  return p;
}

const evidence = [
  { id: evId, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_cdn", url: `${target}a` } },
];

describe("语义重复：从报警改成自动吞噬", () => {
  it("同类任务并入老任务，不再产生 task_duplicate 阻塞错误", () => {
    const p = seeded();
    const planBefore = p.state.planRevision;
    p.merge({ required_tasks: [{
      id: "T_CDN_JS", target, purpose: "取回真实 umi bundle 并提取 api 前缀", reason: "同一件事换个说法",
      completion_criteria: "同上", deliverables: ["js_content", "endpoint_list"], fallback_strategy: "猜 3 次 404 就去读 CDN 列举体",
    }] });
    // 既没有新增任务，也没有把验收卡住
    expect(Object.keys(p.state.tasks)).toEqual(["T_cdn"]);
    expect(p.state.transitionErrors || []).toEqual([]);
    expect(p.state.task_aliases?.T_CDN_JS).toBe("T_cdn");
    expect(p.state.planRevision).toBe(planBefore);
    // 新声明里更完整的契约被并进老任务
    expect(p.state.tasks.T_cdn.deliverables).toEqual(["js_content", "endpoint_list"]);
    expect(p.state.tasks.T_cdn.fallback_strategy).toContain("CDN 列举体");
    expect(p.state.tasks.T_cdn.merged_from).toContain("T_CDN_JS");
    expect(p.state.planMergeLog?.at(-1)).toMatchObject({ dropped: "T_CDN_JS", into: "T_cdn" });
  });

  it("补契约不覆盖老任务已有判断", () => {
    const p = seeded({ success_criteria: "至少一个 /api/ 路径" });
    p.merge({ required_tasks: [{
      id: "T_cdn", target, purpose: "取回真实 umi bundle 并提取 API 前缀", reason: "回填契约",
      completion_criteria: "不同说法", success_criteria: "另一套判据（不该生效）", deliverables: ["js_content"],
    }] });
    expect(p.state.tasks.T_cdn.success_criteria).toBe("至少一个 /api/ 路径");
    expect(p.state.tasks.T_cdn.deliverables).toEqual(["js_content"]);
  });
});

describe("R5：声明了交付物就要逐条认领", () => {
  it("没认领交付物 → 结案被拒，并指出该认领哪些", () => {
    const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `拿到首页 ${evId}`, evidence_ids: [evId] },
    ] }, evidence);
    expect(p.state.tasks.T_cdn.status).toBe("pending");
    expect(p.state.taskOutcomeResults?.T_cdn.issues).toContainEqual(
      expect.objectContaining({ code: "CLOSURE_DELIVERABLES_UNMET", message: "closure_deliverables_unmet:T_cdn" }));
  });

  it("逐条认领后结案通过", () => {
    const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `拿到 index ${evId} 与两条 /api/ 路径`, evidence_ids: [evId],
        deliverables_met: ["js_content", "endpoint_list"] },
    ] }, evidence);
    expect(p.state.tasks.T_cdn.status).toBe("completed");
  });

  it("只认领一部分 → 指出漏了哪几条", () => {
    const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `只拿到 bundle ${evId}`, evidence_ids: [evId], deliverables_met: ["js_content"] },
    ] }, evidence);
    expect(p.state.taskOutcomeResults?.T_cdn.issues).toContainEqual(
      expect.objectContaining({ code: "CLOSURE_DELIVERABLES_UNMET", message: "closure_deliverables_partial:T_cdn" }));
  });

  /**
   * 结案死锁的根因（实跑 768287bceb5e2e01，T1_im_shell_verdict，2026-11-02）：
   * 打回时只给了 `closure_deliverables_partial:T1` 这个码，**"缺哪几项"在 hint 里被丢掉**，
   * 模型连着 4 轮瞎补，最后靠控制面强制 blocked 才收场。
   */
  it("打回时必须点名缺哪几条（不能只给一个 partial 码）", () => {
    const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `只拿到 bundle ${evId}`, evidence_ids: [evId], deliverables_met: ["js_content"] },
    ] }, evidence);
    const issue = p.state.taskOutcomeResults?.T_cdn.issues?.find(item => item.code === "CLOSURE_DELIVERABLES_UNMET");
    expect(issue?.detail).toContain("endpoint_list");
    expect(issue?.detail).toContain("deliverables_unmet");
  });

  /**
   * 逃生门：目标整个是 catch-all 404 时，「抽取前端 JS 里的接口前缀」物理上不成立。
   * 没有这个出口，诚实结案只能撒谎或者被卡死。
   */
  describe("交付物做不到时的如实申报", () => {
    it("逐条申报 item + reason → 结案放行，并记成 warning 留痕", () => {
      const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
      p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
        task_id: "T_cdn", reason: `6 条路径全 404/13B 同一指纹，站点是 catch-all 空壳 ${evId}`,
        evidence_ids: [evId],
        deliverables_met: ["js_content"],
        deliverables_unmet: [{ item: "endpoint_list", reason: "站点无任何 JS 与业务响应，接口清单不存在" }],
      }] }, evidence);
      expect(p.state.tasks.T_cdn.status).toBe("completed");
      const issues = p.state.taskOutcomeResults?.T_cdn.issues || [];
      expect(issues).toContainEqual(expect.objectContaining({ code: "CLOSURE_DELIVERABLES_WAIVED", severity: "warning" }));
      expect(p.state.deliverables_waived?.at(-1)).toMatchObject({ task_id: "T_cdn", items: ["endpoint_list"] });
      expect(p.state.tasks.T_cdn.completion_proof?.at(-1)?.deliverables_unmet).toEqual([
        { item: "endpoint_list", reason: "站点无任何 JS 与业务响应，接口清单不存在" },
      ]);
    });

    it("申报里没写理由的不算数（不许拿空申报绕过审计）", () => {
      const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
      p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
        task_id: "T_cdn", reason: `只拿到 bundle ${evId}`, evidence_ids: [evId],
        deliverables_met: ["js_content"],
        deliverables_unmet: [{ item: "endpoint_list", reason: "   " }],
      }] }, evidence);
      expect(p.state.tasks.T_cdn.status).toBe("pending");
      expect(p.state.taskOutcomeResults?.T_cdn.issues).toContainEqual(
        expect.objectContaining({ code: "CLOSURE_DELIVERABLES_UNMET", severity: "error" }));
    });

    it("一项都没认领、全靠申报豁免 → 仍然打回（不许整条任务零产出结案）", () => {
      const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
      p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
        task_id: "T_cdn", reason: `什么都拿不到 ${evId}`, evidence_ids: [evId],
        deliverables_unmet: [
          { item: "js_content", reason: "无 JS" },
          { item: "endpoint_list", reason: "无接口" },
        ],
      }] }, evidence);
      expect(p.state.tasks.T_cdn.status).toBe("pending");
      expect(p.state.taskOutcomeResults?.T_cdn.issues).toContainEqual(
        expect.objectContaining({ code: "CLOSURE_DELIVERABLES_UNMET", severity: "error" }));
    });
  });
});

describe("R4：写了结论就必须点名证据", () => {
  it("有 ev 证据但结论不引用 → 拒收", () => {
    const p = seeded();
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: "已验证完成，无风险", evidence_ids: [] },
    ] }, evidence);
    expect(p.state.taskOutcomeResults?.T_cdn.issues).toContainEqual(
      expect.objectContaining({ code: "OUTCOME_WITHOUT_EVIDENCE_REFERENCE" }));
  });

  it("结论里点名 ev-id → 通过", () => {
    const p = seeded();
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `按 ${evId} 的 200/4848B 判空壳`, evidence_ids: [evId] },
    ] }, evidence);
    expect(p.state.tasks.T_cdn.status).toBe("completed");
  });
});
describe("连续打回后的兜底（实跑 090e71cc2732165e）", () => {
  const seededWith = () => {
    const p = new BlackboxProgress();
    p.merge({
      required_tasks: [{
        id: "T_shell", target, purpose: "判定根路径是不是 catch-all 空壳并抽取接口前缀", reason: "先判兜底",
        completion_criteria: "给出 catch-all 判定", deliverables: ["render_xhr_list", "exposed_endpoint"],
      }],
    });
    return p;
  };
  const twoEvidence = [
    { id: evId, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_shell", url: `${target}a` } },
    { id: "ev-1111111111111111", kind: "tool-result", source: "http.diff", data: { ok: true, task_id: "T_shell", url: `${target}b` } },
  ];
  const submit = (p: BlackboxProgress) => p.merge({ completed_tasks: ["T_shell"], task_outcomes: [
    { task_id: "T_shell", reason: `6 条路径全 404/13B 同一指纹 ${evId}`, evidence_ids: [evId, "ev-1111111111111111"] },
  ] }, twoEvidence);

  it("打回文案点名缺项，且给出两条出路", () => {
    const p = seededWith();
    submit(p);
    const issue = p.state.taskOutcomeResults?.T_shell.issues?.find(item => item.code === "CLOSURE_DELIVERABLES_UNMET");
    expect(issue?.detail).toContain("render_xhr_list");
    expect(issue?.detail).toContain("deliverables_unmet");
    expect(p.state.taskOutcomeRejects?.T_shell).toBe(1);
  });

  it("第二次仍未认领 → 控制面代为申报未达成并放行，不再无限打回", () => {
    const p = seededWith();
    submit(p);
    expect(p.state.tasks.T_shell.status).toBe("pending");
    submit(p);
    expect(p.state.tasks.T_shell.status).toBe("completed");
    expect(p.state.taskOutcomeResults?.T_shell.issues).toContainEqual(
      expect.objectContaining({ code: "CLOSURE_DELIVERABLES_WAIVED", severity: "warning" }));
    expect(p.state.deliverables_waived?.at(-1)?.items).toEqual(["render_xhr_list", "exposed_endpoint"]);
  });

  it("证据不足 2 条时兜底不生效（不许只打一下就拿兜底结案）", () => {
    const p = seededWith();
    const single = [twoEvidence[0]!];
    const once = () => p.merge({ completed_tasks: ["T_shell"], task_outcomes: [
      { task_id: "T_shell", reason: `只打到一条 ${evId}`, evidence_ids: [evId] },
    ] }, single);
    once(); once(); once();
    expect(p.state.tasks.T_shell.status).toBe("pending");
    expect(p.state.taskOutcomeResults?.T_shell.issues).toContainEqual(
      expect.objectContaining({ code: "CLOSURE_DELIVERABLES_UNMET", severity: "error" }));
  });
});

describe("负向结论是结案，不是 blocked（第五场 b7142138263c586d）", () => {
  const evControl = "ev-2222222222222222";
  const twoEvidence = [
    { id: evId, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_cdn", url: `${target}a` } },
    { id: evControl, kind: "tool-result", source: "http.diff", data: { ok: true, task_id: "T_cdn", url: `${target}b` } },
  ];
  const reason = `verified-negative：6 条敏感路径全 404/13B 同指纹 ${evId}，与随机不存在路径对照 identical ${evControl}`;

  it("自报 verified-negative 的 blocked 归位成 completed 并留 warning 回执", () => {
    const p = seeded({ deliverables: ["js_content", "endpoint_list"] });
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [{ task_id: "T_cdn", reason, evidence_ids: [evId, evControl] }] }, twoEvidence);
    expect(p.state.tasks.T_cdn.status).toBe("completed");
    expect(String(p.state.tasks.T_cdn.outcome_reason)).toMatch(/^verified_negative:/);
    expect(p.state.taskOutcomeResults?.T_cdn).toMatchObject({ status: "applied" });
    expect(p.state.taskOutcomeResults?.T_cdn.issues).toContainEqual(
      expect.objectContaining({ code: "NEGATIVE_VERDICT_PROMOTED", severity: "warning" }));
    // 负向结论下交付物本就不存在：一并记成未达成，报告里查得到
    expect(p.state.deliverables_waived?.at(-1)).toMatchObject({ task_id: "T_cdn", items: ["js_content", "endpoint_list"] });
    expect(p.state.tasks.T_cdn.completion_proof?.at(-1)?.reason).toContain("控制面归位");
  });

  it("证据不足 2 条时照旧留 blocked（不许用一句话换结案）", () => {
    const p = seeded({ deliverables: ["js_content"] });
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `verified-negative：只打了一条 ${evId}`, evidence_ids: [evId] },
    ] }, twoEvidence);
    expect(p.state.tasks.T_cdn.status).toBe("blocked");
  });

  it("引用了账上不存在的证据 id 不生效", () => {
    const p = seeded({ deliverables: ["js_content"] });
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `verified-negative：杜撰 ${evId}、ev-9999999999999999`, evidence_ids: [evId] },
    ] }, twoEvidence);
    expect(p.state.tasks.T_cdn.status).toBe("blocked");
  });

  it("普通 blocked（缺凭证这类真没做完）保持 blocked，不被误归位", () => {
    const p = seeded({ deliverables: ["js_content"] });
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `缺 Token，无法进入业务层 ${evId} ${evControl}`, evidence_ids: [evId, evControl] },
    ] }, twoEvidence);
    expect(p.state.tasks.T_cdn.status).toBe("blocked");
    expect(p.state.deliverables_waived || []).toEqual([]);
  });
});

describe("契约不随重声明漂移（第五场 T1 被并进 3 项别人的交付物）", () => {
  it("同 id 重新声明只补空，不并集交付物", () => {
    const p = seeded({ deliverables: ["js_bundle_url", "catch_all_verdict"] });
    p.merge({ required_tasks: [{
      id: "T_cdn", target, purpose: "取回真实 umi bundle 并提取 API 前缀", reason: "重声明",
      completion_criteria: "同上", deliverables: ["js_bundle_url", "catch_all_verdict", "exposed_endpoint"],
    }] });
    expect(p.state.tasks.T_cdn.deliverables).toEqual(["js_bundle_url", "catch_all_verdict"]);
    // 于是结案时也不会被要求认领本不属于它的那一项
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [
      { task_id: "T_cdn", reason: `bundle 拿到 ${evId}`, evidence_ids: [evId],
        deliverables_met: ["js_bundle_url", "catch_all_verdict"] },
    ] }, evidence);
    expect(p.state.tasks.T_cdn.status).toBe("completed");
  });

  it("换个 id 登记同一件事时仍然并集（那是补充描述，不是漂移）", () => {
    const p = seeded({ deliverables: ["js_bundle_url"] });
    p.merge({ required_tasks: [{
      id: "T_cdn_js", target, purpose: "取回真实 umi bundle 并提取 API 前缀", reason: "细化",
      completion_criteria: "同上", deliverables: ["catch_all_verdict"],
    }] });
    expect(p.state.tasks.T_cdn.deliverables).toEqual(["js_bundle_url", "catch_all_verdict"]);
    expect(p.state.task_aliases?.T_cdn_js).toBe("T_cdn");
  });
});

describe("漏洞类打法的负向结论也要能结案（第七场 e8526ef215536256）", () => {
  const evA = "ev-aaaaaaaaaaaaaaaa";
  const evB = "ev-bbbbbbbbbbbbbbbb";
  const seededVuln = () => {
    const p = new BlackboxProgress();
    p.merge({ required_tasks: [{
      id: "T_unauth", target, purpose: "对敏感路径做未授权访问探测", reason: "根 404 不排除子路径可读",
      completion_criteria: "发现任一匿名可读端点，或一组对照证明全部 404 同指纹", playbook: "unauth_exposure",
      deliverables: ["exposed_endpoint"],
    }] });
    return p;
  };
  const ev = [
    { id: evA, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_unauth", url: `${target}actuator` } },
    { id: evB, kind: "tool-result", source: "http.diff", data: { ok: true, task_id: "T_unauth", url: `${target}zz-random` } },
  ];

  it("verified_negative + 2 条证据 → 通过漏洞谓词门（不再要 finding）", () => {
    const p = seededVuln();
    p.merge({ completed_tasks: ["T_unauth"], task_outcomes: [{
      task_id: "T_unauth", evidence_ids: [evA, evB], deliverables_met: [],
      deliverables_unmet: [{ item: "exposed_endpoint", reason: "全站 404 同指纹，无该端点" }],
      reason: `verified-negative：/actuator 与随机路径 identical ${evA} ${evB}`,
    }] }, ev);
    expect(p.state.tasks.T_unauth.status).toBe("completed");
    expect(String(p.state.tasks.T_unauth.outcome_reason)).toMatch(/^verified_negative:/);
  });

  it("只有一条证据的负向结论仍被拒（一条 404 不是整站空壳）", () => {
    const p = seededVuln();
    p.merge({ completed_tasks: ["T_unauth"], task_outcomes: [{
      task_id: "T_unauth", evidence_ids: [evA],
      deliverables_unmet: [{ item: "exposed_endpoint", reason: "全站 404 同指纹" }],
      reason: `verified-negative：只打了一条 ${evA}`,
    }] }, ev);
    expect(p.state.tasks.T_unauth.status).not.toBe("completed");
    // 两道门谁先命中都算被拦下：交付物门（1 条证据不足以支撑"全都做不到"）或 verdict 门。
    const issues = p.state.taskOutcomeResults?.T_unauth.issues || [];
    expect(issues.some(issue => ["CLOSURE_DELIVERABLES_UNMET", "COMPLETION_WITHOUT_VERDICT"].includes(issue.code))).toBe(true);
    expect(issues.every(issue => issue.severity === "error")).toBe(true);
  });

  it("正向声称完成但没给 finding 时，verdict 门照旧拦（放行只对 verified_negative 生效）", () => {
    const p = seededVuln();
    p.merge({ completed_tasks: ["T_unauth"], task_outcomes: [{
      task_id: "T_unauth", evidence_ids: [evA, evB], deliverables_met: ["exposed_endpoint"],
      reason: `打完了，看着都正常 ${evA} ${evB}`,
    }] }, ev);
    expect(p.state.tasks.T_unauth.status).not.toBe("completed");
    expect(p.state.taskOutcomeResults?.T_unauth.issues).toContainEqual(
      expect.objectContaining({ code: "COMPLETION_WITHOUT_VERDICT" }));
  });

  it("结案被打回时不留\"未达成\"账（旧实现会把 pending 任务的豁免也记账）", () => {
    const p = seededVuln();
    p.merge({ completed_tasks: ["T_unauth"], task_outcomes: [{
      task_id: "T_unauth", evidence_ids: [evA],
      reason: `verified-negative：只有一条 ${evA}`,
      deliverables_unmet: [{ item: "exposed_endpoint", reason: "全站 404 无该端点" }],
    }] }, ev);
    expect(p.state.tasks.T_unauth.status).not.toBe("completed");
    expect(p.state.deliverables_waived || []).toEqual([]);
  });
});

describe("同一任务二次结案不重复记账（b9882a565690c603 的 T1）", () => {
  const evOther = "ev-3333333333333333";
  const two = [
    { id: evId, kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_cdn", url: `${target}a` } },
    { id: evOther, kind: "tool-result", source: "recon.js_endpoints", data: { ok: true, task_id: "T_cdn", url: `${target}b` } },
  ];

  it("第二次申报换了未达成项的措辞，账本仍只有一条凭据、一条豁免", () => {
    const p = seeded({ deliverables: ["js_bundle_url", "backend_api_paths"] });
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", evidence_ids: [evId, evOther], deliverables_met: [],
      deliverables_unmet: [
        { item: "js_bundle_url", reason: "整站 404，无 bundle" },
        { item: "backend_api_paths", reason: "页面零 JS，无可提取前缀" },
      ],
      reason: `verified-negative：全站 404 同指纹 ${evId} ${evOther}`,
    }] }, two);
    expect(p.state.tasks.T_cdn.status).toBe("completed");
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", evidence_ids: [evId, evOther], deliverables_met: [],
      deliverables_unmet: [
        { item: "backend_api_paths", reason: "换了个说法再申一遍" },
        { item: "js_bundle_url", reason: "同上" },
      ],
      reason: `verified-negative：再确认一次全站 404 ${evId} ${evOther}`,
    }] }, two);
    expect(p.state.tasks.T_cdn.completion_proof).toHaveLength(1);
    expect(p.state.deliverables_waived).toEqual([{ at: expect.any(Number), task_id: "T_cdn", items: ["js_bundle_url", "backend_api_paths"] }]);
    expect(p.state.taskOutcomeResults?.T_cdn).toMatchObject({ status: "applied" });
  });

  it("但坏的重复提交仍要被拒（已完成的结论不能被洗一遍）", () => {
    const p = seeded({ deliverables: ["js_bundle_url", "backend_api_paths"] });
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", evidence_ids: [evId, evOther], deliverables_met: ["js_bundle_url", "backend_api_paths"],
      reason: `bundle 拿到 ${evId}`,
    }] }, two);
    expect(p.state.tasks.T_cdn.status).toBe("completed");
    p.merge({ completed_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", evidence_ids: [], deliverables_met: [], reason: "这次什么都没给",
    }] }, two);
    expect(p.state.taskOutcomeResults?.T_cdn).toMatchObject({ status: "rejected" });
    expect(p.state.tasks.T_cdn.status).toBe("completed");
  });
});

describe("结案引用自动回填（2026-11-07 对照会话 1dd9ded9ed239711）", () => {
  const facts = [
    { id: "ev-1111111111111111", kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_cdn", url: `${target}ecs`, status: 403 } },
    { id: "ev-2222222222222222", kind: "tool-result", source: "http.request", data: { ok: true, task_id: "T_cdn", url: `${target}ask/1`, status: 200 } },
  ];

  it("blocked 理由没点名 ev-id 时由控制面回填，不再每轮打回、不进 DLQ", () => {
    const p = seeded();
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", reason: "目标连续返回 403，鉴权门禁未通过，无法继续遍历", evidence_ids: [],
    }] }, facts);
    expect(p.state.taskOutcomeResults?.T_cdn.status).toBe("applied");
    expect(p.state.taskOutcomeResults?.T_cdn.issues[0]).toMatchObject({ code: "OUTCOME_EVIDENCE_AUTO_REPAIRED", severity: "warning" });
    expect(p.state.tasks.T_cdn.status).toBe("blocked");
    // "403" 只命中第一条证据，不该把无关的 200 一起硬凑进来。
    expect(p.state.tasks.T_cdn.outcome_evidence_ids).toEqual(["ev-1111111111111111"]);
    expect(p.state.transitionErrors.some(error => /outcome_without_evidence_reference/.test(error))).toBe(false);
    const acceptance = evaluateAcceptance(p.state, facts);
    expect(acceptance.issues.some(issue => issue.code === "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE")).toBe(false);
    // 独立审计账：seq 自增，desk 按它落 auto-repaired 事件，resume 不会重复写。
    expect(p.state.outcomeAutoRepairs?.[0]).toMatchObject({ seq: 1, task_id: "T_cdn", matched: true });
  });

  it("账本里根本没有本任务证据时不凭空造引用（无证据可引 ≠ 有证据不引）", () => {
    const p = seeded();
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", reason: "外部依赖没有回应", evidence_ids: [],
    }] }, [{ id: "ev-3333333333333333", kind: "tool-result", data: { task_id: "T_other" } }]);
    expect(p.state.tasks.T_cdn.outcome_evidence_ids).toBeUndefined();
    expect(p.state.outcomeAutoRepairs).toBeUndefined();
    expect(p.state.transitionErrors.some(error => /outcome_without_evidence_reference/.test(error))).toBe(false);
  });

  it("已有引用绝不覆盖（历史结论不可被悄悄改写）", () => {
    const p = seeded();
    p.merge({ blocked_tasks: ["T_cdn"], task_outcomes: [{
      task_id: "T_cdn", reason: `按 ${facts[0]!.id} 判定 403 门禁未过`, evidence_ids: [],
    }] }, facts);
    expect(p.state.tasks.T_cdn.outcome_evidence_ids).toEqual([facts[0]!.id]);
    expect(p.state.outcomeAutoRepairs).toBeUndefined();
  });
});

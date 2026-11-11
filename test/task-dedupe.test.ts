import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { boundedContext, checkpointView } from "../src/blackbox/context.js";
import { evaluateAcceptance } from "../src/blackbox/acceptance.js";
import { conceptKeys, pathAnchors, purposeSimilarity, samePurpose, taskFingerprint } from "../src/blackbox/task-fingerprint.js";
const PURPOSES = [
  "枚举 1-1024 端口确认暴露面",
  "检查响应头 CSP 与 HSTS 配置",
  "对比匿名与带 token 的响应差异",
  "提取前端 bundle 里的接口清单",
  "判定 WAF 是前缀级还是关键字级",
  "尝试对象存储桶列举",
  "验证 JWT 是否校验签名与过期",
  "探测 GraphQL introspection 是否开放",
  "抓取 robots.txt 与 sitemap.xml",
];


/**
 * 会话恢复两次后 pending 从 8 涨到 32 的两条真实原因，各锁一个回归。
 *
 * ① 任务簿按模型给的 id 记账（`merge` 只判 `spec.id` 是否存在），同一件事换个 id 就多一条：
 *    CORS 验证 4 份、umi bundle 9 份、API 方法面 7 份。
 * ② checkpoint 到 96KB 后 `bounded(state, 24000)` 返回 `{omitted:true}`，模型**看不到任务**
 *    → 每轮重新规划，越规划越多。
 */
describe("任务语义去重", () => {
  it("同一句话只差标点/任务 id 时不添新任务，记别名", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "T6", purpose: "验证 CORS 配置缺陷：判定 ACAO 是固定 * 还是反射外部 Origin", playbook: "unauth_exposure" },
        { id: "T6_cors_verify", purpose: "验证 CORS 配置缺陷：判定 ACAO 是固定*还是反射外部Origin", playbook: "unauth_exposure" },
        { id: "T20_cors_verify", purpose: "验证 CORS 配置缺陷：判定 ACAO 是反射外部 Origin 还是固定 *", playbook: "unauth_exposure" },
      ],
    });
    expect(Object.keys(progress.state.tasks)).toEqual(["T6"]);
    expect(progress.resolveTaskId("T20_cors_verify")).toBe("T6");
    expect(progress.pendingCount()).toBe(1);
  });

  it("换句式的同义改写（同打法 + 术语重合）也会被合并", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "T_WAF_PROBE", purpose: "判定 WAF 是关键字级还是前缀级，决定是否继续 actuator 面", playbook: "unauth_exposure" },
        { id: "T10", purpose: "判定 OPPO WAF 是前缀级封禁还是关键字级，决定后续能否用低敏感 actuator 端点取证", playbook: "unauth_exposure" },
      ],
    });
    expect(Object.keys(progress.state.tasks)).toEqual(["T_WAF_PROBE"]);
  });

  it("真正不同的任务不会被吞掉（哪怕都带 api）", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "T1", purpose: "取回 CDN 上的 umi 主 bundle 并提取后端 API 前缀", playbook: "unauth_exposure" },
        { id: "T2", purpose: "判定 /api 前缀返回 JSON 鉴权码还是 4848 外壳", playbook: "unauth_exposure" },
        { id: "T3", purpose: "复核 CORS 是否为反射而非固定 *", playbook: "unauth_exposure" },
      ],
    });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["T1", "T2", "T3"]);
  });

  it("待办上限会排队新任务并记下 deferred 回执（不再打回 transitionErrors）", () => {
    const progress = new BlackboxProgress();
    progress.taskPendingLimit = 3;
    progress.merge({
      required_tasks: [
        { id: "A", purpose: "枚举登录框是否有验证码" },
        { id: "B", purpose: "检查响应头里的 CSP 配置" },
        { id: "C", purpose: "对比匿名与带 token 的响应差异" },
      ],
    });
    expect(progress.pendingCount()).toBe(3);
    progress.merge({ required_tasks: [{ id: "D", purpose: "探测对象存储桶是否可列举" }] });
    expect(progress.state.tasks.D).toBeUndefined();
    // ② 簿满不再写 task_backlog_full：那条错误会被每轮 transition-rejected 重播，模型只能原样重发。
    expect(progress.state.transitionErrors?.some(error => error.startsWith("task_backlog_full:"))).toBe(false);
    expect(progress.state.backlog_deferred?.map(entry => String(entry.spec.id))).toEqual(["D"]);
    expect(progress.state.backlog_rejects?.at(-1)).toMatchObject({ task_id: "D", pending: 3, limit: 3, deferred: true });
  });

  it("计划历史只留 5 份，不再无限增长", () => {
    const progress = new BlackboxProgress();
    for (let index = 0; index < 9; index += 1) {
      progress.merge({ required_tasks: [{ id: `T${index}`, purpose: PURPOSES[index] }] });
    }
    expect(Object.keys(progress.state.tasks)).toHaveLength(9);
    expect(progress.state.plans!.length).toBeLessThanOrEqual(5);
  });

  it("指纹吃掉 id、时间戳、标点与大小写；术语键只留 ASCII 技术锚点", () => {
    expect(taskFingerprint("T6 验证 CORS 反射 20261027061910")).toBe(taskFingerprint("验证 CORS 反射"));
    expect(samePurpose("判定 ACAO 是固定 *", "判定ACAO是固定*")).toBe(true);
    expect(purposeSimilarity("取 umi bundle", "判定 WAF 粒度")).toBe(0);
    expect(conceptKeys("判定 OPPO WAF 是前缀级封禁还是关键字级")).toEqual(["oppo", "waf"]);
  });
});

/**
 * 2026-11-02 实跑 4f899c3af6c2ac84 的任务簿：12 条 pending 里 9 条是 3 件事的 3 份拷贝。
 * 旧的"同打法 + 术语 Jaccard ≥0.34"差一点点就放过它们：三对分别是 3/0.25、2/0.18、2/0.50。
 * 同目标（同 host）时把门槛放到 0.15 并要求 ≥2 个术语锚点，正好覆盖这三对；
 * 而真正的不同端点（IDOR 的 /search 与 /getAppConfig.json）由路径互斥直接否决。
 */
describe("同目标同义任务（真实会话复现）", () => {
  const host = "https://m.ctrip.com";
  const cases: Array<[string, string, string, string, string]> = [
    ["spa", "T1_shell_recon", "SPA 外壳逆向：取外壳 HTML、script src 与 bundle 中的 baseURL / /api 前缀，产出可打的接口清单",
      "T1", "SPA 外壳逆向：从 /html5/ 外壳与其引用的 JS bundle 中抠出后端真实接口前缀（restapi / soa2），产出接口清单"],
    ["unauth", "T2_sensitive_unauth_probe", "未授权访问/信息泄露探测：对 swagger、actuator、.env、.git、robots.txt、graphql 等敏感路径做匿名基线，并与带 Cookie 变体做对照",
      "T2_unauth_probe", "未授权访问与信息泄露验证：对敏感/标准路径（robots.txt、sitemap.xml、.well-known、api-docs、actuator 等）做匿名探测，并用 CORS 反射对照判断配置缺陷"],
    ["route", "T3_restapi_route_enum", "枚举 /restapi/ 下的 soa2 网关路由，建立真实可打 JSON 接口候选清单",
      "T_SOA2_ROUTE_PROBE", "对 /restapi/soa2/ 网关做匿名可达性与真实 appid 的三态分层对照，确认它到底是统一 404 信封还是真实路由"],
  ];

  it.each(cases)("%s：同 host + 同打法的改名任务被合并", (_name, keptId, keptPurpose, droppedId, droppedPurpose) => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: keptId, target: host, purpose: keptPurpose, playbook: "unauth_exposure" },
        { id: droppedId, target: host, purpose: droppedPurpose, playbook: "unauth_exposure" },
      ],
    });
    expect(Object.keys(progress.state.tasks)).toEqual([keptId]);
    expect(progress.resolveTaskId(droppedId)).toBe(keptId);
  });

  it("不同 host 的同一句话是两件活，不合并", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "A", target: "https://shop.example.com", purpose: "敏感路径字典探测：robots.txt / .env / actuator", playbook: "unauth_exposure" },
        { id: "B", target: "https://admin.example.com", purpose: "敏感路径字典探测：robots.txt / .env / actuator", playbook: "unauth_exposure" },
      ],
    });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["A", "B"]);
  });

  it("点名不同端点的任务即使措辞几乎相同也不合并（IDOR 两条）", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "H1", target: host, playbook: "unauth_exposure", purpose: "验证假设 idor:ep:m.ctrip.com/restapi/soa2/{id}/search：替换 id 后与自身 baseline 对照，给 verdict" },
        { id: "H2", target: host, playbook: "unauth_exposure", purpose: "验证假设 idor:ep:m.ctrip.com/restapi/soa2/{id}/getAppConfig.json：替换 id 后与自身 baseline 对照，给 verdict" },
      ],
    });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["H1", "H2"]);
  });
});

/**
 * 实跑 768287bceb5e2e01（im.ctrip.com，2026-11-02）暴露的漏判。
 *
 * 那一场里"判定这台主机是不是 catch-all 空壳"被登记了 3 次：
 *   T1_im_shell_verdict (spa_reverse) → 烧 9 轮、4 次结案被拒、被控制面强制 blocked
 *   T1_im_shell         (spa_reverse) → 同一件事，还 pending，结案后要再烧一遍
 *   T1-im-baseline      (无 playbook)  → 同一件事，且因为没 playbook 永远不参与判重
 * 两条独立的漏判路径：① 长句把 bigram Jaccard 稀释到 0.13（阈值 0.34）；
 * ② `!samePlaybook → return false` 把"打法没写"当成"打法不同"，直接放弃同目标分支。
 */
describe("缺 playbook 与长句稀释（实跑 768287bceb5e2e01 复现）", () => {
  const shellHost = "https://im.ctrip.com/";
  const shellA = "判定 im.ctrip.com 是真应用外壳还是纯 404 catch-all 节点，并抽取任何可用的脚本/接口前缀";
  const shellB = "判定 im.ctrip.com 的外壳性质：是 SPA/静态 404 兜底、还是 IM 网关壳；抽取前端 JS 中的 baseURL、/api 前缀、WebSo";
  const shellC = "判定 im.ctrip.com 的承载架构：是 catch-all 404 兜底、SPA 外壳，还是 IM 网关（期望特定路径/前缀才返回业务响应）。";

  it("同一件事换了句式（原始 bigram 只有 0.20）：靠剥 host 后的内容相似度合并", () => {
    // 旧判据：Jaccard 0.202 < 0.6，术语 1/0.13 < 0.34，同目标分支要求术语 ≥2 → 全部落空。
    expect(purposeSimilarity(shellA, shellB)).toBeLessThan(0.34);
    expect(samePurpose(shellA, shellB, true, true)).toBe(true);
  });

  it("没写 playbook 不等于换了打法：同目标仍然要判重", () => {
    expect(samePurpose(shellA, shellC, false, true)).toBe(true);
    expect(samePurpose(shellB, shellC, false, true)).toBe(true);
  });

  it("合并后任务簿里只剩一条，焦点不会为同一件事烧第二遍", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "T1_im_shell_verdict", target: shellHost, purpose: shellA, playbook: "spa_reverse" },
        { id: "T1_im_shell", target: shellHost, purpose: shellB, playbook: "spa_reverse" },
        { id: "T1-im-baseline", target: shellHost, purpose: shellC },
      ],
    });
    expect(Object.keys(progress.state.tasks)).toEqual(["T1_im_shell_verdict"]);
    expect(progress.resolveTaskId("T1-im-baseline")).toBe("T1_im_shell_verdict");
  });

  it("同 host 但确实是两件活的不许合并（CORS 反射 vs .env 泄露）", () => {
    // 剥 host 后只剩 0.033：共享的"对 X 做…探测"是模板语言，不是同一件事。
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "C1", target: shellHost, playbook: "unauth_exposure", purpose: "对 im.ctrip.com 做 CORS 反射验证，看 Access-Control-Allow-Origin 是否回显外部 Origin" },
        { id: "C2", target: shellHost, playbook: "unauth_exposure", purpose: "对 im.ctrip.com 做 .env 泄露探测，看敏感配置文件是否可匿名读取" },
        { id: "C3", target: shellHost, playbook: "unauth_exposure", purpose: "对 im.ctrip.com 做 WebSocket 握手探测，确认网关是否裸露" },
      ],
    });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["C1", "C2", "C3"]);
  });

  /**
   * 明确的打法冲突是否决项：同目标的并行验证面常共享模板措辞
   * （控制面注入的 host_header / open_redirect / takeover 三条都提 http.diff）。
   */
  it("同目标、同端点但打法明确不同 → 不合并", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "H", target: shellHost, playbook: "unauth_exposure",
          purpose: "发伪造 Host / X-Forwarded-Host 头的请求，并用 http.diff 对比默认 Host 与伪造 Host 的 Location 差异" },
        { id: "R", target: shellHost, playbook: "logic",
          purpose: "在跳转参数上试 //evil.example 与 ?next=http://evil.example，并用 http.diff 对比带/不带恶意参数的 Location" },
      ],
    });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["H", "R"]);
  });

  /** 端点级否决：同一 host 下目的地址不同（/p0 与 /p1），文本再像也是两件活。 */
  it("同 host 不同端点 → 不合并", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: Array.from({ length: 3 }, (_, index) => ({
        id: `T_${index}`, target: `https://im.ctrip.com/p${index}`,
        purpose: `第 ${index} 条独立验证面：编号 ${index}`,
      })),
    });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["T_0", "T_1", "T_2"]);
  });
});

describe("任务簿上限的回执与验收影响", () => {
  it("排队会留下带任务名的回执，模型下一轮能看到该干什么", () => {
    const progress = new BlackboxProgress();
    progress.taskPendingLimit = 1;
    progress.state.task_pending_limit = 1;
    progress.merge({ required_tasks: [{ id: "A", purpose: "枚举登录框是否有验证码" }] });
    progress.merge({ required_tasks: [{ id: "B", purpose: "探测对象存储桶是否可列举" }] });
    expect(progress.state.tasks.B).toBeUndefined();
    expect(progress.state.backlog_rejects?.at(-1)).toMatchObject({ task_id: "B", pending: 1, limit: 1 });
    const view = checkpointView(structuredClone(progress.state));
    expect(view.task_backlog).toMatchObject({ pending: 1, limit: 1 });
    const rejects = view.backlog_rejects as Array<{ task_id: string; hint: string }>;
    expect(rejects[0]!.task_id).toBe("B");
    expect(rejects[0]!.hint).toContain("结案");
  });

  it("簿满排队不会给验收留任何残留 issue", () => {
    const progress = new BlackboxProgress();
    progress.taskPendingLimit = 1;
    progress.merge({ required_tasks: [{ id: "A", purpose: "枚举登录框是否有验证码" }] });
    progress.merge({ required_tasks: [{ id: "B", purpose: "探测对象存储桶是否可列举" }] });
    // ② 以前这里会多出一条 task_backlog_full warning（且旧会话里永不清除）；现在只进 deferred 队列。
    expect(progress.state.backlog_deferred?.map(entry => String(entry.spec.id))).toEqual(["B"]);
    // 把唯一的待办结案，验收不该因为"排队过一条新任务"而永远 ready 不了。
    progress.state.tasks.A = { status: "blocked", reason: "目标无此入口", outcome_reason: "三次探测均 404，无验证码面" };
    const acceptance = evaluateAcceptance(progress.state, []);
    expect(acceptance.issues.some(issue => issue.code === "task_backlog_full")).toBe(false);
    expect(acceptance.blocking_error_count).toBe(0);
    // 腾出空位的下一轮，deferred 按 FIFO 自动补入，不需要模型换 id 重发。
    progress.merge({});
    expect(progress.state.tasks.B?.status).toBe("pending");
    expect(progress.state.backlog_deferred).toEqual([]);
  });
});

describe("上下文里的账本投影", () => {
  const huge = () => {
    const progress = new BlackboxProgress();
    for (let index = 0; index < 40; index += 1) {
      progress.state.tasks[`T${index}`] = {
        status: "pending",
        purpose: `任务 ${index} 的说明文字`.padEnd(400, "描述"),
        reason: "x".repeat(200),
        completion_criteria: "y".repeat(200),
        target: "https://gray-push-intl.oppo.com/api/user/info",
      };
    }
    progress.state.plans = Array.from({ length: 19 }, (_, index) => ({ revision: index + 1, created_at: index, task_ids: Object.keys(progress.state.tasks) }));
    progress.state.actions = Object.fromEntries(Array.from({ length: 60 }, (_, index) => [`k${index}`, { attempts: 1, failures: 0, unchanged: 0, inFlight: false, fingerprint: "f".repeat(64) }]));
    progress.state.retrievedEvidence = Array.from({ length: 20 }, (_, index) => ({ id: `ev-${index}`, kind: "tool-result", source: "http.request", summary: "s".repeat(400) }));
    return progress.state;
  };

  it("状态 96KB 时账本仍然可见（不再被整段省略）", () => {
    const state = huge();
    const session = { id: "s1", target: "https://gray-push-intl.oppo.com/", status: "paused", phase: "awaiting_operator", checkpoint: state, evidence: [], events: [] };
    const context = boundedContext(session, {});
    const view = context.checkpoint as Record<string, unknown>;
    expect(JSON.stringify(state).length).toBeGreaterThan(24000);
    expect(view.omitted).toBeUndefined();
    expect(Object.keys(view.tasks as Record<string, unknown>)).toHaveLength(40);
    expect(JSON.stringify(context.checkpoint).length).toBeLessThan(24000);
  });
});

/**
 * 实跑 92d45f2f15f98e01（2026-11-02）：两条"敏感路径探测"留了下来——
 * T3 写了 `swagger/api-docs/actuator/.git/.env/druid/nacos/graphql` 这一串关键词，
 * 锚点提取器把整串斜杠当成了**一个深路径**，于是判成"点名了不同端点"，合并被否决。
 * 斜杠分隔的清单不是路径。
 */
describe("斜杠分隔的关键词清单不是路径锚点", () => {
  const host = "https://im.ctrip.com/";
  it("关键词清单不产生锚点", () => {
    expect(pathAnchors("敏感路径与目录发现：swagger/api-docs/actuator/.git/.env/druid/nacos/graphql 等")).toEqual([]);
  });

  it("真路径仍然认（前面是主机名 / 前面是空白）", () => {
    expect(pathAnchors("验证 idor:ep:m.ctrip.com/restapi/soa2/{id}/search 的越权")).toEqual(["/restapi/soa2/{id}/search"]);
    expect(pathAnchors("对 /restapi/soa2/getAppConfig.json 做匿名基线")).toEqual(["/restapi/soa2/getappconfig.json"]);
  });

  it("两条同义的敏感路径探测会被合并", () => {
    const progress = new BlackboxProgress();
    progress.merge({
      required_tasks: [
        { id: "T3", target: host, playbook: "unauth_exposure",
          purpose: "敏感路径与目录发现：swagger/api-docs/actuator/.git/.env/druid/nacos/graphql 等未授权信息泄露面，以及 IM 常见前缀（/webapp/、/im/、/api/、/msg/、/socket/）" },
        { id: "T4", target: host, playbook: "unauth_exposure",
          purpose: "敏感路径未授权访问与信息泄露排查（swagger/actuator/.env/api-docs 等）" },
      ],
    });
    expect(Object.keys(progress.state.tasks)).toEqual(["T3"]);
  });
});

/**
 * 第七场（7fbbc513e18b66b4）的 6 条任务里，T1 与 T1_im_baseline_catchall 是同一件事：
 * 都是"建根路径基线 + 用随机路径对照判 catch-all"。差别只在打法标签（unauth_exposure vs
 * spa_reverse）——那是模型自己写的，噪声很大。文本指标到顶也不够（sim 0.17、key 1/0.125、
 * content 18/0.189），只有交付物说得很清楚：两条都写了 catch_all_verdict（归一化后同名）。
 * 但并行验证面（host_header / open_redirect / takeover）共享模板措辞且**不写交付物**，
 * 所以"交付物重合"必须是唯一逃逸门，且通用交付物名不算数。
 */
describe("打法标签互相矛盾时，用具体交付物判断是不是同一件活", () => {
  const target = "https://im.ctrip.com/";
  const baseline = {
    id: "T1", target, playbook: "unauth_exposure",
    purpose: "建立 im.ctrip.com 响应基线并判定 404 是否 catch-all，提取网关/框架指纹（Server、X-Powered-By、错误信封）",
    reason: "先确认外壳形态", completion_criteria: "给出基线与判定",
    deliverables: ["baseline_headers", "catchall_verdict", "tech_fingerprint"],
  };

  it("同目标 + 打法不同但共享具体交付物 → 合并", () => {
    const progress = new BlackboxProgress();
    progress.merge({ required_tasks: [baseline] });
    progress.merge({ required_tasks: [{
      id: "T1_im_baseline_catchall", target, playbook: "spa_reverse",
      purpose: "建立根路径基线指纹（status/headers/bytes/body_sha256），并用随机不存在路径做对照，判定 404 是 catch-all 兜底还是路径级真实 404",
      reason: "换个打法再记一遍", completion_criteria: "给出基线与判定",
      deliverables: ["baseline_fingerprint", "catch_all_verdict"],
    }] });
    expect(Object.keys(progress.state.tasks)).toEqual(["T1"]);
    expect(progress.resolveTaskId("T1_im_baseline_catchall")).toBe("T1");
  });

  it("只共享通用交付物（endpoint_list）不合并：一个是横向铺面，一个是本体路径发现", () => {
    const progress = new BlackboxProgress();
    progress.merge({ required_tasks: [{
      id: "T3", target, playbook: "spa_reverse",
      purpose: "按证书 SAN 横向铺面：探活同族 IM 域名并抠出各自可访问的入口、文档与前端接口，作为 im.ctrip.com 的后备攻击面",
      reason: "本体挡住就换战场", completion_criteria: "列出同族入口",
      deliverables: ["host_list", "host_fingerprints", "endpoint_list"],
    }] });
    progress.merge({ required_tasks: [{
      id: "T2_im_surface_discovery", target, playbook: "unauth_exposure",
      purpose: "用被动历史 URL + 内容发现 + JS 端点抽取把 im.ctrip.com 从 404 外壳翻译成真实路径/接口清单",
      reason: "外壳挡住了路径", completion_criteria: "路径清单",
      deliverables: ["endpoint_list", "historical_urls", "js_content"],
    }] });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["T2_im_surface_discovery", "T3"]);
  });

  it("并行验证面（不写交付物、共享 http.diff 措辞）仍不许合并", () => {
    const progress = new BlackboxProgress();
    const host = "shop.example.test";
    progress.merge({ required_tasks: [{
      id: "host_header_injection_1", target: `https://${host}/`, playbook: "unauth_exposure",
      purpose: `对 ${host} 发伪造 Host / X-Forwarded-Host / X-Forwarded-For 头的请求，并用 http.diff 对比默认 Host 与伪造 Host 的 Location/正文差异`,
      reason: "统一跳转", completion_criteria: "http.diff 证据",
    }] });
    progress.merge({ required_tasks: [{
      id: "open_redirect_1", target: `https://${host}/`, playbook: "logic",
      purpose: "在跳转参数上试 //evil.example、?next=http://evil.example，并用 http.diff 对比带/不带恶意参数的 Location",
      reason: "统一跳转", completion_criteria: "http.diff 证据",
    }] });
    expect(Object.keys(progress.state.tasks).sort()).toEqual(["host_header_injection_1", "open_redirect_1"]);
  });
});

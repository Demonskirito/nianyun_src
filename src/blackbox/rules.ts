import { createHash } from "node:crypto";

export type BlackboxRules = {
  version: number;
  /**
   * time_sec 只算"调度时间"（LLM 思考 + 决策 + 记账），工具执行耗时不计入；
   * wall_clock_sec 是整次 run 的墙钟上限，防止单个卡死的 LLM 调用把容器挂住。
   */
  budgets: { time_sec: number; wall_clock_sec: number; tool_calls: number; agent_turns: number; tokens: number; cost: number; retries: number };
  /** 按工具加权计费：http.request=1，nuclei/sqlmap/katana=5。缺省的工具按 1 算。 */
  tool_weights: Record<string, number>;
  loop_control: { task_retry_limit: number; repeat_limit: number; stall_batch_limit: number; stage_timeout_sec: number; stage_rollover_limit: number;
    /** 参数熔断：同一路径调用 N 次、参数变了但响应指纹 <= M 种、且至少 K 种不同参数组合 → 判定参数面已榨干。 */
    param_stall_calls: number; param_stall_queries: number; /** 路径 id 变体数（RESTful 遍历）达到多少算“参数面在变”。 */ param_stall_variants: number; /** 每 N 次调用必须产出 1 个新指纹，否则算榨干。 */ param_stall_ratio: number;
    /** 待处置建议上限：超过就把最旧的 pending 归档成 superseded。 */
    advice_pending_limit: number;
    /** 待办任务上限：任务簿塞满后拒收新任务，逼 agent 先收口（0 = 不限）。 */
    task_pending_limit: number };
  /** 焦点锁：一轮只准推进一个任务（见 focus.ts）。 */
  focus_lock: {
    /** 开关：false 退回"一轮可打多个任务"的旧行为（仅用于对照/排障）。 */
    on: boolean;
    reject_unassigned: boolean;
    /** 单任务微观预算：超过就让模型强制收口（0 = 不限）。 */
    max_turns_per_task: number;
    /** 战术点数上限（按工具成本算，见 tool-cost.ts；0 = 不限）。 */
    max_tp_per_task: number;
    /** 连续多少轮没有新证据/节点状态迁移就判收益递减。 */
    stall_rounds: number;
    /** 整场会话共享的申诉池（不再按任务发，见 focus-budget.ts: spendAppeal）。 */
    appeal_pool: number;
    /** 允许申诉的拓扑势能门槛：任务的势能必须 <= 该值（越小越接近目标）。 */
    appeal_potential_max: number;
    /** 会话级熔断：累计收口多少次就转人工/深交互。 */
    max_session_convergences: number;
    /**
     * 焦点溢出：整批请求都被焦点锁拒收时，允许放行**被拒最多的那一个任务**的最多 N 条请求（默认 2，0 = 关闭）。
     *
     * 2026-11-02 三场实跑（6ee79b87a797904f / 8a2b134101b62649 / f77278fb6b829eda）的共同病灶：
     * 模型每轮把 4-5 个任务的计划一次性铺开，而焦点锁只放行一个任务 → 整批全废 → 要么 stalled，
     * 要么靠申诉在任务间反复交接（3 次 handoff、9 次 focus-lock，10/40 次调用就收场）。
     * 焦点锁的目的是"深度"，不是"每轮只能有一个任务存在"；给溢出一条窄通道，
     * 让模型的多任务计划至少部分落地，同时焦点任务仍拿到其余全部算力。
     */
    overflow_per_round: number;
  };
  request: {
    methods: string[];
    max_redirects: number;
    max_timeout_ms: number;
    max_body_bytes: number;
    max_request_body_bytes: number;
    max_output_bytes: number;
  };
  tools: Record<string, { allow_credential_attack?: boolean; allow_active_scan?: boolean }>;
  /** 鉴权墙：同一主机连续多少个不同入口被同样拒绝就判墙。 */
  auth_wall: {
    streak_limit: number;
    codes: string[];
    /** 墙生效期间仍然放行的敏感路径（子串匹配）：未授权入口本来就该在墙内继续试。 */
    safe_paths: string[];
    /** 是否允许 unauth_exposure 打法的任务在墙内继续请求。 */
    allow_unauth_playbook: boolean;
    /** 是否允许模型用 input.bypass_auth_wall=true 主动声明绕过。 */
    allow_bypass: boolean;
  };
  evidence: { require_ids: boolean; save_raw_results: boolean };
  report: { require_task_outcomes: boolean; distinguish_incomplete: boolean };
  text: Record<string, string>;
};

export const BLACKBOX_RULE_SECTIONS = [
  "version", "budgets", "tool_weights", "loop_control", "request", "auth_wall", "focus_lock", "tools", "evidence", "report", "text",
] as const;

/** 墙生效期间仍然放行的敏感路径：这些正是"未授权访问"该验的东西。 */
export const DEFAULT_AUTH_WALL_SAFE_PATHS = [
  ".env", ".git/", ".svn/", "/swagger", "/v2/api-docs", "/v3/api-docs", "/openapi", "/api-docs",
  "/actuator", "/druid", "/nacos", "/graphql", "/robots.txt", "/sitemap.xml", "/phpinfo",
  "/debug", "/health", "/metrics", "/console",
];

export const DEFAULT_BLACKBOX_RULES: BlackboxRules = {
  version: 1,
  // time_sec 是调度预算（思考/决策），wall_clock_sec 是整次 run 的墙钟上限。
  // 分开以后，nuclei/sqlmap 跑 300 秒不会把"思考时间"烧掉，但也不允许 run 无限挂住。
  budgets: { time_sec: 900, wall_clock_sec: 1800, tool_calls: 120, agent_turns: 24, tokens: 0, cost: 0, retries: 5 },
  // 权重计费：廉价请求 1，扫描器 3–5。默认值见 weights.ts。
  tool_weights: {},
  // The stage now matches budgets.time_sec: a single slow tool (nuclei, katana) must not end
  // a healthy run before its own budget is spent.
  // stage_rollover_limit: how many extra stages one run may open after a stage runs out of time.
  // 0 keeps the old "one stage per run" behaviour; >0 lets a run keep working until its own budget ends.
  loop_control: { task_retry_limit: 2, repeat_limit: 2, stall_batch_limit: 3, stage_timeout_sec: 900, stage_rollover_limit: 4,
    param_stall_calls: 5, param_stall_queries: 3, param_stall_variants: 3, param_stall_ratio: 3, advice_pending_limit: 6,
    // 2026-10-31：12 条上限在"假设驱动"开启后过窄（假设任务会占 3 条），提到 16。
    // 2026-11-02 回撤到 10：16 条从未被当作"预算"用——实测 4f899c3af6c2ac84 24 轮新增 5 组任务、
    // 只结案 2 条，12 条 pending 里 9 条是 3 件事的重复登记（判重已修，见 task-fingerprint.ts）。
    // 上限的作用不是"允许多少"，而是"什么时候必须收口"；10 与假设任务的入簿阈值一致。
    task_pending_limit: 10 },
  /**
   * 2026-11-10：`max_session_convergences` 5 → 0（不限），`stall_rounds` 3 → 5。
   *
   * 现场：会话 `1dd9ded9ed239711` 累计 6 次收口后进入宏观熔断，之后每轮只投
   * "收口级取证"，`graph_drift` 建议的 266 条面一条都不碰（3 轮 12 分钟
   * `unprobed_ready` 纹丝不动）。整场熔断是所有限制的公约数：前面各层再宽松，
   * 这里一关就全白费，而且它是**不可逆**的——计数只涨不落，之后 resume 也回不去。
   *
   * 0 在消费端表示"不限"（`limits.max_session_convergences > 0 &&` 才拦）。
   * `stall_rounds` 3 的问题不是"太严"，是**把否定结果当成无进展**：探测类工作
   * 天然大量产出"这条路不通"，3 轮就收口会把正常排除工作切碎。
   */
  focus_lock: { on: true, reject_unassigned: false, max_turns_per_task: 8, max_tp_per_task: 50, stall_rounds: 5, appeal_pool: 3, appeal_potential_max: 6, max_session_convergences: 0, overflow_per_round: 2 },
  request: {
    methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    max_redirects: 5,
    max_timeout_ms: 60000,
    max_body_bytes: 262144,
    max_request_body_bytes: 5242880,
    max_output_bytes: 2097152,
  },
  // Every registered tool is always callable. This section only carries per-tool risk
  // switches that are off by default; today that is credential attacks (sqlmap/wpscan).
  tools: {
    "recon.ports": {},
    "recon.content_discovery": {},
    "recon.nuclei": {},
    "recon.interactsh": {},
    "recon.parameters": {},
    "recon.js_endpoints": {},
    "recon.tls": {},
    "recon.api_routes": {},
    "recon.xss": {},
    "recon.sql": {},
    "recon.jwt": {},
    "recon.graphql": {},
    "recon.cms": {},
    "recon.secrets": {},
    "recon.sast": {},
    "burp.scan": { allow_active_scan: true },
  },
  auth_wall: {
    streak_limit: 3,
    codes: ["10403", "10401", "10402", "401"],
    safe_paths: [...DEFAULT_AUTH_WALL_SAFE_PATHS],
    allow_unauth_playbook: true,
    allow_bypass: true,
  },
  evidence: { require_ids: true, save_raw_results: true },
  report: { require_task_outcomes: true, distinguish_incomplete: true },
  text: {
    "任务与预算": "按资产规模拆分任务；持续执行直到必需任务完成、预算耗尽或安全停止。预算未耗尽时不要提前收尾。",
    "任务状态与恢复": "任务必须有领取、执行、完成、失败或受阻状态；每批保存检查点，恢复时只做未完成或有新依据的任务。",
    "重复与停滞": "相同目标和参数且没有新信息的动作不重复；停滞时更换打法，而不是重试同一条请求。",
    "授权与请求": "目标均在授权范围内；GET/HEAD/POST/PUT/PATCH/DELETE 全部可用，写操作在 reason 写明预期影响并只做一次，优先可逆动作。",
    "速率与并发": "工具按批次顺序执行；遇到 429/503 先降速再换打法；不为了消耗预算制造无价值请求。",
    "漏洞检测与验证": "先立可证伪假设再选工具。扫描器命中只作线索；确认需要可复现的请求与响应、证据 ID 和排除误报的依据，无回显一律走带外验证。",
    "证据与发现": "发现必须引用该目标成功的工具结果和证据 ID，并区分 confirmed/likely/unconfirmed。",
    "主 Agent 与 Observer": "主 Agent 推进任务并维护证据账本；Observer 只读审阅、提出补证建议，并可在证据充分时把发现置为 confirmed 或 rejected。",
    "完成判定": "completed 的唯一判据是 context.vuln_gaps 为空——即该任务 playbook 的确认谓词（vuln-predicates.ts）逐条成立；谓词未登记的打法以 confirm.evidence 全拿到为准。401/403/10403/未登录/token 失效记为 blocked（outcome_reason=blocked_by_auth），不算完成；只带拒绝证据的结案会被调度器拒绝并转为 blocked，交 Observer 复核。例外：一致性类打法（unauth_exposure / auth_token / jwt_auth / idor）拿到 ≥2 条一致拒绝即为 verified_negative，可结案。",
    "鉴权墙": "同一主机连续多个不同入口返回同一鉴权码即判定鉴权墙：停止遍历被拒前缀，改找登录/Token（jwt_auth）或未授权入口（unauth_exposure）；墙生效期间同前缀的无凭证请求会被执行器直接拦下（auth_wall_requires_token）。**例外**：unauth_exposure 打法的任务、任务目的写明未授权/匿名/越权/鉴权验证的自由文本任务、命中敏感路径字典（.env/.git/swagger/actuator/druid/nacos/graphql 等）的请求、以及显式标注 input.bypass_auth_wall=true 的请求仍然放行——墙是防复读机，不是禁止做未授权验证。",
    "凭据自检": "撞到 401/403/412 或身份墙时，**先怀疑自己的凭证，再怀疑目标**。调度器会做「带凭证 vs 匿名」的对照（结论进 context.seed_health），三种结论的处置完全不同：① seed_tainted（带凭证被拦、匿名正常）——这堵墙是**我方 Cookie 造成**的，不要跑 WAF 阶梯、不要换编码/换头/换路径、更不要把这个 host 记成封锁；已污染项会被自动剔除并从种子文件移除，直接用清理后的会话罐打原接口，或显式 anonymous:true 取未授权基线。② seed_stale（两边结果一样/都跳登录）——种子在这台主机上根本没生效，这种 401/403 **不能**当作未授权证据，先换种子。③ host_walled（两边都被拦）——这才是目标自身的墙，按 WAF/鉴权墙处理。没有 seed_health 结论时，调度器会把「整机拉黑」的门槛翻倍（3→6、兜底 6→12）：先取一次对照，再决定要不要放弃这台主机。",
    "WAF 绕过": "看到拦截**先判墙的性质**，再决定要不要绕（判错性质比不绕更浪费时间）：① 正文含 proxy_authentication_required / client attestation payload / cf_chl / captcha / 滑块 / 瑞数 rsdynamic → **身份墙**：它要的是「证明你是谁」而不是「改你的 payload」，编码/参数/路径/方法/头/报文/夹带 7 档对它全部无效（判定输入里没有 payload），别跑阶梯，改去拿合法 Cookie/Token 或找不经过这层网关的边缘资产；并且**绝不**按挑战页要求提交 principal/username/email/provenance/delegation——那是钓身份，提交等于把资产身份交出去。② 同一路径连打两次指纹不一致（status+bytes+sha 任一不同）→ 风控抖动或限流，不是墙，别绕也别判死，降频重试（间隔 ≥30s，≤3 次）。③ 其余都按**规则墙**处理，可绕：412/418/1020 或阻断页（securityfs/waf、Cloudflare cf-error、Akamai Reference、Access Denied、您的访问被阻断、非法请求）是可绕的规则墙，不是终点：**先查战例库再思考**——context.waf_ledger 里同一厂商或同一拦截指纹的打穿记录，第一条变体原样复刻一次（http.diff 与 baseline 对照），成功就把这条变体带进业务验证并回报 waf_bypasses；复刻失败换下一条，全部失效才重新设计。重新设计时先取拦截基线指纹（同一路径打两次，status+bytes+body_sha256 三者一致才算 WAF，不一致是限流或静态兜底），再按 waf_bypass 阶梯逐档试——① 编码（双重/三重 URL 编码、Unicode 全角、HTML 实体、大小写混写、关键字双写、注释 /**/ 插入、空白符 %09/%0a/%0c/%a0、等价函数替换）；② 参数污染（同名参数双写让 WAF 只查第一个、堆 100+ 无害参数把真载荷挤到末尾、参数顺序调换）；③ 路径规范化（//、%2f、%252f、;、..;/、%00、末尾斜杠、大小写）；④ 方法转换（GET↔POST、PUT/OPTIONS、X-HTTP-Method-Override；非常用动词只能走 burp.send 原始报文，http.request 的 method 是枚举）；⑤ 白名单伪装（UA 伪装 Googlebot/Baiduspider、X-Forwarded-For/X-Real-IP/X-Client-IP/X-Originating-IP=127.0.0.1、X-Original-URL/X-Rewrite-URL、Referer 指向同站内网页）；⑥ 报文层（burp.send 原始报文自定义 Host、重复 Content-Length、chunked 分块、超长前置垃圾+尾部载荷，很多 WAF 只检前 N KB）；⑦ 负载夹带（burp.send_batch 正常流量夹异常包，≤20 条并降速，不做压测）。每一档都要 baseline/hit 对照（http.diff），阶梯没跑满或没有对照不得把任务记为 blocked；只有各档返回同一拦截指纹（三项一致）才判规则级封锁并转 lateral_escape；出现 429/人机挑战（Cloudflare JS challenge、滑块、captcha）立即停手，避免拉黑出口 IP。打穿后必须回报 waf_bypasses（vendor/dimension/tactic/payload/host/evidence_id），战例库与控制台 WAF 战例库页同源。字典/爬虫 0 产出时先判「是没路径还是整片被墙」：调度器会补两枪根路径（拦截码 + 两次 status/bytes/sha 一致 + 阻断字样或已知厂商或战例库同签名 = 墙，直接立 waf_bypass；否则记 waf-probe-negative，说明这里真没路径，换打法而不是换字典）。",
    "预算与降级": "预算是两类：time_sec 只算调度时间（思考与决策），工具执行单独计时并受 wall_clock_sec 墙钟上限约束；工具调用按权重计费（http.request=1，nuclei/sqlmap/katana=5，扫描类 3）。墙钟或权重放不下当前打法的完整时间盒时，打法自动降级为快速模式：只做轻量步骤（算术/引号/时间盲注/结构化 diff/OAST），跳过 sqlmap、nuclei、katana 等重型扫描器；降级后以轻量步骤的证据为确认依据，重型步骤留到预算充足时再补。",
    "工具与执行": "所有已注册工具都可直接调用，没有逐动作人工审批，也没有整体禁用某个工具的总开关；只有凭据爆破与主动扫描两个风险开关默认关闭。工具清单里没有的能力（反连平台拿不到、缺某个专用扫描器/伪造器、缺云元数据探测）不要用 http.request 硬凑，也不要凭空发明工具名：写 tool_gaps:[{need,why,tool?,alternative?,blocked_task?}] 上报，同一缺口只报一次（context.tool_gaps 里已有的不重复），能兜底就先用 exec.python/exec.bash/fs.* 把活干完并说明「有 X 能省 N 轮」。desk 会把它与 74 项注册表对账（不存在的工具标记 missing）并落成 tool-gap 事件供操作员补工具/补配置。",
    "验收与报告": "报告区分已完成、失败、受阻和未执行；未完成的任务不得表述为已验证安全。",
    "JSON 输出协议": "输出必须符合主 Agent / Observer 的 JSON 协议。tool_requests[].reason 写「为什么发这一发」，task_outcomes[].reason 写结案依据；input 里只放执行参数，不要写 reason/note/comment/why——这些注释键会被摘掉、不下传执行器，只回一条教学回执。结案理由必须点名证据 ID（ev-…）；忘了写时控制面会从该任务的账本自动回填，并在 auto-repaired 事件里留痕：命中关键词才按相关项回填，否则只作启发式记账补齐（rule=auto_backfill:heuristic_needs_review），报告复核时需人工确认。",
  },
};

/** Tools whose per-tool risk switches (credential attacks) the document may change. */
export const BLACKBOX_RULE_TOOL_NAMES: string[] = Object.keys(DEFAULT_BLACKBOX_RULES.tools);

export type BlackboxRulesDiagnostics = {
  /** 已废弃但仍出现在文档里的键（控制台据此显示黄色横幅）。 */
  deprecated?: Array<{ key: string; hint: string }>;
  /** false when the document could not be parsed and defaults replace it. */
  valid: boolean;
  /** true when the whole document was rejected and defaults are in force. */
  fallback: boolean;
  /** Human-readable problems; safe to show in the console. */
  issues: string[];
  /** Tools the document explicitly allowed to run credential attacks. */
  credential_tools: string[];
  /** Tools the document explicitly allowed to run active Burp scans. */
  active_scan_tools: string[];
};

const parseDocument = (values: Record<string, string>): { raw: string; value?: Record<string, unknown>; error?: string } => {
  const raw = String(values?.BLACKBOX_RULES_DOCUMENT || "").trim();
  if (!raw) return { raw };
  try {
    const value = JSON.parse(raw) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) return { raw, error: "必须是 JSON 对象" };
    return { raw, value: value as Record<string, unknown> };
  } catch (error) {
    return { raw, error: `不是有效 JSON（${error instanceof Error ? error.message : String(error)}）` };
  }
};

function merge(base: BlackboxRules, value: unknown, issues?: string[]): BlackboxRules {
  if (!value || typeof value !== "object" || Array.isArray(value)) return structuredClone(base);
  const raw = value as Record<string, unknown>;
  const section = (name: string) => raw[name] && typeof raw[name] === "object" && !Array.isArray(raw[name]) ? raw[name] as Record<string, unknown> : {};
  const flag = (v: unknown, fallback: boolean, path: string) => {
    if (v === undefined) return fallback;
    if (typeof v !== "boolean") { issues?.push(`${path} 必须是布尔值，已使用默认值 ${fallback}。`); return fallback; }
    return v;
  };
  const number = (v: unknown, fallback: number, path: string, min = 0, max = 1_000_000_000) => {
    if (v === undefined || v === null || v === "") return fallback;
    const numeric = Number(v);
    if (!Number.isFinite(numeric)) { issues?.push(`${path} 不是有效数字（${JSON.stringify(v)}），已使用默认值 ${fallback}。`); return fallback; }
    const clamped = Math.max(min, Math.min(max, Math.floor(numeric)));
    if (clamped !== Math.floor(numeric)) issues?.push(`${path} 超出允许范围 ${min}–${max}，已限制为 ${clamped}。`);
    return clamped;
  };
  const bool = (v: unknown, fallback: boolean, path: string) => {
    if (v === undefined || v === null || v === "") return fallback;
    if (typeof v === "boolean") return v;
    const text = String(v).trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(text)) return true;
    if (["0", "false", "no", "off"].includes(text)) return false;
    issues?.push(`${path} 不是有效布尔值（${JSON.stringify(v)}），已使用默认值 ${fallback}。`);
    return fallback;
  };
  const money = (v: unknown, fallback: number, path: string) => {
    if (v === undefined || v === null || v === "") return fallback;
    const numeric = Number(v);
    if (!Number.isFinite(numeric)) { issues?.push(`${path} 不是有效数字（${JSON.stringify(v)}），已使用默认值 ${fallback}。`); return fallback; }
    return Math.max(0, numeric);
  };

  const budgetsRaw = section("budgets"); const loop = section("loop_control"); const request = section("request");
  const budgets: BlackboxRules["budgets"] = {
    time_sec: number(budgetsRaw.time_sec, base.budgets.time_sec, "budgets.time_sec"),
    wall_clock_sec: number(budgetsRaw.wall_clock_sec, base.budgets.wall_clock_sec, "budgets.wall_clock_sec"),
    tool_calls: number(budgetsRaw.tool_calls, base.budgets.tool_calls, "budgets.tool_calls"),
    agent_turns: number(budgetsRaw.agent_turns, base.budgets.agent_turns, "budgets.agent_turns"),
    tokens: number(budgetsRaw.tokens, base.budgets.tokens, "budgets.tokens"),
    cost: money(budgetsRaw.cost, base.budgets.cost, "budgets.cost"),
    retries: number(budgetsRaw.retries, base.budgets.retries, "budgets.retries"),
  };
  const toolWeights: BlackboxRules["tool_weights"] = {};
  for (const [name, weight] of Object.entries(section("tool_weights"))) {
    if (!/^(recon|burp|browser|http|katana|evidence)\./.test(name)) {
      issues?.push(`tool_weights["${name}"] 不是工具名（形如 recon.nuclei / http.request），已忽略。`);
      continue;
    }
    const value = number(weight, 0, `tool_weights.${name}`, 1, 50);
    if (value > 0) toolWeights[name] = value;
  }
  const loopControl: BlackboxRules["loop_control"] = {
    task_retry_limit: number(loop.task_retry_limit, base.loop_control.task_retry_limit, "loop_control.task_retry_limit"),
    repeat_limit: number(loop.repeat_limit, base.loop_control.repeat_limit, "loop_control.repeat_limit"),
    stall_batch_limit: number(loop.stall_batch_limit, base.loop_control.stall_batch_limit, "loop_control.stall_batch_limit"),
    stage_timeout_sec: number(loop.stage_timeout_sec, base.loop_control.stage_timeout_sec, "loop_control.stage_timeout_sec"),
    stage_rollover_limit: number(loop.stage_rollover_limit, base.loop_control.stage_rollover_limit, "loop_control.stage_rollover_limit"),
    param_stall_calls: number(loop.param_stall_calls, base.loop_control.param_stall_calls, "loop_control.param_stall_calls"),
    param_stall_variants: number(loop.param_stall_variants, base.loop_control.param_stall_variants, "loop_control.param_stall_variants"),
    param_stall_ratio: number(loop.param_stall_ratio, base.loop_control.param_stall_ratio, "loop_control.param_stall_ratio"),
    param_stall_queries: number(loop.param_stall_queries, base.loop_control.param_stall_queries, "loop_control.param_stall_queries"),
    advice_pending_limit: number(loop.advice_pending_limit, base.loop_control.advice_pending_limit, "loop_control.advice_pending_limit"),
      task_pending_limit: number(loop.task_pending_limit, base.loop_control.task_pending_limit, "loop_control.task_pending_limit"),
  };
  const focusRaw = section("focus_lock");
  const focus = {
    on: bool(focusRaw.on, base.focus_lock.on, "focus_lock.on"),
    reject_unassigned: bool(focusRaw.reject_unassigned, base.focus_lock.reject_unassigned, "focus_lock.reject_unassigned"),
    max_turns_per_task: number(focusRaw.max_turns_per_task, base.focus_lock.max_turns_per_task, "focus_lock.max_turns_per_task", 0, 200),
    max_tp_per_task: number(focusRaw.max_tp_per_task, base.focus_lock.max_tp_per_task, "focus_lock.max_tp_per_task", 0, 5000),
    stall_rounds: number(focusRaw.stall_rounds, base.focus_lock.stall_rounds, "focus_lock.stall_rounds", 0, 50),
    appeal_pool: number(focusRaw.appeal_pool, base.focus_lock.appeal_pool, "focus_lock.appeal_pool", 0, 50),
    appeal_potential_max: number(focusRaw.appeal_potential_max, base.focus_lock.appeal_potential_max, "focus_lock.appeal_potential_max", 0, 100),
    max_session_convergences: number(focusRaw.max_session_convergences, base.focus_lock.max_session_convergences, "focus_lock.max_session_convergences", 0, 100),
    overflow_per_round: number(focusRaw.overflow_per_round, base.focus_lock.overflow_per_round, "focus_lock.overflow_per_round", 0, 20),
  };
  const wallRaw = section("auth_wall");
  const wallLimit = number(wallRaw.streak_limit, base.auth_wall.streak_limit, "auth_wall.streak_limit", 0, 1000);
  let wallCodes = base.auth_wall.codes;
  if (wallRaw.codes !== undefined) {
    if (!Array.isArray(wallRaw.codes) || !wallRaw.codes.length) issues?.push("auth_wall.codes 必须是非空字符串数组，已使用默认值。");
    else {
      const normalized = wallRaw.codes.map(String).map(code => code.trim()).filter(Boolean);
      if (normalized.length) wallCodes = normalized;
      else issues?.push("auth_wall.codes 全部无效，已使用默认值。");
    }
  }
  let safePaths = base.auth_wall.safe_paths;
  if (wallRaw.safe_paths !== undefined) {
    if (!Array.isArray(wallRaw.safe_paths)) issues?.push("auth_wall.safe_paths 必须是字符串数组，已使用默认值。");
    else {
      const normalized = wallRaw.safe_paths.map(String).map(item => item.trim()).filter(Boolean);
      // An empty list is meaningful (fully closed wall), so only reject non-arrays.
      safePaths = normalized;
    }
  }
  let methods = base.request.methods;
  if (request.methods !== undefined) {
    if (!Array.isArray(request.methods)) issues?.push("request.methods 必须是字符串数组，已使用默认方法列表。");
    else {
      const normalized = request.methods.map(String).map((method) => method.toUpperCase()).filter((method) => method.length > 0 && method.length < 16);
      if (!normalized.length) issues?.push("request.methods 为空或全部无效，已使用默认方法列表。");
      else {
        if (normalized.length !== request.methods.length) issues?.push(`request.methods 有 ${request.methods.length - normalized.length} 项无效，已忽略。`);
        methods = normalized;
      }
    }
  }
  const tools: BlackboxRules["tools"] = { ...base.tools };
  for (const [name, policy] of Object.entries(section("tools"))) {
    if (!BLACKBOX_RULE_TOOL_NAMES.includes(name)) {
      issues?.push(`未知工具名 "${name}"，已忽略（可设置风险开关：${BLACKBOX_RULE_TOOL_NAMES.join(", ")}）。`);
      continue;
    }
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) { issues?.push(`tools["${name}"] 必须是对象，已忽略。`); continue; }
    const item = policy as Record<string, unknown>;
    for (const key of Object.keys(item)) {
      if (key === "enabled" || key === "allow_credential_attack" || key === "allow_active_scan") continue;
      issues?.push(`tools["${name}"].${key} 不是已知字段，已忽略（可用：allow_credential_attack、allow_active_scan）。`);
    }
    if (item.enabled !== undefined) {
      // Tools are never switched off by the rules document; a leftover flag is ignored.
      issues?.push(`tools["${name}"].enabled 已废弃：所有工具始终可用，该字段被忽略。`);
    }
    for (const [flag, label] of [["allow_credential_attack", "凭据爆破"], ["allow_active_scan", "主动扫描"]] as const) {
      if (item[flag] !== undefined && typeof item[flag] !== "boolean") {
        issues?.push(`tools["${name}"].${flag} 必须是布尔值，只有 true 才会开启${label}；已按关闭处理。`);
      }
    }
    tools[name] = {
      // Credential attacks are a different risk class (lockout, volume): off unless the
      // operator switches this tool on explicitly.
      ...(item.allow_credential_attack === true ? { allow_credential_attack: true } : {}),
      // Active Burp scans send attack payloads; they are a separate risk class and off by default.
      ...(item.allow_active_scan === true ? { allow_active_scan: true } : {}),
    };
  }
  const text: BlackboxRules["text"] = { ...base.text };
  for (const [name, body] of Object.entries(section("text"))) {
    if (typeof body !== "string") { issues?.push(`text["${name}"] 必须是字符串，已忽略。`); continue; }
    text[name] = body;
  }
  const evidence = section("evidence"); const report = section("report");
  return {
    version: number(raw.version, base.version, "version", 1, 999999),
    budgets,
    tool_weights: toolWeights,
    loop_control: loopControl,
    request: {
      methods,
      max_redirects: number(request.max_redirects, base.request.max_redirects, "request.max_redirects", 0, 20),
      max_timeout_ms: number(request.max_timeout_ms, base.request.max_timeout_ms, "request.max_timeout_ms", 1000, 300000),
      max_body_bytes: number(request.max_body_bytes, base.request.max_body_bytes, "request.max_body_bytes", 1024, 10_000_000),
      max_request_body_bytes: number(request.max_request_body_bytes, base.request.max_request_body_bytes, "request.max_request_body_bytes", 1024, 25_000_000),
      max_output_bytes: number(request.max_output_bytes, base.request.max_output_bytes, "request.max_output_bytes", 1024, 20_000_000),
    },
    focus_lock: focus,
    auth_wall: {
      streak_limit: wallLimit,
      codes: wallCodes,
      safe_paths: safePaths,
      allow_unauth_playbook: flag(wallRaw.allow_unauth_playbook, base.auth_wall.allow_unauth_playbook, "auth_wall.allow_unauth_playbook"),
      allow_bypass: flag(wallRaw.allow_bypass, base.auth_wall.allow_bypass, "auth_wall.allow_bypass"),
    },
    tools,
    evidence: {
      require_ids: flag(evidence.require_ids, base.evidence.require_ids, "evidence.require_ids"),
      save_raw_results: flag(evidence.save_raw_results, base.evidence.save_raw_results, "evidence.save_raw_results"),
    },
    report: {
      require_task_outcomes: flag(report.require_task_outcomes, base.report.require_task_outcomes, "report.require_task_outcomes"),
      distinguish_incomplete: flag(report.distinguish_incomplete, base.report.distinguish_incomplete, "report.distinguish_incomplete"),
    },
    text,
  };
}

/**
 * Settings 里的单项预算键（BLACKBOX_TIME_BUDGET_SEC / BLACKBOX_WALL_CLOCK_BUDGET_SEC /
 * BLACKBOX_TOOL_BUDGET / BLACKBOX_AGENT_TURN_BUDGET / TOKEN_BUDGET / COST_BUDGET / RETRY_BUDGET）
 * 从来没有被任何代码读取过——它们不是"兜底值"，而是纯死键。
 *
 * 这里刻意**不**把它们接进预算：这些键在很多历史配置里残留着随手填的小值（例如 tool_calls=50），
 * 一旦让它们生效，会静默覆盖规则文档里的新默认值（120），把刚调好的额度打回原形。
 * 正确做法是让它们显式报错，让操作员知道配置没生效、该改哪里。
 */
export const LEGACY_BUDGET_KEYS = [
  "BLACKBOX_TIME_BUDGET_SEC", "BLACKBOX_WALL_CLOCK_BUDGET_SEC", "BLACKBOX_TOOL_BUDGET",
  "BLACKBOX_AGENT_TURN_BUDGET", "BLACKBOX_TOKEN_BUDGET", "BLACKBOX_COST_BUDGET", "BLACKBOX_RETRY_BUDGET",
] as const;

/**
 * 已废弃的规则键 → 迁移建议。
 *
 * 静默忽略是配置漂移的温床：操作员以为"20 次调用"还在生效，实际预算早就换成 TP 了。
 * 所以这里显式识别：开发/CI 用 strict 直接抛错，生产环境报 WARN + 控制台黄色横幅。
 */
export const DEPRECATED_RULE_KEYS: Record<string, string> = {
  "focus_lock.max_tool_calls_per_task": "focus_lock.max_tp_per_task（按战术点数记账）",
  "focus_lock.appeals_per_task": "focus_lock.appeal_pool（整场会话共享的申诉池）",
  "focus_lock.enabled": "focus_lock.on",
};

/** 扫描规则文档里的废弃键（只报真正出现了的）。 */
export function deprecatedRuleKeys(value: unknown): Array<{ key: string; hint: string }> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const found: Array<{ key: string; hint: string }> = [];
  const root = value as Record<string, unknown>;
  for (const [path, hint] of Object.entries(DEPRECATED_RULE_KEYS)) {
    const [head, leaf] = path.split(".") as [string, string | undefined];
    const block = root[head];
    if (!leaf) {
      if (head in root) found.push({ key: path, hint });
      continue;
    }
    if (block && typeof block === "object" && !Array.isArray(block) && leaf in (block as Record<string, unknown>)) found.push({ key: path, hint });
  }
  return found;
}

export type RulesLoadOptions = {
  /** 严格模式：遇到废弃键 / 文档损坏直接抛错（测试、CI 用），默认只记 issue。 */
  strict?: boolean;
  /** 诊断输出位置；desk 把它写进 checkpoint.rule_issues，控制台据此显示横幅。 */
  issues?: string[];
};

/**
 * 加载规则文档。
 *
 * strict: true 时抛出 `Deprecated rule key detected: …`，让测试变红；
 * 生产路径不抛（一条废弃配置不该让整场会话起不来），由 blackboxRulesDiagnostics 报到控制台。
 */
export function blackboxRules(values: Record<string, string>, options: RulesLoadOptions = {}): BlackboxRules {
  const document = parseDocument(values);
  const messages = deprecatedRuleKeys(document.value).map(item => `规则项 ${item.key} 已废弃，请迁移到 ${item.hint}（下个版本将完全失效）。`);
  if (options.strict && (messages.length || document.error)) {
    throw new Error(`Deprecated rule key detected: ${[...messages, ...(document.error ? [`BLACKBOX_RULES_DOCUMENT ${document.error}`] : [])].join("; ")}`);
  }
  for (const message of messages) options.issues?.push(message);
  return merge(DEFAULT_BLACKBOX_RULES, document.value, options.issues);
}

/** 出现在配置里但完全不生效的预算键（诊断用）。 */
export function deadBudgetKeys(values: Record<string, string>): string[] {
  return LEGACY_BUDGET_KEYS.filter(key => String(values[key] ?? "").trim().length > 0);
}

/**
 * Reports what the operator-supplied rules document really did: an unparsable
 * document silently falls back to defaults (all tools usable), so surface it
 * instead of leaving the operator to guess.
 */
export function blackboxRulesDiagnostics(values: Record<string, string>): BlackboxRulesDiagnostics {
  const dead = deadBudgetKeys(values);
  const deadIssue = dead.length
    ? `这些预算键不生效，请改用规则文档：${dead.join(", ")}（真正生效的是 BLACKBOX_RULES_DOCUMENT 里的 budgets.*，当前默认 ${DEFAULT_BLACKBOX_RULES.budgets.time_sec}s 调度 / ${DEFAULT_BLACKBOX_RULES.budgets.wall_clock_sec}s 墙钟 / ${DEFAULT_BLACKBOX_RULES.budgets.tool_calls} 权重）。`
    : "";
  const document = parseDocument(values);
  if (document.error) {
    return {
      valid: false,
      fallback: true,
      issues: [`BLACKBOX_RULES_DOCUMENT ${document.error}；已回退到默认规则：所有工具可用、默认预算生效。`, ...(deadIssue ? [deadIssue] : [])],
      credential_tools: [],
      active_scan_tools: [],
    };
  }
  if (!document.value) return { valid: true, fallback: false, issues: deadIssue ? [deadIssue] : [], credential_tools: [], active_scan_tools: [] };
  const issues: string[] = [];
  if (deadIssue) issues.push(deadIssue);
  for (const key of Object.keys(document.value)) {
    if (!(BLACKBOX_RULE_SECTIONS as readonly string[]).includes(key)) issues.push(`未知规则段 "${key}"，已忽略（可用：${BLACKBOX_RULE_SECTIONS.join(", ")}）。`);
  }
  const deprecated = deprecatedRuleKeys(document.value);
  for (const item of deprecated) issues.push(`规则项 ${item.key} 已废弃，请迁移到 ${item.hint}（下个版本将完全失效）。`);
  const rules = merge(DEFAULT_BLACKBOX_RULES, document.value, issues);
  return {
    valid: true, fallback: false, issues, deprecated,
    credential_tools: BLACKBOX_RULE_TOOL_NAMES.filter((name) => rules.tools[name]?.allow_credential_attack === true),
    active_scan_tools: BLACKBOX_RULE_TOOL_NAMES.filter((name) => rules.tools[name]?.allow_active_scan === true),
  };
}

export function blackboxRulesHash(rules: BlackboxRules): string { return createHash("sha256").update(JSON.stringify(rules)).digest("hex"); }

/**
 * 漏洞判定谓词：把 playbook 的 `confirm.must_show`（中文散文）翻成机器可判的条件。
 *
 * 为什么需要（2026-11-02 m.ctrip.com 实测）：
 *   `validateFinding` 当时只校验「证据存在 + 同 host 同 path」，于是
 *   「匿名 GET /restapi/soa2 返回 200」这种**线索**也能通过，成为一个合法 finding。
 *   而 playbook 里写得很专业的确认标准（"未带凭证 200 且 body 含敏感字段"
 *   "凭证属于 A 却返回 B 的对象数据"）**没有任何代码消费**——全仓 grep `confirm`
 *   只有定义、没有读者。结果就是：判定标准存在，约束不存在。
 *
 * 这里把标准变成可判定的谓词，供三处使用：
 *   ① 结案门槛：vuln 打法标 completed 前必须满足本打法的 require（否则退回 pending）
 *   ② 上下文注入：未满足项每轮拍给 agent（"你离确认还差什么"），不靠它自己回忆
 *   ③ 报告分层：满足=漏洞，不满足=线索（lead），杜绝把线索写进漏洞段
 *
 * 设计约束（刻意为之）：
 *   - 判据只取**已有的结构化证据**（diff verdict / status / body / 工具产出），
 *     不新增"模型自述"字段——自述无法证伪，等于没判。
 *   - 无法求值的条件一律算**未满足**：宁可不给结论，也不给假结论。
 */
import type { DiffVerdict } from "./diff.js";

export type Requirement =
  /** 一次对照判定落在给定集合里（http.diff 的 verdict，由 diff.ts 计算）。 */
  | { kind: "diff"; verdict_in: DiffVerdict[] }
  /** 未带任何凭证即成功（匿名可达）。 */
  | { kind: "anonymous_ok"; status_below?: number }
  /** 响应正文里出现真实敏感数据（不是"接口存在"，是"数据出来了"）。 */
  | { kind: "sensitive_body" }
  /** 命令执行回显（uid= 之类），而非文件源码或被拒。 */
  | { kind: "exec_echo" }
  /** 带外回连命中（interactsh / DNSLog / Collaborator）。 */
  | { kind: "oast_callback" }
  /** 浏览器里真的执行了（DOM 变化 / 回调），不是仅字符串回显。 */
  | { kind: "browser_executed" }
  /** 同一资源被并发消耗多次（库存超扣、券超领）。 */
  | { kind: "duplicate_success"; min: number }
  /** 交付物（侦察类打法）：产出可打的接口面即可，**不构成漏洞**。 */
  | { kind: "deliverable"; tools: string[] };

export type PlaybookRequirement = {
  /** all = 全部满足才算确认；any = 命中其一即可（对应 must_show 里的"或"）。 */
  mode: "all" | "any";
  /**
   * true 表示这是**交付类**打法：产出侦察成果即可结案，但不产生漏洞。
   * spa_reverse 是唯一一个（外壳翻译成接口面本身就是它的 confirm）。
   */
  deliverable?: boolean;
  requires: Requirement[];
};

/**
 * 16 个打法的判定谓词。
 *
 * 每条都严格对应 playbooks.ts 里同一 id 的 `confirm.must_show`；
 * `test/vuln-predicates.test.ts` 会断言本表覆盖 PLAYBOOK_IDS 全集，
 * 新增打法忘了写谓词会直接测试失败（不再出现"标准存在、约束不存在"）。
 *
 * 注意 id 用的是**真实 id**（cmdi / jwt_auth / cloud_supply / logic / graphql_ws），
 * 不是"看起来更像"的名字——旧版 progress.ts 用 command_injection / jwt_forgery /
 * subdomain_takeover / business_logic / graphql，导致一半打法的门槛从未生效。
 */
export const PLAYBOOK_REQUIREMENTS: Record<string, PlaybookRequirement> = {
  // "某个变体维度返回非拦截响应，且 http.diff 证明差异由该变体引起"
  waf_bypass: { mode: "all", requires: [{ kind: "diff", verdict_in: ["different"] }] },
  // "bundle 正文抠出 baseURL / /api 清单，或 browser.network 拿到真实 XHR"——交付，不是漏洞
  spa_reverse: { mode: "any", deliverable: true, requires: [{ kind: "deliverable", tools: ["exec.python", "browser.network", "recon.js_endpoints"] }] },
  // "未带任何凭证返回 200 且 body 含敏感字段"
  unauth_exposure: { mode: "all", requires: [{ kind: "anonymous_ok" }, { kind: "sensitive_body" }] },
  // "带 Token 出现业务数据，且与匿名响应结构不同"
  auth_token: { mode: "all", requires: [{ kind: "diff", verdict_in: ["different", "same_shape"] }, { kind: "sensitive_body" }] },
  // "凭证属于 A 却返回 B 的对象数据，且 baseline_self 自比对里不存在该差异"
  idor: { mode: "all", requires: [{ kind: "diff", verdict_in: ["same_shape", "different"] }] },
  // "表达式求值迹象 / timing_delta / sqlmap injectable / OAST 回连"
  sqli: { mode: "any", requires: [{ kind: "diff", verdict_in: ["timing_delta"] }, { kind: "oast_callback" }, { kind: "sensitive_body" }] },
  // "访问上传文件返回命令执行结果，而不是文件源码或被拒绝"
  upload_rce: { mode: "all", requires: [{ kind: "exec_echo" }] },
  // "命令输出回显；无回显时 timing_delta 或 OAST"
  cmdi: { mode: "any", requires: [{ kind: "exec_echo" }, { kind: "diff", verdict_in: ["timing_delta"] }, { kind: "oast_callback" }] },
  // "OAST 收到回连；或内网/元数据内容被回显"
  ssrf: { mode: "any", requires: [{ kind: "oast_callback" }, { kind: "sensitive_body" }] },
  // "OAST 回连命中；SSTI 以算术回显成立"
  deserialization: { mode: "any", requires: [{ kind: "oast_callback" }, { kind: "exec_echo" }] },
  // "伪造/篡改 token 访问受保护接口返回 200 与真实数据"
  jwt_auth: { mode: "all", requires: [{ kind: "anonymous_ok" }, { kind: "sensitive_body" }] },
  // "可列举对象或凭证可读资源"
  cloud_supply: { mode: "all", requires: [{ kind: "sensitive_body" }] },
  // "跳过/乱序调用后服务器状态真的进入非法态，由 diff_effect 证明"
  logic: { mode: "all", requires: [{ kind: "diff", verdict_in: ["different", "same_shape"] }] },
  // "同一资源被并发消耗多次，diff_effect 前后数值按成功次数变化"
  race_condition: { mode: "all", requires: [{ kind: "duplicate_success", min: 2 }] },
  // "未授权查询返回敏感字段，或 WS 订阅到他人频道数据"
  graphql_ws: { mode: "all", requires: [{ kind: "sensitive_body" }] },
  // "浏览器里实际执行（DOM 变化/回调），不是仅字符串回显"
  xss: { mode: "all", requires: [{ kind: "browser_executed" }] },
};

/** 该打法是否"确认漏洞"型（不是交付型）。结案门槛只对这类要求漏洞证据。 */
export function isVulnPlaybook(playbook: string | undefined): boolean {
  const key = String(playbook || "").toLowerCase();
  const rule = PLAYBOOK_REQUIREMENTS[key];
  if (!rule) return false;
  return rule.deliverable !== true;
}

/**
 * 「一致性即结论」的打法。
 *
 * 这里的判据是**两种身份的响应是不是一致**，不是"发现了新东西"。所以：
 *   - 一次对照返回 identical 对它们不是零熵，而是**结论**（入口没按身份区分）；
 *   - 连续多次 401/403 也不是"打不动"，而是负向结论（鉴权生效）。
 *
 * 2026-11-02 审计的冲突 4：`zero_entropy` 把 identical 连判两次就 blocked，恰好把
 * unauth_exposure 要的答案判成噪音。这里做成单一事实源，desk / progress 都从这里取。
 */
export const CONSISTENCY_PLAYBOOKS = new Set(["unauth_exposure", "auth_token", "jwt_auth", "idor"]);

const CONSISTENCY_INTENT = /未授权|未登录|免登|匿名|越权|鉴权|unauth|unauthorized|no[-_ ]?auth|authz|idor/i;

/**
 * 任务算不算「一致性即结论」型：绑了打法就按打法判，没绑打法就看目的是不是在做鉴权/未授权验证。
 * 返回可读标签（用于事件与中断文案），不是则返回 undefined。
 */
export function consistencyPlaybookOf(task?: { playbook?: string; purpose?: string; completion_criteria?: string; target?: string }): string | undefined {
  if (!task) return undefined;
  const playbook = String(task.playbook || "").toLowerCase();
  if (CONSISTENCY_PLAYBOOKS.has(playbook)) return playbook;
  // 自由文本任务（没绑打法）也要认：提示词本来就要求"未授权验证必须匿名"，
  // 不该因为模型没写 playbook 字段就把这类任务的对照判成零熵。
  const intent = `${task.purpose || ""} ${task.completion_criteria || ""}`;
  return CONSISTENCY_INTENT.test(intent) ? "unauth_free_text" : undefined;
}

/** 该打法是否有谓词定义。未登记的打法按"未知"处理：不拦结案，但也不产生漏洞。 */
export function hasRequirements(playbook: string | undefined): boolean {
  return Boolean(PLAYBOOK_REQUIREMENTS[String(playbook || "").toLowerCase()]);
}

/**
 * 真实敏感数据的判据。
 *
 * 刻意**不**收 token / email / userId 这类常见键：它们出现在埋点、错误信封、
 * 匿名建号响应里太正常，收进来会让"敏感字段命中"退化成永远为真，等于没有约束。
 * 留在表里的是"一旦出现几乎只能是泄露"的东西。
 */
const SENSITIVE_PATTERNS: RegExp[] = [
  /passw(?:or)?d\s*["']?\s*[:=]\s*["'][^"']{3,}/i,
  /(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|secret)\s*["']?\s*[:=]\s*["'][A-Za-z0-9/+_-]{12,}/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /jdbc:[a-z]+:\/\/|mongodb(?:\+srv)?:\/\/[^\s"']+:[^\s"']+@|redis:\/\/[^\s"']*:[^\s"']+@/i,
  /\b1[3-9]\d{9}\b(?=.{0,40}(?:手机|mobile|phone|tel))/i,
  /\b\d{17}[\dXx]\b/,
  /"(?:idCard|id_card|identityNo|bankCard|cardNo)"\s*:\s*"[0-9Xx]{10,}"/i,
  /"(?:balance|amount|余额)"\s*:\s*-?\d{2,}/i,
];

const EXEC_ECHO_PATTERNS: RegExp[] = [
  /uid=\d+\([a-z_][a-z0-9_-]*\)\s+gid=\d+/i,
  /root:x:0:0:/,
  /^(?:total \d+|\d{4}-\d{2}-\d{2} \d{2}:\d{2}).*(?:drwx|rw-r--r--)/m,
  /Microsoft Windows \[Version [\d. ]+\]/i,
  /Volume Serial Number is [0-9A-F-]{8,}/i,
];

const OAST_PATTERN = /(?:interactsh|oastify|dnslog|burpcollaborator|canarytokens)[^\s"']{0,80}(?:hit|received|callback|interaction)|(?:callback|interaction)[_ ]?(?:hit|received)\s*[:=]\s*true/i;
const BROWSER_EXEC_PATTERN = /(?:dom_changed|executed|alert_fired|dialog_shown)\s*[:=]\s*true|window\.__xss|onerror=alert\(1\)/i;

type EvidenceLike = Record<string, unknown>;

function dataOf(item: EvidenceLike): Record<string, unknown> {
  const data = item.data;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : {};
}

function textOf(item: EvidenceLike): string {
  const data = dataOf(item);
  const body = data.body ?? data.body_preview ?? data.response ?? data.text ?? data.output ?? item.summary;
  return typeof body === "string" ? body : "";
}

function verdictOf(item: EvidenceLike): string {
  const data = dataOf(item);
  return String(data.verdict ?? data.diff_verdict ?? data.result_verdict ?? "").toLowerCase();
}

function statusOf(item: EvidenceLike): number | undefined {
  const data = dataOf(item);
  const raw = data.status ?? data.status_code ?? data.response_status;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

/** 匿名请求：显式 anonymous 标记，或结果里没有任何"附上凭证"的痕迹。 */
function anonymousOf(item: EvidenceLike): boolean {
  const data = dataOf(item);
  if (data.anonymous === true) return true;
  const applied = data.auth_applied;
  if (typeof applied === "string") return applied.trim().length === 0;
  if (Array.isArray(applied)) return applied.length === 0;
  return false;
}

function succeeded(item: EvidenceLike): boolean {
  const data = dataOf(item);
  if (data.ok === false) return false;
  const status = statusOf(item);
  if (status === undefined) return data.ok === true || data.exit_code === 0 || data.exit === 0;
  return status < 400;
}

function toolOf(item: EvidenceLike): string {
  const data = dataOf(item);
  return String(item.tool ?? data.tool ?? item.source ?? "").toLowerCase();
}

function matchRequirement(requirement: Requirement, evidence: EvidenceLike[]): boolean {
  switch (requirement.kind) {
    case "diff": {
      const allowed = new Set(requirement.verdict_in);
      return evidence.some(item => allowed.has(verdictOf(item) as DiffVerdict));
    }
    case "anonymous_ok": {
      const below = requirement.status_below ?? 400;
      return evidence.some(item => anonymousOf(item) && succeeded(item) && (statusOf(item) ?? 0) < below);
    }
    case "sensitive_body": {
      return evidence.some(item => SENSITIVE_PATTERNS.some(pattern => pattern.test(textOf(item))));
    }
    case "exec_echo": {
      return evidence.some(item => EXEC_ECHO_PATTERNS.some(pattern => pattern.test(textOf(item))));
    }
    case "oast_callback": {
      return evidence.some(item => OAST_PATTERN.test(textOf(item)) || OAST_PATTERN.test(JSON.stringify(dataOf(item))));
    }
    case "browser_executed": {
      return evidence.some(item => BROWSER_EXEC_PATTERN.test(textOf(item)) || BROWSER_EXEC_PATTERN.test(JSON.stringify(dataOf(item))));
    }
    case "duplicate_success": {
      return evidence.some(item => {
        const data = dataOf(item);
        const count = Number(data.success_count ?? data.duplicate_success_count ?? data.successes ?? data.count);
        return Number.isFinite(count) && count >= requirement.min;
      });
    }
    case "deliverable": {
      const tools = new Set(requirement.tools.map(name => name.toLowerCase()));
      return evidence.some(item => tools.has(toolOf(item)) && dataOf(item).ok !== false);
    }
    default:
      return false;
  }
}

const LABELS: Record<Requirement["kind"], string> = {
  diff: "一次 http.diff 对照结论",
  anonymous_ok: "匿名（不带任何凭证）请求成功",
  sensitive_body: "响应正文里的真实敏感数据",
  exec_echo: "命令执行回显",
  oast_callback: "带外回连命中",
  browser_executed: "浏览器内真实执行",
  duplicate_success: "同一资源被并发消耗多次的计数",
  deliverable: "侦察交付物",
};

function labelOf(requirement: Requirement): string {
  if (requirement.kind === "diff") return `一次 verdict ∈ {${requirement.verdict_in.join(", ")}} 的 http.diff 对照`;
  if (requirement.kind === "anonymous_ok") return `匿名（不带任何凭证）请求返回 <${requirement.status_below ?? 400}`;
  if (requirement.kind === "duplicate_success") return `同一资源被并发消耗 ≥${requirement.min} 次的计数`;
  if (requirement.kind === "deliverable") return `侦察交付物（${requirement.tools.join(" / ")}）`;
  return LABELS[requirement.kind];
}

export type RequirementVerdict = {
  /** 该打法是否登记了谓词。未登记时 satisfied 恒为 true（不拦结案），但调用方应据此不给漏洞。 */
  registered: boolean;
  deliverable: boolean;
  satisfied: boolean;
  /** 未满足项的中文描述，可直接注入上下文 / 写事件。 */
  missing: string[];
};

/**
 * 判定某个打法的确认条件是否成立。
 *
 * `evidence` 传该任务（或整场会话）的证据；无法求值的条件算未满足——
 * 宁可让 agent 继续补证，也不要让它凭一句 summary 结案。
 */
export function evaluateRequirements(playbook: string | undefined, evidence: EvidenceLike[]): RequirementVerdict {
  const key = String(playbook || "").toLowerCase();
  const rule = PLAYBOOK_REQUIREMENTS[key];
  if (!rule) return { registered: false, deliverable: false, satisfied: true, missing: [] };
  const hits = rule.requires.map(requirement => matchRequirement(requirement, evidence));
  const satisfied = rule.mode === "any" ? hits.some(Boolean) : hits.every(Boolean);
  const missing = rule.requires.filter((_, index) => !hits[index]).map(labelOf);
  return { registered: true, deliverable: rule.deliverable === true, satisfied, missing };
}

export type VulnGap = { task_id: string; playbook: string; missing: string[] };

/**
 * 未结案的漏洞确认型任务，各自还缺哪件确认证据。
 *
 * 用途是注入上下文（`context.vuln_gaps`）：让 agent 每轮都看得到"我这个任务离确认
 * 还差一次什么对照"，而不是靠它自己从规则里回忆。只取 pending/testing 的任务——
 * 已 blocked/failed 的已经负向结案，completed 的不再需要补证。
 */
export function vulnerabilityGaps(state: unknown, evidence: EvidenceLike[], limit = 4): VulnGap[] {
  const tasks = (state as { tasks?: Record<string, { status?: string; playbook?: string }> } | undefined)?.tasks;
  if (!tasks) return [];
  const out: VulnGap[] = [];
  for (const [taskId, task] of Object.entries(tasks)) {
    if (!task || !isVulnPlaybook(task.playbook)) continue;
    const status = String(task.status || "");
    if (status === "completed" || status === "blocked" || status === "failed") continue;
    const verdict = evaluateRequirements(task.playbook, evidence);
    if (!verdict.registered || verdict.satisfied) continue;
    out.push({ task_id: taskId, playbook: String(task.playbook || ""), missing: verdict.missing });
    if (out.length >= limit) break;
  }
  return out;
}

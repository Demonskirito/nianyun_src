import { z } from "zod/v4";
import { findingSchema } from "./findings.js";

const text = z.string().trim().min(1).max(2000);
const ids = z.array(text).max(500);
export const taskSchema = z.object({
  id: text, target: z.string().url().optional(), purpose: text, reason: text,
  completion_criteria: text,
  /** 打法�?id（见 playbooks.ts）。zod 默认剥掉未声明字段，漏了它任务就永远拿不�?playbook�?*/
  playbook: text.optional(),
  /**
   * 结构化任务契约（�?progress.ts closureAudit）�?
   * deliverables �?这条任务要交出什�?，success_criteria �?到哪一步算�?�?
   * fallback_strategy �?主路走不通时先做这件�?——没有契约的任务不收口�?
   */
  deliverables: z.array(text).max(8).optional(),
  success_criteria: text.optional(),
  fallback_strategy: text.optional(),
});
/**
 * 任务条目的宽容化�?026-10-31）�?
 * 实测会话 e1ac3b04161d4402�? 分钟�?8 �?`required_tasks[0]: invalid_union` —�?
 * 模型写的�?`{id,url,purpose}` / `{task_id,goal}` / 纯字符串，�?schema 只认
 * `{id,target,purpose,reason,completion_criteria}`，于是整批任务被丢、回合白跑�?
 * 这里先把常见别名映射成规范字段、缺的补默认值，再交 schema 校验�?
 * �?purpose 都没有的条目仍然失败，不把噪�?宽容"成任务�?
 */
function taskHash(value: string): string {
  let hash = 5381;
  for (let index = 0; index < value.length; index += 1) hash = ((hash << 5) + hash + value.charCodeAt(index)) >>> 0;
  return hash.toString(36).slice(0, 8);
}

export const coercedTaskSchema = z.preprocess((raw) => {
  const line = typeof raw === "string" ? raw.trim() : "";
  if (line) {
    const url = /https?:\/\/[^\s"'),，、]+/.exec(line)?.[0];
    return {
      id: /^T[\w-]{1,24}/.exec(line)?.[0] || `T_${taskHash(line)}`,
      ...(url ? { target: url } : {}),
      purpose: line.slice(0, 400),
      reason: "模型以字符串声明任务",
      completion_criteria: "�?evidence 可复核，结论写明 verdict",
    };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return raw;
  const value = raw as Record<string, unknown>;
  const pick = (...keys: string[]): string | undefined => {
    for (const key of keys) {
      const item = value[key];
      if (typeof item === "string" && item.trim()) return item.trim();
    }
    return undefined;
  };
  const purpose = pick("purpose", "goal", "title", "description", "task", "summary", "objective");
  const url = pick("target", "url", "target_url", "link") || (purpose ? /https?:\/\/[^\s"'),，、]+/.exec(purpose)?.[0] : undefined);
  return {
    ...value,
    id: pick("id", "task_id", "key", "name") || `T_${taskHash(purpose || JSON.stringify(value).slice(0, 200))}`,
    ...(url ? { target: url } : {}),
    ...(purpose ? { purpose } : {}),
    reason: pick("reason", "why", "rationale", "basis") || "模型未写原因",
    completion_criteria: pick("completion_criteria", "criteria", "success_criteria", "deliverable", "done") || "�?evidence 可复核，结论写明 verdict",
    ...(typeof value.deliverable === "string" && !Array.isArray(value.deliverables) ? { deliverables: [value.deliverable] } : {}),
  };
}, taskSchema);
export const taskOutcomeSchema = z.object({
  task_id: text, reason: text, evidence_ids: ids, audit_ids: ids.optional(),
  /**
   * 逐条认领这轮兑现了哪�?deliverables（见 closureAudit）�?
   * 也接�?`true` 表示"全部达成"——实测模型会这样写，为这个写法把整条 outcome 丢掉不值得�?
   */
  deliverables_met: z.union([z.array(text).max(8), z.boolean()]).optional(),
  /**
   * 逐条申报"这一项没做到、理由是什么"（2026-11-02 补：结案死锁的逃生门）。
   *
   * 起因：实跑 768287bceb5e2e01 里 T1_im_shell_verdict 连续 4 次结案被
   * `closure_deliverables_partial` 打回，而打回文案里**没带缺哪几项**（hint 被丢了），
   * 模型只能瞎猜着补，4 轮全撞在同一堵墙上，最后由控制面强制 blocked 收场。
   * 更根本的问题是：任务声明的交付物本来就不可达成（目标整个是 404 catch-all，
   * 没有 JS 可抽），诚实结案在结构上没有出口——只能撒谎说都做到了，或者被卡死。
   *
   * 现在的语义：申报了 unmet 的项不再要求认领，但**不允许标 completed 之外的走法冒充**——
   * 控制面把它记成"部分兑现的负向结论"（warning，不阻塞验收），并在 completion_proof 留痕。
   */
  deliverables_unmet: z.array(z.object({ item: text, reason: text })).max(8).optional(),
});
const multipartItem = z.object({
  name: text,
  value: z.string().max(1_000_000).optional(),
  filename: z.string().trim().min(1).max(255).optional(),
  content_type: z.string().trim().min(1).max(255).optional(),
  content_base64: z.string().max(8_000_000).optional(),
}).strict().refine((item) => item.value !== undefined || item.content_base64 !== undefined, {
  message: "multipart item requires value or content_base64",
});
/**
 * 工具入参的对�?schema�?*不做** strict）�?
 *
 * 2026-10-28 事故：`.strict()` �?多传一个键"= 整条 tool_request 被丢，而执行器真在读的�?
 * �?48 个没来得及登记，于是 http.diff �?variant、fs.grep �?pattern 全部"工具存在但用不了"�?
 * 路由层没有资格因为多一个字段就吞掉请求：这里改�?`.passthrough()`，未知键�?
 * `splitToolInput()` 里被**摘掉并回�?*，执行器只拿到自己认识的键�?
 */
const toolInputObject = z.object({
  url: z.string().url().optional(),
  method: z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]).optional(),
  /**
   * 非常�?HTTP 动词（`NONSENSE`、`DEBUG`、`TRACE`…）：WAF 常按方法分流�?
   * 换一�?WAF 不认识的动词有时直接放行。http.request �?method 是枚举，
   * 这一档只�?burp.send / burp.repeater / burp.organizer 这类原始报文通道用�?
   */
  raw_method: z.string().trim().regex(/^[A-Za-z]{1,20}$/, "raw_method 必须�?1�?0 个字母的 HTTP 动词").optional(),
  headers: z.record(z.string(), z.string().max(8192)).optional(),
  body: z.string().max(5_000_000).optional(),
  body_base64: z.string().max(8_000_000).optional(),
  json: z.unknown().optional(),
  form: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  multipart: z.array(multipartItem).max(50).optional(),
  timeout_ms: z.number().int().min(1000).max(900000).optional(),
  timeout_seconds: z.number().int().min(5).max(900).optional(),
  // Extra CLI arguments for external tools. Denylisted centrally (target overrides, file
  // writes, code/shell execution); everything else is passed through verbatim.
  args: z.array(z.string().min(1).max(512)).max(40).optional(),
  full_page: z.boolean().optional(),
  /**
   * katana 的深度/时长：schema 原来卡在 3 / 60，而 `recon.scan_profile` 明说可以
   * depth≤8、duration≤300。模型照着 scan_profile 写 depth=8 会**整条请求校验失败**
   * （不是被摘键，是 zod 直接拒），表现为"工具突然不能用"。两处数字必须一致。
   */
  depth: z.number().int().min(1).max(8).optional(),
  duration_seconds: z.number().int().min(5).max(300).optional(),
  // Scripted interaction for browser.open/browser.screenshot: a login flow, a click path, or a
  // DOM check is one human action the agent must be able to reproduce.
  actions: z.array(z.object({
    type: z.enum(["click", "fill", "press", "select", "check", "uncheck", "hover", "wait", "scroll"]),
    selector: z.string().min(1).max(500).optional(),
    value: z.string().max(2000).optional(),
    wait_ms: z.number().int().min(0).max(10000).optional(),
  })).max(20).optional(),
  evaluate: z.string().min(1).max(20000).optional(),
  new_tab: z.boolean().optional(),
  // Pipeline input: the full output of an earlier tool becomes this run's target list.
  source: z.object({
    tool: z.string().min(1).max(64).optional(),
    evidence_id: z.string().min(1).max(64).optional(),
    limit: z.number().int().min(1).max(20000).optional(),
  }).optional(),
  evidence_id: z.string().trim().min(1).max(64).optional(),
  limit: z.number().int().min(1).max(1000).optional(), offset: z.number().int().min(0).max(100000).optional(),
  width: z.number().int().min(100).max(65536).optional(),
  entry_id: z.string().trim().min(1).max(64).optional(),
  wordlist: z.string().trim().min(1).max(512).optional(),
  /**
   * 并发：模型的直觉键。执行器按工具折进 `params`（ffuf 的 -t、httpx 的 -threads、
   * naabu 的 -rate），见 tool-params.ts 的 foldTopLevelParams。不声明它就会被
   * splitToolInput 摘掉，然后回执只说"可用：url, params"——等于教模型"并发不可调"。
   */
  threads: z.number().int().min(1).max(50).optional(),
  action: z.enum(["start", "poll", "stop"]).optional(), runtime_id: z.string().trim().max(200).optional(),
  server: z.string().url().optional(), token: z.string().max(4096).optional(), wait_seconds: z.number().int().min(0).max(30).optional(),
  path: z.string().max(1024).optional(), wordlist_root: z.string().max(1024).optional(),
  // Credential controls the executor actually honours. They were missing from this strict
  // schema, which silently dropped whole tool_requests (`anonymous` baselines, http.diff
  // timing thresholds) before the tool ever saw them.
  anonymous: z.boolean().optional(),
  /** Escape hatch for the spa_disarmed gate (desk.ts): without this key in the
  *  whitelist splitToolInput strips it, the gate never sees it, and every
  *  Observer advice that passes force_armored gets marked unusable. 2026-11-01. */
  force_armored: z.boolean().optional(),
  no_auth: z.boolean().optional(),
  use_jar: z.boolean().optional(),
  jwt: z.string().max(4096).optional(),
  cookies: z.union([z.string().max(8192), z.record(z.string(), z.string().max(4096)), z.array(z.string().max(4096)).max(200)]).optional(),
  cookie_jar: z.union([z.string().max(8192), z.record(z.string(), z.string().max(4096)), z.array(z.string().max(4096)).max(200)]).optional(),
  follow_redirects: z.boolean().optional(),
  timing_threshold_ms: z.number().int().min(0).max(600000).optional(),
  /** 显式声明"这条就是未授权验证，别让鉴权墙拦�?（规则允许时才生效）�?*/
  bypass_auth_wall: z.boolean().optional(),
  // Per-tool knobs. Validated by the executor against an explicit allowlist per tool,
  // so this stays a generic bag instead of one schema per CLI.
  params: z.record(z.string().min(1).max(64), z.union([z.string().max(8192), z.number(), z.boolean()]))
    .refine((value) => Object.keys(value).length <= 32, { message: "params supports at most 32 keys" }).optional(),
  /**
   * 2026-10-28 实测补洞：下面这些键执行�?*真的在读**，但先前�?`.strict()` 挡在门外�?
   * 于是出现�?工具存在但用不了"——`http.diff` �?`variant` 被丢（对照组永远发不出去）�?
   * `fs.grep` �?`pattern` 被丢、`evidence.read` �?`tool` 被丢。schema 与执行器不一�?
   * 比缺功能更糟：模型看到的�?格式无效"，不会怀疑是产品自己写错了�?
   * 新增键必须同�?test/tool-input-schema.test.ts（该测试会扫 tools.ts �?input.* 用法）�?
   */
  variant: z.object({
    url: z.string().url().optional(), method: z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]).optional(),
    headers: z.record(z.string(), z.string().max(8192)).optional(), cookie: z.string().max(8192).optional(),
    body: z.string().max(5_000_000).optional(), anonymous: z.boolean().optional(),
    // 变体就是"另一条请�?，所以它同样能吃这些请求级开关（实测模型会把 bypass_auth_wall 写进 variant）�?
    bypass_auth_wall: z.boolean().optional(), follow_redirects: z.boolean().optional(),
    use_jar: z.boolean().optional(), no_auth: z.boolean().optional(), timing_threshold_ms: z.number().int().min(0).max(600000).optional(),
  }).strict().optional(),
  variant_url: z.string().url().optional(),
  cookie: z.string().max(8192).optional(),
  pattern: z.string().max(2000).optional(),
  max_matches: z.number().int().min(1).max(2000).optional(),
  max_bytes: z.number().int().min(1).max(8_000_000).optional(),
  /** evidence.read �?按工具取最近一次产�?，与 evidence_id 二选一�?*/
  tool: z.string().max(64).optional(),
  /**
   * 2026-10-31 补洞：这三个键执行器一直在读，�?schema 没登记，于是
   * `exec.python` �?`code` 被摘成空 `input:{}` —�?连续 5 次空跑，24 分钟零产出�?
   * `sandbox_tools.ts` 读的�?code/script/requirements/timeout_s/memory_mb/network�?
   * 这里必须逐字对齐（新增键同步 test/tool-input-schema.test.ts）�?
   */
  code: z.string().max(200_000).optional(),
  script: z.string().max(200_000).optional(),
  requirements: z.array(z.string().max(200)).max(50).optional(),
  timeout_s: z.number().int().min(1).max(900).optional(),
  /**
   * 2026-11-06 补洞：`recon.scan_profile` 的全部意义就是调这几个旋钮，但只有 timeout_s
   * 被声明过——rate_limit / katana_depth / katana_duration_s / retries 会被 splitToolInput
   * 直接摘掉。而提示词正写着"设 timeout_s=30、rate_limit=20、katana 可放宽到 depth=8"，
   * 模型照做却毫无效果（工具回执还会说"已更新"），是最难查的一类假成功。
   * 范围与 tool-params.ts / scanProfileTool 的 bounds 对齐。
   */
  rate_limit: z.number().int().min(5).max(150).optional(),
  katana_depth: z.number().int().min(1).max(8).optional(),
  katana_duration_s: z.number().int().min(15).max(300).optional(),
  retries: z.number().int().min(0).max(3).optional(),
  memory_mb: z.number().int().min(64).max(8192).optional(),
  network: z.boolean().optional(),
  /** burp.history / burp.sitemap �?host 过滤：原来执行器固定�?target host，模型传 host 被静默摘掉�?*/
  host: z.string().trim().min(1).max(255).optional(),
  /** browser.network 的过滤条件（渲染期真实请求）�?*/
  resource_type: z.string().max(64).optional(),
  since_ms: z.number().int().min(0).max(86_400_000).optional(),
  include_post_data: z.boolean().optional(),
  tab: z.string().max(64).optional(),
  wait_ms: z.number().int().min(0).max(60000).optional(),
  wait_until: z.enum(["load", "domcontentloaded", "networkidle", "commit"]).optional(),
  wait_for_selector: z.string().max(500).optional(),
  urls: z.array(z.string().max(2048)).max(500).optional(),
  seeds: z.array(z.string().max(2048)).max(200).optional(),
  url_regex: z.string().max(1000).optional(),
  format: z.string().max(32).optional(),
  count: z.number().int().min(1).max(10000).optional(),
  concurrency: z.number().int().min(1).max(50).optional(),
  mode: z.string().max(64).optional(),
  op: z.string().max(64).optional(),
  operation: z.string().max(64).optional(),
  index: z.number().int().min(0).max(100000).optional(),
  key: z.string().max(256).optional(),
  value: z.string().max(8192).optional(),
  enabled: z.boolean().optional(),
  clear: z.boolean().optional(),
  reset: z.boolean().optional(),
  read: z.boolean().optional(),
  local_storage: z.unknown().optional(),
  session_storage: z.unknown().optional(),
  scope: z.unknown().optional(),
  via: z.string().max(64).optional(),
  provider: z.string().max(64).optional(),
  template: z.string().max(2000).optional(),
  analyze: z.string().max(64).optional(),
  bcheck: z.string().max(2000).optional(),
  attack_id: z.string().max(64).optional(),
  audit_id: z.string().max(64).optional(),
  crawl_id: z.string().max(64).optional(),
  /** burp.send_batch / burp.intruder 的批量载荷与攻击类型�?*/
  requests: z.array(z.unknown()).max(500).optional(),
  type: z.string().max(64).optional(),
  category: z.string().max(64).optional(),
  wait_timeout_ms: z.number().int().min(0).max(600000).optional(),
}).passthrough().refine((value) => ["body", "body_base64", "json", "form", "multipart"].filter((key) => value[key as keyof typeof value] !== undefined).length <= 1, {
  message: "use only one of body, body_base64, json, form, multipart",
});

export const toolInputSchema = toolInputObject;

/** 顶层键的权威清单（由 schema 自身导出，不再手抄）�?*/
export function declaredToolInputKeys(): string[] {
  return Object.keys(toolInputObject.shape).sort();
}

/**
 * 执行器白名单：摘�?schema 不认识的键，返回 {clean, ignored}�?
 *
 * `ignored` 不是错误——它会进下一轮的 ignored_keys 回执（带该工具的真实键表），
 * 让模型知�?这几个键被忽略了"，而不是整条请求消失�?
 */
/**
 * 通用注释键（2026-11-07，对照会话 1dd9ded9ed239711）。
 *
 * 模型常把"为什么发这一发"写进 `tool_requests[].input.reason`，而执行器白名单不认识它
 * → 被静默摘掉：既没生效，回执也没说，模型只能反复重写。这是 2026-10-28
 * `exec.python.code` 同类坑的复发，也是本场 31/40 轮 transition-rejected 的噪声来源之一。
 *
 * 契约（同步写进规则文档，防止开发者/模型误用）：
 *   - 理由写**外层** `tool_requests[].reason`（schema 已声明）或 `task_outcomes[].reason`；
 *   - `input` 只放执行参数；
 *   - 下面这几个键在 `splitToolInput` 里既不进 `clean`（不下传执行器），
 *     也不进 `ignored`（不算"参数写错"），单独作为 `annotations` 返回，由回执教学一次。
 */
export const TOOL_INPUT_ANNOTATION_KEYS = ["reason", "note", "comment", "why"] as const;
const TOOL_INPUT_ANNOTATION_SET = new Set<string>(TOOL_INPUT_ANNOTATION_KEYS);
export const TOOL_INPUT_ANNOTATION_HINT =
  "理由请写在外层 tool_requests[].reason（或 task_outcomes[].reason），不要写进 input；input 只放执行参数。";

export function splitToolInput(input: unknown): { clean: Record<string, unknown>; ignored: string[]; annotations: string[] } {
  if (!input || typeof input !== "object" || Array.isArray(input)) return { clean: {}, ignored: [], annotations: [] };
  const declared = new Set(declaredToolInputKeys());
  const clean: Record<string, unknown> = {};
  const ignored: string[] = [];
  const annotations: string[] = [];
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (TOOL_INPUT_ANNOTATION_SET.has(key)) { annotations.push(key); continue; }
    if (declared.has(key)) clean[key] = value;
    else ignored.push(key);
  }
  return { clean, ignored, annotations };
}
/**
 * 工具名唯一事实来源�?4 项，�?tools.ts �?BLACKBOX_TOOL_NAMES 同集合）�?
 *
 * �?Agent �?tool_requests[].tool �?Observer �?next_steps[].tool 都走这个枚举�?
 * 名字打错 = 整条请求被拒 + 回执教它该怎么写，而不是静默丢一步棋�?
 */
export const BLACKBOX_TOOL_ENUM = [
  "browser.open", "browser.screenshot", "browser.close", "evidence.read", "http.request", "http.diff", "burp.check", "burp.request", "burp.history", "burp.sitemap", "burp.entry", "burp.issues", "burp.ws_history", "burp.scope", "burp.intercept", "burp.decoder",
  "burp.send", "burp.repeater", "burp.organizer", "burp.collab_generate", "burp.collab_poll",
  "burp.scan", "burp.scan_status", "burp.scan_stop",
  "burp.info", "burp.control", "burp.options", "burp.cookies", "burp.storage", "burp.sitemap_issues", "burp.sitemap_add", "burp.scope_edit",
  "burp.send_batch", "burp.crawl", "burp.scan_issues", "burp.scan_report", "burp.intruder", "burp.intruder_send", "burp.compare", "burp.convert", "burp.proxy_rule", "burp.websocket", "burp.bchecks", "katana.crawl",
  "recon.subdomains", "recon.dns", "recon.http_probe", "recon.ports", "recon.historical_urls",
  "recon.content_discovery", "recon.nuclei",
  "recon.interactsh",
  "recon.parameters", "recon.js_endpoints", "recon.tls", "recon.api_routes", "recon.xss", "recon.sql",
  "recon.jwt", "recon.graphql", "recon.cms", "recon.secrets", "recon.sast", "recon.traffic_diff",
  "recon.wordlists", "recon.scan_profile", "recon.race_condition", "exec.python", "exec.bash",
  "fs.list", "fs.read", "fs.grep", "browser.storage", "browser.tab", "browser.network",
] as const;

export const mainSchema = z.object({
  // 2026-11-02：`summary` 曾经是必填 string，于是"输出撞到 max_tokens 上限、JSON 尾部被截掉"时
  // 整轮被判协议失败、本轮 tool_requests 全部丢弃（干净 e2e 会话 b9601629efd1f137 连吃两次，
  // 12 轮里白烧 2 轮，主 Agent 随后为躲协议错误干脆一轮发 0 个请求）。
  // 摘要缺失是"叙事缺失"，不该连累"动作"——给它空串默认值，让这一轮的工具动作照常执行。
  summary: z.string().max(16000).default(""),
  findings: z.array(findingSchema).max(50).default([]),
  hypotheses: z.array(z.object({ text, evidence_ids: ids, confidence: text })).default([]),
  required_tasks: z.array(z.union([text, coercedTaskSchema])).default([]),
  completed_tasks: ids.default([]), blocked_tasks: ids.default([]), failed_tasks: ids.default([]),
  task_outcomes: z.array(taskOutcomeSchema).default([]),
  advice_decisions: z.array(z.object({ advice_id: text, accepted: z.boolean(), reason: text, task_ids: ids })).default([]),
  evidence_queries: z.array(z.object({ evidence_id: text.optional(), task_id: text.optional(), url: z.string().url().optional() })
    .refine(q => Boolean(q.evidence_id || q.task_id || q.url))).max(20).default([]),
  continue: z.boolean().default(true), next_actions: ids.default([]),
  /**
   * WAF 战例回报：打穿一堵墙就记一条，落进项目级战例库（waf_bypasses 表）�?
   * 下一次遇到同厂商/同签名的墙时，主 Agent �?prompt 里会直接出现这条变体，先照抄再思考�?
   */
  waf_bypasses: z.array(z.object({
    vendor: text.optional(), vendor_name: text.optional(), signature: text.optional(),
    dimension: z.enum(["encoding", "param", "path", "method", "header", "raw", "chunked", "cover", "baseline", "other"]).optional(),
    step: text.optional(), tactic: text.optional(), payload: text.optional(), variant: text.optional(),
    host: text.optional(), evidence_id: text.optional(), note: text.optional(),
  }).refine(value => Boolean(value.tactic || value.payload || value.variant || value.step || value.note))).max(20).default([]),
  /**
   * 工具缺口上报：清单里没有的能力（或装了但被配置关闭的）在这里点名�?
   * 目的不是让模型抱怨，而是给操作员一条可执行的采�?配置清单�?
   * �?Agent 反复�?http.request 手搓某个扫描器的活，本身就是"缺工�?的证据�?
   * 同一缺口只记一次（desk �?need 去重），后续轮次�?context.tool_gaps 里回灌，避免每轮复读�?
   */
  tool_gaps: z.array(z.object({
    need: text,
    why: text.optional(),
    /** 模型认为最贴近的现有工具（可能不存在，desk 会与 74 项注册表核对后标�?missing）�?*/
    tool: z.string().trim().max(120).optional(),
    /** 现在用什么兜底（exec.python / fs.grep / burp.send …），让操作员知道阻塞程度�?*/
    alternative: z.string().trim().max(500).optional(),
    blocked_task: z.string().trim().max(120).optional(),
  })).max(10).default([]),
  tool_requests: z.array(z.object({
    tool: z.enum(BLACKBOX_TOOL_ENUM),
    task_id: text.optional(), reason: text.optional(), input: toolInputSchema,
    /** Deprecated and ignored: tools execute directly without per-action approval. */
    requires_confirmation: z.boolean().default(false),
  }).strict()).max(500).default([]),
});
export const observerSchema = z.object({
  /**
   * `evidence_ids` 必须可缺省（2026-11-10 现场实测）。
   *
   * 上面的运行时规则原文是"needs_evidence 不需要新的 evidence_ids——证据不足本身就是结论"，
   * 但 schema 把它写成必填数组，模型照规则省略就整份输出被判协议失败。采样 7 次里 3 次
   * 死在这一条上（`finding_reviews.0.evidence_ids: expected array, received undefined`），
   * 而观察者一次调用要 5 万输入 token——契约自相矛盾不能用"模型不听话"来结账。
   * 现在缺省为 []，"confirmed 必须有引用"仍由下面的 refine 守着。
   */
  finding_reviews: z.array(z.object({
    finding_id: text,
    status: z.enum(["needs_evidence", "reviewed", "confirmed", "rejected"]),
    reason: z.string().trim().max(2000).default(""),
    evidence_ids: ids.default([]),
  })
    .refine((review) => review.status !== "confirmed" || review.evidence_ids.length > 0, { message: "confirmed finding requires evidence_ids" })).max(50).default([]),
  review: z.string().max(16000), concerns: ids.default([]), suggestions: ids.default([]),
  /**
   * 精确点名下一步：工具必须来自注册表（打错名字这里就报错，不会流到�?Agent 变成废建议）�?
   * input 用该工具真正接受的键（见 tool-guide.ts）。desk 会把它折成一条带工具名的建议�?
   * �?Agent 下一轮在 critical_actions.advice 里直接看�?用哪个工具、打哪个目标、带什么参�?�?
   * 清单里确实没有的能力：tool 留空，只�?why 里写清楚要什么能力（等价于替�?Agent 报缺口）�?
   */
  next_steps: z.array(z.object({
    tool: z.enum(BLACKBOX_TOOL_ENUM).optional(),
    target: z.string().trim().max(2048).optional(),
    input: z.record(z.string(), z.unknown()).optional(),
    why: text,
  }).refine(step => Boolean(step.tool || step.why))).max(10).default([]),
  supplemental_tasks: z.array(z.union([text, taskSchema])).default([]),
  evidence_gaps: ids.default([]), should_continue: z.boolean().optional(),
  decision: z.enum(["continue", "finish", "pause"]).optional(),
  pause_reason: text.optional(),
}).superRefine((value, ctx) => {
  /**
   * `decision` 缺省不再判协议失败（2026-11-10 现场实测）。
   *
   * 旧规则要求 decision 与 should_continue 至少有一个，可提示词里只给了 decision 一个出口，
   * 模型漏写就整份作废——采样 7 次里 2 次死在这一句上（`Observer decision is required`），
   * 且其中一次是在"截断重试"成功后又被这条打回，等于两次调用全白烧。
   * 语义上缺省就是"继续"：Observer 是参谋，不靠一个可缺省字段来否决 1600 字审查。
   */
  if (value.decision === "pause" && !value.pause_reason) ctx.addIssue({ code: "custom", path: ["pause_reason"], message: "An explicit pause requires a concrete reason" });
  if (value.decision && value.should_continue !== undefined && value.should_continue !== (value.decision === "continue")) ctx.addIssue({ code: "custom", message: "Observer decision conflicts with should_continue" });
});


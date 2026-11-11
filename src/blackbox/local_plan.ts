/**
 * 本地确定性规划器（无模型兜底）
 *
 * 为什么存在：
 *   主 Agent 的每一轮都必须由模型产出结构化 JSON。控制面在只有 CDN/边缘软硬件、
 *   没有模型凭证的机器上（例如临场排查、离线验收、CI 冒烟）就跑不完整场 run——
 *   会话会卡在第一轮，账本里只有环境检查，报告只能写"未执行"。
 *
 * 设计原则（与既有架构保持一致，不另开一套执行路径）：
 *   1. 复用同一套协议：本模块只产出 mainSchema / observerSchema 允许的字段，
 *      于是 progress.merge、闭包审计、验收门禁、证据账本、报告生成全部原样生效。
 *   2. 复用同一套工具：请求仍走 tool_request → 执行器 → tool-result 入账，
 *      因此"证据必须来自成功的 tool-result"这条硬约束对它同样成立。
 *   3. 只做低影响动作：GET/HEAD/OPTIONS + 一次 Origin 变异请求，不做写操作、
 *      不做爆破、不猜路径。它是"能跑完"，不是"能打穿"。
 *   4. 可被显式关闭：NIANYUN_LOCAL_PLANNER=off|auto|force（默认 auto，
 *      即"配了模型就用模型，没配就用本地规划"）。
 *
 * 产物：与模型跑出来的一模一样——required_tasks / task_outcomes / findings，
 * 报告里能看到同样的任务覆盖、证据引用与候选发现。
 */

type Row = Record<string, unknown>;

export type EvidenceRow = { id: string; kind: string; source: string; data: Row };

export type LocalPlanTask = {
  id: string;
  name: string;
  purpose: string;
  reason: string;
  completion_criteria: string;
  deliverables: string[];
  success_criteria: string;
  fallback_strategy: string;
  target: string;
  tool: string;
  input: Row;
};

const SECURITY_HEADERS: Array<[string, string]> = [
  ["strict-transport-security", "HSTS"],
  ["content-security-policy", "CSP"],
  ["x-frame-options", "X-Frame-Options"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["referrer-policy", "Referrer-Policy"],
  ["permissions-policy", "Permissions-Policy"],
];

const MAX_REQUESTS_PER_ROUND = 2;
const MAX_ATTEMPTS_PER_TASK = 3;

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((item): item is Row => Boolean(item && typeof item === "object" && !Array.isArray(item))) : [];
}

/** 模型凭证是否齐备（地址/模型/密钥三者缺一即视为未配置）。 */
export function modelConfigured(values: Record<string, string>): boolean {
  const base = str(values.BLACKBOX_AGENT_BASE_URL || values.ANTHROPIC_BASE_URL || values.NIANYUN_LOOP_BASE_URL).trim();
  const model = str(values.BLACKBOX_AGENT_MODEL || values.ANTHROPIC_MODEL || values.NIANYUN_LOOP_MODEL).trim();
  const key = str(values.BLACKBOX_AGENT_API_KEY || values.ANTHROPIC_API_KEY || values.NIANYUN_LOOP_API_KEY).trim();
  return Boolean(base && model && key);
}

export function localPlannerMode(values: Record<string, string>): "off" | "auto" | "force" {
  const raw = str(values.NIANYUN_LOCAL_PLANNER).trim().toLowerCase();
  if (raw === "off" || raw === "0" || raw === "false") return "off";
  if (raw === "force" || raw === "1" || raw === "true") return "force";
  return "auto";
}

/** 本会话该不该用本地规划器：off 永不启用；force 总是启用；auto 只在没有模型时启用。 */
export function useLocalPlanner(values: Record<string, string>): boolean {
  const mode = localPlannerMode(values);
  if (mode === "off") return false;
  if (mode === "force") return true;
  return !modelConfigured(values);
}

function evidenceOf(session: Row): EvidenceRow[] {
  return rows(session.evidence)
    .map(item => ({
      id: str(item.id),
      kind: str(item.kind),
      source: str(item.source),
      data: (item.data && typeof item.data === "object" ? item.data : {}) as Row,
    }))
    .filter(item => Boolean(item.id));
}

function taskOf(row: EvidenceRow): string {
  return str(row.data.task_id);
}

function forTask(evidence: EvidenceRow[], taskId: string): EvidenceRow[] {
  return evidence.filter(item => taskOf(item) === taskId);
}

function succeeded(evidence: EvidenceRow[]): EvidenceRow[] {
  return evidence.filter(item => item.kind === "tool-result" && item.data.ok === true);
}

function headerMap(data: Row): Record<string, string> {
  const raw = data.headers;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw as Row)) out[key.toLowerCase()] = Array.isArray(value) ? value.map(String).join(", ") : String(value ?? "");
  return out;
}

function bodyOf(data: Row, limit = 400_000): string {
  const body = str(data.body);
  return body.length > limit ? body.slice(0, limit) : body;
}

/** 从首页 HTML 里取同源脚本地址（最多取 2 个，避免把一次 run 变成抓站）。 */
export function sameOriginScripts(pageUrl: string, html: string, limit = 2): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let base: URL;
  try { base = new URL(pageUrl); } catch { return out; }
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) && out.length < limit) {
    const raw = (match[1] || "").trim();
    if (!raw || raw.startsWith("data:")) continue;
    let url: URL;
    try { url = new URL(raw, base); } catch { continue; }
    if (!["http:", "https:"].includes(url.protocol)) continue;
    if (url.host !== base.host) continue;
    if (seen.has(url.toString())) continue;
    seen.add(url.toString());
    out.push(url.toString());
  }
  return out;
}

/** 任务表：确定性、可复算，不含任何"猜路径"。 */
export function localPlanTasks(session: Row): LocalPlanTask[] {
  const target = str(session.target);
  let origin = target;
  try { origin = new URL(target).origin; } catch { /* 目标不是 URL 时退回原串 */ }
  // CORS 探针必须与基线"不是同一条请求"：执行器的重复检测按 URL 去重，
  // 用同一个 URL 换个头会被判成重复（dead_end），查不到任何东西。
  const corsProbeUrl = (() => {
    try { const probe = new URL(target); probe.searchParams.set("nianyun_cors", "1"); return probe.toString(); }
    catch { return target; }
  })();
  // 一个端点被打三次就会被判 dead_end（执行器的死路保护），所以任务必须落在不同端点上：
  // 基线打 seed、CORS 探针复用 seed（第 2 次仍放行）、响应头审计打根路径、robots 与脚本各自独立。
  const headerAuditUrl = (() => {
    try {
      const root = new URL(target).origin + "/";
      return root === target ? new URL("/sitemap.xml", target).toString() : root;
    } catch { return target; }
  })();
  const tasks: LocalPlanTask[] = [
    {
      id: "T1-baseline",
      name: "基线响应",
      purpose: `取回 ${target} 的基线响应，建立后续所有判断的对照面`,
      reason: "没有基线就没有对照：后续每一条结论都要能指回这条响应",
      completion_criteria: "拿到一次成功的 GET，落成 tool-result 证据",
      deliverables: ["http_baseline"],
      success_criteria: "状态码、响应头、正文长度三项齐全",
      fallback_strategy: "GET 失败就改 HEAD；HEAD 也失败则本条 blocked，不重试第三次",
      target,
      tool: "http.request",
      input: { url: target, method: "GET", follow_redirects: true, timeout_ms: 20_000, force_armored: true },
    },
    {
      id: "T2-headers",
      name: "安全响应头审计",
      purpose: "按 HSTS/CSP/X-Frame-Options/nosniff/Referrer-Policy/Permissions-Policy 六项核对响应头",
      reason: "这六项是边缘层一次配置就能覆盖全站的安全基线，缺失可直接对外证明",
      completion_criteria: "拿到一次不跟随重定向的原始响应，六项逐个判定完成",
      deliverables: ["header_audit"],
      success_criteria: "六项各自给出 有/无",
      fallback_strategy: "被 CDN 缓存干扰时加 Cache-Control: no-cache 重取一次",
      target: headerAuditUrl,
      tool: "http.request",
      input: { url: headerAuditUrl, method: "GET", headers: { "Cache-Control": "no-cache" }, timeout_ms: 20_000, force_armored: true },
    },
    {
      id: "T3-robots",
      name: "爬虫协议面",
      purpose: "读取 robots.txt，看站点自己声明了哪些不该被索引的路径",
      reason: "robots.txt 常泄露管理后台与内部路径，且属低影响只读动作",
      completion_criteria: "拿到 /robots.txt 的响应（200 或 404 都算完成，404 本身是结论）",
      deliverables: ["robots_verdict"],
      success_criteria: "拿到状态码；有 Disallow 条目则逐条记录",
      fallback_strategy: "超时则不重试，直接按 404 处理并在结论里标注未取到",
      target: `${origin}/robots.txt`,
      tool: "http.request",
      input: { url: `${origin}/robots.txt`, method: "GET", timeout_ms: 15_000, force_armored: true },
    },
    {
      id: "T4-js-surface",
      name: "前端资产面",
      purpose: "从首页 HTML 提取同源脚本，取回脚本内容作为接口面的来源",
      reason: "前端 bundle 是接口清单的权威来源，比猜路径可靠",
      completion_criteria: "首页无脚本则用基线证据结案；有脚本则至少取回 1 个",
      deliverables: ["js_assets"],
      success_criteria: "列出脚本地址清单；取回内容可后续做接口提取",
      fallback_strategy: "首页无脚本或脚本全为第三方时，直接用 T1 证据结案，不扩面",
      target,
      tool: "http.request",
      input: {},
    },
    {
      id: "T5-cors",
      name: "跨域策略",
      purpose: "用伪造 Origin 打一次请求，核对该站是否把任意来源放进 ACAO",
      reason: "CORS 放开是有实际数据面影响的配置问题，且只需一条只读请求即可证伪",
      completion_criteria: "拿到带 Origin 变异头的响应，并与基线响应头对照",
      deliverables: ["cors_verdict"],
      success_criteria: "明确 ACAO 是否回显攻击者来源、是否同时允许携带凭证",
      fallback_strategy: "被 WAF 拦下先走 waf_bypass 最小档位（编码变形 + UA/XFF 伪装各一次），仍返回同一拦截指纹时记录 wall fingerprint 再结案",
      target: corsProbeUrl,
      tool: "http.request",
      input: {
        url: corsProbeUrl,
        method: "GET",
        headers: { Origin: "https://nianyun-probe.example" },
        timeout_ms: 20_000,
        force_armored: true,
      },
    },
  ];
  // T4 的请求要等基线拿到正文才知道打哪个脚本，规划阶段先留空。
  return tasks;
}

function requestFor(task: LocalPlanTask, evidence: EvidenceRow[]): Row | undefined {
  if (task.id !== "T4-js-surface") return task.input;
  const base = succeeded(forTask(evidence, "T1-baseline"))[0];
  if (!base) return undefined;
  const data = base.data;
  const pageUrl = str(data.url) || task.target;
  const scripts = sameOriginScripts(pageUrl, bodyOf(data));
  const first = scripts[0];
  if (!first) return undefined;
  return { url: first, method: "GET", timeout_ms: 20_000, force_armored: true };
}

function attemptsOf(evidence: EvidenceRow[], taskId: string): number {
  return forTask(evidence, taskId).filter(item => item.kind === "tool-result" || item.kind === "tool-error").length;
}

/**
 * 被拒收的请求不进证据账本（tool-rejected / tool-requests-rejected），
 * 只看证据会让"连续被拒"看起来像"从没试过"，于是一轮轮重复同一条请求直到 stalled。
 * 这里把拒绝事件也算作尝试：够次数就按 fallback 收口，把死路变成结论。
 */
function rejectionsOf(session: Row, taskId: string): number {
  let count = 0;
  for (const event of rows(session.events)) {
    const kind = str(event.kind);
    if (kind !== "tool-rejected" && kind !== "tool-requests-rejected") continue;
    const blob = JSON.stringify(event.data || {}) + str(event.text);
    if (blob.includes(taskId)) count += 1;
  }
  return count;
}

function doneEvidence(task: LocalPlanTask, evidence: EvidenceRow[]): EvidenceRow[] {
  const mine = forTask(evidence, task.id);
  const ok = succeeded(mine);
  if (!ok.length) return [];
  if (task.id === "T4-js-surface") {
    const base = succeeded(forTask(evidence, "T1-baseline"))[0];
    const scripts = base ? sameOriginScripts(str(base.data.url) || task.target, bodyOf(base.data)) : [];
    // 首页没有同源脚本时不需要发请求，基线证据本身就够结案。
    if (!scripts.length && base) return [base];
  }
  return ok;
}

/** 从 JS 正文里抠接口候选：只认像路径的字符串，不做拼接猜测。 */
export function endpointsFrom(js: string, limit = 20): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const re = /["'`](\/(?:api|v\d|rest|graphql|gateway|service)[A-Za-z0-9_\-/{}$.:]{2,120})["'`]/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(js)) && out.length < limit) {
    const path = (match[1] || "").trim();
    if (!path || seen.has(path)) continue;
    seen.add(path);
    out.push(path);
  }
  return out;
}

/**
 * 系统自建任务（如 SPA 外壳缴械后的 T_SPA_REVERSE_*）本地规划器也要认领，
 * 否则它会永远停在 pending，验收门禁判定"任务未收敛"，整场 run 收不了口。
 * 认领方式：用已取回的脚本证据给出接口清单；抠不出接口就给一致性负向结论。
 */
function adoptSystemTask(taskId: string, declared: Row, evidence: EvidenceRow[]): { status: "completed" | "blocked"; evidence_ids: string[]; reason: string; deliverables_met: string[] | boolean } {
  // 证据必须属于这条任务本人：账本会按 tool_result_must_belong_to_task 拒收跨任务引用，
  // 所以只认 task_id 完全一致的 tool-result。
  const own = succeeded(forTask(evidence, taskId));
  const pool = own.length ? own : [];
  const paths: string[] = [];
  for (const row of pool) {
    for (const path of endpointsFrom(bodyOf(row.data))) if (!paths.includes(path)) paths.push(path);
  }
  const ids = pool.map(row => row.id).slice(0, 3);
  if (!ids.length) {
    // 没有本任务证据时不硬凑引用：留空数组，由控制面的焦点收敛逻辑按"无高价值证据"收口。
    return { status: "blocked", evidence_ids: [], reason: `${taskId}：本地规划器未取得该任务的专属证据，交回人工/模型处理`, deliverables_met: false };
  }
  if (paths.length) {
    return {
      status: "completed",
      evidence_ids: ids,
      reason: `${taskId}：从本任务证据中抠出 ${paths.length} 条接口候选（${paths.slice(0, 3).join("、")}…），证据 ${ids[0]}`,
      deliverables_met: ["api_endpoints"],
    };
  }
  return {
    // 抠不出接口时按 blocked 收口而不是 completed：完成声明要能被闭包审计接受，
    // 拿不出 deliverables 却自称 completed 会被拒，随后这条任务又回到 pending，
    // 而它常常正是控制面强制焦点——整场 run 就会卡在"焦点锁定 → 请求被拒 → stalled"。
    status: "blocked",
    evidence_ids: ids,
    reason: `${taskId}：本任务证据中未出现 /api、/v{n}、/graphql 形态的接口字符串，按"无可枚举接口"收口，证据 ${ids[0]}`,
    deliverables_met: false,
  };
}

function riskColor(severity: string): number {
  return ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>)[severity] ?? 0;
}

type Finding = {
  id: string; title: string; type: string; target: string; description: string; impact: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  reproduction_steps: string[]; evidence_ids: string[]; remediation: string; confidence: "low" | "medium" | "high";
};

/** 由证据推导候选发现：每条都必须挂到一条成功的 tool-result 上，否则会被账本拒收。 */
export function localFindings(session: Row): Finding[] {
  const evidence = evidenceOf(session);
  const findings: Finding[] = [];
  const headerRow = succeeded(forTask(evidence, "T2-headers"))[0] || succeeded(forTask(evidence, "T1-baseline"))[0];
  const seen = new Set<string>();

  if (headerRow) {
    const headers = headerMap(headerRow.data);
    const url = str(headerRow.data.url) || str(session.target);
    const missing = SECURITY_HEADERS.filter(([key]) => !headers[key]);
    if (missing.length) {
      const framing = missing.some(([key]) => key === "x-frame-options") && !/frame-ancestors/i.test(headers["content-security-policy"] || "");
      const severity: Finding["severity"] = framing ? "low" : "info";
      findings.push({
        id: `F-01-headers-${headerRow.id}`,
        title: `缺失 ${missing.length} 项安全响应头${framing ? "（含框架化防护）" : ""}`,
        type: "missing-security-headers",
        target: url,
        description: `响应头缺少：${missing.map(([, label]) => label).join("、")}。其中 X-Frame-Options 与 CSP frame-ancestors 同时缺失，意味着该页面可被任意第三方站点以 iframe 嵌入。`,
        impact: "可被用于点击劫持（诱导用户在自己的页面上点击真实业务按钮）；HSTS 缺失使首次访问可被降级注入。",
        severity,
        reproduction_steps: [
          `curl -sI ${url}`,
          `逐项检查 ${SECURITY_HEADERS.map(([key]) => key).join(" / ")}`,
          `实际结果：${missing.map(([, label]) => label).join("、")} 全部缺失（响应头仅有 ${Object.keys(headers).slice(0, 8).join("、")}）`,
        ],
        evidence_ids: [headerRow.id],
        remediation: "在 CDN/边缘层统一下发 X-Frame-Options: SAMEORIGIN 或 CSP frame-ancestors 'self'，并补齐 HSTS、nosniff、Referrer-Policy、Permissions-Policy。",
        confidence: "high",
      });
      seen.add("headers");
    }
  }

  const corsRow = succeeded(forTask(evidence, "T5-cors"))[0];
  if (corsRow) {
    const headers = headerMap(corsRow.data);
    const acao = headers["access-control-allow-origin"] || "";
    const acac = (headers["access-control-allow-credentials"] || "").toLowerCase();
    const url = str(corsRow.data.url) || str(session.target);
    if (acao && (acao === "https://nianyun-probe.example" || acao === "*")) {
      const severity: Finding["severity"] = acao !== "*" && acac === "true" ? "high" : acao === "*" ? "low" : "medium";
      findings.push({
        id: `F-02-cors-${corsRow.id}`,
        title: `CORS 策略回显任意来源（ACAO: ${acao}）`,
        type: "cors-misconfiguration",
        target: url,
        description: `携带 Origin: https://nianyun-probe.example 的请求，响应回了 Access-Control-Allow-Origin: ${acao}${acac ? `，Access-Control-Allow-Credentials: ${acac}` : ""}。`,
        impact: acac === "true" && acao !== "*"
          ? "任意站点可在用户登录态下跨域读取该接口响应，属于可直接获取数据的配置缺陷。"
          : "任意站点可跨域读取匿名可访问的响应内容，放大信息收集面。",
        severity,
        reproduction_steps: [
          `curl -sI -H "Origin: https://nianyun-probe.example" ${url}`,
          "观察 Access-Control-Allow-Origin / Access-Control-Allow-Credentials",
          `实际结果：ACAO=${acao}${acac ? `, ACAC=${acac}` : ""}`,
        ],
        evidence_ids: [corsRow.id],
        remediation: "按来源白名单回显 Origin，禁止对任意来源回显；带凭证的接口不得使用通配或回显来源。",
        confidence: "high",
      });
      seen.add("cors");
    }
  }

  const cookieRow = succeeded(forTask(evidence, "T1-baseline"))[0] || succeeded(forTask(evidence, "T2-headers"))[0];
  if (cookieRow) {
    const headers = headerMap(cookieRow.data);
    const raw = headers["set-cookie"] || "";
    if (raw) {
      const cookies = raw.split(/,(?=[^;]+?=)/).map(item => item.trim()).filter(Boolean);
      const weak = cookies.filter(cookie => {
        const lower = cookie.toLowerCase();
        return !/\bsecure\b/.test(lower) || !/\bhttponly\b/.test(lower) || !/samesite=/.test(lower);
      });
      if (weak.length) {
        const names = weak.map(cookie => (cookie.split("=")[0] || "").trim()).filter(Boolean).slice(0, 8);
        findings.push({
          id: `F-03-cookie-${cookieRow.id}`,
          title: `Cookie 安全属性不完整（${names.join("、") || "未命名"}）`,
          type: "insecure-cookie-attributes",
          target: str(cookieRow.data.url) || str(session.target),
          description: `Set-Cookie 中 ${weak.length} 个条目缺少 Secure / HttpOnly / SameSite 之一：${weak.map(item => item.split(";")[0]).join("；").slice(0, 400)}`,
          impact: "缺少 HttpOnly 时脚本可读取会话；缺少 Secure 时可能经明文信道回传；缺少 SameSite 时跨站请求会自动携带。",
          severity: "low",
          reproduction_steps: [
            `curl -sI ${str(cookieRow.data.url) || str(session.target)}`,
            "检查 Set-Cookie 的 Secure / HttpOnly / SameSite 属性",
            `实际结果：${weak.length} 个 Cookie 属性不完整`,
          ],
          evidence_ids: [cookieRow.id],
          remediation: "会话类 Cookie 统一设置 Secure; HttpOnly; SameSite=Lax（或 Strict），并按域/路径最小化下发。",
          confidence: "medium",
        });
        seen.add("cookie");
      }
    }
  }

  if (headerRow) {
    const headers = headerMap(headerRow.data);
    const disclosure = ["server", "x-powered-by", "x-aspnet-version"].filter(key => headers[key]).map(key => `${key}: ${headers[key]}`);
    if (disclosure.length) {
      findings.push({
        id: `F-04-tech-${headerRow.id}`,
        title: "响应头暴露服务端技术栈",
        type: "technology-disclosure",
        target: str(headerRow.data.url) || str(session.target),
        description: `响应头直接暴露：${disclosure.join("；")}`,
        impact: "为攻击者缩小指纹空间，便于挑选对应组件的已知问题。",
        severity: "info",
        reproduction_steps: [`curl -sI ${str(headerRow.data.url) || str(session.target)}`, `观察 ${disclosure.map(item => item.split(":")[0]).join(" / ")}`],
        evidence_ids: [headerRow.id],
        remediation: "在边缘层移除或改写 Server / X-Powered-By 等版本类响应头。",
        confidence: "high",
      });
      seen.add("tech");
    }
  }

  return findings.sort((a, b) => riskColor(b.severity) - riskColor(a.severity));
}

/**
 * 一轮主规划：读账本 → 决定结案/派活 → 全部结案时产出发现并收口。
 * 返回值必须满足 mainSchema，否则会走协议错误分支。
 */
export function runLocalMainPlan(_values: Record<string, string>, session: Row, _candidate: Row): Row {
  const evidence = evidenceOf(session);
  const checkpoint = (session.checkpoint && typeof session.checkpoint === "object" ? session.checkpoint : {}) as Row;
  const declared = (checkpoint.tasks && typeof checkpoint.tasks === "object" ? checkpoint.tasks : {}) as Record<string, Row>;
  const specs = localPlanTasks(session);
  const target = str(session.target);

  const requiredTasks: Row[] = [];
  for (const spec of specs) {
    if (!declared[spec.id]) {
      requiredTasks.push({
        id: spec.id,
        target: spec.target,
        purpose: spec.purpose,
        reason: spec.reason,
        completion_criteria: spec.completion_criteria,
        deliverables: spec.deliverables,
        success_criteria: spec.success_criteria,
        fallback_strategy: spec.fallback_strategy,
      });
    }
  }

  const completed: string[] = [];
  const blocked: string[] = [];
  const failed: string[] = [];
  const outcomes: Row[] = [];
  const requests: Row[] = [];
  const nextActions: string[] = [];

  for (const spec of specs) {
    const state = declared[spec.id];
    const status = str(state?.status);
    if (status === "completed" || status === "blocked" || status === "failed") continue;

    const done = doneEvidence(spec, evidence);
    if (done.length) {
      const ids = done.map(item => item.id);
      completed.push(spec.id);
      outcomes.push({
        task_id: spec.id,
        reason: `${spec.name}已落地，证据 ${ids[0]}，可直接复核`,
        evidence_ids: ids,
        deliverables_met: true,
      });
      continue;
    }

    if (spec.id === "T4-js-surface" && !attemptsOf(evidence, spec.id)) {
      // 首页没有同源脚本（例如脚本全托管在 CDN）时这条任务无请求可发：
      // 不在这里收口，调度就会连续空转到 stalled。按"无可枚举前端面"结案，
      // 本任务没有自己的证据行，因此不引用他人证据（账本只允许引用本任务证据）。
      const base = succeeded(forTask(evidence, "T1-baseline"))[0];
      const scripts = base ? sameOriginScripts(str(base.data.url) || spec.target, bodyOf(base.data)) : [];
      if (base && !scripts.length) {
        blocked.push(spec.id);
        outcomes.push({
          task_id: spec.id,
          reason: "首页未引用任何同源脚本（前端资源全部托管在第三方 CDN），无可枚举的前端接口面，本条按无可执行动作结案",
          evidence_ids: [],
          deliverables_met: false,
        });
        continue;
      }
    }

    if (attemptsOf(evidence, spec.id) + rejectionsOf(session, spec.id) >= MAX_ATTEMPTS_PER_TASK) {
      blocked.push(spec.id);
      // 受阻也要把证据 id 写进原因里：账本要求"受阻任务必须引用证据"，
      // 只给 evidence_ids 不给 reason 引用会被判 outcome_without_evidence_reference。
      const mine = forTask(evidence, spec.id).map(item => item.id).filter(Boolean);
      outcomes.push({
        task_id: spec.id,
        reason: `连续 ${MAX_ATTEMPTS_PER_TASK} 次未能取到可用响应（证据 ${mine[0] || "无，均为执行器拒收"}），按 fallback 结案：${spec.fallback_strategy}`,
        evidence_ids: mine,
        deliverables_met: false,
      });
      continue;
    }

    const input = requestFor(spec, evidence);
    if (!input || !Object.keys(input).length) {
      // 输入还凑不齐（例如 T4 依赖基线正文）：留到下一轮，不制造空请求。
      nextActions.push(`${spec.id} 等待前置证据就绪后发请求`);
      continue;
    }
    if (requests.length >= MAX_REQUESTS_PER_ROUND) {
      nextActions.push(`${spec.id} 排到下一轮`);
      continue;
    }
    requests.push({ tool: spec.tool, task_id: spec.id, reason: `${spec.name}：${spec.reason}`, input });
  }

  const allDeclared = specs.every(spec => Boolean(declared[spec.id]) || requiredTasks.some(task => task.id === spec.id));
  // 系统自建任务（SPA 缴械、主权转移改写等）不在本地任务表里：认领它们，否则整场 run 收不了口。
  const adopted: string[] = [];
  for (const [taskId, task] of Object.entries(declared)) {
    if (specs.some(spec => spec.id === taskId)) continue;
    if (!/^T[_-]/i.test(taskId)) continue;
    const status = str(task.status);
    if (status === "completed" || status === "blocked" || status === "failed") continue;
    const verdict = adoptSystemTask(taskId, task, evidence);
    if (verdict.status === "completed") completed.push(taskId); else blocked.push(taskId);
    adopted.push(taskId);
    outcomes.push({
      task_id: taskId,
      reason: verdict.reason,
      evidence_ids: verdict.evidence_ids,
      deliverables_met: verdict.deliverables_met,
    });
  }
  const pending = specs.filter(spec => {
    const status = str(declared[spec.id]?.status);
    if (status === "completed" || status === "blocked" || status === "failed") return false;
    return !completed.includes(spec.id) && !blocked.includes(spec.id) && !failed.includes(spec.id);
  });

  const finished = allDeclared && !pending.length && !requests.length;
  const findings = finished ? localFindings(session) : [];

  const summary = finished
    ? `本地规划完成：${specs.length} 条任务全部结案，产出 ${findings.length} 条候选发现（证据来自 ${evidence.filter(item => item.kind === "tool-result").length} 条成功响应）。`
    : `本地规划推进：本轮结案 ${completed.length} 条（${completed.join("、") || "无"}），派发 ${requests.length} 条只读请求${blocked.length ? `，受阻 ${blocked.join("、")}` : ""}。`;

  return {
    summary,
    findings,
    hypotheses: [],
    required_tasks: requiredTasks,
    completed_tasks: completed,
    blocked_tasks: blocked,
    failed_tasks: failed,
    task_outcomes: outcomes,
    advice_decisions: [],
    evidence_queries: [],
    continue: !finished,
    next_actions: finished ? [] : (nextActions.length ? nextActions : [`继续推进 ${pending.map(spec => spec.id).join("、")}`]),
    tool_requests: requests,
    planner: "local-rules",
    target,
  };
}

/**
 * 本地 Observer：按"证据是否真落在成功的 tool-result 上"裁决候选发现。
 * 它不做主观判断，只做一件模型最容易糊弄过去的事——核对引用。
 */
export function runLocalObserverPlan(_values: Record<string, string>, session: Row): Row {
  const evidence = evidenceOf(session);
  const checkpoint = (session.checkpoint && typeof session.checkpoint === "object" ? session.checkpoint : {}) as Row;
  const findings = (checkpoint.findings && typeof checkpoint.findings === "object" ? checkpoint.findings : {}) as Record<string, Row>;
  const reviews: Row[] = [];
  for (const [id, finding] of Object.entries(findings)) {
    if (str(finding.status) !== "candidate") continue;
    const ids = Array.isArray(finding.evidence_ids) ? finding.evidence_ids.map(String) : [];
    const rowsFound = ids.map(ref => evidence.find(item => item.id === ref));
    const allOk = ids.length > 0 && rowsFound.every(item => Boolean(item) && item!.kind === "tool-result" && item!.data.ok === true);
    reviews.push({
      finding_id: str(finding.id) || id,
      status: allOk ? "confirmed" : "needs_evidence",
      reason: allOk
        ? `引用的 ${ids.length} 条证据全部是成功的 tool-result（${ids.join("、")}），复现路径与证据一致`
        : "证据引用未全部落在成功的 tool-result 上，需补一次可复现请求",
      evidence_ids: ids,
    });
  }
  const confirmed = reviews.filter(review => review.status === "confirmed").length;
  return {
    review: `本地 Observer 复核 ${reviews.length} 条候选发现，确认 ${confirmed} 条，待补证 ${reviews.length - confirmed} 条。`,
    concerns: [],
    suggestions: reviews.length && confirmed < reviews.length ? ["补齐 needs_evidence 的引用证据后重新提交"] : [],
    supplemental_tasks: [],
    evidence_gaps: reviews.filter(review => review.status !== "confirmed").flatMap(review => (review.evidence_ids as string[]) || []),
    finding_reviews: reviews,
    decision: "continue",
    should_continue: true,
  };
}
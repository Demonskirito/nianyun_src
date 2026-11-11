/**
 * 外部工具的 `input.params` 白名单：**唯一事实源**。
 *
 * 这张表原来长在 `tools.ts` 里（校验用），而给模型看的入参说明书在 `tool-guide.ts`
 * （另一份手写的文案）。两份各自演化，于是有了 2026-11-06 那次实测事故：
 *
 *   recon.content_discovery 传了 `threads` → 被 schema 摘掉 → 回执写「可用：url, params」
 *   → 模型理解为「并发不可调、只能传 url」→ 十九场会话里只有一场调过一次字典工具，
 *     其余全靠 67 次 http.request 手挑路径（paths.txt 里本来就有 .git/config、.env）。
 *
 * 现在两边都从这张表渲染：`toolOptions()` 用它校验，`tool-guide.ts` / 工具清单用它
 * 生成「这个工具到底能调什么」。加一个参数只改这里一处。
 */

export type ParamRule =
  | { flag: string; kind: "int"; min: number; max: number }
  | { flag: string; kind: "choice"; values: readonly string[] }
  | { flag: string; kind: "tokens"; pattern: RegExp; maxItems: number; maxLength: number }
  | { flag: string; kind: "text"; pattern: RegExp; maxLength: number; noTraversal?: boolean };

/**
 * Per-tool knobs the model may set through `input.params`. Every key is explicitly
 * allowlisted, bounded, and re-emitted as a CLI flag by the matching spec builder, so a
 * new flag cannot be smuggled in by a tool name the runtime does not know.
 */
export const TOOL_PARAMS: Record<string, Record<string, ParamRule>> = {
  "recon.nuclei": {
    severity: { flag: "-severity", kind: "tokens", pattern: /^(critical|high|medium|low|info|unknown)$/, maxItems: 6, maxLength: 8 },
    tags: { flag: "-tags", kind: "tokens", pattern: /^[a-z0-9_-]+$/, maxItems: 10, maxLength: 32 },
    templates: { flag: "-t", kind: "text", pattern: /^[A-Za-z0-9._,/-]+$/, maxLength: 256, noTraversal: true },
    // 动态参数协商（scan_profile）：慢目标把 timeout 提到 30s、rate 压到 20，才有机会出结果。
    timeout_s: { flag: "-timeout", kind: "int", min: 5, max: 60 },
    rate_limit: { flag: "-rate-limit", kind: "int", min: 5, max: 150 },
    concurrency: { flag: "-concurrency", kind: "int", min: 1, max: 25 },
    retries: { flag: "-retries", kind: "int", min: 0, max: 3 },
  },
  "recon.sql": {
    level: { flag: "--level", kind: "int", min: 1, max: 3 },
    risk: { flag: "--risk", kind: "int", min: 1, max: 2 },
    technique: { flag: "--technique", kind: "text", pattern: /^[BEUSTQbeustq]{1,6}$/, maxLength: 6 },
    dbms: { flag: "--dbms", kind: "text", pattern: /^[a-z0-9_-]{1,20}$/, maxLength: 20 },
    data: { flag: "--data", kind: "text", pattern: /^[^\u0000-\u001F\u007F]+$/, maxLength: 8192 },
    param: { flag: "-p", kind: "text", pattern: /^[A-Za-z0-9_\[\].-]{1,64}$/, maxLength: 64 },
  },
  "recon.content_discovery": {
    rate: { flag: "-rate", kind: "int", min: 1, max: 50 },
    threads: { flag: "-t", kind: "int", min: 1, max: 50 },
    extensions: { flag: "-e", kind: "tokens", pattern: /^[a-z0-9]{1,10}$/, maxItems: 10, maxLength: 10 },
    method: { flag: "-X", kind: "choice", values: ["GET", "POST"] },
  },
  "recon.ports": {
    ports: { flag: "-p", kind: "text", pattern: /^[0-9,\-]{1,200}$/, maxLength: 200 },
    rate: { flag: "-rate", kind: "int", min: 1, max: 300 },
  },
  "recon.http_probe": {
    ports: { flag: "-ports", kind: "text", pattern: /^[0-9,\-]{1,200}$/, maxLength: 200 },
    threads: { flag: "-threads", kind: "int", min: 1, max: 20 },
  },
  "recon.tls": {
    severity: { flag: "--severity", kind: "choice", values: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
  },
};

export function toolParamNames(tool: string): string[] {
  return Object.keys(TOOL_PARAMS[tool] || {});
}

/**
 * 一个参数的**人话约束**：`rate=int 1..50`、`severity=critical|high|...`。
 * 直接进工具说明书，模型不用猜范围（猜错的代价是整条请求被拒）。
 */
export function toolParamDoc(tool: string, key: string): string | undefined {
  const rule = TOOL_PARAMS[tool]?.[key];
  if (!rule) return undefined;
  switch (rule.kind) {
    case "int": return `${key}=整数 ${rule.min}..${rule.max}`;
    case "choice": return `${key}=${rule.values.join("|")}`;
    case "tokens": return `${key}=逗号分隔，≤${rule.maxItems} 项`;
    case "text": return `${key}=字符串（≤${rule.maxLength} 字符）`;
    default: return key;
  }
}

/** 一行参数速查，给工具清单与 Reject 回执共用。空字符串表示该工具不接受 params。 */
export function toolParamHint(tool: string): string {
  return toolParamNames(tool).map(key => toolParamDoc(tool, key)!).join(", ");
}

/**
 * 模型爱写、执行器也确实该认的顶层键 → params 键。
 *
 * `threads` 实测被连写两次（2026-11-06 bdd308655a4c65b8）：它对 ffuf / httpx 都是正当
 * 参数，但只在 params 里生效。与其让模型记住「并发要放 params」，不如在这里折进去——
 * 语义相同的两种写法都收，回执里写清最终生效值。
 */
const TOP_LEVEL_PARAM_ALIASES: Record<string, Record<string, string>> = {
  "recon.content_discovery": { threads: "threads" },
  "recon.http_probe": { threads: "threads" },
  "recon.ports": { threads: "rate" },
};

/** 把顶层别名折进 params（显式 params 优先，不覆盖模型自己写的值）。 */
export function foldTopLevelParams(tool: string, input: Record<string, unknown>, params: Record<string, unknown>): Record<string, unknown> {
  const aliases = TOP_LEVEL_PARAM_ALIASES[tool];
  if (!aliases) return params;
  const folded = { ...params };
  let changed = false;
  for (const [from, to] of Object.entries(aliases)) {
    if (input[from] === undefined || folded[to] !== undefined) continue;
    folded[to] = input[from];
    changed = true;
  }
  return changed ? folded : params;
}

/** 吃 `input.wordlist` 的工具（不给就用内置默认字典）。 */
const WORDLIST_TOOLS = new Set(["recon.content_discovery", "recon.api_routes"]);

/**
 * 工具清单里那一行"它能调什么"。
 *
 * 之前清单只有 `名字[层/w权重] 用途`，模型想知道能不能指定字典/并发只能试一次——
 * 试错的代价是整条请求被摘键或拒收。这里把可调项直接写在清单行上。
 */
export function toolInputHint(tool: string): string | undefined {
  const bits: string[] = [];
  if (WORDLIST_TOOLS.has(tool)) bits.push("wordlist");
  const params = toolParamNames(tool);
  if (params.length) bits.push(`params(${params.join("/")})`);
  return bits.length ? bits.join(" + ") : undefined;
}

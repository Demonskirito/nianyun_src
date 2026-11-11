import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

const PLACEHOLDER = /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/;

const PROXY_CLEAR_KEYS = new Set([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
]);

function empty(val: unknown): boolean {
  return val === null || val === undefined || (typeof val === "string" && val.trim() === "");
}

function put(out: Record<string, string>, key: string, val: unknown): void {
  if (empty(val)) {
    if (PROXY_CLEAR_KEYS.has(key)) out[key] = "";
    return;
  }
  if (typeof val === "boolean") {
    out[key] = val ? "true" : "false";
    return;
  }
  const s = String(val);
  if (PLACEHOLDER.test(s.trim())) return;
  out[key] = s;
}

/**
 * 期望值是「一整段 JSON 文档」的键。
 *
 * `BLACKBOX_RULES_DOCUMENT` 的消费方只认 JSON 文本（rules.ts 的 parseDocument 直接
 * JSON.parse）。但操作员最自然的写法是 YAML 嵌套：
 *
 * ```yaml
 * BLACKBOX_RULES_DOCUMENT:
 *   budgets:
 *     tool_calls: 90
 * ```
 *
 * 这种写法走原来的摊平逻辑会散成 `tool_calls: "90"` —— 文档键本身消失，
 * parseDocument 拿到空字符串，**规则静默回退到默认值**。2026-11-05 实测就是这么
 * 踩的：把 budgets 写进 tools.env.yaml 改了两轮，落库的仍然是默认 120 权重。
 * 所以这里显式序列化，让"看起来配好了"真的等于"生效了"。
 */
const JSON_DOCUMENT_KEYS = new Set(["BLACKBOX_RULES_DOCUMENT"]);

function flatten(raw: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  /**
   * 只摊一层是个坑：`tools:` 下面的 `arl:` 分组会把整组键压成一个字符串
   * "[object Object]"，于是 BURP_PROXY_REQUIRED、KATANA_PATH 这类键在
   * "看起来配好了"的文件里全部等于没配（环境检查里表现为
   * "Burp proxy is not configured"，而地址明明写在文件里）。
   * 改为递归摊平：同名键后者覆盖前者，超过 4 层停止。
   */
  const walk = (block: Record<string, unknown>, depth: number): void => {
    if (depth > 4) return;
    for (const [k, v] of Object.entries(block)) {
      if (v && typeof v === "object" && !Array.isArray(v)) {
        if (JSON_DOCUMENT_KEYS.has(k)) { out[k] = JSON.stringify(v); continue; }
        walk(v as Record<string, unknown>, depth + 1);
        continue;
      }
      put(out, k, v);
    }
  };
  for (const [section, block] of Object.entries(raw)) {
    if (section === "version" || section === "required") continue;
    if (block && typeof block === "object" && !Array.isArray(block)) {
      if (JSON_DOCUMENT_KEYS.has(section)) { out[section] = JSON.stringify(block); continue; }
      walk(block as Record<string, unknown>, 0);
      continue;
    }
    // 顶层标量也要收：原实现只走对象段，于是"平铺写法"的整个文件解析出 0 个键，
    // 每一行都静默失效（容器里 data/config/tools.env.yaml 就是这个状态：12 行配置、
    // 12 个键全部没生效，而 overlay 里的旧值照旧生效，改文件看不出任何反应）。
    put(out, section, block);
  }
  return out;
}

export type ToolsEnv = {
  path: string;
  values: Record<string, string>;
  /** 加载期发现的问题（文件读不出来、解析出 0 个键、被 overlay 覆盖……）。供控制台提示，不阻断启动。 */
  warnings: string[];
  mergeInto: (env: Record<string, string>, opts?: { overwrite?: boolean }) => void;
};

export function defaultToolsEnvPath(repoRoot: string): string {
  return join(repoRoot, "tools.env.yaml");
}

export function loadToolsEnv(path: string): ToolsEnv {
  let values: Record<string, string> = {};
  const warnings: string[] = [];
  if (existsSync(path)) {
    try {
      const text = readFileSync(path, "utf8");
      const raw = parseYaml(text) as unknown;
      // 顶层是列表时不能当配置用：会把 "0"/"1"/"2" 变成环境变量名。
      if (Array.isArray(raw)) {
        warnings.push(`${path} 顶层是列表而不是映射（键: 值），本文件当前不生效。`);
      } else if (raw && typeof raw === "object") values = flatten(raw as Record<string, unknown>);
      // "文件在、内容有、键为 0"是最贵的一类故障：操作员改完看不到任何反应，
      // 排查方向会跑到代码上去（2026-11-05 实际花了三轮）。
      const meaningful = text.split("\n").filter(line => line.trim() && !line.trim().startsWith("#")).length;
      if (!Object.keys(values).length && meaningful) {
        warnings.push(`${path} 有 ${meaningful} 行内容，但没有解析出任何配置键；这个文件当前不生效。`);
      }
    } catch (error) {
      values = {};
      warnings.push(`${path} 解析失败（${error instanceof Error ? error.message : String(error)}），本文件当前不生效。`);
    }
  }
  return {
    path,
    values,
    warnings,
    mergeInto(env, opts = {}) {
      const overwrite = opts.overwrite !== false;
      for (const [k, v] of Object.entries(values)) {
        if (!overwrite && env[k] !== undefined && String(env[k]).trim() !== "") continue;
        env[k] = v;
      }
    },
  };
}

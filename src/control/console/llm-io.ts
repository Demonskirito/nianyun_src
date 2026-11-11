import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import type { Config } from "../../shared/config.js";
import { atomicWrite } from "../../shared/fsutil.js";

export const GROUPS: Record<string, string[]> = {
  asset: [
    "ASSET_AGENT_BASE_URL", "ASSET_AGENT_MODEL", "ASSET_AGENT_API_KEY",
    "ASSET_AGENT_PROMPT", "ASSET_AGENT_RULE_VERSION", "BROWSER_PROXY",
  ],
  arl: ["ARL_URL", "ARL_TOKEN"],
  fofa: ["FOFA_URL", "FOFA_KEY", "FOFA_PROXY"],
  blackbox: [
    "BLACKBOX_AGENT_BASE_URL", "BLACKBOX_AGENT_MODEL", "BLACKBOX_AGENT_API_KEY",
    "BLACKBOX_AGENT_PROMPT", "BLACKBOX_OBSERVER_PROMPT",
    "BLACKBOX_AGENT_TIMEOUT_MS", "BLACKBOX_AGENT_MAX_TOKENS",
    // LLM 出口与 Burp 抓包通道分离：这三个键必须能从 Desk 读写，否则只能手改容器 overlay。
    "BLACKBOX_AGENT_PROXY_URL", "BLACKBOX_AGENT_NO_PROXY", "BLACKBOX_AGENT_IGNORE_HTTPS_ERRORS",
    "BLACKBOX_RUNTIME_RULES", "BLACKBOX_OBSERVER_RUNTIME_RULES", "BLACKBOX_RULES_DOCUMENT",
    "BURP_PROXY_URL", "BURP_PROXY_REQUIRED", "BURP_IGNORE_HTTPS_ERRORS", "BURP_BRIDGE_URL", "BURP_BRIDGE_TOKEN",
    // 高危参数开关与 sidecar 沙箱地址：都属于"运行期可调"，放这里是为了能在 Desk 上开关而不用改文件重启。
    // 注意：--os-shell/--sql-shell/--eval/--code 不受这个开关影响，仍由工具层硬拒。
    "BLACKBOX_ALLOW_INTERACTIVE_EXEC", "SANDBOX_URL",
    "KATANA_PATH", "HTTPX_PATH", "NUCLEI_PATH", "INTERACTSH_URL", "INTERACTSH_CLIENT_PATH", "INTERACTSH_TOKEN",
    "ARJUN_PATH", "SUBJS_PATH", "TESTSSL_PATH", "KITERUNNER_PATH", "DALFOX_PATH", "SQLMAP_PATH",
    "JWT_TOOL_PATH", "GRAPHQL_COP_PATH", "WPSCAN_PATH", "TRUFFLEHOG_PATH", "SEMGREP_PATH",
    "SUBFINDER_PATH", "DNSX_PATH", "GAU_PATH", "NAABU_PATH", "FFUF_PATH", "WAYBACKURLS_PATH",
    "NIANYUN_WORDLIST_ROOT",
  ],
};

const SECRET_SUFFIX = ["KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"];

export function overlayPath(cfg: Config): string {
  return join(cfg.data_dir, "console", "llm.yaml");
}

function valuesOf(cfg: Config): Record<string, string> {
  const raw = cfg.tools_env?.values || {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) out[k] = v == null ? "" : String(v);
  return out;
}

function redact(key: string, value: string): string {
  if (!value) return "";
  if (!SECRET_SUFFIX.some((s) => key.toUpperCase().includes(s))) return value;
  if (value.length <= 8) return "••••";
  return `••••${value.slice(-4)}`;
}

export function snapshot(cfg: Config): Record<string, unknown> {
  const vals = valuesOf(cfg);
  const out: Record<string, unknown> = {};
  for (const [group, keys] of Object.entries(GROUPS)) {
    const block: Record<string, unknown> = {};
    for (const key of keys) {
      const val = vals[key] || "";
      const secret = SECRET_SUFFIX.some((s) => key.toUpperCase().includes(s));
      block[key] = {
        set: Boolean(val.trim()),
        value: secret ? "" : val,
        preview: secret ? redact(key, val) : val,
      };
    }
    out[group] = block;
  }
  return out;
}

export function loadOverlay(cfg: Config): void {
  const path = overlayPath(cfg);
  if (!existsSync(path)) return;
  try {
    const raw = parseYaml(readFileSync(path, "utf8")) || {};
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
    if (!cfg.tools_env || typeof cfg.tools_env.values !== "object") return;
    /**
     * overlay 是"运行期设置"，优先级高于 tools.env.yaml，这个方向本身没问题。
     * 问题是它**静默**覆盖：操作员改了 tools.env.yaml 却毫无反应，因为同名键在
     * overlay 里有一份旧值（2026-11-05 改预算就是这么被吃掉的）。
     * 这里把"值不同且被覆盖"的键记下来，由会话启动时提示一次。
     */
    const shadowed: string[] = [];
    for (const [key, val] of Object.entries(raw as Record<string, unknown>)) {
      if (val == null) continue;
      const next = String(val);
      const previous = cfg.tools_env.values[String(key)];
      if (previous !== undefined && previous !== next) shadowed.push(String(key));
      cfg.tools_env.values[String(key)] = next;
    }
    if (shadowed.length) {
      const note = `Desk 设置覆盖了 tools.env.yaml 里的同名键：${shadowed.join("、")}（生效值来自 ${path}）。`;
      cfg.tools_env.warnings ||= [];
      cfg.tools_env.warnings.push(note);
      console.warn(`[config] ${note}`);
    }
  } catch {
    /* ignore */
  }
}

export function applyPayload(cfg: Config, payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("llm settings must be an object");
  }
  const allowed = new Set(Object.values(GROUPS).flat());
  if (!cfg.tools_env) throw new Error("tools.env is not loaded");
  if (!cfg.tools_env.values) cfg.tools_env.values = {};
  const path = overlayPath(cfg);
  let current: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      const raw = parseYaml(readFileSync(path, "utf8")) || {};
      if (raw && typeof raw === "object" && !Array.isArray(raw)) current = raw as Record<string, unknown>;
    } catch {
      current = {};
    }
  }
  for (const [key, raw] of Object.entries(payload as Record<string, unknown>)) {
    if (!allowed.has(key) || raw == null) continue;
    const text = String(raw);
    const secret = SECRET_SUFFIX.some((s) => key.toUpperCase().includes(s));
    if (secret && (!text.trim() || text.startsWith("••••"))) continue;
    cfg.tools_env.values[key] = text;
    current[key] = text;
  }
  mkdirSync(join(cfg.data_dir, "console"), { recursive: true });
  atomicWrite(path, stringifyYaml(current, { sortMapEntries: true }));
  return snapshot(cfg);
}

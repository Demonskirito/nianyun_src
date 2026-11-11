/**
 * 物理边界拦截器（Pre-flight Blocker）。
 *
 * 沙箱没有 raw TCP、没有 DNS 解析：`naabu`/`nmap`/`masscan` 打端口、`subfinder`/`dnsx`/`dig` 查域名，
 * 在 job 容器里必然失败。但失败发生在**容器启动后**，代价是：起容器 ~0.8s、脚本跑到超时、
 * 一轮预算（tool_calls 权重）、外加模型误判成"这里也被挡住"而去重试。
 *
 * 所以在**解析阶段**就掐死：看到越界命令直接返回 exit_code=126 + stderr，容器根本不起。
 * 这不是安全策略，是**能力边界前置**——把文档里的"不可用"变成会说话的报错。
 *
 * 判定只做两件事，不做通用代码分析：
 * 1. bash：命令位置出现被禁 CLI（用行首/分隔符后的词边界，避免误伤 `grep naabu`）；
 * 2. python：调用 socket 的 DNS/raw-connect 接口，或 subprocess 调被禁 CLI。
 */
import { reject } from "./tool-errors.js";

export type BlockedCommand = {
  /** 命中的原始片段。 */
  match: string;
  /** 为什么不可用（一句话）。 */
  why: string;
  /** 该改用哪个控制面工具。 */
  use: string;
};

export type PreflightBlock = {
  blocked: true;
  exit_code: 126;
  stderr: string;
  hints: BlockedCommand[];
};

/** 沙箱里不存在的底层能力 → 对应控制面工具。 */
const BLOCKED_BINARIES: Array<{ name: string; why: string; use: string }> = [
  { name: "naabu", why: "沙箱没有 raw TCP 端口扫描能力", use: "recon.ports" },
  { name: "masscan", why: "沙箱没有 raw socket / 需要 CAP_NET_RAW", use: "recon.ports" },
  { name: "zmap", why: "沙箱没有 raw socket", use: "recon.ports" },
  { name: "nmap", why: "沙箱没有 raw socket（connect 扫描也会被 egress 代理挡住）", use: "recon.ports" },
  { name: "hping3", why: "沙箱没有 raw socket", use: "recon.ports" },
  { name: "unicornscan", why: "沙箱没有 raw socket", use: "recon.ports" },
  { name: "subfinder", why: "沙箱没有外部 DNS，枚举不到子域", use: "recon.subdomains" },
  { name: "dnsx", why: "沙箱没有 DNS 解析", use: "recon.dns" },
  { name: "dig", why: "沙箱没有 DNS 解析器", use: "recon.dns" },
  { name: "nslookup", why: "沙箱没有 DNS 解析器", use: "recon.dns" },
  { name: "host", why: "沙箱没有 DNS 解析器", use: "recon.dns" },
  { name: "traceroute", why: "沙箱没有 raw ICMP", use: "recon.dns" },
  { name: "ping", why: "沙箱没有 raw ICMP", use: "recon.http_probe" },
];

/** python 里等价于"底层网络"的调用。 */
const BLOCKED_PYTHON: Array<{ pattern: RegExp; label: string; why: string; use: string }> = [
  { pattern: /socket\.gethostbyname|socket\.gethostbyaddr|socket\.getaddrinfo/, label: "socket DNS 解析", why: "沙箱没有 DNS 解析", use: "recon.dns" },
  { pattern: /dns\.resolver|import\s+dns\b|from\s+dns\s+import/, label: "dnspython", why: "沙箱没有 DNS 解析", use: "recon.dns" },
  { pattern: /socket\.create_connection|\.connect\(\s*\(\s*['"][^'"]+['"]\s*,\s*\d{2,5}\s*\)\s*\)/, label: "raw TCP 连接", why: "沙箱出站只有 MITM 代理，直连目标端口会被阻断", use: "recon.ports" },
];

/** 命令出现在"命令位置"（行首、; | & ( ` 之后）而不是 grep 的参数里。 */
function commandPattern(name: string): RegExp {
  return new RegExp(`(?:^|[;&|(\\n]\\s*|\\|\\|\\s*)(?:sudo\\s+|timeout\\s+\\S+\\s+)?${name}(?![\\w.-])`, "i");
}

function snippet(source: string, index: number, length: number): string {
  const from = Math.max(0, index - 24);
  return source.slice(from, Math.min(source.length, index + length + 24)).replace(/\s+/g, " ").trim();
}

/** bash 侧：扫命令位置。 */
function scanBash(source: string): BlockedCommand[] {
  const hits: BlockedCommand[] = [];
  for (const binary of BLOCKED_BINARIES) {
    const matcher = commandPattern(binary.name);
    const match = matcher.exec(source);
    if (!match) continue;
    hits.push({ match: snippet(source, match.index, match[0].length), why: binary.why, use: binary.use });
  }
  return hits;
}

/** python 侧：扫底层网络调用 + subprocess 调被禁 CLI。 */
function scanPython(source: string): BlockedCommand[] {
  const hits: BlockedCommand[] = [];
  for (const rule of BLOCKED_PYTHON) {
    const match = rule.pattern.exec(source);
    if (!match) continue;
    hits.push({ match: snippet(source, match.index, match[0].length), why: rule.why, use: rule.use });
  }
  // subprocess/os.system 调被禁 CLI（用引号包着也算）
  for (const binary of BLOCKED_BINARIES) {
    const matcher = new RegExp(`(?:subprocess\\.\\w+|os\\.system|os\\.popen|check_output|run\\()[^\\n]{0,80}?\\b${binary.name}\\b`, "i");
    const match = matcher.exec(source);
    if (!match) continue;
    hits.push({ match: snippet(source, match.index, match[0].length), why: binary.why, use: binary.use });
  }
  return hits;
}

/**
 * 解析阶段判定。命中即返回 126 + stderr；未命中返回 undefined（正常进沙箱）。
 * `lang` 与 `exec.*` 工具一一对应。
 */
export function preflightBlock(lang: "python" | "bash", source: string): PreflightBlock | undefined {
  const code = String(source || "");
  if (!code.trim()) return undefined;
  const hints = lang === "bash" ? scanBash(code) : [...scanPython(code), ...scanBash(code)];
  if (!hints.length) return undefined;
  const unique = hints.filter((hint, index) => hints.findIndex(other => other.use === hint.use && other.why === hint.why) === index);
  const stderr = [
    "BLOCKED: Raw TCP/DNS not available in sandbox.",
    ...unique.map(hint => `  - ${hint.why}（命中：${hint.match}）→ 用 ${hint.use}`),
    "改法：在脚本里写 /state/rpc/requests.jsonl 排队（一行一条 {\"tool\":\"recon.ports\",\"input\":{...}}），控制面会替你跑并把结果放进 data.rpc_results。",
  ].join("\n");
  return { blocked: true, exit_code: 126, stderr, hints: unique };
}

/** 工具层用：命中直接 reject（类型为"模型可修"，不计预算、不进重试）。 */
export function blockOrReject(lang: "python" | "bash", source: string): void {
  const block = preflightBlock(lang, source);
  if (block) throw reject(`${block.stderr}\n（exit_code=${block.exit_code}；容器未启动，本次未消耗预算）`);
}
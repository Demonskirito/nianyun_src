/**
 * 三层漏斗的路由规则（docs/agent-constraints-audit.md §14）。
 *
 * 第一层 Orchestrator：只思考、发号施令（agent.ts / context.ts / progress.ts）。
 * 第二层 Tactical（控制面工具）：标准动作，低延迟、可审计、自动入证据（recon.* / http.request / burp.* / browser.*）。
 * 第三层 Strategic（沙箱 exec.*）：标准工具做不了的——加密参数、签名、并发竞争、多步串联、自定义依赖。
 *
 * 这里只做两件"可判定"的事：
 * 1. toolLayer()：给每条工具结果打层标签，报告里能看出漏斗用量。
 * 2. trivialPassthrough()：识别"把标准 CLI 原样塞进沙箱"这种绕远路，直接拒绝并指向战术工具。
 */

export type ExecutionLayer = "orchestrator" | "tactical" | "strategic";

const STRATEGIC_PREFIXES = ["exec."];

/** 沙箱镜像里装的 CLI → 控制面对应的战术工具。用于识别"绕远路"。 */
export const BUNDLED_CLI_TO_TACTICAL: Record<string, string> = {
  httpx: "recon.http_probe",
  ffuf: "recon.content_discovery",
  nuclei: "recon.nuclei",
  katana: "katana.crawl",
  sqlmap: "recon.sql",
  dalfox: "recon.xss",
  subfinder: "recon.subdomains",
  dnsx: "recon.dns",
  naabu: "recon.ports",
  gau: "recon.historical_urls",
};

export function toolLayer(tool: string): ExecutionLayer {
  const name = String(tool || "").trim().toLowerCase();
  if (STRATEGIC_PREFIXES.some(prefix => name.startsWith(prefix))) return "strategic";
  // 其余全部是控制面工具；orchestrator 层不直接执行工具（它只产出 tool_requests）。
  return "tactical";
}

type Trivial = { tool: string; hint: string };

/** 一行 bash、没有管道/重定向/命令替换：只是把标准 CLI 包了一层。 */
function bareBashCommand(script: string): { command: string; args: string } | undefined {
  const lines = script
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith("#"));
  if (lines.length !== 1) return undefined;
  const line = lines[0]!;
  // 有任何 shell 组合能力就不算"裸调用"：那种脚本值得进沙箱。
  if (/[|;&><]|`|\$\(/.test(line)) return undefined;
  const match = line.match(/^([A-Za-z0-9_.-]+)(\s+.*)?$/);
  if (!match) return undefined;
  const command = match[1]!;
  const args = (match[2] || "").trim();
  if (!BUNDLED_CLI_TO_TACTICAL[command]) return undefined;
  return { command, args };
}

/** 单发 HTTP 请求的 Python 片段（没有循环/函数/重试逻辑）。 */
function barePythonHttp(code: string): string | undefined {
  const lines = code.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith("#"));
  if (lines.length > 4) return undefined;
  if (/\b(def|for|while|async|lambda|class)\b/.test(code)) return undefined;
  if (/requests\.(get|post|put|delete|patch|head|options|request)\s*\(/.test(code) || /urllib\.request\.urlopen\s*\(/.test(code)) {
    return "http.request";
  }
  return undefined;
}

/**
 * 判断这次 exec 是不是"标准动作套了层壳"。
 * 命中的调用会被 reject（输入错误类，不计预算），并给出该用的战术工具。
 */
export function trivialPassthrough(tool: string, input: Record<string, unknown>): Trivial | undefined {
  if (input?.force_sandbox === true) return undefined;
  const lang = tool === "exec.python" ? "python" : "bash";
  if (lang === "bash") {
    const bare = bareBashCommand(String(input?.script ?? input?.code ?? ""));
    if (!bare) return undefined;
    const tactical = BUNDLED_CLI_TO_TACTICAL[bare.command]!;
    return {
      tool: tactical,
      hint: `沙箱里裸调 ${bare.command} 属于绕远路：直接用 ${tactical}（不起容器、自动入证据、参数受校验）。`
        + `沙箱留给标准工具做不了的场景（加密/签名逆向、并发竞争、多步串联、自定义依赖）；确实需要 CLI 原样跑就带 force_sandbox=true。`,
    };
  }
  const httpTool = barePythonHttp(String(input?.code ?? ""));
  if (!httpTool) return undefined;
  return {
    tool: httpTool,
    hint: `单发 HTTP 请求用 ${httpTool}（控制面直发、自动带项目 Cookie、结果进证据）。`
      + `只有需要自定义签名/会话链/并发竞争时才用沙箱；确实要这么做就带 force_sandbox=true。`,
  };
}
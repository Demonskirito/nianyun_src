/**
 * "通讯电台"：沙箱脚本 ↔ 控制面工具之间的统一 RPC 协议。
 *
 * 为什么不是 HTTP RPC：job 容器的网络只有一个出口（`sandbox:8899` → Burp），
 * `NO_PROXY` 故意留空，连沙箱服务自己的 8790 都到不了（实测 502）。
 * 与其在"全流量必过 MITM"上开一个洞，不如用已经存在的东西传话。
 *
 * **一个队列，两种模式**（v2 收敛，旧的双队列已废弃）：
 *
 *   /state/rpc/dispatch.jsonl   一行一条，字段区分行为
 *   /state/rpc/dispatch_cursor.json   已消费条数
 *
 *   {"tool":"http.request","input":{...}}                      mode 缺省 = standard
 *   {"tool":"recon.race_condition","input":{...},"mode":"concurrent","threads":20}
 *
 * 载荷增强只有一条规则：**脚本算出来的值直接写进 input**，控制面原样用，不做优先级合并。
 *
 *   脚本侧：  headers = {"X-Sign": sig, "Cookie": f"sid={sid}"}
 *             call_tool("http.request", url=..., method="POST", headers=headers)
 *   控制面：  input 原样透传给工具；http.request 自己的项目 Cookie 罐仍会叠加（显式 Cookie 优先）。
 *
 * 所以不再有 context_override / from_state / 状态文件读取——那些是"在错误的层解决错误的层的问题"。
 */

/** 允许通过 RPC 调用的工具：只读/探测类，且天然有界。 */
export const RPC_WHITELIST = [
  "recon.wordlists", "recon.scan_profile", "fs.list", "fs.read", "fs.grep",
  "http.request", "recon.http_probe", "recon.race_condition", "burp.history", "burp.sitemap", "burp.issues", "evidence.read",
] as const;

export const RPC_MAX_PER_CALL = 4;
/** 唯一队列（v2）。 */
export const RPC_DISPATCH_PATH = "rpc/dispatch.jsonl";
export const RPC_DISPATCH_CURSOR = "rpc/dispatch_cursor.json";
/** v1 遗留队列：仍然读，但会提示迁移（下一版删除）。 */
export const RPC_LEGACY_REQUESTS = "rpc/requests.jsonl";
export const RPC_LEGACY_CURSOR = "rpc/cursor.json";
export const RPC_LEGACY_RACE = "rpc/race_requests.jsonl";
export const RPC_LEGACY_RACE_CURSOR = "rpc/race_cursor.json";
const RPC_MAX_LINES = 200;

/** standard = 直接派发；concurrent = 控制面并发发射（竞态），threads/count 决定发几份。 */
export type RpcMode = "standard" | "concurrent";

export type RpcRequest = {
  tool: string;
  input: Record<string, unknown>;
  reason?: string;
  mode: RpcMode;
};

export type RpcResult = { tool: string; ok: boolean; summary: string; data?: Record<string, unknown>; error?: string };

export type RpcParse = { requests: RpcRequest[]; skipped: Array<{ line: string; why: string }>; next_cursor: number };

const CONCURRENT_TOOL = "recon.race_condition";

function asInput(record: Record<string, unknown>): Record<string, unknown> {
  return record.input && typeof record.input === "object" && !Array.isArray(record.input)
    ? { ...(record.input as Record<string, unknown>) }
    : {};
}

/** concurrent 模式：threads/count 统一成工具认的 count，并把标准输入字段搬进去。 */
function concurrentInput(record: Record<string, unknown>, input: Record<string, unknown>): Record<string, unknown> {
  const threads = Number(record.threads ?? record.count ?? input.count ?? input.threads ?? 0);
  const merged: Record<string, unknown> = { ...input };
  if (Number.isFinite(threads) && threads > 0) merged.count = Math.max(2, Math.min(Math.floor(threads), 50));
  // 顶层直接写 url/method/requests 也算（少一层嵌套，脚本更好写）
  for (const key of ["url", "method", "requests", "body", "headers"]) {
    if (merged[key] === undefined && record[key] !== undefined) merged[key] = record[key];
  }
  return merged;
}

/**
 * 解析队列。cursor = 已经消费过的条数（0 表示还没消费）。
 * 非法行（缺 tool、工具不在白名单、input 不是对象）逐条跳过并给出原因，不整批失败。
 * `legacy` 标记用于把 v1 队列的请求标出来（提示迁移）。
 */
export function parseRpcRequests(raw: string, cursor: number, options: { defaultTool?: string; legacy?: string } = {}): RpcParse {
  const lines = String(raw || "").split(/\r?\n/).map(line => line.trim()).filter(Boolean).slice(0, RPC_MAX_LINES);
  const start = Math.max(0, Math.min(cursor, lines.length));
  const requests: RpcRequest[] = [];
  const skipped: Array<{ line: string; why: string }> = [];
  let consumed = 0;
  for (const line of lines.slice(start)) {
    // 每次最多执行 RPC_MAX_PER_CALL 条：剩下的留给下一次，避免一条脚本把预算打光。
    if (requests.length >= RPC_MAX_PER_CALL) break;
    consumed += 1;
    let parsed: unknown;
    try { parsed = JSON.parse(line); } catch { skipped.push({ line: line.slice(0, 120), why: "invalid JSON" }); continue; }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) { skipped.push({ line: line.slice(0, 120), why: "not an object" }); continue; }
    const record = parsed as Record<string, unknown>;

    // 废弃字段给出可照做的迁移提示，而不是静默忽略。
    const deprecated = ["context_override", "from_state", "state_files"].filter(key => record[key] !== undefined);
    if (deprecated.length) {
      skipped.push({
        line: line.slice(0, 120),
        why: `${deprecated.join("/")} 已废弃：沙箱脚本自己把算好的值写进 input.headers / input.cookies 即可，控制面原样透传（不再读 /state 状态文件、不再做优先级合并）`,
      });
      continue;
    }

    const modeRaw = String(record.mode || "").trim().toLowerCase();
    if (modeRaw && modeRaw !== "standard" && modeRaw !== "concurrent") {
      skipped.push({ line: line.slice(0, 120), why: `unknown mode ${modeRaw}（只接受 standard / concurrent）` });
      continue;
    }
    const mode: RpcMode = modeRaw === "concurrent" ? "concurrent" : "standard";
    const tool = String(record.tool || options.defaultTool || (mode === "concurrent" ? CONCURRENT_TOOL : "")).trim();
    if (!tool) { skipped.push({ line: line.slice(0, 120), why: "missing tool" }); continue; }
    if (!(RPC_WHITELIST as readonly string[]).includes(tool)) {
      skipped.push({ line: line.slice(0, 120), why: `tool ${tool} is not RPC-callable (allowed: ${RPC_WHITELIST.join(", ")})` });
      continue;
    }
    if (mode === "concurrent" && tool !== CONCURRENT_TOOL) {
      skipped.push({ line: line.slice(0, 120), why: `mode=concurrent 只能用于 ${CONCURRENT_TOOL}（并发在控制面发射，工具必须是它）` });
      continue;
    }
    const input = mode === "concurrent" ? concurrentInput(record, asInput(record)) : asInput(record);
    if (!Object.keys(input).length) { skipped.push({ line: line.slice(0, 120), why: "missing input" }); continue; }
    requests.push({
      tool, input, mode,
      ...(record.reason ? { reason: String(record.reason).slice(0, 500) } : {}),
    });
  }
  return { requests, skipped, next_cursor: start + consumed };
}

/** 沙箱里脚本该用的写入方式（Python，只拼字符串、不引第三方库）。 */
export function rpcPythonHelper(): string {
  return [
    "import json as _json, os as _os",
    "def call_tool(tool, mode='standard', threads=0, reason='', **kwargs):",
    "    d = '/state/rpc'",
    "    _os.makedirs(d, exist_ok=True)",
    "    rec = {'tool': tool, 'input': kwargs, 'mode': mode}",
    "    if threads: rec['threads'] = int(threads)",
    "    if reason: rec['reason'] = reason",
    "    with open(d + '/dispatch.jsonl', 'a') as f:",
    "        f.write(_json.dumps(rec, ensure_ascii=False) + '\\n')",
    "    return True",
  ].join("\n");
}

/** 队列清单：dispatch 是唯一正路，其余是过渡期兼容（会在返回里提示）。 */
export const RPC_QUEUES = [
  { path: RPC_DISPATCH_PATH, cursor: RPC_DISPATCH_CURSOR, legacy: undefined as string | undefined, defaultTool: undefined as string | undefined },
  { path: RPC_LEGACY_REQUESTS, cursor: RPC_LEGACY_CURSOR, legacy: "requests.jsonl 已废弃，请改写 dispatch.jsonl", defaultTool: undefined as string | undefined },
  { path: RPC_LEGACY_RACE, cursor: RPC_LEGACY_RACE_CURSOR, legacy: "race_requests.jsonl 已废弃，请改写 dispatch.jsonl + mode=concurrent", defaultTool: CONCURRENT_TOOL },
] as const;
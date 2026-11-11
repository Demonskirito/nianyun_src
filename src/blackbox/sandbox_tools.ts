/**
 * 特种兵：沙箱执行（`exec.python` / `exec.bash`）。
 *
 * 从 tools.ts 拆出来独立维护（三层漏斗的第三层），but 它仍然只做三件事：
 * 1. 漏斗守卫：标准 CLI / 单发请求别绕道沙箱（routing.ts）；
 * 2. 组装输入、透传 /state 会话键、把结果整理成统一的 tool-result；
 * 3. 电台：抽取脚本写进 `/state/rpc/requests.jsonl` 的工具请求，交给调用方执行
 *    （执行逻辑仍留在控制面，scope/代理/证据语义不变）。
 */
import { reject } from "./tool-errors.js";
import { trivialPassthrough } from "./routing.js";
import { blockOrReject, preflightBlock } from "./preflight_block.js";
import { RPC_MAX_PER_CALL, RPC_QUEUES, parseRpcRequests, type RpcRequest, type RpcResult } from "./sandbox_rpc.js";
import type { BlackboxToolContext, BlackboxToolResult } from "./tools.js";
import { runSandbox } from "./workspace.js";

/** 由 tools.ts 注入：避免 sandbox_tools 直接依赖整个工具注册表（也就没有循环 import）。 */
export type RpcExecutor = (request: RpcRequest) => Promise<{ ok: boolean; summary: string; data?: Record<string, unknown> }>;

export type SandboxStateIo = {
  read: (path: string) => Promise<string | undefined>;
  write: (path: string, content: string) => Promise<void>;
};

export type SandboxToolDeps = { executeRpc?: RpcExecutor; state?: SandboxStateIo };

/** 抽取本次 exec 期间脚本排队的工具请求（每次最多 4 条），并推进 cursor。
 *  两条队列：通用 requests.jsonl，以及竞态专用 race_requests.jsonl（默认工具 recon.race_condition）。
 *  并发在控制面用裸 socket 发射，所以脚本只负责"构造请求"，不负责"同时发出"。 */
export async function drainRpcQueue(io: SandboxStateIo | undefined, execute: RpcExecutor | undefined): Promise<{ results: RpcResult[]; skipped: Array<{ line: string; why: string }> }> {
  if (!io || !execute) return { results: [], skipped: [] };
  const results: RpcResult[] = [];
  const skipped: Array<{ line: string; why: string }> = [];
  // 只有一个正路队列（dispatch.jsonl）；RPC_QUEUES 里的其余项是 v1 兼容，读到就提示迁移。
  for (const queue of RPC_QUEUES) {
    if (results.length >= RPC_MAX_PER_CALL) break;
    let raw: string | undefined;
    let cursor = 0;
    try {
      raw = await io.read(queue.path);
      const cursorRaw = await io.read(queue.cursor);
      if (cursorRaw) cursor = Math.max(0, Number((JSON.parse(cursorRaw) as { consumed?: number }).consumed || 0));
    } catch { continue; }
    if (!raw || !raw.trim()) continue;
    const parsed = parseRpcRequests(raw, cursor, { defaultTool: queue.defaultTool, legacy: queue.legacy });
    if (!parsed.requests.length && !parsed.skipped.length) continue;
    for (const request of parsed.requests) {
      if (results.length >= RPC_MAX_PER_CALL) break;
      try {
        const result = await execute(request);
        results.push({ tool: request.tool, ok: result.ok, summary: String(result.summary || "").slice(0, 1200), mode: request.mode, ...(result.data ? { data: result.data } : {}) } as RpcResult & { mode?: string });
      } catch (error) {
        // RPC 失败不打断本次 exec：把错误当成"特种兵申请被驳回"如实回报。
        results.push({ tool: request.tool, ok: false, summary: `rpc failed: ${error instanceof Error ? error.message : String(error)}`.slice(0, 1200), error: error instanceof Error ? error.message : String(error) });
      }
    }
    if (parsed.requests.length && queue.legacy) skipped.push({ line: queue.path, why: queue.legacy });
    skipped.push(...parsed.skipped);
    try { await io.write(queue.cursor, JSON.stringify({ consumed: parsed.next_cursor, updated_at: Math.round(Date.now() / 1000) })); } catch { /* 写不进去下次会重复执行，接受 */ }
  }
  return { results, skipped };
}

function rpcNote(results: RpcResult[], skipped: Array<{ line: string; why: string }>): string {
  if (!results.length && !skipped.length) return "";
  const ok = results.filter(item => item.ok).length;
  const head = results.map(item => `${item.tool}:${item.ok ? "ok" : "failed"}`).join(", ");
  const skip = skipped.length ? `；驳回 ${skipped.length} 条（${skipped[0]!.why}）` : "";
  return ` ｜ 电台 RPC ${results.length} 条（成功 ${ok}）：${head || "无"}${skip}`;
}

/** /state 摘要：按命名空间报用量，并把"裁了谁"说清楚（模型据此决定下次写哪）。 */
export function stateNoteOf(state: NonNullable<Awaited<ReturnType<typeof runSandbox>>["state"]>): string {
  const bands = (state as { bands?: Record<string, { files: number; bytes: number }> }).bands;
  const parts: string[] = [];
  if (bands) {
    for (const [band, usage] of Object.entries(bands)) {
      if (!usage.files) continue;
      parts.push(`${band} ${usage.files} 个 ${Math.round(usage.bytes / 1024)}KB`);
    }
  }
  const mirror = state.mirror ? `，镜像 ${state.mirror}` : "";
  const prunedProtected = Number((state as { pruned_protected?: number }).pruned_protected || 0);
  const overQuota = (state as { over_quota?: boolean }).over_quota;
  const pruneNote = state.pruned
    ? `，超配额已裁 ${state.pruned} 个（poc/tmp 先裁，auth 受保护${prunedProtected ? `，本次连 auth 也裁了 ${prunedProtected} 个` : ""}）`
    : "";
  const overNote = overQuota ? "，仍超配额（rpc 队列不可裁，清掉 poc/ 大文件）" : "";
  return ` ｜ /state 持久 ${state.files} 个文件 ${Math.round(state.bytes / 1024)}KB${parts.length ? ` ｜${parts.join(" · ")}` : ""}${mirror}${pruneNote}${overNote}`;
}
export async function runSandboxTool(ctx: BlackboxToolContext, tool: string, input: Record<string, unknown>, deps: SandboxToolDeps = {}): Promise<Omit<BlackboxToolResult, "duration_ms">> {
  const code = tool === "exec.python" ? String(input.code ?? "") : String(input.script ?? input.code ?? "");
  const lang = tool === "exec.python" ? "python" : "bash";
  // 顺序很重要：先判"物理上做不到"（raw TCP/DNS），再判"绕远路"。
  // naabu 两条都占，但能力边界是更有用的解释（exit 126 + 该用哪个工具），别让它被
  // "沙箱里裸调 naabu 属于绕远路"这种通用提示盖掉。
  blockOrReject(lang, code);
  // 三层漏斗：标准动作不该绕道沙箱（更慢、绕开参数校验、结果不入证据）。
  const trivial = trivialPassthrough(tool, { ...input, script: input.script ?? code, code });
  if (trivial) throw reject(trivial.hint);
  // 历程图快照：特种兵在沙箱里 open("/state/graph_snapshot.json") 就能看到全局拓扑。
  // 只读单向——沙箱改图无效，所有更新必须经 RPC 回传由 builder 统一 ingest。
  let graphSnapshot: { nodes: number; edges: number; bytes: number } | undefined;
  if (deps.state && ctx.graphContext) {
    try {
      const view = ctx.graphContext();
      const payload = JSON.stringify({ generated_at: new Date().toISOString(), read_only: true, ...view });
      await deps.state.write("graph_snapshot.json", payload);
      const counts = (view.counts || {}) as Record<string, unknown>;
      graphSnapshot = { nodes: Number(counts.nodes || 0), edges: Number(counts.edges || 0), bytes: payload.length };
    } catch {
      // 图快照是增强信息，写失败不能拦住脚本本身执行。
    }
  }

  let result;
  try {
    result = await runSandbox(ctx, {
      lang,
      code,
      requirements: Array.isArray(input.requirements) ? input.requirements as string[] : undefined,
      timeout_s: Number(input.timeout_s || 60),
      memory_mb: Number(input.memory_mb || 512),
      network: input.network !== false,
    });
  } catch (error) {
    // 模型能自己修的（代码为空、依赖名非法）走 rejected：不计预算、不进失败重试。
    throw reject(error instanceof Error ? error.message : String(error));
  }
  // 电台：脚本排队的工具请求就地执行，结果随本次 tool-result 返回（下一轮模型就能看到）。
  const rpc = await drainRpcQueue(deps.state, deps.executeRpc);
  const tail = result.stdout.trim().split("\n").slice(-6).join("\n").slice(-800);
  const fileNote = result.files?.length ? ` ｜ 带回 ${result.files.length} 个文件（${result.files.slice(0, 4).map(f => f.stored).join(", ")}${result.files.length > 4 ? ", …" : ""}）` : "";
  // /state 是跨调用的"短期记忆"：把配额与落点写清楚，模型才知道下一次能接着读。
  const stateNote = result.state ? stateNoteOf(result.state) : "";
  return {
    tool, ok: result.ok,
    summary: result.timed_out
      ? `${tool} 超时（>${Math.round(Number(input.timeout_s || 60))}s，exit=${result.exit_code}），产物见 ${result.stdout_artifact}`
      : `${tool} exit=${result.exit_code} 用时 ${result.duration_ms}ms ｜ 模式=${result.mode} 隔离=${result.isolation} ｜ 输出 ${result.stdout.length} 字符${tail ? `：${tail}` : ""}${fileNote}${stateNote}${rpcNote(rpc.results, rpc.skipped)}`,
    data: {
      ...result,
      ...(graphSnapshot ? { graph_snapshot: graphSnapshot } : {}),
      ...(rpc.results.length ? { rpc_results: rpc.results } : {}),
      ...(rpc.skipped.length ? { rpc_skipped: rpc.skipped } : {}),
    },
    artifacts: [
      { kind: "tool-output", path: result.stdout_artifact, media_type: "text/plain" },
      { kind: "tool-output", path: result.stderr_artifact, media_type: "text/plain" },
      ...(result.files || []).map(file => ({ kind: "tool-output" as const, path: file.stored, media_type: "application/octet-stream" })),
    ],
  };
}

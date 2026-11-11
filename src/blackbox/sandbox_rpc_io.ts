/**
 * 电台的服务端接线：把 `sandbox_tools` 需要的两个能力落到既有设施上。
 *
 * - 读/写 `/state`：走沙箱服务 `GET/PUT /sandbox/state/file`（控制面不挂卷、也不需要）；
 * - 执行 RPC 请求：递归调用 `executeBlackboxTool`（白名单已排除 exec.*，不会套娃）。
 *
 * 单独成模块是为了打破 tools.ts ↔ sandbox_tools.ts 的循环：两边都只依赖这里。
 */
import type { BlackboxToolContext } from "./tools.js";
import type { SandboxToolDeps } from "./sandbox_tools.js";
import type { RpcRequest } from "./sandbox_rpc.js";
import { sandboxStateFile, sandboxStateWriteFile } from "../sandbox/client.js";

import { sandboxStateKey } from "./workspace.js";

type Executor = (ctx: BlackboxToolContext, request: { tool: string; input?: Record<string, unknown>; reason?: string }) => Promise<{ ok: boolean; summary: string; data?: Record<string, unknown> }>;

export function sandboxRpcDeps(ctx: BlackboxToolContext, execute?: Executor): SandboxToolDeps {
  const url = String(ctx.values?.SANDBOX_URL || process.env.SANDBOX_URL || "").trim();
  if (!url) return {};
  const token = String(ctx.values?.SANDBOX_TOKEN || process.env.SANDBOX_TOKEN || "").trim();
  const key = sandboxStateKey(ctx);
  const io = {
    read: async (path: string) => {
      try {
        const file = await sandboxStateFile({ url, token, signal: ctx.signal }, key, path);
        return file.is_text ? file.content || "" : undefined;
      } catch { return undefined; }
    },
    write: async (path: string, content: string) => {
      await sandboxStateWriteFile({ url, token, signal: ctx.signal }, key, path, content);
    },
  };
  return {
    state: io,
    executeRpc: async (request: RpcRequest) => {
      // 用"带证据"的版本：RPC 结果要能变成 ev-… 被报告引用，否则电台等于白干。
      // 动态 import 是为了只在真要执行 RPC 时才付这份依赖（也避免模块初始化期成环）。
      const run = execute || (await import("./tools.js")).executeAndRecordBlackboxTool;
      // 统一协议：脚本算出来的值就在 input 里，控制面原样透传（不做优先级合并、不读状态文件）。
      const result = await run(ctx, { tool: request.tool, input: request.input, ...(request.reason ? { reason: request.reason } : {}) });
      return { ok: Boolean(result.ok), summary: String(result.summary || ""), ...(result.data ? { data: result.data as Record<string, unknown> } : {}) };
    },
  };
}
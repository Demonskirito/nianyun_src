/**
 * 工具层的"可修复拒绝"。
 *
 * 语义：调用者在拿到网络/进程之前就被拦下（缺配置、参数被禁、输入写错）。
 * 它不是失败，不计 tool_calls、不进失败重试；模型看到消息后改一次就能过。
 *
 * 单独成文件是为了让 `sandbox_tools.ts` 与 `tools.ts` 共用同一个类型，
 * 避免两个模块互相 import 形成环。
 */
export class ToolRejected extends Error {
  readonly rejected = true;
  constructor(message: string) { super(message); this.name = "ToolRejected"; }
}

export const reject = (message: string): ToolRejected => new ToolRejected(message);
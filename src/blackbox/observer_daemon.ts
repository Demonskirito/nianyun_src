/**
 * Observer 守护进程（后台审查）。
 *
 * 以前 Observer 是主循环里的一个节点：`await observe(...)` 卡在轮次中间，LLM 的几十秒
 * 完全占着调度预算，而且一旦它决定 pause，整个 run 当场停下。
 *
 * 现在它退到后台：
 *
 *   主循环  Context → LLM → ToolRequest → Router → Execute → Ledger
 *                ↑                                        │
 *                └──── drainInterrupts() ← Observer 守护进程（事件驱动、单飞）
 *
 * 规则：
 * 1. **单飞**：同一会话同时只跑一个审查（多个触发排队，不并发烧 token）；
 * 2. **不阻塞**：`submit()` 立即返回，主循环继续下一轮；
 * 3. **不改主状态**：守护进程只产出 interrupt，落账由主循环在安全点做；
 * 4. **可回退**：`BLACKBOX_OBSERVER_ASYNC=0` 回到同步（证据闸门仍同步，见 shouldRunObserverSync）。
 */

import { canonicalTool } from "./aliases.js";

export type ObserverInterruptKind = "advice" | "anomaly" | "pause_request" | "review_failed" | "review_stale" | "review_conflict";

export type ObserverInterrupt = {
  /** 建议 id：主 Agent 用它写 advice_decisions。 */
  id: string;
  kind: ObserverInterruptKind;
  severity: "high" | "medium";
  text: string;
  data?: Record<string, unknown>;
  created_at: number;
};

export type ObserverJob = {
  id: string;
  run: () => Promise<ObserverInterrupt[] | void>;
};

export type ObserverDaemonStats = {
  submitted: number;
  completed: number;
  failed: number;
  running: boolean;
  queued: number;
  interrupts: number;
};

export const OBSERVER_INTERRUPT_EVENT = "system-interrupt";

/**
 * 哪些审查必须同步跑。
 *
 * `validation_failed` 是**证据闸门**：不合规的 finding 不能因为"后台还在审"就放行，
 * 所以它保持同步（用户要的"异步化"针对的是调度开销，不是放掉证据要求）。
 */
export function shouldRunObserverSync(reason: string, mode: "async" | "sync"): boolean {
  if (mode === "sync") return true;
  // 收尾审查（terminal_review）与证据闸门（validation_failed）必须同步：
  // run 的结束判定就建立在它们的结论上，异步只会让"审查还没回来就结束"。
  return reason === "validation_failed" || reason === "terminal_review";
}

export function observerModeFrom(values: Record<string, string | undefined> | undefined): "async" | "sync" {
  const raw = String(values?.BLACKBOX_OBSERVER_ASYNC ?? "1").trim();
  return raw === "0" || raw.toLowerCase() === "false" ? "sync" : "async";
}

/**
 * 一个 next_step 渲染成可直接照抄的执行行。
 * Observer 的 next_steps 是结构化「工具 + 目标 + 参数」，比自由文本建议更有可执行性，
 * 异步模式原来只丢了 suggestions 文本、把 next_steps 整个丢弃，等于把最该执行的动作吞掉。
 */
function renderNextStep(step: Record<string, unknown>): string {
  const rawTool = String(step.tool || "").trim();
  const tool = rawTool ? canonicalTool(rawTool) : "";
  const target = String(step.target || "").trim();
  const why = String(step.why || "").trim();
  const input = step.input && typeof step.input === "object"
    ? JSON.stringify(step.input as Record<string, unknown>)
    : "";
  if (!tool) return `缺口：${why || target || "Observer 未说明需要什么能力"}`;
  return `→ 用 ${tool}${target ? ` 打 ${target}` : ""}${input ? ` input=${input}` : ""}${why ? `（${why}）` : ""}`;
}

/** 把 interrupt 渲染进下一轮上下文的提示块（空列表返回空串，不占 token）。 */
export function renderInterrupts(interrupts: ObserverInterrupt[]): string {
  if (!interrupts.length) return "";
  const lines = interrupts.slice(0, 8).map(item => {
    const tag = item.severity === "high" ? "[高]" : "[中]";
    const head = `- ${tag}(${item.kind}) ${item.id}：${item.text}`;
    const suggests = Array.isArray(item.data?.suggestions)
      ? (item.data!.suggestions as string[]).filter(Boolean)
      : [];
    const suggestLine = suggests.length ? `    建议：${suggests.join("；")}` : "";
    const steps = Array.isArray(item.data?.next_steps)
      ? (item.data!.next_steps as Array<Record<string, unknown>>)
        .map(renderNextStep)
        .map(line => `    ${line}`)
        .join("\n")
      : "";
    return steps || suggestLine ? `${head}${suggestLine ? `\n${suggestLine}` : ""}${steps ? `\n${steps}` : ""}` : head;
  });
  return [
    "## 后台 Observer 插话（System Interrupt）",
    "这是 Observer 在后台审账本时留下的内容，下一轮上下文里只出现一次。",
    "- **kind=advice（必须处置）**：条目里的 next_steps 是可直接执行的「工具+目标+参数」。本轮要么用对应 tool_requests 执行它们，要么在 advice_decisions 里用该条目 id 明确拒绝并给理由；连续两轮不处置会被代码按未采纳归档，等于把 Observer 的判断丢进垃圾桶。",
    "- **kind=anomaly / pause_request（高优先）**：优先用证据回应（补验证、补对照）。",
    "- 这些插话**不阻塞**你已锁定的焦点任务，但 advisory 类必须给个交代，不能无视。",
    ...lines,
  ].join("\n");
}

export class ObserverDaemon {
  private queue: ObserverJob[] = [];
  private running = false;
  /** 正在执行的任务 id：队列已 shift 出去，但同样不能重复提交。 */
  private activeId: string | undefined;
  /** 本 run 已开始过的审查 id（防止同一快照反复排队）。 */
  private readonly seen = new Set<string>();
  private interrupts: ObserverInterrupt[] = [];
  private readonly maxInterrupts: number;
  private readonly maxQueue: number;
  private stats: ObserverDaemonStats = { submitted: 0, completed: 0, failed: 0, running: false, queued: 0, interrupts: 0 };
  private readonly onError?: (jobId: string, error: unknown) => void;

  constructor(options: { maxInterrupts?: number; maxQueue?: number; onError?: (jobId: string, error: unknown) => void } = {}) {
    this.maxInterrupts = Math.max(4, options.maxInterrupts ?? 24);
    this.maxQueue = Math.max(1, options.maxQueue ?? 4);
    this.onError = options.onError;
  }

  /** 排队（不 await）。同一 id 已在队列里就丢弃，避免重复烧 token。 */
  submit(job: ObserverJob): boolean {
    if (this.activeId === job.id || this.seen.has(job.id) || this.queue.some(item => item.id === job.id)) return false;
    if (this.queue.length >= this.maxQueue) this.queue.shift();
    this.queue.push(job);
    this.seen.add(job.id);
    this.stats.submitted += 1;
    void this.pump();
    return true;
  }

  /** 主循环在安全点调用：取走并清空 interrupt。 */
  drain(): ObserverInterrupt[] {
    const items = this.interrupts;
    this.interrupts = [];
    this.stats.interrupts = 0;
    return items;
  }

  /** 守护进程自己也能塞一条（例如检查点冲突）。 */
  push(interrupt: Omit<ObserverInterrupt, "created_at"> & { created_at?: number }): void {
    this.interrupts.push({ ...interrupt, created_at: interrupt.created_at ?? Date.now() });
    if (this.interrupts.length > this.maxInterrupts) this.interrupts = this.interrupts.slice(-this.maxInterrupts);
    this.stats.interrupts = this.interrupts.length;
  }

  /** 等所有排队任务跑完（收尾用；主循环不调用）。 */
  async idle(): Promise<void> {
    while (this.running || this.queue.length) await new Promise(resolve => setTimeout(resolve, 25));
  }

  snapshot(): ObserverDaemonStats {
    return { ...this.stats, running: this.running, queued: this.queue.length, interrupts: this.interrupts.length };
  }

  private async pump(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.stats.running = true;
    try {
      for (let job = this.queue.shift(); job; job = this.queue.shift()) {
        this.activeId = job.id;
        try {
          const produced = await job.run();
          this.stats.completed += 1;
          for (const item of produced || []) this.push(item);
        } catch (error) {
          this.stats.failed += 1;
          this.onError?.(job.id, error);
          this.push({
            id: job.id, kind: "review_failed", severity: "medium",
            text: `后台 Observer 审查失败（${error instanceof Error ? error.message : String(error)}）；下一轮会用新快照重试。`,
            data: { review_id: job.id },
          });
        }
      }
    } finally {
      this.running = false;
      this.stats.running = false;
    }
  }
}
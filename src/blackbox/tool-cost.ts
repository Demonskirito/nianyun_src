import { TOOL_WEIGHTS } from "./weights.js";

/**
 * 战术点数（Tactical Points, TP）：用"执行成本"而不是"调用次数"算预算。
 *
 * 按次数记账时，`http.request` 和跑 40 分钟的 `nuclei` 全量模板都算 1 次——这直接教坏模型：
 * 它会用最贵的工具做探针，因为"反正只算一次"。TP 把成本折算进来，模型才有"这笔很贵"的直觉。
 *
 * 基数来自"这个动作要付多少机器代价"：一次 http 探针几乎免费，起一个容器/走一次 RPC 就不便宜，
 * 跑整套模板最贵。外加实际耗时（每分钟 +1 TP），长任务不会因为"只调用一次"被低估。
 */

/** 单位成本（不含耗时附加）。 */
export const TOOL_TP: Record<string, number> = {
  "http.request": 1,
  "recon.http_probe": 1,
  "exec.python": 3,
  "exec.bash": 3,
  "browser.open": 4,
  "recon.nuclei": 5,
  "katana.crawl": 5,
};

/** 未登记工具的默认成本：比 http 贵、比 nuclei 便宜。 */
export const DEFAULT_TP = 2;

/** 每满 60 秒实际耗时追加的 TP。 */
export const TP_PER_MINUTE = 1;

/** 单个请求的 TP 上限：防止一条 300 秒的工具调用把整条任务预算一次性打穿到无法判定。 */
export const MAX_TP_PER_CALL = 12;

/** 基准延迟：500ms 是"正常站点"的经验值，低于它不打折，高于它按比例涨价。 */
export const LATENCY_BASE_MS = 500;
/** 通胀上限：慢到 3 倍基准就封顶，否则慢目标会把预算瞬间吃光。 */
export const LATENCY_MAX_MULTIPLIER = 3;
/** EWMA 平滑系数：0.3 让"最近几轮"占主导，又不至于一条慢请求就把价目表打翻。 */
export const LATENCY_EWMA_ALPHA = 0.3;

/**
 * 延迟通胀乘数：目标越慢，每个动作越贵。
 *
 * 慢目标（WAF 限速 / 后端卡）上，一次 1 TP 的 http 探针真实成本接近 browser —— 固定汇率下模型会继续
 * 用步兵战术铺量，正是最亏的打法。乘数让"少而重"和"多而轻"的成本可比。
 */
export function latencyMultiplier(avgLatencyMs: number | undefined): number {
  if (!avgLatencyMs || !Number.isFinite(avgLatencyMs) || avgLatencyMs <= LATENCY_BASE_MS) return 1;
  return Math.min(LATENCY_MAX_MULTIPLIER, Math.round((avgLatencyMs / LATENCY_BASE_MS) * 100) / 100);
}

/** EWMA 更新：没有历史时直接取本次耗时。 */
export function updateLatency(previous: number | undefined, durationMs: number): number {
  if (!Number.isFinite(durationMs) || durationMs <= 0) return previous ?? 0;
  if (!previous || previous <= 0) return durationMs;
  return Math.round(previous * (1 - LATENCY_EWMA_ALPHA) + durationMs * LATENCY_EWMA_ALPHA);
}

export function tpCost(tool: string, durationMs = 0, avgLatencyMs?: number): number {
  const base = TOOL_TP[tool] ?? (TOOL_WEIGHTS[tool] !== undefined ? Math.max(2, Math.round(TOOL_WEIGHTS[tool] / 2)) : DEFAULT_TP);
  const minutes = Math.max(0, durationMs) / 60_000;
  const priced = (base + Math.floor(minutes * TP_PER_MINUTE)) * latencyMultiplier(avgLatencyMs);
  return Math.min(MAX_TP_PER_CALL, Math.max(1, Math.round(priced * 10) / 10));
}

/** 一批请求的 TP 合计（准入前估算：还没有耗时，只算基数 + 延迟通胀）。 */
export function batchTp(requests: Array<{ tool: string }>, avgLatencyMs?: number): number {
  return Math.round(requests.reduce((sum, request) => sum + tpCost(request.tool, 0, avgLatencyMs), 0) * 10) / 10;
}

/** 人类可读的价目表（控制台展示 / 文档用）。 */
export function toolTpTable(): Array<{ tool: string; tp: number }> {
  return Object.entries(TOOL_TP)
    .map(([tool, tp]) => ({ tool, tp }))
    .sort((a, b) => a.tp - b.tp || a.tool.localeCompare(b.tool));
}
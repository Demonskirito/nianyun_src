/**
 * 建议处置（advice disposition）的兜底层。
 *
 * 起因：push.oppo.com 那一轮（session c88cc901）不是没挖到东西，而是死在
 * `ADVICE_DISPOSITION_INVALID`——Observer 给了 9 条建议，模型在 R5 之后注意力涣散，
 * 连续几轮忘了写 `advice_decisions`，验收门禁直接把整场 run 掐了。
 * 长上下文里要求每轮都完美输出结构化 JSON 是不现实的，所以这里做三件事：
 *   1. 从正文里抢救 advice_id（模型常在 review 文本里点名 id，却没放进结构化字段）；
 *   2. 连续两轮没被签收的建议自动归档为「未采纳」，绝不阻塞；
 *   3. 下一轮用 critical_actions 把待处置 id 顶到上下文最前面强制补齐。
 */

/** 建议 id 的两类命名来源：Observer 审查 id（review-xxxx）与代码内生成的 advice-N。 */
const ADVICE_ID_PATTERN = /\b(?:review-[0-9a-f]{6,}|advice-\d+)\b/gi;

/**
 * 从自由文本里提取可能被提及的建议 id。
 * 只做“提取”，不猜态度：调用方一律按未采纳归档，避免把正文里的口头认可当成任务绑定。
 */
export function salvageAdviceIds(text: string, known: Iterable<string> = []): string[] {
  const allowed = new Set(Array.from(known, id => id.toLowerCase()));
  const found: string[] = [];
  for (const match of String(text || "").matchAll(ADVICE_ID_PATTERN)) {
    const id = match[0];
    // 只在 id 确实存在时才算数：模型经常自己编 id，编出来的不能顺手建条目。
    if (allowed.size && !allowed.has(id.toLowerCase())) continue;
    if (!found.some(existing => existing.toLowerCase() === id.toLowerCase())) found.push(id);
  }
  return found;
}

/** 一条建议的可观测形态：谁提的、提了什么、被忽略了几轮。 */
export type AdviceView = {
  advice_id: string;
  suggestions: string[];
  misses: number;
  reason: string;
};

/** 给模型看的「必须现在就处置」清单（critical_actions.advice）。 */
export function pendingAdviceView(advice: Record<string, { suggestions?: unknown[]; status?: string; misses?: number }> | undefined): AdviceView[] {
  return Object.entries(advice || {})
    .filter(([, item]) => item?.status === "pending")
    .map(([advice_id, item]) => ({
      advice_id,
      suggestions: (Array.isArray(item.suggestions) ? item.suggestions : [])
        .map(item => String(item).slice(0, 300)).slice(0, 4),
      misses: Number(item.misses || 0),
      reason: `连续 ${Number(item.misses || 0)} 轮未处置；再漏一轮将按未采纳自动归档。`,
    }));
}

/** 自动归档的原因文案（写进 checkpoint，复盘时能看出是代码兜的底，不是模型认的账）。 */
export function autoSkipReason(misses: number): string {
  return `auto-skip：连续 ${misses} 轮未以 advice_decisions 处置，代码层按未采纳归档（不阻塞 run）。`;
}

export function autoSalvageReason(): string {
  return "auto-salvaged：正文点名了该建议但未输出结构化 advice_decisions，按未采纳归档。";
}
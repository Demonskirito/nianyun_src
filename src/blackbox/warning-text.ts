/**
 * 监督器告警的文案映射。
 *
 * 原来的写法是 if/else 三分支，**兜底分支直接断言"本批有工具失败已记入证据账本"**：
 *
 * ```ts
 * const text = budgetWarning && toolFailure ? "…预算…工具失败…"
 *   : budgetWarning ? "预算接近阈值…"
 *   : "本批有工具失败已记入证据账本；监督器继续推进，不重复相同调用。";
 * ```
 *
 * 于是只要 `warnings` 非空且不含 `budget_warning`（例如只有 `repairable_task_rejections`——
 * 任务完成声明被拒、可自纠，跟工具一点关系都没有），界面就会报"有工具失败"。
 * 实测 gray-push 会话 4 条 supervisor-warning 的 `warnings` 全是
 * `["repairable_task_rejections"]`，而工具健康度是 42 次执行 / 0 失败——文案在撒谎。
 *
 * 现在每个告警码自己一条文案，未知码原样带码露出，绝不臆造原因。
 */

const TEMPLATES: Record<string, string> = {
  budget_warning: "预算接近阈值，将优先处理必要任务并减少低价值重复分析",
  tool_failure: "本批有工具失败，已记入证据账本",
  repairable_task_rejections: "有任务完成声明被拒（可自纠），明细已保留，下一轮修正",
  evidence_traceability_failed: "证据可追溯性不达标，已记录",
  state_validation_failed: "状态校验未通过，已记录",
};

export function supervisorWarningText(warnings: string[]): { kind: "budget-warning" | "supervisor-warning"; text: string } {
  const codes = (warnings || []).map(code => String(code || "").trim()).filter(Boolean);
  const kind = codes.includes("budget_warning") ? "budget-warning" : "supervisor-warning";
  const parts = codes.map(code => TEMPLATES[code] || `未映射告警（${code}）`);
  if (!parts.length) return { kind, text: "监督器继续推进，不重复相同调用。" };
  return { kind, text: `${parts.join("；")}；监督器继续推进，不重复相同调用。` };
}
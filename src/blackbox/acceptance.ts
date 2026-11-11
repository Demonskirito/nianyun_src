import type { RunCheckpoint } from "./progress.js";
import { taskEvidenceIssue, taskAuditIssues } from "./task-evidence.js";
import { outcomeIssue } from "./task-outcome.js";
import { validateFinding } from "./findings.js";
import { EVIDENCE_REFERENCE_CODES } from "./quarantine.js";

export type ValidationIssue = {
  code: string; severity: "error" | "warning"; path: string; message: string;
  task_id?: string; advice_id?: string; evidence_id?: string;
  rule?: string; detail?: string;
    /** 可直接抄的候选池（audit_ids / evidence_ids 场景）：让模型做选择而不是猜。 */
    valid_ids?: string[];
};
export type AcceptanceResult = {
  ready: boolean;
  /** 严格口径：每条任务都落到终态（有 settled:not_reached 的不算）。 */
  all_tasks_terminal: boolean;
  /** 每条任务都有处置：终态，或已声明"预算没轮到"。验收门看这个。 */
  all_tasks_accounted: boolean;
  validation_passed: boolean;
  required_reviews_complete: boolean; unhandled_advice: number; evidence_integrity_ok: boolean;
  reason_codes: string[]; blocking_error_count: number; /** All blocking issues are agent-repairable rejections. */ repairableOnly: boolean; issues: ValidationIssue[];
  pending: string[]; invalidEvidence: string[]; validationErrors: string[];
};

/**
 * 会话级完成判据（2026-11-05）。
 *
 * 旧口径是"有 blocked 任务就永远不算 tasks_completed"，于是 11 场实盘
 * **0 场 completed**。但这不是"没跑完"，是判据走不通：一次渗透评估几乎不可能
 * 让每个任务都成功——T2 被鉴权墙挡住、SPA 逆不出接口面，恰恰是有效结论
 * （blocked + 证据引用），报告里本来就按"部分完成的评估"呈现。
 * 用一个只认"全成功"的判据当交付门槛，结果就是每场都只能由人按取消键结束。
 *
 * 新口径只回答一个问题：**这场评估收口了吗**（所有任务都有结论）。
 * 结论质量的分级交给 stop_reason 与报告：
 *   - failed            执行层出错，报告不可信
 *   - blocked           一条结论都没有：全灭，不算完成
 *   - partial_completed 有结论也有受阻：可交付，报告单列受阻项
 *   - tasks_completed   全部结案
 * 后两者都落 session.status = completed；受阻项另有 PARTIAL_TASK_OUTCOME warning。
 *
 * `action:<hash>` 是恢复用的占位记录不是任务，必须排除（否则永远有"未终结"）。
 *
 * 2026-11-05 试改记录：曾把"blocked 有 outcome_code / pending 已声明 not_reached"也算结论，
 * 让 0 条 completed 的场次落 partial_completed。**已回退**——它把 resume 通道关死了：
 * 预算只够跑 1 次工具时（test/blackbox.test.ts 的 resume 场景），第一轮必是 0 completed，
 * 当场标 completed 就再没有"续跑把剩下的做完"这回事了。预算耗尽 ≠ 评估完成。
 * 所以这里**故意**要求至少一条 completed：一条都没做成，就该留一条命给下一轮。
 */
export function completionVerdictOf(tasks: Record<string, { status?: string }>): string {
  const real = Object.entries(tasks || {}).filter(([id]) => !id.startsWith("action:"));
  if (!real.length) return "blocked";
  if (real.some(([, task]) => task?.status === "failed")) return "failed";
  const completed = real.filter(([, task]) => task?.status === "completed").length;
  if (!completed) return "blocked";
  return real.length > completed ? "partial_completed" : "tasks_completed";
}

/** 会话是否可以标为 completed（partial_completed 也算：评估已收口）。 */
export function isCompletedVerdict(reason: string): boolean {
  return reason === "tasks_completed" || reason === "partial_completed";
}

/** Recompute from the current checkpoint and authoritative session ledger on every call.
 * Rejected transitions are durable unresolved input errors, not cached state-validation results.
 */
export function evaluateAcceptance(state: RunCheckpoint, evidence: Record<string, unknown>[]): AcceptanceResult {
  const issues: ValidationIssue[] = [];
  const add = (issue: ValidationIssue) => issues.push(issue);
  // Old checkpoints have no separate rejection ledger. Preserve their errors conservatively.
  state.transitionErrors ??= [...(state.validationErrors || [])];
  /**
   * 不是"模型写错了"的拒收：`task_backlog_full` 是控制面主动挡下一条新任务（簿子满了）。
   * 它留在 transitionErrors 里只是为了留痕，一旦被升级成 error，验收就永远 ready 不了——
   * 实测 4f899c3af6c2ac84：任务簿一满，拒收本身把整场 run 卡在 VALIDATION_ERRORS_REMAIN，
   * 只能等预算耗尽。这类"系统侧挡下"的记录一律降级为 warning。
   */
  const nonBlockingTransitions = new Set(["task_backlog_full"]);
  for (const message of state.transitionErrors) {
    const [code = "UNRESOLVED_TRANSITION", ...identity] = message.split(":");
    const id = (code === "invalid_task_transition" ? identity.slice(0, -1) : identity).join(":");
    const details = code === "completion_without_valid_task_evidence" ? state.taskOutcomeResults?.[id]?.issues : undefined;
    if (details?.length) { details.forEach(add); continue; }
    // 建议处置类错误保持 error：模型写错决定要能被看见（Observer 与人都要看）。
    // 但"漏处置"已经由 progress.sweepAdvice 兜底归档，不会走到这里变成无解死锁。
    add({ code, severity: nonBlockingTransitions.has(code) ? "warning" : "error", path: `transitionErrors.${message}`, message,
      ...(code.includes("advice") || code === "disposition_conflict" ? { advice_id: id } : { task_id: id }) });
  }
  /** Rejected completion proposals the agent can still repair in the next round. */
  // completion_on_denied_evidence: 任务已被自动置为 blocked_by_auth，属于可自纠的结案错误。
const correctableCodes = new Set(["completion_without_valid_task_evidence", "invalid_task_transition", "completion_on_denied_evidence"]);
  const tasks = Object.entries(state.tasks);
  const terminal = (status: string) => ["completed", "blocked", "failed"].includes(status);
  /**
   * "未终态"要分两种（2026-11-05 修）：
   *   - 悬着没处置 → 真的阻塞，报告会在不知情的情况下漏掉工作；
   *   - 已被收口标记（settled: not_reached）→ 已经写明"预算没轮到"，是**声明过的缺口**。
   * 旧判据把两者都算 TASKS_NOT_TERMINAL，于是只要有一条任务没派发过，验收就永远
   * ready 不了——而预算耗尽时总会剩下几条没轮到（实测 094d157f6fc028f6：收口后
   * 仍有 4 条 pending，会话卡在 paused）。声明过的缺口不该阻止交付，但必须让报告看见。
   */
  const accounted = (task: { status?: string; settled?: string }) => terminal(String(task.status || "")) || Boolean(task.settled);
  const pending = tasks.filter(([, task]) => !accounted(task)).map(([id]) => id);
  /**
   * `action:<hash>` 是**恢复用的占位记录**，不是任务：它在 checkpoint 载入时给
   * "上一轮发出去、结果未知"的工具动作补一条 blocked 记录，防止重放（见 progress 构造函数）。
   *
   * 但它会污染账本口径：一场普通 run 里动不动出现 3-4 条，把 PARTIAL_TASK_OUTCOME
   * 顶起来 → 触发 Observer 审查 → 白烧一轮（实跑 090e71cc2732165e 观察到 4 条）。
   * 统计口径要把它们排除掉，它们本身仍然留在 tasks 里供排查。
   */
  const realTasks = tasks.filter(([id]) => !id.startsWith("action:"));
  /**
   * 按任务归集账本证据（2026-11-05）。
   *
   * 用途是回答"这条任务明明打过，为什么结案说明一条证据都不引"：
   * 控制面自动收口（死胡同/零熵/焦点预算/假设归档/预算 settle）当初全都没写
   * evidence_ids，报告里一排 blocked 看不到任何可回溯的请求。有了这份归集，
   * "有证据却不引用"才算错，"压根没有证据可引用"是另一回事（见 outcomeIssue）。
   */
  const evidenceByTask = new Map<string, string[]>();
  for (const item of evidence) {
    const taskId = String((item.data as Record<string, unknown> | undefined)?.task_id || "");
    const evidenceId = String(item.id || "");
    if (!taskId || !evidenceId) continue;
    const list = evidenceByTask.get(taskId) || [];
    list.push(evidenceId);
    evidenceByTask.set(taskId, list);
  }
  const invalidEvidence: string[] = [];
  /**
   * 已隔离的任务：引用无效、摘掉之后没有证据可支撑结论（quarantine.ts）。
   *
   * 这类任务的错误不能让整场停摆——账已经记过、隔离也留了痕，报告会写"结论未经
   * 证据支撑"。所以把它降级成 warning：**看得见，但不拦住交付**。
   * 反过来，如果这里仍然当 error，隔离就成了纯装饰（门禁照样卡住）。
   */
  const unverified = new Set(tasks.filter(([, task]) => String(task?.evidence_status || "") === "unverified").map(([id]) => id));
  for (const [id, task] of tasks) {
    if (!["pending", "running", "completed", "blocked", "failed"].includes(task.status))
      add({ code: "INVALID_TASK_STATUS", severity: "error", path: `tasks.${id}.status`, task_id: id, message: `invalid_task_status:${id}` });
    /**
     * 结案说明的完整性检查（2026-11-05）。
     *
     * 旧写法是 `!task.outcome_reason?.trim() && !task.reason?.trim()`，用 `reason`
     * 给 `outcome_reason` 兜底——而 `reason` 是创建时的"为什么派这个任务"，几乎
     * 永远非空。这条检查从上线起就没有真正拦住过任何东西：H_* 假设任务只有
     * `closed_reason`（"假设已收口，任务不再需要执行"），照样通过验收，报告里
     * 就只剩一行 status。判据统一收进 task-outcome.ts，验收与结案审计共用。
     */
    // `action:<hash>` 是恢复用的占位记录，不是任务：它天生只有 blocked + 一个机器码
    // （interrupted_unknown_outcome），要求它写结案说明没有意义。
    if (!id.startsWith("action:"))
      for (const issue of outcomeIssue(task, { evidenceOnRecord: evidenceByTask.get(id) })) {
      add({
        // 已隔离的任务：证据类错误降级为 warning（结论标记为"未经证据支撑"，报告里单列）。
        code: issue.code, severity: unverified.has(id) && EVIDENCE_REFERENCE_CODES.has(issue.code) ? "warning" : issue.severity,
        path: issue.code.includes("EVIDENCE") ? `tasks.${id}.outcome_evidence_ids` : `tasks.${id}.outcome_reason`,
        task_id: id, message: `${issue.message}:${id}`, ...(issue.detail ? { detail: issue.detail } : {}),
      });
    }
    taskAuditIssues(evidence, id, task.audit_ids || [], `tasks.${id}.audit_ids`).forEach(add);
    if (task.status !== "completed") continue;
    const refs = task.evidence_ids || [];
    if (!refs.length) {
      // 隔离过的任务不再把引用缺失算成"完整性失败"：账已经记过，报告会写清楚。
      if (!unverified.has(id)) {
        invalidEvidence.push(id);
        add({ code: "TASK_EVIDENCE_MISSING", severity: "error", path: `tasks.${id}.evidence_ids`, task_id: id, message: `task_evidence_missing:${id}` });
      }
    }
    for (const ref of refs) {
      const issue = taskEvidenceIssue(state, evidence, id, ref, `tasks.${id}.evidence_ids`);
      if (issue) {
        if (!unverified.has(id)) {
          if (!invalidEvidence.includes(id)) invalidEvidence.push(id);
          add(issue);
        } else {
          add({ ...issue, severity: "warning" });
        }
      }
    }
    if (task.completion_criteria && !task.outcome_reason?.trim())
      add({ code: "TASK_OUTCOME_MISSING", severity: "error", path: `tasks.${id}.outcome_reason`, task_id: id, message: `task_outcome_missing:${id}` });
  }
  for (const [id, advice] of Object.entries(state.advice || {})) {
    if (advice.status === "pending") continue;
    // superseded = 代码层归档（任务已终态 / 连续漏处置 / 正文点名未结构化）。
    // 它不是模型的错误处置，而是兜底结果，不能算验收阻塞，否则长 run 永远收不了尾。
    if (advice.status === "superseded") {
      if (!advice.reason?.trim())
        add({ code: "ADVICE_ARCHIVED_WITHOUT_REASON", severity: "warning", path: `advice.${id}`, advice_id: id, message: `advice_archived_without_reason:${id}` });
      continue;
    }
    if (!["accepted", "rejected"].includes(advice.status) || !advice.reason?.trim() ||
        (advice.status === "accepted" && !advice.task_ids?.length) || advice.task_ids?.some(id => !state.tasks[id]))
      add({ code: "ADVICE_DISPOSITION_INVALID", severity: "error", path: `advice.${id}`, advice_id: id, message: `advice_disposition_invalid:${id}` });
  }
  for (const [id, finding] of Object.entries(state.findings || {})) {
    // 已隔离的发现：不进验收、不进报告正文，只在附录留痕（quarantine.ts）。
    // 这里必须跳过，否则隔离等于没做——同一个错误每轮都会被重新报成 error。
    if ((finding as { quarantined?: boolean }).quarantined) continue;
    const error = validateFinding(finding, evidence);
    if (error) add({ code: "FINDING_EVIDENCE_INVALID", severity: "error", path: `findings.${id}.evidence_ids`, message: `${id}:${error}` });
    if (finding.status !== "candidate") {
      const review = finding.review;
      // needs_evidence 的语义是"证据不足"：它本来就**没有**新证据可引，要求它给 evidence_ids
      // 等于让这条裁决无法落账（desk 会静默跳过），候选发现于是永远停在 candidate。
      const needsCitation = finding.status !== "needs_evidence";
      const badRefs = (review?.evidence_ids || []).some(ref => !finding.evidence_ids.includes(ref) || !evidence.some(e => e.id === ref));
      if (!review?.actor || !review.reason?.trim() || (needsCitation && !review.evidence_ids?.length) || badRefs)
        add({ code: "FINDING_REVIEW_INVALID", severity: "error", path: `findings.${id}.review`, message: `finding_review_invalid:${id}` });
    }
  }
  if (realTasks.some(([, task]) => ["blocked", "failed"].includes(String(task.status || ""))))
    add({ code: "PARTIAL_TASK_OUTCOME", severity: "warning", path: "tasks", message: "存在受阻或失败任务；验收阶段报告不代表这些任务成功。" });
  const notReached = realTasks.filter(([, task]) => task.settled === "not_reached").map(([id]) => id);
  if (notReached.length)
    add({ code: "TASK_NOT_REACHED", severity: "warning", path: "tasks",
      message: `预算内没轮到的任务：${notReached.join("、")}（未开展，不是"不存在"的结论）。` });
  const blocking = issues.filter(issue => issue.severity === "error");
  /** 每条任务都有处置（终态，或已声明未开展）。验收门用它判断"还有没有悬着的活"。 */
  const all_tasks_accounted = tasks.length > 0 && !pending.length;
  /** 严格口径：真的每条都落到了终态。报告用它单列"未开展"的部分。 */
  const strictly_terminal = tasks.length > 0 && !tasks.some(([, task]) => !terminal(String(task.status || "")));
  /**
   * 冲突 5（2026-11-02 规则审计）：`candidate` 不是错误，是**结论强度**。
   *
   * Observer 对一条候选发现给 needs_evidence 之后，它就停在这个状态——这是正常终点
   * （报告里按 likely / 未确认呈现）。旧判据把"存在 candidate"算成"评审未完成"，
   * 于是 run 永远 ready 不了，只能等预算耗尽，stopReason 退化成 required_review_pending。
   *
   * 新判据只拦"**从没被任何评审看过**"的候选：那说明它根本没进裁决流程，收尾等于
   * 把一条未裁决的发现混进报告。看过但判不了（needs_evidence）的，放行。
   */
  const candidates = Object.values(state.findings || {}).filter(f => f.status === "candidate" && !(f as { quarantined?: boolean }).quarantined);
  const unreviewed = candidates.filter(f => !f.review?.actor);
  for (const finding of unreviewed)
    add({ code: "FINDING_CANDIDATE_UNREVIEWED", severity: "warning", path: `findings.${finding.id}.review`, message: `finding_candidate_unreviewed:${finding.id}` });
  // Observer 连续 3 次审查失败（reviewUnavailable）时不再要求它跑完：
  // 审查是辅助，run 的产出是任务结案与 finding，不该被一个挂掉的副驾驶永久卡住。
  // 同理：run 已经收口时撤销的审查（reviewDropped）也不再计入——它审的是旧快照，
  // 让它把门一直顶住只会把会话拖成 paused（实测 094d157f6fc028f6）。
  const required_reviews_complete = state.supervision?.reviewUnavailable === true
    || (!state.supervision?.reviewPending && !unreviewed.length && !blocking.some(i => i.code === "FINDING_REVIEW_INVALID"));
  const unhandled_advice = Object.values(state.advice || {}).filter(a => a.status === "pending").length;
  const evidence_integrity_ok = !invalidEvidence.length && !blocking.some(i => ["FINDING_EVIDENCE_INVALID", "TASK_EVIDENCE_INVALID", "TASK_AUDIT_INVALID"].includes(i.code));
  // Only agent-repairable rejections: the scheduler keeps working instead of stopping the run.
  // Issue paths under task_outcomes.* come from a rejected completion claim that the agent can
  // redo next round; everything else (committed tasks, findings) is a real integrity failure.
  const repairableOnly = blocking.length > 0 && blocking.every(issue => correctableCodes.has(issue.code) || String(issue.path || "").startsWith("task_outcomes."));
  const reason_codes: string[] = [];
  if (!all_tasks_accounted) reason_codes.push("TASKS_NOT_TERMINAL");
  if (blocking.length) reason_codes.push("VALIDATION_ERRORS_REMAIN");
  if (!required_reviews_complete) reason_codes.push("TERMINAL_REVIEW_PENDING");
  if (unhandled_advice) reason_codes.push("UNHANDLED_ADVICE");
  if (!evidence_integrity_ok) reason_codes.push("EVIDENCE_INTEGRITY_FAILED");
  const validationErrors = [...new Set(blocking.map(i => i.message))];
  state.validationErrors = validationErrors;
  return { repairableOnly, ready: !reason_codes.length, all_tasks_terminal: strictly_terminal, all_tasks_accounted, validation_passed: !blocking.length,
    required_reviews_complete, unhandled_advice, evidence_integrity_ok, reason_codes,
    blocking_error_count: blocking.length, issues, pending, invalidEvidence, validationErrors };
}

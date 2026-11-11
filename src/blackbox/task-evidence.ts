import type { RunCheckpoint } from "./progress.js";
import type { ValidationIssue } from "./acceptance.js";
import { taskHasRecoveredEvidence } from "./recovery.js";

// Only ledger records representing reviews, corrections or the requests that produced a result may
// serve as audit references. "tool-request" is the natural citation for "which call did this", and
// the Observer itself tells the agent to move request ids there.
const auditKinds = new Set(["checkpoint-recovery", "operator-review", "observer-review", "task-outcome-correction", "advice-disposition", "tool-request"]);

export function taskEvidenceIssue(state: RunCheckpoint, evidence: Record<string, unknown>[], taskId: string, ref: string, path: string): ValidationIssue | undefined {
  const fact = evidence.find(e => e.id === ref);
  const data = fact?.data as Record<string, unknown> | undefined;
  let rule: string | undefined;
  if (!fact) rule = "evidence_exists_in_session";
  else if (fact.kind !== "tool-result") rule = "execution_evidence_must_be_tool_result";
  else if (taskHasRecoveredEvidence(state, evidence, fact, taskId)) return;
  else if (data?.ok !== true || data.error) rule = "tool_result_must_succeed";
  else if (data.task_id !== taskId) rule = "tool_result_must_belong_to_task";
  if (rule) return { code: "TASK_EVIDENCE_INVALID", severity: "error", task_id: taskId, evidence_id: ref, path, rule,
    message: `task_evidence_invalid:${taskId}:${ref}`, detail: `${rule}; actual kind=${String(fact?.kind)}, task_id=${String(data?.task_id)}, ok=${String(data?.ok)}. 审计记录请放入 audit_ids；不得从 evidence_ids 静默过滤。` };
}

export function taskAuditIssues(evidence: Record<string, unknown>[], taskId: string, refs: string[], path: string): ValidationIssue[] {
  // 教学式拒绝：把"这个任务现在能引用哪些 audit id"直接写进 detail。
  // 2026-10-28 实测：模型连续 7 轮把 agent-analysis 的 ev-id 塞进 audit_ids，每轮只收到
  // 一句 `actual kind=agent-analysis`，它并不知道该换成哪一条，于是无限重试。
  const allowed = evidence
    .filter(item => auditKinds.has(String(item.kind)) && String((item.data as Record<string, unknown> | undefined)?.task_id || "") === taskId)
    .map(item => String(item.id))
    .slice(0, 4);
  return refs.flatMap((ref, index) => {
    const fact = evidence.find(e => e.id === ref);
    if (fact && auditKinds.has(String(fact.kind))) return [];
    return [{ code: "TASK_AUDIT_INVALID", severity: "error" as const,
      task_id: taskId, evidence_id: ref, path: `${path}.${index}`, rule: "audit_reference_must_exist_and_have_audit_kind",
      message: `task_audit_invalid:${taskId}:${ref}`,
      valid_ids: allowed,
      detail: `actual kind=${String(fact?.kind)}；audit_ids 只接受 ${[...auditKinds].join("/")}；本任务当前可引用：${allowed.length ? allowed.join("、") : "（暂无，先落一条 tool-request）"}；结论引用的证据放 evidence_ids` }];
  });
}

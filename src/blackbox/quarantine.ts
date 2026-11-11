/**
 * 证据类校验失败的**静默降级**（2026-11-06）。
 *
 * 起因是一类反复出现的收场方式：整场评估跑得不错，结论也站得住，但有**一条**记账
 * 写错了——某条发现引用的证据 id 在账本里不存在，或者某条 blocked 任务的结案说明
 * 一条证据都没引。验收把这条记成 error，`validation_failed_review_required` 于是把
 * 整场会话停在 `awaiting_operator`：**为一条记账错误丢掉整份报告**。
 *
 * 实测 e8bdb447acf02283 就是这样收场的：唯一阻塞项是
 * `TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE:T2`（这条任务名下有 22 条执行证据，
 * 结案说明一条没引），其余全部终态。而它修不好——任务已经是 blocked，模型再声明
 * 一次走的是幂等跳过分支（progress.ts），根本没有"补引用"的入口。
 *
 * 这里做三件事，对应"拦截而非终止 / 隔离脏数据 / 保留原始日志"：
 *   1. 把阻塞项分成「可以给模型改的」和「只能隔离的」；
 *   2. 隔离 = 打标记（不删数据）：发现从报告主体剔除、任务降级为"结论未经证据支撑"，
 *      原始记录连同被剔除的引用一起留在 `quarantine` 账里，附录可查；
 *   3. 给模型的修正提示要**具体**（哪条、缺什么、可用的 id 候选池），
 *      只写"校验失败"它会原样再交一遍（见 context.ts 里 reject_envelopes 的教训）。
 */

export type IssueLike = {
  code?: string; severity?: string; path?: string; message?: string;
  task_id?: string; advice_id?: string; evidence_id?: string;
  rule?: string; detail?: string; valid_ids?: string[];
};

export type QuarantineTarget = {
  kind: "finding" | "task";
  id: string;
  /** 这条为什么被隔离：直接给人读，进附录。 */
  reason: string;
  /** 模型可以抄的错误码，便于它自己对照规则。 */
  code: string;
};

/**
 * 哪些错误属于"证据记账写错"，而不是"结论本身有问题"。
 *
 * 判据：错在**引用关系**上——被引用的东西不存在、或者明明是自己的证据却没引。
 * 这类错误可以隔离掉那一项继续交付；而 `COMPLETION_ON_DENIED_EVIDENCE`（拿 401 当
 * 漏洞证据）、`ANOMALY_REQUIRES_DIFF`（异常缺对照）错在**结论的依据**上，
 * 隔离它等于把一条站不住的结论洗白，不能进这个集合。
 */
export const EVIDENCE_REFERENCE_CODES = new Set([
  "FINDING_EVIDENCE_INVALID",     // 发现引用了不存在的证据 / 没引到该目标成功的工具结果
  "FINDING_REVIEW_INVALID",       // Observer 裁决引用了不属于该发现的证据
  "TASK_EVIDENCE_INVALID",        // 任务的结案引用不存在或不属于该任务
  "TASK_AUDIT_INVALID",           // 审计引用不存在
  "TASK_EVIDENCE_MISSING",        // 完成了却一条证据都没引
  "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE", // blocked 了，有证据却没引用
  "OUTCOME_WITHOUT_EVIDENCE_REFERENCE",      // 同上，结案提交时的即时拒收
]);

export function isEvidenceReferenceIssue(issue: IssueLike): boolean {
  return EVIDENCE_REFERENCE_CODES.has(String(issue.code || ""));
}

/** 从 `findings.f_xxx.evidence_ids` / `tasks.T2.outcome_evidence_ids` 里取出被点名的主体。 */
function subjectOf(issue: IssueLike): { kind: "finding" | "task"; id: string } | undefined {
  const path = String(issue.path || "");
  const finding = /^findings\.([^.]+)\./.exec(path);
  if (finding?.[1]) return { kind: "finding", id: finding[1] };
  const task = /^tasks\.([^.]+)\./.exec(path);
  if (task?.[1]) return { kind: "task", id: task[1] };
  // 结案提交的拒收走 `task_outcomes.<index>.*`，主体只能从 issue.task_id 拿。
  if (issue.task_id) return { kind: "task", id: String(issue.task_id) };
  // FINDING_EVIDENCE_INVALID 的 message 形如 `f_xxx:候选发现引用了不存在的会话证据`。
  const message = String(issue.message || "");
  const prefix = /^([^:]+):/.exec(message);
  if (prefix?.[1] && /^f[_-]/.test(prefix[1])) return { kind: "finding", id: prefix[1] };
  if (prefix?.[1] && /^[A-Za-z0-9_.-]+$/.test(prefix[1])) return { kind: "task", id: prefix[1] };
  return undefined;
}

/**
 * 把阻塞项归成"可以隔离的"与"隔离了也不该放的"。
 *
 * 调用方（门禁）只用第一个数组；第二个数组原样留着继续阻塞，并明确记进事件——
 * 因为它们是"结论本身站不住"，不是记账问题。
 */
export function partitionBlocking(issues: IssueLike[]): {
  quarantinable: QuarantineTarget[];
  fatal: IssueLike[];
} {
  const quarantinable: QuarantineTarget[] = [];
  const fatal: IssueLike[] = [];
  const seen = new Set<string>();
  for (const issue of issues || []) {
    if (String(issue.severity || "") !== "error") continue;
    if (!isEvidenceReferenceIssue(issue)) { fatal.push(issue); continue; }
    const subject = subjectOf(issue);
    if (!subject) { fatal.push(issue); continue; }
    const key = `${subject.kind}:${subject.id}:${issue.code}`;
    if (seen.has(key)) continue;
    seen.add(key);
    quarantinable.push({
      kind: subject.kind,
      id: subject.id,
      code: String(issue.code || ""),
      reason: String(issue.detail || issue.message || "证据引用无效").slice(0, 400),
    });
  }
  return { quarantinable, fatal };
}

/**
 * 「没有一项可隔离」时的解释文本（2026-11-10）。
 *
 * 旧写法在 `settleEvidenceBlocks` 里直接 `return "dirty"`，日志只剩 `supervisor-pause`
 * + `validation-failed`：既看不出卡在哪一条，也看不出为什么隔离不动。实测
 * `1dd9ded9ed239711` 连续五场停场，人只能翻 checkpoint 才找到那两条账本残渣。
 *
 * 这里把阻塞项原样摊开，并且**区分两种 dirty**：
 *   - 全部落在 `transitionErrors.` 上 → 这些是账本里的历史记录，不是本轮输出，
 *     隔离按设计就不该碰它；如果它们指向的任务/建议已终态，说明剪枝漏了码，
 *     该修 `pruneAdviceErrors`（`stop: ledger_residue`）。
 *   - 混着别的路径 → 真的错在结论依据上，隔离等于洗白，停场是对的
 *     （`stop: unsupported_conclusion`）。
 */
export function unquarantinableDigest(issues: IssueLike[]): { text: string; data: Record<string, unknown> } | undefined {
  const rows = (issues || [])
    .filter(issue => String(issue.severity || "") === "error")
    .map(issue => ({
      code: String(issue.code || ""),
      path: String(issue.path || ""),
      detail: String(issue.detail || issue.message || "").slice(0, 200),
    }))
    .slice(0, 8);
  if (!rows.length) return undefined;
  const unreachable = rows.every(row => row.path.startsWith("transitionErrors."));
  const short = rows.map(row => `${row.code}:${row.path.replace(/^transitionErrors\./, "")}`).join("、");
  const text = `门禁 ${rows.length} 处阻塞里没有一项属于证据引用问题，隔离无从下手：${short}。`
    + (unreachable
      ? "这些都是**转移账本**里的历史记录（不是本轮输出），按设计不能隔离——若它们对应的任务/建议已经终态，"
        + "说明剪枝漏了这个码，应修 pruneAdviceErrors 而不是隔离。"
      : "这些错在结论依据上，隔离等于把站不住的结论洗白，照旧停场交人看。");
  return { text, data: { fatal: rows, stop: unreachable ? "ledger_residue" : "unsupported_conclusion" } };
}

/**
 * 隔离一条发现：打标记，**不删数据**。
 *
 * `status` 原样保留：`confirmed` / `rejected` 是评审结论，是历史事实；
 * 报告靠 `quarantined` 标志把它从主体挪到附录，而不是假装它从没存在过。
 */
export function quarantineFindings(
  state: { findings?: Record<string, Record<string, unknown>> },
  targets: QuarantineTarget[],
): QuarantineTarget[] {
  const findings = state.findings || {};
  const done: QuarantineTarget[] = [];
  for (const target of targets) {
    if (target.kind !== "finding") continue;
    const record = findings[target.id];
    if (!record) continue;
    record.quarantined = true;
    record.quarantine_reason = target.reason;
    record.quarantine_code = target.code;
    record.quarantined_at = Date.now();
    done.push(target);
  }
  return done;
}

/**
 * 隔离一条任务的证据引用：把不存在的 id 从引用列表里摘出来，
 * 任务本体降级为 `evidence_status: "unverified"`。
 *
 * 为什么不直接删任务：任务状态是"这条工作做到哪了"，与引用对不对是两件事。
 * 摘掉无效引用后仍在的，算有效引用；一条都不剩的，结论就变成"未经证据支撑"——
 * 报告里如实这么写，比让它卡死整场、或者假装引用有效，都更接近真相。
 */
export function quarantineTaskRefs(
  state: { tasks?: Record<string, Record<string, unknown>> },
  evidence: Record<string, unknown>[],
  targets: QuarantineTarget[],
): Array<QuarantineTarget & { stripped: string[] }> {
  const known = new Set((evidence || []).map(item => String(item.id || "")).filter(Boolean));
  const tasks = state.tasks || {};
  const done: Array<QuarantineTarget & { stripped: string[] }> = [];
  for (const target of targets) {
    if (target.kind !== "task") continue;
    const record = tasks[target.id];
    if (!record) continue;
    const fields = ["evidence_ids", "outcome_evidence_ids", "audit_ids"] as const;
    const stripped: string[] = [];
    for (const field of fields) {
      const list = Array.isArray(record[field]) ? (record[field] as string[]).map(String) : [];
      if (!list.length) continue;
      const keep = list.filter(id => known.has(id));
      const dropped = list.filter(id => !known.has(id));
      if (!dropped.length) continue;
      stripped.push(...dropped);
      record[field] = keep;
      const log = Array.isArray(record.stripped_refs) ? (record.stripped_refs as unknown[]) : [];
      record.stripped_refs = [...log, { field, dropped, at: Date.now() }].slice(-6);
    }
    const remaining = ["evidence_ids", "outcome_evidence_ids"].some(field => Array.isArray(record[field]) && (record[field] as unknown[]).length);
    // `TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE` 这类"有证据但没引"，摘不出任何东西——
    // 它没有错引用可摘，只是漏了引用。这种也标 unverified：结论确实缺支撑。
    if (!remaining || target.code === "TASK_OUTCOME_WITHOUT_EVIDENCE_REFERENCE" || target.code === "TASK_EVIDENCE_MISSING") {
      record.evidence_status = "unverified";
      record.evidence_status_reason = target.reason;
    }
    record.quarantined_at = Date.now();
    done.push({ ...target, stripped });
  }
  return done;
}

/**
 * 给模型的修正提示。
 *
 * 只列前三项 + 总数：这是"改账"而不是"再打一遍"，一屏就够；
 * 但每一项必须带**可用的 id 候选**，否则模型只会把同一个错 id 再交一次
 * （context.ts 里 `reject_envelopes` 的注释记着同一教训：7 轮重复提交同一条错证据）。
 */
export function repairDigest(
  targets: QuarantineTarget[],
  evidence: Record<string, unknown>[],
  attempt: number,
  limit: number,
): string {
  const usable = (evidence || [])
    .filter(item => String(item.kind || "") === "tool-result" && (item.data as Record<string, unknown> | undefined)?.ok === true)
    .map(item => String(item.id || ""))
    .filter(Boolean)
    .slice(-8);
  const lines = targets.slice(0, 3).map(target =>
    `- ${target.kind === "finding" ? "发现" : "任务"} ${target.id}：${target.reason}`);
  const more = targets.length > 3 ? `（另有 ${targets.length - 3} 项同类问题）` : "";
  return `门禁发现 ${targets.length} 处**证据引用**问题，这次不停场，先给你改：\n${lines.join("\n")}${more}\n`
    + (usable.length ? `近几轮可用的证据 id（确认过存在、且工具调用成功）：${usable.join("、")}。\n` : "")
    + `改法：\n`
    + `- 发现引错了 → 用**新 id** 重新提交一条引用真实证据的 finding（已有发现不可覆盖），并把旧的那条当作作废，不要再提交；\n`
    + `- 任务结案时漏引证据 → 在 task_outcomes 里对同一条任务补上 evidence_ids（只补空位，历史引用不会被覆盖）；\n`
    + `- 实在找不到能支撑它的证据 → 承认这一点：把结论降级（needs_evidence / blocked）比硬凑一条证据正确。\n`
    + `第 ${attempt}/${limit} 次修正机会；改不动的话，控制面会把这一项隔离出报告正文、在附录里留痕，其余工作照常交付。`;
}

/** 报告附录与上下文共用的隔离清单。 */
export function quarantineView(state: { findings?: Record<string, Record<string, unknown>>; tasks?: Record<string, Record<string, unknown>> }): Array<{ kind: string; id: string; title?: string; reason: string; code?: string }> {
  const rows: Array<{ kind: string; id: string; title?: string; reason: string; code?: string }> = [];
  for (const [id, finding] of Object.entries(state.findings || {})) {
    if (!finding?.quarantined) continue;
    rows.push({ kind: "finding", id, title: String(finding.title || ""), reason: String(finding.quarantine_reason || ""), code: String(finding.quarantine_code || "") });
  }
  for (const [id, task] of Object.entries(state.tasks || {})) {
    if (String(task?.evidence_status || "") !== "unverified") continue;
    rows.push({ kind: "task", id, reason: String(task.evidence_status_reason || "结论引用无效"), code: "EVIDENCE_UNVERIFIED" });
  }
  return rows;
}

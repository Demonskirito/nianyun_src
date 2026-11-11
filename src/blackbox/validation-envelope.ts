/**
 * 结构化校验回执（Reject Envelope v2）
 *
 * 背景（2026-10-28 note.yun 会话）：`required_tasks` 有 13 条任务项被丢弃，
 * 回执只有一句 `(item): Invalid input`。模型不知道缺哪个键，只能把整条任务重写一遍，
 * 于是同一件事被声明了 8 次（`T1/T2/T3` 各 8 条 `merged_from`），上下文被自己的复述撑爆。
 *
 * 这一层做的事：把 zod 的 issues 翻译成"填空式"回执——
 *   缺哪个键 → missing_keys
 *   哪个键类型错 → invalid_keys（写清 expected / received）
 *   哪个键不认识 → unknown_keys
 *   该长什么样 → correct_shape_example
 *
 * 目标：一次填空就能过，而不是猜五轮。
 */

export type IssueSnapshot = {
  code: string;
  path: Array<string | number>;
  message: string;
  expected?: string;
  received?: string;
  keys?: string[];
  union_errors?: IssueSnapshot[][];
};

export type RejectEnvelopeV2 = {
  status: "rejected";
  reason: "schema_validation_failed";
  /** `required_tasks[2]` 这样的定位，模型可以直接对应到自己发的那一条。 */
  target: string;
  missing_keys: string[];
  invalid_keys: Record<string, string>;
  unknown_keys: string[];
  /** 无字段可指的条目级错误（union 全灭 / 不是对象）时的原始说明。 */
  item_level_errors: string[];
  correct_shape_example: Record<string, unknown>;
  hint: string;
};

/** zod 的 issue 是鸭子类型：只取我们需要的字段，避免依赖具体版本的类型导出。 */
export function snapshotIssues(issues: unknown[]): IssueSnapshot[] {
  return (issues || []).map(raw => {
    const issue = (raw || {}) as Record<string, unknown>;
    const path = Array.isArray(issue.path) ? (issue.path as Array<string | number>) : [];
    const union = Array.isArray(issue.unionErrors)
      ? (issue.unionErrors as Array<{ issues?: unknown[] }>).map(error => snapshotIssues(error.issues || []))
      : undefined;
    return {
      code: String(issue.code || "unknown"),
      path,
      message: String(issue.message || ""),
      ...(issue.expected !== undefined ? { expected: String(issue.expected) } : {}),
      ...(issue.received !== undefined ? { received: String(issue.received) } : {}),
      ...(Array.isArray(issue.keys) ? { keys: (issue.keys as unknown[]).map(String) } : {}),
      ...(union ? { union_errors: union } : {}),
    };
  });
}

function joinPath(path: Array<string | number>): string {
  return path.map(part => (typeof part === "number" ? `[${part}]` : `.${part}`)).join("").replace(/^\./, "");
}

/**
 * 把一批 issues 归类成"缺键 / 值错 / 未知键"。
 *
 * 关键判断：`invalid_type` + `received === "undefined"` 就是**缺键**，
 * 而不是"类型错"——这两类修法完全不同（补键 vs 改值），混在一起模型没法照做。
 */
export function classifyIssues(
  issues: IssueSnapshot[],
  options: { nested?: boolean } = {},
): { missing: string[]; invalid: Record<string, string>; unknown: string[]; itemLevel: string[] } {
  const missing = new Set<string>();
  const invalid: Record<string, string> = {};
  const unknown = new Set<string>();
  const itemLevel: string[] = [];

  const walk = (list: IssueSnapshot[]) => {
    for (const issue of list) {
      if (issue.union_errors?.length) {
        // union 全灭：取"最接近成功"的那一支（缺键最少的）来报告，其余丢弃。
        const branches = issue.union_errors
          .map(branch => ({ branch, stats: classifyIssues(branch, { nested: true }) }))
          .sort((left, right) => left.stats.missing.length - right.stats.missing.length);
        const best = branches[0];
        if (best) walkIssueStats(best.stats);
        continue;
      }
      walkIssueStats(classifyIssues([issue], options));
    }
  };

  const walkIssueStats = (stats: ReturnType<typeof classifyIssues>) => {
    for (const key of stats.missing) missing.add(key);
    for (const [key, value] of Object.entries(stats.invalid)) invalid[key] = value;
    for (const key of stats.unknown) unknown.add(key);
    itemLevel.push(...stats.itemLevel);
  };

  for (const issue of issues) {
    if (issue.union_errors?.length) { walk([issue]); continue; }
    if (issue.code === "unrecognized_keys") { for (const key of issue.keys || []) unknown.add(key); continue; }
    const where = joinPath(issue.path);
    if (issue.code === "invalid_type" && (issue.received === "undefined" || issue.received === "NaN")) {
      missing.add(where);
      continue;
    }
    if (issue.code === "invalid_type") {
      invalid[where || "(item)"] = `expected ${issue.expected || "?"}, got ${issue.received || "?"}`;
      continue;
    }
    if (!where) { itemLevel.push(`${issue.code}: ${issue.message}`.slice(0, 200)); continue; }
    invalid[where] = `${issue.code}: ${issue.message}`.slice(0, 200);
  }

  return { missing: [...missing], invalid, unknown: [...unknown], itemLevel: [...new Set(itemLevel)] };
}

/**
 * 组装最终回执。
 *
 * `example` 来自字段/工具指南（fieldGuide / toolGuide），保证"照着抄就能过"。
 */
export function rejectEnvelope(
  issues: IssueSnapshot[],
  input: {
    field: string;
    index: number;
    example?: Record<string, unknown>;
    hint?: string;
  },
): RejectEnvelopeV2 {
  const stats = classifyIssues(issues);
  const target = `${input.field}[${input.index}]`;
  const parts: string[] = [];
  if (stats.missing.length) parts.push(`缺字段 ${stats.missing.join("、")}`);
  if (Object.keys(stats.invalid).length) parts.push(`取值不合法 ${Object.keys(stats.invalid).join("、")}`);
  if (stats.unknown.length) parts.push(`不认识的键 ${stats.unknown.join("、")}`);
  if (stats.itemLevel.length) parts.push(`整体形状不对（${stats.itemLevel[0]!.slice(0, 80)}）`);
  return {
    status: "rejected",
    reason: "schema_validation_failed",
    target,
    missing_keys: stats.missing,
    invalid_keys: stats.invalid,
    unknown_keys: stats.unknown,
    item_level_errors: stats.itemLevel,
    correct_shape_example: input.example || {},
    hint: input.hint || (parts.length ? `${target}：${parts.join("；")}。只改这一条，其它条目不用重写。` : `${target} 形状不对，按 correct_shape_example 重写这一条`),
  };
}

/** 一句话摘要，写进事件与 `_dropped` 的 message（保留原有字段，便于既有读者）。 */
export function envelopeSummary(envelope: RejectEnvelopeV2): string {
  const bits: string[] = [];
  if (envelope.missing_keys.length) bits.push(`缺 ${envelope.missing_keys.join("+")}`);
  if (Object.keys(envelope.invalid_keys).length) bits.push(`值错 ${Object.keys(envelope.invalid_keys).join("+")}`);
  if (envelope.unknown_keys.length) bits.push(`多 ${envelope.unknown_keys.join("+")}`);
  if (!bits.length && envelope.item_level_errors.length) bits.push(envelope.item_level_errors[0]!.slice(0, 60));
  return `${envelope.target}: ${bits.join("；") || "形状不对"}`;
}
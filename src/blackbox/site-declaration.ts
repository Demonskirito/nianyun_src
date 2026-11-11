/**
 * 站点声明文件引水（robots.txt / sitemap.xml）。
 *
 * 为什么单独成模块：
 *   2026-11-04 实测会话 5b59aa1d059b56da，`/sitemap.xml` 第一次抓取拿到 403，
 *   此后**再没重试**——站点自报的 18 个 `/help/*.html` 业务页整批丢失，业务面归零。
 *   对比 6 分钟前那次会话（09a67a8a9aa67cec）同一文件 200、18 个业务页全部入图：
 *   差别不在代码接没接上，而在"一次失败被当成了结论"。
 *
 * 判据要点：
 *   · 200 且有正文、不是拦截页 → 结论（ok）
 *   · 404 / 410 → 结论（站点确实没有这个文件，absent）
 *   · 401 → 结论（匿名拿不到，auth）
 *   · 403 / 412 / 429 / 5xx / 0（网络失败）/ 墙指纹命中 → **不是结论**（retry）
 *
 * 403 为什么不算结论：该站同一 URL 在 6 分钟内出现过 200 → 403 → 200 的抖动，
 * 这是动态风控窗口，不是"禁止访问"。把它写成结论，等于让一次抖动删掉整个业务面。
 *
 * 重试节流：同一 host 最多 3 轮，每轮间隔 45s（按 next_at 判定"是否同一轮"，
 * 因为 robots 与 sitemap 通常在同一个动作里各打一次，不该各算一轮）。
 */

export type DeclarationPath = "/robots.txt" | "/sitemap.xml";

/** 顺序有意义：先 robots（里面常带 `Sitemap:` 行），再 sitemap。 */
export const SITE_DECLARATION_PATHS: DeclarationPath[] = ["/robots.txt", "/sitemap.xml"];

/** 最多重试轮数：3 轮之后仍被墙，说明这道墙不是抖动，交给爬取/JS 反向去补业务面。 */
export const SITE_DECLARATION_MAX_ATTEMPTS = 3;

/** 两轮之间的最小间隔：风控窗口实测在 30–60s 量级，45s 取中位。 */
export const SITE_DECLARATION_COOLDOWN_MS = 45_000;

export type DeclarationVerdict = "ok" | "absent" | "auth" | "retry";

export type DeclarationFileRecord = {
  status: number;
  at: number;
  verdict: DeclarationVerdict;
  /** 正文长度：7155B 这类挑战页长度固定，用来和真正文区分。 */
  bytes?: number;
  /** 命中墙指纹时的 marker（见 graph/extract.ts 的 wallOf）。 */
  wall?: string;
};

export type DeclarationHostState = {
  at: number;
  /** 已经试过几轮（不是几次请求）。 */
  attempts: number;
  /** 早于这个时间点不再重试（冷却窗口）。 */
  next_at: number;
  task_id?: string;
  /**
   * 终结信号已发出过的时间。
   *
   * 为什么需要：重试耗尽或拿到终态时，控制面要告诉模型一句结论。
   * 但引水任务只在 `retry` 分支才建——如果模型的自我重打刚好都落在冷却边界上，
   * 任务可能一次都没建出来（实测会话 bd2b519a4f5037c5：attempts 到 5，任务仍为空）。
   * 那种情况下旧代码直接 `return`，模型既收不到"已到手"也收不到"别再打"，只能自己猜。
   * 这个字段用来保证同一结论只播报一次。
   */
  settled_at?: number;
  files: Partial<Record<DeclarationPath, DeclarationFileRecord>>;
};

/**
 * 这次请求打的是不是站点声明文件。
 *
 * 只认 pathname：`/sitemap.xml?ts=...` 是同一份文件（desk 会给重试加 cache-buster），
 * `sitemap_index.xml` 也归到 `/sitemap.xml` 这一格，避免同一语义占两个键。
 */
export function declarationPathOf(rawUrl: string): DeclarationPath | undefined {
  let path = "";
  try { path = new URL(String(rawUrl || "")).pathname.toLowerCase(); } catch { return undefined; }
  if (path === "/robots.txt") return "/robots.txt";
  if (path === "/sitemap.xml" || path === "/sitemap_index.xml") return "/sitemap.xml";
  return undefined;
}

/** 把一次响应判成终态还是待重试。 */
export function classifyDeclaration(
  input: { status: number; bytes?: number; wall?: string; path?: DeclarationPath },
): DeclarationVerdict {
  const status = Number(input.status || 0);
  // 墙指纹优先于状态码：attestation 挑战在 200 与 403 之间来回出现，
  // 只看状态码会把 200 的挑战页当成"拿到了 sitemap"。
  if (input.wall) return "retry";
  /**
   * 200 的判定要分三种（2026-11-05 实测会话 773eae1a2d5b6c0c 修正）：
   *
   *   ① bytes 未知（工具只回头部、body 没带回来）→ **ok**。
   *      旧规则把"未知"当成 0，判 retry，于是同一个 200 被反复重打：
   *      那次 /robots.txt 连续 4 轮都是 200，耗尽后把已经到手的 sitemap
   *      （18 个 /help 页）一起判成失败。
   *   ② `/robots.txt` 的 0 字节是合法语义（= 不限制任何路径）→ ok。
   *   ③ `/sitemap.xml` 的 0 字节是空壳（解析不出任何 <loc>）→ retry。
   *      这一条保留"空壳不是 sitemap"的原意，但只落在真正有语义的那一侧。
   *
   * 真正的拦截页由上面的 `input.wall` 兜住，不靠长度猜。
   */
  if (status === 200) {
    if (input.bytes === undefined) return "ok";
    if (Number(input.bytes) > 0) return "ok";
    return input.path === "/sitemap.xml" ? "retry" : "ok";
  }
  if (status === 204 || status === 404 || status === 410) return "absent";
  if (status === 401) return "auth";
  // 403 不是结论：该站实测 6 分钟内 200 → 403 → 200。
  if (status === 403 || status === 412 || status === 418 || status === 429) return "retry";
  if (status === 0 || status >= 500) return "retry";
  // 其余状态码（405 / 400 等）对 GET 声明文件没有确定语义，按未结论处理。
  return "retry";
}

export type DeclarationNeed = {
  need: boolean;
  reason: "first" | "retry" | "cooldown" | "exhausted" | "done";
  /** 还没拿到终态的文件。 */
  missing: DeclarationPath[];
  attempts: number;
  /** 已经被墙挡下的文件（用于结案文案）。 */
  blocked: DeclarationPath[];
  /**
   * 已经交付的文件（verdict=ok）。
   *
   * 为什么单独记：sitemap 拿到 200、18 个 /help 页已进图，而 robots 还在风控抖动里——
   * 这是"业务面已到手、附属文件未终结"，不是失败。没有这一栏，
   * 3 轮耗尽后整条任务会被判 blocked，模型会以为业务面没拿到，转头去爬静态路径。
   */
  delivered: DeclarationPath[];
};

/** 现在该不该引水；不该的话原因是什么（cooldown / exhausted / done 三种都有用）。 */
export function declarationNeed(state: DeclarationHostState | undefined, now: number): DeclarationNeed {
  const files = state?.files || {};
  const verdictOf = (path: DeclarationPath): DeclarationVerdict | undefined => files[path]?.verdict;
  const missing = SITE_DECLARATION_PATHS.filter(path => {
    const verdict = verdictOf(path);
    return verdict !== "ok" && verdict !== "absent" && verdict !== "auth";
  });
  const blocked = SITE_DECLARATION_PATHS.filter(path => verdictOf(path) === "retry");
  const delivered = SITE_DECLARATION_PATHS.filter(path => verdictOf(path) === "ok");
  const attempts = Number(state?.attempts || 0);
  if (!missing.length) return { need: false, reason: "done", missing, attempts, blocked, delivered };
  if (attempts >= SITE_DECLARATION_MAX_ATTEMPTS) return { need: false, reason: "exhausted", missing, attempts, blocked, delivered };
  // 从未试过（state 还没有）时不该被 next_at 挡住。
  if (state && now < Number(state.next_at || 0)) return { need: false, reason: "cooldown", missing, attempts, blocked, delivered };
  return { need: true, reason: attempts > 0 ? "retry" : "first", missing, attempts, blocked, delivered };
}

/**
 * 记一次声明文件响应。
 *
 * `attempts` 按"轮"加：同一冷却窗口内打 robots 与 sitemap 各一次，仍算一轮。
 * 否则 3 轮上限会被两个文件对半砍成 1.5 轮，冷却还没到就判 exhausted。
 */
export function recordDeclaration(
  prev: DeclarationHostState | undefined,
  input: { path: DeclarationPath; status: number; bytes?: number; wall?: string; at: number },
): DeclarationHostState {
  const at = Number(input.at || Date.now());
  const verdict = classifyDeclaration(input);
  const base: DeclarationHostState = prev || { at, attempts: 0, next_at: 0, files: {} };
  const sameRound = Boolean(prev) && at < Number(base.next_at || 0);
  const attempts = sameRound ? base.attempts : base.attempts + 1;
  const files = {
    ...base.files,
    [input.path]: {
      status: Number(input.status || 0),
      at,
      verdict,
      ...(input.bytes !== undefined ? { bytes: Number(input.bytes) } : {}),
      ...(input.wall ? { wall: input.wall } : {}),
    } satisfies DeclarationFileRecord,
  };
  return {
    ...base,
    at,
    attempts,
    // 只有"待重试"才开冷却窗口；拿到终态时 next_at 归零，下一步判定直接走 done。
    next_at: verdict === "retry" ? at + SITE_DECLARATION_COOLDOWN_MS : at,
    files,
  };
}

/** 派给 agent 的引水任务描述（控制面自建，不依赖模型自己想）。 */
export function declarationTaskSpec(
  origin: string,
  need: DeclarationNeed,
  prev: DeclarationHostState | undefined,
): { id: string; target: string; purpose: string; reason: string; completion_criteria: string; deliverables: string[]; success_criteria: string } {
  const missingLabel = need.missing.join("、");
  const priorAttempt = need.reason === "retry"
    ? `这是第 ${need.attempts + 1} 轮：上一轮 ${priorHint(prev)}——**那不是结论**，是动态风控窗口（同一 URL 6 分钟内实测 200 → 403 → 200）。`
    : "";
  return {
    id: "T_SITE_DECLARATION",
    target: `${origin}${need.missing[0] || "/sitemap.xml"}`,
    purpose: `取回 ${origin} 的站点声明文件（${missingLabel}），把站点自己声明的业务面接进图`,
    reason: `${priorAttempt}声明文件是业务面的权威来源（实测同一 sitemap 声明了 18 个 /help/*.html，爬取一条都没覆盖到）；`
      + `一次 403/412/5xx 不代表文件不存在。`,
    completion_criteria: "每个文件都要拿到终态：200 且有正文（非拦截页）/ 404 / 410 / 401。403、412、429、5xx、空响应都不算结论。",
    deliverables: ["site_declaration"],
    success_criteria: "robots.txt 与 sitemap.xml 各自给出终态与状态码；有 <loc> 的逐条进图（source=sitemap）",
  };
}

function priorHint(prev: DeclarationHostState | undefined): string {
  if (!prev) return "未尝试";
  const parts = SITE_DECLARATION_PATHS
    .map(path => {
      const record = prev.files[path];
      if (!record) return "";
      return `${path} ${record.status || "无响应"}${record.wall ? `（命中 ${record.wall}）` : ""}`;
    })
    .filter(Boolean);
  return parts.length ? parts.join("、") : "未取得响应";
}

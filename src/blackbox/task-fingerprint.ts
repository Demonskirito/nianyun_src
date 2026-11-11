/**
 * 任务指纹：同一个"要做的事"不该被模型换个 id 再登记一遍。
 *
 * 实测事故（gray-push 会话，恢复两次后）：pending 从 8 涨到 32，其中
 *   CORS 反射验证      T6 / T6_cors_verify / T20_cors_verify / T7                ← 4 份
 *   取真实 umi bundle  T_CDN_JS / T_js_bundle / T8_cdn_js / T31 / T32 / T11 /
 *                      T11_bundle_hunt / T21_cdn_js_real / T13                   ← 9 份
 *   API 方法面判定     T_CATCHALL_METHOD / T7_api_auth_code / T9 / T14 /
 *                      T23_api_authcode / T33 / T12_post_surface_api             ← 7 份
 *
 * 原因是 `progress.merge()` 只按 `spec.id` 记账：模型每轮重新起名（有时以为自己在"细化"），
 * 调度器就建一条新 pending，旧的永远躺着。
 *
 * 判重靠三个信号，全部在真实数据上量过（见 test/task-dedupe.test.ts）：
 *   1. 规范化后完全相等        —— 只差标点/大小写/任务 id/时间戳（c2 与 c4：0.933 也归这类）
 *   2. 字符 bigram Jaccard ≥0.6 —— 同一句话换个语序
 *   3. 同一 playbook + ASCII 术语重合 ≥1 且 Jaccard ≥0.34 —— 换句式的同义改写
 *
 * 为什么不用分词 Jaccard：中文任务描述大多不带空格，按空格切只有一个"词"，相似度恒为 0 或 1。
 */

const ID_LIKE = /\b(?:t\d+[a-z_]*\d*|ev-[0-9a-f]{8,}|\d{10,})\b/gi;
const PUNCT = /[\s，。、；：！？（）【】《》"'`“”‘’·…—\-–_/\\|@#$%^&*+=~<>[\]{}()]+/g;

/** 规范化：吃掉 id、时间戳、标点、大小写。 */
export function normalizePurpose(purpose: unknown): string {
  return String(purpose ?? "").toLowerCase().replace(ID_LIKE, " ").replace(PUNCT, "").trim();
}

/** 指纹：规范化文本本身（中文无空格，不能再分词）。 */
export function taskFingerprint(purpose: unknown): string {
  return normalizePurpose(purpose);
}

function bigrams(text: string): Set<string> {
  const out = new Set<string>();
  for (let index = 0; index < text.length - 1; index += 1) out.add(text.slice(index, index + 2));
  return out;
}

/** 字符 bigram Jaccard：对中文改写比词元 Jaccard 有用得多。 */
export function purposeSimilarity(a: unknown, b: unknown): number {
  const left = bigrams(normalizePurpose(a));
  const right = bigrams(normalizePurpose(b));
  if (!left.size || !right.size) return 0;
  let intersection = 0;
  for (const gram of left) if (right.has(gram)) intersection += 1;
  return intersection / (left.size + right.size - intersection);
}

/** ASCII 术语（cors / acao / umi / bundle / waf / catch-all…）：同一件事的技术锚点。 */
export function conceptKeys(purpose: unknown): string[] {
  const ascii = String(purpose ?? "").toLowerCase().match(/[a-z][a-z0-9_.-]{1,}/g) || [];
  return [...new Set(ascii.filter(key => !["the", "and", "for", "with"].includes(key)))];
}

/** 术语 Jaccard。 */
export function keyOverlap(a: unknown, b: unknown): { intersection: number; jaccard: number } {
  const left = new Set(conceptKeys(a));
  const right = new Set(conceptKeys(b));
  if (!left.size || !right.size) return { intersection: 0, jaccard: 0 };
  let intersection = 0;
  for (const key of left) if (right.has(key)) intersection += 1;
  return { intersection, jaccard: intersection / (left.size + right.size - intersection) };
}

/** 域名形态的 token（im.ctrip.com / api-3.example.cn）。 */
const HOSTY = /(?:[a-z0-9-]+\.)+[a-z]{2,}/gi;

/**
 * 内容相似度：**先剥掉 host 再算 bigram**（2026-11-02 补）。
 *
 * 为什么单开一个：同 host 的两条任务，光"im.ctrip.com"这一串就能贡献大半个相似度。
 * 实测同一场会话里的真实对照——
 *   同一件事（判定外壳性质，换个句式）      原始 0.278 / 剥 host 后 **0.188**
 *   两件不同的事（CORS 反射 vs .env 泄露）  原始 0.191 / 剥 host 后 **0.033**
 * 也就是说，原始相似度把"CORS"和".env"抬到了 0.19，跟真正同义的 0.28 挨得太近；
 * 剥掉 host 之后两者差了 6 倍，才能用一个固定阈值分开。
 *
 * host 是任务的坐标（由 sameTarget 判等），不是"同一件事"的证据——两条不同任务
 * 当然会都提到自己的目标域名。
 */
export function contentSimilarity(a: unknown, b: unknown): number {
  return contentOverlap(a, b).jaccard;
}

/**
 * 剥 host 后的 bigram 交集明细。
 *
 * 为什么要交集**绝对数**：长句会同时稀释分子分母，一对真同义任务可能只有 0.09；
 * 而"对 X 做 CORS 反射验证" vs "对 X 做 .env 泄露探测"这种假相似只有 1 个共享片段
 * （模板连接词）。所以判据是「交集≥3 个内容片段 且 比例≥0.08」，而不是单看比例。
 */
export function contentOverlap(a: unknown, b: unknown): { intersection: number; jaccard: number } {
  const strip = (value: unknown) => {
    const lowered = String(value ?? "").toLowerCase().replace(ID_LIKE, " ");
    return lowered.replace(HOSTY, " ").replace(PUNCT, "").trim();
  };
  const left = bigrams(strip(a));
  const right = bigrams(strip(b));
  if (!left.size || !right.size) return { intersection: 0, jaccard: 0 };
  let intersection = 0;
  for (const gram of left) if (right.has(gram)) intersection += 1;
  return { intersection, jaccard: intersection / (left.size + right.size - intersection) };
}

/** 判重阈值：都在真实任务上量过（见文件头）。 */
export const PURPOSE_BIGRAM_THRESHOLD = 0.6;
export const PURPOSE_KEY_JACCARD_THRESHOLD = 0.34;
/**
 * 同打法 + 同目标时的放宽阈值（2026-11-02 补）。
 *
 * 实测会话 4f899c3af6c2ac84：模型把同一件事重新起名再登记一遍，任务簿 12 条 pending 里
 * 有 9 条是 3 件事的 3 份拷贝——
 *   T1_shell_recon / T1                    sim 0.22  key 3 / 0.25（旧阈值 0.34 差一点）
 *   T2_sensitive_unauth_probe / T2         sim 0.26  key 2 / 0.18（旧阈值 0.34 差很多）
 *   T3_restapi_route_enum / T_SOA2_ROUTE   sim 0.18  key 2 / 0.50（这条本来就该合并）
 * 差 0.04 就放过一份拷贝，代价是每份拷贝都要单独占焦点、单独烧预算。
 * 放宽只在"同 playbook + 同 host"时生效，且要求至少 2 个术语锚点重合。
 */
export const PURPOSE_KEY_SAME_TARGET_JACCARD = 0.15;
/**
 * 同目标下的内容相似度阈值（剥 host 后）：同一件事换句式 ≈0.19，不同的事 ≈0.03。
 * 取 0.18 是站在"同义"这一侧的保守值——合并错一条任务只是少跑一遍重复活，
 * 漏掉一条重复任务则要多烧一整轮焦点预算（9 轮 / 36 TP）。
 */
export const PURPOSE_CONTENT_SAME_TARGET = 0.18;

/**
 * 路径锚点：purpose 里出现的具体 URL 路径（`/restapi/soa2/{id}/search`）。
 *
 * 用途是**否决合并**：两条都点名了不同端点（IDOR 的 /search 与 /getAppConfig.json），
 * 哪怕措辞一模一样，也是两件不同的事。文本相似度只会说"0.95 很像"，路径会说"不是同一发"。
 *
 * 2026-11-02 修：斜杠分隔的**关键词清单**不是路径。
 * `swagger/api-docs/actuator/.git/.env/druid/nacos/graphql` 被整条当成了锚点，
 * 于是同一条"敏感路径探测"被另写一遍时判成"点名了不同端点"，合并被否决
 * （实跑 92d45f2f15f98e01 的 T3/T4 就是这么留下的两条重复任务）。
 * 认锚点的条件收紧为：**前面不是字母数字**，或者前面确实是个主机名
 * （`m.ctrip.com/restapi/soa2/{id}/search` 这种仍要认，它是真路径）。
 */
export function pathAnchors(purpose: unknown): string[] {
  const text = String(purpose ?? "");
  const out = new Set<string>();
  for (const match of text.matchAll(/(?:\/)([a-z0-9_{}.\-*]+(?:\/[a-z0-9_{}.\-*]+)+)/gi)) {
    const start = match.index ?? 0;
    const prev = start > 0 ? text[start - 1]! : "";
    // 紧贴字母/数字时，只有前面是主机名才认。`swagger/api-docs/...` 前面是 "swagger"（不是域名），跳过。
    if (prev && /[a-z0-9]/i.test(prev)) {
      const head = text.slice(Math.max(0, start - 120), start);
      if (!/(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(head)) continue;
    }
    const anchor = match[1]!.toLowerCase().replace(/[.,;:)\]]+$/, "");
    // 单段的 `/api` 之类不构成锚点：它太泛，出现在任何任务里都不代表同一发。
    if (anchor.split("/").filter(Boolean).length >= 2) out.add(`/${anchor}`);
  }
  return [...out];
}

/** 两份描述点名的路径是否互斥（都点名了、但没有一条相同）。 */
export function distinctPaths(a: unknown, b: unknown): boolean {
  const left = pathAnchors(a);
  const right = pathAnchors(b);
  if (!left.length || !right.length) return false;
  return !left.some(path => right.includes(path));
}

/**
 * 同一件事吗？
 *
 * @param samePlaybook 两条任务的 playbook 是否相同——词面相近但打法不同的（"取 bundle" 与
 *   "判定 catch-all"）不能因为都带 "api" 就被合并。
 * @param sameTarget   两条任务的 host 是否相同：true=同目标、false=明确不同、undefined=无法判定。
 *   不同 host 的两条"敏感路径探测"是两个资产的活，哪怕措辞一模一样也不能合并。
 */
export function samePurpose(a: unknown, b: unknown, samePlaybook = false, sameTarget?: boolean): boolean {
  // 目标是任务的坐标。坐标都不同，文本再像也是两件事。
  if (sameTarget === false) return false;
  const left = normalizePurpose(a);
  const right = normalizePurpose(b);
  if (!left || !right) return false;
  if (left === right) return true;
  // 路径互斥是否决项，先于任何相似度：不同端点就是不同任务。
  if (distinctPaths(a, b)) return false;
  if (purposeSimilarity(a, b) >= PURPOSE_BIGRAM_THRESHOLD) return true;
  const overlap = keyOverlap(a, b);
  if (samePlaybook && overlap.intersection >= 1 && overlap.jaccard >= PURPOSE_KEY_JACCARD_THRESHOLD) return true;
  /**
   * 同目标分支**不受 samePlaybook 约束**（2026-11-02 修）。
   *
   * 旧写法把 `!samePlaybook → return false` 放在这条前面，于是同一台主机上、
   * 只是打法没写（playbook 缺省）的任务永远不与任何任务判重。实跑 768287bceb5e2e01
   * 里 T1_im_shell_verdict(spa_reverse) 与 T1-im-baseline(无 playbook) 是同一件事，
   * 却各占一个焦点：前者烧了 9 轮被强制 blocked，后半场还要为后者再烧一遍。
   */
  if (sameTarget === true) {
    // 术语锚点先判：同目标 + 2 个术语重合 + 比例够，与打法无关（打法没写不等于换了活）。
    if (overlap.intersection >= 2 && overlap.jaccard >= PURPOSE_KEY_SAME_TARGET_JACCARD) return true;
    /**
     * 下面两条是"换句式复述"的兜底，**必须同打法**。
     *
     * 同目标不同打法是一组并行的独立验证面——控制面自己就会一次注入三条
     * （host_header_injection=unauth_exposure / open_redirect=logic / takeover_check=cloud_supply），
     * 它们共享「http.diff 对比」这类模板措辞，文本相似度天然偏高。
     * 不锁打法的话，第二条会被第一条吃掉（test/anomaly-scheduler 复现了这一点）。
     */
    if (samePlaybook && overlap.intersection >= 1 && contentSimilarity(a, b) >= PURPOSE_CONTENT_SAME_TARGET) return true;
    /**
     * 同打法的"换句式复述"：同一件事被写两遍时，措辞差异比想象中大——
     * 实测「判定 im.ctrip.com 是真应用外壳还是纯 404 catch-all 节点，并抽取…前缀」与
     * 「判定 im.ctrip.com 的外壳性质：是 SPA/静态 404 兜底…；抽取前端 JS 中的 baseURL…」，
     * 剥 host 后比例只有 0.089，但共享 7 个内容片段（判定/外壳/抽取/404/catch…）。
     * 而两根真不同的任务（CORS 反射 vs .env 泄露）只共享 2 个模板片段。
     * 实测分布：同义 7/14/15/13，不同 2/2 —— 阈值取 3 站在两侧中间。
     * 所以用「绝对片段数 + 低比例」而不是提高比例阈值。
     */
    const content = contentOverlap(a, b);
    if (samePlaybook && content.intersection >= 3 && content.jaccard >= 0.08) return true;
  }
  return false;
}
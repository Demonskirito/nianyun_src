/**
 * 认证种子健康自检（seed health check）。
 *
 * 为什么要有它（2026-11-07 实测，两场共 172 分钟 / 445 次调用 / 17.0M tokens 全打在假墙上）：
 * 人工导出的 storageState 里带着一枚被风控标记的 `cna` cookie，注入后
 * `developer.aliyun.com` / `tianchi.aliyun.com` 整站返回 403 + 7155B 的
 * `proxy_authentication_required` 挑战页；而**同一时刻匿名**访问同一个 URL 是 200 正常页。
 *
 * 也就是说：那堵"阿里云身份墙"是我方凭证造出来的，不是目标的。
 * 系统当时把它判成 `identity_wall` → `blocked_hosts` → 整机拉黑 →
 * 6+8 个任务全部建在错误前提上，最后连一条有效结论都拿不出来。
 * 全程没有任何一处做过"带凭证 vs 匿名"的基线对照——这一发请求就能定性。
 *
 * 本模块只做**判定**，不发请求：真正发请求由 desk 执行（progress 不执行工具）。
 * 保持纯函数是为了能被单测直接覆盖。
 */

import { identityWallOf } from "./waf-ledger.js";

/** 一次探测的观测值：只要状态码、正文和跳转目标，别的都不参与判定。 */
export type SeedSample = { status?: number | string; body?: string; location?: string };

/** 命中即算"被拦住"的状态码（与 progress.recordHostBlock 的口径保持一致）。 */
export const WALL_STATUS = [403, 406, 412, 418, 429, 503, 1020] as const;

/**
 * 自检结论。
 *
 * - `healthy`      ：带凭证能正常拿到内容——种子没问题，撞墙是真墙或真没权限。
 * - `seed_tainted` ：带凭证被拦、匿名却正常——**墙是我方凭证造的**，必须清种子。
 * - `seed_stale`   ：带凭证和匿名拿到同一个"要登录"的回应——种子在这台主机上根本没生效。
 * - `host_walled`  ：两边都被拦——这才是目标自己的墙，可以按 WAF 处理。
 * - `inconclusive` ：探测失败/数据不全，不下结论（保守方向：继续按墙处理但不上横向逃逸）。
 */
export type SeedVerdict = "healthy" | "seed_tainted" | "seed_stale" | "host_walled" | "inconclusive";

export const SEED_VERDICT_LABEL: Record<SeedVerdict, string> = {
  healthy: "种子健康",
  seed_tainted: "种子污染（我方凭证造墙）",
  seed_stale: "种子失效（未生效）",
  host_walled: "目标自身的墙",
  inconclusive: "无法判定",
};

function statusOf(sample: SeedSample | undefined): number {
  return Number(sample?.status || 0) || 0;
}

function bodyOf(sample: SeedSample | undefined): string {
  return String(sample?.body || "");
}

/** 该响应是不是"被拦住"（拦截码 / 人机挑战 / 身份墙特征）。 */
export function isWallSample(sample: SeedSample | undefined): boolean {
  const status = statusOf(sample);
  const body = bodyOf(sample);
  if (identityWallOf(body)) return true;
  if ((WALL_STATUS as readonly number[]).includes(status)) return true;
  return false;
}

/** 该响应是不是"要登录/没权限"（401，或没有墙特征的裸 403）。 */
export function isAuthDeniedSample(sample: SeedSample | undefined): boolean {
  const status = statusOf(sample);
  if (status === 401) return true;
  if (status === 403 && !identityWallOf(bodyOf(sample))) return true;
  return false;
}

/**
 * 该响应是不是"被带去登录页"（302 → passport/login/sso）。
 *
 * 这一条不能漏：带凭证却被打回登录页，说明种子在这台主机上根本没被认，
 * 而状态码是 3xx，按"小于 400 就是正常"会误判成 healthy——于是又被当成真漏洞面去挖。
 */
export function isAuthRedirect(sample: SeedSample | undefined): boolean {
  const status = statusOf(sample);
  if (![301, 302, 303, 307, 308].includes(status)) return false;
  return /login|passport|signin|sign-in|sso|oauth2?\/authorize|account\.|auth\./i.test(String(sample?.location || ""));
}

/** 该响应是不是"拿到了内容"（2xx / 3xx 且不是挑战页、不是登录跳转）。 */
export function isCleanSample(sample: SeedSample | undefined): boolean {
  const status = statusOf(sample);
  if (status <= 0) return false;
  if (status >= 400) return false;
  if (isAuthRedirect(sample)) return false;
  return !identityWallOf(bodyOf(sample));
}

/**
 * 判定种子健康。
 *
 * 判据只有一条主线：**同一 URL、同一时刻，带凭证 vs 匿名，谁被拦**。
 * 这条对照之所以成立，是因为它把"目标的风控"和"我方凭证的状态"两个变量分开了——
 * 之前 172 分钟烧掉的全部原因就是这两者从来没被分开过。
 */
export function judgeSeedHealth(input: { seeded?: SeedSample; anonymous?: SeedSample }): {
  verdict: SeedVerdict;
  detail: string;
} {
  const seeded = input.seeded;
  const anon = input.anonymous;
  const s = statusOf(seeded);
  const a = statusOf(anon);
  if (!s || !a) {
    return { verdict: "inconclusive", detail: `探测未拿到完整结果（带凭证 ${s || "无"} / 匿名 ${a || "无"}）` };
  }
  const seededWall = isWallSample(seeded);
  const anonWall = isWallSample(anon);
  const seededLogin = isAuthRedirect(seeded);
  const anonLogin = isAuthRedirect(anon);

  if (!seededWall) {
    // 带凭证被打回登录页、匿名却正常 → 种子不但没生效，还替我们"登出"了。
    if (seededLogin && !anonLogin && isCleanSample(anon)) {
      return { verdict: "seed_stale", detail: `带凭证 ${s} 跳到登录页、匿名 ${a} 正常：种子在这台主机上没生效` };
    }
    if (isCleanSample(seeded)) return { verdict: "healthy", detail: `带凭证 ${s}，匿名 ${a}：种子可用` };
    // 带凭证是 401/裸 403，且匿名同样：种子没起作用（过期/未覆盖该主机）。
    if (isAuthDeniedSample(seeded) && isAuthDeniedSample(anon)) {
      return { verdict: "seed_stale", detail: `带凭证 ${s}、匿名 ${a} 同为"要登录"：种子在这台主机上没生效` };
    }
    return { verdict: "healthy", detail: `带凭证 ${s}（非拦截码），不构成墙` };
  }
  // 带凭证被拦 —— 关键分支：匿名是不是也拦？
  if (!anonWall && isCleanSample(anon)) {
    return {
      verdict: "seed_tainted",
      detail: `带凭证 ${s} 被拦，匿名 ${a} 正常：墙由我方 Cookie 造成，不是目标的`,
    };
  }
  if (anonWall) {
    return { verdict: "host_walled", detail: `带凭证 ${s}、匿名 ${a} 均被拦：目标自身的墙` };
  }
  return { verdict: "inconclusive", detail: `带凭证 ${s} 被拦，匿名 ${a} 既非正常也非拦截码：无法区分` };
}

/**
 * 风控/追踪类 Cookie 的特征名。只用于**排序**（先怀疑它们）和硬预算下的兜底清理，
 * 不作为判定依据——真正的判定只来自隔离实验。
 *
 * 这份名单来自 2026-11-07 那次二分：`cna` 是元凶，`atpsida`/`tfstk`/`isg`/`acw_tc`
 * 单独测试都无害。所以名单只能加速，不能替代实验。
 */
export const RISK_COOKIE_HINTS: readonly string[] = [
  "cna", "atpsida", "tfstk", "isg", "acw_tc", "cdn_sec_tc", "sca", "ssxmod_itna",
  "_uab_collina", "cookie2", "xlly_s", "tracknick", "cbc", "_m_h5_tk", "_m_h5_tk_enc",
  "arms_uid", "sufei_anti_uid", "aliyun_risk", "sec_tc", "t", "_tb_token_",
];

export function isRiskCookie(name: string): boolean {
  return RISK_COOKIE_HINTS.includes(String(name || "").toLowerCase());
}

export type IsolateResult = {
  /** 命中下标（相对传入的 cookies 数组）。 */
  indexes: number[];
  /** 命中下标对应的 cookie 名（可能有重名，重名会在 names 里出现多次）。 */
  names: string[];
  probes: number;
  /** 是否跑完（预算耗尽或出现"两半都不足以解封"的交互情形时为 false）。 */
  complete: boolean;
  reason?: string;
};

/**
 * 隔离出"哪几枚 Cookie 导致被拦"。
 *
 * 用的是**删除法**而不是"只用子集重放"：每次都保留其余全部 Cookie 只去掉候选那几枚，
 * 因为很多风控是"登录态 + 某枚标记"共同触发，裸子集根本复现不了墙，会得出错误结论。
 *
 * 求解用的是**析取式分组测试**：对一组候选 G，"去掉 G 之后仍然被拦" 等价于
 * "G 之外还有元凶"。于是对左右两半分别问一次，就能独立判断每半是否含元凶，
 * 再只递归含元凶的那一半——单枚元凶时是 2·log₂n 发（31 枚约 10 发），
 * 多枚时也只有含元凶的分支会展开。
 *
 * 预算耗尽或"没有任何单枚能解封"时 `complete=false`，
 * 调用方应当**只清会话级 Cookie 罐、不改种子文件**——宁可留着墙，也不能把登录态删坏。
 */
export async function isolateTaintedCookies(input: {
  cookies: Array<{ name?: unknown; domain?: unknown }>;
  /** 传"待试的删除下标集合"，返回 true 表示去掉这些之后**仍然**被拦。 */
  probe: (removeIndexes: number[]) => Promise<boolean | undefined>;
  maxProbes?: number;
}): Promise<IsolateResult> {
  const cookies = input.cookies || [];
  const budget = Math.max(1, Number(input.maxProbes ?? 10));
  let probes = 0;
  let complete = true;
  let reason: string | undefined;
  /** 已确认的元凶：之后每一次探测都必须把它们一起去掉，否则后面的 cookie 永远"解不了封"。 */
  const excluded: number[] = [];

  const stillWalledWithout = async (remove: number[]): Promise<boolean | undefined> => {
    if (probes >= budget) { complete = false; reason = `隔离预算用尽（${probes}/${budget} 发）`; return undefined; }
    probes += 1;
    return input.probe([...excluded, ...remove]);
  };

  /** 在 cands 里找**一枚**元凶（前提：cands 里一定存在）。`removed` 是已判定"没有元凶"的兄弟组。 */
  const findOne = async (cands: number[], removed: number[]): Promise<number | undefined> => {
    if (!cands.length) return undefined;
    // 到叶子不用再测：前提已经保证这一支里有元凶。
    if (cands.length === 1) return cands[0];
    const mid = Math.ceil(cands.length / 2);
    const left = cands.slice(0, mid);
    const right = cands.slice(mid);
    // 去掉右半（连同已排除项）之后仍然被拦 ⇒ 左半里有元凶。
    const leftHas = await stillWalledWithout([...removed, ...right]);
    if (leftHas === undefined) return undefined;
    if (leftHas) return await findOne(left, [...removed, ...right]);
    const rightHas = await stillWalledWithout([...removed, ...left]);
    if (rightHas === undefined) return undefined;
    if (rightHas) return await findOne(right, [...removed, ...left]);
    return undefined;
  };

  const found: number[] = [];
  const all = cookies.map((_, index) => index);
  while (true) {
    const remaining = all.filter(index => !found.includes(index));
    if (!remaining.length) break;
    const culprit = await findOne(remaining, []);
    if (culprit === undefined) { complete = false; reason ||= `隔离预算用尽（${probes}/${budget} 发）`; break; }
    found.push(culprit);
    excluded.push(culprit);
    // 去掉已找到的这些之后，墙还在吗？不在就说明找齐了。
    const still = await stillWalledWithout([]);
    if (still === undefined) { complete = false; reason ||= `隔离预算用尽（${probes}/${budget} 发）`; break; }
    if (!still) break;
  }

  if (!found.length) {
    return {
      indexes: [], names: [], probes, complete: false,
      reason: reason || "没有任何单枚 Cookie 被移除后能解封（多枚协同或墙与 Cookie 无关）",
    };
  }
  return {
    indexes: found,
    names: found.map(index => String(cookies[index]?.name || "")),
    probes,
    complete,
    ...(reason ? { reason } : {}),
  };
}

/**
 * 预算耗尽时的兜底：只挑"风控特征名"里命中且确实在种子中的那些。
 * 调用方必须知道这是**猜测**——所以绝不用它改写种子文件，只用于会话级罐的降级尝试。
 */
export function riskCookieIndexes(cookies: Array<{ name?: unknown }>): number[] {
  const out: number[] = [];
  cookies.forEach((cookie, index) => {
    if (isRiskCookie(String(cookie?.name || ""))) out.push(index);
  });
  return out;
}

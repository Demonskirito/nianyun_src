/**
 * ④ 挖掘覆盖度清单（2026-11-07）。
 *
 * 背景：对照会话跑到 91 轮 / 224 工具 / 5.28M tokens 仍是 0 findings，而收口判定只看
 * 「任务是否终态 + 门禁是否通过」——模型说挖完了就算挖完了。这里把"挖得深不深"变成
 * 代码可验的四类对照，缺项时 (a) 注入上下文要求补，(b) 由 superviseCheckpoint 在
 * 0 findings 且准备收工时强制再问一次 Observer（最多 2 次，不无限拖延）。
 *
 * 这是**启发式**清单，不是漏洞判定：它只回答"这四类对照有没有留下证据"，
 * 不回答"有没有漏洞"。判定基于证据文本与种子健康自检，误判只会多一次 Observer。
 */
import type { RunCheckpoint } from "./progress.js";

export const COVERAGE_DIMENSIONS = [
  "authenticated", "anonymous", "parameter_variant", "cross_identity",
] as const;

export type CoverageDimension = typeof COVERAGE_DIMENSIONS[number];

export type CoverageChecklist = {
  dimensions: Record<CoverageDimension, boolean>;
  gaps: CoverageDimension[];
  evidence_checked: number;
  /** 明确标注启发式，避免被当成验收结论。 */
  heuristic: true;
};

const DIMENSION_HINT: Record<CoverageDimension, string> = {
  authenticated: "带凭证（登录态）请求对照",
  anonymous: "匿名（跳过 Cookie/Token 罐）请求对照",
  parameter_variant: "参数/路径变异的 baseline-hit 对照（http.diff）",
  cross_identity: "跨身份越权对照（idor / 两身份打同一对象）",
};

export function coverageDimensionHint(dimension: CoverageDimension): string {
  return DIMENSION_HINT[dimension];
}

export function coverageChecklist(state: RunCheckpoint, evidence: Record<string, unknown>[] = []): CoverageChecklist {
  const blob = evidence.slice(-400)
    .map(item => JSON.stringify(item || {}).toLowerCase()).join(" ").slice(0, 400_000);
  const seeds = Object.values((state.seed_health || {}) as Record<string, Record<string, unknown>>);
  const seedHealthy = seeds.some(seed => String(seed.verdict || "") === "healthy"
    && Number(seed.seeded || 0) > 0 && Number(seed.anonymous || 0) > 0);

  const dimensions: Record<CoverageDimension, boolean> = {
    authenticated: seedHealthy || /credential_mode["':\s]+(?:seeded|credential|authenticated)/.test(blob)
      || /带凭证|登录态请求/.test(blob),
    anonymous: seedHealthy || /credential_mode["':\s]+anonymous/.test(blob)
      || /anonymous|匿名/.test(blob),
    parameter_variant: /http\.diff|baseline[\s/_-]*hit|参数变异|param_variant/.test(blob),
    cross_identity: /idor|越权|cross[_\s-]?identity|两身份|双身份|auth_wall/.test(blob),
  };
  const gaps = COVERAGE_DIMENSIONS.filter(dimension => !dimensions[dimension]);
  return { dimensions, gaps, evidence_checked: Math.min(evidence.length, 400), heuristic: true };
}

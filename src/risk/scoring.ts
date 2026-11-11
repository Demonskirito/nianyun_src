const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 45,
  high: 32,
  medium: 22,
  low: 12,
  info: 3,
};

export function scoreAsset(asset: Record<string, unknown>, findings: Record<string, unknown>[]): number {
  let score = asset.kind === "url" ? 8 : asset.kind === "service" ? 12 : 4;
  if (asset.port) score += 5;
  if (asset.status === "active") score += 3;
  for (const finding of findings) score += SEVERITY_WEIGHT[String(finding.severity || "info").toLowerCase()] || 0;
  return Math.min(100, Math.max(0, score));
}

export function scoreProject(
  assets: Record<string, unknown>[],
  findings: Record<string, unknown>[],
): Array<{ asset: Record<string, unknown>; score: number }> {
  const grouped = new Map<string, Record<string, unknown>[]>();
  for (const finding of findings) {
    const id = String(finding.asset_id || "");
    if (!id) continue;
    const list = grouped.get(id) || [];
    list.push(finding);
    grouped.set(id, list);
  }
  return assets.map((asset) => ({ asset, score: scoreAsset(asset, grouped.get(String(asset.id || "")) || []) }));
}

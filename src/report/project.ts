function cell(value: unknown): string {
  return String(value ?? "").replace(/[|\r\n]/g, " ").trim();
}

export function buildProjectReport(input: {
  project: Record<string, unknown>;
  assets: Record<string, unknown>[];
  findings: Record<string, unknown>[];
}): string {
  const name = cell(input.project.name || input.project.id || "SRC project");
  const lines = [
    `# SRC Assessment Report: ${name}`,
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Asset Inventory",
    "",
    "| Kind | Asset | Risk | Source | Last seen |",
    "|---|---|---:|---|---|",
  ];
  for (const asset of input.assets) {
    lines.push(`| ${cell(asset.kind)} | ${cell(asset.url || asset.value)} | ${cell(asset.risk_score || 0)} | ${cell(asset.source)} | ${cell(asset.last_seen)} |`);
  }
  if (!input.assets.length) lines.push("| - | No assets recorded | 0 | - | - |");
  lines.push("", "## Findings", "", "| Severity | Status | Title | Asset | Confidence |", "|---|---|---|---|---|");
  for (const finding of input.findings) {
    lines.push(`| ${cell(finding.severity)} | ${cell(finding.status)} | ${cell(finding.title)} | ${cell(finding.asset_id)} | ${cell(finding.confidence)} |`);
  }
  if (!input.findings.length) lines.push("| - | - | No findings recorded | - | - |");
  lines.push("", "## Evidence", "", "Evidence is available through the project asset and finding APIs.");
  return lines.join("\n") + "\n";
}

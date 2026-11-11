import { describe, expect, it } from "vitest";
import { scoreAsset } from "../src/risk/scoring.js";
import { buildProjectReport } from "../src/report/project.js";

describe("risk and reporting", () => {
  it("prioritizes assets with higher severity findings", () => {
    const base = { id: "a1", kind: "url", value: "https://example.com", status: "active" };
    expect(scoreAsset(base, [])).toBeLessThan(scoreAsset(base, [{ severity: "high" }]));
  });

  it("renders an asset report from inventory and findings", () => {
    const report = buildProjectReport({
      project: { id: "p1", name: "Example SRC" },
      assets: [{ kind: "url", value: "https://example.com", risk_score: 18, source: "seed", last_seen: 1 }],
      findings: [{ severity: "low", status: "candidate", title: "Missing HSTS", asset_id: "a1", confidence: "high" }],
    });
    expect(report).toContain("Example SRC");
    expect(report).not.toContain("https://hackerone.com/example");
    expect(report).not.toContain("Confirmed:");
    expect(report).toContain("Missing HSTS");
  });
});

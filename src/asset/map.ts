import type { Database } from "../shared/db.js";

export type AssetMapNodeDetails = {
  summary: { conclusion: string; basis: string; uncertainty: string | null };
  steps: Array<{ id: string; action: string; result: string; assessment: string | null; evidenceRefs: string[] }>;
  evidenceRefs: string[];
};

type AssetMapNode = AssetMapNodeDetails & {
  id: string;
  label: string;
  group: string;
  sub: string;
  status: string;
  x: number;
  y: number;
  width: number;
  height: number;
};

function nodeDetails(asset: Record<string, unknown>): AssetMapNodeDetails {
  const technologies = Array.isArray(asset.technologies) ? asset.technologies.join(", ") : "";
  const evidence = asset.evidence && typeof asset.evidence === "object" ? JSON.stringify(asset.evidence) : "";
  return {
    summary: {
      conclusion: `${String(asset.kind || "asset")}: ${String(asset.value || "")}`,
      basis: [String(asset.source || "unknown"), technologies].filter(Boolean).join(" · "),
      uncertainty: null,
    },
    steps: [{
      id: `asset-observation-${String(asset.id || "")}`,
      action: "Record authorized asset observation",
      result: [String(asset.title || ""), evidence].filter(Boolean).join(" | ").slice(0, 2000),
      assessment: null,
      evidenceRefs: [`asset:${String(asset.id || "")}`],
    }],
    evidenceRefs: [`asset:${String(asset.id || "")}`],
  };
}

export function buildAssetMap(db: Database, projectId: string): Record<string, unknown> {
  const assets = db.listAssets(projectId, { limit: 1000 });
  const width = 220;
  const height = 76;
  const gapX = 32;
  const gapY = 28;
  const columns = 3;
  const root: AssetMapNode = {
    id: "project-assets",
    label: "Project Assets",
    group: "start",
    sub: `${assets.length} assets`,
    status: "confirmed",
    x: 24,
    y: 24,
    width,
    height,
    summary: { conclusion: "Project asset inventory", basis: "Recorded asset observations", uncertainty: null },
    steps: [],
    evidenceRefs: [],
  };
  const nodes: AssetMapNode[] = [root];
  const edges: Array<{ from: string; to: string }> = [];
  assets.forEach((asset, index) => {
    const id = `asset-${String(asset.id)}`;
    const col = index % columns;
    const row = Math.floor(index / columns);
    nodes.push({
      id,
      label: String(asset.url || asset.value || "asset"),
      group: "recon",
      sub: String(asset.kind || "asset"),
      status: String(asset.status || "active"),
      x: 24 + (width + gapX) * col,
      y: 24 + (height + gapY) * (row + 1),
      width,
      height,
      ...nodeDetails(asset),
    });
    edges.push({ from: root.id, to: id });
  });
  return {
    schemaVersion: "observation-graph-v1",
    publication: {
      jobId: `asset-map:${projectId}`,
      revision: "1",
      phase: "observe",
      publishedAt: Date.now(),
    },
    width: Math.max(width, columns * width + (columns - 1) * gapX + 48),
    height: Math.max(height * 2, 24 + (Math.ceil(assets.length / columns) + 1) * (height + gapY)),
    view: { nodes, edges },
  };
}

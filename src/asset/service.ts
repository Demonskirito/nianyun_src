import type { Database } from "../shared/db.js";
import { normalizeAsset, type AssetInput } from "./model.js";

export type AssetImportResult = {
  accepted: Record<string, unknown>[];
  rejected: Array<{ input: unknown; error: string }>;
};

export function importAssets(
  db: Database,
  projectId: string,
  rawInputs: unknown[],
): AssetImportResult {
  const accepted: Record<string, unknown>[] = [];
  const rejected: Array<{ input: unknown; error: string }> = [];
  const acceptedIds = new Set<string>();
  for (const input of rawInputs.slice(0, 1000)) {
    try {
      if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("asset must be an object");
      const asset = normalizeAsset(input as AssetInput);
      const row = db.upsertAsset(projectId, asset);
      db.addAssetObservation(projectId, String(row.id), asset.source, {
        kind: asset.kind,
        value: asset.value,
        title: asset.title,
        technologies: asset.technologies,
        evidence: asset.evidence,
      });
      const assetId = String(row.id || "");
      if (!acceptedIds.has(assetId)) {
        acceptedIds.add(assetId);
        accepted.push(row);
      }
    } catch (error) {
      rejected.push({ input, error: String(error instanceof Error ? error.message : error) });
    }
  }
  return { accepted, rejected };
}

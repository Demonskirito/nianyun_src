import type { Database } from "../shared/db.js";
import { normalizeAsset, type AssetInput } from "./model.js";

export type CandidateInput = AssetInput & { tags?: string[] };

export type CandidateImportResult = {
  accepted: Record<string, unknown>[];
  rejected: Array<{ input: unknown; error: string }>;
};

function tags(input: CandidateInput): string[] {
  return Array.isArray(input.tags)
    ? [...new Set(input.tags.map(value => String(value).trim()).filter(Boolean))].slice(0, 32)
    : [];
}

export function importAssetCandidates(
  db: Database,
  projectId: string,
  rawInputs: unknown[],
): CandidateImportResult {
  const accepted: Record<string, unknown>[] = [];
  const rejected: CandidateImportResult["rejected"] = [];
  const acceptedIds = new Set<string>();
  for (const input of rawInputs.slice(0, 5000)) {
    try {
      if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("candidate must be an object");
      const candidateInput = input as CandidateInput;
      const candidate = normalizeAsset(candidateInput);
      const row = db.upsertAssetCandidate(projectId, candidate, tags(candidateInput));
      if (!acceptedIds.has(String(row.id))) {
        acceptedIds.add(String(row.id));
        accepted.push(row);
      }
    } catch (error) {
      rejected.push({ input, error: String(error instanceof Error ? error.message : error) });
    }
  }
  return { accepted, rejected };
}

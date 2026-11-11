import type { Database } from "../shared/db.js";
import { importAssets, type AssetImportResult } from "./service.js";
import { normalizeAsset } from "./model.js";

type HttpSeed = { value: string; source?: string };

export type DiscoveryResult = AssetImportResult & {
  probes: Array<{ seed: string; status?: number; error?: string; location?: string }>;
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function headerEvidence(response: Response): Record<string, unknown> {
  const headers: Record<string, string> = {};
  for (const name of ["server", "content-type", "content-length", "x-powered-by", "location"]) {
    const value = response.headers.get(name);
    if (value) headers[name] = value.slice(0, 500);
  }
  return { http_status: response.status, headers };
}

export async function discoverHttpSeeds(
  db: Database,
  projectId: string,
  seeds: HttpSeed[],
): Promise<DiscoveryResult> {
  const probes: DiscoveryResult["probes"] = [];
  const accepted: Record<string, unknown>[] = [];
  const rejected: AssetImportResult["rejected"] = [];
  const maxConcurrency = 2;
  const interval = 1000;
  let next = 0;
  let gate = Promise.resolve();
  const pace = async (): Promise<void> => {
    const prior = gate;
    let release!: () => void;
    gate = new Promise<void>((resolve) => { release = resolve; });
    await prior;
    await sleep(interval);
    release();
  };

  async function worker(): Promise<void> {
    while (true) {
      const index = next++;
      if (index >= Math.min(seeds.length, 100)) return;
      const seed = seeds[index]!;
      let normalized: ReturnType<typeof normalizeAsset>;
      try {
        normalized = normalizeAsset({ kind: "url", value: seed.value, source: seed.source || "http-head" });
      } catch (error) {
        rejected.push({ input: seed, error: String(error instanceof Error ? error.message : error) });
        continue;
      }
      await pace();
      const item: { seed: string; status?: number; error?: string; location?: string } = { seed: normalized.url || seed.value };
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        let response: Response;
        try {
          response = await fetch(normalized.url || seed.value, { method: "HEAD", redirect: "manual", signal: controller.signal });
        } finally {
          clearTimeout(timeout);
        }
        item.status = response.status;
        const location = response.headers.get("location") || "";
        if (location) item.location = location.slice(0, 1000);
        const evidence = headerEvidence(response);
        const result = importAssets(db, projectId, [{
          value: normalized.url || seed.value,
          source: seed.source || "http-head",
          protocol: normalized.protocol || undefined,
          port: normalized.port || undefined,
          evidence,
        }]);
        accepted.push(...result.accepted);
        rejected.push(...result.rejected);
        if (location) {
          try {
            const redirected = normalizeAsset({ kind: "url", value: new URL(location, normalized.url || seed.value).toString(), source: "http-redirect" });
            if (redirected.url) {
              const redirectResult = importAssets(db, projectId, [{ value: redirected.url, source: "http-redirect", evidence: { from: normalized.url, http_status: response.status } }]);
              accepted.push(...redirectResult.accepted);
              rejected.push(...redirectResult.rejected);
            }
          } catch {
            // A malformed location is evidence, not a reason to follow it.
          }
        }
      } catch (error) {
        item.error = String(error instanceof Error ? error.message : error);
        rejected.push({ input: seed, error: item.error });
      }
      probes.push(item);
    }
  }

  await Promise.all(Array.from({ length: maxConcurrency }, () => worker()));
  const unique = new Map(accepted.map((item) => [String(item.id), item]));
  return { accepted: [...unique.values()], rejected, probes };
}

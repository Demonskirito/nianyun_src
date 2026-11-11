import type { Database } from "../shared/db.js";

type CheckResult = {
  findings: Record<string, unknown>[];
  checked: boolean;
  error?: string;
};

function urlFor(asset: Record<string, unknown>): string | null {
  if (asset.url) return String(asset.url);
  const host = String(asset.hostname || asset.value || "");
  if (!host) return null;
  const bracketed = host.includes(":") ? `[${host}]` : host;
  const port = Number(asset.port || 0);
  const protocol = String(asset.protocol || "http");
  return `${protocol}://${bracketed}${port ? `:${port}` : ""}`;
}

export async function validateHttpAsset(
  db: Database,
  projectId: string,
  asset: Record<string, unknown>,
): Promise<CheckResult> {
  const url = urlFor(asset);
  if (!url) return { findings: [], checked: false, error: "asset URL is required" };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  let response: Response;
  try {
    try {
      response = await fetch(url, { method: "HEAD", redirect: "manual", signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  } catch (error) {
    return { findings: [], checked: false, error: String(error instanceof Error ? error.message : error) };
  }
  const evidence: Record<string, unknown> = { url, status: response.status, headers: {} };
  const headers = evidence.headers as Record<string, string>;
  for (const name of ["server", "x-powered-by", "strict-transport-security", "content-security-policy", "x-content-type-options", "set-cookie"]) {
    const value = response.headers.get(name);
    if (value) headers[name] = value.slice(0, 1000);
  }
  const findings: Record<string, unknown>[] = [];
  const assetId = String(asset.id || "");
  if (!assetId) return { findings, checked: true };
  if (url.startsWith("https://") && !headers["strict-transport-security"]) {
    findings.push(db.upsertFinding({
      projectId, assetId, checkId: "http.missing-hsts", title: "HTTPS response is missing HSTS", severity: "low", confidence: "high",
      description: "The HTTPS endpoint did not return Strict-Transport-Security in the response headers.", evidence,
    }));
  }
  if (!headers["x-content-type-options"]) {
    findings.push(db.upsertFinding({
      projectId, assetId, checkId: "http.missing-nosniff", title: "Response is missing X-Content-Type-Options", severity: "info", confidence: "high",
      description: "The endpoint did not return X-Content-Type-Options.", evidence,
    }));
  }
  if (headers.server || headers["x-powered-by"]) {
    findings.push(db.upsertFinding({
      projectId, assetId, checkId: "http.server-disclosure", title: "HTTP service discloses implementation headers", severity: "info", confidence: "high",
      description: "The response exposes a server or framework identification header.", evidence,
    }));
  }
  return { findings, checked: true };
}

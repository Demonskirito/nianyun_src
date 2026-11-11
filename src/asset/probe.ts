import https from "node:https";
import type { Database } from "../shared/db.js";
import { headRequest, probeProxy, proxyFromEnv } from "../shared/outbound.js";

type ProbeCandidate = Record<string, unknown>;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function candidateUrl(candidate: ProbeCandidate): string | null {
  if (candidate.url) return String(candidate.url);
  const host = String(candidate.hostname || candidate.value || "");
  if (!host) return null;
  const protocol = String(candidate.protocol || "http");
  const port = Number(candidate.port || 0);
  return `${protocol}://${host}${port ? `:${port}` : ""}`;
}

type ProbeResponse = { status: number; headers: Headers; tls?: Record<string, unknown> };

function evidence(response: ProbeResponse): Record<string, unknown> {
  const headers: Record<string, string> = {};
  for (const name of ["server", "content-type", "content-length", "location", "x-powered-by", "via"]) {
    const value = response.headers.get(name);
    if (value) headers[name] = value.slice(0, 500);
  }
  return { http_status: response.status, headers, ...(response.tls ? { tls: response.tls } : {}) };
}

function tags(response: ProbeResponse): string[] {
  const out: string[] = [];
  if (response.status >= 200 && response.status < 400) out.push("reachable");
  if (response.status >= 300 && response.status < 400) out.push("redirect");
  const type = response.headers.get("content-type") || "";
  if (/html/i.test(type)) out.push("html");
  if (/json/i.test(type)) out.push("api");
  if (response.headers.get("location")) out.push("redirect-target");
  if (response.tls && response.tls.authorized === false) out.push("tls-unverified");
  return out;
}

function diagnosticHead(url: string): Promise<ProbeResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const request = https.request(parsed, {
      method: "HEAD",
      rejectUnauthorized: false,
      servername: parsed.hostname,
      timeout: 8000,
    }, (response) => {
      const socket = response.socket as import("node:tls").TLSSocket | null;
      const certificate = socket?.getPeerCertificate() as Record<string, unknown> | undefined;
      const headers = new Headers();
      for (const [name, value] of Object.entries(response.headers)) {
        if (typeof value === "string") headers.set(name, value);
        else if (Array.isArray(value)) headers.set(name, value.join(", "));
      }
      response.resume();
      resolve({
        status: response.statusCode || 0,
        headers,
        tls: {
          unverified: true,
          protocol: socket?.getProtocol() || null,
          authorized: socket?.authorized ?? false,
          authorization_error: socket?.authorizationError || null,
          certificate: certificate && Object.keys(certificate).length ? {
            subject: certificate.subject || null,
            issuer: certificate.issuer || null,
            valid_from: certificate.valid_from || null,
            valid_to: certificate.valid_to || null,
            fingerprint256: certificate.fingerprint256 || null,
            serial_number: certificate.serialNumber || null,
            subject_alt_name: certificate.subjectaltname || null,
          } : null,
        },
      });
    });
    request.once("error", reject);
    request.once("timeout", () => request.destroy(new Error("TLS diagnostic timeout")));
    request.end();
  });
}

export type ProbeJobRunResult = {
  ok: boolean;
  job?: Record<string, unknown> | null;
  processed: number;
  error?: string;
};

export type ProbePolicy = { max_rps: number; max_concurrency: number; tls_mode?: "strict" | "diagnostic" };

/** 测试替身注入口：默认走真实 outbound.headRequest，运行时调用方无需传。 */
export type ProbeJobDeps = { headRequest?: typeof headRequest };

export async function runAssetProbeJob(db: Database, projectId: string, jobId: string, policy?: ProbePolicy, deps: ProbeJobDeps = {}): Promise<ProbeJobRunResult> {
  const head = deps.headRequest || headRequest;
  const initial = db.getAssetProbeJob(projectId, jobId);
  if (!initial) return { ok: false, processed: 0, error: "probe job not found" };
  if (["completed", "cancelled"].includes(String(initial.status))) return { ok: true, processed: 0, job: initial };
  // A dead proxy makes every probe fail after 8s; refuse the whole job once instead of per asset.
  const proxyError = await probeProxy(proxyFromEnv());
  if (proxyError) return { ok: false, processed: 0, error: proxyError };
  db.setAssetProbeJobStatus(projectId, jobId, "running");
  const concurrency = Math.max(1, Math.min(16, policy?.max_concurrency || Number(initial.concurrency || 3)));
  const interval = Math.ceil(1000 / Math.max(1, policy?.max_rps || 1));
  let processed = 0;
  let next = 0;
  let candidates = db.listAssetProbeCandidates(projectId, jobId, "queued", 5000);
  const pace = async (): Promise<void> => { await sleep(interval); };

  async function worker(): Promise<void> {
    while (true) {
      const index = next++;
      const candidate = candidates[index];
      if (!candidate) return;
      const current = db.getAssetProbeJob(projectId, jobId);
      if (!current || ["paused", "cancelled"].includes(String(current.status))) return;
      const candidateId = String(candidate.id);
      db.updateAssetProbeItem(projectId, jobId, candidateId, "running");
      const url = candidateUrl(candidate);
      if (!url) {
        db.updateAssetProbeItem(projectId, jobId, candidateId, "failed", { error: "candidate has no HTTP URL" });
        processed++;
        continue;
      }
      await pace();
      const started = Date.now();
      try {
        const result = await head(url, { proxy: proxyFromEnv(), timeoutMs: 8000 });
        const response: ProbeResponse = { status: result.status, headers: result.headers, ...(result.tls ? { tls: result.tls } : {}) };
        const responseTags = tags(response);
        const score = response.status >= 200 && response.status < 400 ? 25 : response.status === 401 || response.status === 403 ? 15 : 0;
        db.updateAssetProbeItem(projectId, jobId, candidateId, "completed", {
          score,
          tags: responseTags,
          httpStatus: response.status,
          responseTimeMs: Date.now() - started,
          evidence: evidence(response),
        });
      } catch (error) {
        db.updateAssetProbeItem(projectId, jobId, candidateId, "failed", {
          responseTimeMs: Date.now() - started,
          error: String(error instanceof Error ? error.message : error),
        });
      }
      processed++;
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const job = db.getAssetProbeJob(projectId, jobId);
  if (job && String(job.status) === "running" && db.listAssetProbeCandidates(projectId, jobId, "queued", 1).length === 0) {
    db.setAssetProbeJobStatus(projectId, jobId, "queued");
  }
  return { ok: true, job: db.getAssetProbeJob(projectId, jobId), processed };
}


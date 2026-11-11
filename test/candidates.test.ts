import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { runAssetProbeJob } from "../src/asset/probe.js";
import { Database } from "../src/shared/db.js";
import { parseCandidateImport } from "../src/asset/importers.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  databases.splice(0).forEach(db => db.close());
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("SRC asset candidate pool", () => {
  it("parses JSONL, CSV, and common asset fields", () => {
    expect(parseCandidateImport('{"host":"app.example.com","title":"Portal"}', "json", "arl")).toMatchObject([
      { value: "app.example.com", source: "arl", title: "Portal" },
    ]);
    expect(parseCandidateImport('{"host":"one.example.com","port":443}\n{"domain":"two.example.com"}', "jsonl", "dns")).toHaveLength(2);
    expect(parseCandidateImport("host,port,source\napi.example.com,443,certificate", "csv")[0]).toMatchObject(
      { value: "api.example.com", port: 443, source: "certificate" },
    );
  });

  it("rejects malformed JSONL and rows without an address", () => {
    expect(() => parseCandidateImport('{"host":"one.example.com"}\nnot-json', "jsonl")).toThrow();
    expect(() => parseCandidateImport("title\nonly-title", "csv")).toThrow("no URL, host, domain, or IP");
  });

  it("filters and deduplicates candidates before they enter the queue", () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-candidates-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const result = importAssetCandidates(db, "p_src", [
      { value: "https://app.example.com/login", source: "arl", tags: ["portal", "portal"] },
      { value: "https://app.example.com/login", source: "certificate" },
      { value: "https://outside.example.net", source: "arl" },
    ]);
    expect(result.accepted).toHaveLength(2);
    expect(result.rejected).toHaveLength(0);
    expect(db.listAssetCandidates("p_src")).toHaveLength(2);
    expect(db.listAssetCandidates("p_src")[0]).toMatchObject({ status: "candidate", tags: ["portal"] });
  });

  it("creates a resumable probe job and supports review state", () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-candidates-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const imported = importAssetCandidates(db, "p_src", [
      { value: "https://one.example.com", source: "dns" },
      { value: "https://two.example.com", source: "arl" },
    ]);
    const ids = imported.accepted.map(row => String(row.id));
    const first = db.updateAssetCandidate("p_src", ids[0]!, { status: "selected", score: 82, tags: ["login"] });
    expect(first).toMatchObject({ status: "selected", score: 82, tags: ["login"] });
    const job = db.createAssetProbeJob("p_src", ids, { concurrency: 3, threshold: 40 });
    expect(job).toMatchObject({ status: "queued", total: 1, concurrency: 3, threshold: 40, queue: { queued: 1 } });
    expect(db.setAssetProbeJobStatus("p_src", String(job.id), "paused")).toMatchObject({ status: "paused" });
  });

  it("runs only queued candidates through a bounded HEAD probe", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-candidates-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const imported = importAssetCandidates(db, "p_src", [{ value: "https://app.example.com", source: "arl" }]);
    const job = db.createAssetProbeJob("p_src", [String(imported.accepted[0]?.id)]);
    const fetchMock = vi.fn(async () => new Response(null, { status: 200, headers: { "content-type": "text/html", server: "test" } }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await runAssetProbeJob(db, "p_src", String(job.id));
    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith("https://app.example.com/", expect.objectContaining({ method: "HEAD", redirect: "manual" }));
    expect(db.getAssetProbeJob("p_src", String(job.id))).toMatchObject({ status: "completed", completed: 1 });
    expect(db.listAssetCandidates("p_src")[0]).toMatchObject({ status: "completed", http_status: 200, tags: ["reachable", "html"] });
  });
});



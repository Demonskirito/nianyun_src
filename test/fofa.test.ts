import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildFofaQueries, buildFofaQuery, checkFofa, discoverFofa, fofaRowToUrl, fofaTransport, normalizeFofaTarget, parseFofaTarget } from "../src/asset/fofa.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { Database } from "../src/shared/db.js";

const dirs: string[] = [];
const databases: Database[] = [];
const realSend = fofaTransport.send;

afterEach(() => {
  fofaTransport.send = realSend;
  vi.restoreAllMocks();
  databases.splice(0).forEach((db) => db.close());
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(): { db: Database; projectId: string } {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-fofa-"));
  dirs.push(dir);
  const db = new Database(join(dir, "nianyun.db"));
  databases.push(db);
  return { db, projectId: "p_fofa" };
}

const FIELDS = ["host", "ip", "port", "protocol", "domain", "title", "server"];

describe("fofa discovery", () => {
  it("anchors the query on the authorised target and rejects non-domains", () => {
    expect(buildFofaQuery("example.com")).toBe('domain="example.com"');
    expect(buildFofaQuery("192.0.2.10")).toBe('ip="192.0.2.10"');
    expect(buildFofaQuery("example.com", 'title="后台"')).toBe('(title="后台") && domain="example.com"');
    expect(buildFofaQuery("example.com", 'domain="example.com" && title="a"')).toBe('domain="example.com" && title="a"');
    expect(normalizeFofaTarget(" https://Example.com/ ")).toBe("example.com");
    expect(() => normalizeFofaTarget("example.com:443")).toThrow(/domain or an IP/);
  });

  it("builds a candidate URL from host, or from protocol/host/port", () => {
    expect(fofaRowToUrl(["https://a.example.com:8443", "1.1.1.1", "8443", "https", "a.example.com", "A", "nginx"], FIELDS)).toMatchObject({ url: "https://a.example.com:8443" });
    expect(fofaRowToUrl(["", "2.2.2.2", "8080", "http", "", "", "Apache"], FIELDS)).toMatchObject({ url: "http://2.2.2.2:8080", evidence: { ip: "2.2.2.2", port: 8080 } });
    expect(fofaRowToUrl(["", "", "", "", "", "", ""], FIELDS)).toBeNull();
  });

  it("turns a wildcard target into domain, host and certificate queries", () => {
    expect(parseFofaTarget(" *.qwen.ai ")).toEqual({ host: "qwen.ai", wildcard: true, kind: "domain" });
    expect(parseFofaTarget("https://*.qwen.ai/console")).toMatchObject({ host: "qwen.ai", wildcard: true });
    expect(parseFofaTarget(".qwen.ai")).toMatchObject({ host: "qwen.ai", wildcard: true });
    expect(normalizeFofaTarget("*.qwen.ai")).toBe("qwen.ai");
    expect(buildFofaQueries("*.qwen.ai")).toEqual([
      { strategy: "domain", query: 'domain="qwen.ai"' },
      { strategy: "host", query: 'host="qwen.ai"' },
      { strategy: "cert", query: 'cert="qwen.ai"' },
    ]);
    expect(buildFofaQueries("qwen.ai", 'title="后台"', ["domain", "cert"]).map((plan) => plan.query)).toEqual([
      '(title="后台") && (domain="qwen.ai" || cert="qwen.ai")',
    ]);
    expect(() => buildFofaQueries("qwen.ai", "", ["shodan"])).toThrow(/domain, host or cert/);
    expect(buildFofaQueries("*.qwen.ai", 'domain="qwen.ai" && title="x"')[0]).toMatchObject({ strategy: "custom", query: 'domain="qwen.ai" && title="x"' });
  });

  it("runs every strategy for a wildcard target and drops out-of-scope certificate hits", async () => {
    const { db, projectId } = fixture();
    const queries: string[] = [];
    fofaTransport.send = async (input) => {
      const url = new URL(String(input));
      const query = Buffer.from(String(url.searchParams.get("qbase64") || ""), "base64").toString("utf8");
      queries.push(query);
      const payload = query === 'domain="qwen.ai"'
        ? { error: false, size: 1, results: [["https://chat.qwen.ai", "1.1.1.1", "443", "https", "chat.qwen.ai", "Qwen", "nginx"]] }
        : query === 'host="qwen.ai"'
          ? { error: false, size: 1, results: [["", "2.2.2.2", "8080", "http", "api.qwen.ai", "API", "Tengine"]] }
          : { error: false, size: 2, results: [
              ["https://co-tenant.example.net", "3.3.3.3", "443", "https", "co-tenant.example.net", "Other", "nginx"],
              ["https://dash.qwen.ai", "4.4.4.4", "443", "https", "dash.qwen.ai", "Dash", "nginx"],
            ] };
      return { status: 200, text: JSON.stringify(payload) };
    };

    const result = await discoverFofa({ db, projectId, values: { FOFA_KEY: "app-key", FOFA_URL: "https://fofa.test" }, target: "*.qwen.ai", size: 300 });
    expect(queries).toEqual(['domain="qwen.ai"', 'host="qwen.ai"', 'cert="qwen.ai"']);
    expect(result).toMatchObject({ ok: true, target: "qwen.ai", wildcard: true, scope: "suffix", discovered: 4, filtered: 1, accepted: 3 });
    const hosts = (result.candidates as Array<Record<string, unknown>>).map((row) => new URL(String(row.value)).host).sort();
    expect(hosts).toEqual(["api.qwen.ai:8080", "chat.qwen.ai", "dash.qwen.ai"]);

    // scope: "any" keeps the off-namespace certificate hit, and the tags record which strategy found it.
    const wide = await discoverFofa({ db, projectId, values: { FOFA_KEY: "app-key", FOFA_URL: "https://fofa.test" }, target: "*.qwen.ai", size: 300, scope: "any" });
    expect(wide).toMatchObject({ filtered: 0, accepted: 4 });
    const tagged = (wide.candidates as Array<Record<string, unknown>>).find((row) => String(row.value).includes("co-tenant"));
    expect(tagged?.tags).toContain("fofa-cert");
  });

  it("checks the account with the saved appkey", async () => {
    fofaTransport.send = async (input) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe("/api/v1/info/my");
      expect(url.searchParams.get("key")).toBe("app-key");
      return { status: 200, text: JSON.stringify({ error: false, email: "ops@example.com", vip_level: 2, fofa_point: 100, remain_api_query: 42 }) };
    };
    await expect(checkFofa({})).rejects.toThrow(/AppKey/);
    await expect(checkFofa({ FOFA_KEY: "app-key" })).resolves.toMatchObject({ ok: true, email: "ops@example.com", vip_level: 2, remain_query: 42 });
  });

  it("imports every result page and reports the remote query", async () => {
    const { db, projectId } = fixture();
    const seen: URL[] = [];
    fofaTransport.send = async (input) => {
      const url = new URL(String(input));
      seen.push(url);
      expect(url.pathname).toBe("/api/v1/search/all");
      expect(url.searchParams.get("key")).toBe("app-key");
      expect(Buffer.from(url.searchParams.get("qbase64") || "", "base64").toString("utf8")).toBe('domain="example.com"');
      const page = Number(url.searchParams.get("page"));
      return {
        status: 200,
        text: JSON.stringify({
          error: false, page, size: 3, remain_api_query: 9,
          results: page === 1
            ? [["https://a.example.com", "1.1.1.1", "443", "https", "a.example.com", "A", "nginx"]]
            : [["", "2.2.2.2", "8080", "http", "b.example.com", "B", "Apache"], ["", "3.3.3.3", "80", "http", "", "", ""]],
        }),
      };
    };

    const result = await discoverFofa({ db, projectId, values: { FOFA_KEY: "app-key", FOFA_URL: "https://fofa.test" }, target: "example.com", size: 1200, strategies: ["domain"] });
    expect(seen).toHaveLength(2);
    expect(seen[0]!.searchParams.get("size")).toBe("1000");
    expect(seen[1]!.searchParams.get("size")).toBe("1000");
    expect(result).toMatchObject({ ok: true, source: "fofa", target: "example.com", query: 'domain="example.com"', discovered: 3, accepted: 3, remain_query: 9 });
    // Normalisation adds a trailing slash and infers the scheme, so compare hosts, not raw strings.
    const hosts = (result.candidates as Array<Record<string, unknown>>).map((row) => new URL(String(row.value)).host).sort();
    expect(hosts).toEqual(["3.3.3.3", "a.example.com", "b.example.com:8080"]);

    // A second run must not duplicate the pool.
    const again = await discoverFofa({ db, projectId, values: { FOFA_KEY: "app-key", FOFA_URL: "https://fofa.test" }, target: "example.com", size: 10, strategies: ["domain"] });
    expect(again.accepted).toBe(3);
    expect(db.listAssetCandidates(projectId, { limit: 50 })).toHaveLength(3);
  });

  it("surfaces FOFA errors and refuses to run without a key", async () => {
    const { db, projectId } = fixture();
    await expect(discoverFofa({ db, projectId, values: {}, target: "example.com" })).rejects.toThrow(/AppKey/);
    fofaTransport.send = async () => ({ status: 200, text: JSON.stringify({ error: true, errmsg: "[-1] 查询语法错误" }) });
    await expect(discoverFofa({ db, projectId, values: { FOFA_KEY: "app-key" }, target: "example.com" })).rejects.toThrow(/查询语法错误/);
  });
});

describe("agent review queue", () => {
  it("does not requeue a candidate whose review already failed", () => {
    const { db, projectId } = fixture();
    const [ok, dead] = importAssetCandidates(db, projectId, [
      { value: "https://ok.example.com", source: "test" },
      { value: "https://dead.example.com", source: "test" },
    ]).accepted.map((row) => String(row.id));
    db.updateAssetAgentReview(projectId, ok!, { agentScore: 70, ruleVersion: "asset-page-v1" });
    db.markAssetCandidateReviewFailed(projectId, dead!, "page.goto: ERR_EMPTY_RESPONSE");

    // A failed review costs a browser run and a model call, so it stays out of the default queue.
    expect(db.listUnscoredAssetCandidates(projectId, "asset-page-v1")).toHaveLength(0);
    expect(db.pendingAssetCandidateIds(projectId, [ok!, dead!], "asset-page-v1")).toEqual([]);
    const failed = db.listFailedAssetCandidates(projectId).map((row) => String(row.id));
    expect(failed).toEqual([dead]);
    // A rule version change still re-scores the candidate that succeeded, but not the dead one.
    expect(db.listUnscoredAssetCandidates(projectId, "asset-page-v2").map((row) => String(row.id))).toEqual([ok]);
    // A later success clears the failure note.
    db.updateAssetAgentReview(projectId, dead!, { agentScore: 42, ruleVersion: "asset-page-v1" });
    expect(db.getAssetCandidate(projectId, dead!)?.review_error).toBeNull();
    expect(db.listFailedAssetCandidates(projectId)).toHaveLength(0);
  });

  it("pulls queued candidates in order without ambiguous rowid", () => {
    const { db, projectId } = fixture();
    const imported = importAssetCandidates(db, projectId, [
      { value: "https://one.example.com", source: "test" },
      { value: "https://two.example.com", source: "test" },
    ]).accepted.map((row) => String(row.id));
    const job = db.createAssetReviewJob(projectId, imported, "asset-page-v1");
    const jobId = String(job.id);
    const first = db.nextAssetReviewCandidate(projectId, jobId);
    expect(String(first?.id)).toBe(imported[0]);
    db.updateAssetReviewItem(projectId, jobId, imported[0]!, "completed");
    const second = db.nextAssetReviewCandidate(projectId, jobId);
    expect(String(second?.id)).toBe(imported[1]);
    db.updateAssetReviewItem(projectId, jobId, imported[1]!, "failed", "boom");
    expect(db.nextAssetReviewCandidate(projectId, jobId)).toBeNull();
    const row = db.getAssetReviewJob(projectId, jobId);
    expect(row).toMatchObject({ status: "completed", completed: 1, failed: 1 });
    db.failAssetReviewJob(projectId, jobId, "closed by test");
    expect(db.getAssetReviewJob(projectId, jobId)).toMatchObject({ status: "failed", error: "closed by test" });
  });

  it("only queues candidates that have no score under the current rule version", () => {
    const { db, projectId } = fixture();
    const imported = importAssetCandidates(db, projectId, [
      { value: "https://one.example.com", source: "test" },
      { value: "https://two.example.com", source: "test" },
    ]).accepted;
    const [first, second] = imported.map((row) => String(row.id));
    db.updateAssetAgentReview(projectId, first!, { agentScore: 81, ruleVersion: "asset-page-v1", scoreReasons: { score: 81 } });

    expect(db.listUnscoredAssetCandidates(projectId, "asset-page-v1").map((row) => String(row.id))).toEqual([second]);
    // A new rule version invalidates the stored score, so both come back.
    expect(db.listUnscoredAssetCandidates(projectId, "asset-page-v2").map((row) => String(row.id)).sort()).toEqual([first, second].sort());
    expect(db.pendingAssetCandidateIds(projectId, [first!, second!], "asset-page-v1")).toEqual([second]);
    expect(db.pendingAssetCandidateIds(projectId, [first!, second!], "asset-page-v2").sort()).toEqual([first, second].sort());
  });
});
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { importAssetCandidates } from "../src/asset/candidates.js";
import { runAssetProbeJob } from "../src/asset/probe.js";
import { Database } from "../src/shared/db.js";
import { parseCandidateImport } from "../src/asset/importers.js";

// 探活实际走 src/shared/outbound.js 的 headRequest（node:https 的 HEAD，支持代理
// CONNECT 与宽容 TLS），不经过全局 fetch，所以桩必须打在 headRequest 上。
// 用 runAssetProbeJob 的 deps 注入而不是 vi.mock：模块级 mock 会触发 vitest 的
// SSR externalize 缓存，多 worker 并发写同一临时文件时在部分 Windows 环境会 EPERM，
// 让整批测试挂上 unhandled errors。
const headRequestMock = vi.fn();

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
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
    const rows = db.listAssetCandidates("p_src");
    expect(rows).toHaveLength(2);
    // listAssetCandidates 按 score DESC / last_seen DESC 排序，最后插入的 outside
    // 常排到 [0]；按值定位才能稳定验证"tags 去重且重复导入不清空"这条契约。
    const portal = rows.find(row => String(row.value ?? row.url ?? "").includes("app.example.com"));
    const outside = rows.find(row => String(row.value ?? row.url ?? "").includes("outside.example.net"));
    expect(portal).toBeDefined();
    expect(outside).toBeDefined();
    expect(portal).toMatchObject({ status: "candidate", tags: ["portal"] });
    expect(outside).toMatchObject({ status: "candidate", tags: [] });
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
    headRequestMock.mockReset();
    headRequestMock.mockResolvedValue({
      status: 200,
      finalUrl: "https://app.example.com/",
      headers: new Headers({ "content-type": "text/html", server: "test" }),
      tls: null,
    });
    const result = await runAssetProbeJob(db, "p_src", String(job.id), undefined, { headRequest: headRequestMock });
    expect(result.ok).toBe(true);
    // HEAD / redirect 语义由 outbound 内部保证，调用参数只断言目标 URL 与超时；
    // 下面两条结果断言仍然验住"探活真的发生且落库"，一条都不能少。
    expect(headRequestMock).toHaveBeenCalledWith("https://app.example.com/", expect.objectContaining({ timeoutMs: 8000 }));
    expect(db.getAssetProbeJob("p_src", String(job.id))).toMatchObject({ status: "completed", completed: 1 });
    expect(db.listAssetCandidates("p_src")[0]).toMatchObject({ status: "completed", http_status: 200, tags: ["reachable", "html"] });
  });
});

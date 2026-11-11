import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { discoverHttpSeeds } from "../src/asset/discover.js";
import { buildAssetMap } from "../src/asset/map.js";
import { validateHttpAsset } from "../src/validation/http.js";
import { importAssets } from "../src/asset/service.js";
import { Database } from "../src/shared/db.js";
import { discoverArl, parseArlTarget } from "../src/asset/arl.js";

const dirs: string[] = [];
const databases: Database[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  databases.splice(0).forEach(db => db.close());
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("asset inventory", () => {
  it("collects every ARL result page and reports remote task status", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-arl-pages-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("Token")).toBe("secret");
      const url = new URL(String(input));
      if (url.pathname === "/api/task/") return Response.json({ code: 200, items: [{ _id: "task1", status: "done" }] });
      if (url.pathname === "/api/site/") return Response.json({ code: 200, total: 0, items: [] });
      const page = Number(url.searchParams.get("page"));
      return Response.json({ code: 200, total: 501, items: Array.from({ length: page === 1 ? 500 : 1 }, (_, i) => ({ domain: `asset${(page - 1) * 500 + i}.example.com` })) });
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await discoverArl({ db, projectId: "p_src", target: "example.com", taskIds: ["task1"], wait: true, values: { ARL_URL: "http://arl.test", ARL_TOKEN: "secret" } });
    expect(result).toMatchObject({ accepted: 501, tasks: [{ id: "task1", status: "done" }] });
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("page=2"))).toBe(true);
  });

  it("normalizes, deduplicates, records observations, and builds a map", () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-assets-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const first = importAssets(db, "p_src", [
      { value: "https://api.example.com:443/health", source: "http-probe", title: "API" },
      { value: "https://api.example.com:443/health", source: "http-probe", title: "API" },
      { value: "https://outside.example.net", source: "http-probe" },
    ]);
    expect(first.accepted).toHaveLength(2);
    expect(first.rejected).toHaveLength(0);
    const rows = db.listAssets("p_src");
    expect(rows).toHaveLength(2);
    // listAssets 按 last_seen DESC 排序，最后插入的 outside 常排到 [0]；
    // 按值定位才能稳定验证"资产去重、但每次导入都单独记一条 observation"。
    const api = rows.find(row => String(row.value ?? row.url ?? "").includes("api.example.com"));
    const outside = rows.find(row => String(row.value ?? row.url ?? "").includes("outside.example.net"));
    expect(api).toBeDefined();
    expect(outside).toBeDefined();
    expect(db.listAssetObservations("p_src", String(api!.id))).toHaveLength(2);
    expect(db.listAssetObservations("p_src", String(outside!.id))).toHaveLength(1);
    const map = buildAssetMap(db, "p_src") as { view?: { nodes?: Array<{ id: string; group: string }> } };
    expect(map.view?.nodes?.some((node) => node.group === "recon")).toBe(true);
  });

  it("performs bounded HEAD discovery for every seed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-assets-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const fetchMock = vi.fn(async () => new Response(null, { status: 200, headers: { server: "test", "content-type": "text/html" } }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await discoverHttpSeeds(db, "p_src", [
      { value: "https://api.example.com" },
      { value: "https://outside.example.net" },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ method: "HEAD", redirect: "manual" });
    expect(result.accepted).toHaveLength(2);
    expect(result.rejected).toHaveLength(0);
  });

  it("records only low-impact HTTP observations as findings", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-assets-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 200, headers: { server: "test" } })));
    const imported = importAssets(db, "p_src", [{ value: "https://api.example.com", source: "seed" }]);
    const findingResult = await validateHttpAsset(db, "p_src", imported.accepted[0]!);
    expect(findingResult.checked).toBe(true);
    expect(findingResult.findings.map((row) => row.check_id)).toContain("http.missing-hsts");
    expect(db.listFindings("p_src").length).toBeGreaterThan(0);
  });

  it("submits an ARL task and imports domain/site results", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-arl-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const fetchMock = vi.fn(async (input: string | URL) => {
      const target = String(input);
      if (target.includes("/api/task/")) return new Response(JSON.stringify({ code: 200, items: [{ task_id: "arl-task-1" }] }), { status: 200 });
      if (target.includes("/api/domain/")) return new Response(JSON.stringify({ code: 200, items: [{ domain: "api.topsec.com.cn" }, { domain: "outside.example.net" }] }), { status: 200 });
      if (target.includes("/api/site/")) return new Response(JSON.stringify({ code: 200, items: [{ site: "https://portal.topsec.com.cn/login" }] }), { status: 200 });
      throw new Error(`unexpected ARL request ${target}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await discoverArl({ db, projectId: "p_src", target: "topsec.com.cn", values: { ARL_URL: "https://arl.test", ARL_TOKEN: "token" }, wait: true });
    expect(result).toMatchObject({ source: "arl", task_ids: ["arl-task-1"], accepted: 3 });
    expect(db.listAssetCandidates("p_src")).toHaveLength(3);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ method: "POST" });
  });

  it("accepts a direct root target and rejects malformed targets", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-arl-target-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const fetchMock = vi.fn(async (input: string | URL) => {
      const target = String(input);
      if (target.includes("/api/task/")) return new Response(JSON.stringify({ code: 200, items: [{ task_id: "arl-target-1" }] }), { status: 200 });
      if (target.includes("/api/domain/")) return new Response(JSON.stringify({ code: 200, items: [{ domain: "api.topsec.com.cn" }] }), { status: 200 });
      if (target.includes("/api/site/")) return new Response(JSON.stringify({ code: 200, items: [] }), { status: 200 });
      throw new Error(`unexpected ARL request ${target}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await discoverArl({ db, projectId: "p_src", target: "topsec.com.cn", values: { ARL_URL: "https://arl.test", ARL_TOKEN: "token" }, wait: true });
    expect(result).toMatchObject({ target: "topsec.com.cn", targets: ["topsec.com.cn"], accepted: 1 });
    const taskBody = JSON.parse(String(fetchMock.mock.calls[0]?.[1] && (fetchMock.mock.calls[0]?.[1] as RequestInit).body));
    expect(taskBody.target).toBe("topsec.com.cn");
    expect(db.listAssetCandidates("p_src")).toHaveLength(1);
    await expect(discoverArl({ db, projectId: "p_src", target: "api.topsec.com.cn/path", values: { ARL_URL: "https://arl.test", ARL_TOKEN: "token" } })).rejects.toThrow("domain name");
  });

  it("expands a wildcard ARL target and pulls ip assets into the pool", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-arl-wildcard-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const posts: RequestInit[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL, init?: RequestInit) => {
      const target = String(input);
      if (target.includes("/api/task/") && (init?.method || "").toUpperCase() === "POST") {
        posts.push(init!);
        return Response.json({ code: 200, items: [{ task_id: "arl-wild-1" }] });
      }
      if (target.includes("/api/domain/")) return Response.json({ code: 200, items: [{ domain: "chat.qwen.ai" }] });
      if (target.includes("/api/site/")) return Response.json({ code: 200, items: [] });
      if (target.includes("/api/ip/")) return Response.json({ code: 200, items: [{ ip: "5.5.5.5", port: 8443 }, { ip: "6.6.6.6", port: 80, domain: "dash.qwen.ai" }] });
      if (target.includes("/api/task/")) return Response.json({ code: 200, items: [{ _id: "arl-wild-1", status: "running" }] });
      throw new Error(`unexpected ARL request ${target}`);
    }));

    expect(parseArlTarget("*.qwen.ai")).toEqual({ host: "qwen.ai", wildcard: true });
    expect(parseArlTarget("https://Qwen.ai/")).toEqual({ host: "qwen.ai", wildcard: false });
    const result = await discoverArl({ db, projectId: "p_src", target: "*.qwen.ai", values: { ARL_URL: "https://arl.test", ARL_TOKEN: "token" }, wait: true, includeIps: true });
    expect(result).toMatchObject({ target: "qwen.ai", targets: ["qwen.ai"], wildcard: true, accepted: 3, task_ids: ["arl-wild-1"], pending: true, pending_status: ["running"] });
    const body = JSON.parse(String(posts[0]?.body));
    expect(body).toMatchObject({
      target: "qwen.ai", domain_brute: true, domain_brute_type: "small", alt_dns: true,
      ssl_cert: true, dns_query_plugin: true, site_identify: true, port_scan: false,
    });
    const hosts = db.listAssetCandidates("p_src").map((row) => new URL(String(row.value)).host).sort();
    expect(hosts).toEqual(["5.5.5.5:8443", "chat.qwen.ai", "dash.qwen.ai"]);
  });

  it("submits one ARL task per target in a comma separated list", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-arl-multi-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    const submitted: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body || "{}"));
      submitted.push(String(body.target));
      return Response.json({ code: 200, items: [{ task_id: `task-${submitted.length}` }] });
    }));
    const result = await discoverArl({
      db, projectId: "p_src", target: "*.qwen.ai, admin.qwen.ai", wait: false,
      brute: "small", scan: { search_engines: true }, values: { ARL_URL: "https://arl.test", ARL_TOKEN: "token" },
    });
    expect(result).toMatchObject({ targets: ["qwen.ai", "admin.qwen.ai"], wildcard: true, status: "submitted" });
    expect(submitted).toEqual(["qwen.ai", "admin.qwen.ai"]);
    expect(result.scan).toMatchObject({ domain_brute_type: "small", search_engines: true });
  });

  it("keeps domain results when the ARL build has no ip collector", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-arl-noip-"));
    dirs.push(dir);
    const db = new Database(join(dir, "nianyun.db")); databases.push(db);
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
      const target = String(input);
      if (target.includes("/api/task/") && !target.includes("_id=")) return Response.json({ code: 200, items: [{ task_id: "no-ip-task" }] });
      if (target.includes("/api/task/")) return Response.json({ code: 200, items: [{ _id: "no-ip-task", status: "done" }] });
      if (target.includes("/api/domain/")) return Response.json({ code: 200, items: [{ domain: "chat.qwen.ai" }] });
      if (target.includes("/api/site/")) return Response.json({ code: 200, items: [] });
      return new Response("not found", { status: 404 });
    }));
    const result = await discoverArl({ db, projectId: "p_src", target: "*.qwen.ai", values: { ARL_URL: "https://arl.test", ARL_TOKEN: "token" }, wait: true, includeIps: true });
    expect(result).toMatchObject({ accepted: 1, discovered: 1 });
    expect(String((result.ip_errors as string[])[0])).toMatch(/404/);
    expect(db.listAssetCandidates("p_src")).toHaveLength(1);
  });
});

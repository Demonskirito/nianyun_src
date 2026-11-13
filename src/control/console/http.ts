import { LedgerError } from "../../shared/project-ledger.js";
import { ExecutionDenied } from "../../shared/execution.js";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { networkInterfaces } from "node:os";
import { extname, join, relative, resolve } from "node:path";
import type { Config } from "../../shared/config.js";
import { Database } from "../../shared/db.js";
import * as llmIo from "./llm-io.js";
import { checkArl } from "../../asset/arl.js";
import { checkFofa } from "../../asset/fofa.js";
import * as workspace from "./workspace.js";
import { Desk } from "./desk.js";
import { blackboxRulesDiagnostics } from "../../blackbox/rules.js";
import { DIMENSION_LABEL, WAF_VENDORS } from "../../blackbox/waf-ledger.js";

const DEFAULT_PORT = 8700;

const CTYPE: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function lanDeskUrls(port: number): string[] {
  const urls: string[] = [];
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs || []) {
      const v4 = a.family === "IPv4" || (a.family as unknown) === 4;
      if (!v4 || a.internal) continue;
      urls.push(`http://${a.address}:${port}/`);
    }
  }
  return urls;
}

export function parseListen(spec: string): { host: string; port: number } {
  const s = (spec || "").trim();
  if (s.includes("://")) {
    const u = new URL(s);
    return { host: u.hostname || "0.0.0.0", port: Number.parseInt(u.port || String(DEFAULT_PORT), 10) || DEFAULT_PORT };
  }
  if (s.includes(":")) {
    const i = s.lastIndexOf(":");
    return { host: s.slice(0, i) || "0.0.0.0", port: Number.parseInt(s.slice(i + 1), 10) || DEFAULT_PORT };
  }
  return { host: "0.0.0.0", port: Number.parseInt(s || String(DEFAULT_PORT), 10) || DEFAULT_PORT };
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("error", reject);
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8") || "{}";
      try {
        const data = JSON.parse(raw) as unknown;
        if (!data || typeof data !== "object" || Array.isArray(data)) {
          reject(new Error("body must be an object"));
          return;
        }
        resolveBody(data as Record<string, unknown>);
      } catch {
        reject(new Error("body must be JSON"));
      }
    });
  });
}

// 已压缩的二进制不要重复 gzip（图片/字体/zip 等）。
const NO_GZIP_CT = /^(image\/|video\/|audio\/|font\/|application\/(zip|gzip|x-gzip|pdf|octet-stream))/i;

/** 挂在 ServerResponse 上的缓存协商元数据，避免改动所有调用点签名。 */
type ResponseCacheMeta = {
  acceptEncoding?: string;
  ifNoneMatch?: string;
  etagToSet?: string;
  cacheControlToSet?: string;
  cacheable?: boolean;
};

function send(res: ServerResponse, status: number, body: Buffer | string, contentType: string, head = false): void {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const meta = res as unknown as ResponseCacheMeta;
  const cacheControl = String(meta.cacheControlToSet || "no-store");
  const etag = String(meta.etagToSet || "");
  const headers: Record<string, string | number> = {
    "Content-Type": contentType,
    "Cache-Control": cacheControl,
    Connection: "close",
  };
  // ETag 与 304 判定都必须在 gzip 分支之前：压缩响应丢 ETag 会让协商失效，
  // 而 304 不能携带 Content-Encoding / 响应体。
  if (etag) headers["ETag"] = etag;
  if (meta.cacheable && etag && !head && String(meta.ifNoneMatch || "") === etag) {
    res.writeHead(304, { ETag: etag, "Cache-Control": cacheControl, Connection: "close" });
    res.end();
    return;
  }
  // 看客户端是否接受 gzip；仅对较大的文本/JSON 压缩，避免小包与已压缩二进制的开销。
  const acceptEncoding = String(meta.acceptEncoding || "");
  if (acceptEncoding.includes("gzip") && buf.length > 512 && !NO_GZIP_CT.test(contentType)) {
    const gz = gzipSync(buf, { level: 6 });
    headers["Content-Encoding"] = "gzip";
    headers["Content-Length"] = gz.length;
    res.writeHead(status, headers);
    if (head) { res.end(); return; }
    res.end(gz);
    return;
  }
  headers["Content-Length"] = buf.length;
  res.writeHead(status, headers);
  if (head) {
    res.end();
    return;
  }
  res.end(buf);
}

function sendJson(res: ServerResponse, status: number, obj: unknown, head = false): void {
  send(res, status, JSON.stringify(obj), "application/json; charset=utf-8", head);
}

/**
 * 可协商的静态型 JSON（目前只有 /api/tools）。
 * routing / rules / tools 清单都由代码同源常量生成，内容不变即可命中 304；
 * updated_at 是每次请求都变的时间戳，必须排除，否则 ETag 永不相等。
 * `private, no-cache` 允许浏览器留存但每次重验证，命中 304 时浏览器把缓存的
 * 完整 body 交给 fetch，前端 api() 无需改动。含凭据的 /api/settings 不走这里。
 */
function sendJsonCached(res: ServerResponse, payload: Record<string, unknown>, head = false): void {
  const stable = { ...payload };
  delete stable.updated_at;
  const etag = `"${createHash("sha1").update(JSON.stringify(stable)).digest("hex").slice(0, 24)}"`;
  const meta = res as unknown as ResponseCacheMeta;
  meta.etagToSet = etag;
  meta.cacheControlToSet = "private, no-cache";
  meta.cacheable = true;
  sendJson(res, 200, payload, head);
}

/** Vite 产物名带内容 hash（index-DUc7yrpT.js）；只有带 hash 才能安全 immutable。 */
function staticAssetHash(path: string): string {
  if (!path.startsWith("/assets/")) return "";
  const name = path.split("/").pop() || "";
  const match = /-([A-Za-z0-9_-]{8,})\.[A-Za-z0-9]+$/.exec(name);
  return match?.[1] || "";
}

function staticRoots(cfg: Config): string[] {
  const spa = join(cfg.repo_root, "console", "spa");
  return existsSync(join(spa, "index.html")) ? [spa] : [];
}

function readStatic(cfg: Config, path: string): { body: Buffer; type: string } | null {
  let rel = path.replace(/^\/+/, "") || "index.html";
  if (rel === "desk" || rel === "desk/") rel = "index.html";
  if (rel.includes("..")) return null;
  const ctype = CTYPE[extname(rel).toLowerCase()] || "application/octet-stream";
  for (const root of staticRoots(cfg)) {
    const fp = resolve(join(root, rel));
    try {
      if (relative(resolve(root), fp).startsWith("..")) continue;
    } catch {
      continue;
    }
    if (existsSync(fp)) {
      try {
        if (!statSync(fp).isFile()) continue;
      } catch {
        continue;
      }
      return { body: readFileSync(fp), type: ctype };
    }
  }
  const spaIndex = join(cfg.repo_root, "console", "spa", "index.html");
  if (existsSync(spaIndex) && !extname(rel.split("/").pop() || rel)) {
    return { body: readFileSync(spaIndex), type: "text/html; charset=utf-8" };
  }
  return null;
}

function qs(url: URL, name: string): string | null {
  const v = url.searchParams.get(name);
  return v == null ? null : v;
}

export function applyConsoleOverlays(cfg: Config): Config {
  llmIo.loadOverlay(cfg);
  return cfg;
}

export async function serveConsole(cfg: Config, db: Database, listen: string): Promise<void> {
  if (cfg.execution.mode === "inspect") throw new ExecutionDenied("HTTP server in inspect mode");
  applyConsoleOverlays(cfg);
  db.recoverBlackboxSessions();
  try { workspace.ensureDefault(cfg); } catch (error) { if (!(error instanceof LedgerError)) throw error; console.error(error.message); }
  const desk = new Desk(cfg, db);
  const { host, port } = parseListen(listen);
  const server = createServer((req, res) => {
    void handle(cfg, desk, req, res);
  });
  // Long-running background jobs (probe, review, blackbox) must never take the desk down with
  // them: log the rejection and keep serving instead of letting Node exit on it.
  process.on("unhandledRejection", (reason) => {
    console.error(`[console] unhandled rejection: ${reason instanceof Error ? reason.stack || reason.message : String(reason)}`);
  });
  server.keepAliveTimeout = 5000;
  try { await new Promise<void>((ok, err) => {
    server.on("error", err);
    server.listen(port, host || "0.0.0.0", () => {
      const bind = host || "0.0.0.0";
      const lan = bind === "0.0.0.0" || bind === "::" ? lanDeskUrls(port) : [];
      const extra = lan.length ? `  lan ${lan.join(" ")}` : "";
      console.log(`console on http://${bind}:${port}  desk http://127.0.0.1:${port}/${extra}`);
      ok();
    });
  }); } catch (error) { desk.dispose(); server.close(); throw error; }
  console.log(`execution mode=${cfg.execution.mode} source=${cfg.execution.source}`);
  const ruleState = blackboxRulesDiagnostics(cfg.tools_env.values);
  if (ruleState.fallback) console.error(`[rules] ${ruleState.issues.join(" ")}`);
  else if (ruleState.issues.length) console.warn(`[rules] 规则文档有被忽略的配置项：${ruleState.issues.join(" ")}`);
  if (ruleState.credential_tools.length) console.log(`[rules] 已开启凭据爆破：${ruleState.credential_tools.join(", ")}`);
  desk.startBackground();
  let stopping = false;
  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    desk.dispose();
    server.close();
    server.closeAllConnections();
    process.exit(0);
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

async function handle(cfg: Config, desk: Desk, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const head = req.method === "HEAD";
  // Scanners and browsers send protocol-relative paths such as `//host/..%22><script>`.
  // `new URL` throws ERR_INVALID_URL on those and used to escape as an unhandled TypeError.
  let url: URL;
  try {
    url = new URL(req.url || "/", "http://console.local");
  } catch {
    sendJson(res, 400, { ok: false, error: "invalid request url" }, head);
    return;
  }
  // 把客户端是否接受 gzip 记到 res 上，send() 据此决定是否压缩（不影响任何调用点签名）。
  (res as unknown as { acceptEncoding?: string }).acceptEncoding = req.headers["accept-encoding"];
  // 记录 If-None-Match，供候选接口做 304 协商（不改动调用点签名）。
  (res as unknown as { ifNoneMatch?: string }).ifNoneMatch = req.headers["if-none-match"];
  try {
    const path = url.pathname || "/";
    const method = (req.method || "GET").toUpperCase();
    if (method === "GET" || method === "HEAD") {
      await handleGet(cfg, desk, path, url, res, head);
      return;
    }
    if (method === "POST" || method === "PUT") {
      const body = await readBody(req);
      await handlePost(desk, path, body, res);
      return;
    }
    if (method === "DELETE") {
      const body = await readBody(req);
      handleDelete(desk, path, body, res);
      return;
    }
    sendJson(res, 405, { ok: false, error: "method not allowed" });
  } catch (e) {
    if (e instanceof ExecutionDenied) { sendJson(res, 403, { ok: false, code: e.code, error: e.message }, head); return; }
    if (e instanceof LedgerError) { sendJson(res, e.code === "ledger_conflict" ? 409 : 503, { ok: false, code: e.code, error: e.message }, head); return; }
    if (e instanceof Error && (e.message === "body must be JSON" || e.message === "body must be an object")) {
      sendJson(res, 400, { ok: false, error: e.message }, head);
      return;
    }
    console.error(`console handler ${req.method} ${req.url}:`, e);
    try {
      sendJson(res, 500, { ok: false, error: "console handler crash" }, head);
    } catch {
      /* ignore */
    }
  }
}

async function handleGet(
  cfg: Config,
  desk: Desk,
  path: string,
  url: URL,
  res: ServerResponse,
  head: boolean,
): Promise<void> {
  if (path === "/api/health" || path === "/health" || path === "/api/status") {
    sendJson(res, 200, desk.status(), head);
    return;
  }
  if (path === "/api/settings") {
    sendJson(res, 200, desk.settingsBundle(), head);
    return;
  }
  if (path === "/api/auth-seeds") {
    sendJson(res, 200, { ok: true, seeds: desk.listAuthSeeds() }, head);
    return;
  }
  if (path === "/api/tools") {
    sendJsonCached(res, desk.systemTools(), head);
    return;
  }
  if (path === "/api/waf-bypasses") {
    // 战例库：厂商归类、档位、可用变体、命中次数。控制台页面与 agent 的 prompt 读同一张表。
    const ledger = desk.wafLedger({
      projectId: url.searchParams.get("project") || undefined,
      vendor: url.searchParams.get("vendor") || undefined,
      limit: Number(url.searchParams.get("limit") || 200),
    });
    sendJson(res, 200, {
      ...ledger,
      dimension_labels: DIMENSION_LABEL,
      known_vendors: WAF_VENDORS.map(vendor => ({ id: vendor.id, name: vendor.name, family: vendor.family })),
    }, head);
    return;
  }
  if (path === "/api/tool-health") {
    const windowParam = url.searchParams.get("window") || "";
    const windowSeconds = (/^\d+$/.test(windowParam) ? Number(windowParam) : ({ "24h": 86400, "7d": 604800, "30d": 2592000, all: 0 } as Record<string, number>)[windowParam] ?? 604800);
    sendJson(res, 200, desk.toolHealth({ windowSeconds, projectId: url.searchParams.get("project") || undefined }), head);
    return;
  }
  if (path === "/api/arl/check") {
    try {
      sendJson(res, 200, await checkArl(desk.cfg.tools_env.values), head);
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }, head);
    }
    return;
  }
  if (path === "/api/fofa/check") {
    try {
      sendJson(res, 200, await checkFofa(desk.cfg.tools_env.values), head);
    } catch (error) {
      sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) }, head);
    }
    return;
  }
  if (path === "/api/projects") {
    const items = workspace.listProjects(desk.cfg).map((project) => {
      const pid = String(project.id || "");
      const candidates = desk.db.listAssetCandidates(pid, { limit: 5000 });
      const sessions = desk.db.listBlackboxSessions(pid, 200);
      return {
        ...project,
        candidate_count: candidates.length,
        session_count: sessions.length,
        running: sessions.filter((session) => session.status === "running").length,
        finding_count: desk.db.listFindings(pid, { limit: 1000 }).length,
      };
    });
    sendJson(res, 200, { items }, head);
    return;
  }
  if (path.startsWith("/api/projects/")) {
    const parts = path.slice("/api/projects/".length).replace(/\/+$/, "").split("/").filter(Boolean);
    if (!parts.length) {
      sendJson(res, 404, { ok: false, error: "not found" }, head);
      return;
    }
    const proj = workspace.getProject(desk.cfg, parts[0]!);
    if (!proj) {
      sendJson(res, 404, { ok: false, error: "project not found" }, head);
      return;
    }
    const pid = String(proj.id);
    if (parts.length === 1) {
      sendJson(res, 200, desk.projectBundle(pid), head);
      return;
    }
    if (parts.length === 2 && parts[1] === "assets") {
      const rec = desk.projectAssets(pid, { limit: Number(qs(url, "limit") || 200), status: qs(url, "status") || undefined });
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 3 && parts[1] === "arl" && parts[2] === "tasks") {
      sendJson(res, 200, desk.projectArlTask(pid), head);
      return;
    }
    if (parts.length === 3 && parts[1] === "fofa" && parts[2] === "state") {
      sendJson(res, 200, desk.projectFofaState(pid), head);
      return;
    }
    if (parts.length === 4 && parts[1] === "candidates" && parts[3] === "screenshot") {
      const image = desk.assetScreenshot(pid, parts[2]!);
      if (!image) { sendJson(res, 404, { ok: false, error: "screenshot not found" }, head); return; }
      send(res, 200, image, "image/png", head);
      return;
    }
    if (parts.length === 3 && parts[1] === "candidates") {
      const rec = desk.projectCandidate(pid, parts[2]!);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "candidates") {
      const idsOnly = url.searchParams.get("ids") === "1";
      const scope = (url.searchParams.get("scope") || "all") as "all" | "pending" | "retry";
      const limit = Number(url.searchParams.get("limit") || (idsOnly ? 10000 : 50));
      const offset = Number(url.searchParams.get("offset") || 0);
      const pagedOpts = {
        limit: Number.isFinite(limit) ? Math.min(10000, Math.max(1, limit)) : 50,
        offset: Number.isFinite(offset) ? Math.max(0, offset) : 0,
        status: url.searchParams.get("status") || undefined,
        tag: url.searchParams.get("tag") || undefined,
        query: url.searchParams.get("query") || undefined,
        minScore: url.searchParams.get("min_score") ? Number(url.searchParams.get("min_score")) : undefined,
        onlyReachable: url.searchParams.get("reachable") === "1",
        sort: (url.searchParams.get("sort") as "score" | "recent") || "score",
        scope,
      };
      if (idsOnly) {
        const rec = desk.projectCandidateIds(pid, pagedOpts);
        if (!rec.ok) { sendJson(res, 404, rec, head); return; }
        sendJson(res, 200, { ok: true, ids: rec.ids }, head);
        return;
      }
      const rec = desk.projectCandidatesPaged(pid, pagedOpts);
      if (!rec.ok) { sendJson(res, 404, rec, head); return; }
      // ETag 由「项目 + 查询串 + 总数 + 最近更新时间」决定；未变化即 304，前端无需重新解析/重排。
      const etag = `"${createHash("sha1").update(`${pid}|${url.search}|${rec.total}|${rec.maxLastSeen}`).digest("hex").slice(0, 24)}"`;
      const prev = (res as unknown as { ifNoneMatch?: string }).ifNoneMatch;
      if (!head && prev === etag) {
        res.writeHead(304, { ETag: etag, "Cache-Control": "no-store", Connection: "close" });
        res.end();
        return;
      }
      (res as unknown as { etagToSet?: string }).etagToSet = etag;
      sendJson(res, 200, { ok: true, items: rec.items, total: rec.total, aggregates: rec.aggregates, tags: rec.tags }, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "probe-jobs") {
      const rec = desk.projectProbeJobs(pid, Number(qs(url, "limit") || 100));
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "asset-review-jobs") {
      const rec = desk.projectAssetReviewJobs(pid, Number(qs(url, "limit") || 50));
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "blackbox-sessions") {
      const rec = desk.projectBlackboxSessions(pid, Number(qs(url, "limit") || 100));
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "report") {
      const rec = desk.projectBlackboxReport(pid, parts[2]!);
      if (qs(url, "format") === "markdown" && rec.ok) send(res, 200, String(rec.markdown), "text/markdown; charset=utf-8", head);
      else sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 3 && parts[1] === "blackbox-sessions") {
      const light = url.searchParams.get("light") === "1";
      const brief = url.searchParams.get("brief") === "1";
      const rec = desk.projectBlackboxSession(pid, parts[2]!, light, brief);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "events") {
      const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit")) || 50));
      const offset = Math.max(0, Number(url.searchParams.get("offset")) || 0);
      const dir = url.searchParams.get("dir") === "desc" ? "desc" : "asc";
      const beforeRaw = url.searchParams.get("before");
      const sinceRaw = url.searchParams.get("since");
      const before = beforeRaw !== null && beforeRaw !== "" ? Number(beforeRaw) : undefined;
      const since = sinceRaw !== null && sinceRaw !== "" ? Number(sinceRaw) : undefined;
      const rec = desk.projectBlackboxEvents(pid, parts[2]!, limit, offset, { dir, before, since });
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "evidence") {
      const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit")) || 24));
      const offset = Math.max(0, Number(url.searchParams.get("offset")) || 0);
      const rec = desk.projectBlackboxEvidence(pid, parts[2]!, limit, offset);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "focus") {
      const rec = desk.projectBlackboxFocus(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
      // 时光机：GET 列快照（fork 是 POST，在 handlePost 里）。
      if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "checkpoints") {
        const rec = desk.listProjectBlackboxCheckpoints(parts[0]!, parts[2]!);
        sendJson(res, rec.ok ? 200 : 404, rec);
        return;
      }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "graph") {
      const rec = desk.projectBlackboxGraph(pid, parts[2]!, { maxNodes: Number(qs(url, "max_nodes") || 300) });
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 5 && parts[1] === "blackbox-sessions" && parts[3] === "artifacts") {
      const artifact = desk.blackboxArtifact(pid, parts[2]!, parts[4]!);
      if (!artifact) { sendJson(res, 404, { ok: false, error: "artifact not found" }, head); return; }
      send(res, 200, artifact.body, artifact.contentType, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "asset-map") {
      const rec = desk.projectAssetMap(pid);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "findings") {
      const rec = desk.projectFindings(pid, { limit: Number(qs(url, "limit") || 200), status: qs(url, "status") || undefined });
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 2 && parts[1] === "report") {
      const rec = desk.projectReport(pid);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "assets" && parts[3] === "observations") {
      const rec = desk.projectAssetObservations(pid, parts[2]!);
      sendJson(res, rec.ok ? 200 : 404, rec, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "candidates" && parts[3] === "review") {
      sendJson(res, 405, { ok: false, error: "use POST" }, head);
      return;
    }
    if (parts.length === 4 && parts[1] === "probe-jobs" && ["pause", "resume", "cancel"].includes(parts[3]!)) {
      sendJson(res, 405, { ok: false, error: "use POST" }, head);
      return;
    }
    sendJson(res, 404, { ok: false, error: "not found" }, head);
    return;
  }
  if (path === "/favicon.ico" || path === "/robots.txt") {
    send(res, 204, Buffer.alloc(0), "text/plain", head);
    return;
  }
  const staticFile = readStatic(cfg, path);
  if (staticFile) {
    const hash = staticAssetHash(path);
    if (hash) {
      // 内容寻址资源：浏览器一年内不再发请求；ETag/304 作为缓存被清后的兜底。
      const meta = res as unknown as ResponseCacheMeta;
      meta.etagToSet = `"${hash}"`;
      meta.cacheControlToSet = "public, max-age=31536000, immutable";
      meta.cacheable = true;
    }
    send(res, 200, staticFile.body, staticFile.type, head);
    return;
  }
  const index = readStatic(cfg, "index.html");
  if (index && !path.startsWith("/api/") && !extname(path)) {
    send(res, 200, index.body, index.type, head);
    return;
  }
  sendJson(res, 404, { ok: false, error: "not found" }, head);
}

async function handlePost(
  desk: Desk,
  path: string,
  body: Record<string, unknown>,
  res: ServerResponse,
): Promise<void> {
  if (path === "/api/settings") {
    try {
      sendJson(res, 200, desk.updateSettings(body));
    } catch (e) {
      if (e instanceof LedgerError) throw e;
      sendJson(res, 400, { ok: false, error: String(e instanceof Error ? e.message : e) });
    }
    return;
  }
  if (path === "/api/auth-seeds") {
    const rec = desk.saveAuthSeed(String(body.host || ""), String(body.content || ""));
    sendJson(res, rec.ok ? 200 : 400, rec);
    return;
  }
  if (path === "/api/projects") {
    try {
      const rec = workspace.createProject(desk.cfg, String(body.name || ""), String(body.note || ""));
      sendJson(res, 200, { ok: true, project: rec });
    } catch (e) {
      if (e instanceof LedgerError) throw e;
      sendJson(res, 400, { ok: false, error: String(e instanceof Error ? e.message : e) });
    }
    return;
  }
  if (path.startsWith("/api/projects/")) {
    const parts = path.slice("/api/projects/".length).replace(/\/+$/, "").split("/").filter(Boolean);
    if (parts.length === 2 && parts[1] === "automation") {
      const rec = desk.updateProjectAutomation(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "assets" && parts[2] === "import") {
      const rec = desk.importProjectAssets(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "assets" && parts[2] === "discover") {
      const rec = await desk.discoverProjectAssets(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "arl" && parts[2] === "discover") {
      const rec = await desk.discoverProjectArl(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "fofa" && parts[2] === "discover") {
      const rec = await desk.discoverProjectFofa(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "asset-review") {
      const rec = await desk.reviewProjectAssets(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : 400, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "blackbox-sessions") {
      const rec = desk.createProjectBlackboxSession(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "check") {
      const rec = await desk.checkProjectBlackboxEnvironment(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "instruction") {
      const rec = desk.addProjectBlackboxInstruction(parts[0]!, parts[2]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "run") {
      const rec = desk.startProjectBlackboxAgents(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "review") {
      const rec = desk.reviewProjectBlackboxItem(parts[0]!, parts[2]!, body);
      sendJson(res, rec.ok ? 200 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "focus") {
      const rec = desk.updateProjectBlackboxFocus(parts[0]!, parts[2]!, String(body.action || ""), String(body.task_id || ""));
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && ["pause", "resume", "cancel"].includes(parts[3]!)) {
      const rec = desk.updateProjectBlackboxSession(parts[0]!, parts[2]!, parts[3]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    // 时光机：从快照 fork 出一个新会话（POST）。
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "fork") {
      const rec = desk.forkProjectBlackboxSession(parts[0]!, parts[2]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    // 历程图：历史回放重建（把已有的 tool-request/tool-result 按时间重放进图）。
    if (parts.length === 5 && parts[1] === "blackbox-sessions" && parts[3] === "graph" && parts[4] === "rebuild") {
      const rec = desk.rebuildProjectBlackboxGraph(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    // 协议回填：用今天新增的四个协议离线重放历史会话（只读），结论写 historical_inference 事件。
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "replay-protocols") {
      const rec = desk.replayProjectBlackboxProtocols(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" || rec.error === "blackbox session not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "candidates" && parts[2] === "import") {
      const rec = desk.importProjectCandidates(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "candidates" && parts[3] === "review") {
      const rec = desk.reviewProjectCandidate(parts[0]!, parts[2]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "probe-jobs") {
      const rec = desk.createProjectProbeJob(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "probe-jobs" && ["pause", "resume", "cancel"].includes(parts[3]!)) {
      const status = parts[3] === "pause" ? "paused" : parts[3] === "resume" ? "running" : "cancelled";
      const rec = desk.updateProjectProbeJob(parts[0]!, parts[2]!, status);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "probe-jobs" && parts[3] === "run") {
      const rec = await desk.runProjectProbeJob(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "validate") {
      const rec = await desk.validateProjectAssets(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "risk") {
      const rec = desk.recalculateProjectRisk(parts[0]!);
      sendJson(res, rec.ok ? 200 : 404, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "automation" && parts[2] === "run") {
      const rec = await desk.runProjectAutomation(parts[0]!);
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    sendJson(res, 404, { ok: false, error: "not found" });
    return;
  }
  sendJson(res, 404, { ok: false, error: "not found" });
}

function handleDelete(desk: Desk, path: string, body: Record<string, unknown>, res: ServerResponse): void {
  if (path.startsWith("/api/auth-seeds/")) {
    const host = decodeURIComponent(path.slice("/api/auth-seeds/".length).replace(/\/+$/, ""));
    const rec = desk.deleteAuthSeed(host);
    sendJson(res, rec.ok ? 200 : 404, rec);
    return;
  }
  if (path.startsWith("/api/waf-bypasses/")) {
    // 战例可以删：模型回报错的变体留着会把后续会话全带偏。
    const id = path.slice("/api/waf-bypasses/".length).replace(/\/+$/, "");
    if (!id) { sendJson(res, 400, { ok: false, error: "id required" }); return; }
    const ok = desk.db.deleteWafBypass(id);
    sendJson(res, ok ? 200 : 404, { ok, id });
    return;
  }
  if (path.startsWith("/api/projects/")) {
    const parts = path.slice("/api/projects/".length).replace(/\/+$/, "").split("/").filter(Boolean);
    if (parts.length === 2 && parts[1] === "candidates") {
      const rec = desk.deleteProjectCandidates(parts[0]!, body);
      sendJson(res, rec.ok ? 200 : 404, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "cookies") {
      const rec = desk.clearProjectCookies(parts[0]!);
      sendJson(res, rec.ok ? 200 : 404, rec);
      return;
    }
    if (parts.length === 4 && parts[1] === "blackbox-sessions" && parts[3] === "cookies") {
      const rec = desk.clearProjectBlackboxCookies(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : rec.error === "blackbox session not found" || rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 2 && parts[1] === "blackbox-sessions") {
      const rec = desk.deleteProjectBlackboxSessions(parts[0]!, {
        ids: Array.isArray(body.ids) ? (body.ids as unknown[]).map(value => String(value)) : [],
        all: body.all === true,
      });
      sendJson(res, rec.ok ? 200 : rec.error === "project not found" ? 404 : 400, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "blackbox-sessions") {
      const rec = desk.deleteProjectBlackboxSession(parts[0]!, parts[2]!);
      const status = rec.ok ? 200 : rec.error === "session not found" || rec.error === "project not found" ? 404 : 409;
      sendJson(res, status, rec);
      return;
    }
    if (parts.length === 3 && parts[1] === "probe-jobs") {
      const rec = desk.deleteProjectProbeJob(parts[0]!, parts[2]!);
      sendJson(res, rec.ok ? 200 : String(rec.error || "").includes("cancelled first") ? 409 : 404, rec);
      return;
    }
    if (parts.length === 1) {
      const rec = desk.purgeProject(parts[0]!);
      sendJson(res, rec.ok ? 200 : 404, rec);
      return;
    }
  }
  sendJson(res, 404, { ok: false, error: "not found" });
}

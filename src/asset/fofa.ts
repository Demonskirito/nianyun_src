import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import type { Socket } from "node:net";
import type { Database } from "../shared/db.js";
import { importAssetCandidates } from "./candidates.js";

type FofaConfig = { baseUrl: string; key: string; proxy: string };

/** FOFA caps a single page at 1000 rows and ignores anything larger. */
const MAX_PAGE = 1000;
const MAX_PAGES = 5;
/** Each query strategy gets its own slice of the result budget. */
const DEFAULT_PER_STRATEGY = 300;
const FIELDS = "host,ip,port,protocol,domain,title,server";

/** Subdomain trees are queried three ways: the registered domain, the host string and the certificate. */
const STRATEGIES = ["domain", "host", "cert"] as const;
export type FofaStrategy = (typeof STRATEGIES)[number];
export type FofaQueryStrategy = FofaStrategy | "custom" | "ip";
export type FofaTarget = { host: string; wildcard: boolean; kind: "domain" | "ip" };
export type FofaQueryPlan = { strategy: FofaQueryStrategy; query: string };

function value(...items: unknown[]): string {
  return items.map((item) => String(item ?? "").trim()).find(Boolean) || "";
}

function config(values: Record<string, string>): FofaConfig {
  return {
    baseUrl: (value(values.FOFA_URL, values.FOFA_BASE_URL) || "https://fofa.info").replace(/\/$/, ""),
    key: value(values.FOFA_KEY, values.FOFA_API_KEY),
    proxy: value(values.FOFA_PROXY),
  };
}

/** `*.qwen.ai`, `.qwen.ai`, `qwen.ai`, `https://*.qwen.ai/console` all resolve to the same wildcard base. */
function inspect(raw: string): { host: string; wildcard: boolean } {
  const text = String(raw ?? "").trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const wildcard = /^(\*\.|\.)/.test(text);
  const host = text
    .replace(/^(\*\.|\.)/, "")
    .split(/[/?#]/)[0]!
    .replace(/\.+$/, "")
    .toLowerCase();
  return { host, wildcard };
}

export function parseFofaTarget(raw: string): FofaTarget {
  const { host, wildcard } = inspect(raw);
  if (!host || host.includes(":")) throw new Error("FOFA target must be a domain or an IP address");
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    if (host.split(".").some((part) => Number(part) > 255)) throw new Error("FOFA target is not a valid IP address");
    return { host, wildcard, kind: "ip" };
  }
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label) || label.length > 63)) {
    throw new Error("FOFA target must be a domain or an IP address");
  }
  return { host, wildcard, kind: "domain" };
}

export function normalizeFofaTarget(raw: string): string {
  return parseFofaTarget(raw).host;
}



/**
 * One query per strategy. `domain=` covers the registered domain, `host=` catches hosts the
 * domain index misses, `cert=` pulls infrastructure that only shows up in the certificate SANs.
 * Every anchor stays on the authorised target, and a user query is always AND-ed with them.
 */
export function buildFofaQueries(target: string, raw?: string, strategies?: string[]): FofaQueryPlan[] {
  const parsed = parseFofaTarget(target);
  const query = String(raw || "").trim();
  if (query.length > 1000) throw new Error("FOFA query is too long (max 1000 characters)");
  if (parsed.kind === "ip") {
    const only = `ip="${parsed.host}"`;
    return [{ strategy: "ip", query: !query || query.includes(parsed.host) ? query || only : `(${query}) && ${only}` }];
  }
  const picked = (strategies?.length ? strategies : [...STRATEGIES])
    .map((item) => String(item).trim().toLowerCase())
    .filter((item, index, list) => item && list.indexOf(item) === index);
  if (!picked.length) throw new Error("FOFA strategies must be domain, host or cert");
  const invalid = picked.find((item) => !(STRATEGIES as readonly string[]).includes(item));
  if (invalid) throw new Error(`FOFA strategies must be domain, host or cert, got: ${invalid}`);
  const anchors = picked.map((item) => `${item}="${parsed.host}"`);
  if (!query) return picked.map((item, index) => ({ strategy: item as FofaStrategy, query: anchors[index]! }));
  if (query.includes(parsed.host)) return [{ strategy: "custom", query }];
  const scoped = anchors.length === 1 ? anchors[0]! : `(${anchors.join(" || ")})`;
  return [{ strategy: "custom", query: `(${query}) && ${scoped}` }];
}

/** Single-anchor helper kept for callers that only want the registered-domain query. */
export function buildFofaQuery(target: string, raw?: string): string {
  return buildFofaQueries(target, raw, ["domain"])[0]!.query;
}

function encodeQuery(query: string): string {
  return Buffer.from(query, "utf8").toString("base64");
}

const REQUEST_TIMEOUT_MS = 45_000;

/** A bare "fetch failed" hides the real reason; surface the undici/socket cause chain instead. */
function describeError(error: unknown): string {
  const parts: string[] = [];
  let current: unknown = error;
  for (let depth = 0; current && depth < 4; depth++) {
    const record = current as { code?: unknown; message?: unknown; cause?: unknown };
    const piece = `${record.code ? String(record.code) : ""} ${record.message ? String(record.message) : ""}`.trim();
    if (piece && !parts.includes(piece)) parts.push(piece);
    current = record.cause;
  }
  return parts.join(" <- ") || String(error);
}

/** Transport failures are worth one retry; protocol and API errors are not. */
function retryable(error: unknown): boolean {
  return /ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EPIPE|UND_ERR|fetch failed|aborted|timeout/i.test(describeError(error));
}

/**
 * FOFA is reached with node:http(s) instead of the global fetch. Undici gives up on a connection
 * after 10s and inherits the container proxy env, which is exactly how a working FOFA account ends
 * up reporting "fetch failed". Here the socket gets a 45s budget, the proxy is opt-in (FOFA_PROXY)
 * and the error keeps the socket code so the desk can show why it failed.
 */
function fetchText(url: string, proxy: string): Promise<{ status: number; text: string }> {
  const target = new URL(url);
  const secure = target.protocol === "https:";
  const port = target.port ? Number(target.port) : secure ? 443 : 80;
  const path = `${target.pathname}${target.search}`;
  const headers = { "User-Agent": "nianyun-fofa/1", Accept: "application/json", Connection: "close" };

  const connect = (socket?: Socket) => secure
    ? https.request({
        host: target.hostname, port, path, headers, method: "GET",
        servername: target.hostname,
        ...(socket ? { createConnection: () => tls.connect({ socket, servername: target.hostname }) } : {}),
      })
    : http.request({ host: target.hostname, port, path, headers, method: "GET", ...(socket ? { createConnection: () => socket } : {}) });

  const collect = (socket?: Socket): Promise<{ status: number; text: string }> => new Promise((resolve, reject) => {
    const request = connect(socket);
    request.setTimeout(REQUEST_TIMEOUT_MS, () => request.destroy(new Error(`timeout after ${REQUEST_TIMEOUT_MS}ms`)));
    request.on("response", (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { text += chunk; });
      response.on("end", () => resolve({ status: response.statusCode || 0, text }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end();
  });

  if (!proxy) return collect();

  return new Promise((resolve, reject) => {
    const forward = new URL(proxy);
    const tunnel = http.request({
      host: forward.hostname,
      port: forward.port ? Number(forward.port) : 80,
      method: "CONNECT",
      path: `${target.hostname}:${port}`,
      timeout: REQUEST_TIMEOUT_MS,
      ...(forward.username
        ? { headers: { "Proxy-Authorization": `Basic ${Buffer.from(`${decodeURIComponent(forward.username)}:${decodeURIComponent(forward.password)}`).toString("base64")}` } }
        : {}),
    });
    tunnel.on("connect", (response, socket) => {
      if (response.statusCode !== 200) { socket.destroy(); reject(new Error(`proxy CONNECT ${response.statusCode}`)); return; }
      collect(socket).then(resolve, reject);
    });
    tunnel.on("timeout", () => tunnel.destroy(new Error(`proxy timeout after ${REQUEST_TIMEOUT_MS}ms`)));
    tunnel.on("error", reject);
    tunnel.end();
  });
}

/** Swappable socket transport; tests replace it instead of dialling fofa.info. */
export const fofaTransport: { send: (url: string, proxy: string) => Promise<{ status: number; text: string }> } = { send: fetchText };

async function send(cfg: FofaConfig, url: string): Promise<Record<string, unknown>> {
  const { status, text } = await fofaTransport.send(url, cfg.proxy);
  let payload: unknown;
  try { payload = JSON.parse(text); } catch { throw new Error(`FOFA returned a non-JSON response (HTTP ${status})`); }
  if (status >= 400 && (!payload || typeof payload !== "object")) throw new Error(`FOFA HTTP ${status}`);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("FOFA returned an invalid response");
  const record = payload as Record<string, unknown>;
  if (record.error === true || record.error === "true") throw new Error(String(record.errmsg || record.message || "FOFA request failed"));
  return record;
}

async function request(cfg: FofaConfig, path: string, params: Record<string, string>): Promise<Record<string, unknown>> {
  const search = new URLSearchParams({ ...params, key: cfg.key });
  const url = `${cfg.baseUrl}${path}?${search.toString()}`;
  let lastError: unknown;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try { return await send(cfg, url); }
    catch (error) {
      lastError = error;
      if (attempt >= 2 || !retryable(error)) break;
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
  }
  throw new Error(`FOFA 请求失败（${cfg.baseUrl}）：${describeError(lastError)}`);
}

export async function checkFofa(values: Record<string, string>): Promise<Record<string, unknown>> {
  const cfg = config(values);
  if (!cfg.key) throw new Error("请先在设置中保存 FOFA AppKey");
  const payload = await request(cfg, "/api/v1/info/my", {});
  return {
    ok: true,
    base_url: cfg.baseUrl,
    email: String(payload.email || ""),
    isv: Boolean(payload.isv),
    vip_level: Number(payload.vip_level || 0),
    points: Number(payload.fofa_point || 0),
    remain_query: Number(payload.remain_api_query ?? payload.remain_free_api_query ?? 0),
  };
}

function rows(payload: Record<string, unknown>): unknown[][] {
  return (Array.isArray(payload.results) ? payload.results : []).filter((row): row is unknown[] => Array.isArray(row));
}

function cell(row: unknown[], index: number): string {
  return String(row[index] ?? "").trim();
}

type Built = { url: string; evidence: Record<string, unknown> };

/** FOFA returns `host` as an absolute URL when it can, otherwise the raw endpoint fields. */
export function fofaRowToUrl(row: unknown[], fields: string[]): Built | null {
  const at = (name: string): string => {
    const index = fields.indexOf(name);
    return index < 0 ? "" : cell(row, index);
  };
  const host = at("host");
  const ip = at("ip");
  const port = at("port");
  const protocol = (at("protocol") || "http").toLowerCase().replace(/:$/, "");
  const domain = at("domain");
  const evidence = {
    ...(ip ? { ip } : {}),
    ...(port ? { port: Number(port) || undefined } : {}),
    ...(protocol ? { protocol } : {}),
    ...(domain ? { domain } : {}),
    ...(at("title") ? { title: at("title").slice(0, 300) } : {}),
    ...(at("server") ? { server: at("server").slice(0, 200) } : {}),
  };
  if (/^https?:\/\//i.test(host)) return { url: host, evidence };
  const endpoint = domain || ip || host;
  if (!endpoint) return null;
  const scheme = protocol === "https" || protocol === "wss" ? "https" : protocol === "ftp" ? "ftp" : "http";
  if (scheme === "ftp") return null;
  return { url: `${scheme}://${endpoint}${port ? `:${port}` : ""}`, evidence };
}

/**
 * `domain=` queries are already anchored on the target namespace. `host=` and `cert=` are substring
 * matches, so their rows are only kept when the host — or the recorded domain of an IP row — sits
 * inside the namespace. `scope: "any"` keeps everything the account returned.
 */
function inScope(item: Built & { strategy: FofaQueryStrategy }, parsed: FofaTarget, scope: "suffix" | "any"): boolean {
  if (scope === "any" || parsed.kind === "ip") return true;
  if (item.strategy !== "host" && item.strategy !== "cert") return true;
  let host = "";
  try { host = new URL(item.url).hostname.toLowerCase(); } catch { return false; }
  const domain = String(item.evidence.domain || "").toLowerCase();
  const inside = (value: string): boolean => Boolean(value) && (value === parsed.host || value.endsWith(`.${parsed.host}`));
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return !domain || inside(domain);
  return inside(host);
}

export type FofaDiscoverOptions = {
  values: Record<string, string>;
  db: Database;
  projectId: string;
  target: string;
  query?: string;
  size?: number;
  strategies?: string[];
  scope?: "suffix" | "any";
};

export async function discoverFofa(options: FofaDiscoverOptions): Promise<Record<string, unknown>> {
  const cfg = config(options.values);
  if (!cfg.key) throw new Error("FOFA 尚未配置，请在设置中保存 AppKey");
  const parsed = parseFofaTarget(options.target);
  const plans = buildFofaQueries(parsed.host, options.query, options.strategies);
  const budget = Math.min(MAX_PAGE * MAX_PAGES, Math.max(1, Number(options.size) || DEFAULT_PER_STRATEGY * plans.length));
  const perPlan = Math.max(1, Math.ceil(budget / plans.length));
  const scope = options.scope === "any" ? "any" : "suffix";
  const fields = FIELDS.split(",");

  const built: Array<Built & { strategy: FofaQueryStrategy }> = [];
  const seen = new Set<string>();
  const queries: Array<{ strategy: FofaQueryStrategy; query: string; pages: number; hits: number }> = [];
  let quota: number | undefined;

  for (const plan of plans) {
    let collected = 0;
    let hits = 0;
    let pages = 0;
    for (let page = 1; collected < perPlan && page <= MAX_PAGES; page++) {
      const payload = await request(cfg, "/api/v1/search/all", {
        qbase64: encodeQuery(plan.query),
        fields: FIELDS,
        size: String(Math.min(MAX_PAGE, Math.max(1, perPlan - collected))),
        page: String(page),
      });
      pages++;
      if (payload.remain_api_query !== undefined) quota = Number(payload.remain_api_query);
      const batch = rows(payload);
      collected += batch.length;
      for (const row of batch) {
        const rowBuilt = fofaRowToUrl(row, fields);
        if (!rowBuilt) continue;
        const key = rowBuilt.url.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        built.push({ ...rowBuilt, strategy: plan.strategy });
        hits++;
      }
      if (!batch.length) break;
      if (payload.size !== undefined && collected >= Number(payload.size)) break;
    }
    queries.push({ strategy: plan.strategy, query: plan.query, pages, hits });
  }

  const scoped = built.filter((item) => inScope(item, parsed, scope));
  const inputs: unknown[] = scoped.map((item) => ({
    value: item.url,
    kind: "url",
    source: "fofa",
    tags: ["fofa", "search-engine", `fofa-${item.strategy}`],
    evidence: { strategy: item.strategy, target: parsed.host, wildcard: parsed.wildcard, ...item.evidence },
  }));

  const result = { accepted: [] as Record<string, unknown>[], rejected: [] as unknown[] };
  for (let offset = 0; offset < inputs.length; offset += 5000) {
    const batch = importAssetCandidates(options.db, options.projectId, inputs.slice(offset, offset + 5000));
    result.accepted.push(...batch.accepted);
    result.rejected.push(...batch.rejected);
  }
  const unique = [...new Map(result.accepted.map((row) => [String(row.id), row])).values()];
  return {
    ok: true, source: "fofa", target: parsed.host, wildcard: parsed.wildcard, scope,
    query: plans.length === 1 ? plans[0]!.query : plans.map((plan) => plan.query).join(" | "),
    queries, strategies: plans.map((plan) => plan.strategy),
    size: budget, pages: queries.reduce((sum, item) => sum + item.pages, 0), fields,
    discovered: built.length, filtered: built.length - scoped.length,
    ...(quota === undefined ? {} : { remain_query: quota }),
    accepted: unique.length, rejected: result.rejected.length,
    candidates: unique,
  };
}
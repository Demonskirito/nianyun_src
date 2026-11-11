import type { Database } from "../shared/db.js";
import { importAssetCandidates } from "./candidates.js";

type ArlConfig = { baseUrl: string; token: string };

/** ARL brute dictionaries, from the smallest built-in list to the biggest. */
const BRUTE_TYPES = ["test", "small", "big"] as const;
export type ArlBruteType = (typeof BRUTE_TYPES)[number];

export type ArlTargetRef = { host: string; wildcard: boolean };

export type ArlScanOptions = {
  domain_brute: boolean;
  domain_brute_type: ArlBruteType;
  alt_dns: boolean;
  ssl_cert: boolean;
  dns_query_plugin: boolean;
  site_identify: boolean;
  skip_scan_cdn_ip: boolean;
  port_scan: boolean;
  service_detection: boolean;
  os_detection: boolean;
  search_engines: boolean;
  site_spider: boolean;
  file_leak: boolean;
  nuclei_scan: boolean;
};

/**
 * The default profile covers the whole *.target tree: DNS dataset lookup, certificate transparency
 * and DNS plugin queries plus site identification. The `small` dictionary keeps the first pass
 * usable within minutes; `big` is opt-in from the console. Port/service/nuclei scanning stays off so
 * discovery never turns into a scan of someone's stack.
 */
const DEFAULT_SCAN: ArlScanOptions = {
  domain_brute: true,
  domain_brute_type: "small",
  alt_dns: true,
  ssl_cert: true,
  dns_query_plugin: true,
  site_identify: true,
  skip_scan_cdn_ip: false,
  port_scan: false,
  service_detection: false,
  os_detection: false,
  search_engines: false,
  site_spider: false,
  file_leak: false,
  nuclei_scan: false,
};

function value(...items: unknown[]): string {
  return items.map((item) => String(item ?? "").trim()).find(Boolean) || "";
}

function config(values: Record<string, string>): ArlConfig {
  return {
    baseUrl: (value(values.ARL_URL, values.ARL_BASE_URL) || "https://127.0.0.1:5003").replace(/\/$/, ""),
    token: value(values.ARL_TOKEN, values.ARL_API_KEY),
  };
}

/** Accepts `*.qwen.ai`, `.qwen.ai`, `qwen.ai` and `https://*.qwen.ai/`, and yields the wildcard base. */
export function parseArlTarget(raw: string): ArlTargetRef {
  let text = String(raw ?? "").trim();
  if (!text) throw new Error("ARL target must be a domain name");
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const wildcard = /^(\*\.|\.)/.test(text);
  const host = text
    .replace(/^(\*\.|\.)/, "")
    .replace(/\/+$/, "")
    .replace(/\.+$/, "")
    .toLowerCase();
  if (!host || host.includes("/") || host.includes(":") || host.includes("*")) throw new Error("ARL target must be a domain name");
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label) || label.length > 63)) {
    throw new Error("ARL target must be a domain name");
  }
  return { host, wildcard };
}

/** Splits a comma/space/semicolon/newline separated target list. */
export function splitTargets(raw: string | string[] | undefined): string[] {
  const list = Array.isArray(raw) ? raw : [raw ?? ""];
  return list
    .flatMap((item) => String(item ?? "").split(/[\s,;，；]+/))
    .map((item) => item.trim())
    .filter(Boolean);
}

function resolveTargets(input: { target?: string; targets?: string[] }): ArlTargetRef[] {
  const refs = new Map<string, ArlTargetRef>();
  for (const raw of splitTargets([...(input.targets || []), input.target || ""])) {
    const ref = parseArlTarget(raw);
    const previous = refs.get(ref.host);
    refs.set(ref.host, { host: ref.host, wildcard: ref.wildcard || Boolean(previous?.wildcard) });
  }
  return [...refs.values()];
}

function resolveScan(brute?: string, overrides?: Record<string, unknown>): ArlScanOptions {
  const wanted = String(brute ?? "").trim().toLowerCase();
  const scan: ArlScanOptions = {
    ...DEFAULT_SCAN,
    ...(BRUTE_TYPES.includes(wanted as ArlBruteType) ? { domain_brute_type: wanted as ArlBruteType } : {}),
  };
  for (const key of Object.keys(DEFAULT_SCAN) as Array<keyof ArlScanOptions>) {
    const raw = overrides?.[key];
    if (raw === undefined) continue;
    if (key === "domain_brute_type") {
      const type = String(raw).trim().toLowerCase();
      if (BRUTE_TYPES.includes(type as ArlBruteType)) scan.domain_brute_type = type as ArlBruteType;
      continue;
    }
    (scan as unknown as Record<string, unknown>)[key] = raw === true || raw === "true";
  }
  return scan;
}

function url(config: ArlConfig, path: string): string {
  return `${config.baseUrl}/api/${path.replace(/^\//, "")}`;
}

async function request(config: ArlConfig, path: string, init: RequestInit = {}): Promise<Record<string, unknown>> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  headers.set("Token", config.token);
  const response = await fetch(url(config, path), { ...init, headers, signal: AbortSignal.timeout(20_000) });
  const payload = await response.json().catch(() => ({})) as unknown;
  if (!response.ok) throw new Error(`ARL HTTP ${response.status}`);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("ARL returned an invalid response");
  const record = payload as Record<string, unknown>;
  if (record.code !== undefined && Number(record.code) !== 200) throw new Error(String(record.message || record.error || "ARL request failed"));
  return record;
}

export async function checkArl(values: Record<string, string>): Promise<Record<string, unknown>> {
  const cfg = config(values);
  if (!cfg.token) throw new Error("请先在设置中保存 ARL Token");
  const payload = await request(cfg, "task/?page=1&size=1");
  return { ok: true, base_url: cfg.baseUrl, total_tasks: Number(payload.total || 0) };
}

async function allRows(cfg: ArlConfig, path: string): Promise<Record<string, unknown>[]> {
  const result: Record<string, unknown>[] = [];
  for (let page = 1; page <= 1000; page++) {
    const payload = await request(cfg, `${path}&page=${page}&size=500&order=_id`);
    const batch = rows(payload);
    result.push(...batch);
    if (!batch.length || (payload.total !== undefined ? result.length >= Number(payload.total) : batch.length < 500)) return result;
  }
  throw new Error("ARL 结果超过分页上限，请缩小任务后重试");
}

function taskIds(payload: Record<string, unknown>): string[] {
  const items = Array.isArray(payload.items) ? payload.items : [];
  return items.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const rec = item as Record<string, unknown>;
    const id = rec.task_id || rec._id || rec.id;
    return id ? [String(id)] : [];
  });
}

function rows(payload: Record<string, unknown>): Record<string, unknown>[] {
  return (Array.isArray(payload.items) ? payload.items : []).filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object" && !Array.isArray(item)));
}

function candidateValues(row: Record<string, unknown>): string[] {
  return [row.domain, row.host, row.hostname, row.url, row.site, row.target].map((item) => String(item ?? "").trim()).filter(Boolean);
}

function toUrl(raw: string): string | null {
  if (/^https?:\/\//i.test(raw)) return raw;
  if (/^[a-z0-9.-]+(?::\d+)?$/i.test(raw)) return `http://${raw}`;
  return null;
}

/** An ARL `ip/` row carries the IP, the port and — when the host resolved — the domain it answered for. */
function ipCandidateValues(row: Record<string, unknown>): string[] {
  const ip = String(row.ip || row.host || "").trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return [];
  const port = Number(row.port || 0);
  const domain = String(row.domain || "").trim();
  const host = domain || ip;
  const suffix = port && port !== 80 ? `:${port}` : "";
  return [`http://${host}${suffix}`];
}

export type ArlDiscoverOptions = {
  values: Record<string, string>;
  db: Database;
  projectId: string;
  target?: string;
  targets?: string[];
  taskIds?: string[];
  wait?: boolean;
  brute?: string;
  scan?: Record<string, unknown>;
  includeIps?: boolean;
};

export async function discoverArl(options: ArlDiscoverOptions): Promise<Record<string, unknown>> {
  const cfg = config(options.values);
  if (!cfg.token) throw new Error("ARL 尚未配置，请在设置中保存 ARL 地址和 Token");
  const refs = resolveTargets(options);
  if (!refs.length) throw new Error("ARL discovery requires a target domain");
  const targets = refs.map((ref) => ref.host);
  const wildcard = refs.some((ref) => ref.wildcard);
  const scan = resolveScan(options.brute, options.scan);
  const includeIps = options.includeIps === true;

  let ids = [...new Set((options.taskIds || []).map(String).filter(Boolean))];
  if (!ids.length) {
    const created = await Promise.all(refs.map(async (ref) => request(cfg, "task/", {
      method: "POST",
      body: JSON.stringify({
        name: `Nianyun SRC ${ref.host}${ref.wildcard ? " (*)" : ""}`,
        target: ref.host,
        ...scan,
      }),
    })));
    ids = created.flatMap(taskIds);
  }
  if (!ids.length) throw new Error("ARL did not return a task id");

  const summary = { ...scan, ip_collect: includeIps, targets };
  if (options.wait !== true) return { ok: true, source: "arl", task_ids: ids, targets, target: targets[0], wildcard, scan: summary, status: "submitted" };

  const imported: unknown[] = [];
  const tasks: Record<string, unknown>[] = [];
  const ipErrors: string[] = [];
  for (const taskId of ids) {
    const [domains, sites, task] = await Promise.all([
      allRows(cfg, `domain/?task_id=${encodeURIComponent(taskId)}`),
      allRows(cfg, `site/?task_id=${encodeURIComponent(taskId)}`),
      request(cfg, `task/?_id=${encodeURIComponent(taskId)}&size=1`),
    ]);
    // Older ARL builds expose no `/api/ip/` endpoint: a missing collector must not lose the domains and sites.
    let ips: Record<string, unknown>[] = [];
    if (includeIps) {
      try { ips = await allRows(cfg, `ip/?task_id=${encodeURIComponent(taskId)}`); }
      catch (error) { ipErrors.push(String(error instanceof Error ? error.message : error)); }
    }
    const taskRow = rows(task)[0] || {};
    tasks.push(...rows(task));
    const taskTarget = String(taskRow.target || taskRow.domain || "");
    for (const row of [...domains, ...sites]) {
      for (const raw of [...candidateValues(row), ...ipCandidateValues(row)]) {
        const target = toUrl(raw);
        if (target) imported.push({ value: target, kind: "url", source: "arl", tags: ["arl", "subdomain-discovery"], evidence: { task_id: taskId, target: taskTarget, raw: row } });
      }
    }
    for (const row of ips) {
      for (const raw of ipCandidateValues(row)) {
        const target = toUrl(raw);
        if (target) imported.push({ value: target, kind: "url", source: "arl", tags: ["arl", "ip-asset"], evidence: { task_id: taskId, target: taskTarget, raw: row } });
      }
    }
  }
  const result = { accepted: [] as Record<string, unknown>[], rejected: [] as unknown[] };
  for (let offset = 0; offset < imported.length; offset += 5000) {
    const batch = importAssetCandidates(options.db, options.projectId, imported.slice(offset, offset + 5000));
    result.accepted.push(...batch.accepted);
    result.rejected.push(...batch.rejected);
  }
  result.accepted = [...new Map(result.accepted.map((row) => [String(row.id), row])).values()];
  // ARL runs its pipeline asynchronously: a collection while `domain_brute`/`site_identify` is still
  // running legitimately yields nothing. Report the phase so the desk can say "come back later".
  const pendingStatus = [...new Set(
    tasks.map((task) => String(task.status || "")).filter((status) => status && status !== "done" && status !== "stop"),
  )];
  return {
    ok: true, source: "arl", task_ids: ids, tasks: tasks.map((task) => ({ id: task._id, status: task.status, statistic: task.statistic })),
    targets, target: targets[0], wildcard, scan: summary,
    pending: pendingStatus.length > 0,
    ...(pendingStatus.length ? { pending_status: pendingStatus } : {}),
    ...(ipErrors.length ? { ip_errors: ipErrors.slice(0, 5) } : {}),
    discovered: imported.length, accepted: result.accepted.length, rejected: result.rejected.length, candidates: result.accepted,
  };
}
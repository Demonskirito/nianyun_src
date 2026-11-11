export type AssetAutomation = {
  enabled: boolean;
  interval_sec: number;
  seeds: Array<{ value: string; source?: string }>;
  discover: boolean;
  validate: boolean;
  score: boolean;
  last_run_at?: number;
  last_status?: string;
  last_error?: string;
};

function seed(value: unknown): { value: string; source?: string } {
  const raw = typeof value === "string" ? { value } : value;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("automation seed must be a string or object");
  const rec = raw as Record<string, unknown>;
  const url = String(rec.value ?? "").trim();
  let parsed: URL;
  try { parsed = new URL(url); } catch { throw new Error(`invalid automation seed: ${url}`); }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("automation seeds must use HTTP(S)");
  return { value: parsed.toString(), ...(rec.source ? { source: String(rec.source).slice(0, 120) } : {}) };
}

export function normalizeAutomation(raw: unknown): AssetAutomation {
  const rec = raw && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : {};
  const interval = Number(rec.interval_sec ?? 3600);
  if (!Number.isInteger(interval) || interval < 300 || interval > 86400) throw new Error("automation interval_sec must be between 300 and 86400");
  const seeds = (Array.isArray(rec.seeds) ? rec.seeds : []).map(seed).slice(0, 100);
  const enabled = Boolean(rec.enabled);
  if (enabled && !seeds.length) throw new Error("enabled automation requires at least one HTTP seed");
  return {
    enabled,
    interval_sec: interval,
    seeds,
    discover: rec.discover === undefined ? true : Boolean(rec.discover),
    validate: rec.validate === undefined ? true : Boolean(rec.validate),
    score: rec.score === undefined ? true : Boolean(rec.score),
    ...(Number.isFinite(Number(rec.last_run_at)) ? { last_run_at: Number(rec.last_run_at) } : {}),
    ...(rec.last_status ? { last_status: String(rec.last_status).slice(0, 40) } : {}),
    ...(rec.last_error ? { last_error: String(rec.last_error).slice(0, 500) } : {}),
  };
}

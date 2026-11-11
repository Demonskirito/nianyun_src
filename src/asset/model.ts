import { isIP } from "node:net";

export type AssetKind = "domain" | "ip" | "url" | "service";

export type AssetInput = {
  kind?: AssetKind;
  value: string;
  port?: number;
  protocol?: string;
  title?: string;
  technologies?: string[];
  source?: string;
  evidence?: Record<string, unknown>;
};

export type NormalizedAsset = {
  kind: AssetKind;
  value: string;
  hostname: string | null;
  port: number | null;
  protocol: string | null;
  url: string | null;
  title: string | null;
  technologies: string[];
  source: string;
  evidence: Record<string, unknown>;
};

function clean(value: unknown): string {
  return String(value ?? "").trim();
}

function validHostname(value: string): boolean {
  return value.length <= 253 && value.split(".").every((label) =>
    label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label),
  );
}

function port(value: unknown): number | null {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error("asset port must be 1-65535");
  return n;
}

function normalizeHost(value: string): string {
  const host = value.toLowerCase().replace(/\.$/, "");
  if (!isIP(host) && !validHostname(host)) throw new Error(`invalid asset host: ${value}`);
  return host;
}

function normalizeUrl(value: string): { url: string; host: string; port: number | null; protocol: string } {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error(`invalid asset URL: ${value}`); }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error(`unsupported asset URL: ${value}`);
  if (parsed.username || parsed.password || parsed.hash) throw new Error("asset URL must not contain credentials or fragments");
  const host = normalizeHost(parsed.hostname);
  const explicitPort = parsed.port ? Number(parsed.port) : null;
  parsed.hostname = host;
  parsed.hash = "";
  return { url: parsed.toString(), host, port: explicitPort, protocol: parsed.protocol.slice(0, -1) };
}

export function normalizeAsset(input: AssetInput): NormalizedAsset {
  const raw = clean(input.value);
  if (!raw) throw new Error("asset value is required");
  const source = clean(input.source) || "unknown";
  const technologyValues = Array.isArray(input.technologies) ? input.technologies : [];
  const technologies = [...new Set(technologyValues.map(clean).filter(Boolean))].slice(0, 64);
  const evidence = input.evidence && typeof input.evidence === "object" && !Array.isArray(input.evidence) ? input.evidence : {};
  if (/^https?:\/\//i.test(raw) || input.kind === "url") {
    const parsed = normalizeUrl(raw);
    return {
      kind: "url",
      value: parsed.url,
      hostname: parsed.host,
      port: port(input.port) ?? parsed.port,
      protocol: clean(input.protocol) || parsed.protocol,
      url: parsed.url,
      title: clean(input.title) || null,
      technologies,
      source,
      evidence,
    };
  }
  const kind = input.kind || (isIP(raw) ? "ip" : "domain");
  if (kind !== "domain" && kind !== "ip" && kind !== "service") throw new Error(`unsupported asset kind: ${kind}`);
  const host = normalizeHost(raw);
  if (kind === "ip" && !isIP(host)) throw new Error(`asset is not an IP: ${raw}`);
  if (kind === "domain" && isIP(host)) throw new Error(`asset is not a domain: ${raw}`);
  return {
    kind,
    value: host,
    hostname: host,
    port: port(input.port),
    protocol: clean(input.protocol) || null,
    url: null,
    title: clean(input.title) || null,
    technologies,
    source,
    evidence,
  };
}

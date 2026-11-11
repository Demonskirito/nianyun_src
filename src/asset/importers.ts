import type { CandidateInput } from "./candidates.js";

function cell(value: unknown): string {
  return String(value ?? "").trim();
}

function list(value: unknown): string[] | undefined {
  if (Array.isArray(value)) return value.map(cell).filter(Boolean);
  const text = cell(value);
  return text ? text.split(/[|,;]/).map((item) => item.trim()).filter(Boolean) : undefined;
}

function rowToCandidate(row: Record<string, unknown>, source: string): CandidateInput {
  const get = (...names: string[]): unknown => names.map((name) => row[name] ?? row[name.toLowerCase()]).find((value) => value !== undefined);
  const value = cell(get("value", "url", "host", "hostname", "domain", "subdomain", "name", "asset", "ip", "link"));
  if (!value) throw new Error("import row has no URL, host, domain, or IP");
  const rowSource = cell(get("source", "来源")) || source;
  const technologies = list(get("technologies", "technology", "tech", "server", "product"));
  const tags = list(get("tags", "tag", "labels"));
  const protocol = cell(get("protocol", "scheme")) || undefined;
  const port = cell(get("port"));
  return {
    value,
    source: rowSource,
    ...(port ? { port: Number(port) } : {}),
    ...(protocol ? { protocol } : {}),
    ...(cell(get("kind", "type", "asset_type")) ? { kind: cell(get("kind", "type", "asset_type")) as CandidateInput["kind"] } : {}),
    ...(cell(get("title", "name")) ? { title: cell(get("title", "name")) } : {}),
    ...(technologies ? { technologies } : {}),
    ...(tags ? { tags } : {}),
    evidence: { imported_row: row },
  };
}

function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === '"') {
      if (quoted && text[i + 1] === '"') { value += '"'; i += 1; }
      else quoted = !quoted;
    } else if (char === "," && !quoted) { row.push(value.trim()); value = ""; }
    else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && text[i + 1] === "\n") i += 1;
      row.push(value.trim()); value = "";
      if (row.some(Boolean)) rows.push(row);
      row = [];
    } else value += char;
  }
  row.push(value.trim());
  if (row.some(Boolean)) rows.push(row);
  const headers = (rows.shift() || []).map((header, index) => header || `column_${index + 1}`);
  return rows.map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] || ""])));
}

function objectRows(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    for (const key of ["results", "data", "items", "rows", "assets", "candidates"]) {
      if (Array.isArray(record[key])) return record[key] as unknown[];
    }
    return [record];
  }
  throw new Error("import content must be an array, object, JSONL, or CSV");
}

export function parseCandidateImport(raw: unknown, format = "auto", source = "import"): CandidateInput[] {
  if (Array.isArray(raw)) return raw.map((row) => rowToCandidate(row as Record<string, unknown>, source));
  if (raw && typeof raw === "object") return objectRows(raw).map((row) => rowToCandidate(row as Record<string, unknown>, source));
  const text = cell(raw);
  if (!text) throw new Error("import content is empty");
  const selected = format.toLowerCase();
  if (selected === "csv") {
    return parseCsv(text).map((row) => rowToCandidate(row, source));
  }
  if (selected === "jsonl") {
    return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>)
      .map((row) => rowToCandidate(row, source));
  }
  if (selected === "json") return objectRows(JSON.parse(text)).map((row) => rowToCandidate(row as Record<string, unknown>, source));
  try {
    return objectRows(JSON.parse(text)).map((row) => rowToCandidate(row as Record<string, unknown>, source));
  } catch (error) {
    if (!text.includes("\n")) throw error;
    return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>)
      .map((row) => rowToCandidate(row, source));
  }
}

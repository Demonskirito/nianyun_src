export type EvidenceQuery = { evidence_id?: string; task_id?: string; url?: string };
export function queryEvidence(evidence: Record<string, unknown>[], queries: EvidenceQuery[]): Record<string, unknown>[] {
  return evidence.filter(e => queries.some(q => {
    const data = (e.data || {}) as Record<string, unknown>;
    const urls = [data.url, data.final_url, data.target, ...(Array.isArray(data.urls) ? data.urls : [])];
    return (!q.evidence_id || e.id === q.evidence_id) && (!q.task_id || data.task_id === q.task_id) && (!q.url || urls.includes(q.url));
  })).slice(0, 100);
}
export function evidenceUrls(e: Record<string, unknown>): string[] {
  const data = (e.data || {}) as Record<string, unknown>;
  return [...new Set([data.url, data.final_url, data.target, ...(Array.isArray(data.urls) ? data.urls : [])]
    .filter((v): v is string => typeof v === "string" && /^https?:\/\//i.test(v)))];
}

/**
 * Tool health is derived from the evidence ledger, never from in-memory counters: the same
 * numbers survive a restart and can be filtered by project or time window.
 *
 * Classification of a single row:
 *   rejected   → the executor refused before touching the network (not a health signal)
 *   timed_out  → the deadline hit (latency signal, never counted as success)
 *   tool-result with ok!==false → success
 *   anything else with kind tool-error → failure
 */

export type ToolStatus = {
  id: string;
  name: string;
  purpose: string;
  family: string;
  agent: string;
  built_in: boolean;
  risk?: string;
  configured: boolean;
  status: string;
};

export type ToolOutcomeRow = {
  id?: string;
  project_id?: string;
  session_id?: string;
  kind?: string;
  source?: string;
  summary?: string;
  data?: Record<string, unknown>;
  created_at?: number;
};

export type ToolHealthState = "failing" | "degraded" | "unconfigured" | "healthy" | "idle";

export type ToolHealthRow = {
  tool: string;
  name: string;
  family: string;
  risk: string;
  configured: boolean;
  state: ToolHealthState;
  executions: number;
  successes: number;
  failures: number;
  timeouts: number;
  rejections: number;
  success_rate: number;
  avg_ms: number;
  p95_ms: number;
  last_used_at: number | null;
  last_error: string | null;
  sessions: number;
};

export type ToolHealthTotals = {
  tools: number;
  used: number;
  executions: number;
  successes: number;
  failures: number;
  timeouts: number;
  rejections: number;
  success_rate: number;
  avg_ms: number;
  sessions: number;
  projects: number;
};

const STATE_RANK: Record<ToolHealthState, number> = { failing: 0, degraded: 1, unconfigured: 2, healthy: 3, idle: 4 };

function percentile(sorted: number[], ratio: number): number {
  if (!sorted.length) return 0;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(ratio * sorted.length) - 1));
  return sorted[index]!;
}

const round = (value: number, digits = 0) => {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
};

export function computeToolHealth(rows: ToolOutcomeRow[], statuses: ToolStatus[] = []): { totals: ToolHealthTotals; tools: ToolHealthRow[] } {
  const stats = new Map<string, {
    successes: number; failures: number; timeouts: number; rejections: number;
    durations: number[]; last_used_at: number; last_error: string | null; sessions: Set<string>; projects: Set<string>;
  }>();
  const allDurations: number[] = [];
  const allSessions = new Set<string>();
  const allProjects = new Set<string>();

  for (const row of rows) {
    const tool = String(row.source || "").trim();
    if (!tool) continue;
    const data = row.data && typeof row.data === "object" ? row.data : {};
    const record = stats.get(tool) || { successes: 0, failures: 0, timeouts: 0, rejections: 0, durations: [], last_used_at: 0, last_error: null, sessions: new Set<string>(), projects: new Set<string>() };
    stats.set(tool, record);
    const at = Number(row.created_at || 0);
    const duration = Number(data.duration_ms);
    const ok = row.kind === "tool-result" && data.ok !== false;
    const rejected = data.rejected === true;
    const timedOut = data.timed_out === true;
    if (rejected) record.rejections += 1;
    else if (timedOut) record.timeouts += 1;
    else if (ok) record.successes += 1;
    else record.failures += 1;
    if (Number.isFinite(duration) && duration > 0) {
      record.durations.push(duration);
      allDurations.push(duration);
    }
    if (at > record.last_used_at) record.last_used_at = at;
    if (!ok && at >= record.last_used_at) record.last_error = String(row.summary || "").slice(0, 300) || null;
    const session = String(row.session_id || "");
    const project = String(row.project_id || "");
    if (session) { record.sessions.add(session); allSessions.add(session); }
    if (project) { record.projects.add(project); allProjects.add(project); }
  }

  const byStatus = new Map(statuses.map((status) => [status.id, status]));
  const toolIds = new Set<string>([...stats.keys(), ...statuses.map((status) => status.id)]);
  const tools: ToolHealthRow[] = [];
  for (const tool of toolIds) {
    const record = stats.get(tool);
    const meta = byStatus.get(tool);
    const executions = record ? record.successes + record.failures + record.timeouts : 0;
    const durations = (record?.durations || []).slice().sort((a, b) => a - b);
    const successRate = executions ? round((record!.successes / executions) * 100, 1) : 0;
    const configured = meta ? meta.configured : true;
    const state: ToolHealthState = executions > 0
      ? (executions >= 2 && successRate < 50 ? "failing" : successRate < 80 ? "degraded" : "healthy")
      : configured ? "idle" : "unconfigured";
    tools.push({
      tool,
      name: meta?.name || tool,
      family: meta?.family || "unknown",
      risk: meta?.risk || "low",
      configured,
      state,
      executions,
      successes: record?.successes || 0,
      failures: record?.failures || 0,
      timeouts: record?.timeouts || 0,
      rejections: record?.rejections || 0,
      success_rate: successRate,
      avg_ms: durations.length ? Math.round(durations.reduce((sum, value) => sum + value, 0) / durations.length) : 0,
      p95_ms: percentile(durations, 0.95),
      last_used_at: record?.last_used_at || null,
      last_error: record?.last_error || null,
      sessions: record?.sessions.size || 0,
    });
  }
  tools.sort((a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || b.executions - a.executions || a.tool.localeCompare(b.tool));

  const totals: ToolHealthTotals = {
    tools: tools.length,
    used: tools.filter((tool) => tool.executions > 0).length,
    executions: tools.reduce((sum, tool) => sum + tool.executions, 0),
    successes: tools.reduce((sum, tool) => sum + tool.successes, 0),
    failures: tools.reduce((sum, tool) => sum + tool.failures, 0),
    timeouts: tools.reduce((sum, tool) => sum + tool.timeouts, 0),
    rejections: tools.reduce((sum, tool) => sum + tool.rejections, 0),
    success_rate: 0,
    avg_ms: allDurations.length ? Math.round(allDurations.reduce((sum, value) => sum + value, 0) / allDurations.length) : 0,
    sessions: allSessions.size,
    projects: allProjects.size,
  };
  totals.success_rate = totals.executions ? round((totals.successes / totals.executions) * 100, 1) : 0;
  return { totals, tools };
}
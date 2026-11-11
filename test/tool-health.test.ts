import { describe, expect, it } from "vitest";
import { computeToolHealth, type ToolOutcomeRow, type ToolStatus } from "../src/control/console/tool-health.js";

const status = (id: string, extra: Partial<ToolStatus> = {}): ToolStatus => ({
  id, name: id, purpose: "", family: "recon", agent: "main", built_in: false, risk: "low",
  configured: true, status: "ready", ...extra,
});

const row = (source: string, kind: "tool-result" | "tool-error", data: Record<string, unknown>, at = 1000): ToolOutcomeRow => ({
  id: `${source}-${at}-${Math.random()}`, project_id: "p1", session_id: "s1", kind, source, summary: String(data.error || `${source} ok`), data, created_at: at,
});

describe("tool health aggregation", () => {
  it("separates success, failure, timeout and rejection", () => {
    const { tools, totals } = computeToolHealth([
      row("recon.nuclei", "tool-result", { ok: true, duration_ms: 2000 }, 10),
      row("recon.nuclei", "tool-result", { ok: true, duration_ms: 4000 }, 20),
      row("recon.nuclei", "tool-error", { ok: false, duration_ms: 1000, error: "exit 2" }, 30),
      row("recon.nuclei", "tool-error", { ok: false, duration_ms: 30000, timed_out: true }, 40),
      row("recon.nuclei", "tool-error", { ok: false, rejected: true, error: "recon.nuclei is not configured (NUCLEI_PATH)" }, 50),
    ], [status("recon.nuclei")]);
    const nuclei = tools[0]!;
    expect(nuclei).toMatchObject({ executions: 4, successes: 2, failures: 1, timeouts: 1, rejections: 1, success_rate: 50, sessions: 1 });
    expect(nuclei.avg_ms).toBe(Math.round((2000 + 4000 + 1000 + 30000) / 4));
    expect(nuclei.p95_ms).toBe(30000);
    expect(nuclei.last_error).toContain("NUCLEI_PATH");
    // Rejected work is not a health signal: it stays out of the denominator.
    expect(totals).toMatchObject({ executions: 4, rejections: 1, success_rate: 50 });
  });

  it("marks a mostly failing tool as failing and keeps a small sample neutral", () => {
    const rows = [
      row("recon.sql", "tool-error", { ok: false }, 1),
      row("recon.sql", "tool-error", { ok: false }, 2),
      row("recon.sql", "tool-result", { ok: true }, 3),
      row("recon.xss", "tool-error", { ok: false }, 4),
    ];
    const { tools } = computeToolHealth(rows, [status("recon.sql"), status("recon.xss")]);
    expect(tools.find((tool) => tool.tool === "recon.sql")!.state).toBe("failing");
    expect(tools.find((tool) => tool.tool === "recon.xss")!.state).toBe("degraded");
    // Problems sort ahead of healthy and idle tools.
    expect(tools.map((tool) => tool.state)).toEqual(["failing", "degraded"]);
  });

  it("reports catalog tools without evidence as idle or unconfigured", () => {
    const { tools } = computeToolHealth([], [
      status("recon.nuclei"),
      status("recon.subdomains", { configured: false }),
      status("recon.cms"),
    ]);
    expect(tools.map((tool) => [tool.tool, tool.state])).toEqual([
      ["recon.subdomains", "unconfigured"],
      ["recon.cms", "idle"],
      ["recon.nuclei", "idle"],
    ]);
    expect(tools.every((tool) => tool.executions === 0 && tool.success_rate === 0)).toBe(true);
  });

  it("counts distinct sessions and projects", () => {
    const { totals } = computeToolHealth([
      row("http.request", "tool-result", { ok: true, duration_ms: 120 }, 1),
      { ...row("http.request", "tool-result", { ok: true, duration_ms: 80 }, 2), session_id: "s2", project_id: "p2" },
      { ...row("http.request", "tool-error", { ok: false }, 3), session_id: "s2", project_id: "p2" },
    ]);
    expect(totals).toMatchObject({ sessions: 2, projects: 2, executions: 3, successes: 2, failures: 1, avg_ms: 100 });
  });

  it("ignores rows without a tool name", () => {
    const { totals, tools } = computeToolHealth([row("", "tool-result", { ok: true }, 1)]);
    expect(totals.executions).toBe(0);
    expect(tools).toHaveLength(0);
  });
});
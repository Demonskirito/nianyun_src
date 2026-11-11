import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import {
  PLAYBOOKS, playbookById, playbookCoverage, coverageSummary, playbookPriority,
  sortRequestsByPlaybook, stepForTool,
} from "../src/blackbox/playbooks.js";

const progressWith = () => {
  const progress = new BlackboxProgress();
  progress.state.tasks.T1 = { status: "pending", target: "https://a.test/", playbook: "unauth_exposure" };
  progress.state.tasks.T2 = { status: "pending", target: "https://b.test/", playbook: "xss" };
  progress.state.tasks.T3 = { status: "pending", target: "https://c.test/" };
  return progress;
};

describe("playbook priority ordering", () => {
  it("sorts work by priority and keeps model order inside one priority", () => {
    expect(playbookPriority("waf_bypass")).toBe(0);
    expect(playbookPriority("unauth_exposure")).toBe(1);
    expect(playbookPriority("xss")).toBe(Math.max(...PLAYBOOKS.map(playbook => playbook.priority)));
    expect(playbookPriority(undefined)).toBe(Number.MAX_SAFE_INTEGER);

    const requests = [
      { tool: "recon.xss", task_id: "T2" },
      { tool: "http.request", task_id: "T3" },
      { tool: "http.request", task_id: "T1" },
      { tool: "burp.sitemap", task_id: "T1" },
    ];
    const order = sortRequestsByPlaybook(requests, taskId => progressWith().state.tasks[taskId]?.playbook);
    expect(order.map(item => `${item.task_id}:${item.tool}`)).toEqual([
      "T1:http.request", "T1:burp.sitemap", "T2:recon.xss", "T3:http.request",
    ]);
  });
});

describe("playbook coverage ledger", () => {
  it("counts calls, outcomes and step hits per playbook", () => {
    const progress = progressWith();
    const request = (tool: string) => ({ tool, task_id: "T1", input: { url: "https://a.test/" } }) as never;

    progress.recordPlaybookCall("T1", "recon.content_discovery");
    progress.recordPlaybookResult("T1", "recon.content_discovery", { ok: false, summary: "ffuf exited 1" });
    progress.recordPlaybookCall("T1", "http.request");
    progress.recordPlaybookResult("T1", "http.request", { ok: true, summary: "200" });

    const run = progress.state.playbook_runs!.unauth_exposure!;
    expect(run.calls).toBe(2);
    expect(run.ok).toBe(1);
    expect(run.failed).toBe(1);
    expect(run.last_error?.summary).toContain("ffuf");
    expect(Object.keys(run.steps || {}).length).toBeGreaterThan(0);
    void request;
  });

  it("ignores tasks without a playbook", () => {
    const progress = progressWith();
    progress.recordPlaybookCall("T3", "http.request");
    expect(progress.state.playbook_runs).toBeUndefined();
  });

  it("turns the ledger into a coverage table with the next step", () => {
    const progress = progressWith();
    progress.state.tasks.T1.status = "completed";
    const first = playbookById("unauth_exposure")!.steps[0]!;
    progress.recordPlaybookCall("T1", first.tool);
    progress.recordPlaybookResult("T1", first.tool, { ok: true, summary: "hit" });

    const coverage = playbookCoverage(progress.state);
    const unauth = coverage.find(item => item.id === "unauth_exposure")!;
    expect(unauth.tasks).toBe(1);
    expect(unauth.tasks_completed).toBe(1);
    expect(unauth.steps_done).toBe(1);
    expect(unauth.steps_total).toBe(playbookById("unauth_exposure")!.steps.length);
    expect(unauth.next_step).toBe(playbookById("unauth_exposure")!.steps[1]!.id);
    expect(coverage.map(item => item.priority)).toEqual([...coverage.map(item => item.priority)].sort((a, b) => a - b));
    expect(coverageSummary(coverage)).toContain("unauth_exposure");
    expect(stepForTool("unauth_exposure", first.tool)).toBe(first.id);
  });

  it("lists a playbook whose tasks exist even before any call", () => {
    const coverage = playbookCoverage(progressWith().state);
    expect(coverage.map(item => item.id)).toEqual(["unauth_exposure", "xss"]);
    expect(coverage.every(item => item.calls === 0)).toBe(true);
  });
});
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PLAYBOOKS, orderedPlaybooks, playbookById, recommendPlaybooks, oastRequiredTask, burpScanTask } from "../src/blackbox/playbooks.js";
import { runPreflight, toolBlockedReason } from "../src/blackbox/preflight.js";
import { DEFAULT_ASSET_RULE, ASSET_RULE_VERSION } from "../src/asset/review.js";

describe("auth chain playbook (cross-tool)", () => {
  it("sits right after unauth exposure and wires browser → http", () => {
    const ids = orderedPlaybooks().map(playbook => playbook.id);
    expect(ids.slice(0, 5)).toEqual(["waf_bypass", "spa_reverse", "unauth_exposure", "auth_token", "idor"]);
    const playbook = playbookById("auth_token")!;
    const tools = playbook.steps.map(step => step.tool);
    expect(tools).toContain("browser.open");
    expect(tools).toContain("http.request");
    expect(tools).toContain("http.diff");
    // 浏览器在前、带 Token 重放在后，顺序不能反
    expect(tools.indexOf("browser.open")).toBeLessThan(tools.indexOf("http.request"));
    expect(playbook.steps.some(step => step.id === "capture_token")).toBe(true);
    expect(PLAYBOOKS.every(playbook => typeof playbook.priority === "number")).toBe(true);
  });

  it("recommends the chain when the site answers 10403 or has a login entry", () => {
    expect(recommendPlaybooks({ notes: ["所有接口统一返回 10403 TOKEN 错误"] }).map(item => item.id)).toContain("auth_token");
    expect(recommendPlaybooks({ urls: ["https://h/api/user/login"] }).map(item => item.id)).toContain("auth_token");
  });
});

describe("OAST / Burp linkage", () => {
  const base = { tasks: {}, tool_calls: {}, endpoints: { a: {}, b: {}, c: {}, d: {}, e: {} } };

  it("asks for an interactsh listener once a blind playbook runs", () => {
    const spec = oastRequiredTask({ ...base, playbook_runs: { ssrf: { calls: 2, ok: 1, failed: 0, steps: {}, last_at: 1 } } }, "20261024");
    expect(spec?.id).toBe("oast_required_20261024");
    expect(spec?.completion_criteria).toContain("回调");
    // listener 起来之后不再投
    expect(oastRequiredTask({ ...base, tool_calls: { "recon.interactsh": 1 }, playbook_runs: { ssrf: { calls: 2, ok: 1, failed: 0, steps: {}, last_at: 1 } } }, "s")).toBeUndefined();
  });

  it("asks for a Burp scan after crawling, but not twice", () => {
    const spec = burpScanTask({ ...base, tool_calls: { "katana.crawl": 1 } }, "20261024");
    expect(spec?.id).toBe("burp_scan_20261024");
    expect(burpScanTask({ ...base, tool_calls: { "katana.crawl": 1, "burp.scan": 1 } }, "s")).toBeUndefined();
    expect(burpScanTask({ ...base, tasks: { burp_scan_x: {} }, tool_calls: { "katana.crawl": 1 } }, "s")).toBeUndefined();
    expect(burpScanTask({ ...base, tool_calls: {} }, "s")).toBeUndefined();
  });
});

describe("preflight smoke", () => {
  it("fails nuclei when the template directory is empty and blocks it in the executor", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nuclei-empty-"));
    const node = process.execPath;
    const report = await runPreflight({ NUCLEI_PATH: node, NUCLEI_TEMPLATES_PATH: dir }, { dataDir: dir, timeoutMs: 4000 });
    const nuclei = report.entries.find(entry => entry.tool === "recon.nuclei");
    expect(nuclei?.ok).toBe(false);
    expect(nuclei?.detail).toContain("模板目录为空");
    expect(report.failed).toContain("recon.nuclei");
    expect(toolBlockedReason("recon.nuclei")).toContain("模板目录为空");
    expect(toolBlockedReason("http.request")).toBeUndefined();
  });

  it("passes nuclei when templates exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nuclei-full-"));
    mkdirSync(join(dir, "http"), { recursive: true });
    writeFileSync(join(dir, "http", "cve.yaml"), "id: demo\n");
    const report = await runPreflight({ NUCLEI_PATH: process.execPath, NUCLEI_TEMPLATES_PATH: dir }, { dataDir: dir, timeoutMs: 4000 });
    expect(report.entries.find(entry => entry.tool === "recon.nuclei")?.ok).toBe(true);
  });
});

describe("candidate scoring rule", () => {
  it("tilts toward API and sensitive paths", () => {
    expect(ASSET_RULE_VERSION).toBe("asset-page-v2");
    expect(DEFAULT_ASSET_RULE).toContain("/api/");
    expect(DEFAULT_ASSET_RULE).toContain("swagger");
    expect(DEFAULT_ASSET_RULE).toContain("actuator");
    expect(DEFAULT_ASSET_RULE).toContain("?id=");
    // 静态页必须压到低分区
    expect(DEFAULT_ASSET_RULE).toMatch(/静态页[\s\S]{0,80}?0-25/);
  });
});
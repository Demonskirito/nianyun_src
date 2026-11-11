import { describe, expect, it } from "vitest";
import { PLAYBOOKS, PLAYBOOK_IDS, orderedPlaybooks, playbookById, playbookIndex, recommendPlaybooks, playbookGuide } from "../src/blackbox/playbooks.js";
import { BLACKBOX_TOOL_NAMES } from "../src/blackbox/tools.js";
import { taskSchema, mainSchema } from "../src/blackbox/protocol.js";

const tools = new Set<string>(BLACKBOX_TOOL_NAMES as readonly string[]);

describe("playbook catalog", () => {
  it("keeps ids unique and every step bound to a registered tool", () => {
    expect(new Set(PLAYBOOK_IDS).size).toBe(PLAYBOOK_IDS.length);
    const unknown: string[] = [];
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) {
        if (!tools.has(step.tool)) unknown.push(`${playbook.id}.${step.id}:${step.tool}`);
        // Every step must be citable by confirm.evidence, otherwise the confirm condition is empty.
        expect(playbook.steps.some(candidate => candidate.id === step.id)).toBe(true);
      }
      for (const id of playbook.confirm.evidence) {
        expect(playbook.steps.map(step => step.id)).toContain(id);
      }
    }
    expect(unknown).toEqual([]);
  });

  it("covers the verification ladder in the documented priority order", () => {
    expect(orderedPlaybooks().map(playbook => playbook.id)).toEqual([
      "waf_bypass", "spa_reverse", "unauth_exposure", "auth_token", "idor", "sqli", "upload_rce", "cmdi", "ssrf", "deserialization",
      "jwt_auth", "cloud_supply", "logic", "race_condition", "graphql_ws", "xss",
    ]);
    const priorities = orderedPlaybooks().map(playbook => playbook.priority);
    expect(priorities).toEqual([...priorities].sort((a, b) => a - b));
  });

  it("uses http.diff or an OAST listener wherever a diff or blind confirmation is needed", () => {
    const needsDiff = ["unauth_exposure", "idor", "sqli", "cmdi", "jwt_auth", "logic"];
    for (const id of needsDiff) {
      const playbook = playbookById(id)!;
      expect(playbook.steps.some(step => step.tool === "http.diff")).toBe(true);
    }
    const needsOast = ["ssrf", "deserialization"];
    for (const id of needsOast) {
      const playbook = playbookById(id)!;
      expect(playbook.steps.some(step => step.tool === "recon.interactsh")).toBe(true);
    }
  });

  it("gives every playbook a timebox, a stop rule and report bullets", () => {
    for (const playbook of PLAYBOOKS) {
      expect(playbook.timebox_sec).toBeGreaterThan(0);
      expect(playbook.stop.length).toBeGreaterThan(0);
      expect(playbook.report.length).toBeGreaterThan(0);
      expect(playbook.confirm.must_show.length).toBeGreaterThan(10);
    }
  });
});

describe("playbook binding in the protocol", () => {
  it("keeps the playbook field instead of stripping it", () => {
    const parsed = taskSchema.safeParse({ id: "T3", target: "https://example.com/", purpose: "check idor", reason: "two accounts available", completion_criteria: "diff shows other user data", playbook: "idor" });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.playbook).toBe("idor");
    const out = mainSchema.safeParse({ summary: "plan", required_tasks: [{ id: "T3", target: "https://example.com/", purpose: "check idor", reason: "r", completion_criteria: "c", playbook: "idor" }] });
    expect(out.success).toBe(true);
    expect((out.data?.required_tasks?.[0] as { playbook?: string } | undefined)?.playbook).toBe("idor");
  });
});

describe("playbook routing", () => {
  it("accepts short and Chinese aliases", () => {
    expect(playbookById("未授权")?.id).toBe("unauth_exposure");
    expect(playbookById("sql")?.id).toBe("sqli");
    expect(playbookById("越权")?.id).toBe("idor");
    expect(playbookById("nope")).toBeUndefined();
  });

  it("recommends playbooks from fingerprints and endpoint shapes", () => {
    expect(recommendPlaybooks({ fingerprints: ["spring boot actuator"] }).map(playbook => playbook.id)).toContain("unauth_exposure");
    const idor = recommendPlaybooks({ urls: ["https://h/api/order?orderId=1"] }).map(playbook => playbook.id);
    expect(idor).toContain("idor");
    expect(idor.indexOf("idor")).toBeLessThan(idor.length);
    const ruoyi = recommendPlaybooks({ notes: ["若依 RuoYi 后台"] }).map(playbook => playbook.id);
    expect(ruoyi).toContain("unauth_exposure");
    // Never returns nothing: a bare target still starts from the cheapest high-value class.
    expect(recommendPlaybooks({}).map(playbook => playbook.id)).toEqual(["unauth_exposure"]);
  });

  it("renders an index for the prompt and a guide on demand", () => {
    const index = playbookIndex();
    expect(index).toContain("unauth_exposure");
    expect(index).toContain("http.diff");
    for (const id of PLAYBOOK_IDS) expect(index).toContain(id);
    expect(playbookGuide("idor")).toContain("越权");
    expect(playbookGuide("missing")).toContain("未知 playbook");
  });
});
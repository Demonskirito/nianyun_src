import { describe, expect, it } from "vitest";
import { BLACKBOX_RULE_TOOL_NAMES, DEFAULT_BLACKBOX_RULES, blackboxRules, blackboxRulesDiagnostics, blackboxRulesHash } from "../src/blackbox/rules.js";
import { mainSchema } from "../src/blackbox/protocol.js";
import { BLACKBOX_TOOL_NAMES } from "../src/blackbox/tools.js";

// Every registered tool runs without an operator switch: there is no approval
// subsystem and no per-tool enable/disable flag. The rules document only carries
// risk switches (credential attacks) plus budgets and limits. The execution path
// itself is covered by blackbox-tool-access.test.ts.
describe("tool availability", () => {
  it("exposes no per-tool policy beyond the credential switch", () => {
    const rules = blackboxRules({});
    expect(Object.keys(rules.tools).sort()).toEqual([...BLACKBOX_TOOL_NAMES].filter(tool => tool in rules.tools).sort());
    for (const [tool, policy] of Object.entries(rules.tools)) {
      // burp.scan is the only default-on high-risk switch; every other tool carries no policy.
      if (tool === "burp.scan") expect(policy).toEqual({ allow_active_scan: true });
      else expect(policy, tool).toEqual({});
      expect(tool).not.toContain("approval");
    }
    expect(JSON.stringify(rules)).not.toMatch(/manual_switch|approval|"enabled"/);
    expect(blackboxRulesHash(rules)).toBe(blackboxRulesHash(blackboxRules({})));
  });

  it("ignores a legacy enabled flag and deprecated confirmation flags", () => {
    const legacy = blackboxRulesDiagnostics({ BLACKBOX_RULES_DOCUMENT: JSON.stringify({ tools: { "recon.xss": { enabled: false } } }) });
    expect(legacy.credential_tools).toEqual([]);
    expect(legacy.issues.join(" ")).toContain("enabled 已废弃");
    const rules = blackboxRules({ BLACKBOX_RULES_DOCUMENT: JSON.stringify({ tools: { "recon.xss": { enabled: false } } }) });
    expect(rules.tools["recon.xss"]).toEqual({});
    expect(rules.tools["recon.sql"]).toEqual(DEFAULT_BLACKBOX_RULES.tools["recon.sql"]);
    const parsed = mainSchema.safeParse({ summary: "fixture", tool_requests: [{ tool: "recon.xss", input: {}, requires_confirmation: true }] });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.tool_requests[0]).toMatchObject({ tool: "recon.xss", requires_confirmation: true });
  });
});

describe("rules document diagnostics", () => {
  it("flags an unparsable document instead of silently falling back", () => {
    const broken = blackboxRulesDiagnostics({ BLACKBOX_RULES_DOCUMENT: "{ not json" });
    expect(broken).toMatchObject({ valid: false, fallback: true, credential_tools: [] });
    expect(broken.issues.join(" ")).toContain("回退到默认规则");
    expect(blackboxRules({ BLACKBOX_RULES_DOCUMENT: "{ not json" })).toEqual(DEFAULT_BLACKBOX_RULES);
    expect(blackboxRulesDiagnostics({})).toEqual({ valid: true, fallback: false, issues: [], credential_tools: [], active_scan_tools: [] });
    expect(blackboxRulesDiagnostics({ BLACKBOX_RULES_DOCUMENT: "[]" })).toMatchObject({ valid: false, fallback: true });
  });

  it("records credential opt-ins and explains every ignored value", () => {
    const document = {
      budgets: { tool_calls: "many", retries: -3 },
      request: { max_timeout_ms: 10 },
      tools: { "recon.sql": { allow_credential_attack: true }, "recon.xss": { allow_credential_attack: "yes" }, "recon.foo": {} },
      unknown_section: { x: 1 },
    };
    const state = blackboxRulesDiagnostics({ BLACKBOX_RULES_DOCUMENT: JSON.stringify(document) });
    expect(state.valid).toBe(true);
    expect(state.credential_tools).toEqual(["recon.sql"]);
    const issues = state.issues.join("\n");
    expect(issues).toMatch(/budgets\.tool_calls 不是有效数字/);
    expect(issues).toMatch(/budgets\.retries 超出允许范围/);
    expect(issues).toMatch(/request\.max_timeout_ms 超出允许范围/);
    expect(issues).toMatch(/未知规则段 "unknown_section"/);
    expect(issues).toMatch(/未知工具名 "recon\.foo"/);
    expect(issues).toMatch(/recon\.xss.*allow_credential_attack 必须是布尔值/);
    const rules = blackboxRules({ BLACKBOX_RULES_DOCUMENT: JSON.stringify(document) });
    expect(rules.tools["recon.sql"]).toEqual({ allow_credential_attack: true });
    expect(rules.tools["recon.xss"]).toEqual({});
    expect(rules.tools["recon.foo"]).toBeUndefined();
    expect(rules.budgets.tool_calls).toBe(DEFAULT_BLACKBOX_RULES.budgets.tool_calls);
    expect(rules.budgets.retries).toBe(0);
  });

  it("keeps the risk-switch tool list in sync with the default rules", () => {
    expect(BLACKBOX_RULE_TOOL_NAMES).toHaveLength(16);
    expect([...BLACKBOX_RULE_TOOL_NAMES].sort()).toEqual(Object.keys(DEFAULT_BLACKBOX_RULES.tools).sort());
    expect(BLACKBOX_TOOL_NAMES).toEqual(expect.arrayContaining(BLACKBOX_RULE_TOOL_NAMES));
  });
});
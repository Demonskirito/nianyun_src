/**
 * tools.env.yaml 的解析语义。
 *
 * 这几条都是 2026-11-05 实盘踩出来的"配置静默失效"：
 * 文件写得像模像样，解析结果为空，代码按默认值跑，操作员改什么都看不到反应。
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadToolsEnv } from "../src/shared/tools-env.js";

const load = (text: string) => {
  const dir = mkdtempSync(join(tmpdir(), "tools-env-"));
  const path = join(dir, "tools.env.yaml");
  writeFileSync(path, text);
  return loadToolsEnv(path);
};

describe("loadToolsEnv", () => {
  it("accepts a flat file where every key sits at the top level", () => {
    const env = load([
      "BLACKBOX_AGENT_MODEL: deepseek-v4.1-flash-1017",
      "BURP_PROXY_URL: http://host.docker.internal:8080",
      "BURP_PROXY_REQUIRED: \"true\"",
    ].join("\n"));
    // 原实现只遍历对象段 → 这三行一个都进不来（实测容器里 12 行配置解析出 0 个键）。
    expect(env.values.BLACKBOX_AGENT_MODEL).toBe("deepseek-v4.1-flash-1017");
    expect(env.values.BURP_PROXY_URL).toBe("http://host.docker.internal:8080");
    expect(env.values.BURP_PROXY_REQUIRED).toBe("true");
    expect(env.warnings).toEqual([]);
  });

  it("still flattens nested sections and lets leaves win", () => {
    const env = load([
      "version: 2",
      "tools:",
      "  arl:",
      "    BURP_PROXY_REQUIRED: \"true\"",
      "    KATANA_PATH: /usr/local/bin/katana",
    ].join("\n"));
    expect(env.values.BURP_PROXY_REQUIRED).toBe("true");
    expect(env.values.KATANA_PATH).toBe("/usr/local/bin/katana");
    expect(env.values.version).toBeUndefined();
  });

  it("serialises a YAML-object rules document instead of scattering its leaves", () => {
    const env = load([
      "BLACKBOX_RULES_DOCUMENT:",
      "  budgets:",
      "    tool_calls: 90",
      "    agent_turns: 30",
      "  loop_control:",
      "    repeat_limit: 2",
    ].join("\n"));
    // 散成 tool_calls / agent_turns 的旧行为会让 parseDocument 拿到空串，预算静默回退默认值。
    expect(env.values.tool_calls).toBeUndefined();
    expect(JSON.parse(env.values.BLACKBOX_RULES_DOCUMENT || "{}")).toEqual({
      budgets: { tool_calls: 90, agent_turns: 30 },
      loop_control: { repeat_limit: 2 },
    });
  });

  it("keeps a rules document that is already JSON text", () => {
    const doc = JSON.stringify({ budgets: { tool_calls: 90 } });
    const env = load(`BLACKBOX_RULES_DOCUMENT: '${doc}'`);
    expect(JSON.parse(env.values.BLACKBOX_RULES_DOCUMENT || "{}").budgets.tool_calls).toBe(90);
  });

  it("warns when a non-empty file yields no keys at all", () => {
    // 只剩元数据段（version/required）时没有任何键进得来，这种"看起来有内容"的文件最容易被当成生效了。
    const env = load(["version: 2", "required: []"].join("\n"));
    expect(env.values).toEqual({});
    expect(env.warnings.join("")).toContain("没有解析出任何配置键");
  });

  it("refuses a top-level list instead of turning indices into env keys", () => {
    const env = load(["- just", "- a", "- list"].join("\n"));
    expect(env.values).toEqual({});
    expect(env.warnings.join("")).toContain("顶层是列表");
  });

  it("warns when the file cannot be parsed", () => {
    const env = load("a: [unclosed\nb: c");
    expect(env.warnings.join("")).toContain("解析失败");
  });

  it("stays quiet for an empty file", () => {
    const env = load("# only a comment\n");
    expect(env.values).toEqual({});
    expect(env.warnings).toEqual([]);
  });
});

import { describe, expect, it } from "vitest";
import { ENUMERATION_RULE, toolGuide, toolGuideText } from "../src/blackbox/tool-guide.js";
import { declaredToolInputKeys } from "../src/blackbox/protocol.js";
import { toolParamNames } from "../src/blackbox/tool-params.js";
import { evidenceReferenceIds } from "../src/blackbox/progress.js";

describe("tool-guide：一次 Reject 变成一次教学", () => {
  it("http.diff 给出真实入参键，并点明 baseline_self/diff_auth 是步骤名不是键", () => {
    const guide = toolGuide("http.diff", ["baseline", "variant", "label"]);
    expect(guide.allowed_keys).toContain("variant");
    expect(guide.allowed_keys).toContain("url");
    expect(guide.allowed_keys).not.toContain("baseline");
    expect(guide.example).toHaveProperty("variant");
    expect(guide.note).toContain("baseline_self");
  });

  it("http.request 明确 Host 不可改写、该走 burp.send", () => {
    const guide = toolGuide("http.request", ["host"]);
    expect(guide.allowed_keys).toContain("headers");
    expect(guide.note).toContain("burp.send");
  });

  it("未知工具退回通用兜底而不是抛错", () => {
    const guide = toolGuide("recon.made_up_tool", ["whatever"]);
    expect(guide.allowed_keys).toContain("params");
    expect(guide.note).toContain("whatever");
  });

  it("recon.dns 不教自造键：domain/hostname/record_types 都不在允许列表里", () => {
    const guide = toolGuide("recon.dns", ["domain", "record_types"]);
    expect(guide.allowed_keys).not.toContain("domain");
    expect(guide.allowed_keys).not.toContain("record_types");
    expect(guide.note).toContain("domain, record_types");
    // 2026-10-28 实测：通用兜底曾把 url/method/headers 当成"可猜的键"，等于用错误示例教模型。
    expect(guide.allowed_keys).toEqual(["url", "source", "timeout_ms"]);
  });

  it("教学文本包含允许键与可照抄的示例", () => {
    const text = toolGuideText("fs.grep", ["pattern"]);
    expect(text).toContain("pattern");
    expect(text).toContain("示例");
    expect(text).toContain("max_matches");
  });
});

/**
 * 2026-11-06 实测（会话 bdd308655a4c65b8）：内容发现工具被模型放弃，根因是说明书说
 * "只接受 url, params""并发由工具自身决定"。这一组用例把"说明书 = 执行器真相"钉死，
 * 而不是钉死某一段文案。
 */
describe("recon 系说明书必须是执行器真相", () => {
  it("content_discovery 亮出字典与并发：模型不必靠试错才知道能指定它们", () => {
    const guide = toolGuide("recon.content_discovery", ["threads"]);
    for (const key of ["url", "wordlist", "wordlist_root", "threads", "params"]) {
      expect(guide.allowed_keys, `${key} 必须出现在允许键里`).toContain(key);
    }
    expect(guide.example).toHaveProperty("wordlist");
    expect(guide.note).toContain("paths.txt");
    expect(guide.note).toContain("threads");
  });

  it("katana.crawl 用 depth/duration_seconds，并明确写成 duration 会被摘掉", () => {
    const guide = toolGuide("katana.crawl", ["duration"]);
    expect(guide.allowed_keys).toContain("depth");
    expect(guide.allowed_keys).toContain("duration_seconds");
    expect(guide.note).toContain("duration");
  });

  it("说明书里的每个键都是 schema 声明过的键（否则说明书本身在教一个会被摘掉的键）", () => {
    const declared = new Set(declaredToolInputKeys());
    const tools = ["recon.content_discovery", "recon.api_routes", "recon.nuclei", "recon.subdomains",
      "recon.dns", "recon.http_probe", "recon.ports", "recon.historical_urls", "recon.parameters",
      "recon.js_endpoints", "recon.tls", "recon.xss", "recon.sql", "recon.jwt", "recon.graphql",
      "recon.cms", "recon.secrets", "recon.sast", "recon.wordlists", "recon.scan_profile",
      "recon.race_condition", "recon.interactsh", "katana.crawl", "nuclei.scan"];
    const unknown: string[] = [];
    for (const tool of tools) {
      for (const key of toolGuide(tool).allowed_keys) if (!declared.has(key)) unknown.push(`${tool}.${key}`);
    }
    expect(unknown).toEqual([]);
  });

  it("说明书承诺的 params 键必须真的在执行器白名单里（反之亦然）", () => {
    const mismatched: string[] = [];
    for (const tool of ["recon.content_discovery", "recon.nuclei", "recon.ports", "recon.http_probe", "recon.tls", "recon.sql"]) {
      const advertised = toolGuide(tool).allowed_keys.includes("params");
      const real = toolParamNames(tool).length > 0;
      if (advertised !== real) mismatched.push(`${tool}: 说明书=${advertised} 执行器=${real}`);
    }
    expect(mismatched).toEqual([]);
  });

  it("不接受 params 的工具不会被教成'放 params'（那是最常见的二次撞墙）", () => {
    for (const tool of ["recon.dns", "recon.subdomains", "recon.parameters", "recon.api_routes"]) {
      expect(toolParamNames(tool), `${tool} 本就没有 params 白名单`).toEqual([]);
      expect(toolGuide(tool).allowed_keys).not.toContain("params");
      expect(toolGuide(tool).note).toContain("不接受 input.params");
    }
  });

  it("枚举分工写进了提示词，并点名禁止循环 http.request", () => {
    expect(ENUMERATION_RULE).toContain("recon.content_discovery");
    expect(ENUMERATION_RULE).toContain("http.request");
    expect(ENUMERATION_RULE).toContain("严禁");
  });
});

describe("R4：结论必须引用证据 id", () => {
  it("抽出 ev-id 并去重", () => {
    const ids = evidenceReferenceIds("ev-03d12a0975caa819 与 ev-03d12a0975caa819 都指向同一响应，另见 ev-9f8e7d6c5b4a3210");
    expect(ids).toEqual(["ev-03d12a0975caa819", "ev-9f8e7d6c5b4a3210"]);
  });

  it("长度不符或格式未中一律不算引用", () => {
    expect(evidenceReferenceIds("ev-03d12a09")).toEqual([]);
    expect(evidenceReferenceIds("没有引用的结论")).toEqual([]);
    expect(evidenceReferenceIds(undefined)).toEqual([]);
  });
});
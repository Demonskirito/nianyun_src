import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { BLACKBOX_TOOL_NAMES } from "../src/blackbox/tools.js";
import { TOOL_DOCS } from "../src/blackbox/tool_docs.js";
import { buildToolManifest, toolManifestDocument, toolManifestPrompt } from "../src/blackbox/tool_manifest.js";
import { RPC_WHITELIST } from "../src/blackbox/sandbox_rpc.js";
import { PLAYBOOKS } from "../src/blackbox/playbooks.js";
import { toolLayer } from "../src/blackbox/routing.js";
import { toolWeight } from "../src/blackbox/weights.js";

const manifestFile = join(process.cwd(), "generated", "tool-manifest.json");

describe("工具清单（manifest）零漂移", () => {
  it("覆盖每一个可调用工具，没有多余条目", () => {
    const manifest = buildToolManifest();
    const names = manifest.tools.map(tool => tool.name).sort();
    expect(names).toEqual([...BLACKBOX_TOOL_NAMES].sort());
    // 名字唯一：重复会导致控制台重复显示、模型看到两份。
    expect(new Set(names).size).toBe(names.length);
  });

  it("manifest 里没有漂移问题（缺文案 / 多幽灵条目 / 白名单不存在）", () => {
    expect(buildToolManifest().issues).toEqual([]);
  });

  it("每个工具都有非空用途文案", () => {
    const silent = buildToolManifest().tools.filter(tool => !tool.purpose.trim()).map(tool => tool.name);
    expect(silent).toEqual([]);
  });

  /**
   * 清单是模型**每轮**都读的东西。它原来只有「名字 + 用途」，于是"这个工具能不能指定字典 /
   * 并发"只能靠试：写 `threads` 被摘掉、回执再说"可用：url, params"，模型就永久放弃了这个工具。
   * 把可调项写在清单行上，是为了让"能调什么"不必成为一次试错。
   */
  it("清单行带上可调项（字典 / params），模型不必靠撞墙才发现", () => {
    const prompt = toolManifestPrompt();
    const line = (name: string) => prompt.split("\n").find(row => row.startsWith(`${name}[`)) || "";
    expect(line("recon.content_discovery")).toContain("wordlist");
    expect(line("recon.content_discovery")).toContain("params(");
    expect(line("recon.api_routes")).toContain("wordlist");
    expect(line("katana.crawl")).not.toContain("可传");
  });

  it("层与权重跟执行期用的是同一批函数（不会各说一套）", () => {
    for (const tool of buildToolManifest().tools) {
      const expected: string = tool.name === "recon.race_condition" ? "tactical_rpc" : toolLayer(tool.name);
      expect({ name: tool.name, layer: tool.layer }).toEqual({ name: tool.name, layer: expected });
      expect(tool.weight).toBe(toolWeight(tool.name));
    }
  });

  it("RPC 白名单与打法库引用的工具都存在，且都被标成可调用", () => {
    const byName = new Map(buildToolManifest().tools.map(tool => [tool.name, tool]));
    for (const tool of RPC_WHITELIST) expect(byName.has(tool)).toBe(true);
    for (const tool of RPC_WHITELIST) expect(byName.get(tool)!.rpc_callable).toBe(true);
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) expect(byName.has(step.tool)).toBe(true);
    }
  });

  it("打法覆盖是反查出来的，不是手填的", () => {
    const manifest = buildToolManifest();
    const executor = manifest.tools.find(tool => tool.name === "exec.python")!;
    const expected = PLAYBOOKS.filter(playbook => playbook.steps.some(step => step.tool === "exec.python")).map(playbook => playbook.id).sort();
    expect([...executor.playbooks].sort()).toEqual(expected);
    expect(expected.length).toBeGreaterThan(0);
  });

  it("落盘的 generated/tool-manifest.json 与代码一致（改代码忘了重新生成会失败）", () => {
    const onDisk = JSON.parse(readFileSync(manifestFile, "utf8")) as Record<string, unknown>;
    const expected = toolManifestDocument(
      ((onDisk.components as { schemas?: { ToolInput?: Record<string, unknown> } } | undefined)?.schemas?.ToolInput) || { type: "object" },
    );
    expect(onDisk.info).toEqual(expected.info);
    expect(onDisk["x-nianyun-counts"]).toEqual(expected["x-nianyun-counts"]);
    expect(Object.keys(onDisk.paths as Record<string, unknown>).sort())
      .toEqual(Object.keys(expected.paths as Record<string, unknown>).sort());
  });

  it("OpenAPI 文档给每个工具一个 operation，并带层/权重/打法元数据", () => {
    const document = toolManifestDocument({ type: "object" });
    const paths = document.paths as Record<string, { post: Record<string, any> }>;
    expect(Object.keys(paths)).toHaveLength(BLACKBOX_TOOL_NAMES.length);
    const http = paths["/tools/http.request"]!.post;
    expect(http.operationId).toBe("http_request");
    expect(http.summary.length).toBeGreaterThan(10);
    expect(http["x-nianyun"].layer).toBe("tactical");
    expect(http["x-nianyun"].weight).toBe(1);
    expect(paths["/tools/exec.python"]!.post["x-nianyun"].layer).toBe("strategic");
    expect(paths["/tools/recon.race_condition"]!.post["x-nianyun"].layer).toBe("tactical_rpc");
  });

  it("统计口径与 manifest 内容一致（tactical+strategic+rpc = total）", () => {
    const counts = buildToolManifest().counts;
    expect(counts.tactical + counts.strategic + counts.tactical_rpc).toBe(counts.total);
    expect(counts.total).toBe(BLACKBOX_TOOL_NAMES.length);
    expect(counts.strategic).toBe(2);
  });

  it("文档表里不再混入 CLI 名字（那正是 62 vs 73 漂移的来源）", () => {
    const cli = ["subfinder", "dnsx", "httpx", "naabu", "ffuf", "nuclei", "sqlmap", "raw sockets"];
    const documented = TOOL_DOCS.map(doc => doc.name);
    for (const name of cli) expect(documented).not.toContain(name);
    // 每条的 id 与 name 一致：以前 name 存的是 CLI 显示名。
    expect(TOOL_DOCS.filter(doc => doc.id !== doc.name)).toEqual([]);
  });
});
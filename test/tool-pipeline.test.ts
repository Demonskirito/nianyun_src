import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ToolRejected, executeBlackboxTool, externalToolCommand, extraToolArgs, resolvePipelineSource, urlsFromText,
  type BlackboxToolContext,
} from "../src/blackbox/tools.js";

const dirs: string[] = [];
afterEach(() => { dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })); });

function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-pipeline-"));
  dirs.push(dir);
  return dir;
}

function pipelineContext(dir: string, artifact: string, source = "katana.crawl") {
  const folder = join(dir, "blackbox-artifacts", "p1", "s1");
  mkdirSync(folder, { recursive: true });
  const relative = `blackbox-artifacts/p1/s1/tool-output.jsonl`;
  writeFileSync(join(dir, relative), artifact);
  return {
    cfg: { data_dir: dir, execution: { mode: "execute", source: "config" } },
    db: {
      getProjectCookies: () => [],
      mergeProjectCookies: (_projectId: string, rows: unknown[]) => rows,
      latestBlackboxToolResult: (_projectId: string, _sessionId: string, tool: string) =>
        (tool === source ? { id: "ev-1", source, artifact_path: null, data: { items: [] } } : null),
      latestBlackboxArtifact: (_projectId: string, _sessionId: string, tool: string) =>
        (tool === source ? { id: "ev-2", source, artifact_path: relative } : null),
      getBlackboxArtifact: () => ({ id: "ev-2", source, artifact_path: relative }),
    },
    projectId: "p1", sessionId: "s1", target: "https://app.example.test/", values: {},
  } as unknown as BlackboxToolContext;
}

describe("tool pipelines", () => {
  it("extracts URLs from JSONL, plain lines and host records", () => {
    const text = [
      JSON.stringify({ url: "https://app.example.test/a" }),
      JSON.stringify({ "matched-at": "https://app.example.test/b?x=1", "template-id": "t" }),
      JSON.stringify({ host: "api.example.test", port: 443 }),
      "not a url",
      "GET https://app.example.test/c HTTP/1.1",
      "https://app.example.test/a",
    ].join("\n");
    expect(urlsFromText(text)).toEqual([
      "https://app.example.test/a", "https://app.example.test/b?x=1", "api.example.test", "https://app.example.test/c",
    ]);
    expect(urlsFromText(text, 2)).toHaveLength(2);
  });

  it("resolves the previous tool's artifact into a target list", () => {
    const dir = workspace();
    const artifact = [
      JSON.stringify({ url: "https://app.example.test/one" }),
      JSON.stringify({ url: "https://app.example.test/two" }),
    ].join("\n");
    const ctx = pipelineContext(dir, artifact);
    const resolved = resolvePipelineSource(ctx, { tool: "katana.crawl", limit: 2 });
    expect(resolved.targets).toEqual(["https://app.example.test/one", "https://app.example.test/two"]);
    expect(resolved.tool).toBe("katana.crawl");
    expect(() => resolvePipelineSource(ctx, {})).toThrow(/requires tool or evidence_id/);
    expect(() => resolvePipelineSource(ctx, { tool: "recon.nuclei" })).toThrow(/pipeline source not found/);
  });

  it("builds the list flag instead of a single target", () => {
    const dir = workspace();
    const ctx = pipelineContext(dir, JSON.stringify({ url: "https://app.example.test/" }));
    expect(externalToolCommand("recon.http_probe", ctx.target, {}, ctx, "C:/tmp/list.txt").args.slice(0, 2)).toEqual(["-l", "C:/tmp/list.txt"]);
    expect(externalToolCommand("recon.nuclei", ctx.target, {}, ctx, "C:/tmp/list.txt").args.slice(0, 2)).toEqual(["-l", "C:/tmp/list.txt"]);
    expect(externalToolCommand("recon.ports", ctx.target, {}, ctx, "C:/tmp/list.txt").args.slice(0, 2)).toEqual(["-list", "C:/tmp/list.txt"]);
    expect(externalToolCommand("recon.tls", ctx.target, {}, ctx, "C:/tmp/list.txt").args)
      .toEqual(expect.arrayContaining(["--file", "C:/tmp/list.txt"]));
    // Single-target tools keep their normal command line.
    expect(externalToolCommand("recon.subdomains", ctx.target, {}, ctx, "C:/tmp/list.txt").args).toEqual(["-d", "app.example.test", "-silent"]);
  });

  it("pages an artifact beyond the bounded result", async () => {
    const dir = workspace();
    const lines = Array.from({ length: 500 }, (_, index) => JSON.stringify({ url: `https://app.example.test/${index}` }));
    const ctx = pipelineContext(dir, lines.join("\n"), "recon.nuclei");
    const head = await executeBlackboxTool(ctx, { tool: "evidence.read", input: { tool: "recon.nuclei", offset: 0, limit: 3 } });
    expect(head.data.total_lines).toBe(500);
    expect(head.data.returned).toBe(3);
    expect(head.data.next_offset).toBe(3);
    const tail = await executeBlackboxTool(ctx, { tool: "evidence.read", input: { tool: "recon.nuclei", offset: 498, limit: 10 } });
    expect(tail.data.returned).toBe(2);
    expect(tail.data.next_offset).toBeNull();
  });

  it("refuses an artifact path outside the data directory", async () => {
    const dir = workspace();
    const ctx = pipelineContext(dir, "x", "recon.nuclei");
    (ctx.db as unknown as { latestBlackboxArtifact: () => Record<string, unknown> }).latestBlackboxArtifact = () => ({ artifact_path: "../../etc/passwd" });
    await expect(executeBlackboxTool(ctx, { tool: "evidence.read", input: { tool: "recon.nuclei" } })).rejects.toThrow(/invalid artifact path/);
  });

  it("keeps credential attacks off unless the rules document enables them", () => {
    expect(() => extraToolArgs("recon.sql", ["--passwords", "words.txt"])).toThrow(/credential attack is disabled/);
    expect(() => extraToolArgs("recon.cms", ["--usernames", "admin"])).toThrow(ToolRejected);
    const dir = workspace();
    writeFileSync(join(dir, "words.txt"), "admin\n");
    expect(() => extraToolArgs("recon.sql", ["--passwords", join(dir, "words.txt")], { allowCredentialAttack: true, wordlistRoots: [dir] }))
      .not.toThrow();
    expect(() => extraToolArgs("recon.sql", ["--passwords", join(tmpdir(), "elsewhere.txt")], { allowCredentialAttack: true, wordlistRoots: [dir] }))
      .toThrow(/not inside the approved roots/);
    expect(extraToolArgs("recon.sql", ["--passwords", join(dir, "words.txt")], { allowCredentialAttack: true, wordlistRoots: [dir] }))
      .toEqual(["--passwords", join(dir, "words.txt")]);
    // The per-tool opt-in reaches the command builder through the rules document.
    const ctx = pipelineContext(dir, "x", "recon.sql");
    ctx.values = { BLACKBOX_RULES_DOCUMENT: JSON.stringify({ tools: { "recon.sql": { allow_credential_attack: true } } }), NIANYUN_WORDLIST_ROOT: dir };
    expect(externalToolCommand("recon.sql", ctx.target, { args: ["--passwords", join(dir, "words.txt")] }, ctx).args)
      .toEqual(expect.arrayContaining(["--passwords", join(dir, "words.txt")]));
  });
});

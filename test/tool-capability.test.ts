import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ToolRejected, externalToolCommand, externalToolTimeoutMs, parseHttpxLine, parseNucleiLine, redactArgs,
  type BlackboxToolContext,
} from "../src/blackbox/tools.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";

const dirs: string[] = [];
afterEach(() => { dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })); });
const target = "https://app.example.test/";

const jar = [
  { name: "sid", value: "s3cr3t", domain: "app.example.test", path: "/", hostOnly: true, secure: true, httpOnly: true },
  { name: "theme", value: "dark", domain: "app.example.test", path: "/", hostOnly: true, secure: true, httpOnly: false },
];

const ctx = (values: Record<string, string> = {}, jarRows = jar) => ({
  target, values, projectId: "p1",
  db: { getProjectCookies: () => jarRows },
} as unknown as BlackboxToolContext);

const argsFor = (tool: string, input: Record<string, unknown>, context = ctx()) =>
  externalToolCommand(tool, target, input, context).args;

describe("external tool capability parity", () => {
  it("passes arbitrary CLI flags through in order", () => {
    const args = argsFor("recon.nuclei", { args: ["-severity", "critical", "-etags", "dos,fuzz", "-stats"] });
    expect(args.slice(-5)).toEqual(["-severity", "critical", "-etags", "dos,fuzz", "-stats"]);
  });

  it("keeps files, targets and code execution out of reach while negotiating wordlists and proxy", () => {
    // 仍然禁止：目标覆盖、输出文件、配置注入、代码执行/交互式 shell、越界字典。
    for (const bad of [["-o", "/tmp/x"], ["--output=/tmp/x"], ["-u", "https://other.test/"], ["--url", "https://other.test/"],
      ["--os-shell"], ["--sql-query", "select 1"], ["--eval", "print(1)"],
      ["-code"], ["--input-cmd", "id"], ["--config", "/tmp/c"], ["-w", "/etc/passwd"], ["-t", "../../x"]]) {
      expect(() => argsFor("recon.nuclei", { args: bad })).toThrow(ToolRejected);
    }
    // 代理不再一刀切禁用：值会被改写成操作员配置的内部 MITM 出口（未配置时丢弃），原地址绝不透传。
    const proxied = argsFor("recon.nuclei", { args: ["-proxy", "http://evil.test:8080"] });
    expect(proxied.join(" ")).not.toContain("evil.test");
    expect(() => argsFor("recon.nuclei", { args: "-severity critical" })).toThrow(/must be an array/);
    expect(() => argsFor("recon.nuclei", { args: Array.from({ length: 41 }, () => "-x") })).toThrow(/at most 40/);
    expect(() => argsFor("recon.nuclei", { args: ["-stats", "a\nb"] })).toThrow(/control characters/);
  });

  it("forwards explicit headers and the project cookie jar in each tool's native form", () => {
    const nuclei = argsFor("recon.nuclei", { headers: { Authorization: "Bearer t0ken", "X-Trace": "abc" } });
    expect(nuclei).toEqual(expect.arrayContaining(["-H", "authorization: Bearer t0ken", "-H", "x-trace: abc"]));
    // No explicit Cookie header: the jar is replayed so authenticated targets are scannable.
    expect(nuclei).toEqual(expect.arrayContaining(["-H", "Cookie: sid=s3cr3t; theme=dark"]));
    // sqlmap takes a raw cookie value, not a `Cookie:` header line.
    const sql = argsFor("recon.sql", {});
    expect(sql).toEqual(expect.arrayContaining(["--cookie", "sid=s3cr3t; theme=dark"]));
    // sqlmap receives headers as a single multi-line `--headers` value——包括默认浏览器 UA，
    // 不能拆成多条（它的 `--headers` 只取一个值，重复传会把前面的头挤掉）。
    const sqlHeaders = argsFor("recon.sql", { headers: { Authorization: "Bearer t0ken" } });
    expect(sqlHeaders.filter((arg) => arg === "--headers")).toHaveLength(1);
    const sqlHeaderValue = sqlHeaders[sqlHeaders.indexOf("--headers") + 1] ?? "";
    expect(sqlHeaderValue).toContain("authorization: Bearer t0ken");
    expect(sqlHeaderValue).toContain("user-agent: Mozilla/5.0");
    // An explicit Cookie header wins over the jar.
    const explicit = argsFor("recon.nuclei", { headers: { Cookie: "manual=1" } });
    expect(explicit).toEqual(expect.arrayContaining(["-H", "cookie: manual=1"]));
    expect(explicit.filter((arg) => arg.startsWith("Cookie: sid="))).toHaveLength(0);
    // Built-in browser tools are untouched by the jar here (they manage it themselves).
    expect(argsFor("recon.subdomains", {})).toEqual(["-d", "app.example.test", "-silent"]);
  });

  it("routes external tools through the operator's Burp proxy when configured", () => {
    const proxied = ctx({ BURP_PROXY_URL: "http://127.0.0.1:8080" });
    expect(argsFor("recon.nuclei", {}, proxied)).toEqual(expect.arrayContaining(["-proxy", "http://127.0.0.1:8080"]));
    expect(argsFor("recon.content_discovery", approvedWordlist(), proxied)).toEqual(expect.arrayContaining(["-x", "http://127.0.0.1:8080"]));
    expect(argsFor("recon.nuclei", {})).not.toContain("-proxy");
  });

  it("raises the per-tool clock on request and caps it", () => {
    expect(externalToolTimeoutMs("recon.nuclei", {})).toBe(300_000);
    expect(externalToolTimeoutMs("recon.sql", {})).toBe(600_000);
    expect(externalToolTimeoutMs("recon.nuclei", { timeout_seconds: 900 })).toBe(900_000);
    expect(externalToolTimeoutMs("recon.subdomains", { timeout_seconds: 600 })).toBe(600_000);
    expect(externalToolTimeoutMs("recon.nuclei", { timeout_seconds: 5000 })).toBe(900_000);
    expect(externalToolTimeoutMs("recon.nuclei", { timeout_seconds: 5 })).toBe(300_000);
  });

  it("keeps the structured fields a human would read from JSONL output", () => {
    const nuclei = parseNucleiLine(JSON.stringify({
      "template-id": "CVE-2021-44228", info: { name: "Log4j RCE", severity: "critical", tags: ["cve", "rce"] },
      type: "http", host: "app.example.test", "matched-at": "https://app.example.test/api?x=1", "matcher-name": "word",
      "extracted-results": ["jndi"], "curl-command": "curl -H 'Authorization: secret'",
    }));
    expect(nuclei).toMatchObject({ url: "https://app.example.test/api?x=1", template_id: "CVE-2021-44228", severity: "critical", matcher: "word" });
    expect(nuclei).not.toHaveProperty("curl_command");
    const httpx = parseHttpxLine(JSON.stringify({ url: "https://app.example.test/", status_code: 200, title: "Home", tech: ["nginx"], webserver: "nginx", content_length: 1024 }));
    expect(httpx).toMatchObject({ status_code: 200, title: "Home", tech: ["nginx"], content_length: 1024 });
    expect(parseNucleiLine("not json")).toBeNull();
    expect(parseHttpxLine("")).toBeNull();
  });

  it("does not leak credentials from extra args into the evidence ledger", () => {
    expect(redactArgs(["-H", "Authorization: Bearer abc123", "-H", "Cookie: sid=abc", "-stats"]))
      .toEqual(["-H", "Authorization: [redacted]", "-H", "Cookie: [redacted]", "-stats"]);
    expect(redactArgs(["-etags", "cve"])).toEqual(["-etags", "cve"]);
  });

  it("treats headers as part of the action identity but timeouts as tuning", () => {
    const progress = new BlackboxProgress();
    const base = { tool: "recon.nuclei", input: { url: target, params: { severity: "high" } } };
    const anon = progress.identity(base, target);
    const auth = progress.identity({ ...base, input: { ...base.input, headers: { Authorization: "Bearer x" } } }, target);
    const extended = progress.identity({ ...base, input: { ...base.input, timeout_seconds: 900 } }, target);
    expect(auth).not.toBe(anon);
    expect(extended).toBe(anon);
  });
});

function approvedWordlist(): { wordlist: string; wordlist_root: string } {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-capability-")); dirs.push(dir);
  const file = join(dir, "words.txt"); writeFileSync(file, "admin\n");
  return { wordlist: file, wordlist_root: dir };
}
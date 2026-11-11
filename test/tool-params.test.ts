import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { externalToolCommand, ToolRejected, type BlackboxToolContext } from "../src/blackbox/tools.js";

const dirs: string[] = [];
afterEach(() => { dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })); });
const target = "https://app.example.test/";
const ctx = (values: Record<string, string> = {}) => ({ target, values } as unknown as BlackboxToolContext);

describe("tool parameters", () => {
  it("maps allowlisted nuclei knobs to flags and keeps the safe defaults", () => {
    const { args, options } = externalToolCommand("recon.nuclei", target, {
      params: { severity: "critical,HIGH", tags: "cve,exposure", templates: "http/cves/", rate_limit: 25, concurrency: 3 },
    }, ctx());
    expect(args.slice(0, 6)).toEqual(["-u", target, "-jsonl", "-silent", "-disable-update-check", "-retries"]);
    // 默认值来自 scan_profile（timeout 10s / rate 50），模型显式 params 仍然优先。
    expect(args).toEqual(expect.arrayContaining(["-timeout", "10", "-bulk-size", "25", "-concurrency", "3", "-rate-limit", "25"]));
    expect(args).toEqual(expect.arrayContaining(["-severity", "critical,high", "-tags", "cve,exposure", "-t", "http/cves/"]));
    expect(options.values).toMatchObject({ severity: "critical,high", rate_limit: "25" });

    const defaults = externalToolCommand("recon.nuclei", target, {}, ctx()).args;
    expect(defaults).toContain("-rate-limit");
    expect(defaults[defaults.indexOf("-rate-limit") + 1]).toBe("50");
    expect(defaults[defaults.indexOf("-concurrency") + 1]).toBe("10");
    expect(defaults).toEqual(expect.arrayContaining(["-severity", "critical,high,medium", "-retries", "0", "-timeout", "10"]));
  });

  it("maps sqlmap knobs and keeps level/risk conservative by default", () => {
    const { args } = externalToolCommand("recon.sql", target, {
      params: { level: 3, risk: 1, technique: "BE", dbms: "mysql", data: "user=admin&pass=1", param: "user" },
    }, ctx());
    expect(args.slice(0, 5)).toEqual(["-u", target, "--batch", "--smart", "--level=3"]);
    expect(args).toContain("--risk=1");
    expect(args).toContain("--technique=BE");
    expect(args).toContain("--dbms=mysql");
    const dataAt = args.indexOf("--data");
    expect(args.slice(dataAt, dataAt + 4)).toEqual(["--data", "user=admin&pass=1", "-p", "user"]);
    // 默认浏览器 UA 必须跟着走，且 sqlmap 的 --headers 只能出现一次（单值 flag，
    // 重复传会让前面的头被静默丢掉）。
    expect(args.filter(item => item === "--headers")).toHaveLength(1);
    const headerAt = args.indexOf("--headers");
    expect(headerAt).toBeGreaterThan(-1);
    expect(args[headerAt + 1]).toContain("user-agent: Mozilla/5.0");
    const defaults = externalToolCommand("recon.sql", target, {}, ctx()).args;
    expect(defaults).toEqual(expect.arrayContaining(["--level=1", "--risk=1", "--threads=1"]));
  });

  it("maps ffuf knobs and validates the wordlist root", () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-params-")); dirs.push(dir);
    const wordlist = join(dir, "words.txt"); writeFileSync(wordlist, "admin\n");
    const { args } = externalToolCommand("recon.content_discovery", target, {
      wordlist, wordlist_root: dir, params: { rate: 30, extensions: "php,html", method: "post" },
    }, ctx());
    // 2026-10-28：ffuf 调用加了 `-ac`（自动校准）+ `-mc`（状态码白名单）。
    // 起因是 note.yun 目标对任意路径都返回 301（catch-all），ffuf 把整本字典 224 条
    // 全当命中，图里凭空多出 224 个“端点”，agent 之后再也没看过它们。
    // 2026-10-30：412/418 必须留在白名单里——云 WAF 的阻断码（securityfs=412）被排除后，
    // 字典撞墙的结果是"0 发现"，墙在账本里消失，waf_escalation 与战例库都不会被触发。
    expect(args.slice(0, 8)).toEqual(["-u", `${target}FUZZ`, "-w", wordlist, "-s", "-ac", "-mc", "200,201,202,204,206,301,302,303,307,308,401,403,405,412,418,500"]);
    expect(args.slice(8, 10)).toEqual(["-rate", "30"]);
    const methodAt = args.indexOf("-X");
    expect(args.slice(methodAt, methodAt + 2)).toEqual(["-X", "POST"]);
    const extensionsAt = args.indexOf("-e");
    expect(args.slice(extensionsAt, extensionsAt + 2)).toEqual(["-e", "php,html"]);
  });

  it("maps naabu, httpx and testssl knobs", () => {
    const ports = externalToolCommand("recon.ports", target, { params: { ports: "80,443,8000-8100", rate: 200 } }, ctx()).args;
    expect(ports.slice(0, 3)).toEqual(["-host", "app.example.test", "-silent"]);
    expect(ports.slice(ports.indexOf("-p"))).toEqual(["-p", "80,443,8000-8100", "-rate", "200"]);
    expect(externalToolCommand("recon.http_probe", target, { params: { ports: "8080", threads: 5 } }, ctx()).args)
      .toEqual(expect.arrayContaining(["-ports", "8080", "-threads", "5"]));
    expect(externalToolCommand("recon.tls", target, { params: { severity: "high" } }, ctx()).args)
      .toEqual(["--warnings", "batch", "--quiet", "--severity", "HIGH", target]);
  });

  it("顶层 threads 折进 params：写在两层都生效，显式 params 优先", () => {
    // 2026-11-06 实测：模型把 threads 写在顶层，被 schema 摘掉后回执只说"可用：url, params"，
    // 于是它认为这个工具不能调并发、再没调用过（21 场里只调了 1 次内容发现）。
    const folded = externalToolCommand("recon.content_discovery", target, { threads: 25 }, ctx());
    expect(folded.options.values).toMatchObject({ threads: "25" });
    expect(folded.args.slice(folded.args.indexOf("-t"), folded.args.indexOf("-t") + 2)).toEqual(["-t", "25"]);
    const explicit = externalToolCommand("recon.content_discovery", target, { threads: 25, params: { threads: 5 } }, ctx());
    expect(explicit.options.values).toMatchObject({ threads: "5" });
    // naabu 没有 threads 概念，同样是"并发"的意思，折到 -rate。
    expect(externalToolCommand("recon.ports", target, { threads: 30 }, ctx()).args)
      .toEqual(expect.arrayContaining(["-rate", "30"]));
  });

  it("rejects unknown keys, out-of-range values and tools without params", () => {
    expect(() => externalToolCommand("recon.nuclei", target, { params: { fuzz: "x" } }, ctx()))
      .toThrow(/unknown parameter "fuzz" for recon\.nuclei; allowed: severity, tags, templates, timeout_s, rate_limit, concurrency, retries/);
    expect(() => externalToolCommand("recon.sql", target, { params: { level: 5 } }, ctx())).toThrow(/level must be an integer between 1 and 3/);
    expect(() => externalToolCommand("recon.sql", target, { params: { level: 1.5 } }, ctx())).toThrow(ToolRejected);
    expect(() => externalToolCommand("recon.sql", target, { params: { technique: "ZZ" } }, ctx())).toThrow(/technique has an invalid value/);
    expect(() => externalToolCommand("recon.subdomains", target, { params: { threads: 2 } }, ctx())).toThrow(/accepts no input\.params/);
    expect(() => externalToolCommand("recon.nuclei", target, { params: { templates: "../../etc/passwd" } }, ctx())).toThrow(/must be a relative path without/);
    expect(() => externalToolCommand("recon.nuclei", target, { params: { templates: "/etc/passwd" } }, ctx())).toThrow(ToolRejected);
    expect(() => externalToolCommand("recon.nuclei", target, { params: "severity=high" }, ctx())).toThrow(/must be an object/);
  });

  it("does not accept params on built-in tools", () => {
    expect(() => externalToolCommand("http.request", target, { params: { rate: 1 } }, ctx())).toThrow(/unsupported external reconnaissance tool/);
  });
});

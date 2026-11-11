import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { externalToolCommand, approvedFilePath } from "../src/blackbox/tools.js";

const ctx = (values: Record<string, string> = {}) => ({ values, target: "https://example.test/" }) as never;

describe("external recon defaults", () => {
  it("falls back to the bundled paths wordlist instead of rejecting the tool", () => {
    // The unauth/exposure playbook starts with a directory probe; a missing wordlist argument
    // used to reject the call outright, which silently killed the whole playbook.
    const { args } = externalToolCommand("recon.content_discovery", "https://example.test/", {}, ctx());
    const index = args.indexOf("-w");
    expect(index).toBeGreaterThan(-1);
    expect(args[index + 1]).toMatch(/paths\.txt$/);
    expect(args.indexOf("FUZZ")).toBe(-1);
    expect(args.join(" ")).toContain("/FUZZ");
  });

  it("keeps an explicit wordlist and refuses one outside the approved root", () => {
    const inside = approvedFilePath("resources/wordlists/sqli.txt");
    expect(inside).toBe("resources/wordlists/sqli.txt");
    expect(() => approvedFilePath("/etc/passwd")).toThrow(/approved wordlist directory/);
    const { args } = externalToolCommand("recon.content_discovery", "https://example.test/", { wordlist: inside }, ctx());
    // 解析后统一给绝对路径，交给 CLI 时不再依赖进程 cwd。
    expect(args[args.indexOf("-w") + 1]).toMatch(/resources[\\/]wordlists[\\/]sqli\.txt$/);
    expect(() => externalToolCommand("recon.content_discovery", "https://example.test/", { wordlist: "/etc/passwd" }, ctx()))
      .toThrow(/not inside the approved roots/);
  });

  it("falls back to any mounted list instead of rejecting a tool with no bundled default", () => {
    // api_routes 以前没字典就直接拒绝（实测两次 tool-rejected）；现在按 recon.wordlists 的结果兜底。
    const { args } = externalToolCommand("recon.api_routes", "https://example.test/", {}, ctx());
    const wordlist = args[1]; // kiterunner 的字典是位置参数：scan <wordlist> ...
    expect(wordlist).toBeTruthy();
    expect(existsSync(wordlist!)).toBe(true);
  });

  it("puts the testssl target last so the CLI does not abort with URI comes last", () => {
    const { args } = externalToolCommand("recon.tls", "https://example.test/", {}, ctx());
    expect(args[args.length - 1]).toBe("https://example.test/");
    expect(args.filter(item => item === "https://example.test/")).toHaveLength(1);
  });
});
describe("recon.dns 的单目标形态", () => {
  /**
   * 实跑 090e71cc2732165e（im.ctrip.com，2026-11-02）：
   * 模型调 recon.dns 想解析证书 SAN 里的域名，输入是空的（目标取自会话资产），
   * 于是走 `-d` 分支，dnsx 当场 exit 1：
   *   `[FTL] missing wordlist(w) flag required with domain(d) input`
   * ——dnsx 的 `-d` 是"对域做子域爆破"，必须配 `-w`；单个主机解析要走 `-l`。
   */
  it("把目标写成一行列表交给 -l，而不是用需要 -w 的 -d", () => {
    const dir = mkdtempSync(join(tmpdir(), "nianyun-dns-"));
    const real = { projectId: "p", sessionId: "s", cfg: { data_dir: dir }, values: {}, target: "https://im.ctrip.com/" } as never;
    const { args } = externalToolCommand("recon.dns", "https://im.ctrip.com/", {}, real);
    expect(args).toContain("-l");
    expect(args).not.toContain("-d");
    const list = args[args.indexOf("-l") + 1]!;
    expect(readFileSync(list, "utf8").trim()).toBe("im.ctrip.com");
    rmSync(dir, { recursive: true, force: true });
  });
});

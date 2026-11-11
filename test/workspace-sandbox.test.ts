import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Database } from "../src/shared/db.js";
import { loadConfig } from "../src/shared/config.js";
import { createProject } from "../src/control/console/workspace.js";
import { importAssetCandidates } from "../src/asset/candidates.js";
import {
  DEFAULT_SCAN_PROFILE, fsGrep, fsList, fsRead, jailPath, listWordlists, readScanProfile,
  resolveApprovedAsset, runSandbox, wordlistRoots, writeScanProfile,
} from "../src/blackbox/workspace.js";
import { executeBlackboxTool, extraToolArgs, type BlackboxToolContext } from "../src/blackbox/tools.js";

const dirs: string[] = [];
const databases: Database[] = [];
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true }));
});

const hasCommand = (command: string, args: string[]) => {
  try {
    spawnSync(command, args, { stdio: "ignore" });
    return true;
  } catch { return false; }
};
const sandboxPythons = process.platform === "win32" ? ["python"] : ["python3"];
const hasPython = sandboxPythons.some(command => hasCommand(command, ["--version"]));
const hasBash = process.platform !== "win32" && hasCommand("bash", ["--version"]);

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-workspace-")); dirs.push(dir);
  mkdirSync(join(dir, "data"));
  const wordlists = join(dir, "wordlists"); mkdirSync(wordlists);
  writeFileSync(join(wordlists, "api.txt"), "admin\nlogin\n");
  writeFileSync(join(wordlists, "paths.txt"), "backup\n.git\n");
  const templates = join(dir, "nuclei-templates"); mkdirSync(join(templates, "http"), { recursive: true });
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  cfg.execution = { mode: "execute", source: "config" };
  Object.assign(cfg.tools_env.values, { NIANYUN_WORDLIST_ROOT: wordlists, NUCLEI_TEMPLATES_PATH: templates, BURP_PROXY_REQUIRED: "false" });
  const db = new Database(join(dir, "data", "nianyun.db")); databases.push(db);
  const pid = String(createProject(cfg, "Workspace", "test").id);
  const candidate = importAssetCandidates(db, pid, [{ value: "http://127.0.0.1:1/", source: "test" }]).accepted[0]!;
  const sid = String(db.createBlackboxSession(pid, String(candidate.id), "http://127.0.0.1:1/").id);
  const ctx: BlackboxToolContext = { cfg, db, projectId: pid, sessionId: sid, target: "http://127.0.0.1:1/", values: cfg.tools_env.values };
  return { ctx, dir, wordlists, templates };
}

describe("workspace, sandbox and negotiation", () => {
  it("lists mounted wordlists and resolves only paths inside the approved roots", () => {
    const f = fixture();
    const listed = listWordlists(f.ctx);
    expect(listed.roots).toContain(f.wordlists);
    expect(listed.wordlists.map(item => item.name)).toEqual(expect.arrayContaining(["api.txt", "paths.txt"]));
    expect(listed.templates.length).toBe(1);
    expect(resolveApprovedAsset(f.ctx, "api.txt", { roots: wordlistRoots(f.ctx), label: "wordlist" })).toBe(join(f.wordlists, "api.txt"));
    // 没给值时按类别挑默认，不再"必须知道路径"
    expect(resolveApprovedAsset(f.ctx, "", { roots: wordlistRoots(f.ctx), label: "wordlist", category: "api" })).toBe(join(f.wordlists, "api.txt"));
    expect(() => resolveApprovedAsset(f.ctx, "../../etc/passwd", { roots: wordlistRoots(f.ctx), label: "wordlist" })).toThrow(/not inside the approved roots/);
    expect(() => resolveApprovedAsset(f.ctx, "https://evil.test/a.txt", { roots: wordlistRoots(f.ctx), label: "wordlist" })).toThrow(/must be a local path/);
  });

  it("serves recon.wordlists so the model stops guessing paths", async () => {
    const f = fixture();
    const result = await executeBlackboxTool(f.ctx, { tool: "recon.wordlists", input: {} });
    expect(result.ok).toBe(true);
    expect(result.data.wordlist_roots).toContain(f.wordlists);
    expect((result.data.wordlists as Array<{ name: string }>).map(item => item.name)).toContain("api.txt");
    expect(String(result.data.usage)).toContain("recon.wordlists");
  });

  it("negotiates and persists a scan profile inside hard bounds", async () => {
    const f = fixture();
    expect(readScanProfile(f.ctx)).toEqual(DEFAULT_SCAN_PROFILE);
    const updated = await executeBlackboxTool(f.ctx, { tool: "recon.scan_profile", input: { timeout_s: 30, rate_limit: 20, katana_depth: 8, katana_duration_s: 300 } });
    expect(updated.ok).toBe(true);
    expect(readScanProfile(f.ctx)).toMatchObject({ timeout_s: 30, rate_limit: 20, katana_depth: 8, katana_duration_s: 300 });
    // 越界值被夹紧，不会出现"50 秒 timeout / 1 万并发"这种把目标打挂的配置
    writeScanProfile(f.ctx, { timeout_s: 9999, rate_limit: 0, katana_depth: 99 });
    expect(readScanProfile(f.ctx)).toMatchObject({ timeout_s: 60, rate_limit: 5, katana_depth: 8 });
    await executeBlackboxTool(f.ctx, { tool: "recon.scan_profile", input: { reset: true } });
    expect(readScanProfile(f.ctx)).toEqual(DEFAULT_SCAN_PROFILE);
  });

  it.skipIf(!hasPython || !hasBash)("runs python and bash in a throwaway sandbox with capped output", async () => {
    const f = fixture();
    const python = await executeBlackboxTool(f.ctx, { tool: "exec.python", input: { code: "print('poc-ok', 6 * 7)" } });
    expect(python.ok).toBe(true);
    expect(python.data.stdout).toContain("poc-ok 42");
    expect(python.data.isolation).toBe("process-jail");
    expect(existsSync(join(f.dir, "data", "workspace", f.ctx.projectId, f.ctx.sessionId, String(python.data.stdout_artifact)))).toBe(true);
    const bash = await executeBlackboxTool(f.ctx, { tool: "exec.bash", input: { script: "printf 'dir-ok\\n'; pwd" } });
    expect(bash.ok).toBe(true);
    expect(bash.data.stdout).toContain("dir-ok");
    // 超时被杀掉并如实标记，而不是把整场 run 卡住
    const slow = await executeBlackboxTool(f.ctx, { tool: "exec.python", input: { code: "import time; time.sleep(30)", timeout_s: 5 } });
    expect(slow.ok).toBe(false);
    expect(slow.data.timed_out).toBe(true);
    expect(slow.duration_ms).toBeLessThan(20_000);
  }, 120_000);

  it("jails the workspace filesystem and greps run records", async () => {
    const f = fixture();
    await executeBlackboxTool(f.ctx, { tool: "recon.scan_profile", input: { timeout_s: 25 } });
    const listed = await executeBlackboxTool(f.ctx, { tool: "fs.list", input: { path: "runs" } });
    expect(listed.ok).toBe(true);
    const read = await executeBlackboxTool(f.ctx, { tool: "fs.read", input: { path: ".scan-profile.json" } });
    expect(read.ok).toBe(true);
    expect(String(read.data.text)).toContain("\"timeout_s\": 25");
    const grepped = await executeBlackboxTool(f.ctx, { tool: "fs.grep", input: { pattern: "timeout_s", path: "" } });
    expect(grepped.ok).toBe(true);
    expect((grepped.data.matches as unknown[]).length).toBeGreaterThan(0);
    expect(() => jailPath("/srv/workspace", "../../etc/passwd")).toThrow(/escapes the workspace/);
    await expect(executeBlackboxTool(f.ctx, { tool: "fs.read", input: { path: "../../../../etc/passwd" } })).rejects.toThrow(/escapes the workspace/);
  });

  it("keeps deny-lists but negotiates wordlists, templates and proxy", () => {
    const f = fixture();
    const roots = { wordlistRoots: wordlistRoots(f.ctx), templateRoots: [f.templates], proxyUrl: "http://burp.internal:8080" };
    const args = extraToolArgs("recon.nuclei", ["-w", "api.txt", "-t=http", "-proxy", "http://attacker:1", "-severity", "high"], roots);
    expect(args).toEqual(["-w", join(f.wordlists, "api.txt"), "-t", join(f.templates, "http"), "-proxy", "http://burp.internal:8080", "-severity", "high"]);
    expect(() => extraToolArgs("recon.nuclei", ["-w", "../../etc/passwd"], roots)).toThrow(/not inside the approved roots/);
    // 交互式 shell 永久禁止；单命令执行需要操作员开关
    expect(() => extraToolArgs("recon.sql", ["--os-shell"], roots)).toThrow(/interactive OS shell/);
    expect(() => extraToolArgs("recon.sql", ["--os-cmd", "id"], roots)).toThrow(/BLACKBOX_ALLOW_INTERACTIVE_EXEC/);
    expect(extraToolArgs("recon.sql", ["--os-cmd", "id"], { ...roots, interactive: true })).toEqual(["--os-cmd", "id"]);
    // 开一次即整场可用：连续两次调用都放行（不做 per-call 确认），但每次都要留审计 note。
    const notes: string[] = [];
    for (const target of ["http://bdev.oppo.com/a?id=1", "http://bdev.oppo.com/b?id=2"]) {
      const passed = extraToolArgs("recon.sql", ["--sql-query", "select 1"], { ...roots, interactive: true, onNote: note => notes.push(note) });
      expect(passed).toEqual(["--sql-query", "select 1"]);
      expect(target).toMatch(/^http:/);
    }
    expect(notes).toHaveLength(2);
    expect(notes[0]).toMatch(/--sql-query/);
    expect(notes[0]).toMatch(/BLACKBOX_ALLOW_INTERACTIVE_EXEC=true/);
    // 永久墙不受开关影响。
    expect(() => extraToolArgs("recon.sql", ["--os-shell"], { ...roots, interactive: true })).toThrow(/interactive OS shell/);
    expect(() => extraToolArgs("recon.nuclei", ["-u", "http://other/"], roots)).toThrow(/target override/);
  });

  it("writes a greppable run record for every tool result", async () => {
    const f = fixture();
    const result = await executeBlackboxTool(f.ctx, { tool: "recon.wordlists", input: {}, task_id: "T1" });
    expect(result.ok).toBe(true);
    // executeBlackboxTool 本身不写账本；执行入口 executeAndRecordBlackboxTool 才写 runs/。
    expect(fsList(f.ctx, "runs").entries.length).toBe(0);
    const workspace = join(f.dir, "data", "workspace", f.ctx.projectId, f.ctx.sessionId);
    mkdirSync(join(workspace, "runs"), { recursive: true });
    writeFileSync(join(workspace, "runs", "1-recon_wordlists.json"), JSON.stringify({ tool: "recon.wordlists", ok: true }));
    expect(fsList(f.ctx, "runs").entries.length).toBe(1);
    expect(fsGrep(f.ctx, "recon.wordlists").matches.length).toBe(1);
    expect(readFileSync(join(workspace, "runs", "1-recon_wordlists.json"), "utf8")).toContain("recon.wordlists");
  });
});





describe("三层漏斗路由", () => {
  it("marks the layer of each tool result", async () => {
    const { toolLayer } = await import("../src/blackbox/routing.js");
    expect(toolLayer("exec.python")).toBe("strategic");
    expect(toolLayer("exec.bash")).toBe("strategic");
    expect(toolLayer("recon.nuclei")).toBe("tactical");
    expect(toolLayer("http.request")).toBe("tactical");
    expect(toolLayer("burp.history")).toBe("tactical");
  });

  it("rejects bare CLI passthrough and points at the tactical tool", async () => {
    const { trivialPassthrough } = await import("../src/blackbox/routing.js");
    // 裸调标准 CLI：绕远路，直接拒绝并给替代工具。
    expect(trivialPassthrough("exec.bash", { script: "httpx -u http://example.com -silent" })).toMatchObject({ tool: "recon.http_probe" });
    expect(trivialPassthrough("exec.bash", { script: "nuclei -u http://x -t http/misc" })?.tool).toBe("recon.nuclei");
    expect(trivialPassthrough("exec.bash", { script: "sqlmap -u http://x/?id=1" })?.tool).toBe("recon.sql");
    // 单发 HTTP 的 python 片段同理。
    expect(trivialPassthrough("exec.python", { code: "import requests\nr = requests.get('http://x')\nprint(r.status_code)" })?.tool).toBe("http.request");
    expect(trivialPassthrough("exec.python", { code: "import urllib.request\nprint(urllib.request.urlopen('http://x').status)" })?.tool).toBe("http.request");
    // 真正的组合脚本必须放行：管道、重定向、循环、多步、状态读写。
    expect(trivialPassthrough("exec.bash", { script: "httpx -u http://x -silent | sort -u > /state/hosts.txt" })).toBeUndefined();
    expect(trivialPassthrough("exec.bash", { script: "for h in a b; do httpx -u http://$h -silent; done" })).toBeUndefined();
    expect(trivialPassthrough("exec.python", { code: "import requests\nfor i in range(10):\n    requests.get(f'http://x/{i}')" })).toBeUndefined();
    // 显式逃生门。
    expect(trivialPassthrough("exec.bash", { script: "httpx -u http://x", force_sandbox: true })).toBeUndefined();
  });
});
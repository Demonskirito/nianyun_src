import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { externalToolCommand } from "../src/blackbox/tools.js";

const ctxWithData = (dataDir: string, values: Record<string, string> = {}) => ({ values, target: "https://example.test/", cfg: { data_dir: dataDir } }) as never;

describe("nuclei defaults", () => {
  it("points -t at the templates directory in the data volume", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "nianyun-nuclei-"));
    mkdirSync(join(dataDir, "nuclei-templates", "http", "cves"), { recursive: true });
    writeFileSync(join(dataDir, "nuclei-templates", "http", "cves", "fixture.yaml"), "id: fixture\n");
    const { args } = externalToolCommand("recon.nuclei", "https://example.test/", {}, ctxWithData(dataDir));
    const index = args.indexOf("-t");
    expect(index).toBeGreaterThan(-1);
    // 只有 http/cves 存在，所以默认范围收敛成这一个目录
    expect(args[index + 1]).toBe(join(dataDir, "nuclei-templates", "http", "cves"));
  });

  it("scopes the default run to the high-value template directories", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "nianyun-nuclei-"));
    const root = join(dataDir, "nuclei-templates");
    for (const scope of ["http/cves", "http/exposures", "http/misconfiguration"]) mkdirSync(join(root, scope), { recursive: true });
    const { args } = externalToolCommand("recon.nuclei", "https://example.test/", {}, ctxWithData(dataDir));
    const targets = args.reduce<string[]>((list, item, index) => item === "-t" ? [...list, String(args[index + 1])] : list, []);
    expect(targets).toEqual([join(root, "http/cves"), join(root, "http/exposures"), join(root, "http/misconfiguration")]);
    expect(args.join(" ")).toContain("-concurrency 10");
  });

  it("keeps an explicit template selection and adds nothing twice", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "nianyun-nuclei-"));
    mkdirSync(join(dataDir, "nuclei-templates"), { recursive: true });
    const { args } = externalToolCommand("recon.nuclei", "https://example.test/", { params: { templates: "custom/tpl" } }, ctxWithData(dataDir));
    expect(args.filter(item => item === "-t")).toHaveLength(1);
    expect(args[args.indexOf("-t") + 1]).toBe("custom/tpl");
  });

  it("leaves the command untouched when no templates exist", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "nianyun-nuclei-"));
    const { args } = externalToolCommand("recon.nuclei", "https://example.test/", {}, ctxWithData(dataDir));
    expect(args).not.toContain("-t");
  });

  it("accepts NUCLEI_TEMPLATES_PATH from tool settings", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "nianyun-nuclei-"));
    const custom = join(dataDir, "elsewhere");
    mkdirSync(custom, { recursive: true });
    const { args } = externalToolCommand("recon.nuclei", "https://example.test/", {}, ctxWithData(dataDir, { NUCLEI_TEMPLATES_PATH: custom }));
    expect(args[args.indexOf("-t") + 1]).toBe(custom);
  });
});
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { defaultToolsEnvPath, loadToolsEnv, type ToolsEnv } from "./tools-env.js";
import { executionPolicy, type ExecutionPolicy } from "./execution.js";

const ENV_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

function expandEnv(value: unknown): unknown {
  if (typeof value === "string") {
    return value.replace(ENV_PATTERN, (_m, name: string) => process.env[name] || "");
  }
  if (Array.isArray(value)) return value.map(expandEnv);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, expandEnv(v)]),
    );
  }
  return value;
}

function loadDotenv(root: string): void {
  const envFile = join(root, ".env");
  if (!existsSync(envFile)) return;
  try {
    for (const line of readFileSync(envFile, "utf8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq < 1) continue;
      const k = t.slice(0, eq).trim();
      let v = t.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      if (process.env[k] === undefined) process.env[k] = v;
    }
  } catch {
    /* ignore */
  }
}

export type Config = {
  execution: ExecutionPolicy;
  data_dir: string;
  repo_root: string;
  tools_env_path: string;
  tools_env: ToolsEnv;
  db_path: string;
};

export function loadConfig(path?: string | null, repoRoot?: string | null): Config {
  const root = resolve(repoRoot || process.cwd());
  loadDotenv(root);
  const cfgPath = path ? resolve(path) : join(root, "config.yaml");
  let raw: Record<string, unknown> = {};
  if (existsSync(cfgPath)) {
    raw = (expandEnv(parseYaml(readFileSync(cfgPath, "utf8")) || {}) || {}) as Record<string, unknown>;
  }
  if (raw.execution !== undefined && (!raw.execution || typeof raw.execution !== "object" || Array.isArray(raw.execution))) throw new Error("invalid execution configuration");
  const docker = (raw.docker || {}) as Record<string, unknown>;
  const paths = (raw.paths || {}) as Record<string, unknown>;

  let dataDir = String(paths.data_dir || "data");
  if (!isAbsolute(dataDir)) dataDir = join(root, dataDir);

  let toolsEnvPath = String(paths.tools_env || docker.tools_env || "tools.env.yaml");
  if (!isAbsolute(toolsEnvPath)) toolsEnvPath = join(root, toolsEnvPath);
  if (!existsSync(toolsEnvPath)) {
    const alt = defaultToolsEnvPath(root);
    if (existsSync(alt)) toolsEnvPath = alt;
  }

  return {
    execution: executionPolicy((raw.execution as Record<string, unknown> | undefined)?.mode),
    data_dir: dataDir,
    repo_root: root,
    tools_env_path: toolsEnvPath,
    tools_env: loadToolsEnv(toolsEnvPath),
    db_path: join(dataDir, "nianyun.db"),
  };
}

export function ensureDirs(cfg: Config): void {
  mkdirSync(cfg.data_dir, { recursive: true });
  mkdirSync(dirname(cfg.db_path), { recursive: true });
}

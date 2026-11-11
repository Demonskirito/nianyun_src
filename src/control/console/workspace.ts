import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { Config } from "../../shared/config.js";
import { nowSec } from "../../shared/fsutil.js";
import { normalizeAutomation, type AssetAutomation } from "../../asset/automation.js";
import { readLedger, writeLedger, type Ledger } from "../../shared/project-ledger.js";

const PROJECT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function safeProjectId(projectId: string | null | undefined): string | null {
  const pid = (projectId || "").trim();
  if (!pid || pid.includes("/") || pid.includes("\\") || pid.includes("..")) return null;
  if (!PROJECT_ID_RE.test(pid)) return null;
  return pid;
}

export function projectRootDir(cfg: Config, projectId: string | null | undefined): string | null {
  const pid = safeProjectId(projectId);
  if (!pid) return null;
  return join(cfg.data_dir, "projects", pid);
}

export function storePath(cfg: Config): string {
  return join(cfg.data_dir, "console", "ledger.json");
}

function makeId(prefix: string): string {
  return `${prefix}_${randomBytes(5).toString("hex")}`;
}

function projectView(project: Record<string, unknown>): Record<string, unknown> {
  const item = { ...project };
  const settings = item.settings;
  item.settings = settings && typeof settings === "object" && !Array.isArray(settings) ? { ...settings } : {};
  delete item.scope;
  item.automation = item.automation && typeof item.automation === "object" && !Array.isArray(item.automation) ? { ...(item.automation as Record<string, unknown>) } : null;
  return item;
}

export function ensureDefault(cfg: Config): Ledger {
  const data = readLedger(cfg);
  if (!existsSync(storePath(cfg))) {
    data.projects.push({ id: makeId("p"), name: "Ledger", note: "Default book", created_at: nowSec(), updated_at: nowSec() });
    writeLedger(cfg, data);
  }
  return data;
}

export function listProjects(cfg: Config): Record<string, unknown>[] {
  const data = readLedger(cfg);
  const out = data.projects.map((p) => projectView(p));
  out.sort((a, b) => Number(b.updated_at || 0) - Number(a.updated_at || 0));
  return out;
}

export function getProject(cfg: Config, projectId: string): Record<string, unknown> | null {
  for (const p of readLedger(cfg).projects) {
    if (p.id === projectId) return projectView(p);
  }
  return null;
}

export function createProject(cfg: Config, name: string, note = ""): Record<string, unknown> {
  const title = (name || "").trim();
  if (!title) throw new Error("project needs a name");
  const rec: Record<string, unknown> = {
    id: makeId("p"),
    name: title.slice(0, 80),
    note: (note || "").trim().slice(0, 400),
    settings: {},
    automation: null,
    created_at: nowSec(),
    updated_at: nowSec(),
  };
  const data = readLedger(cfg);
  data.projects.push(rec);
  writeLedger(cfg, data);
  return rec;
}

export function deleteProject(cfg: Config, projectId: string): boolean {
  const data = readLedger(cfg);
  const before = data.projects.length;
  data.projects = data.projects.filter((p) => p.id !== projectId);
  data.tasks = data.tasks.filter((t) => t.project_id !== projectId);
  if (data.projects.length === before) return false;
  writeLedger(cfg, data);
  return true;
}

export function setProjectSettings(
  cfg: Config,
  projectId: string,
  overrides: Record<string, unknown>,
): Record<string, unknown> | null {
  const pid = (projectId || "").trim();
  if (!pid) return null;
  const data = readLedger(cfg);
  let found: Record<string, unknown> | null = null;
  for (const p of data.projects) {
    if (p.id !== pid) continue;
    p.settings = { ...overrides };
    p.updated_at = nowSec();
    found = projectView(p);
    break;
  }
  if (!found) return null;
  writeLedger(cfg, data);
  return found;
}

export function setProjectAutomation(
  cfg: Config,
  projectId: string,
  rawAutomation: unknown,
): Record<string, unknown> | null {
  const pid = (projectId || "").trim();
  if (!pid) return null;
  const automation = normalizeAutomation(rawAutomation);
  const data = readLedger(cfg);
  let found: Record<string, unknown> | null = null;
  for (const p of data.projects) {
    if (p.id !== pid) continue;
    p.automation = automation;
    p.updated_at = nowSec();
    found = projectView(p);
    break;
  }
  if (!found) return null;
  writeLedger(cfg, data);
  return found;
}

export function getProjectAutomation(cfg: Config, projectId: string): AssetAutomation | null {
  const project = getProject(cfg, projectId);
  if (!project?.automation || typeof project.automation !== "object") return null;
  return normalizeAutomation(project.automation);
}

export function ensureProjectDir(cfg: Config, projectId: string): string {
  const root = projectRootDir(cfg, projectId);
  if (!root) throw new Error("invalid project id");
  mkdirSync(root, { recursive: true });
  return root;
}

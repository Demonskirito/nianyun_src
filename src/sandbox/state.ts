import { chmodSync, existsSync, mkdirSync, readdirSync, rmSync, statSync, unlinkSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import type { SandboxDriverConfig } from "./driver.js";

export type SandboxStateEntry = { path: string; bytes: number; mtime_s: number };

export type SandboxStateSummary = {
  key: string;
  /** 容器内路径（agent 看到的）。 */
  mount: string;
  /** 服务侧路径（排障用）。 */
  root: string;
  files: number;
  bytes: number;
  /** 超出配额被删掉的文件数。 */
  pruned: number;
  /** 其中来自 auth/（受保护带）的个数——>0 说明配额真的不够用了。 */
  pruned_protected: number;
  /** 各命名空间用量。 */
  bands: Record<StateBand, { files: number; bytes: number }>;
  /** 裁完之后仍然超配额（只剩 rpc/ 等 pinned 文件时会这样）。 */
  over_quota: boolean;
  truncated: boolean;
  entries: SandboxStateEntry[];
};

type StateConfig = Pick<SandboxDriverConfig, "stateRoot" | "stateMaxMb" | "stateMaxFiles" | "stateTtlH">;

/**
 * /state 命名空间与裁剪优先级。
 *
 * 之前是"全局最旧优先"，问题很实在：脚本把刚逆出来的签名密钥写进某个文件，
 * 然后往 /state 丢了 20 个响应体，裁剪把密钥删了——Agent 下一步读不到，还以为密钥算错了。
 *
 * 所以按**用途分带**，裁剪从"用完即弃"的那一带动手：
 *
 *   volatile  /state/poc/  /state/tmp/     一次性 POC、抓下来的样本；先死
 *   normal    /state/recon/ 其余           端点、路径、中间结果
 *   protected /state/auth/                 签名密钥、Token、Cookie；只在前两带清空后仍超配额才动
 *   pinned    /state/rpc/                  电台协议队列；永不裁剪（删了等于把待执行的 RPC 吞掉）
 */
export type StateBand = "volatile" | "normal" | "protected" | "pinned";

const BAND_BY_PREFIX: Array<{ prefix: string; band: StateBand }> = [
  { prefix: "poc/", band: "volatile" },
  { prefix: "tmp/", band: "volatile" },
  { prefix: "auth/", band: "protected" },
  { prefix: "rpc/", band: "pinned" },
];

/** 路径 → 所属带。未命中的都算 normal（含根目录下的散文件）。 */
export function stateBand(path: string): StateBand {
  const normalized = String(path || "").replace(/^\/+/, "");
  for (const item of BAND_BY_PREFIX) if (normalized.startsWith(item.prefix)) return item.band;
  return "normal";
}

/** 命名空间用量（按带聚合，供 /state 摘要与提示词用）。 */
export function bandUsage(entries: SandboxStateEntry[]): Record<StateBand, { files: number; bytes: number }> {
  const usage = {
    volatile: { files: 0, bytes: 0 },
    normal: { files: 0, bytes: 0 },
    protected: { files: 0, bytes: 0 },
    pinned: { files: 0, bytes: 0 },
  } as Record<StateBand, { files: number; bytes: number }>;
  for (const entry of entries) {
    const band = stateBand(entry.path);
    usage[band].files += 1;
    usage[band].bytes += entry.bytes;
  }
  return usage;
}

/**
 * 纯函数：算出要删哪些文件。测试与线上走同一份逻辑。
 * 顺序 volatile → normal → protected；pinned 永不删。
 * 同一带内按 mtime 最旧优先，但 **每带至少保留最新一个文件**（刚写的那个不能被自己挤掉）。
 */
export function planStatePrune(
  entries: SandboxStateEntry[],
  quota: { maxBytes: number; maxFiles: number },
): { drop: string[]; over_quota: boolean; protected_hits: number } {
  let bytes = entries.reduce((sum, item) => sum + item.bytes, 0);
  let files = entries.length;
  const over = () => bytes > quota.maxBytes || files > quota.maxFiles;
  const drop: string[] = [];
  if (!over()) return { drop, over_quota: false, protected_hits: 0 };
  let protectedHits = 0;
  for (const band of ["volatile", "normal", "protected"] as const) {
    const bandEntries = entries.filter(entry => stateBand(entry.path) === band).sort((a, b) => a.mtime_s - b.mtime_s);
    for (const victim of bandEntries) {
      if (!over()) break;
      // 每带留最新一个：避免"写进去的那份马上被自己裁掉"。
      if (victim === bandEntries[bandEntries.length - 1]) continue;
      drop.push(victim.path);
      bytes -= victim.bytes;
      files -= 1;
      if (band === "protected") protectedHits += 1;
    }
    if (!over()) break;
  }
  return { drop, over_quota: over(), protected_hits: protectedHits };
}

/** 会话键 → 落盘目录；键已在 driver 归一化过，这里再做一次根目录越界检查。 */
export function stateDirFor(cfg: StateConfig, key: string): string {
  const root = resolve(cfg.stateRoot);
  const dir = resolve(root, key);
  if (dir !== root && !dir.startsWith(root + sep)) throw new Error("state key escapes the state root");
  return dir;
}

/**
 * volume-subpath 要求子目录**先存在**，否则 docker 直接报 "cannot access path"。
 * 顺便放开写权限：job 跑 uid 10001，而这里由服务（root）创建。
 */
export function ensureStateDir(cfg: StateConfig, key: string): string {
  const dir = stateDirFor(cfg, key);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o1777 });
  try { chmodSync(dir, 0o1777); } catch { /* 非 root 时忽略 */ }
  return dir;
}

function walk(dir: string, base = dir, out: Array<{ path: string; bytes: number; mtime_s: number }> = [], limit = 2000) {
  let items: string[];
  try { items = readdirSync(dir); } catch { return out; }
  for (const name of items) {
    if (out.length >= limit) return out;
    const full = join(dir, name);
    let info;
    try { info = statSync(full); } catch { continue; }
    // 只统计普通文件：符号链接一律不跟随（uid 10001 + cap-drop，但也不给它越界的可能）。
    if (info.isDirectory()) { walk(full, base, out, limit); continue; }
    if (!info.isFile()) continue;
    out.push({ path: relative(base, full).split(sep).join("/"), bytes: info.size, mtime_s: Math.round(info.mtimeMs / 1000) });
  }
  return out;
}

/**
 * 度量 /state 并在超配额时按最旧优先裁剪。
 * 目的：给 agent 一个"短期记忆"，但不让它把宿主磁盘写爆（50MB / 100 文件默认）。
 */
export function measureState(cfg: StateConfig, key: string, prune = true): SandboxStateSummary {
  const dir = stateDirFor(cfg, key);
  mkdirSync(dir, { recursive: true });
  const all = walk(dir);
  const maxBytes = Math.round(cfg.stateMaxMb * 1024 * 1024);
  const maxFiles = Math.max(1, Math.round(cfg.stateMaxFiles));
  let pruned = 0;
  let prunedProtected = 0;
  let overQuota = false;
  if (prune) {
    const plan = planStatePrune(all, { maxBytes, maxFiles });
    for (const path of plan.drop) {
      try { unlinkSync(join(dir, path.split("/").join(sep))); } catch { continue; }
      pruned += 1;
      if (stateBand(path) === "protected") prunedProtected += 1;
    }
    overQuota = plan.over_quota;
  }
  const remaining = walk(dir);
  return {
    key, mount: "/state", root: dir,
    files: remaining.length,
    bytes: remaining.reduce((sum, item) => sum + item.bytes, 0),
    pruned,
    pruned_protected: prunedProtected,
    bands: bandUsage(remaining),
    over_quota: overQuota,
    truncated: remaining.length > 100,
    entries: remaining.slice(0, 100),
  };
}

/** 单个文件的绝对路径（越界直接抛）：给控制面回读用。 */
export function stateFilePath(cfg: StateConfig, key: string, path: string): string {
  const dir = stateDirFor(cfg, key);
  const target = resolve(dir, path);
  if (!target.startsWith(dir + sep)) throw new Error("state path escapes the session directory");
  return target;
}

export function clearState(cfg: StateConfig, key: string): { removed: boolean } {
  const dir = stateDirFor(cfg, key);
  const existed = (() => { try { return statSync(dir).isDirectory(); } catch { return false; } })();
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  return { removed: existed };
}

/** 会话结束/超时后自动摘除：按目录 mtime 超过 TTL 的会话目录。 */
export function sweepState(cfg: StateConfig, now = Date.now()): number {
  const root = resolve(cfg.stateRoot);
  let items: string[];
  try { items = readdirSync(root); } catch { return 0; }
  const ttlMs = Math.max(1, cfg.stateTtlH) * 3600_000;
  let removed = 0;
  for (const name of items) {
    const dir = join(root, name);
    try {
      const info = statSync(dir);
      if (!info.isDirectory()) continue;
      if (now - info.mtimeMs < ttlMs) continue;
      rmSync(dir, { recursive: true, force: true });
      removed += 1;
    } catch { /* ignore */ }
  }
  return removed;
}

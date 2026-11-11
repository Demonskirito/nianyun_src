import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export function atomicWrite(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, text, "utf8");
  try {
    chmodSync(tmp, 0o666);
  } catch {
    /* ignore */
  }
  try {
    renameSync(tmp, path);
    try {
      chmodSync(path, 0o666);
    } catch {
      /* ignore */
    }
  } catch {
    try {
      writeFileSync(path, text, "utf8");
      unlinkSync(tmp);
    } catch {
      try {
        unlinkSync(tmp);
      } catch {
        /* ignore */
      }
      throw new Error(`atomic write failed: ${path}`);
    }
  }
}

export function rmTree(path: string | null | undefined): boolean {
  if (!path) return true;
  if (!existsSync(path)) return true;
  try {
    rmSync(path, { recursive: true, force: true });
  } catch {
    try {
      chmodSync(path, 0o700);
      rmSync(path, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
  return !existsSync(path);
}

export function nowSec(): number {
  return Date.now() / 1000;
}

export function copyIfExists(src: string, dest: string): boolean {
  if (!existsSync(src)) return false;
  try {
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, readFileSync(src));
    return true;
  } catch {
    return false;
  }
}

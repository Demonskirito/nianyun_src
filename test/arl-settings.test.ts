import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import type { Config } from "../src/shared/config.js";
import { applyPayload, loadOverlay, snapshot } from "../src/control/console/llm-io.js";
import { checkArl } from "../src/asset/arl.js";

const dirs: string[] = [];
afterEach(() => { vi.unstubAllGlobals(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

it("persists ARL credentials without exposing the token and preserves a blank token", () => {
  const dir = mkdtempSync(join(tmpdir(), "arl-settings-")); dirs.push(dir);
  const cfg = { data_dir: dir, tools_env: { values: {} } } as Config;
  applyPayload(cfg, { ARL_URL: "http://arl-web:5003", ARL_TOKEN: "private-api-token" });
  applyPayload(cfg, { ARL_TOKEN: "" });
  const restored = { data_dir: dir, tools_env: { values: {} } } as Config;
  loadOverlay(restored);
  expect(restored.tools_env.values.ARL_TOKEN).toBe("private-api-token");
  expect(snapshot(restored)).toMatchObject({ arl: { ARL_URL: { value: "http://arl-web:5003" }, ARL_TOKEN: { set: true, value: "", preview: "••••oken" } } });
  expect(JSON.stringify(snapshot(restored))).not.toContain("private-api-token");
});

it("rejects an ARL authentication failure even when HTTP returns 200", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json({ code: 401, message: "invalid token" })));
  await expect(checkArl({ ARL_URL: "http://arl.test", ARL_TOKEN: "bad" })).rejects.toThrow("invalid token");
});

it("persists the interactive-exec switch from the console without a restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "interactive-settings-")); dirs.push(dir);
  const cfg = { data_dir: dir, tools_env: { values: {} } } as Config;
  applyPayload(cfg, { BLACKBOX_ALLOW_INTERACTIVE_EXEC: "true", SANDBOX_URL: "http://sandbox:8790" });
  // 立刻生效：同一个进程内 values 已被改写，工具层按调用读的就是它。
  expect(cfg.tools_env.values.BLACKBOX_ALLOW_INTERACTIVE_EXEC).toBe("true");
  // 重启后仍然生效：overlay 落在 data/console/llm.yaml。
  const restored = { data_dir: dir, tools_env: { values: {} } } as Config;
  loadOverlay(restored);
  expect(restored.tools_env.values.BLACKBOX_ALLOW_INTERACTIVE_EXEC).toBe("true");
  expect(restored.tools_env.values.SANDBOX_URL).toBe("http://sandbox:8790");
  expect(snapshot(restored)).toMatchObject({ blackbox: { BLACKBOX_ALLOW_INTERACTIVE_EXEC: { set: true, value: "true" } } });
  // 关回去也要能落盘。
  applyPayload(cfg, { BLACKBOX_ALLOW_INTERACTIVE_EXEC: "false" });
  const again = { data_dir: dir, tools_env: { values: {} } } as Config;
  loadOverlay(again);
  expect(again.tools_env.values.BLACKBOX_ALLOW_INTERACTIVE_EXEC).toBe("false");
});
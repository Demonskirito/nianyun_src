/**
 * 生成 `generated/tool-manifest.json`（OpenAPI 3.1 形状）。
 *
 * 什么时候跑：
 *   - `npm run build` 之后（见 package.json 的 build:manifest）
 *   - 改了工具注册表 / tool_docs.ts / 路由层 / 权重 / 打法库之后
 *
 * 为什么需要它：控制台以前手写 62 条工具，和 `BLACKBOX_TOOL_NAMES`（73 条）各活一套，
 * 于是出现「模型不知道有什么工具、控制台不显示 exec 层与 fs 层工具」的漂移。这个文件是从代码
 * 生成出来的，报错会直接写进 `x-nianyun-issues`。
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toolInputSchema } from "../dist/blackbox/protocol.js";
import { buildToolManifest, toolManifestDocument } from "../dist/blackbox/tool_manifest.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(root, "generated", "tool-manifest.json");

let inputSchema = { type: "object", additionalProperties: true };
try {
  // zod v4 自带 toJSONSchema：直接拿 tool_requests[].input 的真实形状（41 个字段），
  // 不再手写一份 input 说明——那就是下一处漂移。
  const { z } = await import("zod");
  const candidate = z.toJSONSchema(toolInputSchema, { io: "input" });
  if (candidate && typeof candidate === "object") inputSchema = candidate;
} catch (error) {
  console.warn(`[tool-manifest] 跳过 input schema 提取：${error instanceof Error ? error.message : String(error)}`);
}

const document = toolManifestDocument(inputSchema);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`, "utf8");

const manifest = buildToolManifest();
console.log(`[tool-manifest] ${manifest.counts.total} tools (tactical ${manifest.counts.tactical} / strategic ${manifest.counts.strategic} / tactical_rpc ${manifest.counts.tactical_rpc}, rpc ${manifest.counts.rpc_callable}) → ${out}`);
if (manifest.issues.length) {
  for (const issue of manifest.issues) console.error(`[tool-manifest] DRIFT: ${issue}`);
  process.exitCode = 1;
}
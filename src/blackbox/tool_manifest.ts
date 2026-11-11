/**
 * Tool Manifest：工具目录的**唯一生成源**。
 *
 * 以前控制台的 62 项是手写的（`desk.ts` 里的 `TOOL_CATALOG`），而真正能调用的工具是
 * `tools.ts` 里的 `BLACKBOX_TOOL_NAMES`（73 项）。两套数据各活一套，于是有了"模型不知道
 * 有什么工具 / 控制台少显示 exec.* 与 fs.*"的漂移。
 *
 * 现在：
 *   - 名字：来自**代码里的注册表**（`BLACKBOX_TOOL_NAMES`），不手写；
 *   - 层 / 权重 / 是否重型 / 是否可 RPC：来自路由与权重模块的**同一批函数**（执行时用的就是它们）；
 *   - 打法覆盖：从 `PLAYBOOKS` 反查，谁在用什么；
 *   - 用途文案：来自 `tool_docs.ts`（文案无法从代码生成，但**缺一条就报错**，不再静默漂移）。
 *
 * `scripts/gen-tool-manifest.mjs` 在构建后把它落盘成 `generated/tool-manifest.json`（OpenAPI 3.1 形状），
 * `test/tool-manifest.test.ts` 保证落盘文件和代码一致。
 */
import { createHash } from "node:crypto";
import { BLACKBOX_TOOL_NAMES } from "./tools.js";
import { toolInputHint } from "./tool-params.js";
import { TOOL_DOCS } from "./tool_docs.js";
import { BUNDLED_CLI_TO_TACTICAL, toolLayer } from "./routing.js";
import { isHeavyTool, toolWeight } from "./weights.js";
import { RPC_WHITELIST } from "./sandbox_rpc.js";
import { PLAYBOOKS } from "./playbooks.js";

export type ManifestLayer = "tactical" | "strategic" | "tactical_rpc";

export type ToolManifestEntry = {
  name: string;
  family: string;
  layer: ManifestLayer;
  /** 调度权重（http.request=1，nuclei/sqlmap/katana=5）。 */
  weight: number;
  heavy: boolean;
  /** 能否从沙箱通过电台（RPC）调用。 */
  rpc_callable: boolean;
  /** 哪些打法用它（playbook id）。 */
  playbooks: string[];
  purpose: string;
  /** 有用途文案（缺文案会在 issues 里报出来）。 */
  documented: boolean;
  env?: string;
  client_env?: string;
  bridge?: boolean;
  risk: "low" | "medium" | "high";
};

export type ToolManifest = {
  version: string;
  /** 生成时依赖的源（便于排障时确认没读错表）。 */
  sources: string[];
  counts: { total: number; tactical: number; strategic: number; tactical_rpc: number; rpc_callable: number };
  /** 漂移/缺文档问题；空数组表示干净。 */
  issues: string[];
  tools: ToolManifestEntry[];
  /** 沙箱裸调这些 CLI 会被重定向到对应工具。 */
  cli_redirects: Record<string, string>;
};

function familyOf(name: string): string {
  const dot = name.indexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

function layerOf(name: string): ManifestLayer {
  const layer = toolLayer(name);
  if (layer === "strategic") return "strategic";
  // 沙箱排队、控制面发射的动作（竞态）在路由里仍算 tactical，但 manifest 要区分出来。
  return name === "recon.race_condition" ? "tactical_rpc" : "tactical";
}

/** 构建 manifest（纯函数：同样的代码必然得到同样的输出）。 */
export function buildToolManifest(): ToolManifest {
  const docs = new Map(TOOL_DOCS.map(doc => [doc.name, doc]));
  const playbookUsage = new Map<string, string[]>();
  for (const playbook of PLAYBOOKS) {
    for (const step of playbook.steps) {
      const list = playbookUsage.get(step.tool) || [];
      if (!list.includes(playbook.id)) list.push(playbook.id);
      playbookUsage.set(step.tool, list);
    }
  }
  const names = [...BLACKBOX_TOOL_NAMES].sort();
  const tools: ToolManifestEntry[] = names.map(name => {
    const doc = docs.get(name);
    return {
      name,
      family: familyOf(name),
      layer: layerOf(name),
      weight: toolWeight(name),
      heavy: isHeavyTool(name),
      rpc_callable: (RPC_WHITELIST as readonly string[]).includes(name),
      playbooks: playbookUsage.get(name) || [],
      purpose: doc?.purpose || "",
      documented: Boolean(doc?.purpose),
      ...(doc?.env ? { env: doc.env } : {}),
      ...(doc?.client_env ? { client_env: doc.client_env } : {}),
      ...(doc?.bridge !== undefined ? { bridge: doc.bridge } : {}),
      risk: doc?.risk || "low",
    };
  });
  const issues: string[] = [];
  for (const entry of tools) if (!entry.documented) issues.push(`工具 ${entry.name} 没有用途文案（tool_docs.ts 缺一条）`);
  const known = new Set<string>(names);
  for (const doc of TOOL_DOCS) if (!known.has(doc.name)) issues.push(`tool_docs.ts 里的 ${doc.name} 不是可调用工具（改名/删除后没同步）`);
  for (const tool of RPC_WHITELIST) if (!known.has(tool)) issues.push(`RPC 白名单里的 ${tool} 不存在`);
  for (const [tool, ids] of playbookUsage) if (!known.has(tool)) issues.push(`打法库引用了不存在的工具 ${tool}（${ids.join(",")}）`);
  const counts = {
    total: tools.length,
    tactical: tools.filter(tool => tool.layer === "tactical").length,
    strategic: tools.filter(tool => tool.layer === "strategic").length,
    tactical_rpc: tools.filter(tool => tool.layer === "tactical_rpc").length,
    rpc_callable: tools.filter(tool => tool.rpc_callable).length,
  };
  const version = createHash("sha1")
    .update(JSON.stringify(tools.map(tool => [tool.name, tool.purpose, tool.layer, tool.weight, tool.rpc_callable, tool.playbooks])))
    .digest("hex")
    .slice(0, 12);
  return {
    version,
    sources: ["src/blackbox/tools.ts#BLACKBOX_TOOL_NAMES", "src/blackbox/tool_docs.ts#TOOL_DOCS", "src/blackbox/routing.ts#toolLayer", "src/blackbox/weights.ts#toolWeight", "src/blackbox/sandbox_rpc.ts#RPC_WHITELIST", "src/blackbox/playbooks.ts#PLAYBOOKS"],
    counts,
    issues,
    tools,
    cli_redirects: { ...BUNDLED_CLI_TO_TACTICAL },
  };
}

/** OpenAPI 3.1 形状：一个 tool = 一个 operation，input 是共享的对象 schema。 */
export function toolManifestDocument(inputSchema: Record<string, unknown> = { type: "object", additionalProperties: true }): Record<string, unknown> {
  const manifest = buildToolManifest();
  const paths: Record<string, unknown> = {};
  for (const tool of manifest.tools) {
    paths[`/tools/${tool.name}`] = {
      post: {
        operationId: tool.name.replaceAll(".", "_"),
        summary: tool.purpose || `${tool.name}（未写文档）`,
        tags: [tool.family, tool.layer],
        "x-nianyun": {
          layer: tool.layer, weight: tool.weight, heavy: tool.heavy, rpc_callable: tool.rpc_callable,
          risk: tool.risk, playbooks: tool.playbooks,
          ...(tool.env ? { env: tool.env } : {}),
          ...(tool.client_env ? { client_env: tool.client_env } : {}),
          ...(tool.bridge !== undefined ? { bridge: tool.bridge } : {}),
        },
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/ToolInput" } } },
        },
        responses: {
          "200": { description: "tool-result（写入 Evidence Ledger）" },
          "409": { description: "rejected：模型可修的错，不计预算、不进失败重试" },
        },
      },
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "Nianyun Blackbox Tool Manifest",
      version: manifest.version,
      description: `由 scripts/gen-tool-manifest.mjs 生成。共 ${manifest.counts.total} 个工具（tactical ${manifest.counts.tactical} / strategic ${manifest.counts.strategic} / tactical_rpc ${manifest.counts.tactical_rpc}）。不要手改。`,
    },
    components: { schemas: { ToolInput: inputSchema } },
    "x-nianyun-sources": manifest.sources,
    "x-nianyun-counts": manifest.counts,
    "x-nianyun-issues": manifest.issues,
    "x-nianyun-cli-redirects": manifest.cli_redirects,
    paths,
  };
}
/**
 * 给主 Agent 的**工具清单 prompt**（替代 prompt 里那段手写 4355 字符的工具名列表）。
 *
 * 手写清单的问题不是"长"，而是它会悄悄过期：新增 exec.*、fs.*、browser.tab 之后，
 * prompt 里没有，模型自然不问；控制台也没有，人就以为没实现。
 * 这段文字现在从 manifest 生成：名字、层、权重、一句话用途，全部和注册表同步。
 */
export function toolManifestPrompt(options: { purposeChars?: number } = {}): string {
  const purposeChars = Math.max(0, Math.floor(options.purposeChars ?? 34));
  const manifest = buildToolManifest();
  const tag = (layer: ManifestLayer) => (layer === "strategic" ? "S" : layer === "tactical_rpc" ? "R" : "T");
  const lines = manifest.tools.map(tool => {
    const purpose = tool.purpose.length > purposeChars ? `${tool.purpose.slice(0, purposeChars)}…` : tool.purpose;
    // 可调项直接写在清单行上：模型不用先撞一次墙才知道能指定字典/并发。
    const hint = toolInputHint(tool.name);
    return `${tool.name}[${tag(tool.layer)}/w${tool.weight}] ${purpose}${hint ? ` · 可传 ${hint}` : ""}`;
  });
  return [
    `可用工具共 ${manifest.counts.total} 个（T=tactical 控制面出口，S=strategic 沙箱容器内，R=沙箱排队+控制面齐发；w=预算权重，5 为重型）：`,
    lines.join("\n"),
    `禁止裸调 CLI：${Object.keys(manifest.cli_redirects).join("、")} 在沙箱里会被 preflight 直接拦下（exit_code=126），改调对应工具。`,
  ].join("\n");
}
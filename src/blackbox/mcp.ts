import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { z } from "zod/v4";
import { ensureDirs, loadConfig } from "../shared/config.js";
import { Database } from "../shared/db.js";
import { getProject } from "../control/console/workspace.js";
import { executeAndRecordBlackboxTool, type BlackboxToolContext, type BlackboxToolRequest } from "./tools.js";
import { requireExecution } from "../shared/execution.js";

// Every registered tool executes directly. There is no per-action human approval
// queue: the control plane only enforces execution mode, session state and ledger.
export async function submitBlackboxMcpTool(ctx: BlackboxToolContext, request: BlackboxToolRequest) {
  requireExecution(ctx.cfg, "MCP tool");
  const session = ctx.db.getBlackboxSession(ctx.projectId, ctx.sessionId);
  if (!session || session.status === "cancelled") throw new Error("session unavailable");
  const fresh = { ...ctx, target: String(session.target) };
  return executeAndRecordBlackboxTool(fresh, request);
}

type Cli = { config?: string; project: string; session: string };

function cli(argv: string[]): Cli {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--config" || arg === "-c") values.config = argv[++i] || "";
    else if (arg === "--project") values.project = argv[++i] || "";
    else if (arg === "--session") values.session = argv[++i] || "";
  }
  if (!values.project || !values.session) throw new Error("MCP requires --project <id> and --session <id>");
  return values as Cli;
}

function resultText(result: Awaited<ReturnType<typeof executeAndRecordBlackboxTool>>): { content: [{ type: "text"; text: string }]; isError?: boolean } {
  return { content: [{ type: "text", text: JSON.stringify(result) }], ...(result.ok ? {} : { isError: true }) };
}

function inputSchema() {
  return {
    url: z.string().url().optional(),
    method: z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]).optional(),
    headers: z.record(z.string(), z.string().max(8192)).optional(),
    body: z.string().max(5_000_000).optional(),
    body_base64: z.string().max(8_000_000).optional(),
    json: z.unknown().optional(),
    form: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
    multipart: z.array(z.record(z.string(), z.unknown())).max(50).optional(),
    timeout_ms: z.number().int().min(1000).max(120000).optional(),
    full_page: z.boolean().optional(),
    depth: z.number().int().min(1).max(8).optional(),
    duration_seconds: z.number().int().min(5).max(300).optional(),
    limit: z.number().int().min(1).max(100).optional(),
    offset: z.number().int().min(0).max(100000).optional(),
    entry_id: z.string().trim().min(1).max(64).optional(),
    wordlist: z.string().max(512).optional(),
    action: z.enum(["start", "poll", "stop", "list", "new", "close", "switch"]).optional(),
    // 协商 / 沙箱 / 工作区（MCP 客户端要能看见这些字段，否则会以为工具没有入参）。
    category: z.string().max(64).optional(),
    // protocol.ts 已允许 900s；这里与 workspace.ts 的 clamp 保持一致，避免"看到 900、实际 300"。
    timeout_s: z.number().int().min(5).max(900).optional(),
    rate_limit: z.number().int().min(5).max(150).optional(),
    katana_depth: z.number().int().min(1).max(8).optional(),
    katana_duration_s: z.number().int().min(15).max(300).optional(),
    retries: z.number().int().min(0).max(3).optional(),
    reset: z.boolean().optional(),
    code: z.string().max(200000).optional(),
    script: z.string().max(200000).optional(),
    requirements: z.array(z.string().max(80)).max(8).optional(),
    memory_mb: z.number().int().min(128).max(4096).optional(),
    network: z.boolean().optional(),
    pattern: z.string().max(512).optional(),
    max_bytes: z.number().int().min(1024).max(262144).optional(),
    max_matches: z.number().int().min(1).max(200).optional(),
    index: z.number().int().min(0).max(11).optional(),
    cookies: z.array(z.record(z.string(), z.unknown())).max(100).optional(),
    local_storage: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
    session_storage: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
    clear: z.boolean().optional(),
    read: z.boolean().optional(),
    wait_for_selector: z.string().max(512).optional(),
    wait_until: z.enum(["domcontentloaded", "load", "networkidle"]).optional(),
    wait_ms: z.number().int().min(0).max(30000).optional(),
    runtime_id: z.string().max(200).optional(),
    server: z.string().url().optional(),
    token: z.string().max(4096).optional(),
    wait_seconds: z.number().int().min(0).max(30).optional(),
    path: z.string().max(1024).optional(),
    wordlist_root: z.string().max(1024).optional(),
    reason: z.string().max(2000).optional(),
  };
}

export async function runBlackboxMcp(argv = process.argv.slice(2)): Promise<void> {
  const args = cli(argv);
  const repo = process.env.NIANYUN_REPO_ROOT || process.cwd();
  const cfg = loadConfig(args.config, repo);
  requireExecution(cfg, "MCP server");
  ensureDirs(cfg);
  const db = new Database(cfg.db_path);
  const project = getProject(cfg, args.project);
  const session = db.getBlackboxSession(args.project, args.session);
  if (!project) throw new Error(`project not found: ${args.project}`);
  if (!session) throw new Error(`blackbox session not found: ${args.project}/${args.session}`);
  const ctx: BlackboxToolContext = {
    cfg,
    db,
    projectId: args.project,
    sessionId: args.session,
    target: String(session.target || ""),
    values: cfg.tools_env.values,
  };
  const server = new McpServer({ name: "nianyun-blackbox", version: "0.1.0" });
  const register = (name: string, description: string, tool: BlackboxToolRequest["tool"], transform: (input: Record<string, unknown>) => Record<string, unknown> = (input) => input) => {
    server.registerTool(name, { description, inputSchema: inputSchema() }, async (input) => {
      const { reason, ...parameters } = input;
      const request: BlackboxToolRequest = { tool, input: transform(parameters), reason: String(reason || "MCP tool call") };
      return resultText(await submitBlackboxMcpTool(ctx, request));
    });
  };
  register("browser.open", "Open the authorized target in headless Playwright and record page evidence.", "browser.open");
  register("browser.screenshot", "Open the authorized target, capture a screenshot, and record page evidence.", "browser.screenshot");
  register("http.request", "Make a bounded HTTP request with optional headers and body to the target.", "http.request");
  register("burp.check", "Check that the configured Burp proxy is reachable.", "burp.check", () => ({}));
  register("burp.request", "Make a bounded HTTP request through Burp, including optional headers and body.", "burp.request");
  register("burp.history", "Read a bounded, target-filtered list of Burp Proxy HTTP history entries through the local read-only bridge.", "burp.history");
  register("burp.sitemap", "Read a bounded, target-filtered list of Burp Site map entries through the local read-only bridge.", "burp.sitemap");
  register("burp.entry", "Read one redacted Burp Proxy history or Site map request/response entry returned by burp.history or burp.sitemap.", "burp.entry");
  register("burp.issues", "Read Burp Scanner issues for the current target host as unverified evidence to review.", "burp.issues");
  register("burp.ws_history", "Read Burp Proxy WebSocket messages for the target host.", "burp.ws_history");
  register("burp.scope", "Check whether a URL is inside the Burp target scope.", "burp.scope");
  register("burp.intercept", "Read or disable the Burp Proxy intercept toggle.", "burp.intercept");
  register("burp.decoder", "Encode or decode values with Burp Decoder semantics (base64/url/html/hex/sha256/uuid).", "burp.decoder");
  register("burp.send", "Send one HTTP request through Burp and return status, headers and a redacted body preview.", "burp.send");
  register("burp.repeater", "Send a request into Burp Repeater for manual replay.", "burp.repeater");
  register("burp.organizer", "Send a request into Burp Organizer.", "burp.organizer");
  register("burp.collab_generate", "Generate a Burp Collaborator payload for blind/OOB verification.", "burp.collab_generate");
  register("burp.collab_poll", "Poll Burp Collaborator interactions as out-of-band evidence.", "burp.collab_poll");
  register("burp.scan", "Start a Burp Scanner audit for the target (active mode requires the rule switch).", "burp.scan");
  register("burp.scan_status", "Read Burp Scanner audit progress and issue candidates.", "burp.scan_status");
  register("burp.scan_stop", "Stop and delete a Burp Scanner audit.", "burp.scan_stop");
  register("burp.info", "Burp info (full-surface bridge route).", "burp.info");
  register("burp.control", "Burp control (full-surface bridge route).", "burp.control");
  register("burp.options", "Burp options (full-surface bridge route).", "burp.options");
  register("burp.cookies", "Burp cookies (full-surface bridge route).", "burp.cookies");
  register("burp.storage", "Burp storage (full-surface bridge route).", "burp.storage");
  register("burp.sitemap_issues", "Burp sitemap_issues (full-surface bridge route).", "burp.sitemap_issues");
  register("burp.sitemap_add", "Burp sitemap_add (full-surface bridge route).", "burp.sitemap_add");
  register("burp.scope_edit", "Burp scope_edit (full-surface bridge route).", "burp.scope_edit");
  register("burp.send_batch", "Burp send_batch (full-surface bridge route).", "burp.send_batch");
  register("burp.crawl", "Burp crawl (full-surface bridge route).", "burp.crawl");
  register("burp.scan_issues", "Burp scan_issues (full-surface bridge route).", "burp.scan_issues");
  register("burp.scan_report", "Burp scan_report (full-surface bridge route).", "burp.scan_report");
  register("burp.intruder", "Burp intruder (full-surface bridge route).", "burp.intruder");
  register("burp.intruder_send", "Burp intruder_send (full-surface bridge route).", "burp.intruder_send");
  register("burp.compare", "Burp compare (full-surface bridge route).", "burp.compare");
  register("burp.convert", "Burp convert (full-surface bridge route).", "burp.convert");
  register("burp.proxy_rule", "Burp rewrite rules (Match and Replace) as data: list, add, update, remove, clear, or dry-run test.", "burp.proxy_rule");
  register("burp.websocket", "Open a WebSocket through Burp, send text/binary frames and read the frames that came back.", "burp.websocket");
  register("burp.bchecks", "Import a Burp BCheck script so it participates in active scans.", "burp.bchecks");
  register("katana.crawl", "Run a bounded Katana crawl against the authorized target.", "katana.crawl");
  register("recon.subdomains", "Run bounded passive subdomain discovery.", "recon.subdomains");
  register("recon.dns", "Resolve bounded DNS records for the authorized target.", "recon.dns");
  register("recon.http_probe", "Probe authorized HTTP services and record status and technology evidence.", "recon.http_probe");
  register("recon.ports", "Run a bounded port discovery task when enabled in the tool navigation.", "recon.ports");
  register("recon.historical_urls", "Collect bounded historical URLs for the authorized target.", "recon.historical_urls");
  register("recon.content_discovery", "Run a bounded content discovery task when enabled in the tool navigation.", "recon.content_discovery");
  register("recon.nuclei", "Run a bounded nuclei template check when enabled in the tool navigation.", "recon.nuclei");
  register("recon.interactsh", "Start, poll, or stop a bounded Interactsh callback listener and record callback evidence.", "recon.interactsh");
  register("recon.parameters", "Discover candidate GET/POST parameters with Arjun when configured.", "recon.parameters");
  register("recon.js_endpoints", "Extract JavaScript endpoints with subjs when configured.", "recon.js_endpoints");
  register("recon.tls", "Run a bounded TLS configuration review with testssl.sh when configured.", "recon.tls");
  register("recon.api_routes", "Discover API routes with kiterunner using an approved wordlist.", "recon.api_routes");
  register("recon.xss", "Run a low-rate Dalfox candidate XSS check when manually enabled.", "recon.xss");
  register("recon.sql", "Run a conservative sqlmap candidate check when manually enabled.", "recon.sql");
  register("recon.jwt", "Decode and inspect a supplied JWT with jwt-tool when manually enabled.", "recon.jwt");
  register("recon.graphql", "Run graphql-cop checks against an authorized endpoint when manually enabled.", "recon.graphql");
  register("recon.cms", "Run passive WordPress detection with WPScan when manually enabled.", "recon.cms");
  register("recon.secrets", "Scan an explicitly supplied authorized filesystem path with TruffleHog.", "recon.secrets");
  register("recon.sast", "Run Semgrep against an explicitly supplied authorized source path.", "recon.sast");
  register("recon.wordlists", "List the read-only wordlist and nuclei-template directories this session may reference.", "recon.wordlists");
  register("recon.scan_profile", "Read or negotiate scanner parameters (nuclei timeout/rate/retries, katana depth/duration) for slow or deep targets.", "recon.scan_profile");
  register("exec.python", "Run a Python POC or helper in a throwaway workspace sandbox (fresh directory, stripped env, rlimits, hard timeout, optional pip requirements).", "exec.python");
  register("exec.bash", "Run a shell one-shot in the same throwaway sandbox for CLI pipelines and dictionary generation.", "exec.bash");
  register("fs.list", "List files in this session workspace (artifacts, run records, sandbox output).", "fs.list");
  register("fs.read", "Read a file from the session workspace.", "fs.read");
  register("fs.grep", "Grep across the session workspace to review earlier observations.", "fs.grep");
  register("browser.tab", "List, open, switch or close browser tabs on the live session (agent-managed tab pool).", "browser.tab");
  register("browser.storage", "Inject or read back cookies, localStorage and sessionStorage on the live browser session (identity persistence).", "browser.storage");
  await server.connect(new StdioServerTransport());
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  runBlackboxMcp().catch((error) => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}


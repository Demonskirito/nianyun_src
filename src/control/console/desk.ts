import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { BlackboxProgress, observerReviewId, observerStateVersion, observerStateVersionMatches, type ObserverReview, type RunCheckpoint } from "../../blackbox/progress.js";
import { superviseCheckpoint, type SupervisionEvent } from "../../blackbox/supervision.js";
import { completionVerdictOf, evaluateAcceptance, isCompletedVerdict } from "../../blackbox/acceptance.js";
import { settleTask } from "../../blackbox/task-outcome.js";
import { consistencyPlaybookOf, evaluateRequirements, isVulnPlaybook, vulnerabilityGaps } from "../../blackbox/vuln-predicates.js";
import { playbookPriority, playbookCoverage, coverageSummary, postSurfaceTask, oastRequiredTask, burpScanTask, anomalyTasks, crossDomainTasks, lateralEscapeTask, wafBypassTask, playbookById } from "../../blackbox/playbooks.js";
import { guardTaskSlot } from "../../blackbox/guard-tasks.js";
import { budgetMode, isHeavyTool, toolWeight } from "../../blackbox/weights.js";
import { auditAdviceHistory } from "../../blackbox/advice-history.js";
import { planStaleReview, reviewIssueFingerprint, shouldQueueIssueReview } from "../../blackbox/review-stale.js";
import { supervisorWarningText } from "../../blackbox/warning-text.js";
import { BLACKBOX_TOOL_ENUM, mainSchema } from "../../blackbox/protocol.js";
import { errorTypeForField } from "../../blackbox/envelope.js";
import { blackboxReport, validateFinding, type Finding } from "../../blackbox/findings.js";
import { partitionBlocking, quarantineFindings, quarantineTaskRefs, repairDigest, unquarantinableDigest, type IssueLike } from "../../blackbox/quarantine.js";
import { deleteAuthSeed, listAuthSeeds, loadSeedsForHost, pruneSeedCookies, saveAuthSeed, type AuthSeedView, type DeleteSeedResult, type SaveSeedResult } from "../../blackbox/authseed.js";
import { SEED_VERDICT_LABEL, isolateTaintedCookies, judgeSeedHealth, isWallSample, riskCookieIndexes, type SeedSample } from "../../blackbox/seedcheck.js";
import { cookieJarFingerprint } from "../../blackbox/credential.js";
import { arbitrateFocus, releaseFocusForNoProgress, releaseFocusForPrunedTasks, releaseFocusOnToolFailure } from "../../blackbox/focus-arbitration.js";
import { evidenceUrls, queryEvidence, type EvidenceQuery } from "../../blackbox/facts.js";
import type { Config } from "../../shared/config.js";
import { Database } from "../../shared/db.js";
import { atomicWrite, rmTree } from "../../shared/fsutil.js";
import { canExecute, requireExecution } from "../../shared/execution.js";
import * as llmIo from "./llm-io.js";
import * as workspace from "./workspace.js";
import { importAssets } from "../../asset/service.js";
import { importAssetCandidates } from "../../asset/candidates.js";
import { parseCandidateImport } from "../../asset/importers.js";
import { runAssetProbeJob } from "../../asset/probe.js";
import { discoverHttpSeeds } from "../../asset/discover.js";
import { buildAssetMap } from "../../asset/map.js";
import { validateHttpAsset } from "../../validation/http.js";
import { scoreProject } from "../../risk/scoring.js";
import { buildProjectReport } from "../../report/project.js";
import { discoverArl } from "../../asset/arl.js";
import { checkFofa, discoverFofa } from "../../asset/fofa.js";
import { reviewAssetCandidates, ASSET_RULE_VERSION } from "../../asset/review.js";
import { checkBlackboxEnvironment, type BlackboxEnvironment } from "../../blackbox/environment.js";
import { runPreflight, setPreflight, getPreflight } from "../../blackbox/preflight.js";
import { probeTarget } from "../../blackbox/target-probe.js";
import { clearSandboxState } from "../../blackbox/workspace.js";
import { toolLayer } from "../../blackbox/routing.js";
import { ROUTE_ANTIPATTERNS, ROUTE_SIGNALS, ROUTE_STEPS, ROUTE_VERSION } from "../../blackbox/route-manifest.js";
import { PLAYBOOKS, layerTag, stepLayer } from "../../blackbox/playbooks.js";
import { candidatePathOf, discoveryOf, isCandidateTool, paramsOf, routeMissingOf, wallOf } from "../../blackbox/graph/extract.js";
import { attributeEvidence, type RequestEvidence } from "../../blackbox/graph/evidence.js";
import { applyHypotheses, deadEndVerdict, type DeadEndVerdict, deriveHypotheses, endpointNodeId, graphContextView, graphSignalFingerprint, graphSignalGate, graphSignals, graphState, graphVisualView, ingestToolResult, isClosedHypothesis, normalizeHypothesisStatus, noteHypothesisAttempt, planRoutes, poolBreakdown, resetGraphSignalGate, resolveHypotheses, routeStale, shouldRefreshHypotheses, hypothesisEventBatch, sortRequestsByGraph, activeHypotheses, objectValuesOf, isProbedButUnknown } from "../../blackbox/graph/index.js";
import type { GraphNode } from "../../blackbox/graph/types.js";
import { identityDirective, resolveIdentity, type IdentityState } from "../../blackbox/identity.js";
import {
  declarationNeed, declarationPathOf, declarationTaskSpec, recordDeclaration,
  SITE_DECLARATION_COOLDOWN_MS, SITE_DECLARATION_MAX_ATTEMPTS, SITE_DECLARATION_PATHS,
  type DeclarationHostState,
} from "../../blackbox/site-declaration.js";
import { concurrencyOf, hypothesisTasks } from "../../blackbox/hypothesis_tasks.js";
import { RPC_DISPATCH_PATH, RPC_MAX_PER_CALL, RPC_QUEUES, RPC_WHITELIST } from "../../blackbox/sandbox_rpc.js";
import { BUNDLED_CLI_TO_TACTICAL } from "../../blackbox/routing.js";
import { runBlackboxMainAgent, runBlackboxObserver } from "../../blackbox/agent.js";
import { OBSERVER_INTERRUPT_EVENT, ObserverDaemon, observerModeFrom, renderInterrupts, shouldRunObserverSync, type ObserverInterrupt } from "../../blackbox/observer_daemon.js";
import { blackboxToolMinDurationMs, burpArmAudit, burpReadIssues, burpReadScanIssues, closeBrowserSessions, executeAndRecordBlackboxTool, executeBlackboxTool, type BlackboxToolContext, type BlackboxToolRequest } from "../../blackbox/tools.js";
import { digestText, freshIssues, issueKey, quietDigest, scanMode, severityCounts, shouldHarvest, worthActingOn } from "../../blackbox/burp-scan.js";
import { canonicalTool } from "../../blackbox/aliases.js";
import { blackboxRules, blackboxRulesDiagnostics, blackboxRulesHash } from "../../blackbox/rules.js";
import { useLocalPlanner } from "../../blackbox/local_plan.js";
import { computeToolHealth, type ToolStatus } from "./tool-health.js";
import { buildToolManifest } from "../../blackbox/tool_manifest.js";
import { scoreIngest } from "../../blackbox/evidence-value.js";
import { batchTp, latencyMultiplier, toolTpTable, tpCost, updateLatency } from "../../blackbox/tool-cost.js";
import { applyFocusLock, computeFocus, focusView, type FocusRejection } from "../../blackbox/focus.js";
import { appealPoolLeft, appealText, appealWorthy, chargeFocusRound, criticalSignal, emptyUsage, macroInterruptText, recordFocusCost, recordFocusValue, scaleLimitsForTask, spendAppeal, tpOverBudget, type FocusLimits, type MacroInterrupt } from "../../blackbox/focus-budget.js";
import { bestPotential, potentialDelta, potentialOf, potentialView } from "../../blackbox/potential.js";
import { frustrationAudit } from "../../blackbox/frustration.js";
import { applySovereignty, redirectOf, sovereigntyRejection, violatesSovereignty } from "../../blackbox/sovereignty.js";
import { noteStarvation } from "../../blackbox/task-starvation.js";
import { lockFocus, releaseFocus, releaseFocusIfReleased } from "../../blackbox/dispatcher.js";
import { existingReverseTask, spaDisarmed, spaFingerprint } from "../../blackbox/spa.js";
import { expandFromProbe, planProbes, probeTask } from "../../blackbox/graph/cluster.js";
import { diffResponses, pickPair } from "../../blackbox/traffic_diff.js";
import { replayProtocols, type ReplayEvent } from "../../blackbox/replay_protocols.js";
import { DIMENSION_LABEL, WALL_KIND_LABEL, dimensionOfStep, detectVendor, identityWallOf, normalizeVictory, rankVictories, wafLedgerPrompt, wallKind, wallSignature, type WafDimension, type WafVictory, type WallKind } from "../../blackbox/waf-ledger.js";
import { hostOf } from "../../blackbox/authwall.js";

/**
 * 请求签名：tool + method + url + headers/body/json/form 的短哈希。
 *
 * 为什么要有：2026-10-28 note.yun 那一轮 43 次调用只有 22 个唯一请求（重复率 49%），
 * `https://cloud.oppo.com/` 被打了 17 次、每次都返回 200 —— 旧逻辑只在 blocked 时累加
 * `repeats`，于是毫无变化的重复请求永远判不了死胡同，一半额度白烧。
 * 签名相同 = 完全相同的一次重打，图里累计到 3 次就标 dead_end，执行器据此直接拒收。
 *
 * tool 必须进签名（2026-11-02 实跑 590031a651022390）：`recon.js_endpoints` 只是"从同一
 * URL 抓 JS 清单"，但它算出的签名与 T1 反复打的 `http.request GET /` 完全相同，
 * 于是 T2（SPA 逆向）被判"同一请求已重复 12 次"直接拒收——**换个工具去做另一件事**
 * 被当成了盲重打，整条 JS 逆向线就此断掉。判据的本意是"同一个动作别重打"，动作包含工具。
 */
export function requestSignature(input: Record<string, unknown>, url: string, tool = ""): string {
  return createHash("sha1").update(JSON.stringify({
    // url 用节点 id 归一（去尾斜杠、大小写差异）：实测 `https://cloud.oppo.com` 与
    // `https://cloud.oppo.com/` 交替出现时，签名每轮都被判"变了"，重复计数永远是 1。
    t: String(tool || ""),
    m: String(input.method || "GET").toUpperCase(), u: endpointNodeId(url),
    h: input.headers || null, b: input.body || input.body_base64 || null,
    j: input.json || null, f: input.form || null,
    // variant 是 http.diff 的"对照腿"（换身份/换参数的那一次）。不纳入签名的话，
    // 两次 variant 完全不同的对照会算出同一个哈希 → 被当成"完全相同的一次重打"。
    v: input.variant || null, a: input.anonymous === true ? 1 : null,
  })).digest("hex").slice(0, 16);
}

/**
 * 哪些工具在"端点已标死胡同"后仍然必须放行。
 *
 * 判据不是"重不重要"，而是**它的产出是什么**：
 *   - `http.diff` / `recon.traffic_diff`：产出是对照结果，本来就是为死胡同做二次判定；
 *   - `browser.*`：browser.open 建立会话、其余从会话里取证（截图/网络日志/存储/标签页），
 *     请求由页面自己发起，不是"对同一端点再放一枪"。
 * 把 browser.open 一起挡掉的后果是整族工具不可用：browser.network 会一直报
 * "requires a live browser: open the page with browser.open first"，而 open 又被死胡同拒收。
 * 真正的防重复打由 repeat_limit 与动作指纹负责，不需要 dead_end 越俎代庖。
 */
export function deadEndControlTool(tool: unknown): boolean {
  const name = String(tool || "");
  return name === "http.diff" || name === "recon.traffic_diff" || name.startsWith("browser.");
}

/**
 * 环境检查的一句话结论。
 *
 * 排在最前面的一定是**为什么不通过**：这条文案会出现在时间线和 CLI 的 stderr 上，
 * 操作员看一行就要能判断"是我配错了，还是目标死了"。目标不可达单独成句，不要和
 * "Burp 已连接"挤在一起——后者通了但目标死了，是这轮之前最典型的误导。
 */
export function blackboxEnvironmentSummary(environment: BlackboxEnvironment): string {
  const burp = environment.burp.reachable
    ? `Burp 代理已连接：${environment.burp.proxy_url}`
    : `Burp 代理不可用：${environment.burp.error || "connection failed"}`;
  const target = environment.target;
  if (!target) return burp;
  if (!target.reachable) return `目标可达性检查未通过：${target.reason || target.code}`;
  if (target.code === "skipped") return `${burp}；目标可达性检查已跳过（BLACKBOX_TARGET_PROBE=off）`;
  const route = target.via_proxy ? "经代理" : "直连";
  return `${burp}；目标可达（HTTP ${target.status ?? "?"}，${target.bytes ?? 0}B，${target.elapsed_ms ?? 0}ms，${route}）`;
}

/**
 * 漂移升级阶梯用的固定任务 id（2026-11-09，A4）。
 *
 * 为什么是固定 id：巡检一旦判定"建议三轮没被采纳"，就要有一条真任务可以被派发、
 * 被结案、被记账——插话没有生命周期，模型完全可以一直无视它。
 */
const DRIFT_TASK_ID = "T_GRAPH_DRIFT_ROOTS";

const TOOL_BUNDLED_PATHS: Record<string, string> = {
  KATANA_PATH: "/usr/local/bin/katana", SUBFINDER_PATH: "/usr/local/bin/subfinder", DNSX_PATH: "/usr/local/bin/dnsx",
  HTTPX_PATH: "/usr/local/bin/httpx", NAABU_PATH: "/usr/local/bin/naabu", GAU_PATH: "/usr/local/bin/gau",
  FFUF_PATH: "/usr/local/bin/ffuf", NUCLEI_PATH: "/usr/local/bin/nuclei",
  INTERACTSH_CLIENT_PATH: "/usr/local/bin/interactsh-client",
  ARJUN_PATH: "/usr/local/bin/arjun", SUBJS_PATH: "/usr/local/bin/subjs", TESTSSL_PATH: "/usr/local/bin/testssl.sh",
  KITERUNNER_PATH: "/usr/local/bin/kiterunner", DALFOX_PATH: "/usr/local/bin/dalfox", SQLMAP_PATH: "/usr/local/bin/sqlmap",
  JWT_TOOL_PATH: "/usr/local/bin/jwt_tool", GRAPHQL_COP_PATH: "/usr/local/bin/graphql-cop", WPSCAN_PATH: "/usr/local/bin/wpscan",
  TRUFFLEHOG_PATH: "/usr/local/bin/trufflehog", SEMGREP_PATH: "/usr/local/bin/semgrep",
};


export class Desk {
  cfg: Config;
  db: Database;
  private automationFlight = new Set<string>();
  private blackboxFlight = new Set<string>();
  private blackboxAbort = new Map<string, AbortController>();
  private timers: ReturnType<typeof setInterval>[] = [];
  private disposed = false;
  /** 构建期生成、运行期只读的工具清单（名字/，权重/打法覆盖/文案）。*/
  private readonly toolManifest = buildToolManifest();

  constructor(cfg: Config, db: Database) {
    this.cfg = cfg;
    this.db = db;
  }

  startBackground(): void {
    if (!canExecute(this.cfg) || this.disposed || this.timers.length) return;
    const automation = setInterval(() => { if (!this.disposed) void this.runDueAutomations().catch(e => console.warn(`asset automation: ${e}`)); }, 30_000);
    this.timers.push(automation);
    for (const timer of this.timers) timer.unref();
  }

  dispose(): void {
    this.disposed = true;
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    for (const controller of this.blackboxAbort.values()) controller.abort(new Error("console shutdown"));
  }

  private execution(action: string): void {
    if (this.disposed) throw new Error("console is closed");
    requireExecution(this.cfg, action);
  }

  status(): Record<string, unknown> {
    const projects = workspace.listProjects(this.cfg);
    let candidates = 0;
    let sessions = 0;
    let running = 0;
    let findings = 0;
    for (const project of projects) {
      const pid = String(project.id || "");
      candidates += this.db.listAssetCandidates(pid, { limit: 5000 }).length;
      const items = this.db.listBlackboxSessions(pid, 500);
      sessions += items.length;
      running += items.filter((item) => item.status === "running").length;
      findings += this.db.listFindings(pid, { limit: 1000 }).length;
    }
    return {
      ok: true,
      service: "nianyun-console",
      execution: this.cfg.execution,
      project_count: projects.length,
      candidate_count: candidates,
      session_count: sessions,
      active_sessions: running,
      finding_count: findings,
    };
  }

  // ── 认证种子（控制台上传 / 查看 / 删除）────────────────────────────────────
  listAuthSeeds(): AuthSeedView[] {
    return listAuthSeeds();
  }

  saveAuthSeed(host: string, content: string): SaveSeedResult {
    return saveAuthSeed(host, content);
  }

  deleteAuthSeed(host: string): DeleteSeedResult {
    return deleteAuthSeed(host);
  }

  settingsBundle(): Record<string, unknown> {
    return { llm: llmIo.snapshot(this.cfg), tools: this.systemTools() };
  }

  updateSettings(payload: Record<string, unknown>): Record<string, unknown> {
    const llm = payload.llm && typeof payload.llm === "object" && !Array.isArray(payload.llm) ? payload.llm as Record<string, unknown> : undefined;
    const document = typeof llm?.BLACKBOX_RULES_DOCUMENT === "string" ? llm.BLACKBOX_RULES_DOCUMENT : "";
    if (document.trim()) {
      // Reject an unparsable document here: the runtime would silently fall back to defaults.
      const check = blackboxRulesDiagnostics({ BLACKBOX_RULES_DOCUMENT: document });
      if (!check.valid) throw new Error(check.issues.join(" "));
    }
    if (llm) llmIo.applyPayload(this.cfg, llm);
    return { ...this.settingsBundle(), ok: true };
  }



  systemTools(): Record<string, unknown> {
    const statuses = this.toolStatuses();
    const projects = workspace.listProjects(this.cfg);
    // 一次全局投影取代「每个会话拉一次完整详情」：旧写法会把 4 万条事件与
    // 6 千条证据（55MB data_json）全部读出来解析，只为了下面两个小统计。
    // 语义保持不变：evidence 按 created_at DESC，used_tools 按首次出现去重，
    // layer 优先取证据自带值、缺失时按工具名推断。
    const usage = new Map<string, { used_tools: string[]; layers: { tactical: number; strategic: number } }>();
    for (const row of this.db.listBlackboxToolUsage()) {
      const key = `${String(row.project_id)}|${String(row.session_id)}`;
      let stat = usage.get(key);
      if (!stat) {
        stat = { used_tools: [], layers: { tactical: 0, strategic: 0 } };
        usage.set(key, stat);
      }
      const source = String(row.source || "");
      if (source && !stat.used_tools.includes(source)) stat.used_tools.push(source);
      const layer = String(row.layer || toolLayer(source));
      if (layer === "strategic") stat.layers.strategic += 1;
      else if (layer === "tactical") stat.layers.tactical += 1;
    }
    const emptyUsage = () => ({ used_tools: [] as string[], layers: { tactical: 0, strategic: 0 } });
    const sessions = projects.flatMap((project) => this.db.listBlackboxSessions(String(project.id), 100).map((session) => {
      const stat = usage.get(`${String(project.id)}|${String(session.id)}`) || emptyUsage();
      return {
        id: String(session.id), project_id: String(project.id), project_name: String(project.name || project.id), target: session.target,
        status: session.status, phase: session.phase, updated_at: session.updated_at, environment: session.environment,
        used_tools: stat.used_tools, layers: stat.layers,
      };
    }));
    const ruleState = blackboxRulesDiagnostics(this.cfg.tools_env.values);
    const rules = blackboxRules(this.cfg.tools_env.values);
    return {
      ok: true,
      updated_at: Date.now() / 1000,
      rules: {
        version: rules.version,
        hash: blackboxRulesHash(rules),
        credential_tools: ruleState.credential_tools,
        active_scan_tools: ruleState.active_scan_tools,
        issues: ruleState.issues,
        valid: ruleState.valid,
        fallback: ruleState.fallback,
      },
      // 前端要能看见"路线 / 信号 / 电台协议"：这些原来只存在 prompt 和工具结果里。
      routing: {
        version: ROUTE_VERSION,
        steps: ROUTE_STEPS,
        antipatterns: ROUTE_ANTIPATTERNS,
        signals: ROUTE_SIGNALS,
        radio: {
          queues: [RPC_DISPATCH_PATH],
          legacy_queues: RPC_QUEUES.filter(queue => queue.legacy).map(queue => queue.path),
          modes: ["standard", "concurrent"],
          max_per_call: RPC_MAX_PER_CALL,
          whitelist: RPC_WHITELIST,
          enrichment: "脚本把算好的值直接写。input（headers/cookies/body/query），控制面原样透传，不做优先级合并",
          bundled_cli_redirects: BUNDLED_CLI_TO_TACTICAL,
        },
        race: { tool: "recon.race_condition", via: "burp-proxy", max_requests: 50 },
        // 打法库全貌：id / 标题 / 适用条件 / 步数 / 层分布。前，挖掘路线"页直接渲染，不再手写。
        playbooks: PLAYBOOKS.map(playbook => {
          const layers = { T: 0, S: 0, R: 0 } as Record<string, number>;
          for (const step of playbook.steps) layers[layerTag(stepLayer(step))] = (layers[layerTag(stepLayer(step))] || 0) + 1;
          return {
            id: playbook.id, title: playbook.title, priority: playbook.priority ?? 0,
            when: playbook.when || [], steps: playbook.steps.length,
            timebox_sec: playbook.timebox_sec, layers,
            confirm: playbook.confirm ? { evidence: playbook.confirm.evidence, must_show: playbook.confirm.must_show } : null,
          };
        }),
      },
      tools: statuses.map((tool) => {
        const active = sessions.some((session) => session.status === "running" && (session.environment as Record<string, unknown> | undefined)?.ready === true);
        return { ...tool, status: !tool.configured ? "unconfigured" : active ? "available" : "ready" };
      }),
      agents: [
        { id: "main-agent", name: "Main Agent", purpose: "规划任务、调用工具、分析结果并推进黑盒会话。", status: sessions.some((session) => session.status === "running") ? "running" : "idle", tools: statuses.filter((tool) => tool.agent === "main").map((tool) => tool.id) },
        { id: "observer", name: "Observer Agent", purpose: "只读检查覆盖率、异常、重复动作、停滞和证据质量，提出建议。", status: "ready", tools: [] },
      ],
      sessions,
    };
  }

  /** Catalog plus configuration state, without loading session evidence. */
  /**
   * 工具清单。*。manifest 生成**，不再手写。
   *
   * 旧实现遍。`TOOL_CATALOG`（手。62 条，而且里面混着 subfinder / naabu / sqlmap 这类
   * CLI 名字——它们不是可调用工具，只是被封装的对象）。现在清单来。`buildToolManifest()`
   * 。3 。= `BLACKBOX_TOOL_NAMES`），这里只补一项运行时信息：`configured`。
   */
  private toolStatuses(): ToolStatus[] {
    const values = this.cfg.tools_env.values;
    const configuredPath = (key: string) => Boolean(values[key] || process.env[key] || (TOOL_BUNDLED_PATHS[key] && existsSync(TOOL_BUNDLED_PATHS[key]!)));
    return this.toolManifest.tools.map((tool) => {
      const configured = tool.bridge === true
        ? Boolean((values.BURP_BRIDGE_TOKEN || process.env.BURP_BRIDGE_TOKEN) && (values.BURP_BRIDGE_URL || process.env.BURP_BRIDGE_URL || "http://host.docker.internal:8765"))
        : tool.family === "proxy"
          ? Boolean(values.BURP_PROXY_URL || process.env.BURP_PROXY_URL)
          : tool.env !== undefined
            ? configuredPath(tool.env) && (tool.client_env === undefined ? true : configuredPath(tool.client_env))
            : true;
      return {
        id: tool.name, name: tool.name, purpose: tool.purpose || `${tool.name}（未写文档）`,
        family: tool.family, agent: "main", built_in: true, risk: tool.risk, configured,
        status: configured ? "ready" : "unconfigured",
      } satisfies ToolStatus;
    });
  }

  /** Evidence-derived tool health. `windowSeconds` 0 means all time; projectId narrows the ledger. */
  toolHealth(opts: { windowSeconds?: number; projectId?: string } = {}): Record<string, unknown> {
    const windowSeconds = Math.max(0, Math.min(90 * 24 * 3600, Math.floor(Number(opts.windowSeconds) || 0)));
    const pid = opts.projectId ? workspace.safeProjectId(opts.projectId) : undefined;
    if (opts.projectId && (!pid || !workspace.getProject(this.cfg, pid))) return { ok: false, error: "project not found" };
    const since = windowSeconds > 0 ? Date.now() / 1000 - windowSeconds : 0;
    const rows = this.db.listBlackboxToolOutcomes(since, pid || undefined);
    const health = computeToolHealth(rows, this.toolStatuses());
    return {
      ok: true,
      updated_at: Date.now() / 1000,
      window_seconds: windowSeconds,
      project_id: pid || null,
      ...health,
    };
  }

  projectBundle(projectId: string): Record<string, unknown> | null {
    const pid = workspace.safeProjectId(projectId);
    if (!pid) return null;
    const proj = workspace.getProject(this.cfg, pid);
    if (!proj) return null;
    const candidates = this.db.listAssetCandidates(pid, { limit: 5000 });
    const sessions = this.db.listBlackboxSessions(pid, 200);
    proj.candidates = candidates;
    proj.candidate_count = candidates.length;
    proj.sessions = sessions;
    proj.session_count = sessions.length;
    proj.asset_map = buildAssetMap(this.db, pid);
    proj.finding_count = this.db.listFindings(pid, { limit: 1000 }).length;
    return proj;
  }

  projectAssets(projectId: string, opts: { limit?: number; status?: string } = {}): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, items: this.db.listAssets(pid, opts) };
  }

  projectCandidates(projectId: string, opts: { limit?: number; status?: string; minScore?: number } = {}): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, items: this.db.listAssetCandidates(pid, opts) };
  }

  /** Paged + server-filtered candidates for the assets page. */
  projectCandidatesPaged(projectId: string, opts: {
    limit?: number; offset?: number; status?: string; tag?: string; query?: string;
    minScore?: number; onlyReachable?: boolean; sort?: "score" | "recent";
  } = {}): { ok: boolean; error?: string; items?: Record<string, unknown>[]; total?: number; aggregates?: Record<string, number>; tags?: string[]; maxLastSeen?: number } {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const data = this.db.listAssetCandidatesPaged(pid, opts);
    return {
      ok: true,
      items: data.items,
      total: data.total,
      aggregates: {
        total: data.total, reachable: data.reachable, pending: data.pending, failed: data.failed,
        unscored: data.unscored, review_failed: data.review_failed,
      },
      tags: data.tags,
      maxLastSeen: data.maxLastSeen,
    };
  }

  /** Matching candidate ids only, for bulk actions / review scopes. */
  projectCandidateIds(projectId: string, opts: {
    status?: string; tag?: string; query?: string; minScore?: number; onlyReachable?: boolean; scope?: "all" | "pending" | "retry";
  } = {}): { ok: boolean; error?: string; ids?: string[] } {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, ids: this.db.listAssetCandidateIds(pid, opts) };
  }

  projectBlackboxSessions(projectId: string, limit = 100): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, items: this.db.listBlackboxSessions(pid, limit) };
  }

  /**
   * 焦点仪表盘：控制台右侧卡片的数据源（`#/blackbox` 。Focus Dashboard）。
   *
   * 黑盒焦虑的根因是"看不见消。：模型在打什么、还剩几轮、TP 烧了多少、有没有在空转。
   * 这里。checkpoint 里的 focus_usage / focus_convergence 原样暴露，配上规则上限做成进度条。
   */
  projectBlackboxFocus(projectId: string, sessionId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    const state = (session.checkpoint || {}) as RunCheckpoint;
    const focus = computeFocus(state);
    const usage = state.focus_usage && state.focus_usage.task_id === (focus?.task_id || "") ? state.focus_usage : undefined;
    const tasks = Object.entries(state.tasks || {})
      .filter(([, task]) => !["completed", "failed", "blocked"].includes(String(task.status || "")))
      .slice(0, 24)
      .map(([id, task]) => ({ id, status: String(task.status || ""), target: String(task.target || ""), purpose: String(task.purpose || "").slice(0, 120) }));
    return {
      ok: true,
      session_id: sessionId,
      status: session.status,
      focus_task_id: focus?.task_id || "",
      reason: focus?.reason || "",
      detail: focus?.detail || "",
      // 拓扑势能：焦点任务离最近高价值目标的成本（越小越近；undefined = 图里还不通）。
      potential: potentialView(graphState(state.graph), String(tasks.find(task => String(task.id) === String(focus?.task_id))?.target || "")),
      // 延迟通胀：慢目标上所有工具都变贵（见 tool-cost.ts）。
      latency: { avg_ms: Number(state.usage?.avg_latency_ms || 0), multiplier: latencyMultiplier(state.usage?.avg_latency_ms) },
      appeals_left: appealPoolLeft(state, this.focusLimits()),
      usage: usage || null,
      convergence: state.focus_convergence || null,
      macro_interrupt: state.macro_interrupt || null,
      session_convergences: Number(state.usage?.session_convergences || 0),
      limits: this.focusLimits(),
      tp_table: toolTpTable(),
      // 被操作员亲手收口的任务：可以，撤销收口"救回来，所以必须让前端看见。
      operator_blocked: Object.entries(state.tasks || {})
        // 兼容两种写法：新的是 outcome_code，老 checkpoint 里只有 outcome_reason。
        .filter(([, task]) => String((task as { outcome_code?: string }).outcome_code || "") === "operator_blocked"
          || String(task.outcome_reason || "") === "operator_blocked")
        .map(([id]) => id),
      tasks,
      directive: String((focusView(state) as { directive?: string }).directive || ""),
    };
  }

  /**
   * 人工干预焦点：强制收。/ 手动延期 1 。/ 切换焦点。
   *
   * 这些动作都要。checkpoint，否。HMR 之后的下一轮又把旧账读回来了。
   */
  updateProjectBlackboxFocus(projectId: string, sessionId: string, action: string, taskId = ""): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    const state = (session.checkpoint || {}) as RunCheckpoint;
    const focus = computeFocus(state);
    // ── 撤销收口：操作员连点之后必须能一键救回来 ──────────────────────────────
    // 强制收口把任务写。blocked/operator_blocked，这，人工判定没进，的标记，
    // 但它不该是一次性操作——误。9 下就得有 9 条能被退回去。
    if (action === "restore") {
      const restoreIds = Object.entries(state.tasks || {})
        .filter(([, task]) => String(task.outcome_reason || "") === "operator_blocked")
        .filter(([id]) => !taskId || id === taskId)
        .map(([id]) => id);
      if (!restoreIds.length) return { ok: false, error: "没有需要撤销的操作员收口" };
      for (const id of restoreIds) {
        const task = state.tasks![id]!;
        task.status = "pending";
        delete task.reason;
        delete task.outcome_reason;
      }
      // 焦点回到被救回来的第一条（或指定那条）；收口时 usage 已被删除，这里给一份干净预算。
      state.focus_task_id = taskId && restoreIds.includes(taskId) ? taskId : restoreIds[0]!;
      delete state.focus_convergence;
      delete state.focus_usage;
      this.db.addBlackboxEvent(pid, sessionId, "system", "focus-restore",
        `操作员撤销收口 ${restoreIds.join(", ")}：已退。pending，焦点回。${state.focus_task_id}。`,
        { task_ids: restoreIds, focus_task_id: state.focus_task_id, by: "operator" });
      this.db.updateBlackboxSession(pid, sessionId, { checkpoint: state });
      return { ok: true, restored: restoreIds, ...this.projectBlackboxFocus(projectId, sessionId) };
    }

    const target = taskId || focus?.task_id || "";
    if (!target || !state.tasks?.[target]) return { ok: false, error: "focus task not found" };
    const limits = this.focusLimits();
    if (action === "converge") {
      const task = state.tasks[target]!;
      task.status = "blocked";
      task.reason = "操作员强制收口：控制台上人工判定这条线索没有进展";
      task.outcome_reason = "operator_blocked";
      delete state.focus_convergence;
      delete state.focus_usage;
      this.db.addBlackboxEvent(pid, sessionId, "system", "focus-convergence",
        `操作员强制收。${target}：已标记 blocked，焦点将自动切换。`, { task_id: target, forced: true, by: "operator" });
    } else if (action === "extend") {
      // 手动延期：退回一轮预。+ 清掉待执行的收口指令，给模型一次机会。
      if (state.focus_usage) {
        state.focus_usage.turns = Math.max(0, state.focus_usage.turns - 1);
        state.focus_usage.no_progress_rounds = 0;
        state.focus_usage.appeals_used = Math.max(0, state.focus_usage.appeals_used - 1);
      }
      delete state.focus_convergence;
      this.db.addBlackboxEvent(pid, sessionId, "system", "focus-convergence",
        `操作员手动延。${target}：已退。1 轮预算并清除收口指令。`, { task_id: target, by: "operator", extend: true });
    } else if (action === "switch") {
      if (!state.tasks[target]) return { ok: false, error: "task not found" };
      // 前端的选项来自一次投影快照：刚被收口/跑完的任务可能还挂在列表里。
      // 切到一个已死任务会让焦点永远停在死节点上，所以这里硬拦。
      const switchStatus = String(state.tasks[target]!.status || "");
      if (["completed", "failed", "blocked"].includes(switchStatus)) {
        return { ok: false, error: `任务 ${target} 已经。${switchStatus}，不能再切成焦点` };
      }
      state.focus_task_id = target;
      delete state.focus_usage;
      delete state.focus_convergence;
      this.db.addBlackboxEvent(pid, sessionId, "system", "focus-lock",
        `操作员切换焦点到 ${target}。`, { focus_task_id: target, by: "operator", max_tp: limits.max_tp_per_task });
    } else {
      return { ok: false, error: "unknown action" };
    }
    this.db.updateBlackboxSession(pid, sessionId, { checkpoint: state });
    return { ok: true, ...this.projectBlackboxFocus(projectId, sessionId) };
  }

  /** 焦点预算上限（规则文。+ 默认值），仪表盘与准入用的是同一份。*/
  private focusLimits(issues?: string[]): FocusLimits {
    // 生产不抛错：一条废弃配置不该让整场会话起不来，但必须留痕（issues 由调用方落到 checkpoint）。
    return blackboxRules(this.cfg.tools_env?.values || {}, { issues }).focus_lock;
  }

  /**
   * 历程图的可视化视图（控制。`#/graph` 用）。
   *
   * 顺带。finding 。target/severity 传进去，Kill Chain 面板才能显示人能读的漏洞名，
   * 而不是一。`vuln:idor@host/path`。
   */
  projectBlackboxGraph(projectId: string, sessionId: string, options: { maxNodes?: number } = {}): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    const checkpoint = (session.checkpoint || {}) as { graph?: unknown; findings?: Record<string, { target?: string; severity?: string }> };
    const state = graphState(checkpoint.graph as never);
    const findings = Object.values(checkpoint.findings || {}).map(finding => ({
      target: String(finding.target || ""), severity: String(finding.severity || "unknown"),
    }));
    return {
      ok: true, session_id: sessionId, target: session.target, status: session.status,
      ...graphVisualView(state, { maxNodes: options.maxNodes ?? 300, killChainFindings: findings }),
    };
  }

  /**
   * 三个"代码替模型做决定"的协议（2026-10-28）。
   *
   * 起因。note.yun 那一轮（19 分钟 / 47 次调用）的三个致命脱节：
   *   。301 跳到 cloud.oppo.com 之后，模型又对旧 host 发了 6 次同样的请求。
   *   。burp.history 被当状态检查刷。6 次，299 条真实流量一条没被差分；
   *   ，一次字典吐。224 个节点，全部 untested。 次点。0 次采纳。
   *
   * 这里的每个分支都只做一件事：把"要不要跟"变成"必须。。
   */
  /**
   * 执行前装甲拦截（2026-10-28）。
   *
   * 三道闸，全部，进工具之，拒收，并且都写明替代动作—。
   * 只拒不说等于把模型丢在原地，它下一轮还会用同样请求撞同一面墙。
   */
  /**
   * 假设驱动的验证任务（2026-10-31）。
   *
   * 图里算出"哪里值得，之后，必须把它变成一条可执行任务，否则模型只会看到一段文字。
   * 同时只放。3 条，且待办已满（。0）时不再新增 —，任务簿爆掉比没任务更糟。
   */
  private enqueueHypothesisTasks(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    graph: ReturnType<typeof graphState>,
  ): number {
    const tasks = (progress.state.tasks ||= {}) as Record<string, Record<string, unknown>>;
    // 僵尸任务清理（2026-11-04）：H_ 任务一旦派出就永久占住「同 kind 同 host 只留一条」的名额，
    // 而它依赖的假设可能早就收口了（依赖失效归档 / 尝试耗尽 / 已 confirmed）。
    //
    // 实测 d59f5a15a4ea26aa：H_auth_wall_f9aa4097 创建于 11-03 11:09，一直 pending 到 11-04 04:07
    // 共 17 小时，而它点名的假设「auth_wall:ep:wanxiaozhi.aliyun.com/」早已不在池里。当天新生成的
    // 3 条 auth_wall 假设（.git/config、robots.txt、llms-full.txt）因此一条都派不出去——假设池修好了，
    // 派单通道却被一个死任务堵着。这里先把失去前提的任务收掉，名额才能流转。
    const known = new Map(graph.hypotheses.map(item => [item.id, item]));
    const orphaned: string[] = [];
    for (const [id, task] of Object.entries(tasks)) {
      if (!id.startsWith("H_")) continue;
      if (["completed", "blocked", "failed"].includes(String(task?.status || ""))) continue;
      const hypothesisId = String(task?.hypothesis_id || "");
      const hypothesis = hypothesisId ? known.get(hypothesisId) : undefined;
      // 假设仍在池里且未定案（active / evicted）→ 任务还有意义，放行。
      if (hypothesis && !isClosedHypothesis(hypothesis)) continue;
      /**
       * 收口说明要能被读者读懂（2026-11-05）。
       *
       * 旧写法只留 `closed_reason = "假设已收口（archived），任务不再需要执行"`，
       * `outcome_reason` 完全空 → 报告里这类任务只剩一行 `blocked`，看不出
       * **假设为什么被归档**。而归档原因就在假设自己身上（"尝试 3 次无进展"/
       * "依赖的节点已不存在"），必须带下来。
       */
      const hypothesisWhy = hypothesis
        ? `假设 ${hypothesisId} 已收口（${normalizeHypothesisStatus(String(hypothesis.status || ""))}）：${String(hypothesis.closed_reason || "未记录归档原因")}`
        : `假设 ${hypothesisId || "（未记录 id）"} 已不在池内：依赖的节点已失效或该假设已被淘汰`;
      Object.assign(task, settleTask(task, {
        code: "hypothesis_closed",
        reason: `${hypothesisWhy}。任务的前提已不存在，继续执行它没有意义。`,
        by: "control",
      }), {
        status: "blocked",
        // 旧字段保留（前端/旧报告按它显示一句话摘要），完整说明在 outcome_reason。
        closed_reason: hypothesis ? `假设已收口（${normalizeHypothesisStatus(String(hypothesis.status || ""))}），任务不再需要执行` : "假设已不在池内（依赖事实失效或已被淘汰），任务作废",
        closed_at: Date.now(),
      });
      orphaned.push(id);
    }
    if (orphaned.length) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "hypothesis-tasks-pruned",
        `作废 ${orphaned.length} 条失去前提的假设任务（${orphaned.join("、")}），释放派单名额。`,
        { task_ids: orphaned });
      // ② 被作废的若是当前强制/粘性焦点，同轮就顺延，别等下一轮重抢
      //（对照里「强制焦点任务派单后立刻被作废」正是漏在这里）。
      const prunedFocus = orphaned.filter(id => id === progress.state.focus_task_id || id === progress.state.forced_focus?.task_id);
      if (releaseFocusForPrunedTasks(progress.state, orphaned)) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "focus-release",
          `焦点任务已被作废（${prunedFocus.join("、") || orphaned[0]}），本轮同步放锁顺延。`,
          { task_ids: orphaned, reason: "pruned_focus_task" });
      }
    }
    const pending = Object.values(tasks).filter(task => !["completed", "blocked", "failed"].includes(String(task?.status || ""))).length;
    if (pending >= 10) return 0;
    const hostOf = (value: unknown): string => {
      try { return new URL(String(value || "")).host.toLowerCase(); } catch { return ""; }
    };
    const specs = hypothesisTasks(activeHypotheses(graph), {
      existing: id => Boolean(tasks[id]),
      // 同类推断在同一主机上只留一条在办（见 hypothesisTasks 的 occupied 注释）。
      // 巡检类例外：它是"逐页看一眼"，1 条/轮会让 18 个业务页排到 18 轮；
      // 上限与 hypothesisTasks 的 CONCURRENT_PER_HOST 保持一致（单一来源）。
      occupied: (kind, host) => {
        const live = Object.entries(tasks).filter(([id, task]) =>
          id.startsWith(`H_${kind}_`)
          && !["completed", "blocked", "failed"].includes(String(task?.status || ""))
          && (!host || hostOf(task?.target) === host));
        const limit = concurrencyOf(kind);
        return live.length >= (Number.isFinite(limit) ? limit : 1);
      },
      limit: Math.max(0, 3),
    });
    if (!specs.length) return 0;
    for (const spec of specs) {
      tasks[spec.id] = {
        status: "pending",
        target: spec.target,
        purpose: spec.purpose,
        reason: spec.reason,
        completion_criteria: spec.completion_criteria,
        deliverables: spec.deliverables,
        success_criteria: spec.success_criteria,
        fallback_strategy: spec.fallback_strategy,
        source: spec.source,
        hypothesis_id: spec.hypothesis_id,
        created_at: Date.now(),
      };
    }
    progress.state.planRevision = Number(progress.state.planRevision || 0) + 1;
    this.db.addBlackboxEvent(pid, sessionId, "system", "hypothesis-tasks",
      `假设驱动：${specs.length} 条假设转成验证任务（${specs.map(spec => spec.id).join("、")}），每条限 1-3 发并必须给 verdict。`,
      { task_ids: specs.map(spec => spec.id), hypothesis_ids: specs.map(spec => spec.hypothesis_id) });
    return specs.length;
  }

  /**
   * 硬出路段 3 兜底（2026-11-03）：第四态节点（发了包、没拿到状态码）在被死胡同规则
   * 拒收时，强制派一次补测任务。
   *
   * 为什么必须强制：`counts.probed_unknown` 与图例只是"提示"，实跑证明模型不会因此
   * 回头补测（会话 53a9ff8fca15e361：探针悬 27 分钟，最后带着 `200 + status_unknown`
   * 的矛盾态被封死）。而拒收又把"拿状态码"这个唯一动作挡住了——不强制就永远闭环不了。
   *
   * 为什么只在被拒时派：补测任务的正常入口是假设→任务链（段 1+2，低优先级、有空位才入）。
   * 这里是"正常入口没生效"的兜底，所以它绕过 pending 上限，但每个节点只发一次。
   */
  private forceRetestTask(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    node: GraphNode,
  ): boolean {
    if (!isProbedButUnknown(node)) return false;
    if (node.properties.retest_attempted === true) return false;
    node.properties.retest_attempted = true;
    const tasks = (progress.state.tasks ||= {}) as Record<string, Record<string, unknown>>;
    const probedBy = String(node.properties.probed_by || "");
    const id = `H_retest_for_status_${createHash("sha1").update(node.id).digest("hex").slice(0, 8)}`;
    if (tasks[id] && !["completed", "blocked", "failed"].includes(String(tasks[id]?.status || ""))) return true;
    const target = `https://${String(node.id).replace(/^ep:/, "")}`;
    tasks[id] = {
      status: "pending",
      target,
      purpose: `补测：${node.id} 打过包但没拿到状态码${probedBy ? `（工具 ${probedBy}）` : ""}。`
        + `用 http.request（或 browser.open）发一发，取到真实状态码即可——`
        + `不要再用${probedBy ? ` ${probedBy}` : "原来那个工具"}重打，那只会再得到一次"没状态码"。`,
      reason: `死胡同兜底补测：第四态未补齐（${probedBy || "无状态码"}）`,
      completion_criteria: "对该目标发一发并拿到真实状态码（404/403 也是结论：说明路由存在且被拒绝）",
      deliverables: ["status_code:number"],
      success_criteria: "响应里出现明确状态码",
      fallback_strategy: "再失败就记 inconclusive 并写明失败方式（超时/被墙/连接重置），不要换 payload 重打",
      source: "dead_end_fallback",
      hypothesis_id: `retest_for_status:${node.id}`,
      created_at: Date.now(),
    };
    this.db.addBlackboxEvent(pid, sessionId, "system", "retest-forced",
      `${node.id} 处于第四态（无状态码${probedBy ? `，来自 ${probedBy}` : ""}）却被死胡同拒收：强制派补测任务 ${id}，用 http.request/browser.open 取一次状态码（每节点仅一次）。`,
      { node: node.id, task_id: id, probed_by: probedBy });
    return true;
  }

  /** 端点节点 id 里去。host 之后的模板路径：`ep:h/api/user/{id}` 。`/api/user/{id}`。*/
  private templatePathOf(url: string): string {
    const match = /^ep:[^/]+(\/.*)?$/.exec(endpointNodeId(url));
    return match?.[1] || "/";
  }

  /** 这次请求。`{id}` 位置上真正打过的对象值。*/
  private objectValuesFor(url: string): string[] {
    if (!url) return [];
    return objectValuesOf(url, this.templatePathOf(url));
  }

  /**
   * 身份接线。026-10-31）：，这次请求带没带登录，变成可核对的事实。
   * 显式 input.identity > 目标 host 的会话类 Cookie > anon。
   */
  private identityOf(pid: string, target: string, explicit?: unknown): IdentityState {
    let cookies: unknown[] = [];
    try {
      const jar = this.db.getProjectCookies(pid);
      if (Array.isArray(jar)) cookies = jar;
    } catch { cookies = []; }
    return resolveIdentity({ explicit: typeof explicit === "string" ? explicit : "", cookies: cookies as never, target: target || "" });
  }

  private recordIdentity(pid: string, sessionId: string, progress: BlackboxProgress, identity: IdentityState): void {
    progress.state.identities ||= {};
    const known = progress.state.identities[identity.role];
    if (!known) {
      progress.state.identities[identity.role] = {
        role: identity.role, source: identity.source, host: identity.host,
        cookie_names: identity.cookie_names, first_seen: Date.now(),
      };
      this.db.addBlackboxEvent(pid, sessionId, "system", "identity",
        `身份接线：${identityDirective(identity)}`,
        { identity: identity.role, source: identity.source, host: identity.host, cookie_names: identity.cookie_names });
      return;
    }
    if (known.source !== identity.source || known.host !== identity.host) {
      known.source = identity.source;
      known.host = identity.host;
      known.cookie_names = identity.cookie_names;
    }
  }

  /** 当前主身份（auth 优先）的一句话，进 graph_view。*/
  private primaryIdentity(progress: BlackboxProgress): string | undefined {
    const map = progress.state.identities || {};
    const pick = map["auth"] || Object.values(map).find(item => item.role !== "anon") || map["anon"];
    if (!pick) return undefined;
    return identityDirective({ role: pick.role, source: pick.source as IdentityState["source"], host: pick.host, cookie_names: pick.cookie_names || [] });
  }

  private armorGate(
    progress: BlackboxProgress,
    request: { tool: string; input?: unknown; task_id?: string },
    requestUrl: string,
  ): { code: string; message: string; hint: string } | undefined {
    const input = (request.input || {}) as Record<string, unknown>;

    // ，主权域锁。01 之后。host 一律不再接受请求。
    if (requestUrl) {
      const moved = violatesSovereignty(progress.state as never, requestUrl);
      if (moved) {
        // 分流：已探过的旧 host 路径 = 纯重复，直接拒；
        // 没探过的。host 路径最多放 3 条——catch-all/同形 30x 的证明需。3 条样本，
        // 一律锁死会，这站所有路径都跳同一，这个真结论也挡掉（anomaly-scheduler 就靠它）。
        const known = Boolean(graphState(progress.state.graph).nodes[endpointNodeId(requestUrl)]);
        const fresh = (progress.state.sovereignty_fresh ||= []);
        if (known) {
          return {
            code: "sovereignty_moved",
            message: `${moved.from_host} 。${moved.code} 跳到 ${moved.to_host}，这条路径已探过，旧 host 域锁生效`,
            hint: `改打 ${moved.to_url}（主权已转移）。旧 host 只会继续。30x 。WAF 412，重复请求已由图里的 dead_end 标记`,
          };
        }
        if (fresh.length >= 3) {
          return {
            code: "sovereignty_moved",
            message: `${moved.from_host} 的新路径采样额度（${fresh.length} 条）已用完`,
            hint: `catch-all 判定已经够样本：全部改打 ${moved.to_url}，别在旧 host 上继续扩字典`,
          };
        }
        fresh.push(requestUrl);
      }
    }

    // 。SPA 缴械：纯外壳主机上禁用步兵工具。
    if (requestUrl && input.force_armored !== true) {
      const spa = spaDisarmed(progress.state as never, request.tool, requestUrl);
      if (spa) {
        return {
          code: "spa_disarmed",
          message: `${spa.host} 是 SPA 外壳（${spa.bytes}B），${request.tool} 在该主机被缴械`,
          hint: "改用 browser.network（渲染期真实 XHR，含 method/post_data）；browser.open 只能看 DOM。确需强制时传 input.force_armored=true",
        };
      }
    }

    // ，裸调 burp.history：没有过滤条件的 history 只是"状态检。不产生可证伪结论。
    if (request.tool === "burp.history") {
      const params = (input.params || {}) as Record<string, unknown>;
      // 顶层键与 params 都算：schema 。host/status 等提升到了顶层（params 。burp.history 会被执行器拒收）。
      const scoped = ["url", "method", "status", "status_code", "path", "host"]
        .some(key => (input[key] !== undefined && input[key] !== "") || (params[key] !== undefined && params[key] !== ""));
      if (!scoped) {
        return {
          code: "bare_history_use",
          message: "burp.history 未带任何过滤条件（url/method/status/path/host）",
          hint: "需要差分就走 recon.traffic_diff（输入 url 与 evidence_id_a/evidence_id_b，直接给 diff_score）；确实要看原始记录时带上过滤条件",
        };
      }
    }
    return undefined;
  }

  /**
   * recon.traffic_diff：结构化差分探针。
   *
   * 模型给两条观测（或一。URL + 基线证据），控制面算。diff_score 并回一。verdict。
   * 目的是让"。burp.history 。total 变大"这种没有结论的动作失去意义。
   */
  private runTrafficDiff(
    pid: string,
    sessionId: string,
    input: Record<string, unknown>,
  ): { ok: boolean; summary: string; data: Record<string, unknown> } {
    const session = this.db.getBlackboxSession(pid, sessionId) as { evidence?: Array<Record<string, unknown>> } | undefined;
    const rows = (session?.evidence || [])
      .filter((item: Record<string, unknown>) => String(item.kind) === "tool-result")
      .map((item: Record<string, unknown>) => {
        const data = (item.data || {}) as Record<string, unknown>;
        return {
          evidence_id: String(item.id),
          url: String(data.url || ""),
          status: Number(data.status ?? 0) || undefined,
          headers: (data.headers || {}) as Record<string, string>,
          body: typeof data.body === "string" ? data.body.slice(0, 20000) : undefined,
          body_bytes: Number(data.body_bytes ?? 0) || undefined,
          content_length: Number(data.content_length ?? 0) || undefined,
          content_type: String(data.content_type || ""),
        };
      })
      .filter(row => row.url);
    const idA = String(input.evidence_id_a || input.baseline_evidence_id || "");
    const idB = String(input.evidence_id_b || "");
    const url = String(input.url || "");
    let before = idA ? rows.find(row => row.evidence_id === idA) : undefined;
    let after = idB ? rows.find(row => row.evidence_id === idB) : undefined;
    if (!before || !after) {
      const same = rows.filter(row => row.url === url || row.url.replace(/\/$/, "") === url.replace(/\/$/, ""));
      const pair = pickPair(same);
      if (pair) {
        before ||= pair[0];
        after ||= pair[1];
      }
    }
    const diff = diffResponses(before, after);
    return {
      ok: diff.status !== "insufficient",
      summary: diff.status === "insufficient"
        ? `traffic_diff: ${diff.verdict}`
        : `traffic_diff ${diff.status}（diff_score=${diff.diff_score}）：${diff.verdict}`,
      data: {
        ...diff,
        baseline: before ? { evidence_id: before.evidence_id, status: before.status } : null,
        current: after ? { evidence_id: after.evidence_id, status: after.status } : null,
        compared_url: url || before?.url || after?.url || "",
      },
    };
  }

  /**
   * 引水：站点声明文件（robots.txt / sitemap.xml）的重试调度。
   *
   * 实测依据（2026-11-04 会话 5b59aa1d059b56da）：`/sitemap.xml` 第一次抓取拿到 403 之后，
   * 模型再没碰过它，站点自报的 18 个 `/help/*.html` 业务页整批丢失——业务面归零。
   * 而在另一次会话（09a67a8a9aa67cec）里同一文件 200，这 18 页全部入图。
   * 差别不在代码接没接上，而在"一次失败被当成了结论"。
   *
   * 所以引水不靠模型自觉：控制面自己记账（协议零记 status/verdict）、自己判冷却、
   * 自己在需要时建任务并把焦点钉上去；拿到终态由控制面结案，耗尽重试也由控制面收口，
   * 避免这条线永远悬着卡住验收。
   */
  private ensureSiteDeclaration(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    targetUrl: string,
  ): void {
    let origin = "";
    let host = "";
    try {
      const url = new URL(targetUrl);
      origin = url.origin;
      host = url.host.toLowerCase();
    } catch { return; }
    if (!host) return;

    const taskId = "T_SITE_DECLARATION";
    const task = progress.state.tasks[taskId];
    const hostState = progress.state.site_declaration?.[host];
    const need = declarationNeed(hostState, Date.now());

    // ── 终态：拿齐了 / 耗尽重试——由控制面结案，不等模型申报 ──
    if (!need.need && (need.reason === "done" || need.reason === "exhausted")) {
      // 同一结论只播报一次：这轮之后不再重复写事件、不重复算任务。
      if (hostState?.settled_at) return;
      /**
       * 任务可能一次都没建出来（2026-11-05 实测会话 bd2b519a4f5037c5）：
       * 模型自己就在 45s 冷却边界上重打，控制面每次检查都落在 cooldown，
       * attempts 冲到 5 仍然没有 T_SITE_DECLARATION。
       * 这时候不能静默 return——把结论播报出去，模型才知道业务面已经到手、别再打。
       */
      if (!task || ["completed", "blocked", "failed"].includes(String(task.status))) {
        if (hostState) {
          progress.state.site_declaration = {
            ...(progress.state.site_declaration || {}),
            [host]: { ...hostState, settled_at: Date.now() },
          };
        }
        this.db.addBlackboxEvent(pid, sessionId, "system", "site-declaration-settled",
          `引水结论（无任务）：${host} 的 ${this.declarationSummary(hostState)}。`
            + `${need.delivered.length ? `已交付 ${need.delivered.join("、")}，业务面已进图；` : ""}`
            + `${need.missing.length ? `未终结 ${need.missing.join("、")} 不再重试。` : ""}`,
          { host, reason: need.reason, files: hostState?.files || {}, attempts: need.attempts, delivered: need.delivered });
        return;
      }
      if (need.reason === "done") {
        const ids = this.declarationEvidence(pid, sessionId, taskId);
        /**
         * 账上有终态、却找不到本任务的证据：不能直接置 completed。
         * 验收对 completed 任务要求 `evidence_ids` 非空且每条都归属本任务
         * （TASK_EVIDENCE_MISSING / completion_without_valid_task_evidence），
         * 硬置会让整场 run 永远 ready 不了。按 blocked 收口，理由如实写。
         */
        if (!ids.length) {
          progress.state.tasks[taskId] = {
            ...settleTask(task, {
              code: "declaration_unmet",
              reason: `引水账显示已拿到终态（${this.declarationSummary(hostState)}），但证据账本里没有属于本任务的成功证据：`
                + `状态码 200 不能单独作为结论，缺一份带正文/字节数的响应。按未达成收口。`,
              by: "control",
            }),
            status: "blocked",
          };
        } else {
          progress.state.tasks[taskId] = {
            ...task,
            status: "completed",
            evidence_ids: ids,
            outcome_reason: `引水完成：声明文件已拿到终态（${this.declarationSummary(hostState)}）`,
            completion_proof: [...(task.completion_proof || []), {
              at: Date.now(), reason: "站点声明文件引水完成", evidence_ids: ids, deliverables_met: ["site_declaration"],
            }],
          };
        }
      } else {
        /**
         * 重试耗尽。这里必须分两种，不能一律判失败（2026-11-05 实测会话 773eae1a2d5b6c0c）：
         *
         * 那次 `/sitemap.xml` 在 06:49:21 拿到 200、18 个 /help 页全部入图（source=sitemap），
         * 而 `/robots.txt` 的 200 因正文没带回来被判 retry，4 轮后整条任务落 blocked，
         * 结案文案还写成「3 轮后仍被挡（/robots.txt 200；/sitemap.xml 200）」——
         * 两个 200 却说被挡，模型据此认为业务面没拿到，转头回去爬静态路径。
         *
         * 只要有一个文件拿到 ok，业务面就是**已到手**：任务按 completed 结案，
         * 未终结的那个文件写进理由，交给爬取 / JS 反向补。
         */
        const delivered = need.delivered;
        const pendingLabel = need.missing.join("、") || "无";
        if (delivered.length) {
          const ids = this.declarationEvidence(pid, sessionId, taskId);
          progress.state.tasks[taskId] = ids.length ? {
            ...task,
            status: "completed",
            evidence_ids: ids,
            outcome_reason: `引水已交付 ${delivered.join("、")}（${this.declarationSummary(hostState)}）；`
              + `${pendingLabel} 仍在风控抖动窗口内，最多 ${SITE_DECLARATION_MAX_ATTEMPTS} 轮后不再重试，改由爬取 / JS 反向补。`,
            completion_proof: [...(task.completion_proof || []), {
              at: Date.now(), reason: `站点声明文件部分交付（${delivered.join("、")}）`, evidence_ids: ids, deliverables_met: ["site_declaration"],
            }],
          } : {
            ...settleTask(task, {
              code: "declaration_unmet",
              reason: `引水账显示已交付 ${delivered.join("、")}（${this.declarationSummary(hostState)}），`
                + `但证据账本里没有属于本任务的成功证据，按未达成收口；${pendingLabel} 未终结。`,
              by: "control",
            }),
            status: "blocked",
          };
        } else {
          progress.state.tasks[taskId] = {
            ...settleTask(task, {
              code: "declaration_unmet",
              reason: `引水收口：${need.attempts || SITE_DECLARATION_MAX_ATTEMPTS} 轮后仍被挡（${this.declarationSummary(hostState)}）。`
                + `声明文件这条线不再重试，业务面改由爬取 / JS 反向 / burp.history 补。`,
              by: "control",
            }),
            status: "blocked",
          };
        }
      }
      releaseFocus(progress.state, taskId);
      // 同一结论只播报一次（无论走任务结案还是无任务播报）。
      progress.state.site_declaration = {
        ...(progress.state.site_declaration || {}),
        ...(hostState ? { [host]: { ...hostState, settled_at: Date.now() } } : {}),
      };
      // 事件口径跟着真实结论走：账上 done 但缺证据时任务已按 blocked 收口，别报"引水完成"。
      const settled = String(progress.state.tasks[taskId]?.status || "");
      const partial = settled === "completed" && need.missing.length > 0;
      this.db.addBlackboxEvent(pid, sessionId, "system",
        settled === "completed" ? "site-declaration-done" : "site-declaration-blocked",
        settled === "completed"
          ? `${partial ? "引水部分交付" : "引水完成"}：${host} 的 ${this.declarationSummary(hostState)}；`
            + `${partial ? `未终结 ${need.missing.join("、")} 不再重试；` : ""}任务 ${taskId} 已结案。`
          : `引水收口：${host} 的 ${this.declarationSummary(hostState)}——${
            need.reason === "exhausted" ? `${need.attempts || SITE_DECLARATION_MAX_ATTEMPTS} 轮后仍被墙，不再重试` : "账上终态缺少本任务证据"
          }。`,
        { host, task_id: taskId, reason: need.reason, status: settled, files: hostState?.files || {}, attempts: need.attempts, delivered: need.delivered });
      return;
    }

    // ── 冷却中：把钉在引水上的焦点摘掉，否则这 45s 里模型打什么都会被焦点锁拒收 ──
    if (!need.need && need.reason === "cooldown") {
      releaseFocus(progress.state, taskId);
      return;
    }
    if (!need.need) return;

    /**
     * 从未尝试过：只提示，不建任务、不抢焦点（2026-11-05）。
     *
     * 真正的 bug 不是"模型从不打 sitemap"（实测它会打），而是"打了拿到 403 就不再打"。
     * 每个会话无条件多一条 pending 任务会改变整个任务簿与验收口径——实测
     * test/blackbox-lifecycle 的 14 条用例因此全部多跑一轮。所以首次只给提示，
     * 强制力留给 retry。
     */
    if (need.reason === "first") {
      progress.addInterrupts([{
        id: `site-declaration:hint:${host}`,
        kind: "site_declaration",
        severity: "medium",
        text: `${host} 的站点声明文件（${need.missing.join("、")}）还没取过。`
          + `它声明的是站点自己的业务面：实测同一 sitemap 里 18 个 /help 页，爬取一条都没覆盖到。`
          + `403/412 是风控抖动不是结论，换签名（Cache-Control: no-cache、?ts=）重打。`,
        data: { host, missing: need.missing },
      }]);
      return;
    }

    // ── 需要引水：建任务（已存在就更新重试说明，不重复建） ──
    const spec = declarationTaskSpec(origin, need, hostState);
    if (!task) {
      progress.state.tasks[taskId] = {
        status: "pending",
        target: spec.target,
        purpose: spec.purpose,
        reason: spec.reason,
        completion_criteria: spec.completion_criteria,
        deliverables: spec.deliverables,
        success_criteria: spec.success_criteria,
        source: "system:site_declaration",
        contract_required: false,
      } as never;
      this.db.addBlackboxEvent(pid, sessionId, "system", "site-declaration",
        `引水：${host} 的站点声明文件还没有终态（缺 ${need.missing.join("、")}），建任务 ${taskId} 并钉住焦点。`
        + `声明文件是业务面的权威来源：实测同一 sitemap 声明了 18 个 /help/*.html，爬取一条都没覆盖到。`,
        { host, missing: need.missing, attempts: need.attempts });
    } else if (String(task.status) !== "pending") {
      progress.state.tasks[taskId] = { ...task, status: "pending", reason: spec.reason, target: spec.target };
    } else {
      progress.state.tasks[taskId] = { ...task, reason: spec.reason, target: spec.target };
    }

    // 焦点只在"没有别的活着的强制焦点"时抢：SPA 缴械、主权转移优先级更高。
    // 这条判断已收进 lockFocus 的不变量 I3（存在活锁时默认不抢），这里不再自己算。
    lockFocus(progress.state, {
      task_id: taskId, kind: "site_declaration",
      note: `引水优先：先取回 ${host} 的 ${need.missing.join(" 与 ")}。403/412/429/5xx/空响应都不是结论（风控抖动），`
        + `换签名重打（加 Cache-Control: no-cache 或 ?ts=<时间戳>），拿到 200 有正文 / 404 / 401 才算收口。`,
    });
    progress.addInterrupts([{
      id: `site-declaration:${host}:${need.attempts}`,
      kind: "site_declaration",
      severity: "high",
      text: `${host} 的站点声明文件（${need.missing.join("、")}）还没有终态，先把它取回来：`
        + `它声明的是站点自己的业务面（实测 18 个 /help 页只出现在 sitemap 里，爬取一条没覆盖）。`
        + `403/412 是风控抖动不是结论，换签名（Cache-Control: no-cache、?ts=）重打。`,
      data: { host, missing: need.missing, attempts: need.attempts },
    }]);
  }

  /**
   * 漂移升级阶梯（2026-11-09，A4）。
   *
   * 现场对照组：`component_drift` 从第 2 轮就被升成 high 并附了"下一轮至少发 1 条"
   * 的可复制模板，模型照样在原来的块里打了 129 轮。只提示不动调度，等于没有机制——
   * 所以这里按轮次两级升级：第 3 轮落成真任务（可派发、可结案、可记账），
   * 第 6 轮用 `lockFocus` 强锁，把"要不要换面"从判断题变成调度决定。
   *
   * 两处克制：① 任务已是终态就不再重开（那说明"这块判死"已经是结论）；
   * ② 上锁失败（已有更硬的锁）不报错，强锁优先级本来就更高。
   */
  private escalateGraphDrift(pid: string, sessionId: string, progress: BlackboxProgress, roots: string[], rounds: number, tiers: string[] = []): void {
    const state = progress.state;
    /**
     * 任务 id 由 roots 派生（2026-11-09）。
     *
     * 一开始用的是固定 id，结果和模型自己建的 `T_GRAPH_DRIFT_ROOTS` 撞了：那条任务
     * 早已 completed（结论是"三个 Root 里只有一条有 API 语义，其余两个已 404"），
     * 于是"已终态就不再催"的分支把升级整个吞掉——142 轮漂移照旧，机制等于没上。
     * 按批派生后：同一批只建一张单（幂等），换批就是新单，历史结论不会被覆盖。
     */
    const taskId = `${DRIFT_TASK_ID}_${createHash("sha1").update(roots.join("|")).digest("hex").slice(0, 8)}`;
    const existing = state.tasks?.[taskId];
    const terminal = existing ? ["completed", "blocked", "failed"].includes(String(existing.status)) : false;
    if (terminal) {
      // 这一批已经有终态结论（打过了、判死了）：别用同一张单反复催，等换批。
      return;
    }
    if (!existing) {
      /**
       * 任务文案按档走（2026-11-10，S2-②③）。
       *
       * 同一句话套在三种面上是错的：`unprobed` 是"没人请求过，先确认死活"，
       * `rewall` 是"打过但被 401/403 挡住，换身份再打"，其余才是"打过之后要么长节点要么判死"。
       * 派活派错方向，比不派更浪费轮次。
       */
      const wallOnly = tiers.length > 0 && tiers.every(tier => tier === "rewall");
      const faceOnly = tiers.length > 0 && tiers.every(tier => tier === "unprobed" || tier === "revived");
      state.tasks[taskId] = {
        status: "pending",
        target: roots[0],
        purpose: wallOnly
          ? `把攻击面移出当前分量：这批 ${roots.length} 条是鉴权墙（401/403），带已导入的认证种子或换身份各打一次，把差异写回图。`
          : faceOnly
            ? `把攻击面移出当前分量：这批 ${roots.length} 条是页面里出现过、但从没人请求过的接口，各打一次先确认死活，并把结果写回图。`
            : `把攻击面移出当前分量：对图巡检给出的 ${roots.length} 条未测端点各发一次请求，并把结果写回图。`,
        reason: `图巡检连续 ${rounds} 轮判定分量漂移（一直只在同一块里活动），插话未被采纳，转成任务强制执行。`,
        completion_criteria: wallOnly
          ? `用已导入的认证种子（或另一身份）对 ${roots.join("、")} 各发 1 次 http.request，记录状态码与正文差异；任一端点从 401/403 变成 200/3xx 即算达成。`
          : faceOnly
            ? `对 ${roots.join("、")} 各至少发 1 次 http.request 并记录状态码：200/3xx 就继续挖，404/410 即判死（会自动写墓碑），401/403 记成鉴权墙。`
            : `对 ${roots.join("、")} 各至少发 1 次 http.request（anonymous 基线即可），把状态码与正文指纹写成证据；任一端点长出新节点或判死即算达成。`,
        deliverables: ["每个 root 一条 tool-result 证据"],
        success_criteria: ["至少 1 条 root 被真实请求过"],
        source: "system:graph_drift",
        contract_required: false,
      } as never;
      this.db.addBlackboxEvent(pid, sessionId, "system", "graph-drift-task",
        `图巡检已升级为任务 ${taskId}：把攻击面移出当前块，先打 ${roots.slice(0, 2).join("、")}。`,
        { roots, rounds, task_id: taskId });
    }
    // 记住这批欠账对应的任务，采纳时按 id 精准解锁。
    if (progress.state.graph_drift) progress.state.graph_drift.task_id = taskId;
    if (rounds >= 6) {
      const locked = lockFocus(state, {
        task_id: taskId,
        kind: "graph_drift",
        note: `图巡检连续 ${rounds} 轮判定分量漂移且未被采纳：本任务成为唯一焦点，先打 ${roots.join("、")}。`,
      });
      if (locked) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "graph-drift-lock",
          `图巡检连续 ${rounds} 轮未采纳，已把焦点强锁到 ${taskId}。`, { roots, rounds });
      }
    }
  }

  /** 属于引水任务本身的成功证据（验收要求 completed 任务必须有本任务证据，否则 TASK_EVIDENCE_MISSING）。 */
  private declarationEvidence(pid: string, sessionId: string, taskId: string): string[] {
    const rows = (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[];
    return rows
      .filter(row => String(row.kind) === "tool-result"
        && String((row.data as Record<string, unknown> | undefined)?.task_id || "") === taskId)
      .map(row => String(row.id || ""))
      .filter(Boolean)
      .slice(0, 3);
  }

  /** 人可读的声明文件账（结案文案与事件共用）。 */
  private declarationSummary(state: DeclarationHostState | undefined): string {
    if (!state) return "无记录";
    return SITE_DECLARATION_PATHS.map(path => {
      const record = state.files[path];
      if (!record) return `${path} 未取`;
      return `${path} ${record.status || "无响应"}${record.wall ? `（${record.wall}）` : ""}`;
    }).join("；");
  }

  private applyProtocolHooks(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    input: {
      tool: string;
      data: Record<string, unknown>;
      requestUrl: string;
      ingested: { newNodes: string[]; candidates?: string[] };
      parentUrl: string;
    },
  ): void {
    const stamp = String(Date.now()).slice(-8);

    // ── 协议零：站点声明文件引水记账（2026-11-05）──
    // 只记账，不在这里派任务：派任务要按轮判冷却与焦点，放在主循环的 ensureSiteDeclaration。
    // 记账单独做的理由：`/sitemap.xml` 的 403 必须被标成"待重试"，而不是被当成"站点没有 sitemap"。
    const declPath = declarationPathOf(input.requestUrl);
    if (declPath) {
      let declHost = "";
      try { declHost = new URL(input.requestUrl).host.toLowerCase(); } catch { declHost = ""; }
      if (declHost) {
        const declStatus = Number(input.data.status ?? input.data.status_code ?? 0) || 0;
        /**
         * 正文长度要区分"未知"与"确实是 0"：工具只回头部时 content_length 和 body 都不在，
         * 旧写法 `?? 0` 把未知压成 0，robots 的合法 200 就被判成"空壳"反复重试
         * （实测会话 773eae1a2d5b6c0c：robots 连续 4 轮 200，耗尽后拖垮整条引水任务）。
         */
        const rawBytes = input.data.content_length
          ?? (typeof input.data.body === "string" ? input.data.body.length : undefined);
        const declBytes = rawBytes === undefined || rawBytes === null ? undefined : Number(rawBytes) || 0;
        const declWall = wallOf(input.data);
        const prevVerdict = progress.state.site_declaration?.[declHost]?.files[declPath]?.verdict;
        const record = recordDeclaration(progress.state.site_declaration?.[declHost], {
          path: declPath, status: declStatus, ...(declBytes !== undefined ? { bytes: declBytes } : {}),
          ...(declWall ? { wall: declWall.kind } : {}), at: Date.now(),
        });
        progress.state.site_declaration = { ...(progress.state.site_declaration || {}), [declHost]: record };
        const verdict = record.files[declPath]?.verdict;
        /**
         * 拿到终态时由控制面自己开一张**盖本任务章**的收据（2026-11-05）。
         *
         * 为什么必须开：引水账（site_declaration）与证据账本（evidence）是两套账。
         * 结案时 declarationEvidence 只认 `kind=tool-result && data.task_id=T_SITE_DECLARATION`
         * 的证据，而这次抓取是模型以**别的任务**名义打的，证据挂在那个任务上。
         * 于是出现"引水账说 /robots.txt 200、账本里查不到本任务证据"→ 只能按 blocked 收口
         * （实测 094d157f6fc028f6：T_SITE_DECLARATION 明明拿到了两个 200 却被判未达成，
         * 整场会话 completed 数为 0，判据直接落 blocked）。
         *
         * 工作确实是控制面做的（它判定了终态），收据就该由它开；这不是补证据，
         * 是把已经发生的事实记到正确的账上。只在**终态发生变化**时开一张，避免每个 200 都记一条。
         */
        if (verdict && verdict !== "retry" && prevVerdict !== verdict) {
          this.db.addBlackboxEvidence(pid, sessionId, {
            kind: "tool-result", source: "site_declaration",
            summary: `站点声明文件引水：${declHost}${declPath} → ${declStatus || "无响应"}（判定 ${verdict}）`.slice(0, 8000),
            confidence: verdict === "ok" ? "high" : "medium",
            data: {
              ok: true, task_id: "T_SITE_DECLARATION", url: input.requestUrl, status: declStatus, verdict,
              ...(declBytes !== undefined ? { content_length: declBytes } : {}),
              ...(declWall ? { wall: declWall.kind } : {}),
            },
          });
        }
        if (verdict === "retry") {
          this.db.addBlackboxEvent(pid, sessionId, "system", "site-declaration-retry",
            `${declHost}${declPath} 返回 ${declStatus || "无响应"}${declWall ? `（命中墙 ${declWall.kind}）` : ""}：这是风控抖动窗口，`
            + `不是结论（同一 URL 实测 6 分钟内 200 → 403 → 200）。冷却 ${Math.round(SITE_DECLARATION_COOLDOWN_MS / 1000)}s 后重打，`
            + `第 ${record.attempts}/${SITE_DECLARATION_MAX_ATTEMPTS} 轮；不要把这个状态码写进结案理由。`,
            { host: declHost, path: declPath, status: declStatus, wall: declWall?.kind || null, attempts: record.attempts, verdict });
        }
      }
    }

    // ── 协议一：主权转移（跨主。301/302）──
    const hop = redirectOf(input.data, input.requestUrl);
    if (hop) {
      const before = (progress.state.redirect_hops || []).length;
      const moved = applySovereignty(progress.state as never, hop, Date.now());
      if (moved) {
        // 焦点跟着搬：被改写的任务里，优先，当前焦点"设为强制焦点。
        const current = String(progress.state.focus_task_id || "");
        const target = moved.rewrites.includes(current) ? current : moved.rewrites[0];
        if (target) {
          // 主权转移是"代码替模型做的决定"，允许覆盖普通强制焦点（preempt）。
          lockFocus(progress.state, {
            task_id: target, kind: "sovereignty", preempt: true,
            note: `主权已从 ${moved.from_host} 转移。${moved.to_host}：对本任务的新目标做基线，不要再碰旧 host`,
          });
        }
        this.db.addBlackboxEvent(pid, sessionId, "system", "sovereignty-transfer",
          `主权转移：${moved.from_host} ${hop.code} → ${moved.to_host}；改写任务 ${moved.rewrites.join("、") || "无"}；旧 host 已上锁。`,
          { from: moved.from_host, to: moved.to_host, code: hop.code, rewrites: moved.rewrites, forced_focus: target || null });
      } else if ((progress.state.redirect_hops || []).length > before) {
        /**
         * 跳转不成立时也必须留痕（2026-11-04）。
         *
         * 实测：`wanxiaozhi.aliyun.com/` 被临时风控 302 到 `www.aliyun.com/notfound`，
         * 不加提示的话模型会自己跟去父域门户——那是另一套应用，越出授权范围。
         * 这里把"为什么不搬"写进事件流，同时给出正确动作（等一会儿重打原 URL）。
         */
        const reason = sovereigntyRejection(hop, progress.state.redirect_hops || []);
        if (reason === "parent_portal" || reason === "notfound_target") {
          this.db.addBlackboxEvent(pid, sessionId, "system", "sovereignty-rejected",
            `${hop.from} 返回 ${hop.code} → ${hop.to}：这是${reason === "parent_portal" ? "父域门户兜底页" : " notfound 兜底页"}，不是站点搬家。`
            + `不要跟到 ${hop.to}（另一套应用，越权），也不要改写任务目标；等 30–60s 后重打原 URL 取基线。`,
            { from: hop.from, to: hop.to, code: hop.code, reason, host: (() => { try { return new URL(hop.from).host; } catch { return ""; } })() });
        }
      }
    }

    // ── 协议二：SPA 外壳 ，步兵缴械 + 强征特种兵任。──
    const spa = spaFingerprint(input.data);
    if (spa.is_spa && input.requestUrl) {
      let host = "";
      try { host = new URL(input.requestUrl).host.toLowerCase(); } catch { host = ""; }
      const known = progress.state.spa?.host === host;
      if (host && !known) {
        const purpose = `${host} 判定为纯 SPA 外壳：用可执行/可渲染的工具逆出真实 API 与鉴权入口`;
        const spaDeliverables = ["api_endpoints", "auth_entry"];
        /**
         * 查重（2026-11-05）：这一段以前是**无条件新建**，于是同一件事在簿子里有两份——
         * 主 agent 自己建的「SPA 外壳逆向：抓首页外壳，提取 .js bundle…」和系统在这里补的
         * `T_SPA_REVERSE_*`。两份都占待办额度，而强制焦点只锁后者：证据全记在后者名下，
         * 前者永远拿不到证据，最后只能被 settle 成 blocked。
         *
         * 实测 fb06499adcf889b5：T1 与 T_SPA_REVERSE_75985252 同 host、同"逆出接口面"，
         * 24 个 turns 全锁在后者，browser 抓到 85 条 XHR 却换不来一条 completed，
         * 整场 0 完成。duplicateOf 的文本相似度可能过不了阈值（一个写「bundle 与 baseURL」，
         * 一个写「真实 API 与鉴权入口」），所以补一条硬规则：同 host 且 purpose 点名 SPA/外壳/逆向。
         */
        const reverseLike = existingReverseTask(progress.state.tasks, host);
        /**
         * 顺序不能反：`duplicateOf` 在"已经生成过 T_SPA_REVERSE_*"的簿子上会命中它自己，
         * 于是复用分支等于什么都没做，T1 依旧被饿死。先认"已有的同 host 逆向任务"，
         * 没有再退回文本查重。
         */
        const reuseId = reverseLike || progress.duplicateOf(purpose, "unauth_exposure", input.requestUrl, spaDeliverables);
        const taskId = reuseId || `T_SPA_REVERSE_${stamp}`;
        const existingTask = progress.state.tasks[taskId];
        if (!existingTask) {
          progress.state.tasks[taskId] = {
            status: "pending",
            target: input.requestUrl,
            purpose,
            reason: `${spa.bytes}B HTML 外壳，挂载点特征 ${spa.signals.slice(0, 2).join("、")}，外部脚本仅 ${spa.script_src} 个——字典与裸 GET 在这条路上无效`,
            completion_criteria: "产出至少 1 条真实 XHR/接口路径（含 method 与参数名），或证明该站无匿名可读接口（附证据 id）",
            playbook: "unauth_exposure",
            deliverables: spaDeliverables,
            success_criteria: "至少 1 条接口带 method + 参数名，或一致性负向结论",
            source: "system:spa",
            contract_required: false,
          } as never;
        } else if (existingTask.status === "pending" || existingTask.status === "running") {
          // 复用时不重写任务（会冲掉主 agent 写的判据），只把缺的交付契约补上：只补空、不覆盖。
          const rec = existingTask as unknown as Record<string, unknown>;
          if (!rec.playbook) rec.playbook = "unauth_exposure";
          if (!Array.isArray(rec.deliverables) || !rec.deliverables.length) rec.deliverables = spaDeliverables;
          if (!rec.success_criteria) rec.success_criteria = "至少 1 条接口带 method + 参数名，或一致性负向结论";
        }
        progress.state.spa = { host, at: Date.now(), bytes: spa.bytes, signals: spa.signals, task_id: taskId };
        // 已经终态的任务不再锁焦点：它已经给过结论了，锁住只会把下一件事饿死。
        const spaSettled = ["completed", "blocked", "failed"].includes(String(existingTask?.status || ""));
        // 强制焦点钉住 SPA 逆向：不靠轮数窗口，靠"结案 verdict"释放——agent 必须用 browser/exec
        // 逆出接口面并下结论（挖到洞→finding，或证明无匿名可读接口→带证据引用的负面结案），
        // 焦点才会顺延到下一个任务。真正的兜底见 focus_convergence（无增益→逼出结案）与代码强制 blocked。
        // 缴械是"这一类工具被禁"，不是"这个任务更急"，所以只在本任务还没有更强制锁时生效（不 preempt）。
        if (!spaSettled) lockFocus(progress.state, {
          task_id: taskId, kind: "spa",
          note: "SPA 外壳强制焦点：必须用 browser.open（wait_until=networkidle）加载页面 + browser.network 取渲染期真实 XHR，或 exec.python 跑 SPA 抓取脚本（spa_mode.kit 已给骨架）；不要对该任务用 recon.content_discovery/nuclei/api_routes（已被缴械拒收）。其它任务的请求会被焦点锁拒收，直到本任务结案（completed/blocked/failed）——焦点不会因轮数松手，你必须真的逆出结论才切下一个任务。",
        });
        this.db.addBlackboxEvent(pid, sessionId, "system", "spa-disarm",
          `步兵缴械：${host} 判定为 SPA 外壳（${spa.bytes}B，特征 ${spa.signals.slice(0, 3).join("、")}）；`
            + (reuseId ? `复用已有任务 ${taskId}（不新建重复任务）` : `生成任务 ${taskId}`)
            + `，content_discovery/nuclei/api_routes 对该主机禁用。`,
          { host, bytes: spa.bytes, signals: spa.signals, task_id: taskId, reused: Boolean(reuseId) });
      }
    }

    // ── 协议三：字典聚类抽样（一。ingest 命中 。0 条路径时触发）──
    // 2026-10-28 起，暴力枚举的命中不再是图节点（。graph/extract.ts CANDIDATE_TOOLS），
    // 所以输入有两个来源：候选路径（字典工具）或新端点（其它工具）。
    const candidates = input.ingested.candidates || [];
    const endpoints = input.ingested.newNodes.filter((id: string) => id.startsWith("ep:"));
    let best: { host: string; paths: string[] } | undefined;
    if (candidates.length >= 30) {
      // 候选路径都来自同一次调。同一。host，取本次请求。host 即可。
      const host = String(input.parentUrl || "").replace(/^https?:\/\//i, "").split("/")[0] || "";
      if (host) best = { host, paths: candidates };
    } else if (endpoints.length >= 30) {
      const byHost = new Map<string, string[]>();
      for (const id of endpoints) {
        const match = /^ep:([^/]+)(\/.*)$/.exec(id);
        if (!match) continue;
        const host = match[1]!;
        const list = byHost.get(host) || [];
        list.push(match[2]!);
        byHost.set(host, list);
      }
      for (const [host, paths] of byHost) if (!best || paths.length > best.paths.length) best = { host, paths };
    }
    if (best && best.paths.length >= 30) {
      const plan = planProbes(best.paths, best.host, { maxBuckets: 4 });
      // 2026-11-01（business.oppo.com 实测）：命中全部折进 static 桶时不出探针。
      // 那一轮 sitemap 吐的 30 条全是页面自己引用的 .css/.js/.ico，探针 /static/favicon.ico
      // 必然 200，零信息，却造了任务、劫持了焦点：focus_usage 记录 turns=1、tool_calls=0，
      // 任务最终被判 stalled，还顶掉了 SPA 逆向那条唯一能出结论的动作。
      // static 作为第 4 桶（兜底）保留——只要还有 sensitive/api_doc/admin/other，照常抽样。
      const staticOnly = plan.buckets.length > 0 && plan.buckets.every(bucket => bucket.name === "static");
      if (staticOnly) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "dict-probe-skipped",
          `字典 ${plan.total} 条命中全部属于静态资源类（页面已引用的 .css/.js/.ico），无抽样价值；不生成探针任务，不劫持焦点。`,
          { host: plan.host, total: plan.total, unfolded: plan.unfolded });
      } else {
      const task = probeTask(plan, stamp);
      if (!progress.state.tasks[task.id]) {
        progress.state.tasks[task.id] = {
          status: "pending",
          target: task.target, purpose: task.purpose, reason: task.reason,
          completion_criteria: task.completion_criteria,
          playbook: task.playbook, deliverables: task.deliverables,
          success_criteria: task.success_criteria, source: "system:dict_probe",
          contract_required: false,
        } as never;
      }
      progress.state.dict_probe = {
        host: plan.host, total: plan.total, at: Date.now(), task_id: task.id,
        buckets: plan.buckets.map(bucket => ({ name: bucket.name, members: bucket.members.slice(0, 200), probe: bucket.probe })),
      };
      // 字典抽样是"已经花了钱得到的结构"，允许盖掉普通锁（preempt），否则抽样探针永远排不上队。
      lockFocus(progress.state, {
        task_id: task.id, kind: "dict_probe", preempt: true,
        note: `字典 ${plan.total} 条已折叠。${plan.buckets.length} 个探针，本轮只打这些代表`,
      });
      this.db.addBlackboxEvent(pid, sessionId, "system", "dict-probe",
        `字典聚类：${plan.total} 条命中折叠成 ${plan.buckets.length} 个抽样探针（${plan.buckets.map(bucket => `${bucket.name}:${bucket.probe}`).join("、")}）；生成任务 ${task.id} 并劫持焦点。`,
        { host: plan.host, total: plan.total, buckets: plan.buckets.map(bucket => ({ name: bucket.name, size: bucket.members.length, probe: bucket.probe })), task_id: task.id });
      }
    }
    // ── 展开/收敛（Expansion Rules。026-10-28）：抽样只是"先看哪个"，这里是"看到之后怎么。" ──
    // 探针。200 ，同类剩余提升为下一轮强制焦点；探针。412/WAF ，同类整批标灰，省掉剩下的调用。
    const activeProbe = progress.state.dict_probe;
    if (activeProbe && input.requestUrl) {
      let probePath = "";
      try { probePath = new URL(input.requestUrl).pathname; } catch { probePath = ""; }
      const bucket = activeProbe.buckets.find(item => item.probe === probePath);
      if (bucket) {
        const status = Number(input.data.status ?? 0);
        const blocked = /waf|securityfs|您的访问被拦截/i.test(String(input.data.body ?? "").slice(0, 400)) || [412, 418, 1020].includes(status);
        const expansion = expandFromProbe(
          { host: activeProbe.host, total: activeProbe.total, buckets: activeProbe.buckets as never, unfolded: 0 },
          { probe: probePath, status, blocked },
          { limit: 3 },
        );
        if (expansion.verdict === "collapse" && expansion.collapse.length) {
          const graphNow = graphState(progress.state.graph);
          let marked = 0;
          for (const path of expansion.collapse) {
            const node = graphNow.nodes[`ep:${activeProbe.host}${path}`];
            if (!node) continue;
            node.status = "blocked";
            node.properties.wall = "cluster_collapsed";
            node.properties.note = `同类泛化拦截（${expansion.reason}）`.slice(0, 200);
            marked += 1;
          }
          progress.state.graph = graphNow;
          this.db.addBlackboxEvent(pid, sessionId, "system", "cluster-collapse",
            `聚类收敛（${expansion.reason}）；已把同类 ${marked} 个节点标为 blocked（省掉同样多次调用）。`,
            { bucket: expansion.bucket, probe: probePath, status, collapse: expansion.collapse, marked });
        }
        if (expansion.verdict === "expand" && expansion.expand.length) {
          const nextTask = activeProbe.task_id;
          lockFocus(progress.state, {
            task_id: nextTask, kind: "dict_expand", preempt: true,
            note: `${expansion.reason}；下一批只打：${expansion.expand.join("、")}`,
          });
          // 把展开清单写回 dict_probe，下一轮上下文直接给这 3 条而不是重新抽样
          progress.state.dict_probe = {
            ...activeProbe,
            buckets: activeProbe.buckets.map(item => (item.name === expansion.bucket
              ? { ...item, probe: expansion.expand[0]!, members: [expansion.expand[0]!, ...expansion.expand.slice(1)] }
              : item)),
          };
          this.db.addBlackboxEvent(pid, sessionId, "system", "cluster-expand",
            `聚类展开：${expansion.reason}；下一轮焦点任务 ${nextTask} 只打 ${expansion.expand.join("、")}。`,
            { bucket: expansion.bucket, probe: probePath, status, expand: expansion.expand, task_id: nextTask });
        }
      }
    }
  }

  /**
   * 历史回放：用账本里已有的 tool-request / tool-result 重放一遍，重建历程图。
   *
   * 为什么需要它。026-10-28）：图的 ingest 只在**运行。*发生，抽取逻辑修好之后。
   * 已经跑掉。11 轮不会自动补。—，不重建，控制台上看到的永远是那份"42 节点 37 条边"的旧图。
   * 回放用的是与线上完全相同。ingest 路径，所以重建结果就，假如当初抽取就是对的"那张图。
   */
  rebuildProjectBlackboxGraph(projectId: string, sessionId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    if (String(session.status) === "running") return { ok: false, error: "会话正在运行，先暂停再重建（避免与在。ingest 打架。" };
    const checkpoint = (session.checkpoint || {}) as Record<string, unknown>;
    const evidence = (session.evidence || []) as Array<Record<string, unknown>>;
    // 时间戳口径（踩过的坑）：证据。created_at 。**ISO 字符。*，事件的。**epoch 数字**。
    // 第一次实现直接用 Number(a.created_at)，字符串。NaN ，排序等于没排（拿到的。DESC），
    // 和事件比较也恒为 false 。259 个节点全。round=1。统一。epoch 再比。
    const epoch = (value: unknown): number => {
      if (typeof value === "number" && Number.isFinite(value)) return value;
      const text = String(value ?? "");
      const asNumber = Number(text);
      if (Number.isFinite(asNumber) && asNumber > 0) return asNumber;
      const parsed = Date.parse(text);
      return Number.isFinite(parsed) ? parsed : 0;
    };
    const ordered = evidence.slice().sort((a, b) => epoch(a.created_at) - epoch(b.created_at));
    // 请求表：结果里的 request_evidence_id 指向它。
    const requests = new Map<string, { tool: string; input: Record<string, unknown>; task_id?: string }>();
    for (const item of ordered) {
      if (String(item.kind) !== "tool-request") continue;
      const data = (item.data || {}) as Record<string, unknown>;
      requests.set(String(item.id), {
        tool: String(data.tool || "unknown"),
        input: (data.input || {}) as Record<string, unknown>,
        ...(typeof data.task_id === "string" ? { task_id: data.task_id } : {}),
      });
    }
    const state = graphState(undefined);
    // round 。*真实 run 边界**（事件流里的 lifecycle「主 Agent 开始」），不是拍脑袋的计数器。
    const runStarts = ((session.events || []) as Array<{ kind?: string; text?: string; created_at?: unknown }>)
      .filter(event => String(event.kind) === "lifecycle" && String(event.text || "").includes("。Agent 开。"))
      .map(event => epoch(event.created_at))
      .filter(start => start > 0)
      .sort((a, b) => a - b);
    const roundOf = (createdAt: number): number => {
      if (!runStarts.length) return 1;
      let index = 0;
      for (const start of runStarts) if (createdAt >= start) index += 1;
      return Math.max(1, index);
    };
    let ingestedResults = 0;
    let missingRequest = 0;
    let round = 1;
    for (const item of ordered) {
      const kind = String(item.kind || "");
      if (kind !== "tool-result") continue;
      round = roundOf(epoch(item.created_at));
      const data = (item.data || {}) as Record<string, unknown>;
      const requestId = String(data.request_evidence_id || "");
      const request = requests.get(requestId);
      if (!request) { missingRequest += 1; continue; }
      const discovery = discoveryOf(data);
      const requestUrl = String(request.input.url || discovery.self[0] || data.url || "");
      const parentUrl = /^https?:\/\//i.test(requestUrl) ? requestUrl : "";
      const statusOf = (value: unknown): number | undefined => {
        const parsed = Number(value);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
      };
      const bruteForce = isCandidateTool(request.tool);
      ingestToolResult(state, {
        tool: request.tool,
        round,
        ...(parentUrl ? { parent: endpointNodeId(parentUrl) } : {}),
        ...(bruteForce && discovery.found.length
          ? { candidates: discovery.found.map(found => ({ url: candidatePathOf(found.url, parentUrl || undefined), note: request.tool })) }
          : {}),
        endpoints: [
          ...discovery.self.map(url => ({
            url,
            requested: true,
            origin: "request",
            ...(typeof data.method === "string" ? { method: data.method } : {}),
            ...(statusOf(data.status) !== undefined ? { status_code: statusOf(data.status) } : {}),
            ...(statusOf(data.content_length) !== undefined ? { content_length: statusOf(data.content_length) } : {}),
            ...(typeof data.content_type === "string" ? { content_type: data.content_type } : {}),
            ...(paramsOf(request.input, url).length ? { params: paramsOf(request.input, url) } : {}),
            ...(statusOf(data.status) === 401 || statusOf(data.status) === 403 ? { auth_required: true, blocked: true } : {}),
            ...(wallOf(data) ? { wall: wallOf(data)!.kind, blocked: true } : {}),
            ...(routeMissingOf(data) ? { route_missing: true } : {}),
            ...(requestSignature(request.input, url, request.tool) ? { signature: requestSignature(request.input, url, request.tool) } : {}),
          })),
          ...(bruteForce ? [] : discovery.found.map(found => ({
            origin: found.kind,
            url: found.url,
            ...(found.method ? { method: found.method } : {}),
            ...(found.params?.length ? { params: found.params } : {}),
            ...(found.via ? { via: found.via } : {}),
            // sitemap/robots 声明的业务面：可信度高于爬取所得，必须落进节点属性，
            // 否则复盘时分不清"站点自报的 18 个 /help 页"和"导航栏里的外链"。
            ...(found.source ? { source: found.source } : {}),
          }))),
        ],
        // form 也要走 navigates_to：表单 action 是最典型的"业务入口"，
        // 漏掉它等于把登录/下单/上传这些入口从图里摘掉。
        links: bruteForce ? [] : discovery.found.filter(found => found.kind === "link" || found.kind === "js" || found.kind === "form").map(found => ({ from: parentUrl, to: found.url, kind: found.kind, ...(found.source ? { source: found.source } : {}) })),
        api_calls: bruteForce ? [] : discovery.found.filter(found => found.kind === "api").map(found => ({ from: parentUrl, to: found.url, kind: found.kind })),
        evidence_id: String(item.id || ""),
      });
      ingestedResults += 1;
    }
    // 轮次用 graphRound（run 编号，与节点 round 同口径），不是 planRevision——
    // 后者是任务计划版本，用来做假设池的 LRU 会把"改了几版计划"当成"过了几轮"。
    applyHypotheses(state, deriveHypotheses(state, Number(checkpoint.graphRound || 0)), Number(checkpoint.graphRound || 0));
    checkpoint.graph = state;
    // 重放等于重新认识这张图：旧图攒下的漂移告警（"图裂。120 。）在新图上没有意义，
    // 不清掉的话上下文会一直催下一轮去打那些已经不存在。Root。
    checkpoint.graph_drift = undefined;
    this.db.updateBlackboxSession(pid, sessionId, { checkpoint } as never);
    const depths = Object.values(state.nodes).map(node => Number(node.depth || 1));
    const edgesByType: Record<string, number> = {};
    for (const edge of state.edges) edgesByType[edge.type] = (edgesByType[edge.type] || 0) + 1;
    this.db.addBlackboxEvent(pid, sessionId, "system", "graph-rebuilt",
      `历史回放完成：${ingestedResults} 条工具结果重放进图，最深 ${Math.max(1, ...depths)} 跳。`,
      { nodes: Object.keys(state.nodes).length, edges: state.edges.length, edges_by_type: edgesByType, max_depth: Math.max(1, ...depths), skipped_without_request: missingRequest });
    return {
      ok: true,
      nodes: Object.keys(state.nodes).length,
      edges: state.edges.length,
      edges_by_type: edgesByType,
      max_depth: Math.max(1, ...depths),
      ingested: ingestedResults,
      run_starts: runStarts.length,
      events_seen: ((session.events || []) as unknown[]).length,
      skipped_without_request: missingRequest,
      stats: state.stats,
    };
  }

  /**
   * 协议回填：拿历史 tool-result 事件离线重放四个协议（只读，不改历史账本的状态）。
   * 结论。historical_inference 事件追加，前端用虚线渲染—。
   * 这样"如果当时有这些协议会怎样"是可查的，而不是靠回忆。
   */
  replayProjectBlackboxProtocols(projectId: string, sessionId: string): Record<string, unknown> {
    const session = this.db.getBlackboxSession(projectId, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    const evidence = ((session as { evidence?: Array<Record<string, unknown>> }).evidence || []) as ReplayEvent[];
    const events: ReplayEvent[] = evidence.map(item => ({
      id: String(item.id || ""),
      kind: String(item.kind || ""),
      source: String(item.source || ""),
      summary: String(item.summary || ""),
      created_at: Number(item.created_at || 0),
      data: (item.data || {}) as Record<string, unknown>,
    }));
    const replay = replayProtocols(sessionId, events);
    for (const inferred of replay.inferred_events) {
      this.db.addBlackboxEvent(projectId, sessionId, "system", inferred.kind, inferred.text, inferred.data);
    }
    this.db.addBlackboxEvent(projectId, sessionId, "system", "protocol-backfill",
      `协议回填：扫。${replay.tool_results} 。tool-result，得。${replay.findings.length} 条结论；`
      + `历史调用 ${replay.summary.calls_actual} 次，新协议下预计 ${replay.summary.calls_with_protocols} 次。`,
      { window: replay.window, summary: replay.summary, findings: replay.findings });
    return { ok: true, ...replay };
  }

  projectBlackboxSession(projectId: string, sessionId: string, light = false, brief = false): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    // brief：运行中轮询用，只回状态/环境等标量，几 KB；不含 events/evidence/checkpoint 大块。
    if (brief) {
      return {
        ok: true,
        session: {
          id: session.id,
          status: session.status,
          phase: session.phase,
          environment: session.environment,
          cookie_count: session.cookie_count,
          checkpoint: { planRevision: (session.checkpoint as Record<string, unknown> | undefined)?.planRevision },
        },
      };
    }
    // light：轮询用，剔除 events/evidence 巨量数组，只留状态/环境/checkpoint。
    if (light) {
      const { events: _e, evidence: _v, ...rest } = session;
      return { ok: true, session: rest };
    }
    // full：详情接口。events/evidence 改为前端分页按需拉取（projectBlackboxEvents/Evidence），
    // 这里只回总数 + 单条 run_summary，避免一次把上万条（最大实测 88MB）全量下发导致前端卡死。
    // 注意：内部 getBlackboxSession 仍内联数组（报告/acceptance/supervisor 依赖），此处仅剥离 HTTP 响应体。
    const { events: _e, evidence: _v, event_count: _ec, evidence_count: _vc, ...rest } = session as Record<string, unknown> & { events?: unknown; evidence?: unknown; event_count?: number; evidence_count?: number };
    return {
      ok: true,
      session: {
        ...rest,
        event_count: this.db.listBlackboxEvents(pid, sessionId, 1, 0).total,
        evidence_count: this.db.listBlackboxEvidence(pid, sessionId, 1, 0).total,
        run_summary: this.db.getBlackboxEvidenceByKind(pid, sessionId, "run-summary"),
      },
    };
  }

  /** 单条资产候选（黑盒页候选下拉的远程搜索 / 预选项补齐用）。 */
  projectCandidate(projectId: string, candidateId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const candidate = this.db.getAssetCandidate(pid, candidateId);
    return candidate ? { ok: true, item: candidate } : { ok: false, error: "candidate not found" };
  }

  /** 会话时间线分页（前端"加载更多"/粘顶自动刷用）。dir=desc + before/since 游标支持翻历史与拉更新。 */
  projectBlackboxEvents(
    projectId: string, sessionId: string, limit = 50, offset = 0,
    opts: { dir?: "asc" | "desc"; before?: number; since?: number } = {},
  ): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const rec = this.db.listBlackboxEvents(pid, sessionId, limit, offset, opts);
    return { ok: true, items: rec.items, total: rec.total };
  }

  /** Evidence Ledger 分页。 */
  projectBlackboxEvidence(projectId: string, sessionId: string, limit = 24, offset = 0): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const rec = this.db.listBlackboxEvidence(pid, sessionId, limit, offset);
    return { ok: true, items: rec.items, total: rec.total };
  }

  createProjectBlackboxSession(projectId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const candidateId = String(payload.candidate_id || "").trim();
    const candidate = this.db.getAssetCandidate(pid, candidateId);
    if (!candidate) return { ok: false, error: "candidate not found" };
    const raw = String(candidate.url || "").trim();
    let target = raw;
    if (!target) {
      const host = String(candidate.hostname || candidate.value || "").trim();
      if (!host) return { ok: false, error: "candidate has no target" };
      const protocol = String(candidate.protocol || (Number(candidate.port) === 443 ? "https" : "http"));
      const port = Number(candidate.port || 0);
      const bracketed = host.includes(":") ? `[${host}]` : host;
      target = `${protocol}://${bracketed}${port ? `:${port}` : ""}`;
    }
    try {
      const parsed = new URL(target);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("only HTTP(S) targets are supported");
      target = parsed.toString();
    } catch {
      return { ok: false, error: "candidate target must be an HTTP(S) URL" };
    }
    try {
      // "Send to blackbox" is a repeated gesture: reuse the session already opened for this
      // candidate instead of stacking duplicates in the session list.
      const existing = payload.force === true ? null : this.db.findBlackboxSessionByCandidate(pid, candidateId);
      if (existing) return { ok: true, session: existing, reused: true };
      return { ok: true, session: this.db.createBlackboxSession(pid, candidateId, target), reused: false };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  async checkProjectBlackboxEnvironment(projectId: string, sessionId: string): Promise<Record<string, unknown>> {
    this.execution("environment network check");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const current = this.db.getBlackboxSession(pid, sessionId);
    if (!current) return { ok: false, error: "blackbox session not found" };
    if (this.blackboxAbort.has(`${pid}:${sessionId}`)) return { ok: false, error: "请先暂停当前执行再检查环。" };
    const environment = await checkBlackboxEnvironment(this.cfg.tools_env.values);
    /**
     * 工具链齐全 ≠ 这台目标能连上。
     *
     * 实测 ce01b328599615a7（2026-11-06）：环境检查全绿，目标其实早已下线；Burp 用它自己的
     * 错误页顶替每次响应（状态码仍是 200），7 条路径"同长度"→ 派发 Host 头注入等 3 条假任务，
     * browser.open 每次吃 5 分钟，整场 25 分钟烧完只换来假信号（细节见 proxy-error.ts）。
     * 开跑前打一次 GET 只用几百毫秒，能把这一类整场白跑挡在门外，所以它就长在环境检查里，
     * 结论直接参与 ready 判定——resume 与 Agent 分析都以 ready 为门禁。
     */
    const target = await probeTarget({ url: String(current.target || ""), values: this.cfg.tools_env.values });
    environment.target = target;
    if (!target.reachable) environment.ready = false;
    if (this.blackboxAbort.has(`${pid}:${sessionId}`)) return { ok: false, error: "会话已开始执行，环境检查未修改运行状。" };
    /**
     * 已完成/已取消会话只更新 environment，不回写 status/phase。
     *
     * `completed` 是"这一场评估已经收口"的唯一权威结论，而环境是**会变的**：目标下线、
     * Burp 端口被占都能让下一次检查变红。如果这里无条件把 status 写成 paused，就等于
     * 让一次环境复检把历史结论抹掉——和上一轮 pause 覆盖 completed 是同一个坑
     * （6e716ecad149f8d7：14:09 收口，14:45 一次 pause 把状态改成 paused，结论再也写不回来）。
     */
    const terminal = current.status === "completed" || current.status === "cancelled";
    const status = terminal ? String(current.status) : environment.ready ? "ready" : "paused";
    this.db.updateBlackboxSession(pid, sessionId, {
      ...(terminal ? {} : { status, phase: "environment_check" }),
      environment,
    });
    const summary = blackboxEnvironmentSummary(environment);
    this.db.addBlackboxEvent(pid, sessionId, "system", environment.ready ? "environment" : "warning", summary, environment as unknown as Record<string, unknown>);
    if (!environment.ready) {
      /**
       * 已经判不通过了，就别再花 8s 跑一遍二进制探活：那些结论这一场用不上，目标修好后再
       * check 一次自然会有；而在这里"顺手跑完"会让一次失败的环境检查看起来像做了什么。
       */
      this.db.addBlackboxEvidence(pid, sessionId, {
        kind: "environment", source: "nianyun", summary,
        confidence: "high", data: environment as unknown as Record<string, unknown>,
      });
      return { ok: true, environment, session: this.db.getBlackboxSession(pid, sessionId) };
    }
    // 环境通了不代表工具能干活：这一步对每个工具做一次空跑校验（二进制、模板、字典、Chromium），
    // 失败项进 checkpoint.preflight 与时间线，执行器随后会直接拒绝这些工具。
    const preflight = await runPreflight(this.cfg.tools_env.values, { dataDir: this.cfg.data_dir });
    const checkpointRow = this.db.getBlackboxSession(pid, sessionId)?.checkpoint;
    if (checkpointRow) this.db.updateBlackboxSession(pid, sessionId, { checkpoint: { ...checkpointRow, preflight } });
    this.db.addBlackboxEvent(pid, sessionId, "system", preflight.ok ? "preflight" : "warning",
      preflight.ok
        ? `冒烟校验通过：${preflight.entries.filter(entry => entry.ok).length} 个工具可用`
        : `冒烟校验发现不可用工具：${preflight.failed.join(", ") || "(none)"}`,
      { failed: preflight.failed, entries: preflight.entries });
    this.db.addBlackboxEvidence(pid, sessionId, {
      kind: "environment", source: "nianyun", summary,
      confidence: "high", data: environment as unknown as Record<string, unknown>,
    });
    return { ok: true, environment, session: this.db.getBlackboxSession(pid, sessionId) };
  }

  updateProjectBlackboxSession(projectId: string, sessionId: string, action: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const current = this.db.getBlackboxSession(pid, sessionId);
    if (!current) return { ok: false, error: "blackbox session not found" };
    if (!["pause", "resume", "cancel"].includes(action)) return { ok: false, error: "invalid blackbox action" };
    if (current.status === "cancelled") return { ok: false, error: "已取消会话不能恢复，请创建新会话" };
    /**
     * 已完成会话不能再暂停：pause 会无条件 `status = "paused"`，把"评估已收口"这条
     * 唯一的权威结论覆盖成"等人处置"。前端按钮、脚本、手抖的重复点击都会触发，
     * 而覆盖之后没有任何入口能把 completed 写回来——收口结论就此丢失。
     * 实测 6e716ecad149f8d7：14:09 已按 partial_completed 收口（completed:true），
     * 14:45 一次误调 pause 把它变成 paused，run-settled 的证据还在、状态没了。
     * resume 仍然放行：那是有意义的"继续评估"，会重新起一场 run。
     */
    if (action === "pause" && current.status === "completed") {
      return { ok: false, error: "已完成会话无需暂停；如需继续评估请用 resume" };
    }
    const environment = (current.environment || {}) as Record<string, unknown>;
    if (action === "resume" && environment.ready !== true) return { ok: false, error: "environment check must pass before resume" };
    if (action === "resume" && this.blackboxAbort.has(`${pid}:${sessionId}`)) return { ok: false, error: "正在停止当前调用，请等待检查点保存后恢。" };
    const status = action === "cancel" ? "cancelled" : action === "pause" ? "paused" : "ready";
    const text = action === "cancel" ? "操作员已取消黑盒会话，保留证据和检查点。" : action === "pause" ? "操作员已暂停黑盒会话。" : "黑盒会话已恢复，等待。Agent 调度。";
    this.db.updateBlackboxSession(pid, sessionId, { status, ...(action !== "resume" && this.blackboxAbort.has(`${pid}:${sessionId}`) ? { phase: "stopping" } : {}) });
    if (action !== "resume") this.blackboxAbort.get(`${pid}:${sessionId}`)?.abort(new Error(text));
    if (action === "resume") this.clearUnreachableAdviceErrors(pid, sessionId);
    if (action === "cancel") void closeBrowserSessions(pid, sessionId);
    this.db.addBlackboxEvent(pid, sessionId, "operator", "lifecycle", text);
    return { ok: true, session: this.db.getBlackboxSession(pid, sessionId) };
  }

  /**
   * POST 功能面兜底：推荐器只对已发现。URL 做正则，站点没有 upload/import/export 字样。
   * upload_rce/cmdi/ssrf 永远不会被推荐，于是整局只打 GET。发现面够大却一。POST 打法都没跑过时，
   * 强制投一条“方法面枚举”任务，逼模型去。OPTIONS/405 差异。JS/Swagger 里的 method:"post"。
   */
  /**
   * POST 面任务从"建议"，强制"：连续两轮没有任何请求归属它，就把它提权成唯一可执行任务。
   * 提权后由 progress.begin() 拒绝其它任务（认证链除外），模型只能，做它"，被拒"之间选。
   */
  /**
   * WAF 战例库（读）：控制台页面、prompt、派任务三处读同一份归一结果。
   * `items` 是全部战例（按最近成功排序），`vendors` 是按厂商的汇总（哪堵墙被打穿得最多）。
   */
  wafLedger(filter: { projectId?: string; vendor?: string; host?: string; limit?: number } = {}): {
    items: Array<WafVictory & { id: string }>;
    vendors: Array<{ vendor: string; vendor_name: string; family: string; victories: number; hits: number; last_ok_at: number }>;
    stats: { total: number; vendors: number; hits: number; last_ok_at: number };
  } {
    const rows = this.db.listWafBypasses({ projectId: filter.projectId, vendor: filter.vendor, host: filter.host, limit: filter.limit ?? 200 });
    const items = rows.map(row => ({
      id: String(row.id || ""), vendor: String(row.vendor || ""), vendor_name: String(row.vendor_name || ""),
      family: String(row.family || "unknown") as WafVictory["family"], signature: String(row.signature || ""),
      dimension: String(row.dimension || "other"), tactic: String(row.tactic || ""),
      payload: String(row.payload || ""), host: String(row.host || ""), project_id: String(row.project_id || ""),
      session_id: String(row.session_id || ""), evidence_id: String(row.evidence_id || ""),
      source: String(row.source || "model") as WafVictory["source"], note: String(row.note || ""),
      hits: Number(row.hits || 1), created_at: Number(row.created_at || 0), last_ok_at: Number(row.last_ok_at || 0),
    }));
    const vendors = this.db.wafVendorSummary();
    return {
      items,
      vendors,
      stats: {
        total: items.length,
        vendors: vendors.length,
        hits: items.reduce((sum, item) => sum + Number(item.hits || 0), 0),
        last_ok_at: items.reduce((max, item) => Math.max(max, Number(item.last_ok_at || 0)), 0),
      },
    };
  }

  /**
   * 战例库（喂给。Agent 的运行时视图）：命中同厂，同指纹的记录被排到最前面。
   * 这里只负，给清。不负责判断能不能绕——判断权仍在模型手里，但入口被压，先复。。
   */
  private wafLedgerRuntime(wall?: { host?: string; marker?: string }): { count: number; vendor: string; vendor_name: string; text: string } {
    const rows = this.db.listWafBypasses({ limit: 120 }) as unknown as WafVictory[];
    if (!rows.length) return { count: 0, vendor: "", vendor_name: "", text: "" };
    /**
     * 厂商只看**拦截特征**，不能拼 host。
     *
     * 反例（2026-11-04 实测）：`detectVendor(`${marker} ${host}`)` 里 host 是
     * `wanxiaozhi.aliyun.com`，`/aliyun/i` 直接命中，于是任何打在这台机器上的墙
     * 都被判成"阿里云 WAF/盾"，再据此把阿里云档位的战例排到最前。
     * 而同一份 attestation 正文单独喂给 detectVendor 的结果是 `unknown`。
     * 也就是说：厂商是被域名前缀"认"出来的，不是被墙认出来的。
     */
    const vendor = detectVendor(String(wall?.marker || ""));
    const ranked = rankVictories(rows, { vendor: vendor.id === "unknown" ? "" : vendor.id, host: wall?.host });
    const text = wafLedgerPrompt(ranked, { vendor: vendor.id === "unknown" ? "" : vendor.id, host: wall?.host });
    return { count: rows.length, vendor: vendor.id, vendor_name: vendor.name, text };
  }

  /**
   * 战例库（写）：主 Agent 回报。waf_bypasses 落库，另外从 waf_bypass 打法的成功步骤补一条兜底记录。
   * 写失败不能影响主流程——战例库是加速器，不是账本。
   */
  private recordWafVictories(projectId: string, sessionId: string, main: Record<string, unknown>, target: string, progress?: BlackboxProgress): number {
    const host = hostOf(target);
    const wall = progress?.state.waf_escalation;
    /**
     * 签名从**拦截特征**算，不再硬编码空串。
     *
     * 空签名的后果：`rankVictories` 的"同签名优先"永远不命中，只能按厂商匹配，
     * 而厂商判定又很容易被 host 名污染（`wanxiaozhi.aliyun.com` 里的 aliyun 会让
     * 任何墙都被判成"阿里云 WAF"）。签名补上后，同签名才真正聚得起来。
     */
    const wallVendor = detectVendor(String(wall?.marker || ""));
    const signature = wall ? wallSignature({ body: wall.marker, vendor: wallVendor.id }) : "";
    const reported = Array.isArray(main.waf_bypasses) ? main.waf_bypasses as Record<string, unknown>[] : [];
    let recorded = 0;
    let skipped = 0;
    const push = (victory: WafVictory | undefined, source: "model" | "auto") => {
      if (!victory) return;
      /**
       * 铁律：**没有变体的战例不入库**（2026-11-04 修正）。
       *
       * 战例库的全部价值是"下次照抄这条 payload"。只有"某档成功过"而没有
       * "成功时发了什么"的记录，下游唯一能做的就是照着它复刻一次失败——
       * 实测这条路径产出了一条 hits=50 的假战例，此后每个会话都被它带到沟里，
       * 而且越复刻失败 hits 越大、排序越靠前，形成正反馈污染。
       */
      if (!String(victory.payload || "").trim()) { skipped += 1; return; }
      try {
        this.db.upsertWafBypass({
          vendor: victory.vendor || "unknown", vendor_name: victory.vendor_name || victory.vendor || "unknown",
          family: victory.family || "unknown", signature: victory.signature || signature,
          dimension: String(victory.dimension || "other"), tactic: victory.tactic || String(victory.dimension || "other"),
          payload: victory.payload, host: victory.host || host, project_id: projectId, session_id: sessionId,
          evidence_id: victory.evidence_id, source, note: victory.note,
        });
        recorded += 1;
      } catch {
        /* 战例库写失败不阻塞会。*/
        skipped += 1;
      }
    };
    for (const raw of reported.slice(0, 20)) push(normalizeVictory(raw, { host }), "model");
    /**
     * 兜底**只做观测，不再伪造战例**。
     *
     * 旧兜底从 `playbook_runs.waf_bypass.steps` 的 `ok` 数推"打穿过哪一档"，
     * 但 steps 只有 {calls, ok}，**没有任何变体内容**——它要写 payload 只能拿
     * `wall.marker`（拦截响应本身）充数。这就是那条 `拦截基线：{status:403…}`
     * 假战例的来源，`source=auto`、`hits=50`。
     *
     * 另外 `ok` 只代表"工具调用成功返回"，403 也算 ok，它跟"墙被绕过"没有关系。
     * 所以这里改成：发现"阶梯跑过、模型却没回报变体"时写一条事件，让人知道
     * 战例没收上来的原因，而不是往库里灌一条不能用的记录。
     */
    if (!recorded && wall && progress) {
      const steps = progress.state.playbook_runs?.waf_bypass?.steps || {};
      const ran = Object.entries(steps).filter(([, entry]) => Number(entry?.ok || 0) > 0).map(([id]) => id);
      if (ran.length) {
        this.db.addBlackboxEvent(projectId, sessionId, "system", "waf-ledger-skip",
          `${wall.host} 的 waf_bypass 跑过了 ${ran.join("/")}，但模型没有回报打穿变体：战例不入库。`
          + `（"步骤 ok" 只说明请求发出去了，不等于墙被绕过；没有具体 payload 的记录下次只能复刻失败。）`,
          { host: wall.host, steps: ran, skipped, kind: wall.kind || "rule_wall" });
      }
    }
    if (recorded) {
      this.db.addBlackboxEvent(projectId, sessionId, "system", "waf-ledger",
        `已写。${recorded} 。WAF 绕过战例：下次遇到同厂商/同签名的墙。Agent 会先复刻这些变体，不再从零枚举。`,
        { count: recorded, skipped, signature });
    }
    return recorded;
  }
  /**
   * 每次工具结果后的"观察，动作：异常响应派利用任务。" 产出工具禁掉、跨。JS 来源立任务。
   * 这三件都，看到就该立刻，的事，交给模型自觉就会漏。
   */
  /**
   * 。waf_bypass 任务（只派一次）。抽出来是因为两个入口都要用。
   * ，工具结果里看到拦截（observeToolResult）；。0 产出补枪判定成立（runWallProbe）。
   */
  private dispatchWafTask(pid: string, sessionId: string, progress: BlackboxProgress, stamp: string): string | undefined {
    const waf = progress.state.waf_escalation;
    if (!waf) return undefined;
    const seenWaf = progress.state.linkage?.waf_tasks || [];
    if (seenWaf.length) return undefined;
    const suspectPath = Object.keys(progress.state.endpoints || {}).find(item => item.startsWith("/")) || "/";
    /**
     * 先按墙的**性质**分流，再决定派哪种任务。
     *
     * 老 checkpoint 上没有 `kind` → 默认 `rule_wall`，走原来的派单路径。
     * 这条默认值是整套改动里最重要的一行：它保证"判不出性质"时**照常尝试绕过**，
     * 而不是把一堵可能可绕的墙静默跳过。
     */
    const kind: WallKind = waf.kind || "rule_wall";

    if (kind === "unstable") {
      // 两次指纹不一致 → 这不是墙，是风控抖动/限流。没有墙可绕，跑 8 档等于打空气。
      // 但也不能判死：实测同一路径过一会儿就放行，所以给的是"降频重试"，不是"放弃"。
      progress.state.linkage = { ...progress.state.linkage, waf_tasks: [`waf_unstable_${stamp}`] };
      this.db.addBlackboxEvent(pid, sessionId, "system", "waf-unstable",
        `${waf.host} 的拦截响应两次指纹不一致（${waf.marker || "WAF/阻断页"}）：这是风控抖动或限流，不是规则墙。`
        + `编码/参数/路径等 8 档对它无效（判定输入里不含 payload），别浪费预算；改为降频重试同一路径（间隔 ≥30s，≤3 次），仍不稳定就换时间窗口或换边缘资产。`,
        { host: waf.host, hits: waf.hits, kind, marker: waf.marker, path: suspectPath });
      return undefined;
    }

    if (kind === "identity_wall") {
      /**
       * 身份墙：要求提交身份或过人机验证才放行（attestation / captcha / JS 挑战）。
       *
       * 为什么**不派** waf_bypass：8 档改的都是 payload 形态，而这堵墙的判定输入里
       * 根本没有 payload——编码再花也不会改变"你是谁"。跑了必然 1200 秒零命中。
       *
       * 但也不能直接弃墙。改派"拿身份"这条路，它才是有可能真正打开的：
       *   ① 站点有登录 → 拿合法 Cookie/Token，带凭证重打（凭证是这堵墙唯一的通行证）
       *   ② 找不经过网关的边缘资产（源站 IP、旧域名、OSS/API 子域）
       *   ③ **绝不**按挑战页要求提交 principal/email/provenance —— 那是钓身份
       */
      const marker = identityWallOf(String(waf.marker || "")) || "identity";
      // ② 稳定槽位：撞墙复发时复用同一条 open 任务，不再用时间戳开新 id 顶满任务簿。
      const slot = guardTaskSlot(progress.state.tasks, "identity_wall", waf.host);
      const spec = {
        id: slot.id,
        target: `https://${waf.host}/`,
        purpose: `对 ${waf.host} 这堵**身份墙**取证，不要跑 waf_bypass 阶梯（那 8 档改 payload，而这堵墙不看 payload）：`
          + `① 找登录入口/SSO，用 auth_token 打法拿到合法 Cookie 或 Token，带凭证重打被拦路径；`
          + `② 找不经过这层网关的边缘资产（源站 IP、旧域名、OSS/API 子域）；`
          + `③ 明令禁止：**不要**按挑战页要求提交 principal / username / email / provenance / delegation 等任何身份字段——那是钓身份，提交等于把资产身份交出去。`
          + `【逃生门】如果你握有反证（某个编码/参数/路径变体已经拿到非拦截响应），说明性质判错了，直接转 waf_bypass 阶梯放开打，不必受本条约束。`,
        reason: `${waf.host} 返回的是身份/人机挑战（${marker}，命中 ${waf.hits} 次），不是规则墙：`
          + `它要的是"证明你是谁"而非"改你的 payload"，所以编码/参数/路径/方法/头/报文/夹带 7 档全部无效。`,
        completion_criteria: `给出该 host 的通行证来源（合法 Cookie/Token，或一条不经过该网关的边缘路径）并带它打回被拦端点；`
          + `或确认站点无登录入口且无边缘资产，认定这堵墙只能等人工凭证——此时记 blocked(reason=identity_wall) 并转其他攻击面。`,
        playbook: "auth_token",
      };
      if (slot.reused) {
        // 同一堵墙已有一条在跑的守护任务：只把去重账钉回它，不重复入簿、不重复落事件。
        progress.state.linkage = { ...progress.state.linkage, waf_tasks: [spec.id] };
        return spec.id;
      }
      progress.merge({ required_tasks: [spec] });
      progress.state.linkage = { ...progress.state.linkage, waf_tasks: [spec.id] };
      this.db.addBlackboxEvent(pid, sessionId, "system", "waf-identity-wall",
        `${waf.host} 判定为**身份墙**（${marker}，命中 ${waf.hits} 次）：不派 waf_bypass 阶梯——那 8 档改的是 payload，`
        + `而这堵墙的判定输入里没有 payload。改派 ${spec.id} 去拿合法凭证或找边缘资产；禁止按挑战页提交身份字段。`,
        { host: waf.host, hits: waf.hits, kind, marker, task: spec.id, path: suspectPath, identity_marker: marker });
      return spec.id;
    }

    // ── rule_wall：原来的行为，一个字不改 ──
    // 派任务时就把战例库塞。purpose：这，先不思考、照抄旧方案"的入口。
    const ledger = this.wafLedgerRuntime(waf);
    const spec = wafBypassTask(waf.host, stamp, { marker: waf.marker, path: suspectPath, replay: ledger.text ? ledger.text.split("\n").slice(1, 3).join("\n") : "" });
    progress.merge({ required_tasks: [spec] });
    progress.state.linkage = { ...progress.state.linkage, waf_tasks: [spec.id] };
    this.db.addBlackboxEvent(pid, sessionId, "system", "waf-escalation",
      `${waf.host} 已连续 ${waf.hits} 次返回拦截响应（${waf.marker || "WAF/阻断页"}）：先按 waf_bypass 阶梯打（编码 → 参数污染 → 路径/方法/头 → 原始报文/分块），各档返回同一拦截指纹再转横向逃逸。`,
      { host: waf.host, hits: waf.hits, task: spec.id, marker: waf.marker, path: suspectPath, kind });
    return spec.id;
  }

  /**
   * 0 产出判墙：字，爬虫一条没扫到时分不清"没路。整片被墙"。
   * 于是对根路径补两枪（基线 + 复测），，拦截。+ 指纹"判：
   *   - 状态码属于拦截集（403/406/412/418/429/503/1020。
   *   - 且两次响应的 status+bytes+body_sha256 完全一致（排除偶发 5xx/限流。
   *   - 且（正文命中拦截字样 / 能认出厂。/ 该指纹在战例库里出现过）
   * 三条同时成立才立 waf_escalation 并派 waf_bypass；否则记一条否定事件，让模型知。
   * "这里是真没路径，别再拿字典磨"。整场最多补 3 次。host 只补一次。
   */
  /**
   * 会话开局替模型启动一次 Burp 审计。
   *
   * 21 场会话里 `burp.scan` 与 `burp.issues` 都是 0 次——模型从没主动碰过 Scanner，
   * 于是 Burp 只剩"读历史"一个用途。这个动作不需要模型配合：开局打一枪 passive 审计，
   * 之后由 {@link harvestBurpIssues} 收账。
   *
   * passive 而不是 active：passive 只审已经抓到的响应，不向目标发攻击载荷；
   * active 有真实写操作风险，必须操作员在规则里显式打开，这里只做显式透传。
   */
  private async armBurpScan(pid: string, sessionId: string, progress: BlackboxProgress, toolContext: BlackboxToolContext, targetUrl: string): Promise<void> {
    const mode = scanMode(toolContext.values);
    if (mode === "off") return;
    // 每场会话只启一次：审计对象留在 Burp 里，重复启动只会在操作员的 Burp 里堆垃圾。
    if (progress.state.burp_scan?.at) return;
    const url = String(targetUrl || "").trim();
    if (!/^https?:\/\//i.test(url)) return;
    progress.state.burp_scan = { at: Date.now(), mode, ok: false, url };
    const armed = await burpArmAudit(toolContext, url, mode);
    progress.state.burp_scan = {
      ...progress.state.burp_scan,
      ok: armed.ok,
      ...(armed.audit_id ? { audit_id: armed.audit_id } : {}),
      ...(armed.error ? { error: armed.error } : {}),
    };
    if (!armed.ok) {
      // 不阻断、不重试：Burp Community 没有 Scanner，桥会直接报错。这是环境能力问题。
      this.db.addBlackboxEvent(pid, sessionId, "system", "burp-scan-skipped",
        `未能启动 Burp 审计（${mode}）：${armed.error || "unknown error"}。会话继续；问题清单仍会从 site map 读取（/issues 不依赖 Scanner 审计对象）。`,
        { mode, url, error: armed.error });
      return;
    }
    this.db.addBlackboxEvent(pid, sessionId, "system", "burp-scan",
      `已启动 Burp ${armed.mode || mode} 审计 ${armed.audit_id || ""}（${url}）：结论可用 burp.scan_status / burp.scan_issues 读，site map 里的问题会自动收进上下文。`,
      { mode: armed.mode || mode, audit_id: armed.audit_id, url, insertion_points: armed.insertion_points });
  }

  /**
   * 周期性收账：把 Burp site map 里新出现的 high/medium 问题塞进下一轮上下文。
   *
   * 为什么由控制面做而不是"提示模型自己去看"：21 场里 `burp.issues` 一次都没被调用过。
   * 提示会被忽略，插话不会——它出现在 context.system_interrupts 里，模型必须处置。
   * 只报 high/medium：Burp 对任意页面都会报一堆 info（缺 CSP、缺 X-Frame-Options），
   * 那些不构成渗透结论，塞给模型只会烧预算。
   */
  private async harvestBurpIssues(pid: string, sessionId: string, progress: BlackboxProgress, toolContext: BlackboxToolContext, round: number): Promise<void> {
    if (scanMode(toolContext.values) === "off") return;
    if (!shouldHarvest(round)) return;
    // 已经确认读不到（桥没起 / 版本不认 /issues）就不再每 3 轮重试一次。
    if (progress.state.burp_scan?.harvest_error) return;
    let host = "";
    try { host = new URL(String(toolContext.target || "")).hostname.toLowerCase(); } catch { return; }
    if (!host) return;
    const read = await burpReadIssues(toolContext, host, 100);
    if (!read.ok) {
      // 只记一次：桥不可达时每轮都报会把事件流淹掉。
      if (!progress.state.burp_scan?.harvest_error) {
        progress.state.burp_scan = { ...(progress.state.burp_scan || { at: Date.now(), mode: "passive", ok: false }), harvest_error: read.error };
        this.db.addBlackboxEvent(pid, sessionId, "system", "burp-issues-unavailable",
          `读取 Burp 问题清单失败：${read.error || "unknown error"}。问题清单这条线就此停用（不影响其它工具）。`,
          { host, error: read.error });
      }
      return;
    }
    const seen = progress.state.burp_scan?.seen || [];
    // 审计对象自己产出的问题（passive/active 审计真发过请求换来的）单独一条线：
    // `/issues` 只是 site map 的被动汇总，读它等于"审计起了却没人看结果"。
    // audit_id 是开局 armBurpScan 记下的；Community 没有 Scanner 时这里为空，跳过即可。
    const auditId = progress.state.burp_scan?.audit_id;
    const scanned = auditId ? await burpReadScanIssues(toolContext, auditId, 100) : undefined;
    const all = [...read.issues, ...(scanned?.ok ? scanned.issues : [])];
    const total = read.total + (scanned?.ok ? scanned.total : 0);
    const actionable = worthActingOn(all);
    const fresh = freshIssues(actionable, seen);
    // 分布每轮都刷新（不在 observerStateVersion 的 material 里，不会作废排队审查）：
    // 报告和上下文都要能回答"Burp 到底报了几条、几条是真的"。
    const severity = Object.fromEntries(severityCounts(all).map(item => [item.severity, item.count]));
    progress.state.burp_scan = {
      ...(progress.state.burp_scan || { at: Date.now(), mode: "passive", ok: true }),
      seen: [...seen, ...fresh.map(issueKey)].slice(-200),
      harvested_at: Date.now(),
      total,
      severity,
      actionable: actionable.length,
      ...(scanned ? { scan_total: scanned.ok ? scanned.total : 0, ...(scanned.ok ? {} : { scan_error: scanned.error }) } : {}),
    };
    if (!fresh.length) {
      // 读到了、但没有一条 high/medium —— 实测里这是常态（任意页面都有一堆缺安全头）。
      // 以前这里直接 return，于是"接上了但全是低价值"和"根本没接上"在会话里长得一样：
      // 0 事件、0 插话、报告里也查不到。现在留一次痕迹，之后不再重复。
      if (total > 0 && !progress.state.burp_scan.quiet_reported) {
        progress.state.burp_scan = { ...progress.state.burp_scan, quiet_reported: true };
        this.db.addBlackboxEvent(pid, sessionId, "system", "burp-passive-quiet",
          quietDigest(total, all, host),
          { host, total, actionable: actionable.length, severity, scan_total: scanned?.ok ? scanned.total : undefined });
      }
      return;
    }
    progress.addInterrupts([{
      id: `burp-passive:${issueKey(fresh[0]!)}`,
      kind: "burp_passive",
      severity: "medium",
      text: digestText(fresh, host),
      data: {
        host, count: fresh.length, total, severity,
        ...(progress.state.burp_scan?.audit_id ? { audit_id: progress.state.burp_scan.audit_id } : {}),
        issues: fresh.slice(0, 8).map(issue => ({ name: issue.name, severity: issue.severity, base_url: issue.base_url })),
      },
    }]);
    this.db.addBlackboxEvent(pid, sessionId, "system", "burp-passive",
      `Burp 被动扫描在 ${host} 新增 ${fresh.length} 条候选问题（账本共 ${total} 条），已进下一轮上下文。`,
      { host, count: fresh.length, total, issues: fresh.slice(0, 8) });
  }

  /**
   * 证据引用类校验失败的处置（2026-11-06）：先给模型改，改不动就隔离，隔离完还脏才算真失败。
   *
   * 为什么会走到这里：验收把"引用了不存在的证据"记成 error，门禁于是把整场停在
   * `validation_failed_review_required`——**一条记账错误换掉整份报告**。实测
   * e8bdb447acf02283 的唯一阻塞项是 T2 的结案说明没引用它名下那 22 条证据，
   * 而模型连补的入口都没有（结案幂等跳过的分支已补，见 progress.ts）。
   *
   * 三态返回：
   *   retry → 已把具体错误塞进插话，再开一轮 pass 让它改（不修改任何账本）；
   *   clean → 隔离完成，剩下来的阻塞项都能降级；调用方按"没有阻塞"继续；
   *   dirty → 要么没有可隔离的项（结论本身站不住），要么隔离后仍有硬错误 → 按原语义停场。
   */
  private settleEvidenceBlocks(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    evidence: Record<string, unknown>[],
    options: { attemptsLimit: number; canSpend: boolean; pass: number; passLimit: number },
  ): "retry" | "clean" | "dirty" {
    const acceptance = (progress.state.supervision?.acceptance || {}) as { issues?: IssueLike[] };
    const { quarantinable } = partitionBlocking(acceptance.issues || []);
    // 没有可隔离的项 = 错在结论的依据上（拿 401 当漏洞证据之类），隔离等于把站不住的
    // 结论洗白。这类照原样停场，交给 Observer 与操作员看。
    //
    // 但**不能静默**（2026-11-10 修）：旧写法在这里直接 return，日志里只剩
    // `supervisor-pause` + `validation-failed`，看不出卡在哪一条、为什么隔离不掉。
    // 实测 `1dd9ded9ed239711` 连续五场都是这个形态，人只能靠翻 checkpoint 才找得到
    // 那两条永远修不好的账本残渣。这里把 fatal 原样写出来，并点明"无隔离路径"。
    if (!quarantinable.length) {
      const digest = unquarantinableDigest(acceptance.issues || []);
      if (digest) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "evidence-quarantine-skipped", digest.text,
          { ...digest.data, attempts: Number(progress.state.evidence_repair_attempts || 0) });
      }
      return "dirty";
    }
    const attempts = Number(progress.state.evidence_repair_attempts || 0);
    if (attempts < options.attemptsLimit && options.canSpend && options.pass < options.passLimit) {
      progress.state.evidence_repair_attempts = attempts + 1;
      const attempt = attempts + 1;
      progress.addInterrupts([{
        id: `evidence-repair:${attempt}`,
        kind: "evidence_repair",
        severity: "high",
        text: repairDigest(quarantinable, evidence, attempt, options.attemptsLimit),
        data: { attempt, limit: options.attemptsLimit, targets: quarantinable },
      }]);
      this.db.addBlackboxEvent(pid, sessionId, "system", "evidence-repair",
        `门禁发现 ${quarantinable.length} 处证据引用问题，第 ${attempt}/${options.attemptsLimit} 次给模型修正机会（不停场，已进下一轮上下文）。`,
        { targets: quarantinable, attempt, limit: options.attemptsLimit });
      return "retry";
    }
    /**
     * 修正机会用尽 → 隔离。
     *
     * 注意这里**不删任何东西**：发现打 `quarantined` 标记（报告主体剔除、附录留痕），
     * 任务只摘掉账本里不存在的引用、标 `evidence_status: unverified`。
     * 隔离之后立刻重算验收——如果还有硬错误，说明脏的不止这一处，照旧停场。
     */
    const findings = quarantineFindings(progress.state as unknown as { findings?: Record<string, Record<string, unknown>> }, quarantinable);
    const tasks = quarantineTaskRefs(progress.state as unknown as { tasks?: Record<string, Record<string, unknown>> }, evidence, quarantinable);
    const after = evaluateAcceptance(progress.state, evidence);
    progress.state.supervision ||= { observerRuns: 0 };
    progress.state.supervision.acceptance = after;
    const stillDirty = after.blocking_error_count > 0 && !after.repairableOnly;
    /** 这几条不再是"引用错了"，而是"结论本身站不住"——必须让报告与操作员看见。 */
    const fatal = after.issues.filter(issue => issue.severity === "error")
      .map(issue => ({ code: issue.code, path: issue.path, detail: String(issue.detail || issue.message || "").slice(0, 200) })).slice(0, 8);
    this.db.addBlackboxEvent(pid, sessionId, "system", "evidence-quarantine",
      `修正机会已用尽，隔离 ${findings.length} 条发现、${tasks.length} 条任务的无效引用`
        + `${stillDirty ? `；仍有 ${after.blocking_error_count} 处无法降级的阻塞` : "；报告正文只保留证据链闭合的结论，附录列明被过滤项"}。`,
      { findings, tasks, attempts, remaining_blocking: after.blocking_error_count, fatal });
    return stillDirty ? "dirty" : "clean";
  }

  /**
   * 种子自检：同一 URL 发两发（带凭证 / 匿名），先分清"这堵墙是谁造的"。
   *
   * 这是 2026-11-07 那两场 17.0M tokens 换来的唯一一条最重要结论：
   * 系统判墙的整条链路（recordHostBlock → waf_escalation → lateral_escape → blocked_hosts）
   * **从来没有验证过自己的凭证是否干净**。种子里的 `cna` 把阿里云整站打成
   * 403 + attestation 挑战页，于是六个任务被"合理"地判成 blocked，最后一条结论都拿不出来。
   *
   * 判据只有一条主线，成本两发请求；判出污染后再花 ~8 发做二分定位。
   * 比起"整机拉黑 + 全部任务作废"，这个开销可以忽略。
   */
  private async runSeedProbe(pid: string, sessionId: string, progress: BlackboxProgress, toolContext: BlackboxToolContext): Promise<void> {
    const probe = progress.consumeSeedProbe();
    if (!probe) return;
    const url = String(probe.url || `https://${probe.host}/`);
    /**
     * 走**原始执行器**，不走 `executeAndRecordBlackboxTool`。
     *
     * 自检是控制面的仪表，不是主 Agent 的证据：写进证据账本会让"tool-request"里多出
     * 两条用户从没要求过的请求，验收、计数、上下文全被它污染；模型也会误以为是自己发的。
     * 这里只要状态码、正文、跳转目标三样东西。
     */
    const send = async (anonymous: boolean) => executeBlackboxTool(toolContext, {
      tool: "http.request",
      task_id: "seed_probe",
      reason: `${anonymous ? "种子自检（匿名基线）" : "种子自检（带凭证）"}：${probe.reason}`,
      input: { url, method: "GET", follow_redirects: false, ...(anonymous ? { anonymous: true } : {}) },
    }).catch(() => undefined);
    const sampleOf = (result: Awaited<ReturnType<typeof send>>): SeedSample => {
      const data = (result?.data || {}) as Record<string, unknown>;
      return {
        status: Number(data.status || 0),
        body: String(data.body || data.summary || ""),
        location: String(data.location || ""),
      };
    };
    const seeded = sampleOf(await send(false));
    const anonymous = sampleOf(await send(true));
    const judged = judgeSeedHealth({ seeded, anonymous });
    const base = { host: probe.host, url, seeded: Number(seeded.status || 0), anonymous: Number(anonymous.status || 0) };

    if (judged.verdict === "inconclusive") {
      progress.noteSeedHealth(probe.host, { verdict: "inconclusive", url, seeded: Number(seeded.status || 0), anonymous: Number(anonymous.status || 0), probes: 2, at: Date.now(), detail: judged.detail });
      this.db.addBlackboxEvent(pid, sessionId, "system", "seed-check-inconclusive",
        `种子自检无法判定（${judged.detail}）：不据此改结论，但**也不许整机拉黑**——拦截门槛已抬到 6 次，请换一条路径再取一次样本。`,
        { ...base });
      return;
    }
    if (judged.verdict === "healthy" || judged.verdict === "host_walled") {
      progress.noteSeedHealth(probe.host, { verdict: judged.verdict, url, seeded: Number(seeded.status || 0), anonymous: Number(anonymous.status || 0), probes: 2, at: Date.now(), detail: judged.detail });
      this.db.addBlackboxEvent(pid, sessionId, "system",
        judged.verdict === "healthy" ? "seed-check-ok" : "seed-check-host-wall",
        judged.verdict === "healthy"
          ? `种子自检通过（${probe.host}）：带凭证 ${base.seeded}、匿名 ${base.anonymous}——凭证是干净的，后面撞墙按目标自身的问题处理。`
          : `种子自检：${probe.host} 带凭证 ${base.seeded}、匿名 ${base.anonymous} **都被拦**——这是目标自身的墙，不是我方凭证造成的；可以按 WAF/身份墙处理。`,
        { ...base, verdict: judged.verdict });
      return;
    }
    if (judged.verdict === "seed_stale") {
      progress.noteSeedHealth(probe.host, { verdict: "seed_stale", url, seeded: Number(seeded.status || 0), anonymous: Number(anonymous.status || 0), probes: 2, at: Date.now(), detail: judged.detail });
      this.db.addBlackboxEvent(pid, sessionId, "system", "seed-check-stale",
        `种子失效（${probe.host}）：${judged.detail}。不要把它当成"未授权漏洞"的证据——`
          + `带不带凭证结果一样，说明这份种子在这台主机上根本没生效；请重新导出覆盖该主机的种子，或改用 anonymous:true 做匿名面。`,
        { ...base, verdict: judged.verdict });
      return;
    }

    // ── seed_tainted：墙是我方凭证造的。开始定位具体是哪几枚 Cookie。 ──
    const jar = this.db.getProjectCookies(pid);
    const fullLength = jar.length;
    let probes = 2;
    const probeWith = async (keep: typeof jar): Promise<SeedSample> => {
      // 直接把罐换成待测集合再发：http.request 读的就是项目罐，这样能保证
      // 除被剔除项之外的**全部** Cookie 仍在场上（很多风控是"登录态 + 某枚标记"共同触发，
      // 只拿子集重放根本复现不了墙，会得出相反结论）。
      this.db.setProjectCookies(pid, keep);
      probes += 1;
      return sampleOf(await send(false));
    };
    let tainted: string[] = [];
    let isolated = false;
    const found = await isolateTaintedCookies({
      cookies: jar,
      maxProbes: Math.min(10, Math.max(4, Math.ceil(Math.log2(Math.max(2, fullLength))) * 2 + 2)),
      probe: async (remove) => {
        const keep = jar.filter((_, index) => !remove.includes(index));
        const sample = await probeWith(keep);
        return isWallSample(sample);
      },
    });
    probes += found.probes;
    if (found.complete && found.indexes.length) {
      tainted = found.names;
      isolated = true;
    } else {
      // 二分没跑完 / 多枚协同：退一步只清"风控特征名"里确实存在的那几枚，并**验证**一次。
      // 验证不过就什么都不删——宁可留着墙，也不能把登录态删坏。
      const risk = riskCookieIndexes(jar);
      if (risk.length) {
        const keep = jar.filter((_, index) => !risk.includes(index));
        const sample = await probeWith(keep);
        if (!isWallSample(sample)) {
          tainted = risk.map(index => String(jar[index]?.name || "")).filter(Boolean);
          isolated = true;
        }
      }
    }

    if (!isolated || !tainted.length) {
      // 定位失败：把罐恢复原样，只留结论，让操作员自己决定（不猜着删）。
      this.db.setProjectCookies(pid, jar);
      progress.noteSeedHealth(probe.host, { verdict: "seed_tainted", url, seeded: Number(seeded.status || 0), anonymous: Number(anonymous.status || 0), probes, at: Date.now(), detail: `${judged.detail}；但未能隔离到具体 Cookie（${found.reason || "预算/交互"}）` });
      this.db.addBlackboxEvent(pid, sessionId, "system", "seed-check-tainted",
        `种子自检判定 **污染**（${probe.host}）：带凭证 ${base.seeded} 被拦、匿名 ${base.anonymous} 正常——这堵墙是我方 Cookie 造的。`
          + `但二分没能定位到具体哪几枚（${found.reason || "预算耗尽"}），未自动改写种子。`
          + `处置：按 host 重新导出一份干净种子，或后续一律用 anonymous:true；**不要**把这个 host 记成封锁。`,
        { ...base, verdict: "seed_tainted", probes, isolated: false });
      return;
    }

    // 已定位：清罐 + 改写种子文件（带备份）+ 复验一次。
    const keep = jar.filter(cookie => !tainted.includes(String(cookie.name || "")));
    this.db.setProjectCookies(pid, keep);
    // 种子文件按**主机名**匹配（host 里带端口会让 hostMatches 失配）。
    let seedHost = probe.host;
    try { seedHost = new URL(url).hostname; } catch { /* 保留 host */ }
    const pruned = pruneSeedCookies(seedHost, tainted);
    const verifySample = sampleOf(await send(false));
    probes += 1;
    const verified = !isWallSample(verifySample);
    progress.noteSeedHealth(probe.host, {
      verdict: "seed_tainted", url, seeded: Number(seeded.status || 0), anonymous: Number(anonymous.status || 0),
      tainted, seed_rewritten: pruned.ok === true, probes, at: Date.now(),
      detail: `${judged.detail}；已剔除 ${tainted.join("/")}${pruned.ok ? `（种子文件 ${pruned.file} 已改，备份 ${pruned.backup}）` : `（仅清会话罐：${pruned.error || "种子文件未改"}）`}`,
    });
    this.db.addBlackboxEvent(pid, sessionId, "system", "seed-check-tainted",
      `种子自检判定 **污染并已修复**（${probe.host}）：带凭证 ${base.seeded} 被拦、匿名 ${base.anonymous} 正常——`
        + `元凶是 ${tainted.join("/")}。已从采购罐剔除（${fullLength} → ${keep.length} 枚），`
        + `${pruned.ok ? `种子文件 ${pruned.file} 同步改写（备份 ${pruned.backup}）` : `种子文件未改（${pruned.error || "无匹配种子"}）`}；`
        + `复验 ${Number(verifySample.status || 0)}${verified ? "（墙已消失，可以继续打这台主机）" : "（仍被拦，说明还有别的成因，按真墙处理）"}。`
        + `**这不是目标的墙**：别再换编码/换头绕它，也别把这个 host 记成封锁。`,
      { ...base, verdict: "seed_tainted", tainted, probes, seed_rewritten: pruned.ok === true, verified, remaining: keep.length });
  }

  private async runWallProbe(pid: string, sessionId: string, progress: BlackboxProgress, toolContext: BlackboxToolContext): Promise<void> {
    if (!progress.state.waf_probe) return;
    // 只有字典/爬虫。0 产出才会登记；执行器不可用（沙箱未就绪）时直接放弃，不写假结论。
    const probe = progress.consumeWallProbe();
    if (!probe) return;
    const again = (probe.url || `https://${probe.host}/`).replace(/([^:])\/{2,}/g, "$1/");
    const request = (tag: string): BlackboxToolRequest => ({
      tool: "http.request", task_id: "waf_probe",
      reason: `0 产出判墙（${probe.reason}）：对 ${probe.host} 根路径补一次 ${tag}，用拦截码 + 指纹确认是不是墙`,
      input: { url: again, method: "GET", anonymous: true, follow_redirects: false },
    });
    const first = await executeAndRecordBlackboxTool(toolContext, request("（基线）")).catch(() => undefined);
    const second = await executeAndRecordBlackboxTool(toolContext, request("（复测指纹）")).catch(() => undefined);
    const viewOf = (result: typeof first): { status: number; bytes: number; sha: string; body: string; headers: Record<string, unknown> } | undefined => {
      if (!result?.ok) return undefined;
      const data = (result.data || {}) as Record<string, unknown>;
      const body = String(data.body || "");
      return {
        status: Number(data.status || 0), bytes: Number(data.body_bytes || body.length),
        sha: createHash("sha256").update(body).digest("hex").slice(0, 16), body,
        headers: (data.headers || {}) as Record<string, unknown>,
      };
    };
    const a = viewOf(first);
    const b = viewOf(second);
    const wafCodes = [403, 406, 412, 418, 429, 503, 1020];
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    if (!a || !b) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "waf-probe-skipped",
        `0 产出补枪未拿到结果（${first?.summary || second?.summary || "执行器拒绝"}）：不据此下结论，继续按字典结果推进。`,
        { host: probe.host, url: again });
      return;
    }
    const stable = a.status === b.status && a.bytes === b.bytes && a.sha === b.sha;
    const blockedCode = wafCodes.includes(a.status) && wafCodes.includes(b.status);
    const headerText = JSON.stringify(a.headers || {});
    const vendor = detectVendor(`${a.body} ${headerText}`);
    const marker = /waf|拦截|阻断|blocked by|security policy|securityfs|cloudflare|cf-error|安全策略|请求异常|非法请求|forbidden/i.test(a.body);
    const signature = wallSignature({ status: a.status, body: a.body, vendor: vendor.id });
    const known = (this.db.listWafBypasses({ limit: 200 }) as Array<Record<string, unknown>>)
      .some(row => String(row.signature || "") === signature);
    // 302 跳人机校验（Cloudflare/瑞数常见）：那不，没路。但阶梯也绕不过 captcha。
    // 所以既不能判否误导模型继续磨字典，也不该派 waf_bypass —，直接说明停手换面。
    const location = String((a.headers || {})["location"] || (a.headers || {})["Location"] || "");
    const redirect = [301, 302, 303, 307, 308].includes(a.status);
    const challenge = redirect && /captcha|challenge|verify|chk|slider|__cf_chl|waf|校验|验证/i.test(`${location} ${a.body}`);
    if (challenge && stable) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "waf-probe-challenge",
        `${probe.host} 0 产出补枪命中人机校验（${a.status} ${location || "挑战页"}，两次一致）：这是挑战不是缺路径，阶梯绕不过 captcha；停掉字典与编码尝试，换边缘资产或等 Cookie 复用后再来。`,
        { host: probe.host, url: again, status: a.status, location, vendor: vendor.id });
      return;
    }
    if (!(blockedCode && stable && (marker || vendor.id !== "unknown" || known))) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "waf-probe-negative",
        `0 产出补枪判否：根路径返回 ${a.status}${stable ? "（两次一致）" : "（两次不一致）"}，没有拦截码/拦截指纹，是没路径不是墙；继续按扫描结果换打法，别再用同一本字典磨。`,
        { host: probe.host, url: again, status: a.status, stable, vendor: vendor.id, marker });
      return;
    }
    progress.state.blocked_hosts ||= {};
    const record = (progress.state.blocked_hosts[probe.host] ||= { hits: 0, kinds: [], at: Date.now() });
    record.hits += 1;
    record.at = Date.now();
    if (!record.kinds.includes("waf")) record.kinds = [...record.kinds, "waf"].slice(-4);
    progress.state.waf_escalation = {
      host: probe.host, at: Date.now(), hits: record.hits,
      marker: `${a.status} ${vendor.name}${marker ? " 阻断页" : ""}（0 产出补枪${known ? " · 战例库同签名" : ""}）`,
      // 到这里 stable 必为 true（不稳定在前面就被判 negative 返回了），所以只需判性质。
      // 注意传的是**真实正文** a.body，不是上面那个拼接出来的描述性 marker——
      // attestation/captcha 的特征串只在正文里，描述串里永远匹配不到。
      kind: wallKind({ status: a.status, body: a.body }),
    };
    this.db.addBlackboxEvent(pid, sessionId, "system", "waf-probe",
      `${probe.host} 字典 0 产出但根路径返回 ${a.status}（两次指纹一致，${vendor.name}${known ? "，战例库已有同签名记录" : ""}）：判定为整片拦截，派 waf_bypass 任务。`,
      { host: probe.host, url: again, status: a.status, vendor: vendor.id, signature, known, marker });
    this.dispatchWafTask(pid, sessionId, progress, stamp);
  }

  /**
   * 登记工具缺口：模型说"缺什么能。desk 把它变成操作员能执行的一条清单。
   * 关键是把"模型以为的工具名"，注册表里真实。74 ，对账。
   *   - 名字不存。。missing=true（这就是"缺工，的字面证据）
   *   - 名字存在但被配置关闭/冒烟失败 。。why 里标注（缺的是配置，不是工具。
   */
  private recordToolGaps(pid: string, sessionId: string, progress: BlackboxProgress, main: Record<string, unknown>): void {
    const raw = Array.isArray(main.tool_gaps) ? main.tool_gaps as Array<Record<string, unknown>> : [];
    if (!raw.length) return;
    const known = new Set<string>(BLACKBOX_TOOL_ENUM as readonly string[]);
    const disabled = new Set((progress.state.linkage?.disabled_tools || []).map(item => String(item)));
    const health = (progress.state.tool_health || {}) as Record<string, { disabled?: boolean }>;
    const prepared = raw.map(gap => {
      const tool = String(gap.tool || "").trim();
      const unavailable = tool ? (disabled.has(tool) || health[tool]?.disabled === true) : false;
      return {
        ...gap,
        missing: tool ? !known.has(tool) : true,
        ...(unavailable ? { why: `${String(gap.why || "被卡住")}：${tool} 已注册但当前不可用（未配置/冒烟失败）` } : {}),
      };
    });
    for (const gap of progress.recordToolGaps(prepared)) {
      const state = gap.missing ? "清单里没有这个工。" : "工具已注册但不够。";
      this.db.addBlackboxEvent(pid, sessionId, "system", "tool-gap",
        `工具缺口：${gap.need}${gap.tool ? `（模型点名 ${gap.tool}：${state}）` : "（清单里无对应工具）"}${gap.alternative ? `；当前兜底 ${gap.alternative}` : "；当前无兜底"}`.slice(0, 900),
        { need: gap.need, tool: gap.tool || null, missing: gap.missing === true, alternative: gap.alternative || null, blocked_task: gap.blocked_task || null });
    }
  }

  /** context.tool_gaps：已登记缺口——作用是"别重复报同一。" + "先想兜底工具"。*/
  private toolGapRuntime(state: BlackboxProgress["state"] | undefined): Record<string, unknown> | undefined {
    const list = state?.linkage?.tool_gaps || [];
    if (!list.length) return undefined;
    return {
      registered: list.map(gap => ({ need: gap.need, tool: gap.tool || null, missing: gap.missing === true, alternative: gap.alternative || null })),
      rule: "同一条缺口不要再报；先用手上工具兜底把活干完（exec.python/exec.bash/fs.*/burp.*），只有新的缺口才写 tool_gaps。",
    };
  }

  /**
   * context.seed_health：把"这堵墙是不是我方凭证造的"直接摆到模型眼前。
   *
   * 为什么必须进上下文：结论只落在事件流里的话，模型下一轮看到的仍然是"403"，
   * 它会继续按"目标 WAF"那套（换编码/换头/换路径）去推——2026-11-07 就是这样
   * 每轮稳定烧掉一次推理，最后派一个请求。一句话进上下文，比十条事件便宜得多。
   */
  private seedHealthRuntime(state: BlackboxProgress["state"] | undefined): Record<string, unknown> | undefined {
    const all = state?.seed_health || {};
    const hosts = Object.entries(all);
    if (!hosts.length) return undefined;
    return {
      hosts: hosts.map(([host, record]) => ({
        host,
        verdict: record.verdict,
        label: SEED_VERDICT_LABEL[record.verdict],
        seeded_status: record.seeded ?? null,
        anonymous_status: record.anonymous ?? null,
        tainted_cookies: record.tainted || [],
        ...(record.detail ? { detail: record.detail } : {}),
      })),
      rule: "seed_tainted = 带凭证被拦、匿名正常，**墙是我方 Cookie 造的**：不要换编码/换头去绕，不要把这个 host 记成封锁；用已清理的会话罐继续打原接口，或用 anonymous:true 做未授权基线。"
        + "seed_stale = 带凭证和不带凭证结果一样：不要把这种 401/403 当成未授权证据，先换种子。"
        + "host_walled = 两边都被拦，才是目标自己的墙，可以按 WAF 处理。",
    };
  }

  private observeToolResult(pid: string, sessionId: string, progress: BlackboxProgress, request: BlackboxToolRequest, result: { ok: boolean; data?: Record<string, unknown> }): void {
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    // (a0) 登录门禁：验证码 / MFA / 滑块 / SSO，识别到就写事件并让认证链任务停。
    const gate = progress.state.auth_gate;
    const seenGate = progress.state.linkage?.auth_gates || [];
    if (gate && !seenGate.includes(`${gate.kind}:${gate.task || ""}`)) {
      progress.state.linkage = { ...progress.state.linkage, auth_gates: [...seenGate, `${gate.kind}:${gate.task || ""}`] };
      this.db.addBlackboxEvent(pid, sessionId, "system", "auth-gate",
        `登录门禁不可自动通过（${gate.kind}）：已把 ${gate.task || "认证链任务"} 判 blocked，禁止重试；改走 unauth_exposure 或另找取 Token 通道。`,
        { kind: gate.kind, task: gate.task, detail: gate.detail });
    }
    // (a) 异常响应：catch-all 跳转 / 统一响应。
    // 去重必须，稳定。（kind:host）：任务 id 带的是本轮时间戳（host_header_injection_20261027061910），
    // 。id 比对等于每轮都判"没派。——catch-all 存在几轮就派几轮，pending 里堆出三份一模一样的任务。
    const alert = progress.state.anomaly_alert;
    const anomalyKey = alert ? `${alert.kind}:${alert.host}` : "";
    const seenAnomaly = progress.state.linkage?.anomaly_tasks || [];
    if (alert && progress.state.linkage?.anomaly_key !== anomalyKey) {
      const specs = anomalyTasks(alert, stamp);
      progress.merge({ required_tasks: specs });
      progress.state.linkage = { ...progress.state.linkage, anomaly_key: anomalyKey, anomaly_tasks: [...seenAnomaly, ...specs.map(item => item.id)] };
      this.db.addBlackboxEvent(pid, sessionId, "system", "anomaly-exploit",
        `检测到 ${alert.kind === "catch_all_redirect" ? "全站统一跳转" : "全站同长度响应"}（${alert.host}，${alert.paths.length} 条路径）：已停止按目录遍历的思路，派发 Host 头注入 / 开放重定向 / 子域接管三条任务。`,
        { host: alert.host, kind: alert.kind, location: alert.location, tasks: specs.map(item => item.id) });
    }
    // (a0) WAF 阶梯：同一 host 。2 次命中拦截就先派 waf_bypass，绕不过再横向逃逸。
    // 2026-10-30 qwen 一轮：412 阻断页直接判死、一整条可绕的墙没打就走 lateral_escape。
    // 结果。WAF 一出现就不再挖"。墙先绕，逃逸是最后一档。
    if (progress.state.waf_escalation) this.dispatchWafTask(pid, sessionId, progress, stamp);
    // (a1) 攻击面降级（Plan B）：同一 host 被拦 3 。派子，旧版/移动端探测任。
    const escape = progress.state.lateral_escape;
    const seenEscape = progress.state.linkage?.lateral_tasks || [];
    if (escape && !seenEscape.length) {
      const versions = Object.keys(progress.state.endpoints || {})
        .map(path => /\/v(\d)(?:\/|$)/i.exec(path))
        .filter((match): match is RegExpExecArray => Boolean(match))
        .map(match => match[1]!)
        .filter((version, index, list) => list.indexOf(version) === index)
        .map(version => `/v${version}/`);
      const spec = lateralEscapeTask(escape.host, stamp, { oldVersions: versions });
      // ② 稳定槽位 + 复用：id 里的时间戳会让同一 host 的横向逃逸每次都是"新任务"。
      const slot = guardTaskSlot(progress.state.tasks, "lateral_escape", escape.host);
      spec.id = slot.id;
      if (!slot.reused) progress.merge({ required_tasks: [spec] });
      progress.state.linkage = { ...progress.state.linkage, lateral_tasks: [spec.id] };
      const crossHosts = Object.keys(progress.state.cross_domain || {}).slice(0, 2);
      if (crossHosts.length && !slot.reused) progress.merge({ required_tasks: crossHosts.flatMap(host => crossDomainTasks(host, stamp)) });
      if (!slot.reused) this.db.addBlackboxEvent(pid, sessionId, "system", "lateral-escape",
        `${escape.host} 已被拦截 ${escape.hits} 次（${(progress.state.blocked_hosts?.[escape.host]?.kinds || []).join("/")}）：停止在原地换参数，改为横向逃逸——子域枚举＋旧版/移动端接口探测${crossHosts.length ? `＋跨域资产 ${crossHosts.join("、")}` : ""}。`,
        { host: escape.host, hits: escape.hits, task: spec.id, cross_domain: crossHosts });
    }
    // (b) 工具 Fail-Fast：第一次被禁用时写一条事件，后续 begin() 会直接拒。
    const disabled = Object.entries(progress.state.tool_health || {}).filter(([, health]) => health.disabled);
    for (const [tool, health] of disabled) {
      const known = (progress.state.linkage?.disabled_tools || []).includes(tool);
      if (known) continue;
      progress.state.linkage = { ...progress.state.linkage, disabled_tools: [...(progress.state.linkage?.disabled_tools || []), tool] };
      this.db.addBlackboxEvent(pid, sessionId, "system", "tool-disabled", `${health.detail || `${tool} 已禁用`}；后续调用会被拒绝（tool_disabled:${tool}）。`, { tool, zeros: health.zeros });
    }
    // (c) 跨域 JS 来源：第三方 SDK / 统一认证。
    if (request.tool !== "recon.js_endpoints" || !result.ok) return;
    const items = Array.isArray(result.data?.items) ? (result.data.items as unknown[]).map(String) : [];
    if (!items.length) return;
    const targetHost = String(progress.state.target_host || new URL(String(progress.state.tasks[request.task_id || ""]?.target || "https://invalid/")).host);
    const hosts = new Set<string>();
    for (const item of items) {
      try {
        const host = new URL(item).host;
        if (!host || host === targetHost || host.endsWith(`.${targetHost}`)) continue;
        hosts.add(host);
      } catch { /* 非绝。URL，跳。*/ }
    }
    if (!hosts.size) return;
    progress.state.cross_domain ||= {};
    const fresh: string[] = [];
    for (const host of hosts) {
      if (progress.state.cross_domain[host]) continue;
      const identity = /(^|[.-])(id|auth|login|sso|passport|account|api)([.-]|$)/i.test(host);
      progress.state.cross_domain[host] = { first_seen: Date.now(), identity };
      fresh.push(host);
    }
    if (!fresh.length) return;
    const specs = fresh.flatMap(host => crossDomainTasks(host, stamp));
    progress.merge({ required_tasks: specs });
    this.db.addBlackboxEvent(pid, sessionId, "system", "cross-domain-asset",
      `JS 里引用了 ${fresh.length} 个跨域来源（${fresh.slice(0, 5).join(", ")}）：已当作独立资产立任务，其中身份类域名。auth_token。`,
      { hosts: fresh, tasks: specs.map(item => item.id) });
  }
  /**
   * 熔断即交付：把《阻碍分析与防御测绘报告》写到产物目录，写事件，必要时推 Webhook。
   *
   * 只做"失败也是情报"这一件事：报告内容全部来。checkpoint 与图，不需要重新跑任何工具。
   */
  private deliverFrustrationReport(pid: string, sessionId: string, state: RunCheckpoint, stopReason: string): void {
    try {
      const session = this.db.getBlackboxSession(pid, sessionId);
      const report = frustrationAudit(state as unknown as Record<string, unknown>, {
        session_id: sessionId, target: String(session?.target || ""), stopReason,
      });
      const root = resolve(join(this.cfg.data_dir, "blackbox-artifacts", pid, sessionId));
      mkdirSync(root, { recursive: true });
      const filename = `frustration-audit-${Date.now()}.md`;
      writeFileSync(join(root, filename), report.markdown, "utf8");
      this.db.addBlackboxEvent(pid, sessionId, "warning", "frustration-report",
        `已自动生成《阻碍分析与防御测绘》：${report.counts.blocked} 条阻塞任。/ ${report.counts.dead_ends} 个死胡同 / ${report.counts.blocked_edges} 条拦截边。`,
        { file: filename, counts: report.counts, stop_reason: stopReason });
      void this.pushFrustrationWebhook(pid, sessionId, report.markdown, report.counts as unknown as Record<string, number>);
    } catch (error) {
      this.db.addBlackboxEvent(pid, sessionId, "warning", "frustration-report",
        `自动报告生成失败：${error instanceof Error ? error.message : String(error)}`, { stop_reason: stopReason });
    }
  }

  /** Webhook 推送（可选）：只在配置了 NIANYUN_WEBHOOK_URL 时尝试，失败不影响会话收尾。*/
  private async pushFrustrationWebhook(pid: string, sessionId: string, markdown: string, counts: Record<string, number>): Promise<void> {
    const url = String(this.cfg.tools_env?.values?.NIANYUN_WEBHOOK_URL || "").trim();
    if (!url) return;
    try {
      const deepLink = `http://127.0.0.1:8700/#/blackbox?project=${encodeURIComponent(pid)}&session=${encodeURIComponent(sessionId)}`;
      await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          msgtype: "markdown",
          markdown: { title: "Nianyun 阻碍分析", text: `${markdown.slice(0, 3500)}\n\n[打开控制台](${deepLink})` },
          counts, session_id: sessionId, project_id: pid,
        }),
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      // 推送失败不是会话失败：事件已留痕，操作员从控制台仍能拿到报告。
    }
  }

  /**
   * 给"没有结论"的任务补一条账（2026-11-05）。
   *
   * 分两种，处置必须不同：
   *   - **真的打过**（有 tool-result）：试过却没收敛 → blocked + outcome_reason
   *     （"试过，未得结论"）。
   *   - **从没派发过**：不能写 blocked —— "这条不行"和"没轮到"是两件事，
   *     写成前者是伪造结论。保持 pending，另记 `settled: "not_reached"`，
   *     让验收知道"悬着的原因已经写明"（报告用 TASK_NOT_REACHED 单列）。
   *
   * 只改状态与理由，不动证据。
   */
  private settleRemainingTasks(progress: BlackboxProgress, reason: string, evidence: Record<string, unknown>[]): { settled: number; notReached: number } {
    // "碰过"只认 tool-result（真的执行并拿到了结果）。
    // tool-request 不能作数：被焦点锁/执行器拒收的请求同样会记一条 request，
    // 但它一次都没发出去——按 request 判断会把"没打"算成"打过"。
    /**
     * 按任务归集证据 id 与**响应分布**（2026-11-05）。
     *
     * 结案说明要能回答"卡在哪"，只说"预算到了"等于没写。这里不做"最后一条"：
     * evidence 数组的顺序不是执行顺序（id 是内容哈希），拿末尾一条当"最后动作"
     * 会写出错误的事实。改成统计状态码分布——"36 条里 31 条 200、5 条 403"
     * 无论顺序如何都是真的，而且正好回答"试了很多次但没收敛"。
     */
    const touched = new Map<string, { ids: string[]; states: Map<string, number>; sample: string }>();
    const stateOf = (data: Record<string, unknown>): string => {
      if (data.status !== undefined && data.status !== null) return `HTTP ${String(data.status)}`;
      if (data.total !== undefined) return `记录 ${String(data.total)} 条`;
      if (data.error) return `错误 ${String(data.error).slice(0, 40)}`;
      return data.ok === true ? "成功（无状态码）" : "未知";
    };
    for (const item of evidence) {
      if (String(item.kind || "") !== "tool-result") continue;
      const data = (item.data || {}) as Record<string, unknown>;
      const id = String(data.task_id || "");
      if (!id) continue;
      const entry = touched.get(id) || { ids: [], states: new Map<string, number>(), sample: "" };
      const evidenceId = String(item.id || "");
      if (evidenceId) entry.ids.push(evidenceId);
      const label = stateOf(data);
      entry.states.set(label, (entry.states.get(label) || 0) + 1);
      if (!entry.sample) entry.sample = String(data.url || data.final_url || data.requested_url || "").slice(0, 100);
      touched.set(id, entry);
    }
    let settled = 0;
    let notReached = 0;
    for (const [id, task] of Object.entries(progress.state.tasks || {})) {
      if (!task || typeof task !== "object" || id.startsWith("action:")) continue;
      if (["completed", "blocked", "failed"].includes(String(task.status || ""))) continue;
      if (!touched.has(id)) {
        /**
         * 一次都没派发过：**不能**写成 blocked —— "这条不行"和"没轮到"是两件事，
         * 后者写成前者等于往报告里塞一条伪造结论。
         * 但也不能就这么悬着：验收门要求每条任务都有处置，悬着的直接后果是
         * 会话永远只能落 paused（实测 094d157f6fc028f6：收口后还剩 4 条 pending）。
         * 折中是状态保持 pending（真的没做），另记 settled:"not_reached" 与原因，
         * 验收按"已声明的缺口"放行，报告用 TASK_NOT_REACHED 单列。
         */
        progress.state.tasks[id] = {
          ...task,
          settled: "not_reached",
          outcome_reason: `未开展（${reason}）：预算在轮到本条之前耗尽，本轮一次也没有派发过。`
            + `这是"没覆盖到"，不是"不存在该问题"，需要的话下一轮优先接上。`,
        };
        notReached += 1;
        continue;
      }
      const hit = touched.get(id)!;
      const dist = [...hit.states.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([label, count]) => `${label}×${count}`)
        .join("、");
      progress.state.tasks[id] = {
        ...settleTask(task, {
          code: "budget_settled",
          reason: `未结案收口（${reason}）：预算/熔断到达上限时这条还在进行中。`
            + `本轮它拿到 ${hit.ids.length} 条执行证据，响应分布 ${dist || "（无）"}${hit.sample ? `，例如 ${hit.sample}` : ""}，但没有形成结论。`
            + `已得的证据仍有效；未验证的部分在报告里按"未覆盖"呈现，不要当作"不存在"。`,
          evidence_ids: hit.ids,
          by: "control",
        }),
        status: "blocked",
      };
      settled += 1;
    }
    // 收口后强制焦点必须摘掉：否则 resume 时会锁在一条已 blocked 的任务上（I2 的反面）。
    if ((settled || notReached) && progress.state.forced_focus?.task_id
      && ["completed", "blocked", "failed"].includes(String(progress.state.tasks[progress.state.forced_focus.task_id]?.status || ""))) {
      releaseFocus(progress.state);
    }
    return { settled, notReached };
  }

  /**
   * 任务饥饿接管（2026-11-05，改法 2）。
   *
   * 焦点锁只保证"一轮不散打"，代价是新任务可能永远排队：实测会话 51f8d006a7192f24
   * 里 graph 生成的 content_review 任务（target=/help/...）全程 pending，37 次请求
   * 一条都没派给它——焦点被 sticky 钉在首页 T1 上，模型每轮都在首页重发同一发。
   *
   * 改法 1（拒收带改投建议）解决"模型不知道有别的任务"，这里解决"知道了也不动"：
   * 连续 `STARVATION_ROUNDS` 轮 0 派发 → 控制面把焦点强制交给它（forced_focus），
   * 并留一条 `focus-auto-handoff` 事件 + 插话，让模型知道焦点是被**自动**切的，
   * 而不是莫名其妙换了（否则它下一轮还会往旧任务上投）。
   *
   * N=5 的取法：2 轮太短（一次失败的尝试就换焦点，模型更晕），10 轮太长（任务直接饿死）。
   * 5 轮 ≈ 一次完整的"焦点任务深挖→确认无进展"周期。
   */
  private noteTaskStarvation(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    requests: Array<{ task_id?: string }>,
    round: number,
  ): void {
    const dispatched = new Map<string, number>();
    for (const request of requests) {
      const id = progress.resolveTaskId(String(request.task_id || ""));
      if (id) dispatched.set(id, (dispatched.get(id) || 0) + 1);
    }
    const handoff = noteStarvation(progress.state, dispatched);
    if (!handoff) return;
    const { task_id: target, target: target_, rounds, previous_focus: focusId } = handoff;
    progress.addInterrupts([{
      /**
       * id 用被接管的**任务**，不用轮次（2026-11-09，P1）。
       *
       * 旧写法 `focus-auto-handoff:${round}` 每轮都是新 id，插话池（12 条）被这类
       * 一次性条目占满后，会把 `graph:*` 的长期欠账挤出去；被挤出后下一轮重新插入
       * 又算"新插话"，graph-signal 因此重复写事件（现场 15 分钟 7 条）。
       * 同一个任务再次饥饿就是同一件事，repeats 累加、正文原地刷新即可。
       */
      id: `focus-auto-handoff:${target}`,
      kind: "focus_auto_handoff",
      severity: "high",
      text: `【焦点自动接管】${target}${target_ ? `（${target_}）` : ""} 已连续 ${rounds} 轮没有拿到一条请求，而 ${focusId || "上一轮焦点"} 一直在被重复打。焦点**已经由控制面切给 ${target}**，不是随机漂移：本轮所有 tool_requests 都写 task_id=${target}，用它能打的最便宜的探针先拿一次响应；原焦点 ${focusId || "-"} 的结论留到它之后再收。`,
      data: { task_id: target, target: target_ || null, rounds, previous_focus: focusId || null },
    }]);
    this.db.addBlackboxEvent(pid, sessionId, "system", "focus-auto-handoff",
      `任务饥饿接管：${target}（${target_ || "-"}）连续 ${rounds} 轮 0 派发，焦点由 ${focusId || "-"} 强制切给它（旧焦点的请求本轮起会被拒收）。`,
      { task_id: target, target: target_ || null, rounds, previous_focus: focusId || null, ledger: progress.state.task_starvation || {} });
  }

  /**
   * 焦点微预算的收口判定（见 focus-budget.ts）。
   *
   * 四段式，按顺序：
   *   ，上一轮已发收口指。模型没照办就兜底。blocked
   *   ，有临界信号（新身，跳转/新假设）且没用过申诉 ，发【预算警告】宽。1 。
   *   ，刚触发预。发【强制收口】指令，本轮全部请求不执。
   *   ，本场累计收口到阈。宏观熔断，直接结束本轮并交人。
   *
   * 返回值：`reject` 非空表示本轮请求都不该执行（字符串就是回给模型的理由）；
   * `stopReason` 非空表示整场会话该停下来交人工。
   */
  private convergeFocus(
    pid: string,
    sessionId: string,
    progress: BlackboxProgress,
    focusTaskId: string,
    rawLimits: FocusLimits,
    dispatched = 1,
  ): { reject?: string; stopReason?: string } {
    const terminal = new Set(["completed", "blocked", "failed"]);
    // 阶梯型任务（waf_bypass 七档）预算按档位缩放：8 轮跑不完七档，而提示词又规定
    // "阶梯没跑满不得 blocked"——不缩放的话两条规则互相拆台（见 focus-budget.ts）。
    const limits = scaleLimitsForTask(rawLimits, progress.state.tasks[focusTaskId]);
    const pending = progress.state.focus_convergence;
    const usage = progress.state.focus_usage;

    // ，上一轮的收口指令：模型照办（任务已终态）就清账；没照办就兜底判死。
    if (pending && pending.task_id === focusTaskId) {
      const task = progress.state.tasks[focusTaskId];
      const stillOpen = Boolean(task && !terminal.has(String(task.status || "")));
      if (!stillOpen) {
        delete progress.state.focus_convergence;
        delete progress.state.focus_usage;
        return {};
      }
      // ，申诉宽限：临界信。× 价值门。× 全局池余量，三者都过才批。
      const signal = pending.appealed ? undefined : criticalSignal(progress.state, focusTaskId);
      if (signal) {
        const graph = graphState(progress.state.graph);
        const potential = potentialOf(graph, endpointNodeId(String(progress.state.tasks[focusTaskId]?.target || "")));
        const identity = Object.keys(graph.nodes).some(id => id.startsWith("id:") && graph.nodes[id]?.status !== "dead_end");
        const worthy = appealWorthy({ state: { focus_usage: usage, appealPotentialMax: limits.appeal_potential_max }, potential, identity });
        const left = appealPoolLeft(progress.state, limits);
        if (worthy.ok && left > 0 && spendAppeal(progress.state, limits)) {
          const text = appealText(usage || emptyUsage(focusTaskId, limits), `${signal}（${worthy.why}）`, pending.reason, left - 1);
          progress.state.focus_convergence = { ...pending, appealed: true, text };
          if (usage) usage.appeals_used += 1;
          if (usage) delete usage.critical;
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-appeal",
            `预算警告：${focusTaskId} 出现临界信号（${signal}）：${worthy.why}，从全局池取 1 次（剩余 ${left - 1}）。`,
            { task_id: focusTaskId, signal, worthy: worthy.why, pool_left: left - 1, potential, rounds: pending.rounds, tp: pending.tp });
          // 这一轮放行：让模型真的去用那条线索。
          return {};
        }
        this.db.addBlackboxEvent(pid, sessionId, "system", "focus-appeal-denied",
          `拒绝申诉（${focusTaskId}：${signal}）——${worthy.ok ? "全局申诉池已满" : worthy.why}，直接判 blocked。`,
          { task_id: focusTaskId, signal, worthy: worthy.why, pool_left: left, potential });
      }
      /**
       * 这里曾经把两个字段用反：`reason` 写成"焦点预算（连续 3 轮…）** 的说明，
       * `outcome_reason` 却写 `pending.reason`——那是机器码（`focus_stalled`）。
       * 报告取 `outcome_reason || reason`，于是读者只看到一行 `blocked · focus_stalled`。
       */
      Object.assign(task!, settleTask(task!, {
        code: pending.reason === "focus_stalled" ? "focus_stalled" : "focus_budget_exhausted",
        reason: `焦点预算耗尽（${pending.detail}；累计 ${pending.rounds} 轮、TP ${pending.tp}），控制面强制收口：`
          + `这几轮在这条任务上没有拿到新证据（没有新节点、新指纹或新接口），继续打它的边际收益已归零。`,
        by: "control",
      }), { status: "blocked" });
      delete progress.state.focus_convergence;
      delete progress.state.focus_usage;
      this.db.addBlackboxEvent(pid, sessionId, "system", "focus-convergence",
        `强制收口：模型未在下一轮结案 ${focusTaskId}（${pending.detail}），已由控制面标为 blocked。`,
        { task_id: focusTaskId, reason: pending.reason, detail: pending.detail, forced: true });
      return { reject: `焦点任务 ${focusTaskId} 已按焦点预算强制标记 blocked（${pending.reason}）：本轮不要再打它，直接在新焦点上规划。` };
    }
    // 焦点漂移：收口指令指向的任务已经不是本焦点。旧实现直接丢弃指令。
    // 于是「强制收口」在焦点被粘，排他任务抢走后静默失效（2026-10-31 m.ctrip.com
    // 连续两次 focus-convergence 都没让任务进入终态）。这里对该任务直接兜底收口。
    if (pending && pending.task_id !== focusTaskId) {
      const other = progress.state.tasks[pending.task_id];
      const stillOpen = Boolean(other && !terminal.has(String(other.status || "")));
      if (stillOpen) {
        Object.assign(other!, settleTask(other!, {
          code: pending.reason === "focus_stalled" ? "focus_stalled" : "focus_budget_exhausted",
          reason: `焦点预算耗尽（${pending.detail}；累计 ${pending.rounds} 轮、TP ${pending.tp}），且焦点已漂移到 ${focusTaskId}，`
            + `收口指令没有被执行，由控制面兜底收口。`,
          by: "control",
        }), { status: "blocked" });
        this.db.addBlackboxEvent(pid, sessionId, "system", "focus-convergence",
          `兜底收口：${pending.task_id} 的收口指令在焦点漂移后未被模型执行，已标为 blocked。`,
          { task_id: pending.task_id, reason: pending.reason, detail: pending.detail, forced: true, drifted: true });
      }
      delete progress.state.focus_convergence;
    }

    // ，本轮结算：轮。/ TP / 无增益轮数。
    const { usage: charged, convergence } = chargeFocusRound(progress.state, focusTaskId, limits, dispatched);
    if (!convergence) return {};
    progress.state.focus_convergence = convergence;
    const count = Number(progress.state.usage?.session_convergences || 0) + 1;
    if (progress.state.usage) progress.state.usage.session_convergences = count;
    this.db.addBlackboxEvent(pid, sessionId, "system", "focus-convergence",
      `收益递减：${focusTaskId} 已消耗 ${convergence.rounds} 轮 / ${convergence.tp} TP（${convergence.detail}），本轮改为强制收口。`,
      {
        task_id: focusTaskId, reason: convergence.reason, detail: convergence.detail,
        rounds: convergence.rounds, tp: convergence.tp,
        value_score: charged.value_score, high_value: charged.high_value, noise: charged.noise,
        session_convergences: count,
      });

    // ，宏观熔断：全场都在收口说明方向错了，别再一条条试。
    if (limits.max_session_convergences > 0 && count >= limits.max_session_convergences) {
      const macro: MacroInterrupt = { count, limit: limits.max_session_convergences, text: macroInterruptText(count, limits.max_session_convergences), at: Date.now() };
      progress.state.macro_interrupt = macro;
      this.db.addBlackboxEvent(pid, sessionId, "warning", "macro-interrupt",
        `宏观熔断：本场累计收口 ${count} 次（阈值 ${limits.max_session_convergences}），停止常规探测，转人工介入。`, { count, limit: limits.max_session_convergences });
      // 熔断即交付：立刻产出一份《阻碍分析与防御测绘》，别让人再点一。Summary。
      this.deliverFrustrationReport(pid, sessionId, progress.state, "macro_frustration");
      return { reject: macro.text, stopReason: "macro_frustration" };
    }
    return { reject: convergence.text };
  }

  private watchPostSurface(pid: string, sessionId: string, progress: BlackboxProgress, requests: Array<{ task_id?: string }>): void {
    const watch = progress.state.linkage?.post_surface;
    if (!watch) return;
    const status = String(progress.state.tasks[watch.task_id]?.status || "");
    if (["completed", "blocked", "failed"].includes(status)) {
      if (progress.state.exclusive_task === watch.task_id) {
        progress.state.exclusive_task = undefined;
        progress.state.exclusive_reason = undefined;
        this.db.addBlackboxEvent(pid, sessionId, "system", "exclusive-release",
          `POST 面任。${watch.task_id} 。${status}，排他锁解除，其余任务恢复。`, { task_id: watch.task_id, status });
      }
      return;
    }
    const served = requests.some(item => String(item.task_id || "") === watch.task_id);
    const result = progress.tickPostSurface(served);
    if (result.released) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "post-surface-release",
        `排他提权后连。4 轮无人服。${watch.task_id}：已释放排他锁并。blocked，避免整轮请求被 skip。`,
        { task_id: watch.task_id });
      return;
    }
    if (result.blocked_by === "forced_focus" && result.ignored_turns === 2) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "post-surface-defer",
        `POST 面任务 ${watch.task_id} 暂不提权：当前存在更强的强制焦点（${progress.state.forced_focus?.task_id || "?"}），抢锁只会互相 skip。`,
        { task_id: watch.task_id, forced_focus: progress.state.forced_focus?.task_id });
      return;
    }
    if (!result.escalated) return;
    this.db.addBlackboxEvent(pid, sessionId, "system", "post-surface-escalate",
      `POST 面任。${watch.task_id} 连续 ${result.ignored_turns} 轮未被派活：已提权为唯一可执行任务，其余任务暂停（认证链除外）。`,
      { task_id: watch.task_id, ignored_turns: result.ignored_turns });
  }

  private injectPostSurfaceTask(pid: string, sessionId: string, progress: BlackboxProgress): void {
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const spec = postSurfaceTask(progress.state, stamp);
    if (!spec) return;
    const host = String(progress.state.auth_wall?.host || "").replace(/\/+$/, "");
    progress.merge({ required_tasks: [{ ...spec, target: host ? `${host}/` : spec.target }] });
    progress.state.linkage = { ...progress.state.linkage, post_surface: { task_id: spec.id, ignored_turns: 0 } };
    this.db.addBlackboxEvent(pid, sessionId, "system", "post-surface",
      `没有任何 POST 型打法被运行：已投递方法面枚举任务 ${spec.id}（${spec.reason}）。`, { task_id: spec.id, discovered: Object.keys(progress.state.endpoints || {}).length });
  }
  /**
   * OAST / Burp 联动：高危无回显打法必须先挂 interactsh；爬完入口必须过一。Burp 扫描。
   * 两条都是"不投就永远漏"的动作，所以由代码兜底而不是指望模型自觉。
   */
  private injectLinkageTasks(pid: string, sessionId: string, progress: BlackboxProgress): void {
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    for (const [kind, spec] of [["oast", oastRequiredTask(progress.state, stamp)], ["burp", burpScanTask(progress.state, stamp)]] as const) {
      if (!spec) continue;
      progress.merge({ required_tasks: [spec] });
      this.db.addBlackboxEvent(pid, sessionId, "system", `linkage-${kind}`,
        `${spec.reason}：已投递任。${spec.id}。`, { task_id: spec.id });
    }
  }

  /** 参数面熔断时补一条事件，让操作员在时间线上看见“这个端点被榨干了”。*/
  private reportParamStall(pid: string, sessionId: string, progress: BlackboxProgress): void {
    const alert = progress.state.param_stall_alert;
    if (!alert) return;
    const seen = Number(progress.state.supervision?.paramStallSeenAt || 0);
    if (alert.at <= seen) return;
    progress.state.supervision = { ...progress.state.supervision, paramStallSeenAt: alert.at } as never;
    this.db.addBlackboxEvent(pid, sessionId, "system", "param-stall",
      `参数面熔断：${alert.path} 打了 ${alert.calls} 次（${alert.queries} 种参。/ ${alert.variants ?? 0} 个路。id），响应指纹只有 ${alert.fingerprints} 种，已停止该端点的参数遍历。`,
      { ...alert });
  }
  /**
   * 鉴权墙触发后强制换方向：。"/api/* 已被。" 变成两条具体任务（拿 Token / 找未授权入口），
   * 并投一条待处置建议，模型必须逐条回应才能继续。返。true 表示本次需。Observer 介入。
   */
  private injectAuthWallAdvice(pid: string, sessionId: string, progress: BlackboxProgress): boolean {
    const wall = progress.state.auth_wall;
    const alert = progress.state.auth_wall_alert;
    if (!wall?.tripped_at || !alert || wall.advice_id) return false;
    const host = wall.host || "";
    const stamp = new Date(alert.at).toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const denied = (wall.urls || []).slice(0, 5).join(", ");
    const specs = [
      { id: `auth_login_${stamp}`, target: `${host}/`, purpose: "认证链：browser.open 填登录表单并 evaluate 取 token，再用 http.request 带 Authorization 重打被拒接口",
        reason: `统一鉴权拦截：${denied} 全部返回 ${wall.code || "401"}；先解决凭证问题`,
        completion_criteria: "拿到可用的 Token/Cookie，并用它让至少一个原本 10403 的接口返回业务数据", playbook: "auth_token" },
      { id: `auth_unauth_${stamp}`, target: `${host}/`, purpose: "找不需要 Token 的入口（swagger/actuator/robots/JS 里的接口）",
        reason: "统一鉴权拦截：换一条不需要凭证的。",
        completion_criteria: "确认一个无需鉴权即可读到业务数据的入口", playbook: "unauth_exposure" },
    ];
    progress.merge({ required_tasks: specs });
    const adviceId = `advice-authwall-${stamp}`;
    progress.supplement({ tasks: specs, suggestions: [`${denied} 已被同一鉴权墙拦截，停止遍历这些前缀；先用登。Token 或未授权入口推进。`] }, adviceId);
    progress.state.auth_wall = { ...wall, advice_id: adviceId };
    this.db.addBlackboxEvent(pid, sessionId, "system", "auth-wall",
      `检测到统一鉴权拦截（${wall.urls.length} 个不同入口返回 ${wall.code || "401"}）：已停止遍历，改找 Token/登录/未授权入口。`,
      { host, code: wall.code, denied: wall.urls.slice(0, 10), advice_id: adviceId, kind: alert.kind });
    return true;
  }

  /**
   * An advice decision recorded against an id that never existed (the agent pasted an evidence id)
   * can never be repaired by the agent. Only an explicit operator resume clears it, so the desk
   * never silently forgives protocol mistakes on its own.
   */
  private clearUnreachableAdviceErrors(pid: string, sessionId: string): void {
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return;
    const progress = new BlackboxProgress(session.checkpoint, { resume: false });
    const stale = (progress.state.transitionErrors || []).filter(message => {
      const [code, ...identity] = message.split(":");
      return code === "invalid_advice_decision" && !progress.state.advice?.[identity.join(":")];
    });
    if (!stale.length) return;
    progress.state.transitionErrors = (progress.state.transitionErrors || []).filter(message => !stale.includes(message));
    progress.state.validationErrors = [...progress.state.transitionErrors];
    this.db.updateBlackboxSession(pid, sessionId, { checkpoint: progress.state });
    this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
      `操作员恢复时清理。${stale.length} 条不可达的建议处置错误（引用了不存在的建。id）。`, { errors: stale });
  }

  reviewProjectBlackboxItem(projectId: string, sessionId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    if (this.blackboxAbort.has(`${pid}:${sessionId}`) || this.blackboxFlight.has(`${pid}:${sessionId}`)) return { ok: false, error: "请等待当前执行停止并保存检查点" };
    if (session.status === "cancelled") return { ok: false, error: "会话已取。" };
    const reason = String(payload.reason || "").trim();
    if (!reason || reason.length > 2000) return { ok: false, error: "需。1。000 字的复核理由" };
    const progress = new BlackboxProgress(session.checkpoint, { resume: false });
    const id = String(payload.id || "");
    const action = String(payload.action || "");
    if (payload.kind === "advice_decisions") {
      if (session.status === "running") return { ok: false, error: "请先暂停会话并等待检查点保存" };
      const parsed = mainSchema.pick({ advice_decisions: true }).strict().safeParse(payload.output);
      if (!parsed.success || !parsed.data.advice_decisions.length ||
          new Set(parsed.data.advice_decisions.map(d => d.advice_id)).size !== parsed.data.advice_decisions.length)
        return { ok: false, error: "需要唯一、明确且符合 Schema 的建议处置；不允许附带其他动。" };
      progress.merge(parsed.data);
      const results = progress.state.adviceDecisionResults || [];
      const rejected = results.some(r => r.status !== "applied" && r.status !== "already_applied");
      const acceptance = evaluateAcceptance(progress.state, session.evidence as Record<string, unknown>[]);
      progress.state.supervision ||= { observerRuns: 0 };
      progress.state.supervision.acceptance = acceptance;
      const committed = this.db.commitBlackboxProgressReview(pid, sessionId, session.checkpoint as object, progress.state, {
        reason, output: parsed.data, rejected, results, acceptance,
      }, "advice-disposition");
      if (!committed) return { ok: false, error: "检查点已变化，请刷新后重新提交" };
      const saved = this.db.getBlackboxSession(pid, sessionId)!;
      return { ok: !rejected, results, acceptance, advice_audit: auditAdviceHistory(progress.state, saved.events as Parameters<typeof auditAdviceHistory>[1]), session: saved };
    }
    if (payload.kind === "task_outcomes") {
      if (session.status === "running") return { ok: false, error: "请先暂停会话并等待检查点保存" };
      const parsed = mainSchema.pick({ completed_tasks: true, task_outcomes: true }).strict().safeParse(payload.output);
      if (!parsed.success || !parsed.data.completed_tasks.length ||
          new Set(parsed.data.completed_tasks).size !== parsed.data.completed_tasks.length ||
          parsed.data.task_outcomes.length !== parsed.data.completed_tasks.length ||
          new Set(parsed.data.task_outcomes.map(o => o.task_id)).size !== parsed.data.task_outcomes.length ||
          parsed.data.completed_tasks.some(task => !parsed.data.task_outcomes.some(o => o.task_id === task)))
        return { ok: false, error: "需要逐项明确提交完成任务及唯一 task_outcomes；不允许隐式过滤或额外动。" };
      progress.merge(parsed.data, session.evidence as Record<string, unknown>[]);
      const rejected = parsed.data.completed_tasks.some(task => progress.state.taskOutcomeResults?.[task]?.status !== "applied");
      const acceptance = evaluateAcceptance(progress.state, session.evidence as Record<string, unknown>[]);
      progress.state.supervision ||= { observerRuns: 0 };
      progress.state.supervision.acceptance = acceptance;
      // Keep the paused state and all other blockers; a correction never resumes tests or marks the run successful.
      const committed = this.db.commitBlackboxProgressReview(pid, sessionId, session.checkpoint as object, progress.state, {
        reason, output: parsed.data, rejected, results: progress.state.taskOutcomeResults, acceptance,
      });
      if (!committed) return { ok: false, error: "检查点已变化，请刷新后重新提交" };
      return { ok: !rejected, error: rejected ? "任务完成引用被拒绝，请按校验明细修正" : undefined, acceptance,
        results: progress.state.taskOutcomeResults, session: this.db.getBlackboxSession(pid, sessionId) };
    }
    if (payload.kind === "finding") {
      const finding = progress.state.findings?.[id];
      if (!finding || !["confirm", "reject", "needs_evidence"].includes(action)) return { ok: false, error: "发现不存在或决策无效" };
      const error = validateFinding(finding, session.evidence as Record<string, unknown>[]);
      if (action === "confirm" && error) return { ok: false, error };
      if (action === "confirm" && finding.status !== "reviewed") return { ok: false, error: "需要先完成 Observer 证据审阅，再人工确认" };
      finding.status = action === "confirm" ? "confirmed" : action === "reject" ? "rejected" : "needs_evidence";
      finding.review = { actor: "operator", reason, evidence_ids: finding.evidence_ids, at: Date.now() };
    } else return { ok: false, error: "invalid review kind" };
    this.db.updateBlackboxSession(pid, sessionId, { checkpoint: progress.state });
    this.db.addBlackboxEvidence(pid, sessionId, { kind: "operator-review", source: "operator", summary: reason, data: { kind: payload.kind, id, action } });
    this.db.addBlackboxEvent(pid, sessionId, "operator", "review", `${action}: ${reason}`, { kind: payload.kind, id });
    return { ok: true, session: this.db.getBlackboxSession(pid, sessionId) };
  }

  projectBlackboxReport(projectId: string, sessionId: string): Record<string, unknown> {
    // 报告 / 验收属于内部逻辑，必须用 DB 里的完整会话（events / evidence 仍是内联数组）。
    // projectBlackboxSession 是 HTTP 详情投影：为前端分页把这两个大数组剥离了，
    // 只留 event_count / evidence_count / run_summary。拿它喂给 evaluateAcceptance、
    // blackboxReport、auditAdviceHistory 会收到 undefined 并直接抛 "not iterable"。
    // 这里直接读 DB，既保住内部逻辑，又不影响详情接口的分页瘦身。
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    const progress = new BlackboxProgress(session.checkpoint, { resume: false });
    return { ok: true, ...blackboxReport(session),
      acceptance: evaluateAcceptance(progress.state, (session.evidence || []) as Record<string, unknown>[]),
      advice_audit: auditAdviceHistory(progress.state, (session.events || []) as Parameters<typeof auditAdviceHistory>[1]) };
  }

  clearProjectCookies(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    this.db.setProjectCookies(pid, []);
    return { ok: true };
  }

  clearProjectBlackboxCookies(projectId: string, sessionId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    this.db.setProjectCookies(pid, []);
    this.db.addBlackboxEvent(pid, sessionId, "operator", "cookies-cleared", "操作员清空了项目 Cookie jar（该项目的所有黑盒会话共享）。");
    return { ok: true, session: this.db.getBlackboxSession(pid, sessionId) };
  }

  addProjectBlackboxInstruction(projectId: string, sessionId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const text = String(payload.text || "").trim();
    if (!text) return { ok: false, error: "instruction is required" };
    if (text.length > 8000) return { ok: false, error: "instruction is too long" };
    const event = this.db.addBlackboxEvent(pid, sessionId, "operator", "instruction", text);
    return event ? { ok: true, event, session: this.db.getBlackboxSession(pid, sessionId) } : { ok: false, error: "blackbox session not found" };
  }

  async runProjectBlackboxAgents(projectId: string, sessionId: string): Promise<Record<string, unknown>> {
    this.execution("blackbox agents");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    if (session.status === "running" || this.blackboxAbort.has(`${pid}:${sessionId}`)) return { ok: false, error: "blackbox session is already running" };
    if (session.status === "cancelled") return { ok: false, error: "blackbox session is cancelled" };
    // 时光机：开跑前把当前账本归档成快照（fork 从这里分叉，不依赖任何数据库状态位操作）。
    try {
      const archived = this.db.addBlackboxCheckpoint(pid, sessionId, (session.checkpoint as Record<string, unknown> | undefined) || {}, "run_start");
      this.db.addBlackboxEvent(pid, sessionId, "system", "checkpoint-archived",
        `已归档第 ${this.db.listBlackboxCheckpoints(pid, sessionId, 1)[0]?.run_index || 1} 。run 的账本快照（id=${archived}），可从。fork 对照实验。`,
        { checkpoint_id: archived });
    } catch (error) { console.warn(`[blackbox] checkpoint archive failed: ${error}`); }
    const environment = (session.environment || {}) as Record<string, unknown>;
    if (environment.ready !== true) return { ok: false, error: "environment check must pass before Agent analysis" };
    const candidate = this.db.getAssetCandidate(pid, String(session.candidate_id || ""));
    if (!candidate) return { ok: false, error: "candidate not found" };
    if (!this.db.claimBlackboxSession(pid, sessionId, session.checkpoint as object)) return { ok: false, error: "会话已被其他执行者领取或检查点已变。" };
    const budget = this.blackboxBudget();
    // 规则加载带上诊断口：废弃，非法值一律留痕，控制台据此显示黄色横幅。
    const ruleIssues: string[] = [];
    const rules = blackboxRules(this.cfg.tools_env.values, { issues: ruleIssues });
    // 焦点锁是。LLM 的注意力漂移准备的（一轮只许推一个任务，其余请求拒收）。
    // 本地规划器是确定性调度：它自己按任务表推进，被焦点锁拒收只会空转。stalled。
    // 因此本地规划模式下关掉焦点锁，并在时间线里留一条可追溯的记录。
    const localPlanner = useLocalPlanner(this.cfg.tools_env.values);
    if (localPlanner && rules.focus_lock?.on) {
      rules.focus_lock.on = false;
      this.db.addBlackboxEvent(pid, sessionId, "system", "local-planner",
        "本地规划模式：已关闭焦点锁（确定性调度不需要单任务强制收敛）。", { focus_lock: false });
    }
    const progress = new BlackboxProgress(session.checkpoint);
    // 历程图横。= 第几。run：刚归档的那。run_index 就是本轮编号，写。state 。ingest 用。
    // （不。planRevision：那是任务计划版本，，第几轮挖，不是一回事。）
    progress.graphRound = Number(this.db.listBlackboxCheckpoints(pid, sessionId, 1)[0]?.run_index || 1);
    /**
     * 旧熔断的自我修复（2026-11-10）。
     *
     * `macro_interrupt` 是**粘性**的：一旦写入，`focus.ts` 每轮都把它当指令，
     * resume 也不会清。所以把 `max_session_convergences` 调成 0（不限）后，
     * 老会话仍然卡在"只投收口级取证"上——规则改了等于没改。
     * 这里在加载时检测：上限已放宽到不限，就把残留的熔断状态清掉并留痕。
     */
    if (rules.focus_lock.max_session_convergences <= 0 && progress.state.macro_interrupt) {
      const stale = progress.state.macro_interrupt;
      progress.state.macro_interrupt = undefined;
      this.db.addBlackboxEvent(pid, sessionId, "system", "macro-interrupt-released",
        `宏观熔断已解除：上限改为不限（原熔断在第 ${stale.count} 次收口时触发），恢复常规探测。`,
        { count: stale.count, limit: stale.limit });
    }
    // 同步进 state：`progress.graphRound` 是类实例字段，而 checkpoint 落盘的是
    // `progress.state`。消费侧（ingest 的 round、假设池 LRU）读的是 state 字段，
    // 只写类字段等于没写——实测 round 恒为 1，历程图横轴全挤在同一列。
    progress.state.graphRound = progress.graphRound;
    progress.authWall = rules.auth_wall;
    // 鉴权墙的放行通道（未授权打法 / 敏感路径 / 显式 bypass）：墙是防复读机，不是禁做未授权验证。
    progress.wallOptions = {
      safePaths: rules.auth_wall.safe_paths,
      allowUnauthPlaybook: rules.auth_wall.allow_unauth_playbook,
      allowBypass: rules.auth_wall.allow_bypass,
    };
    progress.paramStall = { calls: rules.loop_control.param_stall_calls, queries: rules.loop_control.param_stall_queries, variants: rules.loop_control.param_stall_variants, ratio: rules.loop_control.param_stall_ratio };
    progress.advicePendingLimit = rules.loop_control.advice_pending_limit;
    progress.taskPendingLimit = rules.loop_control.task_pending_limit;
    // 任务簿水位要进上下文：看不见上限，模型就只会不停地往簿子上加"再确认一下"。
    // 只写一个数字（不进配置文件），下一轮 checkpointView 直接渲染成 backlog。
    if (rules.loop_control.task_pending_limit > 0) {
      (progress.state as { task_pending_limit?: number }).task_pending_limit = rules.loop_control.task_pending_limit;
    }
    // 冒烟校验：优先复。checkpoint 里的结果（只灌进执行器缓存，不改状态）。
    // 没有结果且当前没有待审的 Observer 复核时才现跑一次——有 pending review 时改状态会。
    // 已经签发的复核快照失效（review id 绑定了状态版本）。
    // 冒烟校验：checkpoint 里有就直接灌进执行器缓存（不改状态）；没有就等第一批工具执行前再跑。
    // 避免"一跑会话就探活 12 个二进制"把没有工具调用的回合拖慢。
    const storedPreflight = progress.state.preflight as Parameters<typeof setPreflight>[0] | undefined;
    if (storedPreflight) setPreflight(storedPreflight);
    // 跨域 JS 判断"是不是第三方"要用目标主域，会话目标在 checkpoint 里可能还没有。
    if (!progress.state.target_host) {
      try { progress.state.target_host = new URL(String((session as { target?: string }).target || "")).host; } catch { /* 目标不是 URL，忽。*/ }
    }
    const controller = new AbortController();
    this.blackboxAbort.set(`${pid}:${sessionId}`, controller);
    try {
    const usage = progress.state.usage;
    // 。checkpoint 没有 toolMs：先补齐，否则调度时间会把历史墙钟全算进来。
    usage.toolMs ??= 0;
    const startedAt = Date.now();
    const previousElapsed = usage.elapsedMs;
    // Budgets are per run (time/tools/turns). Session totals stay cumulative for reporting only.
    const runBase = { elapsedMs: previousElapsed, toolCalls: usage.toolCalls, agentTurns: usage.agentTurns, tokens: usage.tokens, cost: usage.cost, retries: usage.retries, toolMs: Number(usage.toolMs || 0) };
    const runBudget = { ...this.blackboxBudget(), base: runBase };
    const runUsage = () => {
      const wallMs = Date.now() - startedAt;
      const toolMs = Math.max(0, Number(usage.toolMs || 0) - Number(runBase.toolMs || 0));
      return {
        wallMs,
        toolMs,
        // 调度时间：墙钟减去工具执行耗时。慢工具不再吃掉"思考预。。
        timeMs: Math.max(0, wallMs - toolMs),
        toolCalls: Math.max(0, usage.toolCalls - runBase.toolCalls),
        agentTurns: Math.max(0, usage.agentTurns - runBase.agentTurns),
        tokens: Math.max(0, usage.tokens - runBase.tokens),
        cost: Math.max(0, usage.cost - runBase.cost),
        retries: Math.max(0, usage.retries - runBase.retries),
      };
    };
    const taskRetryLimit = rules.loop_control.task_retry_limit;
    const repeatLimit = rules.loop_control.repeat_limit;
    const stallLimit = rules.loop_control.stall_batch_limit;
    // 。stalled 的调用地板：3 次调用就收尾，是，还没开，当成"打不。。
    // 2026-10-31 实测会话 277a31c5647c7864。 次调。/ 8 回合后判 stalled。0 个待办一个没跑。
    const STALL_CALL_FLOOR = 12;
    const stageMs = rules.loop_control.stage_timeout_sec * 1000;
    const stageRolloverLimit = Math.max(0, Number(rules.loop_control.stage_rollover_limit || 0));
    let stageRollovers = 0;
    let stopReason = "";
    let expectedCheckpoint = structuredClone(session.checkpoint as object);
    const reviewVersionOf = (state: typeof progress.state) => observerStateVersion(state,
      (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
    /** 存量会话的 review.state_version 是旧算法算出来的：两套都认，resume 不会一次性全判 stale。 */
    const versionMatches = (stored: unknown, state: RunCheckpoint = progress.state) => observerStateVersionMatches(stored, state,
      (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
    const commitReview: typeof this.db.commitBlackboxObserverReview = (project, sid, expected, next, event) => {
      const committed = this.db.commitBlackboxObserverReview(project, sid, expected, next, event);
      if (committed) expectedCheckpoint = structuredClone(next);
      else {
        const current = this.db.getBlackboxSession(pid, sessionId)!;
        progress.state = new BlackboxProgress(current.checkpoint, { resume: false }).state;
        expectedCheckpoint = structuredClone(current.checkpoint as object);
        stopReason = "observer_review_checkpoint_conflict";
      }
      return committed;
    };
    let lastCheckpointDigest = "";
    const save = () => {
      usage.elapsedMs = previousElapsed + Date.now() - startedAt;
      progress.state.usage = { ...usage, session_convergences: progress.state.usage?.session_convergences };
      // Persist on every save, but only write a timeline row when the checkpoint really moved:
      // a round saved 5-6 times, drowning the events the operator actually reads.
      // 焦点必须在每次落盘时都成立：supervise 会用落盘快照替换 progress.state。
      // 只在请求准入时赋一次会丢。这里只做轻量校验，不重复跑 Dijkstra。
      const focusTask = progress.state.focus_task_id ? progress.state.tasks[progress.state.focus_task_id] : undefined;
      if (!focusTask || ["completed", "blocked", "failed"].includes(String(focusTask.status || ""))) {
        progress.state.focus_task_id = computeFocus(progress.state)?.task_id || "";
      }
      const digest = createHash("sha256").update(JSON.stringify({ ...progress.state, usage: null })).digest("hex");
      const silent = digest === lastCheckpointDigest;
      if (!commitReview(pid, sessionId, expectedCheckpoint, progress.state, silent ? null : { kind: "checkpoint", text: "保存执行检查点。", data: {} })) throw new Error("observer_review_checkpoint_conflict");
      lastCheckpointDigest = digest;
    };
    const overBudget = (): string => {
      if (this.db.getBlackboxSession(pid, sessionId)?.status === "cancelled") return "operator_cancelled";
      if (this.db.getBlackboxSession(pid, sessionId)?.status === "paused") return "operator_paused";
      const run = runUsage();
      // 调度预算：只，思考与决策"花了多久，工具执行的秒数不算。
      if (budget.timeMs > 0 && run.timeMs >= budget.timeMs) return "time_budget_exhausted";
      // 墙钟上限：真正的兜底，防止容器被慢工具或卡死的模型调用挂住。
      if (budget.wallClockMs > 0 && run.wallMs >= budget.wallClockMs) return "wall_clock_exhausted";
      if (budget.toolCalls > 0 && run.toolCalls >= budget.toolCalls) return "tool_budget_exhausted";
      if (budget.agentTurns > 0 && run.agentTurns >= budget.agentTurns) return "agent_turn_budget_exhausted";
      if (budget.tokens > 0 && run.tokens >= budget.tokens) return "token_budget_exhausted";
      if (budget.cost > 0 && run.cost >= budget.cost) return "cost_budget_exhausted";
      if (budget.retries > 0 && run.retries >= budget.retries) return "retry_budget_exhausted";
      return "";
    };
    const addUsage = (result: Record<string, unknown>, persist = true) => {
      const modelUsage = result._usage && typeof result._usage === "object" ? result._usage as Record<string, unknown> : {};
      usage.tokens += Number(modelUsage.input_tokens || 0) + Number(modelUsage.output_tokens || 0);
      usage.cost += Number(modelUsage.cost || 0);
      if (persist) save();
    };
    /**
     * 输出预算的跨轮放大系数：空正文 / JSON 截断时，根因往往是输出预算不够
     * （推理模型把 max_tokens 吃在思维链上），下一轮临时抬一次，成功后自动回落。
     */
    let outputBoost = 1;
    const configuredMaxTokens = Number(this.cfg.tools_env.values.BLACKBOX_AGENT_MAX_TOKENS) || 0;
    const modelValues = () => {
      const run = runUsage();
      const scheduleLeft = budget.timeMs > 0 ? Math.max(1, budget.timeMs - run.timeMs) : stageMs;
      const wallLeft = budget.wallClockMs > 0 ? Math.max(1, budget.wallClockMs - run.wallMs) : stageMs;
      const boostedTokens = outputBoost > 1
        ? Math.min(16_000, Math.round((configuredMaxTokens || 12_000) * outputBoost))
        : configuredMaxTokens;
      return {
        ...this.cfg.tools_env.values,
        ...(boostedTokens ? { BLACKBOX_AGENT_MAX_TOKENS: String(boostedTokens) } : {}),
        BLACKBOX_AGENT_TIMEOUT_MS: String(Math.max(1, Math.min(stageMs,
          Number(this.cfg.tools_env.values.BLACKBOX_AGENT_TIMEOUT_MS) || 180000, scheduleLeft, wallLeft))),
      };
    };
    /**
     * 本次 run 的预算视图：模型据此决定"上不上重型扫描器"。
     * 降级判据。weights.ts —，墙钟/权重放不下待推进 playbook 的时间盒时切 fast。
     */
    const budgetView = () => {
      const run = runUsage();
      const pendingPlaybooks = Object.values(progress.state.tasks)
        .filter(task => !["completed", "blocked", "failed"].includes(String(task.status)))
        .map(task => playbookById(String(task.playbook || "")))
        .filter((playbook): playbook is NonNullable<typeof playbook> => Boolean(playbook));
      const timeboxSec = pendingPlaybooks.length ? Math.min(...pendingPlaybooks.map(playbook => playbook.timebox_sec)) : 0;
      const view = budgetMode({
        wallMsLeft: budget.wallClockMs > 0 ? Math.max(0, budget.wallClockMs - run.wallMs) : 0,
        scheduleMsLeft: budget.timeMs > 0 ? Math.max(0, budget.timeMs - run.timeMs) : 0,
        weightLeft: budget.toolCalls > 0 ? Math.max(0, budget.toolCalls - run.toolCalls) : 0,
        timeboxSec,
      });
      return {
        mode: view.mode,
        reasons: view.reasons,
        schedule_ms_left: budget.timeMs > 0 ? Math.max(0, budget.timeMs - run.timeMs) : 0,
        wall_ms_left: budget.wallClockMs > 0 ? Math.max(0, budget.wallClockMs - run.wallMs) : 0,
        tool_weight_left: budget.toolCalls > 0 ? Math.max(0, budget.toolCalls - run.toolCalls) : 0,
        tool_ms_spent: run.toolMs,
        pending_timebox_sec: timeboxSec,
        guidance: view.mode === "fast"
          ? "预算只能支持快速模式：只做轻量步骤（http.request / http.diff / interactsh / browser），跳过 sqlmap、nuclei、katana、目录爆破等重型扫描器——调用它们会被执行器以 budget_degraded 拒绝。确认以轻量证据为准（timing_delta、结构化 diff、OAST 回连）。"
          : "预算充足：可以按完整 playbook 推进，包。sqlmap/nuclei/katana 等重型步骤。",
        // 战例库每轮重算：本轮刚打穿的墙下一轮就变成"先照抄的。1 。。
        waf_ledger: this.wafLedgerRuntime(progress.state.waf_escalation),
        // 种子体检结论：模型据此知道"这堵墙是谁造的"，别把自家 Cookie 的问题当成目标的风控。
        ...(this.seedHealthRuntime(progress.state) ? { seed_health: this.seedHealthRuntime(progress.state) } : {}),
        // 已登记的工具缺口：主 Agent 据此不重复报同一条，也提醒它先用兜底工具把活干完。
        ...(this.toolGapRuntime(progress.state) ? { tool_gaps: this.toolGapRuntime(progress.state) } : {}),
      };
    };
    progress.state.rule_version = rules.version;
    progress.state.rule_hash = blackboxRulesHash(rules);
    // 把自检结论绑定到当前这罐 Cookie：开局先落一次指纹，存量会话里缺指纹的旧结论
    // 补一次戳（不判 stale），之后罐一变就能正常触发重检。冷却窗口可按环境调，
    // 默认 5 分钟，避免开发环境 Set-Cookie 抖动导致每轮重检。
    const jarFingerprint = cookieJarFingerprint(this.db.getProjectCookies(pid));
    progress.state.seed_jar_fingerprint = jarFingerprint;
    const cooldown = Number(this.cfg.tools_env?.values?.BLACKBOX_SEED_PROBE_COOLDOWN_MS ?? 300_000);
    progress.state.seed_probe_cooldown_ms = Number.isFinite(cooldown) && cooldown >= 0 ? cooldown : 300_000;
    for (const record of Object.values(progress.state.seed_health || {})) {
      if (!record.jar_fingerprint) record.jar_fingerprint = jarFingerprint;
    }
    const ruleState = blackboxRulesDiagnostics(this.cfg.tools_env.values);
    progress.state.credential_tools = ruleState.credential_tools;
    progress.state.rule_issues = ruleState.issues;
    const credentialNote = ruleState.credential_tools.length ? ` 本次开启凭据爆破：${ruleState.credential_tools.join("、")}。` : "";
    this.db.addBlackboxEvent(pid, sessionId, "system", "lifecycle", `Agent 开始按任务状态机推进。工具数量不设固定轮次限制，直到任务完成、预算耗尽或安全停止。${credentialNote}`, {
      automatic_tool_execution: true, budget, rule_version: rules.version, rule_hash: progress.state.rule_hash,
      credential_tools: ruleState.credential_tools, rule_issues: ruleState.issues,
    });
    if (ruleState.issues.length) {
      const head = ruleState.fallback ? "规则文档无法解析，本次按默认规则运行（所有工具可用、默认预算生效）。" : "规则文档有被忽略的配置项，本次按其余配置运行。";
      this.db.addBlackboxEvent(pid, sessionId, "system", "rule-warning", head, { issues: ruleState.issues, credential_tools: ruleState.credential_tools });
    }
    // 配置文件本身的问题（一个键都没解析出来 / 被 Desk 设置覆盖）：这些不开日志就完全看不见，
    // 表现为"改了配置毫无反应"，是最容易被误判成代码 bug 的一类故障。
    const envWarnings = this.cfg.tools_env.warnings || [];
    if (envWarnings.length) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "config-warning",
        `配置加载有 ${envWarnings.length} 项问题：${envWarnings.join("；")}`, { warnings: envWarnings });
    }
    // 后台审查守护：submit 立即返回，主循环不等它；interrupt 在下一轮开。drain。
    const observerMode = observerModeFrom(modelValues());
    const observerDaemon = new ObserverDaemon({
      onError: (_jobId, error) => this.db.addBlackboxEvent(pid, sessionId, "system", "observer-async-error",
        `后台 Observer 失败：${error instanceof Error ? error.message : String(error)}`, {}),
    });
    let observe!: (reason: ObserverReview["reason"], triggerEventId: string, issues?: unknown[], detach?: boolean) => Promise<Record<string, unknown>>;
    /**
     * 门禁全放行（2026-11-06）：评审挂账不再直接停场。
     *
     * 实测 e8bdb447acf02283：跑到 418s（预算 720s）时终审已经完成、还写下了可执行建议，
     * 4 个待办一个没跑，却因为 `reviewPending` 为真把整场停成 `awaiting_operator`，
     * 白扔 300s。而"等操作员签收"在无人值守场景下根本不会发生，等于会话提前收工。
     *
     * 现在把"一轮 pass"（主循环 + 离场门禁 + 终审 + 建议处置）包进循环：只要还有活
     * （待办任务 / 未处置建议）且预算还够，就再开一轮 pass，把终审给的动作真跑掉，
     * 而不是先停下来等人。挡死循环的只有两条，而且都不是门禁——
     * 预算是硬上限，REVIEW_REENTRY_LIMIT 只是"连唤 3 次都不动就按真因收口"的防呆。
     *
     * 注：循环体保持原有缩进（不重排 500 行），diff 可读性优先。
     */
    const REVIEW_REENTRY_LIMIT = 3;
    /**
     * 证据类校验失败的修正次数上限（2026-11-06）。
     *
     * 用户口径是 1-2 次：给模型一次带具体错误的自纠机会，再给一次确认，
     * 第三次还错就不是"没看清"，是"确实改不动"——那时候隔离比继续要预算更诚实。
     */
    const EVIDENCE_REPAIR_LIMIT = 2;
    let reviewPass = 0;
    let reviewReenter = false;
    for (;;) {
    reviewPass += 1;
    reviewReenter = false;
    try {
      let latest = this.db.getBlackboxSession(pid, sessionId)!;
      let main: Record<string, unknown> = {};
      const toolContext = {
        cfg: this.cfg, db: this.db, projectId: pid, sessionId, target: String(session.target || ""),
        values: this.cfg.tools_env.values,
        signal: controller.signal,
        // 特种兵视野：只读图快照（沙箱。/state/graph_snapshot.json）。图本身只由控制面写。
        graphContext: (): Record<string, unknown> => {
          const view = graphContextView(graphState(progress.state.graph)) as unknown as Record<string, unknown>;
          // 身份一句话进上下文：越权结论必须先，带没带登录，这个前提。
          const identity = this.primaryIdentity(progress);
          return identity ? { ...view, identity } : view;
        },
      };
      // Burp 被动扫描：开局替模型启一次审计（失败不阻断），之后每几轮由 harvest 收账。
      await this.armBurpScan(pid, sessionId, progress, toolContext, String(latest.target || session.target || ""));
      observe = async (reason: ObserverReview["reason"], triggerEventId: string, issues: unknown[] = [], detach = false): Promise<Record<string, unknown>> => {
        // detach=true（后台守护）。*不碰 stopReason、不改进程内 progress.state**。
        // 该停的由主循环在安全点根。interrupt 决定，状态由下一轮重新读取。
        const halt = (reasonCode: string, interrupt?: Omit<ObserverInterrupt, "created_at" | "id"> & { id?: string }): void => {
          if (detach) {
            if (interrupt) observerDaemon.push({ id: interrupt.id || reasonCode, kind: interrupt.kind, severity: interrupt.severity, text: interrupt.text, data: interrupt.data });
            return;
          }
          stopReason = reasonCode;
        };
        progress.state.supervision ||= { observerRuns: 0 };
        const version = reviewVersionOf(progress.state);
        let id = observerReviewId(reason, version, issues);
        const reviews = progress.state.supervision.reviews ||= {};
        // 语义版本切换后，存量 review 的 id 与 state_version 都是旧算法算出来的：
        // 按 reason + issues 指纹 + 兼容版本找回，避免同一批问题重排一条审查。
        if (!reviews[id]) {
          const issueFingerprint = reviewIssueFingerprint(issues);
          const legacyKey = Object.keys(reviews).find(key => {
            const candidate = reviews[key];
            return Boolean(candidate && candidate.reason === reason &&
              candidate.status !== "failed" && candidate.failure !== "stale_snapshot_retained_as_history" &&
              versionMatches(candidate.state_version) &&
              reviewIssueFingerprint(candidate.issues) === issueFingerprint);
          });
          if (legacyKey) id = legacyKey;
        }
        let review = reviews[id];
        if (review?.status === "completed" && !review.failure && versionMatches(review.state_version)) return review.result || {};
        if (review?.status === "running") { halt("observer_review_checkpoint_conflict"); return {}; }
        if (review?.status === "failed" && (review.retryable === false || review.attempts >= 2)) {
          stopReason = "observer_review_retry_exhausted"; return {};
        }
        if (!review) {
          review = reviews[id] = { id, reason, trigger_event_id: triggerEventId, session_id: sessionId, state_version: version, status: "pending", created_at: Date.now(), attempts: 0, issues: structuredClone(issues) };
          progress.state.supervision.reviewPending = true;
          const before = expectedCheckpoint;
          const pending = structuredClone(progress.state);
          if (!commitReview(pid, sessionId, before, pending, { kind: "review-pending", text: `Observer 审查已排队：${reason}`, data: { review_id: id, reason, trigger_event_id: triggerEventId, state_version: version, issues } })) {
            halt("observer_review_checkpoint_conflict"); return {};
          }
          if (!detach) progress.state = pending;
        }
        if (overBudget()) { halt(overBudget() as string); return {}; }
        const beforeRunning = expectedCheckpoint;
        const running = structuredClone(progress.state);
        const active = running.supervision!.reviews![id]!;
        active.status = "running"; active.attempts += 1; active.failure = undefined;
        if (!commitReview(pid, sessionId, beforeRunning, running, { kind: "review-running", text: "Observer 审查开始。", data: { review_id: id, attempt: active.attempts, state_version: version } })) {
          halt("observer_review_checkpoint_conflict"); return {};
        }
        if (!detach) progress.state = running;
        latest = this.db.getBlackboxSession(pid, sessionId)!;
        try {
          const observerInput = { ...main, review_request: { review_id: id, reason, state_version: version, issues } };
          const observer = await runBlackboxObserver(modelValues(), latest, candidate, observerInput, controller.signal, budgetView());
          // Do not save the review's old checkpoint snapshot here. The checkpoint may
          // have changed while the Observer was running; the CAS review commit below
          // must see and preserve that newer state.
          addUsage(observer, false);
          controller.signal.throwIfAborted();
          if (!observer || observer.protocol_error || observer.parse_error || !String(observer.review || "").trim()) {
            /**
             * 2026-11-10：这条失败必须自己说明白。
             *
             * 旧写法对所有情况都吐一句"响应为空或协议校验失败"，而这句话把三种完全不同的
             * 故障（空正文 / JSON 截断 / schema 不过）压成一条，事件里也就再没有可诊断的线索。
             * 现场采样 7 次（同一会话、同一出口）：成功 3 次、失败 4 次，其中 3 次是
             * `finding_reviews.0.evidence_ids` 缺失（schema 与提示词自相矛盾），2 次是
             * `Observer decision is required`（可缺省字段被当成必填）。分不清类型就只能瞎加重试。
             */
            const diag = (observer?._diag || {}) as Record<string, unknown>;
            const validation = Array.isArray(observer?.validation_errors) ? (observer!.validation_errors as unknown[]).map(String) : [];
            const message = observer?.protocol_error
              ? `Observer 输出不符合协议：${validation.slice(0, 3).join("；") || "（无明细）"}`
              : observer?.parse_error
                ? `Observer 输出无法解析（${String(observer.empty_reason || diag.finish_reason || "unknown")}；正文 ${Number(diag.content_chars ?? 0)} 字）`
                : "Observer 返回的 review 为空";
            const protocolFailure = new Error(message.slice(0, 600)) as Error & { retryable?: boolean; detail?: Record<string, unknown> };
            // 协议/解析类失败是模型侧抖动，不是"这个会话没救了"：允许一次重来（attempts 上限仍为 2）。
            protocolFailure.retryable = true;
            protocolFailure.detail = {
              kind: observer?.protocol_error ? "protocol" : observer?.parse_error ? "parse" : "empty_review",
              validation_errors: validation.slice(0, 8),
              diag,
              // 解析失败时 summary 就是原始正文；协议失败时拿它的前 400 字看模型到底写了什么结构。
              raw_head: String(observer?.summary || "").slice(0, 400),
            };
            throw protocolFailure;
          }
          // 战术参谋的机械检查：会话已有架构特征信号（全站跳。/ 鉴权墙）时，
          // Observer 一条具体打法都给不出来，就是查账式审查——留痕，便于调参。
          const suggestions = Array.isArray(observer.suggestions) ? observer.suggestions.filter(item => String(item || "").trim()) : [];
          const current = this.db.getBlackboxSession(pid, sessionId)!;
          const currentProgress = new BlackboxProgress(current.checkpoint, { resume: false });
          if (!suggestions.length && (currentProgress.state.anomaly_alert || currentProgress.state.auth_wall_alert)) {
            this.db.addBlackboxEvent(pid, sessionId, "system", "observer-low-signal",
              "Observer 未给出任何具体打法，但会话已有架构特征信号（异常响应/鉴权墙）：本次审查按查账处理，不计战术参谋产出。",
              { anomaly: currentProgress.state.anomaly_alert?.kind, auth_wall: currentProgress.state.auth_wall_alert?.kind });
          }
          currentProgress.state.usage = { ...usage, session_convergences: currentProgress.state.usage?.session_convergences ?? progress.state.usage?.session_convergences };
          if (!versionMatches(version, currentProgress.state)) {
            const stale = structuredClone(currentProgress.state);
            stale.supervision ||= { observerRuns: 0 };
            stale.supervision.reviews ||= {};
            Object.assign(stale.supervision.reviews[id] || (stale.supervision.reviews[id] = active), { status: "completed", result: observer, completed_at: Date.now(), failure: "stale_snapshot_retained_as_history" });
            // 过期审查不能变成永久门禁：按接受度 + 「点名的问题是否已修好」重算，建议一律保留。
            const staleAcceptance = evaluateAcceptance(stale, (current.evidence || []) as Record<string, unknown>[]);
            stale.supervision.acceptance = staleAcceptance;
            // ④ 同一批 issues 的 stale 连续计数：第 3 次起降级放行，切断
            // 「排队→stale→门禁保持→再排队」的空转（现场 warning 级 issue 永不消失）。
            const staleFingerprint = reviewIssueFingerprint(active.issues || []);
            const staleStreak = stale.supervision.lastStaleFingerprint === staleFingerprint
              ? Number(stale.supervision.staleStreak || 0) + 1 : 1;
            stale.supervision.lastStaleFingerprint = staleFingerprint;
            stale.supervision.staleStreak = staleStreak;
            const plan = planStaleReview({
              acceptance: staleAcceptance,
              suggestionCount: suggestions.length,
              reviewIssues: active.issues || [],
              currentIssues: staleAcceptance.issues,
              staleStreak,
            });
            stale.supervision.reviewPending = plan.keepPending;
            if (plan.injectAdvice && !detach) progress.supplement(observer, id);
            if (commitReview(pid, sessionId, current.checkpoint as object, stale, {
              kind: "review-stale",
              text: plan.reason === "stale_degraded" ? "Observer 结果连续第 3 次对应旧状态快照：审查降级，建议保留、门禁放行，不再重复排队。" :
                plan.keepPending ? "Observer 结果对应旧状态快照，但仍有未解决阻塞项，门禁保持。" :
                  plan.reason === "stale_issues_resolved" ? "Observer 结果对应旧状态快照，但它点名的阻塞问题已全部修好：建议保留、门禁重算后放行。" :
                    "Observer 结果对应旧状态快照，建议已保留、门禁已重算。",
              data: { review_id: id, expected: version, actual: reviewVersionOf(stale), verdict: plan.reason, pending: plan.keepPending, blocking: staleAcceptance.blocking_error_count, unhandled_advice: staleAcceptance.unhandled_advice, suggestions: suggestions.length, issues_compared: plan.issuesCompared, stale_streak: staleStreak },
            })) progress.state = stale;
            if (plan.halt) halt("observer_review_stale_snapshot", { kind: "review_stale", severity: "medium", text: "Observer 结果对应旧状态快照，且仍有阻塞项：门禁保持，建议已注入下一轮。" });
            return observer;
          }
          // The material state version still matches. Base the result on the latest
          // stored checkpoint so non-material concurrent updates are not overwritten.
          if (!detach) progress.state = currentProgress.state;
          const completed = structuredClone(progress.state);
          completed.supervision ||= { observerRuns: 0 };
          completed.supervision.observerRuns += 1;
          // 一次正常（不过期）的审查把 stale 欠账清零。
          completed.supervision.staleStreak = 0;
          completed.supervision.lastStaleFingerprint = undefined;
          const finalReview = completed.supervision.reviews![id]!;
          finalReview.status = "completed"; finalReview.result = observer; finalReview.completed_at = Date.now(); finalReview.failure = undefined;
          // 旧算法落盘的 state_version 在这里一次性迁移：之后所有比较都走新语义版本。
          finalReview.state_version = version;
          const summary = String(observer.review).slice(0, 8000);
          if (!detach) { progress.state = completed; progress.supplement(observer, id); }
          // detach：补充建议由 daemon interrupt 在下一轮注入，避免和主循环。progress.state。
          for (const findingReview of (Array.isArray(observer.finding_reviews) ? observer.finding_reviews : []) as Array<{ finding_id: string; status: "reviewed" | "needs_evidence" | "confirmed" | "rejected"; reason: string; evidence_ids: string[] }>) {
            const finding = completed.findings?.[findingReview.finding_id];
            const facts = latest.evidence as Record<string, unknown>[];
            // needs_evidence 本来就没有新证据可引（"证据不足"就是结论），空引用不该被当成噪声丢掉——
            // 丢掉它，候选发现就会永远停在 candidate，验收门永远 TERMINAL_REVIEW_PENDING（冲突 5）。
            const needsCitation = findingReview.status !== "needs_evidence";
            if (!finding || finding.status === "confirmed" || (finding.status === "rejected" && finding.review?.actor === "operator") || (needsCitation && !findingReview.evidence_ids.length) || findingReview.evidence_ids.some(ref => !finding.evidence_ids.includes(ref)) || validateFinding(finding, facts)) continue;
            finding.status = findingReview.status;
            finding.review = { actor: "observer", reason: findingReview.reason, evidence_ids: findingReview.evidence_ids, at: Date.now() };
          }
          const currentAfterResult = this.db.getBlackboxSession(pid, sessionId)!;
          const beforeComplete = currentAfterResult.checkpoint as object;
          const persisted = structuredClone(completed);
          persisted.supervision!.reviewPending = false;
          // 审查成功一次就把失败计数与"不可用"标记清掉：Observer 恢复后门禁也要恢复。
          persisted.supervision!.reviewFailures = 0;
          delete persisted.supervision!.reviewUnavailable;
          const acceptance = evaluateAcceptance(persisted, (currentAfterResult.evidence || []) as Record<string, unknown>[]);
          persisted.supervision!.acceptance = acceptance;
          persisted.supervision!.reviewPending = acceptance.blocking_error_count > 0 || acceptance.unhandled_advice > 0 || acceptance.reason_codes.includes("TERMINAL_REVIEW_PENDING");
          if (reason === "terminal_review" && !persisted.supervision!.reviewPending) persisted.supervision!.terminalReviewVersion = reviewVersionOf(persisted);
          if (!commitReview(pid, sessionId, beforeComplete, persisted, { kind: observer.decision === "finish" ? "review-complete" : "review-result", text: "Observer 审查结果已持久化。", data: { review_id: id, reason, state_version: version, decision: observer.decision || "review", acceptance }, result: { summary, output: { ...observer, review_id: id, state_version: version } } })) {
            halt("observer_review_checkpoint_conflict"); return observer;
          }
          if (!detach) progress.state = persisted;
          if (observer.decision === "pause" || (!observer.decision && observer.should_continue === false)) {
            halt("observer_paused", { kind: "pause_request", severity: "high", text: `Observer 要求暂停：${String(observer.pause_reason || observer.review).slice(0, 400)}；本轮继续，下一轮开头按建议收尾。`, data: { review_id: id } });
            this.db.addBlackboxEvent(pid, sessionId, "observer", "pause", `Observer 请求暂停：${String(observer.pause_reason || observer.review)}`, { review_id: id, reason: observer.pause_reason || observer.review });
          }
          return observer;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          const current = this.db.getBlackboxSession(pid, sessionId)!;
          const failed = structuredClone(new BlackboxProgress(current.checkpoint, { resume: false }).state);
          failed.supervision ||= { observerRuns: 0 };
          const failedReview = failed.supervision.reviews?.[id];
          // An operator pause/cancel interrupts the Observer request. That is not a bad review:
          // recording it as a non-retryable failure permanently locks the session out of further
          // runs ("observer_review_retry_exhausted" on every resume).
          const interrupted = controller.signal.aborted;
          const retryable = (error as Error & { retryable?: boolean }).retryable !== false && !interrupted;
          if (failedReview) {
            failedReview.status = interrupted ? "pending" : "failed";
            // 保留**首次**失败原因：审查失败后主循环会继续并重试，后续重试的报错（常见是"响应为空"）
            // 会盖掉真正的根因（事务写失败/网络错误），诊断就永远看不到第一现场。
            if (!interrupted) failedReview.failure ||= message;
            failedReview.failure_fingerprint = interrupted ? undefined : createHash("sha256").update(message).digest("hex").slice(0, 24);
            failedReview.retryable = retryable;
            failedReview.completed_at = interrupted ? undefined : Date.now();
            // Give the attempt back: nothing was reviewed, so nothing was spent.
            if (interrupted) failedReview.attempts = Math.max(0, Number(failedReview.attempts || 1) - 1);
          }
          failed.supervision.reviewPending = true;
          // Observer 是辅助，不是主循环的必要条件。旧行为：单次审查失败即 halt
          // → 2026-11-02 实跑（8a2b134101b62649）在 39/40 次调用、1 条 finding 时被停成
          // observer_review_failed。现在按次降级：第 1-2 次失败只记 warning 继续跑（下一轮用新快照重试），
          // 连续 3 次视为"审查不可用"——关掉 reviewPending 并让验收放行，主循环继续用现有证据推进。
          const failures = Number(failed.supervision.reviewFailures || 0) + 1;
          failed.supervision.reviewFailures = failures;
          if (failures >= 3) {
            failed.supervision.reviewPending = false;
            failed.supervision.reviewUnavailable = true;
          }
          const failureDetail = (error as Error & { detail?: Record<string, unknown> }).detail;
          if (commitReview(pid, sessionId, current.checkpoint as object, failed, {
            kind: interrupted ? "review-interrupted" : "review-failed",
            text: interrupted ? "Observer 审查被操作员中断，未计入重试，下次运行继续。" : `Observer 审查失败（连续第 ${failures} 次）：${message.slice(0, 300)}`,
            data: { review_id: id, error: message, retryable, interrupted, failure_fingerprint: failedReview?.failure_fingerprint, failures, ...(failureDetail ? { detail: failureDetail } : {}) },
          })) { if (!detach) progress.state = failed; }
          if (interrupted) { halt(overBudget() || "operator_paused"); return {}; }
          if (failures >= 3) {
            // 降级：不要求审查，也不停场。让 models 继续用已有证据推进任务。
            progress.addInterrupts([{
              id: `observer-unavailable:${id}`,
              kind: "observer_unavailable",
              severity: "medium",
              text: `Observer 已连续 ${failures} 次审查失败（${message.slice(0, 160)}），本轮起不再要求审查：按你自己的证据账本继续推进任务，结案标准仍是 context.vuln_gaps 与三条结案口径。不要因为"没有 Observer 背书"就不下结论。`,
              data: { review_id: id, failures, error: message },
            }]);
            this.db.addBlackboxEvent(pid, sessionId, "system", "observer-unavailable",
              `Observer 连续 ${failures} 次审查失败，已降级为"审查不可用"：验收不再等它，主循环继续。`,
              { review_id: id, failures, error: message });
            return {};
          }
          this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
            `Observer 审查第 ${failures} 次失败（${message.slice(0, 200)}）：不停场，下一轮用新快照重试。`,
            { review_id: id, failures, retryable, error: message, ...(failureDetail ? { detail: failureDetail } : {}) });
          return {};
        }
      };
      const supervise = async (event: SupervisionEvent) => {
        const facts = (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[];
        const decision = superviseCheckpoint(progress.state, runBudget, event, facts);
        if (decision.warnings.length) {
          // 文案。warning 码决定（。warning-text.ts）：兜底分支曾无条件宣称"有工具失。。
          // 而实。warnings 可能只是 repairable_task_rejections（任务完成声明被拒，可自纠）。
          const { kind: warningKind, text } = supervisorWarningText(decision.warnings);
          this.db.addBlackboxEvent(pid, sessionId, "system", warningKind, text, { warnings: decision.warnings, coverage: decision.coverage });
        }
        // ── 图巡检：环。/ 分量漂移。00 节点 DFS 是毫秒级，不进异步队列）──
        {
          const graphNow = graphState(progress.state.graph);
          /**
           * 连续无新节点的兜底计数（2026-11-07）。
           *
           * 只在 tool_batch 这一档累计：analysis 事件在工具执行前触发，拿不到本轮 ingest 结果，
           * 用它计数会把"一轮"算成两轮，阈值 3 就名不副实。
           */
          let quietRounds = Number(progress.state.supervision?.graphQuietStreak || 0);
          if (event.kind === "tool_batch") {
            const grew = progress.state.graph_growth_pending === true;
            quietRounds = grew ? 0 : quietRounds + 1;
            progress.state.graph_growth_pending = false;
            progress.state.supervision = { ...(progress.state.supervision || { observerRuns: 0 }), graphQuietStreak: quietRounds };
          }
          /**
           * 采纳判定（2026-11-09，A4）。
           *
           * 欠账期间只要最近打过的端点是建议过的 root 之一，就说明模型听进去了：
           * 清零 + 解锁，别让"催了三轮的同一句话"继续占着焦点。
           * 这一步必须在算新信号之前做，否则刚采纳就会被新的 rounds 覆盖回去。
           */
          const driftBefore = progress.state.graph_drift;
          const recentIds = new Set((progress.state.graphRecent || []).map(String));
          if (driftBefore?.roots?.length && recentIds.size) {
            const suggestedIds = new Set(driftBefore.roots.map(root => endpointNodeId(root)));
            const adopted = [...recentIds].some(id => suggestedIds.has(id));
            if (adopted) {
              releaseFocus(progress.state, driftBefore.task_id || DRIFT_TASK_ID);
              progress.state.graph_drift = undefined;
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-drift-adopted",
                `已按巡检建议打了另一块（${driftBefore.roots.slice(0, 2).join("、")}），漂移欠账清零，焦点解锁。`,
                // `rounds` 是欠账连续轮数（跨批次），`batch_rounds` 才是这一批自己压了几轮——
                // 后者是判断"建议发出后多久被执行"的唯一可比指标（2026-11-10）。
                { roots: driftBefore.roots, rounds: driftBefore.rounds, batch_rounds: driftBefore.batch_rounds });
            }
          }
          const driftState = progress.state.graph_drift;
          // 每 6 轮换一次批：不换就永远吐同 3 条（旧实现的病根）；换太勤则正文天天变，插话去不掉。
          // 第 3 轮已经升级成任务了，不需要靠换批来制造新意——换批是兜底，不是主手段。
          const rotateRoots = Boolean(driftState?.roots?.length) && Number(driftState?.rounds || 0) > 0
            && Number(driftState?.rounds || 0) % 6 === 0;
          const signals = graphSignals(graphNow, progress.state.graphRecent || [], {
            quietRounds,
            // 采纳会清掉 graph_drift（连同它里面的 suggested），所以计数必须回落到
            // 独立账本（2026-11-09，P3）：否则每次采纳后 rank 都从全 0 重排，
            // 批次在两组 URL 之间来回切，每切一次就多一条 graph-signal。
            suggested: driftState?.suggested ?? progress.state.graph_drift_suggested,
            prefer: rotateRoots ? [] : driftState?.roots,
            rotate: rotateRoots,
            // 桶轮转的奇偶 + 鉴权墙冷却都按图轮次算（S2-②③）。
            round: Number(progress.state.graphRound || progress.graphRound || 0),
          });
          if (signals.length) {
            // 漂移欠账。026-10-28）：note.yun 那轮 component_drift 连发 3 次、agent 一次没采纳。
            // 只给"提示"是没牙的，所以这里把 roots 记成欠账，并在第 2 轮起升级。high。
            const drift = signals.find(signal => signal.kind === "component_drift");
            if (drift) {
              const roots = (Array.isArray(drift.data?.roots) ? drift.data!.roots as unknown[] : [])
                .map(String).filter(root => /^https?:\/\//i.test(root) && !/[{}]/.test(root)).slice(0, 3);
              // 桶轮转（S2-③）：计数记在 `host + 一级路径` 上，换批才有"另一片"可换。
              // URL 级计数保留只作兼容（老 checkpoint 里全是 URL 键），不再新增。
              const buckets = (Array.isArray(drift.data?.buckets) ? drift.data!.buckets as unknown[] : [])
                .map(String).filter(Boolean).slice(0, 3);
              const tiers = (Array.isArray(drift.data?.tiers) ? drift.data!.tiers as unknown[] : [])
                .map(String).slice(0, 3);
              // 入口全是模板路径时，信号仍然成立，只是给不出可直接照抄的 URL。
              // 这个标记要落进 checkpoint，面板才不会一直显示上一轮那批老 roots。
              const templateOnly = drift.data?.template_only === true;
              const previous = progress.state.graph_drift;
              const rounds = Number(previous?.rounds || 0) + 1;
              // 建议计数：只涨不落，作为下一轮换批的依据（A2）。
              // 从独立账本继承（P3）：采纳清空 graph_drift 时计数不跟着丢。
              const suggested: Record<string, number> = { ...(previous?.suggested || progress.state.graph_drift_suggested || {}) };
              for (const bucket of buckets) suggested[bucket] = Number(suggested[bucket] || 0) + 1;
              progress.state.graph_drift_suggested = suggested;
              /**
               * 这一批的"在桌轮数"（2026-11-10）。
               *
               * `rounds` 换批不清零，拿它说"这批压了 N 轮"是假数（刚换上来就能显示 40）。
               * roots 集合变了就归 1；只看集合、不看顺序，重排不算换批。
               */
              const batchKey = [...roots].sort().join("|");
              const previousKey = [...(previous?.roots || [])].sort().join("|");
              const batchRounds = previous && previousKey === batchKey
                ? Number(previous.batch_rounds || 1) + 1
                : 1;
              progress.state.graph_drift = {
                rounds, roots, last_at: Date.now(), suggested, batch_rounds: batchRounds,
                ...(buckets.length ? { buckets } : {}),
                ...(tiers.length ? { tiers } : {}),
                ...(templateOnly ? { degraded: "template_only" as const } : {}),
              };
              if (rounds >= 2 && roots.length) {
                drift.severity = "high";
                // 轮次绝不拼进 text：旧写法让 id+text 每轮都变，addInterrupts 按 (id,text)
                // 去重完全失效，现场同一句提醒写了 77 条 graph-signal 事件。
                drift.text += `下一轮至少发 1 条打这些 URL 的请求：`
                  + roots.map(root => `http.request GET ${root}`).join("。")
                  + "。这些 URL 是图里还没证伪的面。";
                drift.data = { ...(drift.data || {}), repeat_count: rounds };
              }
              // 升级阶梯（A4）：第 3 轮把 roots 落成真任务，第 6 轮上强锁。
              // 只提示不动调度，现场就是 129 轮空转——所以这里必须有"代码替模型做决定"的那一档。
              if (rounds >= 3 && roots.length) this.escalateGraphDrift(pid, sessionId, progress, roots, rounds, tiers);
            } else {
              // 已经没有漂移了（说明 agent 真的去打了别的块）：欠账清零，别永久记账。
              if (progress.state.graph_drift) progress.state.graph_drift = undefined;
            }
            progress.addInterrupts(signals.map(signal => ({
              id: `graph:${signal.kind}:${signal.data?.cycle ? String((signal.data.cycle as string[]).join("|")).slice(0, 80) : signal.kind}`.slice(0, 120),
              kind: signal.kind, severity: signal.severity, text: signal.text, data: signal.data,
              /**
               * 指纹只看语义，不看数字、也不看顺序（2026-11-09，A3）。
               * ① 正文里的"图裂成 62 块 / 另有 35 块"每轮都在变，只看 text 判新旧就会
               *    每轮都算新插话——现场 13 分钟写了 7 条同义 graph-signal。
               * ② roots 排序后参与指纹：换批是换内容，重排不是。否则 rankDriftRoots
               *    在计数变化时换个顺序，就又是一条"新插话"。
               */
              fingerprint: graphSignalFingerprint(signal),
            })));
            /**
             * 事件门禁改看**语义指纹**，不看 addInterrupts 的返回值（2026-11-09，P2）。
             *
             * `added > 0` 并不等于"图的情况变了"：插话池只有 12 格，`graph:*` 被
             * `focus-auto-handoff:${round}` 这类一次性条目挤出后，下一轮重新插入也算新增。
             * 现场两条正文完全相同（301 字符、同一批 roots）的信号就是这样重复落账的。
             *
             * 现在两种变化才写事件：
             *   ① 拓扑信号的指纹集合变了（换批 / 环路出现 / 漂移消失）；
             *   ② "连续无新节点"首次出现（它由轮次计数驱动，重复出现没有新信息，
             *      后续只在每 20 轮的汇总里带一次）。
             */
            const driftRounds = Number(progress.state.graph_drift?.rounds || 0);
            // 汇总按**图轮次**计（2026-11-10）：driftRounds 会在采纳时清零，用它算间隔的话，
            // 勤采纳的会话永远到不了 20 轮，汇总一条都不会留。
            const gate = graphSignalGate(progress.state.graph_signal_gate, signals, {
              graphRound: Number(progress.state.graphRound || progress.graphRound || 0),
            });
            if (gate.emit) {
              progress.state.graph_signal_gate = gate.gate;
              // 轮数只能进 data（2026-11-09）：拼进 text 会让 addInterrupts 的 (id,text) 去重每轮失效，
              // 现场因此连续写出 repeat_count 115/116/117 三条同义插话。
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-signal",
                // 320 而不是 200：S2 的铺面文案带"先确认死活"的判定规则，200 字会把它截断成半句。
                `图巡检：${signals.map(signal => signal.text.slice(0, 320)).join("；")}`,
                { signals: signals.map(signal => ({ kind: signal.kind, severity: signal.severity })), repeat_count: driftRounds,
                  // 汇总说的是"这批压了多久"：`repeat_count` 是欠账连续轮数（跨批次），
                  // `batch_rounds` 才是当前这批自己的年龄（2026-11-10）。
                  batch_rounds: progress.state.graph_drift?.batch_rounds,
                  // 面池构成（2026-11-10，S2-①）：`observed_unprobed` 是可建议的点数，
                  // `unprobed` 是尚未被当成面的数量。两者相差一个数量级就说明口径有问题，
                  // 这条数据是后续"配额 + 桶轮转"的观测基线。
                  pool: poolBreakdown(graphNow, progress.graphRound) });
            }
          } else if (progress.state.graph_signal_gate) {
            /**
             * 漂移/环路都消失了（2026-11-09，P2）：只清拓扑指纹，保留 quiet 账本。
             *
             * 清 `prints` 是为了"图重新裂开、还是同一批 roots"能再出声；
             * 但 quiet 不能一起清（2026-11-10）：清了它，下一轮 `graph_no_new_nodes`
             * 又会被判成"首次出现"，正文与上一条逐字相同——这正是 12 轮里那条
             * 看起来重复的 graph-signal。停摆段号跨复位保留，只有图真长过才换段。
             */
            progress.state.graph_signal_gate = resetGraphSignalGate(progress.state.graph_signal_gate);
          }
        }
        if (decision.action === "pause") {
          stopReason = decision.reasons[0] || "supervisor_paused";
          this.db.addBlackboxEvent(pid, sessionId, "system", "supervisor-pause", "程序监督器发现不可自动恢复的问题，已保存检查点。", decision);
          save();
          return;
        }
        if (decision.action === "observer") {
          save();
          const trigger = this.db.addBlackboxEvent(pid, sessionId, "system", "review-trigger", "监督器要。Observer 审查。", { reasons: decision.reasons, issues: decision.acceptance.issues });
          const reviewReason: ObserverReview["reason"] = decision.acceptance.blocking_error_count ? "validation_failed" : decision.acceptance.all_tasks_terminal ? "terminal_review" : "ordinary";
          const triggerId = String(trigger?.id || `event:${reviewVersionOf(progress.state)}`);
          if (shouldRunObserverSync(reviewReason, observerMode)) {
            await observe(reviewReason, triggerId, decision.acceptance.issues);
            const acceptance = evaluateAcceptance(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
            progress.state.supervision!.acceptance = acceptance;
            if (acceptance.blocking_error_count && !stopReason) {
              /**
               * 这里也要放过证据引用类错误（2026-11-06）。
               *
               * 这条路径在**主循环中途**触发：监督器发现阻塞 → 同步跑 Observer → 仍然阻塞
               * 就立刻把整场停成 state_validation_failed。可证据类错误是模型下一轮能改、
               * 改不动可隔离的——在这里停等于把"离场门禁的修正/隔离"整段绕过去了
               * （实测 e8bdb447acf02283 第 4 轮：隔离刚做完，模型又交了一条坏结案，
               * 当场停成 state_validation_failed）。
               */
              const errors = acceptance.issues.filter(issue => issue.severity === "error");
              const { quarantinable } = partitionBlocking(errors);
              if (quarantinable.length && quarantinable.length === errors.length) {
                this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
                  `本轮有 ${quarantinable.length} 处证据引用问题：交给离场门禁处置（先给模型改，改不动再隔离），此处不停场。`,
                  { targets: quarantinable });
              } else {
                stopReason = "state_validation_failed";
                this.db.addBlackboxEvent(pid, sessionId, "system", "supervisor-pause", "审核后验收校验失败，已保留错误明细。", { reasons: [stopReason], acceptance });
              }
            }
          } else {
            // 后台审查：主循环不等它。审查结果在下一轮开头以 system interrupt 的形式注入上下文。
            const reviewId = observerReviewId(reviewReason, reviewVersionOf(progress.state), decision.acceptance.issues);
            const queued = observerDaemon.submit({
              id: reviewId,
              run: async (): Promise<ObserverInterrupt[]> => {
                const result = await observe(reviewReason, triggerId, decision.acceptance.issues, true);
                const suggestions = Array.isArray(result?.suggestions) ? result.suggestions.map(item => String(item || "")).filter(Boolean).slice(0, 4) : [];
                // 结构化 next_steps（工具 + 目标 + 参数）才是 Observer 最有执行价值的输出，
                // 异步模式原本只丢了 suggestions 文本、把 next_steps 整个吞掉，等于把最该做的动作藏起来了。
                // 这里把它一并带进 interrupt 的 data 与 text，下一轮 Agent 才能直接照抄执行。
                const nextSteps = Array.isArray(result?.next_steps) ? (result!.next_steps as Array<Record<string, unknown>>).slice(0, 4) : [];
                const stepLines = nextSteps.map(step => {
                  const tool = String(step.tool || "").trim();
                  const target = String(step.target || "").trim();
                  const why = String(step.why || "").trim();
                  const input = step.input && typeof step.input === "object" ? JSON.stringify(step.input as Record<string, unknown>) : "";
                  return tool ? `用 ${tool}${target ? ` 打 ${target}` : ""}${input ? ` input=${input}` : ""}${why ? `（${why}）` : ""}` : `缺口：${why || target || "Observer 未说明"}`;
                });
                const interrupts: ObserverInterrupt[] = [];
                if (suggestions.length || stepLines.length) {
                  interrupts.push({
                    id: reviewId, kind: "advice", severity: "high", created_at: Date.now(),
                    text: `Observer 建议（${reviewReason}）：${[...suggestions, ...stepLines].join("；")}`.slice(0, 1200),
                    data: { review_id: reviewId, reason: reviewReason, suggestions, next_steps: nextSteps },
                  });
                }
                return interrupts;
              },
            });
            this.db.addBlackboxEvent(pid, sessionId, "system", "review-dispatched",
              queued ? "Observer 审查已转入后台守护进程，主循环继续执行。" : "后台已有同快照审查在排队，跳过重复派发。",
              { review_id: reviewId, reason: reviewReason, mode: observerMode, daemon: observerDaemon.snapshot() });
          }
        }
        if (stopReason === "observer_paused") save();
        else save();
      };
      // Resume a persisted required review before allowing a new Main Agent turn to
      // mutate the state it was created to inspect.
      // 兼容性比对在 versionMatches 里完成（旧版 state_version 用旧算法重算），不再按字符串相等。
      // A process killed mid-review leaves its row in "running". Nothing owns that row any more,
      // so treat it as pending here instead of refusing every later run with a CAS conflict.
      const staleRunning = Object.values(progress.state.supervision?.reviews || {}).filter(review => review.status === "running" ||
        // Older builds recorded an operator pause inside the Observer as a non-retryable failure,
        // which locked the session out of every later run.
        (review.status === "failed" && !review.retryable && /取消|aborted|cancell?ed|cancel/i.test(String(review.failure || ""))));
      if (staleRunning.length) {
        const revived = structuredClone(progress.state);
        for (const review of Object.values(revived.supervision?.reviews || {})) {
          const stale = review.status === "running" ||
            (review.status === "failed" && !review.retryable && /取消|aborted|cancell?ed|cancel/i.test(String(review.failure || "")));
          if (!stale) continue;
          review.status = "pending";
          review.failure = undefined;
          review.retryable = undefined;
          review.attempts = Math.max(0, Number(review.attempts || 1) - 1);
        }
        if (commitReview(pid, sessionId, expectedCheckpoint, revived, { kind: "review-recovered", text: "发现中断遗留。Observer 审查记录，已重置为待审。", data: { reviews: staleRunning.map(review => review.id) } })) progress.state = revived;
      }
      const exhaustedReview = Object.values(progress.state.supervision?.reviews || {}).find(review =>
        versionMatches(review.state_version) && review.status === "failed" &&
        (review.retryable === false || review.attempts >= 2));
      if (progress.state.supervision?.reviewPending && exhaustedReview) stopReason = "observer_review_retry_exhausted";
      const interruptedReview = Object.values(progress.state.supervision?.reviews || {})
        .filter(review => versionMatches(review.state_version) &&
          (review.status === "pending" || review.status === "running" ||
            (review.status === "failed" && review.retryable !== false && review.attempts < 2)))
        .sort((a, b) => a.created_at - b.created_at)[0];
      if (!stopReason && progress.state.supervision?.reviewPending && interruptedReview) {
        await observe(interruptedReview.reason, interruptedReview.trigger_event_id, interruptedReview.issues || []);
        if (!stopReason && interruptedReview.reason !== "ordinary") {
          const resumedAcceptance = evaluateAcceptance(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
          progress.state.supervision!.acceptance = resumedAcceptance;
          // 证据引用类阻塞不在续跑入口停：它要交给主循环末尾的门禁处置
          // （先给模型修正机会、再隔离）。这里提前停会让 resume 变成
          // "续跑一次、原地停一次"，永远修不好（2026-11-06）。
          if (resumedAcceptance.blocking_error_count && !resumedAcceptance.repairableOnly) {
            const { quarantinable } = partitionBlocking(resumedAcceptance.issues);
            if (!quarantinable.length) stopReason = "validation_failed_review_required";
            else this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
              `续跑发现 ${quarantinable.length} 处证据引用问题：本轮先给模型修正机会，改不动再隔离，不在这里停场。`,
              { targets: quarantinable });
          }
          else if (progress.state.supervision!.reviewPending) {
            // 终审给出的是"接下来怎么。不，就地停下"。只有当它没留下可执行建议。
            // 或者待，预算都已见底时，才把 reviewPending 当停止理由。
            // 2026-10-31 实测（会。3eed109246c6d18c）：4 分钟。run 在终审产出三条主 Agent 没用。
            // 强信号（robots.txt 泄漏 /restapi/*、按 UA 区分。Allow 白名单、burp history 双形态响应）。
            // 立刻 paused。0 个待办一个都没跑。
            const openAdvice = progress.openAdviceCount();
            // 终审"过期"也是同一类事：补跑一回合处置建议会改变状态版本，刚做完的终审因此失效。
            // 门禁仍按旧标记判停。实测会。efe916a2c414f9eb：建议已被采纳（applied），
            // reviewPending 却因终审过期一直为真，5 次调用就 paused。1 个待办未跑。
            const staleTerminal = Object.values(progress.state.supervision?.reviews || {})
              .some(review => review.reason === "terminal_review" && review.status === "completed" && !versionMatches(review.state_version));
            const remaining = budget.toolCalls > 0 ? budget.toolCalls - runUsage().toolCalls : Number.POSITIVE_INFINITY;
            const continues = Number(progress.state.review_continue_count || 0);
            // 还有漏洞任务缺谓词证据（vuln_gaps 非空）本身就是"没干完"：这类续跑不该被建议计数卡死。
            const gaps = vulnerabilityGaps(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[], 4);
            // 门禁全放行（2026-11-06）：不再按"建议条数 / 续跑次数"决定停不停，也不再走
            // `stopReason = required_review_pending`。终审提了新动作就让它真跑掉——这正是
            // 会话最该花时间的地方。真正的终止由主循环里的预算检查负责。
            progress.state.review_continue_count = continues + 1;
            progress.state.supervision!.reviewPending = false;
            const gapText = gaps.length ? `还缺证据：${gaps.map(gap => `${gap.task_id}（${gap.playbook}）${gap.missing.join("、")}`).join("；")}。` : "";
            this.db.addBlackboxEvent(pid, sessionId, "system", "review-continue",
              `终审留下 ${openAdvice} 条未处置建议${staleTerminal ? "、且刚被补跑改写而失效" : ""}，还有 ${progress.pendingCount()} 个待办${gapText ? `，${gapText}` : ""}：先按建议再打一轮，不在这里停（剩余 ${remaining} 次调用）。`,
              { review_id: interruptedReview.id, open_advice: openAdvice, stale_terminal: staleTerminal, pending_tasks: progress.pendingCount(), remaining, gaps });
          }
          else if (interruptedReview.reason === "terminal_review" && resumedAcceptance.ready) {
            const lists = progress.lists();
            stopReason = completionVerdictOf(progress.state.tasks);
          }
        }
      }
      if (!stopReason && versionMatches(progress.state.supervision?.terminalReviewVersion)) {
        const acceptance = evaluateAcceptance(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
        if (acceptance.ready) {
          const lists = progress.lists();
          stopReason = completionVerdictOf(progress.state.tasks);
        }
      }
      // 协议校验失败的连续计数：单次失败只损失一轮，不终。run。
      let protocolErrors = 0;
      /** 零动作回合（一个工具没发、也没有状态变更）的计数：连续两次就停，不许无限空转。 */
      let zeroActionRounds = 0;
      /** 「发了请求但被调度器全拒」的连续轮次：这不是模型的错，单独计数（见下方 scheduler-refused）。 */
      let refusedRounds = 0;
      /**
       * 开局种子自检（2026-11-07）：在模型发第一发请求之前，先确认"带凭证 vs 匿名"的差异。
       *
       * 两发请求的成本，换掉的是"整场会话建在错误前提上"的风险：那次种子里的 cna
       * 让整个阿里云一片 403，系统用 77 分钟、194 次调用、6.64M tokens 去绕一堵自己造的墙。
       *
       * 只在**确实有种子命中该主机**时才跑：没有种子就没有"种子污染"这回事，
       * 也就不该为每场会话凭空多发两发请求。自检失败不阻断开局（探不到 ≠ 种子有问题）。
       */
      {
        const seedTarget = String(session.target || latest.target || "");
        try {
          const host = new URL(seedTarget).host;
          const seed = host ? loadSeedsForHost(new URL(seedTarget).hostname) : null;
          if (host && seed?.cookies.length && progress.requestSeedProbe(host, seedTarget, "会话开局基线：先确认种子是否把目标打成不可访问")) {
            await this.runSeedProbe(pid, sessionId, progress, toolContext);
          }
        } catch {
          // 目标不是合法 URL（还没定到具体资产）时跳过，不阻断开局。
        }
      }
      for (let round = 1; ; round += 1) {
        if (stopReason) break;
        stopReason = overBudget();
        if (stopReason) break;
        if (budget.agentTurns > 0 && runUsage().agentTurns >= budget.agentTurns) { stopReason = "agent_turn_budget_exhausted"; break; }
      // 后台 Observer 的插话落账：写进 checkpoint.interrupts + 事件流，下一。context.system_interrupts 里出现。
      // 插话**不是** advice——不进验收门禁、不产生 pending advice（否则会和主循环抢进度，还会。sweepAdvice 归档）。
      const flushInterrupts = (): void => {
        const interrupts = observerDaemon.drain();
        if (!interrupts.length) return;
        progress.addInterrupts(interrupts.map(item => ({ id: item.id, kind: item.kind, severity: item.severity, text: item.text, data: item.data })));
        for (const item of interrupts) {
          this.db.addBlackboxEvent(pid, sessionId, "system", OBSERVER_INTERRUPT_EVENT, item.text,
            { kind: item.kind, severity: item.severity, interrupt_id: item.id, ...(item.data || {}) });
          if (item.kind === "pause_request" && !stopReason) stopReason = "observer_paused";
        }
        this.db.addBlackboxEvent(pid, sessionId, "system", OBSERVER_INTERRUPT_EVENT,
          `后台 Observer 插话 ${interrupts.length} 条（下一轮上下文已包含）`,
          { rendered: renderInterrupts(interrupts), daemon: observerDaemon.snapshot() });
        save();
      };
        flushInterrupts();
        // 引水（2026-11-05）：站点声明文件还没拿到终态时，由控制面建任务并钉焦点，
        // 不靠模型自觉重试——实测一次 403 就会让这条线永远断掉（18 个业务页整批丢失）。
        this.ensureSiteDeclaration(pid, sessionId, progress, String(latest.target || ""));
        // Burp 被动扫描的新问题：进 context.system_interrupts，模型必须处置（读明细 → 复现或证伪）。
        await this.harvestBurpIssues(pid, sessionId, progress, toolContext, round);
        let madeProgress = false;
        let newFinding = false;
        let queries: EvidenceQuery[] = [];
        let requests: BlackboxToolRequest[] = [];
        usage.agentTurns += 1;
        save();
        /**
         * 每轮把「活的状态」喂给模型。
         *
         * 原来 `latest` 只在 Observer 审查时刷新，于是插话（Burp 被动扫描、协议降级）与当轮证据
         * 要等下一次审查才进上下文。这里只换两个字段：
         *   - checkpoint 用**进程内**的 progress.state（它才是权威，含刚 addInterrupts 的内容）；
         *   - evidence 从库里重读（同一 run 里工具刚落的证据，旧快照里没有，
         *     会导致引用当轮证据的假设被 knownEvidence 判成"证据不存在"而丢掉）。
         * 不整体重读会话：DB 里的 checkpoint 与内存可能因审查/CAS 时序短暂不同步，
         * 整体替换会把审查生命周期搅乱（observer-reliability 用例就是这么挂的）。
         */
        const freshEvidence = this.db.getBlackboxSession(pid, sessionId)?.evidence;
        latest = { ...latest, checkpoint: progress.state, ...(Array.isArray(freshEvidence) ? { evidence: freshEvidence } : {}) };
        main = await runBlackboxMainAgent(modelValues(), latest, candidate, controller.signal, budgetView());
        addUsage(main);
        controller.signal.throwIfAborted();
        if (main.protocol_error || main.parse_error) {
          // 一轮格式不合规不该掐掉整场 run：这次是因为它直接把 stopReason 设成 protocol_error 。break。
          // 7 。turn 里废。1 个，剩下的待办全部作废。改，计次 + 继续"，连。2 次才停。
          protocolErrors += 1;
          // 空正文不是"格式写错了"：agent 层已经换过参数重试一次，到这里说明重试也是空。
          // 把体检报告落进事件，并在下一轮真正改预算，而不是重复同一组参数再空一次。
          const diag = main._diag && typeof main._diag === "object" ? main._diag as Record<string, unknown> : {};
          const emptyReason = String(main.empty_reason || diag.empty_reason || "");
          if (emptyReason === "reasoning_exhausted" || main.truncated) outputBoost = Math.min(2, outputBoost * 1.6);
          this.db.addBlackboxEvent(pid, sessionId, "system", "protocol-error",
            emptyReason
              ? `模型本轮返回空正文（${emptyReason}，finish_reason=${String(diag.finish_reason || "?")}，output_tokens=${Number(diag.output_tokens || 0)}/${Number(diag.requested_max_tokens || 0)}）；本轮动作未执行。`
              : `。Agent 输出校验失败（连续第 ${protocolErrors} 次）；本轮动作未执行。`,
            { ...main, output_boost: outputBoost, empty_reason: emptyReason || undefined });
          // 连续第 2 次：不是"模型坏了"，多半是上下文太长导致输出被截断（实测 output_tokens 顶格）。
          // 这时候停场最亏——2026-11-02 实测会话 b9601629efd1f137 用 12/600 次调用就因两次
          // 协议错误整场结束，7 个待办没跑。改为降级输出要求继续；第 3 次仍失败才停。
          // 空正文单独给指令：缺的是"内容"，不是"格式"，让它写得更短没有用，得让它别把预算烧在推理上。
          if (protocolErrors >= 3) { stopReason = "protocol_error"; break; }
          if (emptyReason) {
            progress.addInterrupts([{
              id: `empty-output:${round}`,
              kind: "protocol_degrade",
              severity: "high",
              text: `${emptyReason === "reasoning_exhausted"
                ? `连续空正文：上一轮 output_tokens 顶到 ${Number(diag.requested_max_tokens || 0)} 上限，推理把预算吃完了。`
                : `连续空正文（${emptyReason}）：模型这一轮没有吐出任何内容。`}本轮已把输出预算抬到 ${Math.round((configuredMaxTokens || 12_000) * outputBoost)}，并关闭 JSON 模式。下一步：不要写推理过程，直接输出 JSON——以 { 开头、以 } 结束；tool_requests 最多 2 条，省略 findings/hypotheses 等大段落。`,
              data: { empty_reason: emptyReason, diag, output_boost: outputBoost },
            }]);
            this.db.addBlackboxEvent(pid, sessionId, "system", "protocol-degrade",
              `空正文（${emptyReason}）：下一轮输出预算 ×${outputBoost.toFixed(2)}，并要求直接输出 JSON。`,
              { empty_reason: emptyReason, diag, output_boost: outputBoost });
          } else if (protocolErrors >= 2) {
            progress.addInterrupts([{
              id: `protocol-degrade:${round}`,
              kind: "protocol_degrade",
              severity: "high",
              text: `连续 ${protocolErrors} 次输出协议校验失败（多半是输出被长度截断）。本轮改成极简输出：summary 只写一句结论（≤120 字），tool_requests 最多 2 条，先保证 JSON 结构完整；不要再输出 findings / task_outcomes / advice_decisions 以外的大段文字。`,
              data: { protocol_errors: protocolErrors, mode: "minimal" },
            }]);
            this.db.addBlackboxEvent(pid, sessionId, "system", "protocol-degrade",
              `连续 ${protocolErrors} 次协议失败：下一轮切极简输出（summary 一句话 + ≤2 条 tool_requests）。`,
              { protocol_errors: protocolErrors });
          }
          continue;
        }
        protocolErrors = 0;
        // 成功一轮就收回放大系数：预算是稀缺资源，不能因为一次空输出整场都用双倍。
        if (outputBoost > 1) {
          outputBoost = 1;
          if (main._recovered) {
            this.db.addBlackboxEvent(pid, sessionId, "system", "protocol-note",
              `上一轮空正文/截断已通过降级重试恢复（${String(main._recovered_kind || "truncated")}），输出预算回到常规值。`,
              { recovered: String(main._recovered_kind || "truncated"), diag: main._diag });
          }
        }
        const allEvidence = (latest.evidence || []) as Record<string, unknown>[];
        // A single malformed item is reported and skipped; it must not void the whole round.
        type DropReceipt = { field: string; index: number; message: string; tool?: string; dropped_keys?: string[]; allowed_keys?: string[]; example?: Record<string, unknown>; hint?: string };
        const droppedItems = Array.isArray(main._dropped) ? main._dropped as DropReceipt[] : [];
        if (droppedItems.length) {
          // R3：不要只，格式无效"。把该工具允许的。+ 一条可照抄的示例一起写进回执与下一轮上下文—。
          // 实测里模型因为只收到"Unrecognized key(s)"，连着三轮写同一批错键，三条请求一次都没发出。
          const hints = droppedItems.map(item => String(item.hint || "")).filter(Boolean);
          const text = `本轮有 ${droppedItems.length} 个条目格式无效，已忽略并继续执行其余动作${hints.length ? ` 纠错：${[...new Set(hints)].slice(0, 2).join("；")}` : ""}`;
          this.db.addBlackboxEvent(pid, sessionId, "system", "protocol-warning", text, { dropped: droppedItems.slice(0, 20) });
          progress.state.drop_receipts = droppedItems.slice(0, 10);
          save();
        } else if (progress.state.drop_receipts?.length) {
          // 本轮没有再被丢弃：清掉旧回执，避免上下文里长期挂着过期教学。
          progress.state.drop_receipts = [];
        }
        // 。schema 摘掉的键（请求照跑）：单独记一。note，不计入 _dropped。
        // 2026-10-28：strict 时代这是"整条请求消失"，如今只，这几个键没生。。
        // 。*必须让模型看。*，否则等于同一个坑换个静默方式复发。
        type IgnoredReceipt = { field: string; index: number; tool: string; keys: string[]; valid_keys: string[]; hint: string };
        const ignoredItems = Array.isArray(main._ignored) ? main._ignored as IgnoredReceipt[] : [];
        if (ignoredItems.length) {
          const ignoredLines = ignoredItems.map(item => `${item.tool || "该工具"} 忽略了键 ${item.keys.join("/")}（可用：${item.valid_keys.join(", ")}）`);
          this.db.addBlackboxEvent(pid, sessionId, "system", "protocol-note",
            `本轮 ${ignoredItems.length} 条请求带了未登记的键，已摘掉后照常执行：${[...new Set(ignoredLines)].slice(0, 3).join("；")}`,
            { ignored: ignoredItems.slice(0, 10) });
          progress.state.ignored_keys = ignoredItems.slice(0, 8);
          save();
        } else if (progress.state.ignored_keys?.length) {
          progress.state.ignored_keys = [];
        }
        // WAF 战例入库：本轮回报的绕过记录立刻写库——同一轮后续迭代就能在上下文里看到。
        // 下一场会话（甚至别的项目打同一厂商的墙）也能直接复用。
        this.recordWafVictories(pid, sessionId, main, String(latest.target || ""), progress);
        // 工具缺口：模型说"缺什么能，就落成事。+ 回灌上下文，下一轮不再重复报。
        this.recordToolGaps(pid, sessionId, progress, main);
        const knownEvidence = new Set(allEvidence.map(item => String(item.id)));
        const knownTasks = new Set([...Object.keys(progress.state.tasks), ...(main.required_tasks as Array<string | { id: string }>).map(t => typeof t === "string" ? t : t.id)]);
        const hypotheses = (main.hypotheses as Array<{ evidence_ids: string[] }>);
        const invalidHypotheses = hypotheses.filter(h => h.evidence_ids.some(id => !knownEvidence.has(id)));
        if (invalidHypotheses.length) {
          main.hypotheses = hypotheses.filter(h => !invalidHypotheses.includes(h));
          this.db.addBlackboxEvent(pid, sessionId, "system", "hypothesis-rejected", `已忽。${invalidHypotheses.length} 个引用不存在证据的假设。`, { count: invalidHypotheses.length });
        }
        const mergeLogBefore = (progress.state.planMergeLog || []).length;
        madeProgress = progress.merge(main, allEvidence);
        // 语义重复被自动吞噬：记事件而不是记错误（旧行为。reject 一。task_duplicate，卡验收）。
        const mergedNow = (progress.state.planMergeLog || []).slice(mergeLogBefore);
        if (mergedNow.length) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "task-merged",
            `${mergedNow.length} 条重复任务已并入既有任务（不再阻塞验收）：${mergedNow.map(item => `${item.dropped}→${item.into}`).join("、")}`,
            { merged: mergedNow, note: "改契约请直接更新被并入的任务；新 id 已记为别。" });
        }
        // 建议兜底：漏处置的建议由代码归档为「未采纳」，绝不为一条建议掐掉整场 run。
        // 连续两轮漏写才会归档，所以模型仍有一整轮机会；本轮已经把请求投给建议指向的任务时
        // 不归档——那是"行动了但还没写处置"，归档掉反而让焦点锁失去让位依据（冲突 1）。
        const pressedTasks = new Set<string>();
        for (const item of Array.isArray(main.tool_requests) ? main.tool_requests : []) {
          const rawId = typeof (item as { task_id?: unknown })?.task_id === "string" ? String((item as { task_id?: string }).task_id).trim() : "";
          const resolved = rawId ? progress.resolveTaskId(rawId) : "";
          if (resolved) pressedTasks.add(resolved);
        }
        const sweptAdvice = progress.sweepAdvice({ salvaged: Array.isArray(main._salvaged_advice_ids) ? main._salvaged_advice_ids as string[] : [], actedTasks: pressedTasks });
        if (sweptAdvice.length) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "advice-auto-skip",
            `${sweptAdvice.length} 条建议未被处置，已按「未采纳」自动归档（不阻塞会话）。`,
            { advice_ids: sweptAdvice, auto_skipped: true, misses: sweptAdvice.map(id => progress.state.advice?.[id]?.misses || 0) });
        }
        queries = main.evidence_queries as EvidenceQuery[];
        for (const finding of main.findings as Finding[]) {
          const error = validateFinding(finding, allEvidence);
          if (error) { this.db.addBlackboxEvent(pid, sessionId, "system", "finding-rejected", error, { finding_id: finding.id }); continue; }
          progress.state.findings ||= {};
          // Reviewed versions are immutable; corrections must use a new candidate ID.
          if (!progress.state.findings[finding.id]) {
            progress.state.findings[finding.id] = { ...finding, status: "candidate" };
            this.db.addBlackboxEvidence(pid, sessionId, { kind: "candidate-finding", source: "main-agent", summary: finding.title, data: finding });
            madeProgress = true;
            newFinding = true;
          }
        }
        progress.state.retrievedEvidence = queryEvidence(allEvidence, queries);
        if (queries.length) this.db.addBlackboxEvent(pid, sessionId, "system", "evidence-query", "历史证据查询已完成；结果供下一轮读取。", { queries, evidence_ids: progress.state.retrievedEvidence.map(e => e.id), limit: 100 });
        // auto-repaired 审计事件（2026-11-07）：结案引用由控制面回填，必须留一条可检索的事件。
        // 用自增 seq 做游标：resume、同毫秒、日志截断都不会重复落账或漏写。
        {
          const log = progress.state.outcomeAutoRepairs || [];
          const cursor = Number(progress.state.outcomeAutoRepairsEmittedSeq || 0);
          const fresh = log.filter(entry => entry.seq > cursor);
          if (fresh.length) {
            const heuristic = fresh.filter(entry => !entry.matched).length;
            this.db.addBlackboxEvent(pid, sessionId, "system", "auto-repaired",
              `控制面自动补上 ${fresh.length} 条结案证据引用（${fresh.map(entry => entry.task_id).join("、")}）：`
              + `${fresh.length - heuristic} 条按关键词命中回填，${heuristic} 条为启发式补齐需人工复核。`,
              { repairs: fresh.map(entry => ({ task_id: entry.task_id, evidence_ids: entry.ids,
                rule: entry.matched ? "auto_backfill:related" : "auto_backfill:heuristic_needs_review",
                basis: entry.basis, at: entry.at })) });
            progress.state.outcomeAutoRepairsEmittedSeq = Math.max(...fresh.map(entry => entry.seq));
          }
        }
        // ② 背压审计（2026-11-07）：簿满改为排队而不是打回，这里留一条可检索事件。
        // 同样用自增 seq 做游标，resume / 同毫秒不会重复落账。
        {
          const seq = Number(progress.state.backlog_deferred_seq || 0);
          const cursor = Number(progress.state.backlog_deferred_emitted_seq || 0);
          if (seq > cursor) {
            const queued = (progress.state.backlog_deferred || [])
              .map(entry => String(entry.spec?.id || "")).filter(Boolean);
            this.db.addBlackboxEvent(pid, sessionId, "system", "backlog-deferred",
              `任务簿已满：${queued.length} 条新任务改为排队（${queued.slice(-3).join("、")}），`
              + `簿子腾出空位会自动入簿，本轮不判协议错误。`,
              { queued, seq, cursor });
            progress.state.backlog_deferred_emitted_seq = seq;
          }
        }
        if (progress.state.validationErrors?.length) {
          // 缺陷 3/7：结构化信封「字段 / 原因 / 该写什么 / 可用 id」一次给全。
          // 2026-11-07 补：信封以前只放在事件的 data 里，而模型读的是事件正文，
          // 于是 31/40 轮都在重复同一批被拒条目。现在正文就是一份可直接照抄的填空清单。
          const envelopes = Object.entries(progress.state.taskOutcomeResults || {})
            .filter(([, record]) => record.status === "rejected")
            .flatMap(([task, record]) => (record.issues || []).map(issue => ({
              error_type: errorTypeForField("task_outcomes"),
              dropped_field: "task_outcomes",
              task_id: task,
              reason: issue.code,
              hint: String(issue.detail || issue.rule || issue.message || "").slice(0, 500),
              ...(issue.valid_ids?.length ? { valid_ids: issue.valid_ids.slice(0, 6) } : {}),
            })))
            .slice(0, 8);
          const lines = envelopes.slice(0, 6).map((env, index) =>
            `${index + 1}. [${env.dropped_field}] ${env.task_id} · ${env.reason}：${env.hint}`
            + (env.valid_ids?.length ? ` 可用 id：${env.valid_ids.join("、")}` : ""));
          const other = progress.actionableTransitionErrors().slice(0, 6);
          const idle = (progress.state.validationErrors || []).length - other.length;
          const text = `本轮 ${progress.state.validationErrors.length} 条校验未通过；逐条按下面的信封改，不要重写其它条目：\n`
            + (lines.length ? `${lines.join("\n")}\n` : "")
            + (other.length ? `待办码：${other.join("、")}。` : "")
            // 不可修的那些要点明"别管"，否则模型会继续拿它们当 KPI（旧版把全量塞进待办码，
            // 实测每轮把 49 条 task_outcomes 重放一遍）。只报数，不列码，避免又变成新的待办。
            + (idle > 0 ? `另有 ${idle} 条历史账本记录（任务已终态/建议已处置）无法再修，已转死信队列，本轮不要为它们改任何条目。` : "");
          this.db.addBlackboxEvent(pid, sessionId, "system", "transition-rejected", text.slice(0, 4000), {
            errors: progress.state.validationErrors,
            actionable: other,
            idle,
            task_outcomes: progress.state.taskOutcomeResults,
            envelopes,
          });
        }
        // 已终态任务被重交结案：聚合说明一次，别让模型以为"再改一版就能过"。
        {
          const replayed = progress.state.taskOutcomeSkipped || [];
          if (replayed.length) {
            const ids = [...new Set(replayed.map(entry => entry.task_id))];
            this.db.addBlackboxEvent(pid, sessionId, "system", "task-outcome-replayed",
              `本轮 ${replayed.length} 条结案指向**已终态**任务（${ids.slice(0, 6).join("、")}${ids.length > 6 ? ` 等 ${ids.length} 条` : ""}），已按重复提交忽略：`
                + `终态（blocked/failed）不可重开，重交不会改判、也不会补证据；要继续就在新任务上做。`,
              { task_ids: ids, count: replayed.length, statuses: replayed.map(entry => entry.status) });
            progress.state.taskOutcomeSkipped = [];
          }
        }
        save();
        const mainSummary = String(main.summary || "。Agent 已完成本轮分析。").slice(0, 8000);
        this.db.addBlackboxEvent(pid, sessionId, "agent", "analysis", mainSummary, { ...main, iteration: round, advice_decision_results: progress.state.adviceDecisionResults });
        this.db.addBlackboxEvidence(pid, sessionId, { kind: "agent-analysis", source: "main-agent", summary: mainSummary, confidence: "medium", data: { ...main, iteration: round, advice_decision_results: progress.state.adviceDecisionResults } });
        const rawRequests = (Array.isArray(main.tool_requests) ? main.tool_requests : [])
          .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object" && !Array.isArray(item)));
        // Requests that cannot be attributed to a declared task are skipped one by one, with a
        // reason the model can act on. The rest of the batch still runs.
        const rejectedRequests: FocusRejection[] = [];
        requests = [];
        // 强制焦点不再用轮数定时器释放（那会让 agent 重新散开，违背锚定深挖的初衷）。
        // 焦点只在被锁任务结案（completed/blocked/failed）时由 computeFocus 自动丢弃；
        // 死锁由 focus_convergence 逼出 verdict、被无视时由主循环代码兜底强制 blocked 解决。
        // ② 零进展释放：连续 4 轮没有任何有增益的结果时自动放锁，避免焦点把整场钉死。
        // SPA 缴械 / 主权转移这类硬锁豁免——它们必须逆出结论，放早了等于撤掉设计。
        const noProgress = releaseFocusForNoProgress(progress.state, 4);
        if (noProgress.released) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-release",
            `焦点 ${noProgress.task_id || "-"} 连续 ${noProgress.rounds} 轮无进展，已自动放锁并顺延到下一任务（硬锁豁免未生效）。`,
            { ...noProgress });
        }
        const focusForMerge = rules.focus_lock.on ? computeFocus(progress.state) : undefined;
        // 锁定任务已终态：显式清掉过期的 forced_focus 字段，避免留存误导（焦点已顺延到下一任务）。
        releaseFocusIfReleased(progress.state);
        const mergedTaskIds: Array<{ tool: string; from: string; to: string }> = [];
        for (const item of rawRequests) {
          const tool = canonicalTool(item.tool ?? (item as { name?: unknown }).name);
          const rawTaskId = typeof item.task_id === "string" ? item.task_id.trim() : "";
          // 别名先解析：模型可能用上一轮的。id 指同一件事（见 task-fingerprint.ts）。
          const rawResolved = rawTaskId ? progress.resolveTaskId(rawTaskId) : "";
          if (!tool) { rejectedRequests.push({ tool: "", task_id: rawResolved || undefined, reason: "缺少工具。" }); continue; }
          if (!rawResolved) { rejectedRequests.push({ tool, reason: "缺少 task_id：工具请求必须归属于已声明任。" }); continue; }
          /**
           * 未登记的 task_id 不再直接拒收。
           *
           * 2026-10-31 实测：模型习惯用 `T1`/`T2`/`T_SPA_xxx` 这类短名指代它正在做的事。
           * 但只要这个名字没进任务簿，整条请求就被判"不在已声明任务中"——一。run 。
           * 3 条请求全废、零点放行，然后 stalled。有焦点任务时把请求归到焦点任务上：
           * 动作是模型想做的，账本记账写，归并"，比空转强。
           */
          let taskId = rawResolved;
          if (!knownTasks.has(taskId)) {
            // 显式哨兵（unknown/none/…）表示"我不知道该归哪个任务"：跳过，不要瞎挂。
            const sentinel = /^(unknown|none|null|undefined|n\/?a|tbd|todo)$/i.test(taskId);
            if (!sentinel && focusForMerge?.task_id) {
              mergedTaskIds.push({ tool, from: taskId, to: focusForMerge.task_id });
              taskId = focusForMerge.task_id;
            } else {
              rejectedRequests.push({ tool, task_id: taskId, reason: "task_id 不在已声明任务中（当前也没有焦点任务可归并）" });
              continue;
            }
          }
          requests.push({ ...(item as unknown as BlackboxToolRequest), tool, task_id: taskId });
        }
        if (mergedTaskIds.length) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "task-id-merged",
            `未登记的 task_id 已归并到焦点任务：${mergedTaskIds.map(entry => `${entry.from}→${entry.to}`).join("、")}。`,
            { merged: mergedTaskIds.slice(0, 20), focus_task_id: focusForMerge?.task_id });
        }
        // 焦点锁：控制面只认一个任务，其余请求当场拒收（指令见 focus.ts；模型在 System Prompt 里也收到同一句）。
        const focusChoice = focusForMerge;
        // 溢出候选按任务分组保留**原始请求对象**（applyFocusLock 的 rejected 只有 tool/task_id，
        // 重建请求会丢掉 input/headers，执行出来是另一条请求）。
        const batchByTask = new Map<string, BlackboxToolRequest[]>();
        for (const request of requests) {
          const id = progress.resolveTaskId(String(request.task_id || ""));
          if (!id) continue;
          const bucket = batchByTask.get(id);
          if (bucket) bucket.push(request); else batchByTask.set(id, [request]);
        }
        // 改法 1（2026-11-05）：拒收不只是"拒"，还要带上"另一条任务叫什么、下一轮怎么合法地转过去"。
        // 实测表明模型被拒后不会自己重排计划，只会回焦点打同一发，所以信息必须随拒收回传。
        const focusLocked = applyFocusLock(focusChoice, requests, id => progress.resolveTaskId(id),
          id => {
            const task = progress.state.tasks[id];
            return task ? { target: task.target, purpose: task.purpose, status: String(task.status || "") } : undefined;
          });
        const focusRejected = focusLocked.rejected;
        if (focusRejected.length) rejectedRequests.push(...focusRejected);
        requests = focusLocked.allowed;
        // 焦点溢出（2026-11-02 三场实跑后补）：整批都被拒时，放行"被拒最多的那一个任务"的最多
        // overflow_per_round 条请求。不改焦点、不改契约，只是不让一整轮 4-5 条计划全废——
        // 实测模型不会因为拒收就改写计划，它只会下轮原样重发（f77278fb6b829eda：3 次 handoff、
        // 9 次 focus-lock、10/40 次调用就停在 required_review_pending）。
        const overflowQuota = Math.max(0, Number(rules.focus_lock.overflow_per_round ?? 2));
        // ② 单一仲裁：四个机制谁有权改状态，一次决策定稿，依据逐条留痕。
        // 放在溢出放行之前，此时 requests 还是焦点锁的原始放行集合，判据才准。
        const arbitration = arbitrateFocus({
          state: progress.state, choice: focusChoice, requests, rejected: focusRejected,
          resolveTaskId: id => progress.resolveTaskId(id), overflowQuota,
        });
        this.db.addBlackboxEvent(pid, sessionId, "system", "focus-arbitration",
          `焦点仲裁：${arbitration.summary}；本轮状态写入方=${arbitration.state_writer}。`,
          { ...arbitration, rejected: focusRejected.slice(0, 12) });
        if (!requests.length && focusRejected.length && overflowQuota > 0) {
          const counts = new Map<string, number>();
          for (const item of focusRejected) {
            const id = progress.resolveTaskId(String(item.task_id || ""));
            if (!id || id === focusChoice?.task_id) continue;
            counts.set(id, (counts.get(id) || 0) + 1);
          }
          const [overflowTask] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0] || [];
          const picked = overflowTask ? (batchByTask.get(overflowTask) || []).slice(0, overflowQuota) : [];
          if (picked.length) {
            requests = picked;
            // 这些请求已经放行，不能再同时记在"拒收"账上（否则事件数与实际执行数对不上）。
            for (const request of picked) {
              const index = rejectedRequests.findIndex(item =>
                item.tool === request.tool && progress.resolveTaskId(String(item.task_id || "")) === overflowTask);
              if (index >= 0) rejectedRequests.splice(index, 1);
            }
            this.db.addBlackboxEvent(pid, sessionId, "system", "focus-overflow",
              `焦点仍在 ${focusChoice?.task_id || "-"}，但整批被拒：溢出放行 ${overflowTask} 的 ${picked.length} 条请求（上限 ${overflowQuota}/轮）。`,
              { focus_task_id: focusChoice?.task_id, overflow_task: overflowTask, allowed: picked.length, quota: overflowQuota, rejected: rejectedRequests.slice(0, 12) });
          }
        }
        if (focusRejected.length) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-lock",
            `焦点锁定在 ${focusChoice?.task_id || "-"}：拒收 ${focusRejected.length} 个其它任务的请求，放行 ${requests.length} 个。`,
            { focus_task_id: focusChoice?.task_id, reason: focusChoice?.reason, detail: focusChoice?.detail, rejected: focusRejected.slice(0, 20) });
        }
        // 焦点申诉（2026-11-02 改）：整批被拒收时不再"只记账不动焦点"。
        //
        // 只记账的版本让 run 空转：实测会话 2b92c7fad2779398 连续三轮"拒收 5/3/4 个、放行 0 个"，
        // 全场只跑 3 次调用，5 个待办没动一下。焦点契约不该等于"模型永远不能改主意"。
        // 现在分两级：第一轮只记账；连续两轮同一目标才真的交接（computeFocus 的 appeal 分支）。
        //
        // 2026-11-02 第二次修（会话 a007634f）：判据原来写的是 `!requests.length`，
        // 但焦点溢出会先把 2 条请求塞回 requests，于是"整批被拒"永远为假、申诉永远不计票——
        // 焦点钉在原地，模型每轮重发同一批，连续 9 次 overflow + 11 次 focus-lock 都没能换焦点。
        // 判据要盯的是"焦点任务本轮拿到几条活"，而不是"放行了几条"。
        const dispatchedToFocusNow = requests.filter(request =>
          progress.resolveTaskId(String(request.task_id || "")) === focusChoice?.task_id).length;
        // 多数派：焦点任务只拿到零星 1 条，而另一个任务被拒了 ≥2 条 —— 模型的实际重心在那边。
        // forced 焦点只认"整批全拒"这种硬证据（代码替模型做的决定不能被弱信号推翻）。
        const rejectedByTask = new Map<string, number>();
        for (const item of focusRejected) {
          const id = progress.resolveTaskId(String(item.task_id || ""));
          if (!id || id === focusChoice?.task_id) continue;
          rejectedByTask.set(id, (rejectedByTask.get(id) || 0) + 1);
        }
        const [rivalTask, rivalCount] = [...rejectedByTask.entries()].sort((a, b) => b[1] - a[1])[0] || [];
        const fullyRejected = dispatchedToFocusNow === 0 && focusRejected.length > 0;
        const majorityElsewhere = dispatchedToFocusNow > 0 && Number(rivalCount || 0) >= 2
          && Number(rivalCount) > dispatchedToFocusNow && focusChoice?.reason !== "forced";
        const appealEligible = (fullyRejected || majorityElsewhere) && Boolean(focusChoice?.task_id);
        // ② 冲突抑制：饥饿接管已经真正写了锁时，申诉本轮只留痕、不再写一次
        // focus_appeal / focus_task_id。四个机制各写各的正是死锁里那组矛盾事件的来源。
        const starvationTookOver = progress.state.forced_focus?.kind === "starvation"
          && arbitration.state_writer === "starvation";
        if (appealEligible && starvationTookOver) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-arbitration-deferred",
            `饥饿接管优先：本轮申诉只记日志不改状态（${arbitration.summary}）。`,
            { from: focusChoice?.task_id || null, to: rivalTask || null, state_writer: arbitration.state_writer,
              decisions: arbitration.decisions, rejected: focusRejected.slice(0, 12) });
        } else if (appealEligible && focusChoice) {
          const votesByTask = new Map<string, number>();
          for (const item of focusRejected) {
            const id = progress.resolveTaskId(String(item.task_id || ""));
            if (!id || id === focusChoice.task_id) continue;
            votesByTask.set(id, (votesByTask.get(id) || 0) + 1);
          }
          const [target, rejected] = [...votesByTask.entries()].sort((a, b) => b[1] - a[1])[0] || [];
          if (target) {
            const previous = progress.state.focus_appeal;
            const streak = previous && previous.task_id === target ? Number(previous.votes || 0) + 1 : 1;
            progress.state.focus_appeal = {
              task_id: target, votes: streak, at: Date.now(),
              // 强制焦点（SPA 缴械）被申诉让位后要留挂起标记：交接那一轮会把 votes 归零，
              // 没有这个标记，下一轮 computeFocus 的 forced 分支又会把焦点抢回去。
              // 只在票数已达让位门槛时才挂起——第 1 轮仍按"不抖焦点"处理，门槛才不会被架空。
              ...(streak >= 2 && focusChoice.reason === "forced" ? { suspended: true, suspended_from: focusChoice.task_id } : {}),
            };
            this.db.addBlackboxEvent(pid, sessionId, "system", "focus-appeal",
              streak >= 2
                ? `连续 ${streak} 轮请求重心都在 ${target}（焦点 ${focusChoice.task_id} 本轮只拿到 ${dispatchedToFocusNow} 条）：下一轮焦点让位给它。`
                : `${fullyRejected ? "本轮全部请求" : `本轮 ${rivalCount} 条请求`}都挂在 ${target} 上、被焦点 ${focusChoice.task_id} 拒收：先记一次，连续两轮同一目标才让位。`,
              { from: focusChoice.task_id, to: target, votes: streak, displaced: fullyRejected ? "all" : "majority", focus_dispatched: dispatchedToFocusNow, rejected });
          }
        } else if (progress.state.focus_appeal) {
          // 本轮通了（或焦点已经动了）：申诉账归零，别让旧票数在后面某轮突然触发让位。
          delete progress.state.focus_appeal;
        }
        /**
         * 改法 1（2026-11-05）：**部分**拒收也必须把"另一条任务"摆到模型面前。
         *
         * 旧逻辑只在"整批全拒"时注入 scheduler-refused；而实盘最常见的形态是
         * "拒 1 条、放行 2 条"（会话 51f8d006a7192f24 的 focus-lock 原文就是这样）——
         * 模型完全不知道自己有一条被拒，也不知道被拒的那条指向 /help，
         * 于是它回到焦点任务把同一发再打一遍（T1 的 `/` 7 次、burp.history 4 次）。
         * 这里不切焦点（避免抖动），只把 id/target/两条合法出路写进下一轮上下文。
         */
        const redirect = focusRejected.map(item => item.next_action).find(Boolean);
        if (redirect && dispatchedToFocusNow > 0 && focusChoice?.task_id && redirect.task_id !== focusChoice.task_id) {
          const focusTask = progress.state.tasks[focusChoice.task_id];
          // 同一条建议每轮都会重写一次（措辞含"本轮"）。旧实现靠"先删同类再插"来避免堆满
          // 12 条插话槽，但那一删一插每次都让 addInterrupts 返回 1（等于永久"新增"）。
          // 2026-11-09（P1）改成稳定 id：重复只累加 repeats、正文原地刷新，不再新占槽位。
          progress.addInterrupts([{
            id: "focus-redirect",
            kind: "focus_redirect",
            severity: "medium",
            text: `【改投建议】${redirect.instruction}`,
            data: {
              focus_task_id: focusChoice.task_id,
              focus_target: focusTask?.target || null,
              next_action: redirect,
              rejected: focusRejected.slice(0, 8),
            },
          }]);
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-redirect",
            `焦点 ${focusChoice.task_id}（${focusTask?.target || "-"}）本轮仍有 ${dispatchedToFocusNow} 条活，同时拒收 ${focusRejected.length} 条：已告知可改投 ${redirect.task_id}（${redirect.target || "-"}）。`,
            { focus_task_id: focusChoice.task_id, focus_target: focusTask?.target || null, next_action: redirect, rejected: focusRejected.slice(0, 12) });
        }
        if (focusChoice?.reason === "appeal") {
          // 让位是真的交接：粘性焦点也挪过去，否则每两轮都要再申诉一次。
          const handedFrom = progress.state.focus_appeal?.suspended_from || "";
          progress.state.focus_task_id = focusChoice.task_id;
          progress.state.focus_appeal = {
            task_id: focusChoice.task_id, votes: 0, at: Date.now(),
            ...(handedFrom ? { suspended: true, suspended_from: handedFrom } : {}),
          };
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-handoff",
            `焦点由申诉交接给 ${focusChoice.task_id}：${focusChoice.detail}`,
            { task_id: focusChoice.task_id, reason: focusChoice.reason, suspended_from: handedFrom || null });
        }
        if (focusChoice?.reason === "advice") {
          // 建议让位不改粘性焦点：建议处置完（accepted/rejected）焦点自动回到原任务。
          this.db.addBlackboxEvent(pid, sessionId, "system", "focus-handoff",
            `焦点因未处置的 Observer 建议让位给 ${focusChoice.task_id}（原焦点 ${progress.state.focus_task_id || "无"}）：先执行或拒绝那条建议，处置完自动回原焦点。`,
            { task_id: focusChoice.task_id, reason: focusChoice.reason, sticky: progress.state.focus_task_id || "" });
        }
        // 微观预算：单任务几轮 / 几次调用 / 连续几轮无进展（。focus-budget.ts）。
        // 触发就拒收本轮全部请求并注入【强制收口】；模型不听，下一轮由代码兜底。blocked。
        if (rules.focus_lock.on && focusChoice) {
          // 本轮真正派给焦点任务的条数（含溢出）：0 表示焦点被无视，不是"打了没收益"。
          const dispatchedToFocus = requests.filter(request => String(request.task_id || "") === focusChoice.task_id).length;
          const decision = this.convergeFocus(pid, sessionId, progress, focusChoice.task_id, rules.focus_lock, dispatchedToFocus);
          if (decision.stopReason) stopReason = decision.stopReason;
          // TP 预检：付不起就别开跑（nuclei 5 TP 不是一次 http 的量级）。
          // 预算也要按任务形态缩放，否则阶梯任务在预检这一关就被判超支，跟上面的缩放自相矛盾。
          const focusLimits = scaleLimitsForTask(rules.focus_lock, progress.state.tasks[focusChoice.task_id]);
          const tp = batchTp(requests, progress.state.usage?.avg_latency_ms);
          const canPay = !tpOverBudget(progress.state, focusChoice.task_id, tp, focusLimits);
          const reason = decision.reject || (canPay ? "" : `战术点数不足：本批请求需要 ${tp} TP，焦点任务 ${focusChoice.task_id} 已用 ${progress.state.focus_usage?.tp || 0}/${focusLimits.max_tp_per_task}。先换便宜的探针（http.request 1 TP），或给结论切焦点。`);
          if (reason) {
            // 收口 / 超预算期间一条都不执行：再打一批只会继续烧同一份预算。
            rejectedRequests.push(...requests.map(request => ({ tool: request.tool, task_id: request.task_id, reason })));
            requests = [];
          } else {
            recordFocusCost(progress.state, focusChoice.task_id, { calls: requests.length, tp });
          }
        }
        // ② 派发有效性不再按「放行条数」记：被收口拒掉、超时、崩溃、跳过（action-skipped）
        // 的请求什么都没做，不该算这个任务有进展。饥饿账迁移到工具**实际返回之后**，
        // 用 executedRequests 回填（见本轮工具循环末尾）。
        if (rejectedRequests.length > focusRejected.length) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "tool-requests-rejected",
            `已忽。${rejectedRequests.length - focusRejected.length} 个无法归属任务的工具请求，其。${requests.length} 个照常执行。`, { rejected: rejectedRequests.slice(0, 20) });
        }
        // 打法优先级决定执行顺序：未授。> 越权 > SQLi > 。> XSS，同优先级保留模型顺序。
        this.watchPostSurface(pid, sessionId, progress, requests);
        // 排序：打法基础。+ 图拓扑加。死胡同罚分（。graph/rank.ts）。
        const ranked = sortRequestsByGraph(requests, {
          graph: graphState(progress.state.graph),
          playbookOf: taskId => progress.state.tasks[taskId]?.playbook,
          playbookPriority,
        });
        requests = ranked.requests;
        if (ranked.scores.some(score => score.reasons.length)) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "graph-rank",
            `批次排序（图加成生效）：${ranked.scores.slice(0, 4).map(score => `${score.tool} ${score.final}。${score.reasons.join("/")}`).join(" 。")}`,
            { scores: ranked.scores.slice(0, 8) });
        }
        progress.enqueue(requests, toolContext.target);
        save();
        if (!requests.length) {
          await supervise({ kind: "analysis", madeProgress, newFinding, evidenceCount: ((latest.evidence || []) as unknown[]).length });
        flushInterrupts();
          if (stopReason) break;
          const lists = progress.lists();
          stopReason = overBudget();
          if (stopReason) break;
          const acceptance = evaluateAcceptance(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
          progress.state.supervision!.acceptance = acceptance;
          if (acceptance.ready && !queries.length) {
            stopReason = completionVerdictOf(progress.state.tasks);
            break;
          }
          // 「零动作」要区分两种：模型不动，还是调度器把它发的动作全拒了。
          // 2026-11-02 实跑（会话 6ee79b87a797904f）：forced 焦点（SPA 缴械）把连续 4 轮共 11 个
          // 请求全拒（focus-lock），旧判据把每一轮都算成"零动作"，第 3 轮直接 stalled 收场——
          // 40 次调用只用了 3 次，而且罚的是模型，错的是调度器。这里分两条路：
          //   ① 模型一个请求都没发（rawRequests=0）→ 老逻辑，注入强制行动，最多 2 次；
          //   ② 模型发了但全被系统拒（focus/dead_end/converge）→ 不记零动作、不累 stall，
          //      把申诉票抬到让位阈值并下一轮重算焦点；连续 3 轮仍被拒才判 scheduler_deadlock。
          if (!madeProgress && !queries.length && progress.pendingCount() > 0 && rawRequests.length > 0) {
            refusedRounds += 1;
            zeroActionRounds = 0;
            progress.state.stalledBatches = 0;
            if (refusedRounds > 3) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
                `连续 ${refusedRounds} 轮请求全部被调度器拒收（焦点/死胡同/收口），仍有 ${progress.pendingCount()} 个待办：判调度死锁。`,
                { pending_tasks: progress.pendingCount(), refused_rounds: refusedRounds, rejected: rejectedRequests.slice(0, 20) });
              stopReason = "scheduler_deadlock";
              break;
            }
            // 抬票：谁被拒得最多、且不是当前焦点，就把它作为让位目标（下一轮 computeFocus 认）。
            const refusedVotes = new Map<string, number>();
            for (const item of rejectedRequests) {
              const id = progress.resolveTaskId(String(item.task_id || ""));
              if (!id || id === focusChoice?.task_id) continue;
              refusedVotes.set(id, (refusedVotes.get(id) || 0) + 1);
            }
            const [refusedTarget, refusedCount] = [...refusedVotes.entries()].sort((a, b) => b[1] - a[1])[0] || [];
            if (refusedTarget) {
              const prevVotes = progress.state.focus_appeal?.task_id === refusedTarget ? Number(progress.state.focus_appeal?.votes || 0) : 0;
              progress.state.focus_appeal = {
                task_id: refusedTarget,
                votes: Math.max(2, prevVotes + 1),
                at: Date.now(),
                ...(focusChoice?.reason === "forced" ? { suspended: true, suspended_from: focusChoice.task_id } : {}),
              };
            }
            const sample = rejectedRequests.slice(0, 3).map(item => `${item.tool}${item.task_id ? `@${item.task_id}` : ""}：${String(item.reason || "").slice(0, 80)}`).join("；");
            progress.addInterrupts([{
              id: `scheduler-refused:${round}`,
              kind: "scheduler_refused",
              severity: "high",
              text: `上一轮你发了 ${rawRequests.length} 个请求，全部被调度器拒收（不是你的格式问题，是控制面的锁）：${sample}。${refusedTarget ? `已把焦点让位目标排到 ${refusedTarget}（累计 ${Math.max(2, refusedCount || 0)} 票），下一轮重算焦点后再打同一批。` : "下一轮重算焦点后再试。"}这不算错误动作，不要改写计划去迎合锁；按原计划重发一轮即可。`,
              data: { round, refused_rounds: refusedRounds, rejected: rejectedRequests.slice(0, 20), appeal_target: refusedTarget || null },
            }]);
            this.db.addBlackboxEvent(pid, sessionId, "system", "scheduler-refused",
              `第 ${refusedRounds} 轮请求全被拒收（${rejectedRequests.length} 条，焦点 ${focusChoice?.task_id || "-"}）：不记零动作，${refusedTarget ? `申诉指向 ${refusedTarget}` : "等待下一轮重算"}`,
              { round, rejected: rejectedRequests.slice(0, 20), appeal_target: refusedTarget || null });
            save();
            continue;
          }
          if (!madeProgress && !queries.length && progress.pendingCount() > 0) {
            zeroActionRounds += 1;
            refusedRounds = 0;
            if (zeroActionRounds <= 2) {
              const gaps = vulnerabilityGaps(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[], 3);
              const gapText = gaps.length
                ? `谓语缺口：${gaps.map(gap => `${gap.task_id}（${gap.playbook}）缺 ${gap.missing.join("、")}`).join("；")}。`
                : "";
              /**
               * 五重惩罚叠加的典型死结（2026-11-02 审计第 7 条）：焦点预算已判"强制收口"，
               * 模型照做只结案不发请求；结案因证据/契约被打回 → 本轮就成了"零动作"，
               * 而零动作的老文案要求"必须发 1 个 tool_request"——两条指令正好相反，
               * 模型发请求被收口拒、结案被审计拒，两边都走不通，只能空转到 stalled。
               * 有收口在生效时，零动作的第一指令必须是"结案"，不是"发请求"。
               */
              const converging = progress.state.focus_convergence;
              const convergingText = converging
                ? `上一轮零动作，但焦点任务 ${converging.task_id} 正处在【强制收口】：本轮**不要发新的探测请求**（会被收口拒收），先按收口指令给它下 verdict——completed/blocked/failed 三选一，并在 task_outcomes 里引用证据；结案被打回时按 reject_envelopes 的提示补字段，不要改去发请求。${gapText}`
                : `上一轮零动作（0 个 tool_request、0 个任务状态变更），但还有 ${progress.pendingCount()} 个待办没跑。${gapText}本轮必须至少发出 1 个 tool_request 去推进其中一个待办；用 advice_decisions 签收建议不算动作，也不要用「规避协议错误」当作不发请求的理由（本轮按极简输出写：summary 一句话 + 1 条 tool_request）。`;
              progress.addInterrupts([{
                // 稳定 id（2026-11-09，P1）：零动作是同一件事，别用轮次把插话池塞满。
                id: "zero-action",
                kind: "zero_action",
                severity: "high",
                text: convergingText,
                data: { round, pending_tasks: progress.pendingCount(), gaps, converging: converging?.task_id || null },
              }]);
              this.db.addBlackboxEvent(pid, sessionId, "system", "zero-action-round",
                `第 ${zeroActionRounds} 次零动作回合：还有 ${progress.pendingCount()} 个待办，已注入${converging ? "结案优先" : "强制行动"}指令。`,
                { round, pending_tasks: progress.pendingCount(), gaps, converging: converging?.task_id || null });
              save();
              continue;
            }
            this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
              `连续 ${zeroActionRounds} 次零动作回合，仍有 ${progress.pendingCount()} 个待办：按停滞处理（stalled）。`,
              { pending_tasks: progress.pendingCount(), zero_action_rounds: zeroActionRounds });
            stopReason = "stalled";
            break;
          }
          // 有进展或本轮确实有请求放行 → 两个"空转"计数都清零。
          // 只清 zeroActionRounds 不清 refusedRounds 是个记账 bug：三场实跑里三次**不连续**的
          // 全拒被累加成"连续 4 轮调度死锁"，直接把还有 30 次预算的 run 判死（f77278fb6b829eda）。
          if (madeProgress || queries.length) { zeroActionRounds = 0; refusedRounds = 0; }
          progress.state.stalledBatches = madeProgress ? 0 : progress.state.stalledBatches + 1;
          save();
          if (progress.state.stalledBatches >= stallLimit && (runUsage().toolCalls >= STALL_CALL_FLOOR || progress.pendingCount() === 0 || main.continue === false)) { stopReason = "stalled"; break; }
          continue;
        }
        stopReason = overBudget();
        if (stopReason) break;
        const remaining = budget.toolCalls > 0 ? Math.max(0, budget.toolCalls - runUsage().toolCalls) : Number.MAX_SAFE_INTEGER;
        // 权重预算：一。katana.crawl 。5 。http.request。按权重装批，装不下的留给下一轮。
        const weightOf = (request: BlackboxToolRequest) => toolWeight(String(request.tool || ""), rules.tool_weights);
        let allowedRequests: BlackboxToolRequest[] = [];
        let plannedWeight = 0;
        for (const request of requests) {
          const weight = weightOf(request);
          // 第一条总是放行，否则极小额度会把整批卡死。
          if (allowedRequests.length && plannedWeight + weight > remaining) break;
          allowedRequests.push(request);
          plannedWeight += weight;
        }
        if (!allowedRequests.length) { stopReason = "tool_budget_exhausted"; break; }
        const batchView = budgetView();
        const allowHeavy = batchView.mode === "full";
        if (!allowHeavy) {
          const heavy = allowedRequests.filter(request => isHeavyTool(String(request.tool || "")));
          if (heavy.length) {
            for (const request of heavy) progress.defer(request, progress.identity(request, toolContext.target), "budget_degraded");
            allowedRequests = allowedRequests.filter(request => !isHeavyTool(String(request.tool || "")));
            this.db.addBlackboxEvent(pid, sessionId, "system", "budget-degraded",
              `预算降级为快速模式（${batchView.reasons.join("；")}）：本批 ${heavy.map(request => String(request.tool || "")).join("、")} 属重型扫描器，已延后；先做轻量步骤。`,
              { mode: batchView.mode, reasons: batchView.reasons, deferred_tools: heavy.map(request => String(request.tool || "")) });
            save();
          }
          if (!allowedRequests.length) {
            // 整批都是重型工具：不开 stage、不烧重试，把控制权交回模型换打法。
            // 连续几批都这样说明它不听劝，按停滞处理而不是空转到轮次上限。
            progress.state.stalledBatches += 1;
            save();
            await supervise({ kind: "tool_batch", madeProgress: false, failed: false, toolCalls: 0, evidenceCount: ((this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as unknown[]).length });
        flushInterrupts();
            if (stopReason) break;
            if (progress.state.stalledBatches >= stallLimit && (runUsage().toolCalls >= STALL_CALL_FLOOR || progress.pendingCount() === 0 || main.continue === false)) { stopReason = "stalled"; break; }
            continue;
          }
        }
        this.db.updateBlackboxSession(pid, sessionId, { phase: "tool_execution" });
        const stageStarted = Date.now();
        let batchFailed = false;
        let batchFailureKind: string | undefined;
        let executed = 0;
        /** ② 真正拿到工具返回结果的请求；饥饿账只认这些，不认"放行过"。 */
        const executedRequests: Array<{ task_id?: string }> = [];
        // ② 异常路径也要能放锁：超时/崩溃若把焦点钉在一条永远跑不完的任务上，
        // 会留下半状态。单次失败不释放（正常重试），连续 2 次才放。
        let focusFailures = 0;
        const noteFocusFailure = (taskId: string, kind: string) => {
          focusFailures += 1;
          const verdict = releaseFocusOnToolFailure(progress.state, taskId, focusFailures, 2);
          if (verdict.released) {
            this.db.addBlackboxEvent(pid, sessionId, "system", "focus-release",
              `工具 ${kind} 连续 ${focusFailures} 次失败/超时，已释放焦点 ${taskId} 的锁，避免半状态死锁。`,
              { task_id: taskId, kind, ...verdict });
          }
        };
        // Work the batch did not have room for stays pending with a reason the model can read,
        // instead of silently disappearing between rounds.
        const deferRest = (from: number, reason: string) => {
          for (const skipped of allowedRequests.slice(from)) {
            const key = progress.identity(skipped, toolContext.target);
            progress.defer(skipped, key, reason);
            this.db.addBlackboxEvent(pid, sessionId, "system", "action-deferred", `未执行（${reason}）：${String(skipped.tool || "")}`, {
              tool: skipped.tool, action_key: key, task_id: skipped.task_id, reason,
            });
          }
        };
        for (let index = 0; index < allowedRequests.length; index += 1) {
          const request = allowedRequests[index]!;
          stopReason = overBudget();
          if (stopReason) { deferRest(index, "budget_exhausted"); break; }
          const remainingMs = stageStarted + stageMs - Date.now();
          if (executed > 0 && remainingMs < blackboxToolMinDurationMs(String(request.tool || ""))) {
            // Starting a slow tool with less than its floor would guarantee a kill and a lost
            // result. An empty batch still attempts one tool so a small stage budget is visible.
            deferRest(index, "stage_timeout");
            break;
          }
          const action = progress.begin(request, toolContext.target, taskRetryLimit, repeatLimit, { allowHeavy });
          if (action.blocked) {
            save();
            this.db.addBlackboxEvent(pid, sessionId, "system", "action-skipped", `停止重复动作：${action.blocked}`, { tool: request.tool, action_key: action.key, task_id: request.task_id });
            continue;
          }
          const weight = weightOf(request);
          usage.toolCalls += weight;
          save();
          if (!getPreflight()) {
          // 第一批工具要跑了：这时候才值得。1-2 秒确认工具真能用（nuclei 没模板、二进制缺失）。
          const report = await runPreflight(this.cfg.tools_env.values, { dataDir: this.cfg.data_dir });
          progress.state.preflight = report;
          this.db.addBlackboxEvent(pid, sessionId, "system", report.ok ? "preflight" : "warning",
            report.ok ? `冒烟校验通过：${report.entries.filter(entry => entry.ok).length} 个工具可用`
              : `冒烟校验发现不可用工具：${report.failed.join(", ")}`,
            { failed: report.failed, entries: report.entries });
        }
        const toolStartedAt = Date.now();
        // ── 历程图拦截：已标死胡同的端点不再打（这是"终结参数空转"的硬手段）──
        // 但只拦**同一个动作**：死胡同记的是"这条请求重复到没变化"，不是"这条路由永远别碰"。
        // 2026-11-02 实测 b9601629efd1f137：`ep:m.ctrip.com/html5` 被封后，T1 想做
        // 匿名/带罐对照（unauth_exposure 谓词的唯一证据来源）被这条规则拒收，任务随即 blocked。
        const graphBefore = graphState(progress.state.graph);
        const requestInput = (request.input || {}) as Record<string, unknown>;
        const requestUrl = String(requestInput.url || "");
        const requestSig = requestUrl ? requestSignature(requestInput, requestUrl, request.tool) : "";
        const deadEndNow: DeadEndVerdict = requestUrl
          ? deadEndVerdict(graphBefore, requestUrl, requestSig, {
            // 控制类动作不该被"这个端点已死"挡住：它们的产出不是对端点的又一次探测，
            // 而是"让后续动作可用"的状态（对照 diff / 浏览器会话）。
            //
            // 2026-11-02 实跑（4f899c3af6c2ac84）的死锁：browser.open 被判 dead_end 拒收 →
            // browser.network 报 "requires a live browser: open the page with browser.open first"
            // → 模型再发 browser.open → 又被 dead_end 拒。一套 SPA 取证工具就此整体不可用，
            // 而拒收理由永远是同一句 dead_end，模型没有任何出口。
            controlTool: deadEndControlTool(request.tool),
            bypass: requestInput.bypass_dead_end === true,
          })
          : { blocked: false };
        const deadEnd = deadEndNow.blocked ? deadEndNow.node : undefined;
        const bypassDeadEnd = requestInput.bypass_dead_end === true;
        if (!deadEndNow.blocked && deadEndNow.exempt && deadEndNow.node) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "dead-end-exempt",
            `${deadEndNow.node.id} 已标死胡同，但本次按「${deadEndNow.exempt === "control_tool" ? "对照实验" : deadEndNow.exempt === "new_signature" ? "换了签名" : "显式 bypass"}」放行 ${request.tool}：不按重打处理。`,
            { node: deadEndNow.node.id, exempt: deadEndNow.exempt, tool: request.tool, task_id: request.task_id, signature: requestSig });
        }
        // ── 装甲拦截。026-10-28）：三条都由控制面直接拒收，不进工具、不烧预。──
        const armor = this.armorGate(progress, request, requestUrl);
        if (armor) {
          this.db.addBlackboxEvidence(pid, sessionId, {
            kind: "tool-error", source: request.tool,
            summary: `装甲拦截 ${request.tool}（${armor.code}：${armor.message}）`.slice(0, 8000),
            confidence: "high",
            data: { rejected: true, error: armor.code, hint: armor.hint, task_id: request.task_id, url: requestUrl },
          });
          this.db.addBlackboxEvent(pid, sessionId, "system", "armor-reject",
            `装甲拦截 ${request.tool} @ ${requestUrl || "(no url)"}：${armor.message}`,
            { code: armor.code, tool: request.tool, task_id: request.task_id, url: requestUrl });
          usage.toolCalls = Math.max(0, usage.toolCalls - weight);
          continue;
        }
        // recon.traffic_diff：差分由控制面算（读的是账本里已有的两行证据），不进工具进程。
        // 模型拿到的必须是 diff_score 而不。raw 列表——否则它只会继续。burp.history 。total 变大。
        const diffProbe = request.tool === "recon.traffic_diff"
          ? this.runTrafficDiff(pid, sessionId, (request.input || {}) as Record<string, unknown>)
          : undefined;
        // ── 零熵熔断（2026-10-28；2026-11-02 修语义冲突）：traffic_diff 两次完全一致，
        //    对"找差异"的任务是零熵，对"未授权访问/鉴权对照"的任务**就是结论本身**——
        //    匿名与带凭证完全一致 = 该入口没有做鉴权区分。把这种任务判 blocked 等于把答案当噪音。
        if (diffProbe && diffProbe.ok && String(diffProbe.data.status || "") === "identical") {
          const streak = Number(progress.state.zero_diff_streak || 0) + 1;
          progress.state.zero_diff_streak = streak;
          const consistencyTask = consistencyPlaybookOf(progress.state.tasks[String(request.task_id || "")]);
          if (streak >= 2 && consistencyTask) {
            // 一致性打法：不改状态，把"这就是结论"推给模型 + 谓词缺口自己会要求它结案。
            progress.state.zero_diff_streak = 0;
            progress.addInterrupts([{
              id: `zero-diff-consistent:${request.task_id || "task"}`,
              kind: "zero_diff_consistent",
              severity: "high",
              text: `${request.task_id || "当前任务"} 连续 ${streak} 次对照完全一致——对「${consistencyTask}」这类打法，一致本身就是结论：该入口没有按身份做区分。不要再换路径找差异，直接按 context.vuln_gaps 的缺口结案（negative 结论也要引用这两条对照证据）。`,
              data: { task_id: request.task_id, streak, playbook: consistencyTask },
            }]);
            this.db.addBlackboxEvent(pid, sessionId, "system", "zero-entropy-consistent",
              `对照连续 ${streak} 次 identical，但任务是「${consistencyTask}」打法：一致性即结论，不判 blocked（旧逻辑会把答案判成零熵）。`,
              { task_id: request.task_id, streak, playbook: consistencyTask });
          } else if (streak >= 2) {
            if (request.task_id) {
              const compared = String((diffProbe.data as Record<string, unknown>).compared_url || "").slice(0, 100);
              progress.state.tasks[request.task_id] = {
                ...settleTask(progress.state.tasks[request.task_id] || {}, {
                  code: "zero_entropy",
                  reason: `零熵熔断：同一条对照连续 ${streak} 次 diff_score=0${compared ? `（${compared}）` : ""}——`
                    + `同身份下换参数不产生任何响应差异，这条路径已经没有新信息可拿。`,
                  by: "control",
                }),
                status: "blocked",
              };
            }
            // 焦点交给下一个还活着的探针任务，而不是继续粘在这条上；没有下一个就释放锁。
            const probe = progress.state.dict_probe;
            const nextProbe = probe?.buckets
              .map(bucket => bucket.probe)
              .find(path => path !== String(diffProbe.data.compared_url || ""));
            if (nextProbe && probe) {
              lockFocus(progress.state, {
                task_id: probe.task_id, kind: "dict_probe", preempt: true,
                note: `零熵熔断后切到 ${nextProbe}`,
              });
            } else {
              releaseFocus(progress.state);
            }
            progress.state.zero_diff_streak = 0;
            this.db.addBlackboxEvent(pid, sessionId, "system", "zero-entropy-stop",
              `零熵熔断：${request.task_id || "当前任务"} 连续 ${streak} 次 diff_score=0 已判 blocked（zero_entropy_diff），焦点转向 ${nextProbe || "下一个任务"}。`,
              { task_id: request.task_id, streak, next_probe: nextProbe || null });
          }
        } else if (diffProbe) {
          progress.state.zero_diff_streak = 0;
        }
        const result = diffProbe
          ? {
            tool: request.tool, ok: diffProbe.ok, summary: diffProbe.summary,
            data: diffProbe.data, artifacts: [] as never[], duration_ms: 0,
          }
          : deadEnd && !bypassDeadEnd
          ? {
            tool: request.tool, ok: false,
            summary: `${request.tool} rejected: ${deadEnd.id} 已在历程图标为死胡同（${deadEnd.properties.note || "同特征响应反复出现"}）；换攻击面：同目录其他端点、换身份、换方法；确需重打时传 input.bypass_dead_end=true`,
            data: { rejected: true, error: "dead_end", graph_node: deadEnd.id, hint: "。context.attack_graph 。dead_ends 。hypotheses，换节点而不是换 payload" },
            artifacts: [], duration_ms: 0,
          }
          : await executeAndRecordBlackboxTool({ ...toolContext, deadline: Math.min(stageStarted + stageMs,
            budget.wallClockMs > 0 ? startedAt + budget.wallClockMs : Infinity) }, request);
          // 死胡同拦截在 desk 里合成结果，绕过。executeAndRecordBlackboxTool，因此原本只写一。
          // 事件、证据账本里没有对应。—。/api/tool-health ，拒绝"数于是永远是 0。这里补账。
          if (deadEnd && !bypassDeadEnd) {
            this.db.addBlackboxEvidence(pid, sessionId, {
              kind: "tool-error",
              source: request.tool,
              summary: `${request.tool} rejected: dead_end ${deadEnd.id}`.slice(0, 8000),
              confidence: "high",
              data: { ok: false, rejected: true, error: "dead_end", tool: request.tool, graph_node: deadEnd.id, task_id: request.task_id, action_key: action.key, duration_ms: 0, billed: false },
            });
            // 硬出路段 3（2026-11-03 兜底）：被拒的这个节点如果还处于第四态
            // （发了包、没拿到状态码），"别再打它"恰好挡住了唯一能把状态补齐的动作。
            // 这里强制派一次补测任务——即使任务簿已满（补测是低优先级、但它是这条路的出口），
            // 并置 retest_attempted，每个节点只强制一次，防止"补测又失败→再派→再失败"。
            this.forceRetestTask(pid, sessionId, progress, deadEnd);
            // 第二次拒收同一死胡同：，还指着这条，的任务收口，并给出图上还活着的替代节点。
            // 只警告不停手是无效的——死胡同的提示模型看得到，任务里。URL 它也在看。
            const rejects = (progress.state.dead_end_rejects ||= {});
            rejects[deadEnd.id] = (rejects[deadEnd.id] || 0) + 1;
            if (rejects[deadEnd.id] === 2) {
              const alive = (Object.values(graphState(progress.state.graph).nodes) as Array<{ id: string; type: string; status: string; properties: { hits?: number } }>)
                .filter(node => node.type === "endpoint" && node.status !== "dead_end" && node.status !== "blocked")
                .sort((a, b) => Number(b.properties.hits || 0) - Number(a.properties.hits || 0))
                .slice(0, 3)
                .map(node => node.id.replace(/^ep:/, "https://"));
              const blockedTaskId = String(request.task_id || "");
              const taskRecord = blockedTaskId ? progress.state.tasks[blockedTaskId] : undefined;
              const taskPlaybook = String((taskRecord as { playbook?: string } | undefined)?.playbook || "");
              // 漏洞确认型任务：谓词还缺证据时不收口。
              // 这类任务要的往往正是"对同一条路由换个身份再打一次"，收口等于把它唯一能拿证据的路堵死
              // （2026-11-02 T1 实测：/html5 被封 → 任务 blocked → unauth_exposure 的对照永远做不成）。
              const taskGap = isVulnPlaybook(taskPlaybook)
                ? evaluateRequirements(taskPlaybook, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[])
                : undefined;
              const keepForVerdict = Boolean(taskGap && taskGap.registered && !taskGap.satisfied);
              if (taskRecord && taskRecord.status === "pending" && !keepForVerdict) {
                progress.state.tasks[blockedTaskId] = {
                  ...settleTask(taskRecord, {
                    code: "dead_end",
                    reason: `攻击图判死胡同：${deadEnd.id} 同特征响应反复出现（${String((deadEnd.properties as { note?: string }).note || "无补充说明")}），`
                      + `且本轮第 ${rejects[deadEnd.id]} 次拒收同一个动作。任务指向的入口已无攻击面，收口。`,
                    by: "control",
                  }),
                  status: "blocked",
                };
              }
              progress.addInterrupts([{
                id: `dead-end-redirect:${deadEnd.id}`,
                kind: "dead_end_redirect",
                severity: "high",
                text: keepForVerdict
                  ? `${deadEnd.id} 已判死胡同，本轮第 2 次拒收同一个动作。但任务 ${request.task_id}（${taskPlaybook}）还缺证据：${(taskGap?.missing || []).join("；")}。任务保持 pending，别收口——换成另一次动作再打：① 换身份/换 Cookie/换 UA（匿名 vs 带罐）；② 换方法或换 body；③ 用 http.diff 显式写 variant 做对照；④ 确需原样重打时传 input.bypass_dead_end=true 并说明理由。`
                  : `${deadEnd.id} 已判死胡同（${deadEnd.properties.note || "同特征响应反复出现"}），本轮第 2 次拒收：任务 ${request.task_id || "-"} 已收口。改打这些还活着的节点：${alive.join("、") || "（图上暂无，先做被动面收集：burp.history / browser.network）"}。`,
                data: { node: deadEnd.id, task_id: request.task_id, alternatives: alive, kept_pending: keepForVerdict, missing: taskGap?.missing || [] },
              }]);
              this.db.addBlackboxEvent(pid, sessionId, "system", "dead-end-redirect",
                keepForVerdict
                  ? `死胡同连拒 ${rejects[deadEnd.id]} 次：${deadEnd.id} 上的任务 ${request.task_id} 仍缺证据（${(taskGap?.missing || []).join("；")}），保持 pending 并给出换动作的四种打法。`
                  : `死胡同连。${rejects[deadEnd.id]} 次：${deadEnd.id} 任务 ${request.task_id || "-"} 收口，替代节。${alive.length} 个。`,
                { node: deadEnd.id, task_id: request.task_id, alternatives: alive, kept_pending: keepForVerdict });
            }
          }
          // 工具执行耗时单独记账：它不进调度预算，但进墙钟总额。
          usage.toolMs = Number(usage.toolMs || 0) + (Date.now() - toolStartedAt);
          // A rejected request never reached the tool: refund the call and do not count it as work.
          const rejected = result.data.rejected === true;
          if (rejected) usage.toolCalls = Math.max(0, usage.toolCalls - weight);
          else { executed += 1; if (!result.data.cancelled && !result.data.timed_out) executedRequests.push(request); }
          if (result.data.cancelled) {
            progress.state.actions[action.key]!.inFlight = false;
            progress.state.tasks[`action:${action.key}`] = { status: "blocked", reason: "interrupted_unknown_outcome" };
            if (request.task_id) {
              progress.state.tasks[request.task_id] = {
                ...settleTask(progress.state.tasks[request.task_id] || {}, {
                  code: "operator_cancelled",
                  reason: `操作员取消了会话，取消时这条任务的 ${String(request.tool || "工具")} 调用还在执行中，`
                    + `结果未知（请求已发出但没有拿回响应）。按"未得结论"收口，不要当成已失败或已完成。`,
                  by: "control",
                }),
                status: "blocked",
              };
            }
            stopReason = overBudget() || "operator_paused";
            save(); break;
          }
          const facts = (this.db.getBlackboxSession(pid, sessionId)!.evidence || []) as Record<string, unknown>[];
          progress.state.endpoints ||= {};
          for (const fact of facts) if (["tool-result", "tool-error"].includes(String(fact.kind))) for (const url of evidenceUrls(fact)) {
            const endpoint = progress.state.endpoints[url] ||= { evidence_ids: [], task_ids: [] };
            const taskId = (fact.data as Record<string, unknown>)?.task_id;
            if (typeof taskId === "string" && !endpoint.task_ids.includes(taskId)) endpoint.task_ids.push(taskId);
            if (!endpoint.evidence_ids.includes(String(fact.id))) endpoint.evidence_ids.push(String(fact.id));
          }
          // ── Agent 历程图：把本次工具结果翻译成节点与边（只吃摘要，不吃 body）──
          {
            const graph = graphState(progress.state.graph);
            const data = result.data as Record<string, unknown>;
            const inputOfRequest = (request.input || {}) as Record<string, unknown>;
            const requester = String(inputOfRequest.url || "");
            // ── 证据归因（2026-11-03）───────────────────────────────────────────────
            // 谁能产出 origin="request" 由 graph/evidence.ts 的归因表决定：只有真发了包的
            // 9 个 response 工具（browser.open / http.request / http.diff / burp.send /
            // recon.http_probe / recon.race_condition …）和 13 个 probe 工具（扫描器类，带
            // status_unknown）。以前这里用 evidenceUrls() 把 data.urls（katana 一次 500 条
            // 外链）整批标成 requested:true —— 图的事实层从那一刻起就是假的。
            const attribution = attributeEvidence({
              tool: request.tool, data, input: inputOfRequest, fallbackUrl: requestUrl,
            });
            // 2026-10-28 修正：发现物，任意工具的结果形，统一抽取（见 graph/extract.ts）。
            // 原来只认 data.urls/data.endpoints，于。recon.js_endpoints 。items、browser.open 。links
            // 全都没进。—。165 次调用之后图。42 个节。37 条边仍然全是 asset→endpoint。
            const discovery = attribution.discovery;
            // 请求签名：判"完全相同的一次重。（note.yun 那轮 43 次调用只。22 个唯一请求）。
            // WAF 墙：412/418/1020 或阻断页指纹（见 graph/extract.ts 。wallOf）。
            const wall = wallOf(data);
            // 路由不存在：与 WAF 墙分开记。墙是"挡住了"，这是"根本没这条路由"——
            // 后者绝不能生成越权假设（2026-11-02 m.ctrip.com 的 z9probe_notexist 白烧 3 轮）。
            const routeMissing = routeMissingOf(data);
            const parentUrl = String(requester || discovery.self[0] || data.url || "");
            // 暴力枚举工具（content_discovery/api_routes）的 items 是「字典命中」，不是观测到的端点。
            // catch-all 目标。113 条命中全是同一。302，建节点会让图裂。113 块（2026-10-28 实测）。
            // 它们改挂父节点的 candidates，等真的打过一次再。http.request 建出节点。
            const bruteForce = isCandidateTool(request.tool);
            const candidatePaths = bruteForce
              ? discovery.found.map(item => ({ url: candidatePathOf(item.url, parentUrl || undefined), note: request.tool }))
              : [];
            // 响应级判据（墙 / 路由不存在 / 签名 / 对象值）只对**单次交互**的工具成立：
            // http_probe 一次打 20 台主机、race_condition 一次发 20 条，用同一份 data 给每条
            // 证据盖同一个章，就是把"某一条被墙"说成"全部被墙"。
            const single = attribution.requests.length === 1 ? attribution.requests[0] : undefined;
            const graphEndpoints = [
              // ① 本次真的发出过请求的目标：状态码是**这次响应**的（probe 类显式标 status_unknown）。
              ...attribution.requests.map((item: RequestEvidence) => ({
                url: item.url,
                requested: true,
                origin: "request" as const,
                ...(item.status_unknown === true ? { status_unknown: true } : {}),
                ...(item.method ? { method: item.method } : {}),
                ...(item.status_code !== undefined ? { status_code: item.status_code } : {}),
                ...(item.content_length !== undefined ? { content_length: item.content_length } : {}),
                ...(single && item === single && typeof data.content_type === "string" ? { content_type: data.content_type } : {}),
                // 参数从请求里取：query/json/form 才是参数的真正来源（原来从响应里读，恒为空）。
                ...(paramsOf(inputOfRequest, item.url).length ? { params: paramsOf(inputOfRequest, item.url) } : {}),
                ...(item.status_code === 401 || item.status_code === 403 ? { auth_required: true, blocked: true } : {}),
                ...(single && item === single && wall ? { wall: wall.kind, blocked: true } : {}),
                // 路由不存在（网关 Not-Found-Route / 空壳 404）：只记属性，供假设生成器跳过。
                ...(single && item === single && routeMissing ? { route_missing: true } : {}),
                ...(single && item === single && requestSignature(inputOfRequest, item.url, request.tool)
                  ? { signature: requestSignature(inputOfRequest, item.url, request.tool) }
                  : {}),
                // 对象模型：把这次真实打过的 {id} 值记进图，双身份对照才有"同一对象"。
                ...(this.objectValuesFor(item.url).length ? { object_values: this.objectValuesFor(item.url) } : {}),
              })),
              // ② 本次挖到的端点（被动发现，不带状态码：没请求过就不编）。
              // 暴力枚举的产物不进这里（。candidates），否则就是「把字典当资产」。
              ...(bruteForce ? [] : discovery.found.map(item => ({
                url: item.url,
                origin: "discovery" as const,
                discovery_kind: item.kind,
                ...(item.method ? { method: item.method } : {}),
                ...(item.params?.length ? { params: item.params } : {}),
                ...(item.via ? { via: item.via } : {}),
                // burp.sitemap / burp.history 的条目自带状态码：有了它，被动发现也，已验证的。。
                ...(item.status !== undefined ? { status_code: item.status } : {}),
                ...(item.source ? { source: item.source } : {}),
                ...(this.objectValuesFor(item.url).length ? { object_values: this.objectValuesFor(item.url) } : {}),
              }))),
            ];
            // 链接/接口调用：源统一，本次作用的页。不再依赖工具恰好返。urls/endpoints。
            const links = bruteForce ? [] : discovery.found.filter(item => item.kind === "link" || item.kind === "js" || item.kind === "form").map(item => ({ from: parentUrl, to: item.url, kind: item.kind, ...(item.source ? { source: item.source } : {}) }));
            const apiCalls = bruteForce ? [] : discovery.found.filter(item => item.kind === "api").map(item => ({ from: parentUrl, to: item.url, kind: item.kind }));
            // 基线：ingest 之前的端点状态。没有基线就分不，图变。白打一。。
            const endpointId = requestUrl ? endpointNodeId(requestUrl) : "";
            const baseline = endpointId ? graph.nodes[endpointId] : undefined;
            const statusBefore = baseline?.status;
            const codeBefore = baseline?.properties.status_code;
            // 势能基线：ingest 之前，请求端点离"最近的高价值目，有多远（。potential.ts）。
            const focusNodeId = endpointNodeId(requester || String(data.url || ""));
            const potentialBefore = focusNodeId ? potentialOf(graph, focusNodeId) : undefined;
            // 漏洞态也进图：findings 早就在账本里，但 excalidraw 上永。0 。vuln_state 节点。
            // 因为 desk 从没。findings 传给 builder（见 §44 的排查）。
            const findingsOfSession = Object.values((progress.state.findings || {}) as Record<string, { target?: string; severity?: string; title?: string; evidence_ids?: string[] }>)
              .filter(item => String(item.target || "") === String(data.url || requestUrl || ""))
              .map(item => ({ url: String(item.target || ""), kind: String(item.title || item.severity || "finding").slice(0, 40) }))
              .filter(item => /^https?:\/\//i.test(item.url));
            const identityState = this.identityOf(pid, String(requestUrl || toolContext.target || ""), (request.input as Record<string, unknown> | undefined)?.identity);
            this.recordIdentity(pid, sessionId, progress, identityState);
            const ingested = ingestToolResult(graph, {
              tool: request.tool,
              identity: identityState.role,
              // 父节点：本次作用的页面；它就，从哪挖到。。
              ...(parentUrl && /^https?:\/\//i.test(parentUrl) ? { parent: endpointNodeId(parentUrl) } : {}),
              // 横轴。run 编号（与历史回放同口径）。planRevision 是任务计划版本，不是轮次。
              round: Math.max(1, Number(progress.state.graphRound || 1)),
              endpoints: graphEndpoints,
              ...(candidatePaths.length ? { candidates: candidatePaths } : {}),
              links,
              api_calls: apiCalls,
              ...(findingsOfSession.length ? { vulnerabilities: findingsOfSession.slice(0, 8) } : {}),
              evidence_id: `ev-${Date.now()}`,
            });
            const graphRoundNow = Math.max(1, Number(progress.state.graphRound || progress.graphRound || 1));
            /**
             * 假设推导调用闸（2026-11-07，对照会话 1dd9ded9ed239711）。
             *
             * 只在本次结果真的改变了图时才跑全图推导。判据不只看结构：节点属性
             * （status / 状态码 / 响应体长度 / content_type）、响应头的身份与重定向信号、
             * 对照判出的差异都算——否则「同一个端点 403 → 200」这种最有价值的属性迁移
             * 会被吞掉。失败/被拒/非纯读工具一律保守重算，不赌隐式侧效应。
             */
            const afterNode = endpointId ? graph.nodes[endpointId] : undefined;
            const propertiesChanged = Boolean(baseline && afterNode && (
              statusBefore !== afterNode.status
              || Number(codeBefore ?? 0) !== Number(afterNode.properties.status_code ?? 0)
              || Number(baseline.properties.content_length ?? 0) !== Number(afterNode.properties.content_length ?? 0)
              || String(baseline.properties.content_type ?? "") !== String(afterNode.properties.content_type ?? "")
            ));
            const responseHeaders = (data.headers && typeof data.headers === "object"
              ? data.headers as Record<string, unknown> : {});
            const signalHeaders = Object.keys(responseHeaders).some(key => /^(set-cookie|location)$/i.test(key));
            const comparisonDiff = data.identical === false;
            const refresh = shouldRefreshHypotheses({
              tool: request.tool, ok: result.ok, rejected,
              newNodes: ingested.newNodes.length, newEdges: ingested.newEdges.length,
              deadEnds: ingested.deadEnds.length, candidates: ingested.candidates.length,
              propertiesChanged, signalHeaders, comparisonDiff,
            });
            // 只记数不写事件：回放时可直接对比 deriveHypotheses 的调用量与耗时，不额外撑大事件账。
            const tally = (progress.state.hypothesisRefresh ||= { checked: 0, skipped: 0, ran: 0, ranMs: 0 });
            tally.checked += 1;
            const deriveStarted = refresh.refresh ? performance.now() : 0;
            const newHypotheses = refresh.refresh
              ? applyHypotheses(graph, deriveHypotheses(graph, graphRoundNow), graphRoundNow)
              : [];
            // 旧 checkpoint 没有 ranMs，用 ||0 兜底，避免 undefined + 数字变 NaN。
            if (refresh.refresh) { tally.ran += 1; tally.ranMs = (tally.ranMs || 0) + performance.now() - deriveStarted; }
            else tally.skipped += 1;
            // 假设必须进任务簿，否则它只是图上的装饰：执行器只跑任务，
            // 2026-10-31 m.ctrip.com 。19 条假。attempts 。0 就是这么来的。
            // 跳过推导时池子没变，但任务链照常从现有池派单（见 shouldRefreshHypotheses）。
            const newHypothesisTasks = this.enqueueHypothesisTasks(pid, sessionId, progress, graph);
            // 证据含金量：只有结构性变化（新端，新参，新身，状态迁移）才让焦点预算"续命"。
            // 10 。404 在这里就。0 。—，这是"无效探索"唯一的客观判据（。evidence-value.ts）。
            const value = scoreIngest({
              newNodes: ingested.newNodes,
              newEdges: ingested.newEdges,
              deadEnds: ingested.deadEnds,
              ...(baseline ? { before: { status: statusBefore, code: codeBefore, content_length: baseline.properties.content_length, content_type: baseline.properties.content_type } } : {}),
              ...(endpointId && graph.nodes[endpointId] ? { after: { status: graph.nodes[endpointId]!.status, code: graph.nodes[endpointId]!.properties.status_code, content_length: graph.nodes[endpointId]!.properties.content_length, content_type: graph.nodes[endpointId]!.properties.content_type } } : {}),
              ...(data.headers && typeof data.headers === "object" ? { headers: data.headers as Record<string, unknown> } : {}),
              ...(data.identical !== undefined || data.diff_score !== undefined
                ? { comparison: { identical: data.identical === true, score: Number(data.diff_score ?? 0) || 0, field: String(data.diff_field || data.field || "") || undefined } }
                : {}),
              // 计分只认真正转成任务的条数；池子里推导出多少条不是进展（见 evidence-value.ts）。
              newHypothesisTasks,
              repeated: (Number((endpointId && graph.nodes[endpointId]?.properties.repeats) || 0)) >= 2,
              // 势能：唯一带全局寻路视角的判据。路径变。= 真的逼近核心。5），
              // 新节点但路径没变 = 边缘探索。0.5，不算进展）。
              potential: (() => {
                const after = focusNodeId ? potentialOf(graph, focusNodeId) : undefined;
                const delta = potentialDelta(potentialBefore, after);
                return { before: potentialBefore, after, improved: delta.improved, delta: delta.delta, reason: delta.reason };
              })(),
            });
            if (request.task_id) recordFocusValue(progress.state, request.task_id, value);
            if (value.tier > 0) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "evidence-value",
                `证据增益 +${value.score}（${request.tool}）：${value.reasons.slice(0, 3).join("；")}`,
                { task_id: request.task_id, score: value.score, tier: value.tier, high: value.high, medium: value.medium, noise: value.noise, reasons: value.reasons });
            }
            progress.state.graph = graph;
            // 三个「代码替模型做决定」的协议：主权转。/ SPA 缴械 / 字典聚类抽样。
            // 。blackbox/sovereignty.ts、blackbox/spa.ts、blackbox/graph/cluster.ts。
            this.applyProtocolHooks(pid, sessionId, progress, {
              tool: request.tool, data, requestUrl, ingested, parentUrl,
            });
            // 最近活动端点（时间倒序）：Observer 图巡检与环路判定都靠它。
            if (endpointId) {
              progress.state.graphRecent = [endpointId, ...(progress.state.graphRecent || []).filter(id => id !== endpointId)].slice(0, 12);
            }
            // 按需寻路：只在新身份或新端点出现时算一次，不是每轮跑全图。
            {
              const fresh = ingested.newNodes.filter(id => id.startsWith("id:") || id.startsWith("ep:"));
              // 新节点出现就重算；没有新节点但存着。Next Hop 已经打不动了，也要重算。
              const keep = progress.state.graphRoute;
              const stale = keep ? routeStale(graph, keep.routes.map(route => route.next_hop)) : false;
              const start = fresh.find(id => id.startsWith("id:")) || fresh.find(id => id.startsWith("ep:"))
                || (stale ? keep?.start : undefined);
              if (start) {
                const routes = planRoutes(graph, start, { limit: 3 });
                if (routes.length) {
                  progress.state.graphRoute = {
                    start, start_kind: start.startsWith("id:") ? "identity" : "endpoint",
                    routes: routes.map(route => ({
                      target: route.target, cost: Math.round(route.cost * 10) / 10, next_hop: route.next_hop,
                      why: route.why, via: route.hops.map(hop => hop.to),
                    })),
                    at: Date.now(),
                  };
                  this.db.addBlackboxEvent(pid, sessionId, "system", "graph-route",
                    `按需寻路（起点 ${start}）：下一步打 ${progress.state.graphRoute.routes.map(route => route.next_hop).join("、")}`,
                    { start, routes: progress.state.graphRoute.routes });
                }
              }
            }
            if (ingested.newNodes.length) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-node",
                `历程：+${ingested.newNodes.length} 节点（${request.tool}）`,
                { tool: request.tool, nodes: ingested.newNodes.slice(0, 12), counts: graph.stats });
              // 给图巡检一个"这一轮图还在长"的一次性标记（见 supervise 里的 graphQuietStreak）。
              progress.state.graph_growth_pending = true;
            }
            // 建完即被容量裁剪丢掉的节点必须单独记账（2026-11-07）：
            // 以前这类节点既不在图里、又混在"发现新端点"里，模型会去追一个不存在的对象。
            if (ingested.prunedSameRound.length) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-node-pruned",
                `历程：${ingested.prunedSameRound.length} 个节点建完即被容量裁剪丢弃（${request.tool}）：${ingested.prunedSameRound.slice(0, 5).join("、")}`,
                {
                  tool: request.tool, reason: "pruned_same_round",
                  nodes: ingested.prunedSameRound.slice(0, 12), counts: graph.stats,
                });
            }
            // 被挡下的发现物必须留痕（2026-11-03）：以前它们在 builder 里被静默 continue，
            // 事件流、统计、上下文全无踪影——模型根本不知道自己错过了什么面。
            // 只落事件不进节点：500 上限留给真正打得动的面。
            if (ingested.skipped.length) {
              const byReason: Record<string, number> = {};
              for (const record of ingested.skipped) byReason[record.reason] = (byReason[record.reason] || 0) + 1;
              const sample = ingested.skipped.slice(0, 5).map(record => record.url);
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-skipped",
                `历程：${ingested.skipped.length} 条发现物未入图（${Object.entries(byReason).map(([reason, count]) => `${reason}×${count}`).join("、")}）：${sample.join("、")}${ingested.skipped.length > sample.length ? " …" : ""}`,
                {
                  tool: request.tool, count: ingested.skipped.length, reasons: byReason,
                  sample, anchors: [...new Set(ingested.skipped.map(record => record.anchor))].slice(0, 5),
                });
            }
            if (ingested.deadEnds.length) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-dead-end",
                `标记死胡同 ${ingested.deadEnds.join("、")}：换攻击面，不要再打同一参数面`,
                { nodes: ingested.deadEnds });
            }
            // 单轮事件上限（2026-11-07）：明细最多 5 条，其余聚合成 1 条。
            // 对照会话 07:00–07:06 六分钟写 1717 条 graph-hypothesis、占全场事件 78%，
            // 模型上下文与 checkpoint 都被写放大撑爆。聚合事件保留完整 id 前 40 条供追溯。
            const { shown, rest, kinds: byKind } = hypothesisEventBatch(newHypotheses);
            for (const hypothesis of shown) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-hypothesis",
                `新假设（${hypothesis.kind}）：${hypothesis.text}`, { hypothesis_id: hypothesis.id, nodes: hypothesis.nodes });
            }
            if (rest.length) {
              this.db.addBlackboxEvent(pid, sessionId, "system", "graph-hypothesis",
                `另有 ${rest.length} 条新假设（${Object.entries(byKind).map(([kind, count]) => `${kind}×${count}`).join("、")}），已按轮聚合；完整 id 见 data。`,
                { aggregated: true, count: rest.length, kinds: byKind,
                  hypothesis_ids: rest.slice(0, 40).map(item => item.id) });
            }
            // 假设记账：只，打了但图没有结构性变。执行失败"才算一次徒劳尝试。
            if (endpointId) {
              const node = graph.nodes[endpointId];
              const codeAfter = node?.properties.status_code;
              const changed = node?.status === "vulnerable"
                || (codeBefore !== undefined && codeAfter !== undefined && codeBefore !== codeAfter);
              if (node?.status === "vulnerable") {
                for (const resolved of resolveHypotheses(graph, endpointId)) {
                  this.db.addBlackboxEvent(pid, sessionId, "system", "graph-hypothesis-resolved",
                    `假设已成立并撤销（${resolved.kind}）：${resolved.text.slice(0, 120)}`,
                    { hypothesis_id: resolved.id, nodes: resolved.nodes });
                }
              } else if (!changed && (statusBefore !== undefined || !result.ok || rejected)) {
                // identity 必须传：auth_wall 的账只能记在"带该假设点名身份重打"的动作上，
                // 匿名/换身份请求不该替它记失败（否则同端点的越权探测会把它打到 unreachable）。
                for (const hypothesis of noteHypothesisAttempt(graph, endpointId, { failed: !result.ok || rejected, identity: identityState.role })) {
                  this.db.addBlackboxEvent(pid, sessionId, "system", "graph-hypothesis-closed",
                    `假设降级（${hypothesis.kind}）：${hypothesis.closed_reason}——换攻击面，别再打这条`,
                    { hypothesis_id: hypothesis.id, attempts: hypothesis.attempts, nodes: hypothesis.nodes });
                }
              }
            }
          }
          const timedOut = result.data.timed_out === true;
          // katana reports `urls`, subjs `endpoints`, list tools `items`: count whatever the tool
          // actually returned, otherwise a 28-URL partial crawl is logged as "0 partial results".
          const data = result.data as Record<string, unknown>;
          const partial = Number(data.count ?? (Array.isArray(data.items) ? data.items.length : undefined)
            ?? (Array.isArray(data.urls) ? data.urls.length : undefined)
            ?? (Array.isArray(data.endpoints) ? data.endpoints.length : undefined) ?? 0);
          // 罐指纹必须在 finish 之前刷新：recordHostBlock 在 finish 内部用 seed_health，
          // 而 http.request 的 Set-Cookie / browser.open 的种子注入刚刚可能改过罐。
          progress.state.seed_jar_fingerprint = cookieJarFingerprint(this.db.getProjectCookies(pid));
          madeProgress = progress.finish(request, action.key, result, taskRetryLimit, { timedOut, rejected }) || madeProgress;
          this.observeToolResult(pid, sessionId, progress, request, result);
          // 种子自检：撞墙时先问"这堵墙是不是我方凭证造的"，再谈绕不绕、逃不逃。
          // 顺序有意放在补枪之前——补枪判的是"目标是不是整片拦截"，
          // 而这个判的是更前置的一层：**拦我们的到底是不是目标**。
          await this.runSeedProbe(pid, sessionId, progress, { ...toolContext, deadline: Math.min(stageStarted + stageMs,
            budget.wallClockMs > 0 ? startedAt + budget.wallClockMs : Infinity) });
          // 0 产出补枪：字，爬虫什么都没扫到时，先补一枪根路径，没路。整片被墙"分开。
          await this.runWallProbe(pid, sessionId, progress, { ...toolContext, deadline: Math.min(stageStarted + stageMs,
            budget.wallClockMs > 0 ? startedAt + budget.wallClockMs : Infinity) });
          if (rejected) {
            // Disabled, unconfigured, or unusable input: nothing ran, nothing is billed, and the
            // model sees the reason. Identical repeats still stop through the repeat limit.
            this.db.addBlackboxEvent(pid, sessionId, "system", "tool-rejected",
              `${request.tool} 被拒绝执行（未计入工具调用与重试）：${String((result.data as Record<string, unknown>).error || result.summary)}`,
              { tool: request.tool, task_id: request.task_id, action_key: action.key, billed: false });
            save();
            continue;
          }
          if (timedOut) {
            noteFocusFailure(String(request.task_id || ""), "timeout");
            // A deadline hit is an environment fact, not a tool failure: no retry, no failed task.
            if (partial > 0) madeProgress = true;
            const stageExhausted = Date.now() >= stageStarted + stageMs - 250;
            this.db.addBlackboxEvent(pid, sessionId, "system", "tool-timeout",
              `${request.tool} 超时，已保留 ${partial} 条部分结果；任务回到待执行，不计入重试${stageExhausted ? "，本阶段剩余时间已用尽，下一步换新阶段继续" : ""}`,
              { tool: request.tool, task_id: request.task_id, action_key: action.key, partial, stage_exhausted: stageExhausted });
            save();
            if (stageExhausted) {
              deferRest(index + 1, "stage_timeout");
              // One slow tool must not end the run: open another stage, up to the configured
              // number of rollovers, and let the run budget be the thing that stops it.
              if (stageRollovers >= stageRolloverLimit) { stopReason = "stage_timeout"; break; }
              stageRollovers += 1;
              this.db.addBlackboxEvent(pid, sessionId, "system", "stage-rollover",
                `。${stageRollovers} 阶段预算用尽，已开启新阶段继续推进（上。${stageRolloverLimit}）。`,
                { rollover: stageRollovers, limit: stageRolloverLimit, tool: request.tool });
              break;
            }
            continue;
          }
          if (!result.ok) {
            noteFocusFailure(String(request.task_id || ""), "failed");
            usage.retries += 1;
            batchFailed = true;
            const failureText = `${result.summary} ${String((result.data as Record<string, unknown>).error || "")}`;
            if (/unauthorized/i.test(failureText)) batchFailureKind = "critical";
          }
          save();
          if (Date.now() - stageStarted >= stageMs) { deferRest(index + 1, "stage_timeout"); break; }
          stopReason = overBudget();
          if (stopReason) { deferRest(index + 1, "budget_exhausted"); break; }
        }
        // ② 派发有效性回填：只用真正拿到工具结果的请求记饥饿账。
        // 全拒轮次 requests=[] 时这里同样是空数组，所有任务照常累计 0 派发。
        this.noteTaskStarvation(pid, sessionId, progress, executedRequests, round);
        if (stopReason) break;
        this.db.updateBlackboxSession(pid, sessionId, { phase: "analysis" });
        const wallAdvice = this.injectAuthWallAdvice(pid, sessionId, progress);
        this.injectPostSurfaceTask(pid, sessionId, progress);
        this.injectLinkageTasks(pid, sessionId, progress);
        this.reportParamStall(pid, sessionId, progress);
        await supervise({ kind: "tool_batch", madeProgress, failed: batchFailed, failureKind: batchFailureKind || (madeProgress ? undefined : "stall"), toolCalls: executed, evidenceCount: ((this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as unknown[]).length, authWall: wallAdvice });
        flushInterrupts();
        if (stopReason) break;
        stopReason = overBudget();
        if (stopReason) break;
        progress.state.stalledBatches = madeProgress ? 0 : progress.state.stalledBatches + 1;
        save();
        if (progress.state.stalledBatches >= stallLimit && (runUsage().toolCalls >= STALL_CALL_FLOOR || progress.pendingCount() === 0 || main.continue === false)) { stopReason = "stalled"; break; }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      stopReason = message === "observer_review_checkpoint_conflict" ? message : overBudget() || (/timeout|abort/i.test(message) ? "stage_timeout" : "agent_error");
      this.db.addBlackboxEvent(pid, sessionId, "system", "warning", `Agent 回合失败：${message}`);
    }
    // All non-operator exits pass through one review gate. Budget exhaustion records
    // the required review but cannot spend beyond the configured budget.
    if (!stopReason.startsWith("operator_") && !["observer_paused", "observer_review_checkpoint_conflict"].includes(stopReason)) {
      // 离场前先归档"给过机会却没处置"的建议（至少一轮）：这类建议留到门禁就会把整场 run
      // 变成 required_review_pending，而它已经拿到过处置机会，属于"记账没做"（见 advice.ts）。
      const exitSwept = progress.sweepAdvice({ maxMisses: 1 });
      if (exitSwept.length) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "advice-auto-skip",
          `${exitSwept.length} 条建议到离场时仍未被处置，已按「未采纳」归档，不作为终止理由。`,
          { advice_ids: exitSwept, auto_skipped: true, exit_sweep: true });
      }
      /**
       * 建议处置补跑：Observer 的审查发生在回合末尾（终审还在门禁里），它产出的建议只能。
       * "下一回合"被处置。如。run 正好在那一回合结束，模型就带着自己从没见过的建议离场了。
       * 这里补一回合（每场最多一次、预算允许时）专用于处置建议：不执行工具（请求一。deferred），
       * 只落 advice_decisions 与任务账目。
       */
      let disposalRoundUsed = false;
      const disposeAdviceRound = async (): Promise<boolean> => {
        const unseen = progress.pendingAdvice().filter(item => item.misses === 0);
        if (disposalRoundUsed || !unseen.length) return false;
        if (overBudget() || (budget.agentTurns > 0 && runUsage().agentTurns >= budget.agentTurns)) {
          this.db.addBlackboxEvent(pid, sessionId, "system", "action-skipped",
            "有建议模型尚未看到，但预算已用尽，不再补跑处置回合。", { advice_ids: unseen.map(item => item.advice_id) });
          return false;
        }
        disposalRoundUsed = true;
        try {
          save();
          this.db.addBlackboxEvent(pid, sessionId, "system", "advice-disposal-round",
            `补跑一回合专用于处。${unseen.length} 条刚产出、模型还没见过的建议。`,
            { advice_ids: unseen.map(item => item.advice_id), budget: { ...budget, ...runUsage() } });
          // 不计入轮次预算：这是收尾记账，不是新一轮探测；tokens 照常计费。
          const latest = this.db.getBlackboxSession(pid, sessionId)!;
          const mainRound = await runBlackboxMainAgent(modelValues(), latest, candidate, controller.signal, budgetView());
          addUsage(mainRound);
          if (mainRound.protocol_error || mainRound.parse_error) {
            this.db.addBlackboxEvent(pid, sessionId, "system", "warning", "建议处置回合输出无法解析，保留待处置建议交给门禁。", {});
            return false;
          }
          const roundFacts = (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[];
          progress.merge(mainRound, roundFacts);
          // 这一回合的工具请求一律不执行（只记账），所以"接受了建议"在这里默认是**纸面采纳**：
          // 除非同一回合真的把任务推进到终态，否则不能算处置完成——否则门禁会看到 openAdvice=0
          // 就以为没人再提要求（2026-11-02 实测 b9601629efd1f137 就是这么在 12/600 次调用时收工的）。
          const completedInDisposal = (Array.isArray(mainRound.completed_tasks) ? mainRound.completed_tasks as unknown[] : []).length > 0;
          if (!completedInDisposal) {
            for (const result of progress.state.adviceDecisionResults || []) {
              if (result.status !== "applied" && result.status !== "already_applied") continue;
              const item = progress.state.advice?.[result.advice_id];
              if (item && item.status === "accepted") item.paper = true;
            }
          }
          const sweeps = progress.sweepAdvice({ salvaged: Array.isArray(mainRound._salvaged_advice_ids) ? mainRound._salvaged_advice_ids as string[] : [] });
          // 工具请求不在这一回合执行：它不是用来继续探测的，只用来把建议记账。
          const requested = (Array.isArray(mainRound.tool_requests) ? mainRound.tool_requests : []) as BlackboxToolRequest[];
          for (const request of requested) {
            const key = request.tool && request.task_id ? `${request.tool}:${request.task_id}` : undefined;
            if (key) progress.defer(request, key, "advice_disposal_only");
          }
          if (requested.length) {
            this.db.addBlackboxEvent(pid, sessionId, "system", "action-skipped",
              `建议处置回合不执行工具：${requested.length} 个请求已登记延后。`, { count: requested.length });
          }
          // 处置完就清掉"等审，的标记，否则门禁仍会按旧标记。required_review_pending。
          const postRound = evaluateAcceptance(progress.state, roundFacts);
          if (postRound.ready) progress.state.supervision!.reviewPending = false;
          this.db.addBlackboxEvent(pid, sessionId, "agent", "analysis", String(mainRound.summary || "建议处置回合完成。").slice(0, 8000),
            { ...mainRound, iteration: "advice-disposal", advice_decision_results: progress.state.adviceDecisionResults, swept: sweeps });
          save();
          return true;
        } catch (error) {
          // 补跑，尽力而为"：模型调用失败时保留建议，交给门禁如实记录，绝不因此抛掉整场结果。
          this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
            `建议处置回合失败：${error instanceof Error ? error.message : String(error)}`, {});
          return false;
        }
      };
      save();
      const facts = (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[];
      const currentAcceptance = evaluateAcceptance(progress.state, facts);
      progress.state.supervision ||= { observerRuns: 0 };
      progress.state.supervision.acceptance = currentAcceptance;
      if (currentAcceptance.blocking_error_count && currentAcceptance.repairableOnly) {
        // Only the agent's own rejected completion claims: keep them for the next round instead of
        // spending an Observer review and stopping the session.
        this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
          "本轮存在可自纠的任务完成声明（引用字段写错），已保留明细，下一轮继续修正。",
          { issues: currentAcceptance.issues, state_version: reviewVersionOf(progress.state) });
      } else if (currentAcceptance.blocking_error_count) {
        // 同一批 issues 只排一次审查：这里与 superviseCheckpoint 共用 checkpoint 里的指纹账，
        // 打断「validation_failed → 排队 → stale → 门禁保持 → 再排队」的闭环空转。
        const queue = shouldQueueIssueReview(progress.state, currentAcceptance.issues);
        if (!queue.queue) {
          // 事件照写（门禁发现阻塞这件事必须留痕），只是不再重复排一次 Observer 调用。
          this.db.addBlackboxEvent(pid, sessionId, "system", "validation-failed",
            "阶段结束门禁发现阻塞校验错误；同一批问题已有审查在账，跳过重复排队。",
            { issues: currentAcceptance.issues, state_version: reviewVersionOf(progress.state), deduped: true, issue_fingerprint: queue.fingerprint });
          this.db.addBlackboxEvent(pid, sessionId, "system", "review-deduped",
            `同一批阻塞问题已有审查在账（${queue.reason}），跳过重复排队；问题集合变化、修好后重现或审查失败时会自动重排。`,
            { fingerprint: queue.fingerprint, reason: queue.reason, issues: currentAcceptance.issues,
              last_queue: progress.state.supervision?.lastReviewIssueQueue, state_version: reviewVersionOf(progress.state) });
        } else {
          progress.state.supervision.reviewPending = true;
          const trigger = this.db.addBlackboxEvent(pid, sessionId, "system", "validation-failed", "阶段结束门禁发现阻塞校验错误。", { issues: currentAcceptance.issues, state_version: reviewVersionOf(progress.state), issue_fingerprint: queue.fingerprint });
          await observe("validation_failed", String(trigger?.id || `validation:${reviewVersionOf(progress.state)}`), currentAcceptance.issues);
        }
      }
      const afterValidation = evaluateAcceptance(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
      const reviewVersion = reviewVersionOf(progress.state);
      const terminalReviewDone = versionMatches(progress.state.supervision.terminalReviewVersion);
      const reviewFailure = ["observer_review_failed", "observer_review_retry_exhausted", "observer_review_stale_snapshot", "observer_review_checkpoint_conflict", "observer_paused"].includes(stopReason);
      if (!terminalReviewDone && !afterValidation.blocking_error_count && !reviewFailure) {
        progress.state.supervision.reviewPending = true;
        save();
        const trigger = this.db.addBlackboxEvent(pid, sessionId, "system", "terminal-review-trigger", "阶段结束前要。Observer 终审。", { state_version: reviewVersion, all_tasks_terminal: afterValidation.all_tasks_terminal, reason: stopReason });
        await observe("terminal_review", String(trigger?.id || `terminal:${reviewVersion}`));
      }
      // 终审/校验审查同样，刚产出、模型没见过"的建议来源：在这里补跑处置回合。
      const disposalDone = await disposeAdviceRound();
      const postSweep = progress.sweepAdvice({ maxMisses: disposalDone ? 0 : 1 });
      if (postSweep.length) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "advice-auto-skip",
          `${postSweep.length} 条建议在补跑后仍未处置，已按「未采纳」归档。`,
          { advice_ids: postSweep, auto_skipped: true, exit_sweep: true, after_disposal: disposalDone });
      }
      // 归档后重新算一次：只剩"等审，这个旧标记时，不能让它把 session 判成 required_review_pending。
      if (evaluateAcceptance(progress.state, facts).ready) progress.state.supervision!.reviewPending = false;
      else if (disposalDone) {
        // 补跑改变了状态版本，刚做完的终审因此"过期"。但它审的就是同一批任，发现。
        // 只差一条已被归档的建议——重来一遍只会再产一条建议、再归档、再过期。这里给它结账。
        const residue = evaluateAcceptance(progress.state, facts);
        const completedTerminal = Object.values(progress.state.supervision?.reviews || {})
          .some(review => review.reason === "terminal_review" && review.status === "completed");
        const adviceOnly = residue.blocking_error_count === 0 && residue.unhandled_advice === 0 &&
          residue.reason_codes.every(code => code === "TERMINAL_REVIEW_PENDING");
        if (completedTerminal && adviceOnly) {
          progress.state.supervision!.terminalReviewVersion = reviewVersionOf(progress.state);
          progress.state.supervision!.reviewPending = false;
          this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
            "补跑处置后的状态已由刚完成的终审覆盖（只差一条已归档的建议），不再重复要求审查。",
            { reason_codes: residue.reason_codes });
        }
      }
      // 离场前清一次"永远修不好"的历史错误：任务已经终态的转移类错误（closure_deliverables_* /
      // completion_without_* 等）没有任何输出能修复，留着只会让验收永远报 VALIDATION_ERRORS_REMAIN，
      // 于是停止原因退化成 required_review_pending（2026-11-02 实测 T1 已完成，却因
      // `closure_deliverables_partial:T1` 残留把整场标成"等审"）。隔离进 dlq，控制台仍可见。
      const prunedAtExit = progress.pruneAdviceErrors();
      if (prunedAtExit.length) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
          `离场前隔离 ${prunedAtExit.length} 条不可修复的历史错误（任务已终态），不再计入验收阻塞。`,
          { pruned: prunedAtExit.slice(0, 20), origin: "unrepairable" });
      }
      /**
       * 按**主体**兜底（2026-11-10）：码表之外的新死码不该再让会话停五场。
       *
       * `pruneAdviceErrors` 认的是码；认不出的码就只能停场等人改代码（
       * `completion_without_verdict` 实战五场）。这里换个判据：任务已终态、建议已处置，
       * 这条错误就再没有合法输入能让它消失——与码表无关，一律进 dlq 并退出阻塞。
       * 判据与 `actionableTransitionErrors()` 同源，待办清单与阻塞清单不会错位。
       */
      const retiredAtExit = progress.retireUnrepairableTransitions();
      if (retiredAtExit.length) {
        this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
          `离场前把 ${retiredAtExit.length} 条「主体已终态」的转移错误转死信队列（${retiredAtExit.slice(0, 3).join("、")}${retiredAtExit.length > 3 ? " …" : ""}）：`
            + `对应任务/建议不会再有合法输入，保留它们只会让每场都停在 validation_failed。明细可在控制台死信队列查。`,
          { retired: retiredAtExit.slice(0, 20), origin: "unrepairable:subject_dead" });
      }
      const finalAcceptance = evaluateAcceptance(progress.state, (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[]);
      progress.state.supervision!.acceptance = finalAcceptance;
      /**
       * 证据类阻塞的处置（2026-11-06）：先给模型改，改不动就隔离，隔离完还脏才停场。
       *
       * 这三态把"一条记账错误"和"结论站不住"彻底分开了：前者可修、可隔离、不该
       * 推翻整份报告；后者是红线，照旧让 `validation_failed_review_required` 停住。
       *
       * **必须无条件调用**，包括 Observer 已经挂掉的情况：实测 e8bdb447acf02283 第二轮
       * 修正时 Observer 重试耗尽先设了 stopReason，旧顺序下这里被短路，隔离一次都没执行，
       * 于是"证据没补上 + Observer 挂了"两个问题一起挂到下次 resume。隔离是纯记账动作，
       * 不依赖模型也不依赖 Observer，任何时候都该做完。
       */
      const observerFailure = stopReason === "observer_review_failed" || stopReason === "observer_review_retry_exhausted"
        || stopReason === "observer_review_stale_snapshot" || stopReason === "observer_review_checkpoint_conflict";
      const evidenceVerdict = finalAcceptance.blocking_error_count && !finalAcceptance.repairableOnly
        ? this.settleEvidenceBlocks(pid, sessionId, progress,
          (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[],
          {
            attemptsLimit: EVIDENCE_REPAIR_LIMIT,
            // Observer 已经重试耗尽时不再开修正轮：下一轮它还会失败，等于空烧预算。
            canSpend: !overBudget() && !observerFailure && (budget.toolCalls === 0 || budget.toolCalls - runUsage().toolCalls >= 5),
            pass: reviewPass, passLimit: REVIEW_REENTRY_LIMIT,
          })
        : "clean";
      if (evidenceVerdict === "retry") {
        // 修正轮：不设 stopReason，清掉挂账后回去再打一轮，让模型把账改对。
        progress.state.supervision!.reviewPending = false;
        reviewReenter = true;
      } else if (evidenceVerdict === "dirty") {
        // 隔离后仍有硬错误。只有更上游的故障（Observer 挂了）才配保住自己的原因；
        // 主循环中途记下的 state_validation_failed 在这里被更准确的结论覆盖——
        // 它说的只是"当时校验没过"，而这里能说清"隔离之后仍有哪几处站不住"。
        if (!observerFailure) stopReason = "validation_failed_review_required";
      } else if (observerFailure) {
        // Keep the explicit review failure as the stop reason.
      } else if (progress.state.supervision!.reviewPending) {
        // 门禁全放行（2026-11-06）：这里以前会落到 `required_review_pending` —— 终审跑完了、
        // 建议也写下来了，却因为"等操作员签收"让整场停在 awaiting_operator（实测 418s/720s，
        // 4 个待办一个没跑）。现在只做两件事：
        //   ① 有活可干（待办 / 未处置建议）且预算还够 → 清掉挂账，再开一轮 pass 把动作跑掉；
        //   ② 实在干不动（没活或预算见底）→ 按真实原因收口，绝不再用"等审"当停止理由。
        const openAdvice = progress.openAdviceCount();
        const pending = progress.pendingCount();
        const completedTerminal = Object.values(progress.state.supervision?.reviews || {})
          .some(review => review.reason === "terminal_review" && review.status === "completed");
        const remainingCalls = budget.toolCalls > 0 ? budget.toolCalls - runUsage().toolCalls : Number.POSITIVE_INFINITY;
        const wantWork = pending > 0 || openAdvice > 0;
        if (wantWork && remainingCalls >= 5 && !overBudget() && reviewPass < REVIEW_REENTRY_LIMIT) {
          // 续跑就必须清挂账：否则下一轮 pass 的门禁又按"等审"从头判一遍。
          progress.state.supervision!.reviewPending = false;
          reviewReenter = true;
          progress.state.review_continue_count = Number(progress.state.review_continue_count || 0) + 1;
          this.db.addBlackboxEvent(pid, sessionId, "system", "review-continue",
            `终审留下 ${openAdvice} 条未处置建议、${pending} 个待办，预算还剩 ${remainingCalls === Number.POSITIVE_INFINITY ? "不限" : remainingCalls} 次调用：`
              + `再开一轮（第 ${reviewPass + 1} 轮 pass）把动作跑掉，不停场等签收。`,
            { pass: reviewPass, open_advice: openAdvice, pending_tasks: pending, remaining_calls: remainingCalls, reason_codes: finalAcceptance.reason_codes });
        } else {
          // 停场时**不动** reviewPending：排队的审查要能跨 run 存活，resume 才有东西可跑。
          // 它也不再影响收口判定（见末尾 finished 的判据）。
          // 停止原因按"真实原因"给：已经有 stalled/agent_error/预算这类原因就保留它，
          // 不要把诊断信息改写成一句更模糊的话。
          const fallback = pending ? "tasks_pending" : completionVerdictOf(progress.state.tasks);
          stopReason = overBudget() || (stopReason && stopReason !== "required_review_pending" ? stopReason : fallback);
          this.db.addBlackboxEvent(pid, sessionId, "system", "warning",
            `门禁放行（不再等签收）：${wantWork ? `还剩 ${pending} 个待办、${openAdvice} 条建议，但预算/轮次已到上限` : "确实没有剩余动作"}，`
              + `停止原因记为 ${stopReason}；排队中的审查保留给下次 resume。`,
            { pass: reviewPass, pending_tasks: pending, open_advice: openAdvice, completed_terminal: completedTerminal, reason_codes: finalAcceptance.reason_codes });
        }
      }
    }
    // 门禁放行后的续跑：回到主循环再打一轮（stopReason 必须清空，否则第 1 轮开头就 break）。
    if (!reviewReenter) break;
    stopReason = "";
    progress.state.stalledBatches = 0;
    save();
    }
    /**
     * 收口（2026-11-05）：预算/熔断/终审到期时，剩余任务不能悬着。
     *
     * 悬着的直接后果是"这场评估没有结论"——验收门要求所有任务终态，
     * 于是 11 场实盘只能靠人按取消键结束，session.status 永远是 cancelled/paused。
     * 但"这一轮预算用完了"本身就是一种结论：能做过的都做过，没做的要写明为什么。
     *
     * 这里只补结论，不伪造证据：settle 出来的 blocked 带 outcome_reason，
     * 报告里按 PARTIAL_TASK_OUTCOME 单列；全灭（0 条 completed）仍判 blocked，不会变成"完成"。
     * 人工取消/暂停不在此列——那是会话要留着 resume 的。
     */
    const SETTLE_REASONS = new Set([
      "time_budget_exhausted", "wall_clock_exhausted", "tool_budget_exhausted", "agent_turn_budget_exhausted",
      "token_budget_exhausted", "cost_budget_exhausted", "retry_budget_exhausted",
      "tasks_pending", "macro_frustration",
    ]);
    let settledCompleted = false;
    if (SETTLE_REASONS.has(stopReason) && progress.pendingCount() > 0) {
      const evidence = (this.db.getBlackboxSession(pid, sessionId)?.evidence || []) as Record<string, unknown>[];
      const { settled, notReached } = this.settleRemainingTasks(progress, stopReason, evidence);
      if (settled || notReached) {
        /**
         * 收口时刻排队中的审查已经失去意义：它审的是收口**前**的快照（实测会出现
         * review-stale 循环：结果对不上旧快照 → 门禁保持 → 会话落 paused，永远到不了 completed）。
         *
         * 处置上刻意**不动 checkpoint 里的 reviewPending**：那个字段一改，恢复后的下一场
         * 会带着"审查已过"的假状态起跑（实测 test/blackbox.test.ts 的 resume 场景因此把
         * 完成声明烧在没证据的那一轮上，整场从 completed 退化成 stalled）。
         * 所以只在**终止判定**里豁免它——状态保持可恢复，结论只对这一次收口生效。
         */
        let droppedReview = "";
        if (progress.state.supervision?.reviewPending) {
          droppedReview = `run_terminated:${stopReason}`;
          progress.state.supervision.reviewDropped = droppedReview;
          this.db.addBlackboxEvent(pid, sessionId, "system", "review-dropped",
            `收口时排队中的 Observer 审查不再计入本次完成判定（审的是收口前快照，结果必然 stale）。`,
            { stop_reason: stopReason });
        }
        // 终止判定用的临时视图：审查视为已完成，其余口径与实际状态一致。
        const acceptanceView = droppedReview
          ? { ...progress.state, supervision: { ...progress.state.supervision!, reviewPending: false } }
          : progress.state;
        const settledAcceptance = evaluateAcceptance(acceptanceView, evidence);
        if (progress.state.supervision) progress.state.supervision.acceptance = settledAcceptance;
        if (acceptanceView !== progress.state) progress.state.validationErrors = acceptanceView.validationErrors;
        const verdict = completionVerdictOf(progress.state.tasks);
        if (settledAcceptance.ready) settledCompleted = isCompletedVerdict(verdict);
        // 停止原因不覆盖：macro_frustration / tool_budget_exhausted 是诊断信息，
        // 报告要能回答"为什么结束"。收口结果单独记在事件与会话状态里。
        /**
         * 三句话，不能只准备两句（2026-11-05 修）。
         *
         * 旧写法是二选一：`settledCompleted ? 通过 : "验收仍有阻塞（${reason_codes}）"`。
         * 但存在第三种状态——验收门已经 ready（reason_codes 为空）、会话却没按完成收口
         * （verdict 还是 blocked）。那时会打印出"验收仍有阻塞（）"，括号里什么都没有，
         * 读日志的人无从判断到底卡在哪。实测 fb06499adcf889b5 就是这句话。
         */
        const settleText = settledCompleted
          ? `验收通过，会话按 ${verdict} 收口（停止原因保持 ${stopReason}）`
          : settledAcceptance.ready
            ? `验收门已放行（无阻塞），但任务形态判为 ${verdict}：仍有任务没结出结论，保持未完成`
            : `验收仍有阻塞（${settledAcceptance.reason_codes.join("、") || "无阻塞码但未放行"}），保持未完成`;
        this.db.addBlackboxEvent(pid, sessionId, "system", "run-settled",
          `收口：${stopReason} 时仍有 ${settled + notReached} 个未结案任务`
            + `（${settled} 条打过未收敛→blocked，${notReached} 条没轮到→未开展）；`
            + `${settleText}。`,
          { settled, not_reached: notReached, stop_reason: stopReason, verdict, completed: settledCompleted,
            review_dropped: droppedReview || undefined, ready: settledAcceptance.ready, reason_codes: settledAcceptance.reason_codes });
      }
    }
    progress.state.stopReason = stopReason;
    save();
    const lists = progress.lists();
    const finalBudget = { ...budget, ...usage, stopReason };
    // 打法覆盖账本：每。playbook 绑了多少任务、跑了几次、走到第几步、卡在哪一步。
    const coverage = playbookCoverage(progress.state);
    if (coverage.length) {
      this.db.addBlackboxEvent(pid, sessionId, "system", "playbook-coverage", `打法覆盖：${coverage.length} 个 playbook 有绑定`, { coverage: coverage as unknown as Record<string, unknown>[] });
      if (coverage.some(item => item.calls > 0)) {
        this.db.addBlackboxEvidence(pid, sessionId, { kind: "playbook-coverage", source: "nianyun", summary: coverageSummary(coverage, 12), confidence: "high", data: { coverage } });
      }
    }
    this.db.addBlackboxEvent(pid, sessionId, "system", "lifecycle", `黑盒任务停止：${stopReason}；已保存检查点。`, finalBudget);
    this.db.addBlackboxEvidence(pid, sessionId, { kind: "run-summary", source: "nianyun", summary: `任务状态：${stopReason}；完。${lists.completed_tasks.length}，失。${lists.failed_tasks.length}，受。${lists.blocked_tasks.length}，未执行/未完。${lists.pending_tasks.length}`, confidence: "high", data: { budget: finalBudget, ...lists, tasks: progress.state.tasks, advice: progress.state.advice, plan_revision: progress.state.planRevision, endpoints: progress.state.endpoints, acceptance: progress.state.supervision?.acceptance } });
    // partial_completed（有结论也有受阻项）同样算完成：评估已收口，受阻项在报告里单列。
    // settledCompleted 覆盖「预算/熔断耗尽、剩余任务已逐条给结论」的收口路径：
    // 此时 stopReason 仍是 tool_budget_exhausted 之类，但评估本身已经可以交付。
    /**
     * 门禁全放行（2026-11-06）：**审查状态不再参与收口判定**。
     *
     * 旧判据是 `&& (!reviewPending || reviewDropped)`——只要还有一个"没人看过"的挂账，
     * 任务全做完、报告全能交付，会话也照样落 paused/awaiting_operator 等操作员点一下。
     * 实测 e8bdb447acf02283 就是这么在 418s 停掉的：4 个待办没跑，还白扔 300s 预算。
     * 审查是辅助结论强度的，不是交付的许可证；它缺了就在 acceptance.reason_codes 里
     * 如实写着（TERMINAL_REVIEW_PENDING），报告照常按"未评审"呈现。
     */
    const finished = isCompletedVerdict(stopReason) || settledCompleted;
    this.db.updateBlackboxSession(pid, sessionId, { status: stopReason === "operator_cancelled" ? "cancelled" : finished ? "completed" : "paused", phase: "awaiting_operator" });
    // 只有真正结束（完成/取消）才清 /state；paused 要留着给操作员恢复会话用。
    if (stopReason === "operator_cancelled" || finished) {
      void clearSandboxState(this.cfg.tools_env?.values, pid, sessionId);
    }
    return { ok: true, session: this.db.getBlackboxSession(pid, sessionId) };
    } catch (error) {
      // Includes failures in the final review gate itself. Never leave a live
      // session marked running or write a guessed checkpoint after a failed CAS.
      const message = error instanceof Error ? error.message : String(error);
      const current = this.db.getBlackboxSession(pid, sessionId);
      if (current && current.status !== "cancelled") this.db.updateBlackboxSession(pid, sessionId, { status: "paused", phase: "awaiting_operator" });
      this.db.addBlackboxEvent(pid, sessionId, "system", "review-persistence-failed", `审查或检查点持久化失败：${message}`, { error: message, recoverable: true });
      return { ok: false, error: message, session: this.db.getBlackboxSession(pid, sessionId) };
    } finally {
      this.blackboxAbort.delete(`${pid}:${sessionId}`);
    }
  }

  /** 时光机：快照列表（控制台"历史 run"下拉的数据源）。*/
  listProjectBlackboxCheckpoints(projectId: string, sessionId: string, limit = 50): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    if (!this.db.getBlackboxSession(pid, sessionId)) return { ok: false, error: "blackbox session not found" };
    return { ok: true, items: this.db.listBlackboxCheckpoints(pid, sessionId, limit) };
  }

  /**
   * 从快。fork：同一初始账本、新 session id，用来做"改前/改后"的平行对照。
   * 不复制证据与事件（它们是运行产物）；需要历史证据时用原会话。evidence 查询。
   */
  forkProjectBlackboxSession(projectId: string, sessionId: string, payload: Record<string, unknown> = {}): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    if (!this.db.getBlackboxSession(pid, sessionId)) return { ok: false, error: "blackbox session not found" };
    const list = this.db.listBlackboxCheckpoints(pid, sessionId, 200);
    if (!list.length) return { ok: false, error: "该会话还没有归档过快照：跑一。run 会自动归。" };
    const wanted = Number(payload.checkpoint_id || 0);
    const target = wanted ? list.find(item => item.id === wanted) : list[0];
    if (!target) return { ok: false, error: "checkpoint not found" };
    const checkpoint = this.db.getBlackboxCheckpoint(pid, sessionId, target.id);
    if (!checkpoint) return { ok: false, error: "checkpoint 内容损坏或不存在" };
    try {
      const session = this.db.forkBlackboxSession(pid, sessionId, checkpoint, target.run_index);
      return { ok: true, session, source: { session_id: sessionId, checkpoint_id: target.id, run_index: target.run_index } };
    } catch (error) { return { ok: false, error: String(error) }; }
  }

  startProjectBlackboxAgents(projectId: string, sessionId: string): Record<string, unknown> {
    this.execution("start blackbox agents");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const session = this.db.getBlackboxSession(pid, sessionId);
    if (!session) return { ok: false, error: "blackbox session not found" };
    const key = `${pid}:${sessionId}`;
    if (session.status === "running" || this.blackboxFlight.has(key) || this.blackboxAbort.has(key)) return { ok: false, error: "blackbox session is already running" };
    if (session.status === "cancelled") return { ok: false, error: "blackbox session is cancelled" };
    if ((session.environment as Record<string, unknown> | undefined)?.ready !== true) return { ok: false, error: "environment check must pass before Agent analysis" };
    if (!this.db.getAssetCandidate(pid, String(session.candidate_id || ""))) return { ok: false, error: "candidate not found" };
    this.blackboxFlight.add(key);
    void this.runProjectBlackboxAgents(pid, sessionId)
      .catch((error) => console.warn(`[blackbox] background run failed: ${error}`))
      .finally(() => this.blackboxFlight.delete(key));
    return { ok: true, started: true, session: this.db.getBlackboxSession(pid, sessionId) };
  }

  private blackboxBudget(): { timeMs: number; wallClockMs: number; toolCalls: number; agentTurns: number; tokens: number; cost: number; retries: number } {
    const rules = blackboxRules(this.cfg.tools_env.values);
    return {
      // timeMs 只算调度时间（思，决策）；工具执行耗时单独记账，受 wallClockMs 约束。
      timeMs: rules.budgets.time_sec * 1000,
      wallClockMs: rules.budgets.wall_clock_sec * 1000,
      toolCalls: rules.budgets.tool_calls,
      agentTurns: rules.budgets.agent_turns,
      tokens: rules.budgets.tokens,
      cost: rules.budgets.cost,
      retries: rules.budgets.retries,
    };
  }

  async reviewProjectAssets(projectId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.execution("asset review");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const ruleVersion = String(this.cfg.tools_env.values.ASSET_AGENT_RULE_VERSION || ASSET_RULE_VERSION);
    const rescore = payload.rescore === true;
    const retryFailed = payload.retry_failed === true;
    const explicit = Array.isArray(payload.candidate_ids) ? [...new Set(payload.candidate_ids.map(String).filter(Boolean))].slice(0, 5000) : null;
    const failedCount = this.db.listFailedAssetCandidates(pid, 5000).length;
    let ids: string[];
    let skipped = 0;
    let retried = 0;
    if (explicit) {
      if (rescore || retryFailed) {
        ids = explicit;
        retried = retryFailed ? explicit.length : 0;
      } else {
        const pending = new Set(this.db.pendingAssetCandidateIds(pid, explicit, ruleVersion));
        ids = explicit.filter((id) => pending.has(id));
        skipped = explicit.length - ids.length;
      }
    } else if (rescore) {
      ids = this.db.listAssetCandidates(pid, { limit: 5000 }).map((row) => String(row.id));
    } else if (retryFailed) {
      ids = this.db.listFailedAssetCandidates(pid, 5000).map((row) => String(row.id));
      retried = ids.length;
      skipped = Math.max(0, this.db.listAssetCandidates(pid, { limit: 5000 }).length - ids.length);
    } else {
      ids = this.db.listUnscoredAssetCandidates(pid, ruleVersion, 5000).map((row) => String(row.id));
      skipped = Math.max(0, this.db.listAssetCandidates(pid, { limit: 5000 }).length - ids.length);
    }
    try {
      if (!ids.length) {
        return {
          ok: true, queued: 0, skipped, failed: failedCount, retried, rule_version: ruleVersion, job: null,
          message: retryFailed
            ? "没有评分失败的候选资产"
            : skipped ? `${skipped} 个候选资产无需再评分（已评分、评分失败或不在该分组内），本次跳过` : "没有可评分的候选资产",
        };
      }
      const job = this.db.createAssetReviewJob(pid, ids, ruleVersion);
      // Never leave this rejection unhandled: it used to take the whole console process down.
      void this.runAssetReviewJob(pid, String(job.id)).catch((error) => {
        const message = String(error instanceof Error ? error.message : error);
        try { this.db.failAssetReviewJob(pid, String(job.id), message); } catch { /* job already closed */ }
        console.warn(`[asset-review] job ${String(job.id)} failed: ${message}`);
      });
      return { ok: true, job, queued: ids.length, skipped, failed: failedCount, retried, rule_version: ruleVersion };
    } catch (error) { return { ok: false, error: String(error instanceof Error ? error.message : error) }; }
  }

  projectAssetReviewJobs(projectId: string, limit?: number): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, items: this.db.listAssetReviewJobs(pid, limit) };
  }

  private async runAssetReviewJob(projectId: string, jobId: string): Promise<void> {
    // Batches share one browser: a Chromium launch per candidate is what made long queues crawl.
    const batchSize = 6;
    while (true) {
      const batch: Record<string, unknown>[] = [];
      for (let index = 0; index < batchSize; index++) {
        const candidate = this.db.nextAssetReviewCandidate(projectId, jobId);
        if (!candidate) break;
        this.db.updateAssetReviewItem(projectId, jobId, String(candidate.id), "running");
        batch.push(candidate);
      }
      if (!batch.length) return;
      const outcomes = await reviewAssetCandidates(this.cfg, this.db, projectId, batch, 2);
      for (const candidate of batch) {
        const id = String(candidate.id);
        const outcome = outcomes.get(id) || { ok: false, error: "review worker returned no result" };
        // A failed attempt is recorded on the candidate too, so the default queue skips it and
        // a dead host does not burn another browser run and model call on the next click.
        if (!outcome.ok) this.db.markAssetCandidateReviewFailed(projectId, id, outcome.error || "review failed");
        this.db.updateAssetReviewItem(projectId, jobId, id, outcome.ok ? "completed" : "failed", outcome.error);
      }
    }
  }

  deleteProjectCandidates(projectId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const raw = Array.isArray(payload.candidate_ids) ? payload.candidate_ids.map(String) : [];
    const result = this.db.deleteAssetCandidates(pid, raw);
    const root = resolve(join(this.cfg.data_dir, "asset-screenshots", pid));
    for (const relativePath of result.screenshots) {
      const path = resolve(join(this.cfg.data_dir, relativePath));
      if (path !== root && path.startsWith(`${root}${sep}`)) { try { unlinkSync(path); } catch { /* already removed */ } }
    }
    return { ok: true, deleted: result.deleted };
  }

  deleteProjectProbeJob(projectId: string, jobId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return this.db.deleteAssetProbeJob(pid, jobId);
  }

  deleteProjectBlackboxSession(projectId: string, sessionId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const result = this.db.deleteBlackboxSession(pid, sessionId);
    if (!result.ok) return result;
    // A deleted session must not keep a headless browser pointed at its target.
    void closeBrowserSessions(pid, sessionId);
    // Artifacts live under blackbox-artifacts/<project>/<session>/ (see blackbox/tools.ts).
    const root = resolve(join(this.cfg.data_dir, "blackbox-artifacts", pid, sessionId));
    for (const relativePath of result.artifacts || []) {
      const path = resolve(join(this.cfg.data_dir, relativePath));
      if (path !== root && path.startsWith(`${root}${sep}`)) { try { unlinkSync(path); } catch { /* already removed */ } }
    }
    return { ok: true, events: result.events || 0, evidence: result.evidence || 0, artifacts: (result.artifacts || []).length };
  }

  /**
   * 批量删除黑盒会话（会话列表多。/ 清空项目都走这里）。
   *
   * `all: true` 时删掉该项目下所。*非运行中**的会话；运行中的单独列进 skipped。
   * 让调用方知道"还剩几条在跑、为什么没。。
   */
  deleteProjectBlackboxSessions(projectId: string, payload: { ids?: string[]; all?: boolean }): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const ids = Array.isArray(payload.ids) ? payload.ids.map(id => String(id)).filter(Boolean) : [];
    const targets = payload.all
      ? this.db.listBlackboxSessions(pid, 500).map(session => String(session.id))
      : ids;
    if (!targets.length) return { ok: false, error: "没有要删除的会话" };
    const result = this.db.deleteBlackboxSessions(pid, targets);
    for (const sessionId of result.deleted) {
      void closeBrowserSessions(pid, sessionId);
      // 产物文件。blackbox-artifacts/<project>/<session>/ 下，随会话一起清掉。
      const root = resolve(join(this.cfg.data_dir, "blackbox-artifacts", pid, sessionId));
      try { rmSync(root, { recursive: true, force: true }); } catch { /* 已不存在 */ }
    }
    return { ...result, ok: true, requested: targets.length };
  }

  assetScreenshot(projectId: string, candidateId: string): Buffer | null {
    const pid = workspace.safeProjectId(projectId);
    const candidate = pid ? this.db.getAssetCandidate(pid, candidateId) : null;
    if (!candidate?.screenshot_path) return null;
    const path = join(this.cfg.data_dir, String(candidate.screenshot_path));
    const safePid = pid || "";
    const root = resolve(join(this.cfg.data_dir, "asset-screenshots", safePid));
    const resolvedPath = resolve(path);
    if (resolvedPath !== root && !resolvedPath.startsWith(`${root}${sep}`)) return null;
    try { return readFileSync(path); } catch { return null; }
  }

  blackboxArtifact(projectId: string, sessionId: string, filename: string): { body: Buffer; contentType: string } | null {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !this.db.getBlackboxSession(pid, sessionId) || !/^[a-zA-Z0-9._-]+$/.test(filename)) return null;
    const root = resolve(join(this.cfg.data_dir, "blackbox-artifacts", pid, sessionId));
    const path = resolve(join(root, filename));
    if (!path.startsWith(`${root}${sep}`)) return null;
    try {
      return { body: readFileSync(path), contentType: filename.endsWith(".png") ? "image/png" : "application/x-ndjson; charset=utf-8" };
    } catch { return null; }
  }

  async discoverProjectArl(projectId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.execution("ARL discovery");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    try {
      const result = await discoverArl({
        db: this.db, projectId: pid, values: this.cfg.tools_env.values,
        target: typeof payload.target === "string" ? payload.target : undefined,
        targets: Array.isArray(payload.targets) ? payload.targets.map(String) : undefined,
        taskIds: Array.isArray(payload.task_ids) ? payload.task_ids.map(String) : undefined,
        wait: payload.wait === true,
        brute: typeof payload.brute === "string" ? payload.brute : undefined,
        scan: payload.scan && typeof payload.scan === "object" && !Array.isArray(payload.scan) ? payload.scan as Record<string, unknown> : undefined,
        includeIps: payload.include_ips !== false,
      });
      const targetList = Array.isArray(result.targets) ? result.targets.map(String).join(", ") : String(result.target || "");
      atomicWrite(join(this.cfg.data_dir, "console", `arl-${pid}.json`), JSON.stringify({
        target: targetList, targets: result.targets || [], wildcard: result.wildcard === true,
        task_ids: result.task_ids, tasks: result.tasks || [], scan: result.scan || {}, updated_at: Date.now(),
      }));
      return result;
    } catch (error) {
      return { ok: false, error: String(error instanceof Error ? error.message : error) };
    }
  }

  projectArlTask(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const path = join(this.cfg.data_dir, "console", `arl-${pid}.json`);
    return { ok: true, ...(existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : { task_ids: [] }) };
  }

  async checkFofa(): Promise<Record<string, unknown>> {
    try { return await checkFofa(this.cfg.tools_env.values); }
    catch (error) { return { ok: false, error: String(error instanceof Error ? error.message : error) }; }
  }

  async discoverProjectFofa(projectId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.execution("FOFA discovery");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    try {
      const result = await discoverFofa({
        db: this.db, projectId: pid, values: this.cfg.tools_env.values,
        target: String(payload.target || ""),
        query: typeof payload.query === "string" ? payload.query : undefined,
        size: payload.size === undefined ? undefined : Number(payload.size),
        strategies: Array.isArray(payload.strategies) ? payload.strategies.map(String) : undefined,
        scope: payload.scope === "any" ? "any" : undefined,
      });
      atomicWrite(join(this.cfg.data_dir, "console", `fofa-${pid}.json`), JSON.stringify({
        target: result.target, wildcard: result.wildcard === true, query: result.query, queries: result.queries || [],
        strategies: result.strategies || [], last_count: result.accepted, remain_query: result.remain_query, updated_at: Date.now(),
      }));
      return result;
    } catch (error) {
      return { ok: false, error: String(error instanceof Error ? error.message : error) };
    }
  }

  projectFofaState(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const path = join(this.cfg.data_dir, "console", `fofa-${pid}.json`);
    return { ok: true, ...(existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {}) };
  }

  importProjectCandidates(projectId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    try {
      const raw = payload.candidates ?? payload.items ?? payload.assets ?? payload.content;
      const parsed = parseCandidateImport(raw, String(payload.format || "auto"), String(payload.source || "import"));
      return { ok: true, ...importAssetCandidates(this.db, pid, parsed) };
    } catch (error) {
      return { ok: false, error: String(error instanceof Error ? error.message : error) };
    }
  }

  reviewProjectCandidate(projectId: string, candidateId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const status = String(payload.status || "review");
    if (!["candidate", "review", "selected", "rejected"].includes(status)) return { ok: false, error: "invalid candidate status" };
    const tags = Array.isArray(payload.tags) ? payload.tags.map(String) : undefined;
    const score = payload.score === undefined ? undefined : Number(payload.score);
    if (score !== undefined && (!Number.isFinite(score) || score < 0 || score > 100)) return { ok: false, error: "candidate score must be 0-100" };
    const row = this.db.updateAssetCandidate(pid, candidateId, { status, tags, score });
    return row ? { ok: true, candidate: row } : { ok: false, error: "candidate not found" };
  }

  createProjectProbeJob(projectId: string, payload: Record<string, unknown>): Record<string, unknown> {
    this.execution("create probe job");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const ids = Array.isArray(payload.candidate_ids) ? payload.candidate_ids.map(String) : [];
    try {
      return { ok: true, job: this.db.createAssetProbeJob(pid, ids, {
        concurrency: Math.max(1, Math.min(Number(payload.concurrency) || 2, 8)),
        threshold: Number(payload.threshold),
      }) };
    } catch (error) {
      return { ok: false, error: String(error instanceof Error ? error.message : error) };
    }
  }

  projectProbeJobs(projectId: string, limit?: number): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, items: this.db.listAssetProbeJobs(pid, limit) };
  }

  updateProjectProbeJob(projectId: string, jobId: string, status: "queued" | "running" | "paused" | "cancelled"): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const job = this.db.setAssetProbeJobStatus(pid, jobId, status);
    return job ? { ok: true, job } : { ok: false, error: "probe job not found" };
  }

  async runProjectProbeJob(projectId: string, jobId: string): Promise<Record<string, unknown>> {
    this.execution("asset probe");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return runAssetProbeJob(this.db, pid, jobId, { max_rps: 1, max_concurrency: 2, tls_mode: "strict" });
  }

  projectAssetMap(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, ...buildAssetMap(this.db, pid) };
  }

  projectAssetObservations(projectId: string, assetId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const asset = this.db.getAsset(pid, assetId);
    if (!asset) return { ok: false, error: "asset not found" };
    return { ok: true, asset, observations: this.db.listAssetObservations(pid, assetId) };
  }

  importProjectAssets(projectId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const raw = payload.assets ?? payload.items;
    if (!Array.isArray(raw)) return { ok: false, error: "assets must be an array" };
    const result = importAssets(this.db, pid, raw);
    return { ok: true, ...result };
  }

  async discoverProjectAssets(projectId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.execution("asset discovery");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const raw = payload.seeds ?? payload.urls;
    if (!Array.isArray(raw)) return { ok: false, error: "seeds must be an array" };
    const seeds = raw.map((value) => typeof value === "string" ? { value } : value).filter((value): value is { value: string; source?: string } => Boolean(value && typeof value === "object" && typeof value.value === "string"));
    if (!seeds.length) return { ok: false, error: "at least one HTTP seed is required" };
    return { ok: true, ...(await discoverHttpSeeds(this.db, pid, seeds)) };
  }

  projectFindings(projectId: string, opts: { limit?: number; status?: string } = {}): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    return { ok: true, items: this.db.listFindings(pid, opts) };
  }

  async validateProjectAssets(projectId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.execution("asset validation");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const rawIds = payload.asset_ids ?? payload.assets;
    const ids = Array.isArray(rawIds) ? rawIds.map(String).filter(Boolean).slice(0, 100) : [];
    const assets = ids.length
      ? ids.map((id) => this.db.getAsset(pid, id)).filter((asset): asset is Record<string, unknown> => Boolean(asset))
      : this.db.listAssets(pid, { limit: 100 });
    const checked: string[] = [];
    const errors: Array<{ asset_id: string; error: string }> = [];
    const findings: Record<string, unknown>[] = [];
    for (const asset of assets) {
      const result = await validateHttpAsset(this.db, pid, asset);
      if (result.checked) checked.push(String(asset.id));
      if (result.error) errors.push({ asset_id: String(asset.id), error: result.error });
      findings.push(...result.findings);
    }
    return { ok: true, checked, errors, findings };
  }

  updateProjectAutomation(projectId: string, payload: Record<string, unknown>): Record<string, unknown> {
    const raw = payload.automation && typeof payload.automation === "object" ? payload.automation : payload;
    try {
      const rec = workspace.setProjectAutomation(this.cfg, projectId, raw);
      if (!rec) return { ok: false, error: "project not found" };
      rec.ok = true;
      return rec;
    } catch (error) {
      return { ok: false, error: String(error instanceof Error ? error.message : error) };
    }
  }

  async runProjectAutomation(projectId: string): Promise<Record<string, unknown>> {
    this.execution("asset automation");
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    if (this.automationFlight.has(pid)) return { ok: false, error: "automation already running" };
    const automation = workspace.getProjectAutomation(this.cfg, pid);
    if (!automation?.enabled) return { ok: false, error: "automation is not enabled" };
    this.automationFlight.add(pid);
    try {
      const output: Record<string, unknown> = { discovered: null, validated: null, scored: false };
      if (automation.discover) {
        const discovered = await this.discoverProjectAssets(pid, { seeds: automation.seeds });
        output.discovered = discovered;
        if (!discovered.ok) throw new Error(String(discovered.error || "asset discovery failed"));
      }
      if (automation.validate) {
        const validated = await this.validateProjectAssets(pid, {});
        output.validated = validated;
        if (!validated.ok) throw new Error(String(validated.error || "asset validation failed"));
      }
      if (automation.score) {
        output.scored = Boolean(this.recalculateProjectRisk(pid).ok);
      }
      const next = { ...automation, last_run_at: Math.floor(Date.now() / 1000), last_status: "ok" };
      delete next.last_error;
      workspace.setProjectAutomation(this.cfg, pid, next);
      return { ok: true, ...output };
    } catch (error) {
      const next = { ...automation, last_run_at: Math.floor(Date.now() / 1000), last_status: "failed", last_error: String(error instanceof Error ? error.message : error) };
      workspace.setProjectAutomation(this.cfg, pid, next);
      return { ok: false, error: next.last_error };
    } finally {
      this.automationFlight.delete(pid);
    }
  }

  private async runDueAutomations(): Promise<void> {
    this.execution("due automations");
    const now = Math.floor(Date.now() / 1000);
    for (const project of workspace.listProjects(this.cfg)) {
      const pid = String(project.id || "");
      const automation = workspace.getProjectAutomation(this.cfg, pid);
      if (!automation?.enabled || now < Number(automation.last_run_at || 0) + automation.interval_sec) continue;
      await this.runProjectAutomation(pid);
    }
  }

  recalculateProjectRisk(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    const assets = this.db.listAssets(pid, { limit: 1000 });
    const findings = this.db.listFindings(pid, { limit: 1000 });
    const scored = scoreProject(assets, findings);
    for (const row of scored) this.db.updateAssetRiskScore(pid, String(row.asset.id), row.score);
    return { ok: true, items: this.db.listAssets(pid, { limit: 1000 }) };
  }

  projectReport(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    const project = pid ? workspace.getProject(this.cfg, pid) : null;
    if (!pid || !project) return { ok: false, error: "project not found" };
    const assets = this.db.listAssets(pid, { limit: 1000 });
    const findings = this.db.listFindings(pid, { limit: 1000 });
    return { ok: true, format: "markdown", content: buildProjectReport({ project, assets, findings }) };
  }



  purgeProject(projectId: string): Record<string, unknown> {
    const pid = workspace.safeProjectId(projectId);
    if (!pid || !workspace.getProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    for (const session of this.db.listBlackboxSessions(pid, 500)) {
      const key = `${pid}:${String(session.id)}`;
      this.blackboxAbort.get(key)?.abort(new Error("project deleted"));
      this.blackboxAbort.delete(key);
    }
    const stats = this.db.purgeProjectRecords(pid);
    if (!workspace.deleteProject(this.cfg, pid)) return { ok: false, error: "project not found" };
    for (const dir of [
      join(this.cfg.data_dir, "projects", pid),
      join(this.cfg.data_dir, "asset-screenshots", pid),
      join(this.cfg.data_dir, "blackbox-artifacts", pid),
      join(this.cfg.data_dir, "console", `arl-${pid}.json`),
    ]) {
      try { rmTree(dir); } catch { /* best effort */ }
    }
    return { ok: true, deleted: stats };
  }
}


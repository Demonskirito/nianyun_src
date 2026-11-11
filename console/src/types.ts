/** Console data contracts. These mirror the SRC asset / blackbox console API. */

export type ExecutionMode = "inspect" | "serve" | "execute";

export type ExecutionPolicy = {
  mode: ExecutionMode;
  source: "default" | "config" | "environment";
};

/** GET /api/status */
export type ConsoleStatus = {
  ok?: boolean;
  service?: string;
  execution?: ExecutionPolicy;
  project_count?: number;
  candidate_count?: number;
  session_count?: number;
  active_sessions?: number;
  finding_count?: number;
};

export type AssetAutomation = {
  enabled: boolean;
  interval_sec: number;
  seeds: Array<{ value: string; source?: string }>;
  discover: boolean;
  validate: boolean;
  score: boolean;
  last_run_at?: number;
  last_status?: string;
  last_error?: string;
};

export type Asset = {
  id: string;
  project_id: string;
  kind: string;
  value: string;
  hostname?: string | null;
  port?: number | null;
  protocol?: string | null;
  url?: string | null;
  title?: string | null;
  technologies?: string[];
  source?: string;
  status?: string;
  risk_score?: number;
  first_seen?: number;
  last_seen?: number;
  evidence?: Record<string, unknown>;
};

export type AssetCandidate = Asset & {
  status?: "candidate" | "queued" | "running" | "completed" | "review" | "selected" | "rejected" | "failed";
  score?: number;
  agent_score?: number | null;
  score_reasons?: Record<string, unknown> | string[];
  screenshot_path?: string | null;
  score_rule_version?: string | null;
  review_attempts?: number | null;
  review_error?: string | null;
  page_evidence?: Record<string, unknown>;
  tags?: string[];
  http_status?: number | null;
  response_time_ms?: number | null;
  error?: string | null;
};

export type AssetProbeJob = {
  id: string;
  project_id: string;
  status: "queued" | "running" | "paused" | "cancelled" | "completed" | "failed";
  concurrency: number;
  threshold: number;
  total: number;
  completed: number;
  skipped: number;
  failed: number;
  error?: string | null;
  created_at?: number;
  updated_at?: number;
};

export type AssetReviewJob = {
  id: string;
  project_id: string;
  status: "queued" | "running" | "completed";
  total: number;
  completed: number;
  failed: number;
  current_candidate_id?: string | null;
  rule_version?: string | null;
  error?: string | null;
};

export type Finding = {
  id: string;
  asset_id?: string;
  check_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  confidence?: string;
  description?: string | null;
  evidence?: Record<string, unknown>;
  first_seen?: number;
  last_seen?: number;
};

export type AssetMapNode = {
  id: string;
  label?: string;
  group?: string;
  sub?: string;
  status?: string;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  summary?: { conclusion: string; basis: string; uncertainty: string | null };
  steps?: Array<{ id: string; action: string; result: string; assessment: string | null; evidenceRefs: string[] }>;
  evidenceRefs?: string[];
};

export type AssetMap = {
  schemaVersion?: string;
  publication?: { jobId?: string; revision?: string; phase?: string; publishedAt?: number };
  width?: number;
  height?: number;
  view?: { nodes?: AssetMapNode[]; edges?: Array<{ from: string; to: string }> };
};

export type Project = {
  id: string;
  name: string;
  note?: string;
  settings?: Record<string, unknown>;
  automation?: AssetAutomation | null;
  created_at?: number;
  updated_at?: number;
  candidate_count?: number;
  session_count?: number;
  running?: number;
  finding_count?: number;
  candidates?: AssetCandidate[];
  sessions?: BlackboxSession[];
  asset_map?: AssetMap | null;
};

export type LlmKeyState = {
  set?: boolean;
  value?: string;
  preview?: string;
};

export type LlmGroup = Record<string, LlmKeyState>;

/** GET /api/settings → llm.{asset,arl,blackbox} */
export type LlmSettings = {
  asset?: LlmGroup;
  arl?: LlmGroup;
  fofa?: LlmGroup;
  blackbox?: LlmGroup;
};

export type ToolInfo = {
  id: string;
  name: string;
  purpose: string;
  family: string;
  agent: string;
  built_in: boolean;
  configured: boolean;
  status: string;
  risk?: string;
};

export type RulesState = {
  version: number;
  hash: string;
  credential_tools: string[]; active_scan_tools?: string[];
  issues: string[];
  valid: boolean;
  fallback: boolean;
};

export type ToolsPayload = {
  ok?: boolean;
  error?: string;
  rules?: RulesState;
  tools?: ToolInfo[];
  agents?: Array<{ id: string; name: string; purpose: string; status: string; tools: string[] }>;
  sessions?: Array<{ id: string; project_id: string; project_name: string; target: string; status: string; phase?: string; updated_at: number; used_tools?: string[] }>;
};

export type SettingsBundle = {
  ok?: boolean;
  llm?: LlmSettings;
  tools?: ToolsPayload;
  error?: string;
};

export type ToolHealthState = "failing" | "degraded" | "unconfigured" | "healthy" | "idle";

export type ToolHealthRow = {
  tool: string;
  name: string;
  family: string;
  risk: string;
  configured: boolean;
  state: ToolHealthState;
  executions: number;
  successes: number;
  failures: number;
  timeouts: number;
  rejections: number;
  success_rate: number;
  avg_ms: number;
  p95_ms: number;
  last_used_at: number | null;
  last_error: string | null;
  sessions: number;
};

/** GET /api/tool-health */
export type ToolHealthPayload = {
  ok?: boolean;
  error?: string;
  updated_at?: number;
  window_seconds?: number;
  project_id?: string | null;
  totals?: {
    tools: number;
    used: number;
    executions: number;
    successes: number;
    failures: number;
    timeouts: number;
    rejections: number;
    success_rate: number;
    avg_ms: number;
    sessions: number;
    projects: number;
  };
  tools?: ToolHealthRow[];
};

export type BlackboxEnvironment = {
  checked_at?: number;
  ready?: boolean;
  burp?: { configured?: boolean; reachable?: boolean; required?: boolean; proxy_url?: string; error?: string; bridge_configured?: boolean; bridge_url?: string; bridge_reachable?: boolean; bridge_error?: string };
  /** 目标可达性探测：工具链全通但目标下线时，ready 为 false 的唯一原因就是它。 */
  target?: { url?: string; reachable?: boolean; code?: string; status?: number; bytes?: number; elapsed_ms?: number; via_proxy?: boolean; reason?: string };
  tools?: Array<{ id: string; label: string; configured: boolean; value?: string }>;
};

export type BlackboxEvent = {
  id: number;
  actor: "system" | "operator" | "agent" | "observer";
  kind: string;
  text: string;
  data?: Record<string, unknown>;
  created_at: number;
};

export type BlackboxEvidence = {
  id: string;
  kind: string;
  source: string;
  summary: string;
  confidence: string;
  data?: Record<string, unknown>;
  artifact_path?: string | null;
  created_at: number;
};

export type AuthSeed = {
  host: string;
  file: string;
  cookies: number;
  origins: number;
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  updated_at: number;
};

export type AuthSeedList = { ok?: boolean; seeds?: AuthSeed[]; error?: string };
export type SaveSeedResult = { ok?: boolean; host?: string; file?: string; error?: string };

export type BlackboxSession = {
  checkpoint?: {
    findings?: Record<string, { id: string; title: string; target: string; status: string; severity: string; description: string; impact: string; reproduction_steps: string[]; evidence_ids: string[]; remediation: string; review?: { actor: string; reason: string } }>;
    planRevision?: number;
    tasks?: Record<string, { status: string; target?: string; purpose?: string; reason?: string; completion_criteria?: string; outcome_code?: string; outcome_reason?: string; outcome_evidence_ids?: string[]; outcome_by?: string; evidence_ids?: string[] }>;
    advice?: Record<string, { status: string; reason?: string; task_ids?: string[] }>;
    endpoints?: Record<string, { evidence_ids: string[]; task_ids: string[] }>;
    credential_tools?: string[];
    rule_issues?: string[];
  };
  id: string;
  project_id: string;
  candidate_id: string;
  target: string;
  status: "pending" | "ready" | "running" | "paused" | "failed" | "completed" | "cancelled";
  phase: string;
  environment?: BlackboxEnvironment;
  events?: BlackboxEvent[];
  evidence?: BlackboxEvidence[];
  /** 时间线 / 证据总数（详情接口返回，前端分页用）；分页加载前即可显示计数。 */
  event_count?: number;
  evidence_count?: number;
  /** 单条 run-summary 证据（详情接口内联，避免前端全量拉取后还要 find）。 */
  run_summary?: BlackboxEvidence | null;
  cookie_count?: number;
  cookies?: Array<{ name: string; domain: string; path: string; expires: number | null }>;
  created_at: number;
  updated_at: number;
};

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import type { NormalizedAsset } from "../asset/model.js";
import { cookieSummary, mergeCookies, type CookieRecord } from "../blackbox/cookies.js";

// Resolve the Node 22 builtin at runtime so Vite/Vitest do not try to bundle it.
const { DatabaseSync: DatabaseSyncCtor } = createRequire(import.meta.url)("node:sqlite") as typeof import("node:sqlite");
type DatabaseSync = import("node:sqlite").DatabaseSync;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS deleted_projects (
  project_id TEXT PRIMARY KEY, workspace_root TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  hostname TEXT,
  port INTEGER,
  protocol TEXT,
  url TEXT,
  title TEXT,
  technologies_json TEXT,
  source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  risk_score REAL DEFAULT 0,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  evidence_json TEXT,
  UNIQUE(project_id, kind, value, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id, last_seen DESC);
CREATE TABLE IF NOT EXISTS asset_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  observed_at REAL NOT NULL,
  source TEXT NOT NULL,
  data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_observations_asset ON asset_observations(asset_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate',
  confidence TEXT NOT NULL DEFAULT 'medium',
  description TEXT,
  evidence_json TEXT NOT NULL,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  UNIQUE(project_id, asset_id, check_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, status, severity, last_seen DESC);
CREATE TABLE IF NOT EXISTS asset_candidates (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  hostname TEXT,
  port INTEGER,
  protocol TEXT,
  url TEXT,
  title TEXT,
  technologies_json TEXT,
  source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate',
  score REAL DEFAULT 0,
  tags_json TEXT NOT NULL DEFAULT '[]',
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  http_status INTEGER,
  response_time_ms INTEGER,
  evidence_json TEXT,
  error TEXT,
  agent_score REAL,
  score_reasons_json TEXT,
  screenshot_path TEXT,
  score_rule_version TEXT,
  page_evidence_json TEXT,
  UNIQUE(project_id, kind, value, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_asset_candidates_project ON asset_candidates(project_id, status, score DESC, last_seen DESC);
CREATE TABLE IF NOT EXISTS asset_probe_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  concurrency INTEGER NOT NULL DEFAULT 3,
  threshold REAL NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0,
  completed INTEGER NOT NULL DEFAULT 0,
  skipped INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  started_at REAL,
  finished_at REAL,
  updated_at REAL NOT NULL,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_asset_probe_jobs_project ON asset_probe_jobs(project_id, created_at DESC);
CREATE TABLE IF NOT EXISTS asset_probe_queue (
  job_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  queued_at REAL NOT NULL,
  started_at REAL,
  finished_at REAL,
  error TEXT,
  PRIMARY KEY(job_id, candidate_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_probe_queue_job ON asset_probe_queue(job_id, status);
CREATE TABLE IF NOT EXISTS asset_review_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  total INTEGER NOT NULL DEFAULT 0,
  completed INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  current_candidate_id TEXT,
  rule_version TEXT,
  created_at REAL NOT NULL,
  started_at REAL,
  finished_at REAL,
  updated_at REAL NOT NULL,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_asset_review_jobs_project ON asset_review_jobs(project_id, created_at DESC);
CREATE TABLE IF NOT EXISTS asset_review_queue (
  job_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  error TEXT,
  started_at REAL,
  finished_at REAL,
  PRIMARY KEY(job_id, candidate_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_review_queue_job ON asset_review_queue(job_id, status);
CREATE TABLE IF NOT EXISTS blackbox_sessions (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  phase TEXT NOT NULL DEFAULT 'environment_check',
  environment_json TEXT NOT NULL DEFAULT '{}',
  checkpoint_json TEXT NOT NULL DEFAULT '{}',
  cookies_json TEXT NOT NULL DEFAULT '[]',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blackbox_sessions_project ON blackbox_sessions(project_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS blackbox_checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  run_index INTEGER NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  checkpoint_json TEXT NOT NULL DEFAULT '{}',
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blackbox_checkpoints_session ON blackbox_checkpoints(project_id, session_id, id DESC);
CREATE TABLE IF NOT EXISTS project_cookies (
  project_id TEXT PRIMARY KEY,
  cookies_json TEXT NOT NULL DEFAULT '[]',
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS project_tokens (
  project_id TEXT NOT NULL,
  host TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  scheme TEXT NOT NULL DEFAULT 'Bearer',
  source TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL,
  PRIMARY KEY (project_id, host, name)
);
CREATE TABLE IF NOT EXISTS blackbox_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  kind TEXT NOT NULL,
  text TEXT NOT NULL,
  data_json TEXT NOT NULL DEFAULT '{}',
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blackbox_events_session ON blackbox_events(session_id, id);
CREATE TABLE IF NOT EXISTS blackbox_evidence (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  source TEXT NOT NULL,
  summary TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'medium',
  data_json TEXT NOT NULL DEFAULT '{}',
  artifact_path TEXT,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blackbox_evidence_session ON blackbox_evidence(session_id, created_at DESC);
CREATE TABLE IF NOT EXISTS waf_bypasses (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL,
  vendor_name TEXT NOT NULL DEFAULT '',
  family TEXT NOT NULL DEFAULT 'unknown',
  signature TEXT NOT NULL DEFAULT '',
  dimension TEXT NOT NULL DEFAULT 'other',
  tactic TEXT NOT NULL,
  payload TEXT,
  host TEXT,
  project_id TEXT,
  session_id TEXT,
  evidence_id TEXT,
  source TEXT NOT NULL DEFAULT 'model',
  note TEXT,
  hits INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  last_ok_at REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_waf_bypasses_key ON waf_bypasses(vendor, dimension, tactic, COALESCE(host, ''));
CREATE INDEX IF NOT EXISTS idx_waf_bypasses_recent ON waf_bypasses(last_ok_at DESC);
`;

export class Database {
  private db: DatabaseSync;

  constructor(path: string, options: { readOnly?: boolean } = {}) {
    if (options.readOnly) {
      this.db = new DatabaseSyncCtor(path, { readOnly: true, timeout: 60000 });
      this.db.exec("PRAGMA query_only=ON");
      return;
    }
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSyncCtor(path, { timeout: 60000 });
    this.db.exec("PRAGMA journal_mode=WAL");
    this.db.exec("PRAGMA foreign_keys=ON");
    this.db.exec("PRAGMA busy_timeout=60000");
    this.db.exec(SCHEMA);
    this.db.exec("BEGIN IMMEDIATE");
    try { this.migrate(); this.db.exec("COMMIT"); }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  close(): void { this.db.close(); }

  private tableCols(table: string): Set<string> {
    const names = new Set<string>();
    try {
      const rows = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<Record<string, unknown>>;
      for (const row of rows) {
        const name = row.name ?? row[1];
        if (name != null) names.add(String(name));
      }
    } catch {
      /* missing table */
    }
    return names;
  }

  private migrate(): void {
    if (!this.tableCols("blackbox_sessions").has("checkpoint_json")) this.db.exec("ALTER TABLE blackbox_sessions ADD COLUMN checkpoint_json TEXT NOT NULL DEFAULT '{}'");
    if (!this.tableCols("blackbox_sessions").has("cookies_json")) this.db.exec("ALTER TABLE blackbox_sessions ADD COLUMN cookies_json TEXT NOT NULL DEFAULT '[]'");
    const candidateCols = this.tableCols("asset_candidates");
    for (const [name, sql] of [
      ["agent_score", "ALTER TABLE asset_candidates ADD COLUMN agent_score REAL"],
      ["score_reasons_json", "ALTER TABLE asset_candidates ADD COLUMN score_reasons_json TEXT"],
      ["screenshot_path", "ALTER TABLE asset_candidates ADD COLUMN screenshot_path TEXT"],
      ["score_rule_version", "ALTER TABLE asset_candidates ADD COLUMN score_rule_version TEXT"],
      ["page_evidence_json", "ALTER TABLE asset_candidates ADD COLUMN page_evidence_json TEXT"],
      ["review_attempts", "ALTER TABLE asset_candidates ADD COLUMN review_attempts INTEGER NOT NULL DEFAULT 0"],
      ["review_error", "ALTER TABLE asset_candidates ADD COLUMN review_error TEXT"],
    ] as const) if (!candidateCols.has(name)) this.db.exec(sql);
    this.migrateProjectCookies();
  }

  /** Move legacy per-session jars into the project-level jar exactly once. */
  private migrateProjectCookies(): void {
    const rows = this.db.prepare("SELECT project_id, cookies_json FROM blackbox_sessions WHERE cookies_json IS NOT NULL AND cookies_json != '[]'")
      .all() as Array<{ project_id: string; cookies_json: string }>;
    if (!rows.length) return;
    const now = Date.now() / 1000;
    for (const row of rows) {
      try {
        const parsed = JSON.parse(String(row.cookies_json)) as unknown;
        if (!Array.isArray(parsed) || !parsed.length) continue;
        const merged = mergeCookies(this.getProjectCookies(row.project_id), parsed as CookieRecord[], now);
        this.db.prepare("INSERT INTO project_cookies(project_id,cookies_json,updated_at) VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET cookies_json=excluded.cookies_json,updated_at=excluded.updated_at")
          .run(row.project_id, JSON.stringify(merged), now);
        this.db.prepare("UPDATE blackbox_sessions SET cookies_json='[]' WHERE project_id=?").run(row.project_id);
      } catch {
        /* ignore malformed legacy jars */
      }
    }
  }

  upsertAsset(projectId: string, asset: NormalizedAsset): Record<string, unknown> {
    const pid = (projectId || "").trim();
    if (!pid) throw new Error("asset project_id is required");
    const now = Date.now() / 1000;
    const id = randomBytes(8).toString("hex");
    const row = this.db.prepare(`
      INSERT INTO assets (
        id, project_id, kind, value, hostname, port, protocol, url, title,
        technologies_json, source, status, first_seen, last_seen, evidence_json
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(project_id, kind, value, port, protocol) DO UPDATE SET
        hostname=COALESCE(excluded.hostname, assets.hostname),
        url=COALESCE(excluded.url, assets.url),
        title=COALESCE(excluded.title, assets.title),
        technologies_json=excluded.technologies_json,
        source=excluded.source,
        status='active',
        last_seen=excluded.last_seen,
        evidence_json=excluded.evidence_json
      RETURNING *
    `).get(
      id, pid, asset.kind, asset.value, asset.hostname, asset.port ?? 0, asset.protocol ?? "", asset.url, asset.title,
      JSON.stringify(asset.technologies), asset.source, "active", now, now, JSON.stringify(asset.evidence),
    ) as Record<string, unknown>;
    return this.assetView(row);
  }

  private assetView(row: Record<string, unknown>): Record<string, unknown> {
    return {
      ...row,
      technologies: row.technologies_json ? JSON.parse(String(row.technologies_json)) : [],
      evidence: row.evidence_json ? JSON.parse(String(row.evidence_json)) : {},
    };
  }

  listAssets(projectId: string, opts: { limit?: number; status?: string } = {}): Record<string, unknown>[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const requested = Number(opts.limit || 200);
    const limit = Number.isInteger(requested) ? Math.max(1, Math.min(1000, requested)) : 200;
    const args: unknown[] = [pid];
    const status = String(opts.status || "").trim();
    const where = status ? " AND status=?" : "";
    if (status) args.push(status);
    args.push(limit);
    return (this.db.prepare(`SELECT * FROM assets WHERE project_id=?${where} ORDER BY last_seen DESC, value ASC LIMIT ?`).all(...args) as Record<string, unknown>[]).map((row) => this.assetView(row));
  }

  updateAssetRiskScore(projectId: string, assetId: string, score: number): void {
    this.db.prepare("UPDATE assets SET risk_score=? WHERE project_id=? AND id=?")
      .run(Math.max(0, Math.min(100, Number(score) || 0)), projectId, assetId);
  }

  getAsset(projectId: string, assetId: string): Record<string, unknown> | null {
    const row = this.db.prepare("SELECT * FROM assets WHERE project_id=? AND id=?").get(projectId, assetId) as Record<string, unknown> | undefined;
    return row ? this.assetView(row) : null;
  }

  addAssetObservation(projectId: string, assetId: string, source: string, data: Record<string, unknown>): number {
    const info = this.db.prepare("INSERT INTO asset_observations(asset_id,project_id,observed_at,source,data_json) VALUES(?,?,?,?,?)")
      .run(assetId, projectId, Date.now() / 1000, source, JSON.stringify(data));
    return Number(info.lastInsertRowid);
  }

  listAssetObservations(projectId: string, assetId: string, limit = 100): Record<string, unknown>[] {
    return this.db.prepare("SELECT * FROM asset_observations WHERE project_id=? AND asset_id=? ORDER BY observed_at DESC LIMIT ?")
      .all(projectId, assetId, Math.max(1, Math.min(500, limit))) as Record<string, unknown>[];
  }

  upsertFinding(opts: {
    projectId: string;
    assetId: string;
    checkId: string;
    title: string;
    severity: string;
    confidence?: string;
    description?: string;
    evidence: Record<string, unknown>;
  }): Record<string, unknown> {
    const now = Date.now() / 1000;
    const id = randomBytes(8).toString("hex");
    const row = this.db.prepare(`
      INSERT INTO findings (
        id, project_id, asset_id, check_id, title, severity, status, confidence,
        description, evidence_json, first_seen, last_seen
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(project_id, asset_id, check_id) DO UPDATE SET
        title=excluded.title,
        severity=excluded.severity,
        status='candidate',
        confidence=excluded.confidence,
        description=excluded.description,
        evidence_json=excluded.evidence_json,
        last_seen=excluded.last_seen
      RETURNING *
    `).get(
      id, opts.projectId, opts.assetId, opts.checkId, opts.title, opts.severity, "candidate",
      opts.confidence || "medium", opts.description || null, JSON.stringify(opts.evidence), now, now,
    ) as Record<string, unknown>;
    return this.findingView(row);
  }

  private findingView(row: Record<string, unknown>): Record<string, unknown> {
    return { ...row, evidence: row.evidence_json ? JSON.parse(String(row.evidence_json)) : {} };
  }

  updateAssetAgentReview(projectId: string, candidateId: string, review: {
    agentScore?: number | null;
    scoreReasons?: unknown;
    screenshotPath?: string | null;
    ruleVersion?: string | null;
    pageEvidence?: Record<string, unknown>;
  }): Record<string, unknown> | null {
    const set: string[] = ["last_seen=?"];
    const params: unknown[] = [Date.now() / 1000];
    const values: Array<[string, unknown]> = [
      ["agent_score", review.agentScore],
      ["score_reasons_json", review.scoreReasons === undefined ? undefined : JSON.stringify(review.scoreReasons)],
      ["screenshot_path", review.screenshotPath],
      ["score_rule_version", review.ruleVersion],
      ["page_evidence_json", review.pageEvidence === undefined ? undefined : JSON.stringify(review.pageEvidence)],
      ["review_error", null],
    ];
    for (const [column, value] of values) {
      if (value !== undefined) { set.push(`${column}=?`); params.push(value); }
    }
    params.push(projectId, candidateId);
    this.db.prepare(`UPDATE asset_candidates SET ${set.join(", ")} WHERE project_id=? AND id=?`).run(...params);
    return this.getAssetCandidate(projectId, candidateId);
  }

  upsertAssetCandidate(projectId: string, candidate: NormalizedAsset, tags: string[] = []): Record<string, unknown> {
    const pid = (projectId || "").trim();
    if (!pid) throw new Error("candidate project_id is required");
    const now = Date.now() / 1000;
    const normalizedTags = [...new Set(tags.map(String).map(tag => tag.trim()).filter(Boolean))].slice(0, 32);
    const existing = this.db.prepare("SELECT tags_json FROM asset_candidates WHERE project_id=? AND kind=? AND value=? AND port=? AND protocol=?")
      .get(pid, candidate.kind, candidate.value, candidate.port ?? 0, candidate.protocol ?? "") as { tags_json?: string } | undefined;
    const previousTags = existing?.tags_json ? JSON.parse(String(existing.tags_json)) as unknown : [];
    const mergedTags = [...new Set([...(Array.isArray(previousTags) ? previousTags : []), ...normalizedTags].map(String).map(tag => tag.trim()).filter(Boolean))].slice(0, 32);
    const id = randomBytes(8).toString("hex");
    const row = this.db.prepare(`
      INSERT INTO asset_candidates (
        id, project_id, kind, value, hostname, port, protocol, url, title,
        technologies_json, source, status, score, tags_json, first_seen, last_seen, evidence_json
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(project_id, kind, value, port, protocol) DO UPDATE SET
        hostname=COALESCE(excluded.hostname, asset_candidates.hostname),
        url=COALESCE(excluded.url, asset_candidates.url),
        title=COALESCE(excluded.title, asset_candidates.title),
        technologies_json=excluded.technologies_json,
        source=excluded.source,
        last_seen=excluded.last_seen,
        tags_json=excluded.tags_json,
        evidence_json=excluded.evidence_json,
        error=NULL
      RETURNING *
    `).get(
      id, pid, candidate.kind, candidate.value, candidate.hostname, candidate.port ?? 0, candidate.protocol ?? "", candidate.url,
      candidate.title, JSON.stringify(candidate.technologies), candidate.source, "candidate", 0, JSON.stringify(mergedTags), now, now,
      JSON.stringify(candidate.evidence),
    ) as Record<string, unknown>;
    return this.candidateView(row);
  }

  private candidateView(row: Record<string, unknown>): Record<string, unknown> {
    return {
      ...row,
      technologies: row.technologies_json ? JSON.parse(String(row.technologies_json)) : [],
      tags: row.tags_json ? JSON.parse(String(row.tags_json)) : [],
      evidence: row.evidence_json ? JSON.parse(String(row.evidence_json)) : {},
      score_reasons: row.score_reasons_json ? JSON.parse(String(row.score_reasons_json)) : [],
      page_evidence: row.page_evidence_json ? JSON.parse(String(row.page_evidence_json)) : {},
    };
  }

  listAssetCandidates(projectId: string, opts: { limit?: number; status?: string; minScore?: number } = {}): Record<string, unknown>[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const requested = Number(opts.limit || 200);
    const limit = Number.isInteger(requested) ? Math.max(1, Math.min(5000, requested)) : 200;
    const args: unknown[] = [pid];
    const conditions: string[] = [];
    if (opts.status) { conditions.push("status=?"); args.push(String(opts.status)); }
    if (opts.minScore !== undefined && Number.isFinite(Number(opts.minScore))) { conditions.push("score>=?"); args.push(Number(opts.minScore)); }
    args.push(limit);
    const where = conditions.length ? ` AND ${conditions.join(" AND ")}` : "";
    return (this.db.prepare(`SELECT * FROM asset_candidates WHERE project_id=?${where} ORDER BY score DESC, last_seen DESC, value ASC LIMIT ?`)
      .all(...args) as Record<string, unknown>[]).map(row => this.candidateView(row));
  }

  /** Shared WHERE builder for the console assets page so pagination, id-only and
   *  full-list queries stay consistent. */
  private candidateWhere(opts: {
    status?: string; tag?: string; query?: string; minScore?: number; onlyReachable?: boolean;
    scope?: "all" | "pending" | "retry";
  }): { sql: string; args: unknown[] } {
    const args: unknown[] = [];
    const conditions: string[] = [];
    if (opts.status) { conditions.push("status=?"); args.push(String(opts.status)); }
    if (opts.tag) { conditions.push("tags_json LIKE ?"); args.push(`%"${String(opts.tag).replace(/"/g, "")}"%`); }
    if (opts.onlyReachable) { conditions.push("tags_json LIKE ?"); args.push('%"reachable"%'); }
    if (opts.query) {
      const q = `%${String(opts.query).replace(/[\\%_]/g, (c) => "\\" + c)}%`;
      conditions.push("(url LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\' OR tags_json LIKE ? ESCAPE '\\' OR technologies_json LIKE ? ESCAPE '\\')");
      args.push(q, q, q, q, q, q);
    }
    if (opts.minScore !== undefined && Number.isFinite(Number(opts.minScore))) { conditions.push("score>=?"); args.push(Number(opts.minScore)); }
    if (opts.scope === "pending") conditions.push("agent_score IS NULL AND COALESCE(review_attempts,0)=0");
    else if (opts.scope === "retry") conditions.push("agent_score IS NULL AND COALESCE(review_attempts,0)>0");
    const sql = conditions.length ? ` AND ${conditions.join(" AND ")}` : "";
    return { sql, args };
  }

  /** Paged + server-filtered candidates for the assets page (no full-pool download). */
  listAssetCandidatesPaged(
    projectId: string,
    opts: {
      limit?: number; offset?: number; status?: string; tag?: string; query?: string;
      minScore?: number; onlyReachable?: boolean; sort?: "score" | "recent";
    } = {},
  ): { items: Record<string, unknown>[]; total: number; maxLastSeen: number; reachable: number; pending: number; failed: number; unscored: number; review_failed: number; tags: string[] } {
    const pid = (projectId || "").trim();
    if (!pid) return { items: [], total: 0, maxLastSeen: 0, reachable: 0, pending: 0, failed: 0, unscored: 0, review_failed: 0, tags: [] };
    const { sql, args } = this.candidateWhere(opts);
    const order = opts.sort === "recent" ? "last_seen DESC, value ASC" : "COALESCE(agent_score, score, 0) DESC, value ASC";
    const limit = Math.max(1, Math.min(200, Number.isFinite(Number(opts.limit)) ? Number(opts.limit) : 50));
    const offset = Math.max(0, Number.isFinite(Number(opts.offset)) ? Number(opts.offset) : 0);
    const agg = this.db.prepare(
      `SELECT COUNT(*) AS total, COALESCE(MAX(last_seen),0) AS mls,
              SUM(CASE WHEN tags_json LIKE '%"reachable"%' THEN 1 ELSE 0 END) AS reachable,
              SUM(CASE WHEN (http_status IS NULL OR http_status='') AND status<>'failed' THEN 1 ELSE 0 END) AS pending,
              SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed,
              SUM(CASE WHEN agent_score IS NULL AND COALESCE(review_attempts,0)=0 THEN 1 ELSE 0 END) AS unscored,
              SUM(CASE WHEN agent_score IS NULL AND COALESCE(review_attempts,0)>0 THEN 1 ELSE 0 END) AS review_failed
       FROM asset_candidates WHERE project_id=?${sql}`,
    ).get(pid, ...args) as { total: number; mls: number; reachable: number; pending: number; failed: number; unscored: number; review_failed: number };
    const total = Number(agg.total || 0);
    const items = (this.db.prepare(
      `SELECT * FROM asset_candidates WHERE project_id=?${sql} ORDER BY ${order} LIMIT ? OFFSET ?`,
    ).all(pid, ...args, limit, offset) as Record<string, unknown>[]).map((row) => this.candidateView(row));
    const tagSet = new Set<string>();
    const tagRows = (this.db.prepare(`SELECT tags_json FROM asset_candidates WHERE project_id=?${sql}`).all(pid, ...args) as { tags_json?: string }[]).slice(0, 4000);
    for (const r of tagRows) {
      if (!r.tags_json) continue;
      try { for (const t of JSON.parse(String(r.tags_json)) as unknown[]) tagSet.add(String(t)); } catch { /* ignore */ }
    }
    return {
      items, total,
      maxLastSeen: Number(agg.mls || 0),
      reachable: Number(agg.reachable || 0),
      pending: Number(agg.pending || 0),
      failed: Number(agg.failed || 0),
      unscored: Number(agg.unscored || 0),
      review_failed: Number(agg.review_failed || 0),
      tags: [...tagSet].sort(),
    };
  }

  /** Matching candidate ids only (bulk actions / review scopes). */
  listAssetCandidateIds(projectId: string, opts: {
    status?: string; tag?: string; query?: string; minScore?: number; onlyReachable?: boolean; scope?: "all" | "pending" | "retry";
  } = {}): string[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const { sql, args } = this.candidateWhere(opts);
    return (this.db.prepare(`SELECT id FROM asset_candidates WHERE project_id=?${sql}`).all(pid, ...args) as { id: unknown }[]).map((r) => String(r.id));
  }

  /** Record an attempt that ended without a score, so it is not retried implicitly. */
  markAssetCandidateReviewFailed(projectId: string, candidateId: string, error: string): void {
    this.db.prepare("UPDATE asset_candidates SET review_attempts=COALESCE(review_attempts,0)+1, review_error=? WHERE project_id=? AND id=?")
      .run(String(error || "review failed").slice(0, 500), projectId, candidateId);
  }

  /** Candidates whose review was attempted and failed; retried only on explicit request. */
  listFailedAssetCandidates(projectId: string, limit = 5000): Record<string, unknown>[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const requested = Number(limit);
    const capped = Number.isInteger(requested) ? Math.max(1, Math.min(5000, requested)) : 5000;
    const rows = this.db.prepare(
      "SELECT * FROM asset_candidates WHERE project_id=? AND agent_score IS NULL AND COALESCE(review_attempts,0)>0 ORDER BY review_attempts DESC, last_seen DESC LIMIT ?",
    ).all(pid, capped) as Record<string, unknown>[];
    return rows.map((row) => this.candidateView(row));
  }

  /** Candidates that still need an agent score under the current rule version. */
  listUnscoredAssetCandidates(projectId: string, ruleVersion: string, limit = 5000): Record<string, unknown>[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const requested = Number(limit);
    const capped = Number.isInteger(requested) ? Math.max(1, Math.min(5000, requested)) : 5000;
    const rows = this.db.prepare(
      // A failed review already burned one browser run and one model call: keep it out of the
      // default queue so a dead host cannot be re-scored on every click.
      `SELECT * FROM asset_candidates WHERE project_id=?
         AND ((agent_score IS NULL AND COALESCE(review_attempts,0)=0)
              OR (agent_score IS NOT NULL AND (score_rule_version IS NULL OR score_rule_version<>?)))
       ORDER BY score DESC, last_seen DESC, value ASC LIMIT ?`,
    ).all(pid, String(ruleVersion || ""), capped) as Record<string, unknown>[];
    return rows.map((row) => this.candidateView(row));
  }

  /** Subset of the given ids that still need a score; already-scored ids are dropped. */
  pendingAssetCandidateIds(projectId: string, ids: string[], ruleVersion: string): string[] {
    const pid = (projectId || "").trim();
    const unique = [...new Set(ids.map((id) => String(id || "").trim()).filter(Boolean))];
    if (!pid || !unique.length) return [];
    const out: string[] = [];
    for (let offset = 0; offset < unique.length; offset += 500) {
      const chunk = unique.slice(offset, offset + 500);
      const placeholders = chunk.map(() => "?").join(",");
      const rows = this.db.prepare(
        `SELECT id FROM asset_candidates WHERE project_id=? AND id IN (${placeholders})
         AND ((agent_score IS NULL AND COALESCE(review_attempts,0)=0)
              OR (agent_score IS NOT NULL AND (score_rule_version IS NULL OR score_rule_version<>?)))`,
      ).all(pid, ...chunk, String(ruleVersion || "")) as Array<{ id: string }>;
      out.push(...rows.map((row) => String(row.id)));
    }
    const wanted = new Set(out);
    return unique.filter((id) => wanted.has(id));
  }

  getAssetCandidate(projectId: string, candidateId: string): Record<string, unknown> | null {
    const row = this.db.prepare("SELECT * FROM asset_candidates WHERE project_id=? AND id=?").get(projectId, candidateId) as Record<string, unknown> | undefined;
    return row ? this.candidateView(row) : null;
  }

  private blackboxEventView(row: Record<string, unknown>): Record<string, unknown> {
    return { ...row, data: row.data_json ? JSON.parse(String(row.data_json)) : {} };
  }

  private blackboxEvidenceView(row: Record<string, unknown>): Record<string, unknown> {
    const category = ["tool-result", "tool-error", "artifact"].includes(String(row.kind)) ? "observation"
      : row.kind === "agent-analysis" ? "analysis" : row.kind === "observer-review" ? "advice" : "execution";
    return { ...row, category, data: row.data_json ? JSON.parse(String(row.data_json)) : {} };
  }

  /** 分页取会话时间线（旧→新），避免一次性把上万条事件塞进前端。 */
  listBlackboxEvents(projectId: string, sessionId: string, limit = 50, offset = 0): { items: Record<string, unknown>[]; total: number } {
    const pid = (projectId || "").trim();
    const sid = (sessionId || "").trim();
    if (!pid || !sid) return { items: [], total: 0 };
    const total = Number((this.db.prepare("SELECT COUNT(*) AS c FROM blackbox_events WHERE project_id=? AND session_id=?").get(pid, sid) as { c: number }).c || 0);
    const items = (this.db.prepare("SELECT * FROM blackbox_events WHERE project_id=? AND session_id=? ORDER BY id ASC LIMIT ? OFFSET ?")
      .all(pid, sid, Math.max(1, Math.min(500, Number(limit) || 50)), Math.max(0, Number(offset) || 0)) as Record<string, unknown>[])
      .map((row) => this.blackboxEventView(row));
    return { items, total };
  }

  /** 分页取 Evidence Ledger（新→旧）。 */
  listBlackboxEvidence(projectId: string, sessionId: string, limit = 24, offset = 0): { items: Record<string, unknown>[]; total: number } {
    const pid = (projectId || "").trim();
    const sid = (sessionId || "").trim();
    if (!pid || !sid) return { items: [], total: 0 };
    const total = Number((this.db.prepare("SELECT COUNT(*) AS c FROM blackbox_evidence WHERE project_id=? AND session_id=?").get(pid, sid) as { c: number }).c || 0);
    const items = (this.db.prepare("SELECT * FROM blackbox_evidence WHERE project_id=? AND session_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?")
      .all(pid, sid, Math.max(1, Math.min(200, Number(limit) || 24)), Math.max(0, Number(offset) || 0)) as Record<string, unknown>[])
      .map((row) => this.blackboxEvidenceView(row));
    return { items, total };
  }

  /** 取某类证据的最新一条（详情接口内联 run-summary 用，不拉全量）。 */
  getBlackboxEvidenceByKind(projectId: string, sessionId: string, kind: string): Record<string, unknown> | null {
    const pid = (projectId || "").trim();
    const sid = (sessionId || "").trim();
    if (!pid || !sid) return null;
    const row = this.db.prepare("SELECT * FROM blackbox_evidence WHERE project_id=? AND session_id=? AND kind=? ORDER BY created_at DESC LIMIT 1")
      .get(pid, sid, kind) as Record<string, unknown> | undefined;
    return row ? this.blackboxEvidenceView(row) : null;
  }

  private blackboxSessionView(row: Record<string, unknown>, details = false): Record<string, unknown> {
    const cookies = this.getProjectCookies(String(row.project_id));
    const session: Record<string, unknown> = {
      ...row,
      environment: row.environment_json ? JSON.parse(String(row.environment_json)) : {},
      checkpoint: row.checkpoint_json ? JSON.parse(String(row.checkpoint_json)) : {},
      cookie_count: cookies.length,
      cookies: cookieSummary(cookies),
    };
    // 已解析成 environment / checkpoint，原始 JSON blob 不再下发（否则列表/详情体积翻倍）。
    delete session.cookies_json;
    delete session.checkpoint_json;
    delete session.environment_json;
    if (details) {
      session.events = (this.db.prepare("SELECT * FROM blackbox_events WHERE project_id=? AND session_id=? ORDER BY id ASC")
        .all(String(row.project_id), String(row.id)) as Record<string, unknown>[]).map((item) => this.blackboxEventView(item));
      session.evidence = (this.db.prepare("SELECT * FROM blackbox_evidence WHERE project_id=? AND session_id=? ORDER BY created_at DESC")
        .all(String(row.project_id), String(row.id)) as Record<string, unknown>[]).map((item) => this.blackboxEvidenceView(item));
    }
    return session;
  }

  getProjectCookies(projectId: string): CookieRecord[] {
    const row = this.db.prepare("SELECT cookies_json FROM project_cookies WHERE project_id=?")
      .get(projectId) as { cookies_json?: string } | undefined;
    if (!row?.cookies_json) return [];
    try {
      const parsed = JSON.parse(String(row.cookies_json)) as unknown;
      return Array.isArray(parsed) ? parsed as CookieRecord[] : [];
    } catch {
      return [];
    }
  }

  /**
   * 取 Token（全局凭据罐）：`browser.open` 登录后抓到的 Bearer/会话 Token 按 host 存这里，
   * 后续 http.request 自动挂到 Authorization 上——效果等同"Burp 里登录一次，后面自动带凭证"。
   */
  getProjectTokens(projectId: string): Array<{ host: string; name: string; value: string; scheme: string; source: string }> {
    const rows = this.db.prepare("SELECT host,name,value,scheme,source FROM project_tokens WHERE project_id=? ORDER BY updated_at DESC")
      .all(projectId) as Array<{ host: string; name: string; value: string; scheme: string; source: string }>;
    return rows;
  }

  /** 按 host 匹配（含父域后缀匹配），取最具体的一条 Token。 */
  getTokenForHost(projectId: string, host: string): { name: string; value: string; scheme: string; host: string } | undefined {
    const target = String(host || "").toLowerCase();
    if (!target) return undefined;
    const rows = this.getProjectTokens(projectId);
    const match = rows.find(row => row.host.toLowerCase() === target)
      || rows.find(row => target.endsWith(`.${row.host.toLowerCase()}`))
      || rows.find(row => row.host.toLowerCase().endsWith(`.${target}`));
    return match ? { name: match.name, value: match.value, scheme: match.scheme, host: match.host } : undefined;
  }

  mergeProjectTokens(projectId: string, additions: Array<{ host: string; name?: string; value: string; scheme?: string; source?: string }>): number {
    const now = Date.now() / 1000;
    let written = 0;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const item of additions) {
        const host = String(item.host || "").trim().toLowerCase();
        const value = String(item.value || "").trim();
        if (!host || !value) continue;
        this.db.prepare("INSERT INTO project_tokens(project_id,host,name,value,scheme,source,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(project_id,host,name) DO UPDATE SET value=excluded.value,scheme=excluded.scheme,source=excluded.source,updated_at=excluded.updated_at")
          .run(projectId, host, String(item.name || "bearer"), value, String(item.scheme || "Bearer"), String(item.source || ""), now);
        written += 1;
      }
      this.db.exec("COMMIT");
      return written;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  clearProjectTokens(projectId: string): void {
    this.db.prepare("DELETE FROM project_tokens WHERE project_id=?").run(projectId);
  }

  /** Merge inside an immediate transaction so concurrent sessions cannot lose updates. */
  mergeProjectCookies(projectId: string, additions: CookieRecord[]): CookieRecord[] {
    const now = Date.now() / 1000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const merged = mergeCookies(this.getProjectCookies(projectId), additions, now);
      this.db.prepare("INSERT INTO project_cookies(project_id,cookies_json,updated_at) VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET cookies_json=excluded.cookies_json,updated_at=excluded.updated_at")
        .run(projectId, JSON.stringify(merged), now);
      this.db.exec("COMMIT");
      return merged;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  setProjectCookies(projectId: string, cookies: CookieRecord[]): void {
    const now = Date.now() / 1000;
    this.db.prepare("INSERT INTO project_cookies(project_id,cookies_json,updated_at) VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET cookies_json=excluded.cookies_json,updated_at=excluded.updated_at")
      .run(projectId, JSON.stringify(cookies.slice(-300)), now);
  }

  createBlackboxSession(projectId: string, candidateId: string, target: string): Record<string, unknown> {
    if (!projectId || !candidateId || !target) throw new Error("project, candidate and target are required");
    if (!this.getAssetCandidate(projectId, candidateId)) throw new Error("candidate not found");
    const id = randomBytes(8).toString("hex");
    const now = Date.now() / 1000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO blackbox_sessions(id,project_id,candidate_id,target,status,phase,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
        .run(id, projectId, candidateId, target, "pending", "environment_check", now, now);
      this.db.prepare("INSERT INTO blackbox_events(session_id,project_id,actor,kind,text,data_json,created_at) VALUES(?,?,?,?,?,?,?)")
        .run(id, projectId, "system", "lifecycle", "黑盒会话已创建，等待环境检查。", "{}", now);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return this.getBlackboxSession(projectId, id)!;
  }

  /**
   * 时光机：每次 run 开始前把当前 checkpoint 归档一份。
   *
   * 2026-10-28 的教训：cancel 是不可逆状态，一次成本控制就毁掉了复跑能力，最后只能改 SQL 状态位。
   * 有了快照就能"同一初始状态跑两条平行宇宙"，不用动数据库。
   */
  addBlackboxCheckpoint(projectId: string, sessionId: string, checkpoint: Record<string, unknown>, label = "run_start"): number {
    const next = this.db.prepare("SELECT COALESCE(MAX(run_index),0)+1 AS n FROM blackbox_checkpoints WHERE project_id=? AND session_id=?")
      .get(projectId, sessionId) as { n: number } | undefined;
    const runIndex = Number(next?.n || 1);
    const info = this.db.prepare("INSERT INTO blackbox_checkpoints(project_id,session_id,run_index,label,checkpoint_json,created_at) VALUES(?,?,?,?,?,?)")
      .run(projectId, sessionId, runIndex, label, JSON.stringify(checkpoint || {}), Date.now() / 1000);
    return Number(info.lastInsertRowid || 0);
  }

  /** 快照列表（不返回 checkpoint_json，避免列表接口被账本撑爆）。 */
  listBlackboxCheckpoints(projectId: string, sessionId: string, limit = 50): Array<{ id: number; run_index: number; label: string; created_at: number; bytes: number }> {
    const rows = this.db.prepare("SELECT id, run_index, label, created_at, LENGTH(checkpoint_json) AS bytes FROM blackbox_checkpoints WHERE project_id=? AND session_id=? ORDER BY id DESC LIMIT ?")
      .all(projectId, sessionId, Math.max(1, Math.floor(limit))) as Array<{ id: number; run_index: number; label: string; created_at: number; bytes: number }>;
    return rows.map(row => ({ id: Number(row.id), run_index: Number(row.run_index), label: String(row.label || ""), created_at: Number(row.created_at), bytes: Number(row.bytes || 0) }));
  }

  getBlackboxCheckpoint(projectId: string, sessionId: string, checkpointId: number): Record<string, unknown> | undefined {
    const row = this.db.prepare("SELECT checkpoint_json FROM blackbox_checkpoints WHERE project_id=? AND session_id=? AND id=?")
      .get(projectId, sessionId, checkpointId) as { checkpoint_json?: string } | undefined;
    if (!row) return undefined;
    try { return JSON.parse(String(row.checkpoint_json || "{}")) as Record<string, unknown>; } catch { return undefined; }
  }

  /**
   * 从快照 fork 一个新会话：同一候选、同一目标、指定 checkpoint。
   * 新会话一律落成 paused/awaiting_operator，由操作员显式点 run 决定下一步。
   */
  forkBlackboxSession(projectId: string, sessionId: string, checkpoint: Record<string, unknown>, sourceRun: number): Record<string, unknown> {
    const parent = this.getBlackboxSession(projectId, sessionId);
    if (!parent) throw new Error("session not found");
    const id = randomBytes(8).toString("hex");
    const now = Date.now() / 1000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      // environment 描述的是沙箱/工具链可用性，不是一次运行的产物：跟着账本一起继承，fork 出来即可直接跑。
      // blackboxSessionView 已把 environment_json 解析成 environment 并删掉原始 blob（列表/详情瘦身），
      // 所以这里必须读解析后的 parent.environment；再读 environment_json 只会拿到 undefined，
      // 导致 fork 出的会话丢了 ready，desk 的 run 门禁会拒绝启动。
      this.db.prepare("INSERT INTO blackbox_sessions(id,project_id,candidate_id,target,status,phase,environment_json,checkpoint_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .run(id, projectId, String(parent.candidate_id), String(parent.target), "paused", "awaiting_operator", JSON.stringify((parent.environment || {}) as Record<string, unknown>), JSON.stringify(checkpoint || {}), now, now);
      this.db.prepare("INSERT INTO blackbox_events(session_id,project_id,actor,kind,text,data_json,created_at) VALUES(?,?,?,?,?,?,?)")
        .run(id, projectId, "operator", "lifecycle", `从会话 ${sessionId} 的第 ${sourceRun} 次 run 快照 fork 出来的新会话（账本一致，证据不复制）。`,
          JSON.stringify({ forked_from: sessionId, source_run: sourceRun }), now);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return this.getBlackboxSession(projectId, id)!;
  }

  /**
   * Removes a session together with its timeline and evidence rows. Running sessions are refused
   * so a live run cannot lose its ledger mid-flight; artifact files are returned for the caller
   * to unlink, because the database does not own the filesystem.
   */
  deleteBlackboxSession(projectId: string, sessionId: string): { ok: boolean; error?: string; events?: number; evidence?: number; artifacts?: string[] } {
    const session = this.getBlackboxSession(projectId, sessionId);
    if (!session) return { ok: false, error: "session not found" };
    if (String(session.status) === "running" || String(session.phase) === "stopping") {
      return { ok: false, error: "会话正在运行，请先暂停或取消后再删除" };
    }
    const artifacts = (this.db.prepare("SELECT artifact_path FROM blackbox_evidence WHERE project_id=? AND session_id=? AND artifact_path IS NOT NULL AND artifact_path<>''")
      .all(projectId, sessionId) as Array<{ artifact_path: string }>).map((row) => String(row.artifact_path));
    const evidence = this.db.prepare("DELETE FROM blackbox_evidence WHERE project_id=? AND session_id=?").run(projectId, sessionId);
    const events = this.db.prepare("DELETE FROM blackbox_events WHERE project_id=? AND session_id=?").run(projectId, sessionId);
    this.db.prepare("DELETE FROM blackbox_sessions WHERE project_id=? AND id=?").run(projectId, sessionId);
    return { ok: true, events: Number(events.changes || 0), evidence: Number(evidence.changes || 0), artifacts };
  }

  /**
   * 批量删除会话。
   *
   * 逐条走 deleteBlackboxSession 的同一套级联（证据/事件/产物文件），不写第二份删除逻辑；
   * 运行中的会话跳过并单独报告原因——批量操作最怕"看起来都删了，其实有几条没动"。
   */
  deleteBlackboxSessions(projectId: string, sessionIds: string[]): {
    ok: boolean; deleted: string[]; skipped: Array<{ id: string; reason: string }>;
    events: number; evidence: number; artifacts: number;
  } {
    const deleted: string[] = [];
    const skipped: Array<{ id: string; reason: string }> = [];
    let events = 0, evidence = 0, artifacts = 0;
    for (const sessionId of [...new Set(sessionIds.filter(Boolean))]) {
      const result = this.deleteBlackboxSession(projectId, sessionId);
      if (!result.ok) { skipped.push({ id: sessionId, reason: result.error || "删除失败" }); continue; }
      deleted.push(sessionId);
      events += Number(result.events || 0);
      evidence += Number(result.evidence || 0);
      artifacts += (result.artifacts || []).length;
    }
    return { ok: deleted.length > 0 || skipped.length === 0, deleted, skipped, events, evidence, artifacts };
  }

  /** The session already opened for this candidate, if any; used to keep "send to blackbox" idempotent. */  /** The session already opened for this candidate, if any; used to keep "send to blackbox" idempotent. */
  findBlackboxSessionByCandidate(projectId: string, candidateId: string): Record<string, unknown> | null {
    const row = this.db.prepare("SELECT * FROM blackbox_sessions WHERE project_id=? AND candidate_id=? AND status<>'cancelled' ORDER BY updated_at DESC LIMIT 1")
      .get(projectId, candidateId) as Record<string, unknown> | undefined;
    return row ? this.blackboxSessionView(row) : null;
  }

  /**
   * 会话列表只返回元数据摘要（不内联 checkpoint / events / evidence 巨量 JSON），
   * 否则 4 个会话就能撑到 8MB、几十个会话直接上 18MB，前端每切项目/轮询都重新下载。
   * 完整详情走 getBlackboxSession（单条）。
   */
  listBlackboxSessions(projectId: string, limit = 100): Record<string, unknown>[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const cap = Math.max(1, Math.min(500, Number(limit) || 100));
    const rows = this.db.prepare("SELECT * FROM blackbox_sessions WHERE project_id=? ORDER BY updated_at DESC LIMIT ?")
      .all(pid, cap) as Record<string, unknown>[];
    const evCounts = new Map<string, number>();
    for (const row of this.db.prepare("SELECT session_id, COUNT(*) AS c FROM blackbox_events WHERE project_id=? GROUP BY session_id").all(pid) as Array<{ session_id: string; c: number }>) {
      evCounts.set(row.session_id, Number(row.c));
    }
    const evdCounts = new Map<string, number>();
    for (const row of this.db.prepare("SELECT session_id, COUNT(*) AS c FROM blackbox_evidence WHERE project_id=? GROUP BY session_id").all(pid) as Array<{ session_id: string; c: number }>) {
      evdCounts.set(row.session_id, Number(row.c));
    }
    const cookies = this.getProjectCookies(pid);
    return rows.map((row) => {
      let environmentReady = false;
      try { const env = row.environment_json ? JSON.parse(String(row.environment_json)) : null; environmentReady = Boolean(env && env.ready); } catch { /* ignore */ }
      return {
        id: row.id,
        project_id: row.project_id,
        candidate_id: row.candidate_id,
        target: row.target,
        status: row.status,
        phase: row.phase,
        created_at: row.created_at,
        updated_at: row.updated_at,
        cookie_count: cookies.length,
        environment_ready: environmentReady,
        evidence_count: evdCounts.get(String(row.id)) || 0,
        event_count: evCounts.get(String(row.id)) || 0,
      };
    });
  }

  getBlackboxSession(projectId: string, sessionId: string): Record<string, unknown> | null {
    const row = this.db.prepare("SELECT * FROM blackbox_sessions WHERE project_id=? AND id=?").get(projectId, sessionId) as Record<string, unknown> | undefined;
    return row ? this.blackboxSessionView(row, true) : null;
  }

  recoverBlackboxSessions(): void {
    const rows = this.db.prepare("SELECT project_id,id FROM blackbox_sessions WHERE status='running'").all() as Array<{ project_id: string; id: string }>;
    for (const row of rows) {
      this.db.exec("BEGIN IMMEDIATE");
      try {
        const session = this.getBlackboxSession(row.project_id, row.id);
        if (session?.status !== "running") { this.db.exec("ROLLBACK"); continue; }
        const checkpoint = session.checkpoint && typeof session.checkpoint === "object" ? structuredClone(session.checkpoint as Record<string, unknown>) : null;
        const supervision = checkpoint?.supervision && typeof checkpoint.supervision === "object" ? checkpoint.supervision as Record<string, unknown> : null;
        const reviews = supervision?.reviews && typeof supervision.reviews === "object" ? supervision.reviews as Record<string, Record<string, unknown>> : {};
        for (const review of Object.values(reviews)) if (review.status === "running") {
          review.status = "failed";
          review.failure = "process_interrupted_during_observer_review";
          review.failure_fingerprint = "process_interrupted_during_observer_review";
          review.retryable = true;
          review.completed_at = Date.now();
        }
        if (Object.values(reviews).some(review => review.failure === "process_interrupted_during_observer_review")) {
          if (supervision) supervision.reviewPending = true;
        }
        this.updateBlackboxSession(row.project_id, row.id, { status: "paused", phase: "interrupted", ...(checkpoint ? { checkpoint } : {}) });
        this.addBlackboxEvent(row.project_id, row.id, "system", "checkpoint", "服务重启：已暂停中断的会话，保留数据库检查点；执行结果未知的动作不会自动重放。");
        this.db.exec("COMMIT");
      } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    }
  }

  updateBlackboxSession(projectId: string, sessionId: string, fields: { status?: string; phase?: string; environment?: Record<string, unknown>; checkpoint?: object }): Record<string, unknown> | null {
    if (!this.getBlackboxSession(projectId, sessionId)) return null;
    const set = ["updated_at=?"];
    const params: unknown[] = [Date.now() / 1000];
    if (fields.status !== undefined) { set.push("status=?"); params.push(fields.status); }
    if (fields.phase !== undefined) { set.push("phase=?"); params.push(fields.phase); }
    if (fields.environment !== undefined) { set.push("environment_json=?"); params.push(JSON.stringify(fields.environment)); }
    if (fields.checkpoint !== undefined) { set.push("checkpoint_json=?"); params.push(JSON.stringify(fields.checkpoint)); }
    params.push(projectId, sessionId);
    this.db.prepare(`UPDATE blackbox_sessions SET ${set.join(",")} WHERE project_id=? AND id=?`).run(...params);
    return this.getBlackboxSession(projectId, sessionId);
  }

  /** Atomically claim an idle session without racing another scheduler worker. */
  claimBlackboxSession(projectId: string, sessionId: string, expected: object): boolean {
    return this.db.prepare("UPDATE blackbox_sessions SET status='running',phase='analysis' WHERE project_id=? AND id=? AND status NOT IN ('running','cancelled') AND checkpoint_json=?")
      .run(projectId, sessionId, JSON.stringify(expected)).changes === 1;
  }

  commitBlackboxObserverReview(projectId: string, sessionId: string, expected: object, next: object, event: { kind: string; text: string; data: Record<string, unknown>; result?: { summary: string; output: Record<string, unknown> } } | null): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.getBlackboxSession(projectId, sessionId);
      if (!current || JSON.stringify(current.checkpoint) !== JSON.stringify(expected)) {
        this.db.exec("ROLLBACK"); return false;
      }
      const now = Date.now() / 1000;
      // A null event commits the checkpoint without a timeline row: repeated saves inside one
      // round used to flood the ledger with identical "保存执行检查点" entries.
      if (event) this.db.prepare("INSERT INTO blackbox_events(session_id,project_id,actor,kind,text,data_json,created_at) VALUES(?,?,?,?,?,?,?)")
        .run(sessionId, projectId, "observer", event.kind, event.text, JSON.stringify(event.data), now);
      this.updateBlackboxSession(projectId, sessionId, { checkpoint: next });
      if (event?.result) {
        this.addBlackboxEvent(projectId, sessionId, "observer", "advice", event.result.summary, event.result.output);
        this.addBlackboxEvidence(projectId, sessionId, { kind: "observer-review", source: "observer", summary: event.result.summary, confidence: "medium", data: event.result.output });
      }
      this.db.exec("COMMIT"); return true;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  commitBlackboxProgressReview(projectId: string, sessionId: string, expected: object, next: object, data: Record<string, unknown>, kind: "task-outcome-correction" | "advice-disposition" = "task-outcome-correction"): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.getBlackboxSession(projectId, sessionId);
      if (!current || current.status === "running" || current.status === "cancelled" || JSON.stringify(current.checkpoint) !== JSON.stringify(expected)) {
        this.db.exec("ROLLBACK"); return false;
      }
      this.addBlackboxEvent(projectId, sessionId, "operator", kind, String(data.reason), {
        ...data, before_checkpoint: current.checkpoint, after_checkpoint: next,
      });
      this.addBlackboxEvidence(projectId, sessionId, { kind, source: "operator", summary: String(data.reason),
        data: { output: data.output, rejected: data.rejected, results: data.results, acceptance: data.acceptance } });
      this.updateBlackboxSession(projectId, sessionId, { checkpoint: next });
      this.db.exec("COMMIT"); return true;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  addBlackboxEvent(projectId: string, sessionId: string, actor: string, kind: string, text: string, data: Record<string, unknown> = {}): Record<string, unknown> | null {
    if (!this.getBlackboxSession(projectId, sessionId)) return null;
    const now = Date.now() / 1000;
    const row = this.db.prepare("INSERT INTO blackbox_events(session_id,project_id,actor,kind,text,data_json,created_at) VALUES(?,?,?,?,?,?,?) RETURNING *")
      .get(sessionId, projectId, actor, kind, text, JSON.stringify(data), now) as Record<string, unknown>;
    this.db.prepare("UPDATE blackbox_sessions SET updated_at=? WHERE project_id=? AND id=?").run(now, projectId, sessionId);
    return this.blackboxEventView(row);
  }

  addBlackboxEvidence(projectId: string, sessionId: string, evidence: { kind: string; source: string; summary: string; confidence?: string; data?: Record<string, unknown>; artifactPath?: string }): Record<string, unknown> | null {
    if (!this.getBlackboxSession(projectId, sessionId)) return null;
    const id = `ev-${randomBytes(8).toString("hex")}`;
    const now = Date.now() / 1000;
    const row = this.db.prepare("INSERT INTO blackbox_evidence(id,session_id,project_id,kind,source,summary,confidence,data_json,artifact_path,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING *")
      .get(id, sessionId, projectId, evidence.kind, evidence.source, evidence.summary, evidence.confidence || "medium", JSON.stringify(evidence.data || {}), evidence.artifactPath || null, now) as Record<string, unknown>;
    this.db.prepare("UPDATE blackbox_sessions SET updated_at=? WHERE project_id=? AND id=?").run(now, projectId, sessionId);
    return this.blackboxEvidenceView(row);
  }

  /**
   * WAF 战例入库（幂等）：同 vendor+档位+战术+host 的记录只累加命中次数。
   * 战例库的价值是"下次先照抄"，所以写路径必须无脑、无校验、失败不阻塞主流程；
   * 归一化（厂商识别、指纹）在 src/blackbox/waf-ledger.ts 里做，这里只存。
   */
  upsertWafBypass(victory: {
    vendor: string; vendor_name?: string; family?: string; signature?: string; dimension?: string;
    tactic: string; payload?: string; host?: string; project_id?: string; session_id?: string;
    evidence_id?: string; source?: string; note?: string;
  }): Record<string, unknown> {
    const now = Date.now() / 1000;
    const existing = this.db.prepare(
      "SELECT * FROM waf_bypasses WHERE vendor=? AND dimension=? AND tactic=? AND COALESCE(host,'')=? LIMIT 1",
    ).get(victory.vendor, victory.dimension || "other", victory.tactic, victory.host || "") as Record<string, unknown> | undefined;
    if (existing) {
      this.db.prepare(
        `UPDATE waf_bypasses SET hits=hits+1, last_ok_at=?, payload=COALESCE(NULLIF(?, ''), payload),
           signature=COALESCE(NULLIF(?, ''), signature), evidence_id=COALESCE(?, evidence_id),
           project_id=COALESCE(?, project_id), session_id=COALESCE(?, session_id), note=COALESCE(NULLIF(?, ''), note)
         WHERE id=?`,
      ).run(now, victory.payload || "", victory.signature || "", victory.evidence_id || null,
        victory.project_id || null, victory.session_id || null, victory.note || "", String(existing.id));
      return this.wafBypassView(this.db.prepare("SELECT * FROM waf_bypasses WHERE id=?").get(String(existing.id)) as Record<string, unknown>);
    }
    const row = this.db.prepare(
      `INSERT INTO waf_bypasses(id,vendor,vendor_name,family,signature,dimension,tactic,payload,host,project_id,session_id,evidence_id,source,note,hits,created_at,last_ok_at)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?) RETURNING *`,
    ).get(
      `waf-${randomBytes(8).toString("hex")}`, victory.vendor, victory.vendor_name || victory.vendor,
      victory.family || "unknown", victory.signature || "", victory.dimension || "other", victory.tactic,
      victory.payload || null, victory.host || null, victory.project_id || null, victory.session_id || null,
      victory.evidence_id || null, victory.source || "model", victory.note || null, now, now,
    ) as Record<string, unknown>;
    return this.wafBypassView(row);
  }

  listWafBypasses(filter: { vendor?: string; projectId?: string; host?: string; limit?: number } = {}): Record<string, unknown>[] {
    const where: string[] = [];
    const params: Array<string | number> = [];
    if (filter.vendor) { where.push("vendor = ?"); params.push(filter.vendor); }
    if (filter.projectId) { where.push("project_id = ?"); params.push(filter.projectId); }
    if (filter.host) { where.push("COALESCE(host,'') = ?"); params.push(filter.host); }
    const sql = `SELECT * FROM waf_bypasses ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY last_ok_at DESC LIMIT ?`;
    const rows = this.db.prepare(sql).all(...params, Math.max(1, Math.min(500, filter.limit ?? 200))) as Record<string, unknown>[];
    return rows.map(row => this.wafBypassView(row));
  }

  /** 厂商维度的汇总：控制台顶卡与 prompt 里的"见过哪些墙"都读它。 */
  wafVendorSummary(): Array<{ vendor: string; vendor_name: string; family: string; victories: number; hits: number; last_ok_at: number }> {
    const rows = this.db.prepare(
      `SELECT vendor, vendor_name, family, COUNT(*) AS victories, SUM(hits) AS hits, MAX(last_ok_at) AS last_ok_at
       FROM waf_bypasses GROUP BY vendor ORDER BY hits DESC, last_ok_at DESC`,
    ).all() as Record<string, unknown>[];
    return rows.map(row => ({
      vendor: String(row.vendor || ""), vendor_name: String(row.vendor_name || row.vendor || ""),
      family: String(row.family || "unknown"), victories: Number(row.victories || 0),
      hits: Number(row.hits || 0), last_ok_at: Number(row.last_ok_at || 0),
    }));
  }

  deleteWafBypass(id: string): boolean {
    const info = this.db.prepare("DELETE FROM waf_bypasses WHERE id=?").run(id);
    return Number(info.changes || 0) > 0;
  }

  private wafBypassView(row: Record<string, unknown>): Record<string, unknown> {
    return {
      id: String(row.id || ""), vendor: String(row.vendor || ""), vendor_name: String(row.vendor_name || ""),
      family: String(row.family || "unknown"), signature: String(row.signature || ""),
      dimension: String(row.dimension || "other"), tactic: String(row.tactic || ""),
      payload: row.payload == null ? "" : String(row.payload), host: row.host == null ? "" : String(row.host),
      project_id: row.project_id == null ? "" : String(row.project_id), session_id: row.session_id == null ? "" : String(row.session_id),
      evidence_id: row.evidence_id == null ? "" : String(row.evidence_id), source: String(row.source || "model"),
      note: row.note == null ? "" : String(row.note), hits: Number(row.hits || 1),
      created_at: Number(row.created_at || 0), last_ok_at: Number(row.last_ok_at || 0),
    };
  }

  /** Tool outcome rows for health statistics. `since` is a unix timestamp in seconds. */
  listBlackboxToolOutcomes(since: number, projectId?: string, limit = 20000): Record<string, unknown>[] {
    const filter = projectId ? "AND project_id = ?" : "";
    const params: Array<string | number> = projectId ? [since, projectId, limit] : [since, limit];
    const rows = this.db.prepare(
      `SELECT id, project_id, session_id, kind, source, summary, data_json, created_at FROM blackbox_evidence
       WHERE kind IN ('tool-result','tool-error') AND created_at >= ? ${filter} ORDER BY created_at DESC LIMIT ?`,
    ).all(...params) as Record<string, unknown>[];
    return rows.map((row) => {
      let data: Record<string, unknown> = {};
      try { data = JSON.parse(String(row.data_json || "{}")) as Record<string, unknown>; } catch { data = {}; }
      return { id: row.id, project_id: row.project_id, session_id: row.session_id, kind: row.kind, source: row.source,
        summary: row.summary, data, created_at: Number(row.created_at || 0) };
    });
  }

  /** Latest completed result for one tool in one session; the pipeline reads its full artifact. */
  latestBlackboxToolResult(projectId: string, sessionId: string, source: string): Record<string, unknown> | null {
    const row = this.db.prepare(
      `SELECT * FROM blackbox_evidence WHERE project_id=? AND session_id=? AND kind='tool-result' AND source=? ORDER BY created_at DESC LIMIT 1`,
    ).get(projectId, sessionId, source) as Record<string, unknown> | undefined;
    return row ? this.blackboxEvidenceView(row) : null;
  }

  /** Latest artifact row written by a tool, used to read output beyond the bounded result. */
  latestBlackboxArtifact(projectId: string, sessionId: string, source: string): Record<string, unknown> | null {
    const row = this.db.prepare(
      `SELECT * FROM blackbox_evidence WHERE project_id=? AND session_id=? AND kind='artifact' AND source=? ORDER BY created_at DESC LIMIT 1`,
    ).get(projectId, sessionId, source) as Record<string, unknown> | undefined;
    return row ? this.blackboxEvidenceView(row) : null;
  }

  getBlackboxArtifact(projectId: string, sessionId: string, evidenceId: string): Record<string, unknown> | null {
    const row = this.db.prepare(
      "SELECT * FROM blackbox_evidence WHERE project_id=? AND session_id=? AND id=?",
    ).get(projectId, sessionId, evidenceId) as Record<string, unknown> | undefined;
    return row ? this.blackboxEvidenceView(row) : null;
  }

  createAssetReviewJob(projectId: string, candidateIds: string[], ruleVersion: string): Record<string, unknown> {
    const ids = [...new Set(candidateIds.map(String).filter(Boolean))].slice(0, 5000);
    if (!projectId || !ids.length) throw new Error("at least one candidate is required");
    const valid = ids.filter((id) => Boolean(this.getAssetCandidate(projectId, id)));
    if (!valid.length) throw new Error("no candidates found for project");
    const id = randomBytes(8).toString("hex");
    const now = Date.now() / 1000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO asset_review_jobs(id,project_id,status,total,rule_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
        .run(id, projectId, "queued", valid.length, ruleVersion, now, now);
      const insert = this.db.prepare("INSERT INTO asset_review_queue(job_id,candidate_id,status) VALUES(?,?,?)");
      for (const candidateId of valid) insert.run(id, candidateId, "queued");
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return this.getAssetReviewJob(projectId, id)!;
  }

  getAssetReviewJob(projectId: string, jobId: string): Record<string, unknown> | null {
    const row = this.db.prepare("SELECT * FROM asset_review_jobs WHERE project_id=? AND id=?").get(projectId, jobId) as Record<string, unknown> | undefined;
    if (!row) return null;
    const queue = this.db.prepare("SELECT status, COUNT(*) AS count FROM asset_review_queue WHERE job_id=? GROUP BY status").all(jobId) as Array<Record<string, unknown>>;
    return { ...row, queue: Object.fromEntries(queue.map((item) => [String(item.status), Number(item.count)])) };
  }

  listAssetReviewJobs(projectId: string, limit = 50): Record<string, unknown>[] {
    return (this.db.prepare("SELECT * FROM asset_review_jobs WHERE project_id=? ORDER BY created_at DESC LIMIT ?")
      .all(projectId, Math.max(1, Math.min(200, limit))) as Record<string, unknown>[])
      .map((row) => this.getAssetReviewJob(projectId, String(row.id)) || row);
  }

  nextAssetReviewCandidate(projectId: string, jobId: string): Record<string, unknown> | null {
    return (this.db.prepare(`SELECT c.* FROM asset_review_queue q JOIN asset_candidates c ON c.id=q.candidate_id
      WHERE q.job_id=? AND c.project_id=? AND q.status='queued' ORDER BY q.rowid LIMIT 1`).get(jobId, projectId) as Record<string, unknown> | undefined) || null;
  }

  /** Closes a review job that cannot continue, so the desk shows a failure instead of a stuck queue. */
  failAssetReviewJob(projectId: string, jobId: string, error: string): void {
    const now = Date.now() / 1000;
    const message = String(error || "review job failed").slice(0, 500);
    this.db.prepare("UPDATE asset_review_queue SET status='failed', error=?, finished_at=? WHERE job_id=? AND status IN ('queued','running')")
      .run(message, now, jobId);
    this.db.prepare("UPDATE asset_review_jobs SET status='failed', error=?, current_candidate_id=NULL, finished_at=?, updated_at=? WHERE project_id=? AND id=?")
      .run(message, now, now, projectId, jobId);
  }

  updateAssetReviewItem(projectId: string, jobId: string, candidateId: string, status: "running" | "completed" | "failed", error?: string): Record<string, unknown> | null {
    const now = Date.now() / 1000;
    const queue = this.db.prepare("UPDATE asset_review_queue SET status=?, error=?, started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END, finished_at=CASE WHEN ? IN ('completed','failed') THEN ? ELSE finished_at END WHERE job_id=? AND candidate_id=?");
    queue.run(status, error || null, status, now, status, now, jobId, candidateId);
    const counts = this.db.prepare("SELECT status, COUNT(*) AS count FROM asset_review_queue WHERE job_id=? GROUP BY status").all(jobId) as Array<Record<string, unknown>>;
    const map = Object.fromEntries(counts.map((row) => [String(row.status), Number(row.count)]));
    const total = Number(this.getAssetReviewJob(projectId, jobId)?.total || 0);
    const done = Number(map.completed || 0) + Number(map.failed || 0) >= total;
    this.db.prepare("UPDATE asset_review_jobs SET completed=?, failed=?, current_candidate_id=?, status=CASE WHEN ? THEN 'completed' ELSE CASE WHEN ?='running' THEN 'running' ELSE status END END, started_at=COALESCE(started_at,CASE WHEN ?='running' THEN ? ELSE started_at END), finished_at=CASE WHEN ? THEN ? ELSE finished_at END, updated_at=?, error=? WHERE project_id=? AND id=?")
      .run(Number(map.completed || 0), Number(map.failed || 0), done ? null : candidateId, done ? 1 : 0, status, status, now, done ? 1 : 0, now, now, error || null, projectId, jobId);
    return this.getAssetReviewJob(projectId, jobId);
  }

  deleteAssetCandidates(projectId: string, candidateIds: string[] = []): { deleted: number; screenshots: string[] } {
    const ids = [...new Set(candidateIds.map(String).filter(Boolean))];
    const rows = (ids.length
      ? this.db.prepare(`SELECT id, screenshot_path FROM asset_candidates WHERE project_id=? AND id IN (${ids.map(() => "?").join(",")})`).all(projectId, ...ids)
      : this.db.prepare("SELECT id, screenshot_path FROM asset_candidates WHERE project_id=?").all(projectId)) as Array<Record<string, unknown>>;
    if (!rows.length) return { deleted: 0, screenshots: [] };
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const selected = rows.map((row) => String(row.id));
      const marks = selected.map(() => "?").join(",");
      this.db.prepare(`DELETE FROM asset_probe_queue WHERE candidate_id IN (${marks})`).run(...selected);
      this.db.prepare(`DELETE FROM asset_review_queue WHERE candidate_id IN (${marks})`).run(...selected);
      this.db.prepare(`DELETE FROM asset_candidates WHERE project_id=? AND id IN (${marks})`).run(projectId, ...selected);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return { deleted: rows.length, screenshots: rows.map((row) => String(row.screenshot_path || "")).filter(Boolean) };
  }

  deleteAssetProbeJob(projectId: string, jobId: string): { ok: boolean; error?: string } {
    const job = this.getAssetProbeJob(projectId, jobId);
    if (!job) return { ok: false, error: "probe job not found" };
    if (["queued", "running", "paused"].includes(String(job.status))) return { ok: false, error: "running probe job must be cancelled first" };
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM asset_probe_queue WHERE job_id=?").run(jobId);
      this.db.prepare("DELETE FROM asset_probe_jobs WHERE project_id=? AND id=?").run(projectId, jobId);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return { ok: true };
  }

  updateAssetCandidate(projectId: string, candidateId: string, fields: {
    status?: string; score?: number; tags?: string[]; title?: string | null; technologies?: string[];
    httpStatus?: number | null; responseTimeMs?: number | null; evidence?: Record<string, unknown>; error?: string | null;
  }): Record<string, unknown> | null {
    const current = this.getAssetCandidate(projectId, candidateId);
    if (!current) return null;
    const tags = fields.tags ? JSON.stringify([...new Set(fields.tags.map(String).map(tag => tag.trim()).filter(Boolean))].slice(0, 32)) : undefined;
    const setParts = ["last_seen=?"];
    const params: unknown[] = [Date.now() / 1000];
    const optional: Array<[string, unknown]> = [
      ["status", fields.status],
      ["score", fields.score],
      ["tags_json", tags],
      ["title", fields.title],
      ["technologies_json", fields.technologies ? JSON.stringify(fields.technologies) : undefined],
      ["http_status", fields.httpStatus],
      ["response_time_ms", fields.responseTimeMs],
      ["evidence_json", fields.evidence ? JSON.stringify(fields.evidence) : undefined],
    ];
    for (const [column, value] of optional) {
      if (value !== undefined && value !== null) {
        setParts.push(`${column}=?`);
        params.push(value);
      }
    }
    if (fields.error === undefined) setParts.push("error=NULL");
    else if (fields.error === null) setParts.push("error=NULL");
    else { setParts.push("error=?"); params.push(fields.error); }
    params.push(projectId, candidateId);
    this.db.prepare(`UPDATE asset_candidates SET ${setParts.join(", ")} WHERE project_id=? AND id=?`).run(...params);
    return this.getAssetCandidate(projectId, candidateId);
  }

  createAssetProbeJob(projectId: string, candidateIds: string[], opts: { concurrency?: number; threshold?: number } = {}): Record<string, unknown> {
    const pid = (projectId || "").trim();
    const ids = [...new Set(candidateIds.map(String).filter(Boolean))].slice(0, 5000);
    if (!pid || !ids.length) throw new Error("at least one candidate is required");
    const concurrency = Math.max(1, Math.min(16, Math.trunc(Number(opts.concurrency || 3))));
    const threshold = Math.max(0, Math.min(100, Number(opts.threshold || 0)));
    const jobId = randomBytes(8).toString("hex");
    const now = Date.now() / 1000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const valid = ids.filter(id => {
        const candidate = this.getAssetCandidate(pid, id);
        return Boolean(candidate && Number(candidate.score || 0) >= threshold);
      });
      if (!valid.length) throw new Error("no candidates found for project");
      this.db.prepare("INSERT INTO asset_probe_jobs(id,project_id,status,concurrency,threshold,total,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
        .run(jobId, pid, "queued", concurrency, threshold, valid.length, now, now);
      const queue = this.db.prepare("INSERT INTO asset_probe_queue(job_id,candidate_id,status,attempts,queued_at) VALUES(?,?,?,?,?)");
      for (const id of valid) {
        queue.run(jobId, id, "queued", 0, now);
        this.db.prepare("UPDATE asset_candidates SET status='queued', error=NULL, last_seen=? WHERE project_id=? AND id=? AND status IN ('candidate','review','selected')")
          .run(now, pid, id);
      }
      this.db.exec("COMMIT");
      return this.getAssetProbeJob(pid, jobId)!;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  getAssetProbeJob(projectId: string, jobId: string): Record<string, unknown> | null {
    const row = this.db.prepare("SELECT * FROM asset_probe_jobs WHERE project_id=? AND id=?").get(projectId, jobId) as Record<string, unknown> | undefined;
    if (!row) return null;
    const queue = this.db.prepare("SELECT status, COUNT(*) AS count FROM asset_probe_queue WHERE job_id=? GROUP BY status").all(jobId) as Array<Record<string, unknown>>;
    return { ...row, queue: Object.fromEntries(queue.map(item => [String(item.status), Number(item.count)])) };
  }

  listAssetProbeJobs(projectId: string, limit = 100): Record<string, unknown>[] {
    return (this.db.prepare("SELECT * FROM asset_probe_jobs WHERE project_id=? ORDER BY created_at DESC LIMIT ?")
      .all(projectId, Math.max(1, Math.min(500, limit))) as Record<string, unknown>[]).map(row => this.getAssetProbeJob(projectId, String(row.id)) || row);
  }

  setAssetProbeJobStatus(projectId: string, jobId: string, status: "queued" | "running" | "paused" | "cancelled"): Record<string, unknown> | null {
    const job = this.getAssetProbeJob(projectId, jobId);
    if (!job) return null;
    const now = Date.now() / 1000;
    this.db.prepare("UPDATE asset_probe_jobs SET status=?, started_at=CASE WHEN ?='running' AND started_at IS NULL THEN ? ELSE started_at END, updated_at=? WHERE project_id=? AND id=?")
      .run(status, status, now, now, projectId, jobId);
    if (status === "cancelled") {
      this.db.prepare("UPDATE asset_probe_queue SET status='cancelled', finished_at=? WHERE job_id=? AND status IN ('queued','running')").run(now, jobId);
      this.db.prepare("UPDATE asset_candidates SET status='candidate', last_seen=? WHERE project_id=? AND id IN (SELECT candidate_id FROM asset_probe_queue WHERE job_id=?) AND status IN ('queued','running')").run(now, projectId, jobId);
    }
    return this.getAssetProbeJob(projectId, jobId);
  }

  listAssetProbeCandidates(projectId: string, jobId: string, status = "queued", limit = 500): Record<string, unknown>[] {
    return this.db.prepare(`SELECT c.*, q.status AS queue_status, q.attempts, q.error AS queue_error
      FROM asset_probe_queue q JOIN asset_candidates c ON c.id=q.candidate_id
      WHERE q.job_id=? AND c.project_id=? AND q.status=? ORDER BY q.queued_at ASC LIMIT ?`)
      .all(jobId, projectId, status, Math.max(1, Math.min(5000, limit))) as Record<string, unknown>[];
  }

  updateAssetProbeItem(projectId: string, jobId: string, candidateId: string, status: "running" | "completed" | "failed" | "skipped", fields: {
    score?: number; tags?: string[]; title?: string | null; technologies?: string[];
    httpStatus?: number | null; responseTimeMs?: number | null; evidence?: Record<string, unknown>; error?: string | null;
  } = {}): Record<string, unknown> | null {
    const now = Date.now() / 1000;
    const current = this.db.prepare("SELECT status FROM asset_probe_queue WHERE job_id=? AND candidate_id=?").get(jobId, candidateId) as { status?: string } | undefined;
    if (!current) return null;
    const terminalStatus = ["completed", "failed", "skipped"].includes(status);
    const setParts = ["status=?", "attempts=attempts+?"];
    const params: unknown[] = [status, status === "running" ? 1 : 0];
    if (status === "running") {
      setParts.push("started_at=COALESCE(started_at,?)");
      params.push(now);
    }
    if (terminalStatus) {
      setParts.push("finished_at=?");
      params.push(now);
    }
    if (fields.error !== undefined) {
      setParts.push("error=?");
      params.push(fields.error);
    }
    params.push(jobId, candidateId);
    this.db.prepare(`UPDATE asset_probe_queue SET ${setParts.join(", ")} WHERE job_id=? AND candidate_id=?`).run(...params);
    this.updateAssetCandidate(projectId, candidateId, {
      status, score: fields.score, tags: fields.tags, title: fields.title, technologies: fields.technologies,
      httpStatus: fields.httpStatus, responseTimeMs: fields.responseTimeMs, evidence: fields.evidence, error: fields.error,
    });
    const queueCounts = this.db.prepare("SELECT status, COUNT(*) AS count FROM asset_probe_queue WHERE job_id=? GROUP BY status").all(jobId) as Array<Record<string, unknown>>;
    const counts = Object.fromEntries(queueCounts.map(row => [String(row.status), Number(row.count)]));
    const terminal = Number(counts.completed || 0) + Number(counts.failed || 0) + Number(counts.skipped || 0) + Number(counts.cancelled || 0);
    const job = this.getAssetProbeJob(projectId, jobId);
    if (job) {
      const done = terminal >= Number(job.total || 0);
      this.db.prepare("UPDATE asset_probe_jobs SET completed=?, failed=?, skipped=?, status=CASE WHEN ? AND status NOT IN ('paused','cancelled') THEN 'completed' ELSE status END, finished_at=CASE WHEN ? AND status NOT IN ('paused','cancelled') THEN ? ELSE finished_at END, updated_at=? WHERE project_id=? AND id=?")
        .run(Number(counts.completed || 0), Number(counts.failed || 0), Number(counts.skipped || 0), done ? 1 : 0, done ? 1 : 0, now, now, projectId, jobId);
    }
    return this.getAssetProbeJob(projectId, jobId);
  }

  listFindings(projectId: string, opts: { limit?: number; status?: string } = {}): Record<string, unknown>[] {
    const pid = (projectId || "").trim();
    if (!pid) return [];
    const requested = Number(opts.limit || 200);
    const limit = Number.isInteger(requested) ? Math.max(1, Math.min(1000, requested)) : 200;
    const status = String(opts.status || "").trim();
    const args: unknown[] = [pid];
    const where = status ? " AND status=?" : "";
    if (status) args.push(status);
    args.push(limit);
    return (this.db.prepare(`SELECT * FROM findings WHERE project_id=?${where} ORDER BY last_seen DESC LIMIT ?`).all(...args) as Record<string, unknown>[])
      .map((row) => this.findingView(row));
  }

  projectDeleted(projectId: string): boolean {
    return Boolean(projectId && this.db.prepare("SELECT 1 FROM deleted_projects WHERE project_id=?").get(projectId));
  }

  purgeProjectRecords(projectId: string): { assets: number; candidates: number; sessions: number; findings: number } {
    const pid = (projectId || "").trim();
    const empty = { assets: 0, candidates: 0, sessions: 0, findings: 0 };
    if (!pid) return empty;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO deleted_projects VALUES(?,?) ON CONFLICT(project_id) DO UPDATE SET workspace_root=excluded.workspace_root")
        .run(pid, null);
      this.db.prepare("DELETE FROM asset_probe_queue WHERE job_id IN (SELECT id FROM asset_probe_jobs WHERE project_id=?)").run(pid);
      this.db.prepare("DELETE FROM asset_probe_jobs WHERE project_id=?").run(pid);
      this.db.prepare("DELETE FROM asset_review_queue WHERE job_id IN (SELECT id FROM asset_review_jobs WHERE project_id=?)").run(pid);
      this.db.prepare("DELETE FROM asset_review_jobs WHERE project_id=?").run(pid);
      this.db.prepare("DELETE FROM blackbox_events WHERE project_id=?").run(pid);
      this.db.prepare("DELETE FROM blackbox_evidence WHERE project_id=?").run(pid);
      this.db.prepare("DELETE FROM project_cookies WHERE project_id=?").run(pid);
      const sessions = Number(this.db.prepare("DELETE FROM blackbox_sessions WHERE project_id=?").run(pid).changes || 0);
      const candidates = Number(this.db.prepare("DELETE FROM asset_candidates WHERE project_id=?").run(pid).changes || 0);
      this.db.prepare("DELETE FROM asset_observations WHERE project_id=?").run(pid);
      const assets = Number(this.db.prepare("DELETE FROM assets WHERE project_id=?").run(pid).changes || 0);
      const findings = Number(this.db.prepare("DELETE FROM findings WHERE project_id=?").run(pid).changes || 0);
      this.db.exec("COMMIT");
      return { assets, candidates, sessions, findings };
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
}

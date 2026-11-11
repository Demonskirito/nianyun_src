#!/usr/bin/env node
/**
 * 图容量离线复现探针（阶段 0 建立，阶段 1/2/3 复用）。
 *
 * 为什么要有它：`depth` 崩溃只在"图满 + 假设保护吃掉可淘汰池"这一特定组合下复现，
 * 线上等它自然发生一次代价是一整个模型回合。这里把线上图快照固定成文件，
 * 每次运行都从同一份快照深拷贝启动，等价于固定 seed —— 结果可比、可回归。
 *
 * 用法：
 *   node scripts/runtime/graph-repro.mjs --mode baseline
 *   node scripts/runtime/graph-repro.mjs --mode repro
 *   node scripts/runtime/graph-repro.mjs --mode stress --count 20
 *
 * 依赖 `dist/`（先 npm run build:server），不读线上 API、不连数据库。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const { ingestToolResult, endpointNodeId, evictionRank, MAX_NODES } = await import(`file://${path.join(root, "dist/blackbox/graph/builder.js").replace(/\\/g, "/")}`);

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const mode = arg("mode", "baseline");
const count = Number(arg("count", "1"));
const snapshotPath = path.resolve(root, arg("snapshot", ".workbuddy/graph-repro/snapshot-6761.json"));

if (!fs.existsSync(snapshotPath)) {
  console.error(`快照不存在: ${snapshotPath}`);
  console.error("先用 API 导出一份：见 .workbuddy/graph-repro/README 或阶段 0 记录。");
  process.exit(2);
}
const snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
if (!snapshot.graph?.nodes) {
  console.error("快照缺少 graph.nodes");
  process.exit(2);
}

/**
 * 淘汰档位直接取实现（`evictionRank`），不再在脚本里复制一份。
 * 阶段 2 分档后如果这里还留着手抄的旧口径，基线数字会静默失真。
 */
function rankOf(node, referenced) {
  return evictionRank(node, referenced);
}

function referencedIds(state) {
  const ref = new Set();
  for (const h of state.hypotheses || []) {
    if (h.status && h.status !== "active" && h.status !== "evicted") continue;
    for (const id of h.nodes || []) ref.add(id);
  }
  return ref;
}

function describe(state) {
  const ref = referencedIds(state);
  const nodes = Object.values(state.nodes);
  const dist = {};
  for (const n of nodes) {
    const r = rankOf(n, ref);
    dist[r] = (dist[r] || 0) + 1;
  }
  const testing = nodes.filter(n => n.status === "testing");
  const testingProtected = testing.filter(n => ref.has(n.id)).length;
  const nodeIds = new Set(Object.keys(state.nodes));
  const dangling = (state.edges || []).filter(e => !nodeIds.has(e.source_id) || !nodeIds.has(e.target_id));
  return {
    nodes: nodes.length,
    max_nodes: MAX_NODES,
    edges: (state.edges || []).length,
    dangling_edges: dangling.length,
    at_ceiling: nodes.length >= MAX_NODES,
    pruned_total: state.stats?.pruned ?? null,
    hypotheses: (state.hypotheses || []).length,
    referenced_nodes: ref.size,
    rank_distribution: dist,
    testing_nodes: testing.length,
    testing_protected: testingProtected,
    evictable_pool: nodes.filter(n => rankOf(n, ref) < 1000).length,
  };
}

/** 从固定快照启动一份独立副本：等价固定 seed。 */
function freshState() {
  return structuredClone(snapshot.graph);
}

/** 注入一个"真打过"的端点（origin=request → status=testing），与线上 http.request 200 同形态。 */
function injectOne(state, i) {
  const url = `https://developer.aliyun.com/__repro_${i}__/probe`;
  const id = endpointNodeId(url);
  const before = Object.keys(state.nodes).length;
  const record = { round: i, url, id, before, after: null, survived: null, reported_new: null, ok: null, error: null };
  try {
    const out = ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{
        url, method: "get", status_code: 200, content_length: 1342,
        requested: true, params: ["id"],
      }],
    });
    record.after = Object.keys(state.nodes).length;
    record.survived = Boolean(state.nodes[id]);
    record.reported_new = out.newNodes.includes(id);
    record.ok = true;
  } catch (error) {
    record.after = Object.keys(state.nodes).length;
    record.survived = Boolean(state.nodes[id]);
    record.ok = false;
    record.error = error?.message || String(error);
  }
  return record;
}

if (mode === "baseline") {
  const state = freshState();
  console.log(JSON.stringify({
    snapshot: path.relative(root, snapshotPath),
    captured_at: snapshot.captured_at,
    session: snapshot.session_id,
    session_status: snapshot.status,
    stop_reason: snapshot.stopReason,
    baseline: describe(state),
  }, null, 2));
  process.exit(0);
}

if (mode === "repro") {
  const state = freshState();
  const beforeInfo = describe(state);
  const record = injectOne(state, 0);
  console.log(JSON.stringify({ mode: "repro", before: beforeInfo, record, after: describe(state) }, null, 2));
  process.exit(record.ok ? 0 : 1);
}

if (mode === "stress") {
  const state = freshState();
  const beforeInfo = describe(state);
  const records = [];
  for (let i = 0; i < count; i++) records.push(injectOne(state, i));
  const crashes = records.filter(r => !r.ok);
  const selfPruned = records.filter(r => r.ok && !r.survived);
  const ghostReport = records.filter(r => r.ok && r.reported_new && !r.survived);
  console.log(JSON.stringify({
    mode: "stress",
    count,
    before: beforeInfo,
    summary: {
      crashes: crashes.length,
      self_pruned: selfPruned.length,
      ghost_reported_new: ghostReport.length,
      final_nodes: Object.keys(state.nodes).length,
      pruned_total: state.stats?.pruned ?? null,
    },
    records,
  }, null, 2));
  process.exit(crashes.length ? 1 : 0);
}

if (mode === "signals") {
  const { graphSignals } = await import(`file://${path.join(root, "dist/blackbox/graph/analyze.js").replace(/\\/g, "/")}`);
  const state = freshState();
  // 用图上最近更新的端点当"最近在打什么"：快照没带 graphRecent，这是最接近的替代。
  const recent = Object.values(state.nodes)
    .filter(n => n.type === "endpoint" || String(n.id).startsWith("ep:"))
    .sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0))
    .slice(0, 3)
    .map(n => n.id);
  const signals = graphSignals(state, recent, { quietRounds: 3 });
  console.log(JSON.stringify({
    mode: "signals",
    recent,
    signals: signals.map(s => ({ kind: s.kind, severity: s.severity, text: s.text, data: s.data })),
  }, null, 2));
  process.exit(0);
}

console.error(`未知 mode: ${mode}`);
process.exit(2);

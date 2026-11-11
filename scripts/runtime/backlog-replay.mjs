#!/usr/bin/env node
/**
 * backlog_deferred 离线回放（阶段 4，不改产品代码）。
 *
 * 线上从部署到现在任务簿一次没满过，排队逻辑只有单测覆盖、没有真实 checkpoint 形状验证。
 * 这里拿线上 checkpoint 的副本离线跑：把簿子塞满 → 看是否排队 → 人为腾位 → 看是否 FIFO 补入。
 * 全程只动内存副本，不写数据库、不碰会话。
 *
 * 用法：node scripts/runtime/backlog-replay.mjs [--limit N]
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const { BlackboxProgress } = await import(`file://${path.join(root, "dist/blackbox/progress.js").replace(/\\/g, "/")}`);

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const checkpointPath = path.resolve(root, arg("checkpoint", ".workbuddy/graph-repro/checkpoint-6761.json"));
if (!fs.existsSync(checkpointPath)) {
  console.error(`checkpoint 不存在: ${checkpointPath}`);
  process.exit(2);
}
const snapshot = JSON.parse(fs.readFileSync(checkpointPath, "utf8"));

// resume:false —— 这是"同进程内重读账本"，不是崩溃恢复；否则 in-flight 会被判成结果未知。
const progress = new BlackboxProgress(snapshot, { resume: false });
const initialPending = progress.pendingCount();
// 默认上限贴着当前待办数设，等价"簿子正好满"；--limit 可覆盖。
const limit = Number(arg("limit", String(initialPending)));
progress.taskPendingLimit = limit;

const report = {
  checkpoint: path.relative(root, checkpointPath),
  initial: {
    pending: initialPending,
    limit,
    tasks: Object.keys(progress.state.tasks).length,
    deferred: (progress.state.backlog_deferred || []).length,
  },
  steps: [],
};

/**
 * 三条声明必须**语义不同**：`duplicateOf()` 会按 purpose/target 做语义去重，
 * 三条同义任务（只差 id 后缀）会被判成别名静默吞噬——那是正确行为，
 * 但会掩盖"排队是否 FIFO"这个要验证的点。
 */
const declared = [
  {
    id: "R4_probe_a",
    target: "https://developer.aliyun.com/api/order",
    purpose: "枚举 /api/order 的 order_id 越权：换对象 ID 对比两身份响应",
    playbook: "idor",
  },
  {
    id: "R4_probe_b",
    target: "https://developer.aliyun.com/api/upload",
    purpose: "测试 /api/upload 的参数污染与路径穿越：filename 注入 ../",
    playbook: "logic_bypass",
  },
  {
    id: "R4_probe_c",
    target: "https://developer.aliyun.com/api/report",
    purpose: "验证 /api/report 分页越界导致响应拆分：page_size 放大到 10000",
    playbook: "data_flow",
  },
];

function snap(label) {
  return {
    step: label,
    pending: progress.pendingCount(),
    deferred: (progress.state.backlog_deferred || []).map(entry => ({
      id: String(entry.spec?.id || ""), attempts: entry.attempts, round: entry.round,
    })),
    landed: declared.map(spec => Boolean(progress.state.tasks[spec.id])),
    deferredSeq: progress.state.backlog_deferred_seq ?? 0,
    lastReject: progress.state.backlog_rejects?.at(-1),
  };
}

// ① 簿满时声明 3 条：应当全部排队，且不进任务簿
progress.merge({ required_tasks: declared });
report.steps.push(snap("declare-3-while-full"));

// ② 人为结案 1 条 pending → 下一轮 merge 应 FIFO 补入第 1 条
const victimEntry = Object.entries(progress.state.tasks).find(([, task]) => task.status === "pending");
if (victimEntry) {
  victimEntry[1].status = "blocked";
  victimEntry[1].reason = "离线回放：人为结案腾位";
  victimEntry[1].outcome_reason = "离线回放，不改线上会话";
}
report.freed = victimEntry ? victimEntry[0] : null;
progress.merge({});
report.steps.push(snap("after-free-one-slot"));

// ③ 再结案 1 条 → 应补入第 2 条
const nextVictim = Object.entries(progress.state.tasks).find(([, task]) => task.status === "pending");
if (nextVictim && nextVictim[0] !== report.freed) {
  nextVictim[1].status = "blocked";
  nextVictim[1].reason = "离线回放：第二次人为结案";
  nextVictim[1].outcome_reason = "离线回放，不改线上会话";
  progress.merge({});
  report.steps.push(snap("after-free-second-slot"));
}

report.verdict = (() => {
  const [first, second] = report.steps;
  const issues = [];
  if (!first) return { ok: false, issues: ["没有采集到步骤"] };
  if (first.deferred.length !== 3) issues.push(`簿满时应有 3 条进入排队，实际 ${first.deferred.length} 条`);
  if (first.landed.some(Boolean)) issues.push("簿满时不应有任务直接进任务簿");
  if (first.deferred.map(entry => entry.id).join(",") !== declared.map(spec => spec.id).join(",")) {
    issues.push("排队顺序与声明顺序不一致（应 FIFO）");
  }
  if (second) {
    if (!second.landed[0]) issues.push("腾出一个空位后，第 1 条未补入");
    if (second.deferred.length !== 2) issues.push(`补 1 条后应剩 2 条排队，实际 ${second.deferred.length} 条`);
  }
  const third = report.steps[2];
  if (third) {
    if (!third.landed[1]) issues.push("腾出第二个空位后，第 2 条未补入");
    if (third.landed[2]) issues.push("一次只补 2 条的限制被突破");
  }
  return { ok: issues.length === 0, issues };
})();

console.log(JSON.stringify(report, null, 2));
process.exit(report.verdict.ok ? 0 : 1);

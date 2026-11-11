/**
 * 假设 → 验证任务（2026-10-31）。
 *
 * 事故：m.ctrip.com 那轮图里有 19 条假设（17 条 IDOR），`attempts` 全是 0 ——
 * 假设只写进图，不进任务簿，而执行器只跑任务。于是"想法"与"动作"是两套东西，
 * 44 分钟里真正发出的目标请求只有 2 条。
 *
 * 这个模块把每条活跃假设翻译成一个最小验证任务：
 *   - id 稳定（`H_<kind>_<hash>`），同一假设不会重复入园；
 *   - purpose 里带"打什么 + 怎么判"（1–3 发，verdict 三选一）；
 *   - deliverables 固定为 `verdict`，结案时必须给结论（positive/negative/inconclusive）。
 *
 * 只入前 N 条（默认 3），超出的留在图的 active 列表里等下一轮 —— 任务簿不是越大越好。
 */
import { isActiveHypothesis } from "./graph/hypotheses.js";
import type { Hypothesis } from "./graph/types.js";

export type HypothesisTaskSpec = {
  id: string;
  target: string;
  purpose: string;
  reason: string;
  completion_criteria: string;
  deliverables: string[];
  success_criteria: string;
  fallback_strategy: string;
  source: "hypothesis";
  hypothesis_id: string;
  playbook?: string;
};

/** 32-bit FNV-1a：够短、够稳，不引依赖。 */
function shortHash(value: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

export function hypothesisTaskId(hypothesis: Hypothesis): string {
  return `H_${hypothesis.kind}_${shortHash(hypothesis.id)}`;
}

/** `ep:host/path` → `https://host/path`（保留 {id} 占位，模型自己换值）。 */
function urlOfNode(id: string): string {
  const raw = String(id || "").replace(/^ep:/, "");
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) return raw;
  return `https://${raw}`;
}

function purposeOf(hypothesis: Hypothesis): string {
  const target = urlOfNode(hypothesis.nodes.find(node => node.startsWith("ep:")) || "");
  const head = `验证假设 ${hypothesis.id}：${hypothesis.text}`;
  // 巡检不是"验证漏洞"，别给它套越权口径的步骤——模型会照抄成一次无意义的 id 替换。
  if (hypothesis.kind === "content_review") {
    return `${head}\n${target
      ? `目标 ${target}。只花 1–2 发：先取一次真实正文（http.request；被墙就换 browser.open / burp.entry），`
        + `把页面里出现的 API 路径、表单 action、JS 文件、版本号/调试开关记进结论；`
        + `有新的可打面就给 positive 并在结论里列出它们，纯静态无内容就给 negative。`
      : "取该页面正文并记录其中出现的新攻击面，给 verdict。"}`.slice(0, 1200);
  }
  const steps = target
    ? `目标 ${target}。只花 1–3 发：①按要求替换 id/身份；②与自身 baseline 对照；③给出 verdict（positive=有差异且可复现 / negative=无差异或 404 / inconclusive=被墙或被鉴权挡）。`
    : "按假设文本做 1–3 发最小验证，并给出 verdict。";
  return `${head}\n${steps}`.slice(0, 1200);
}

function hostOf(url: string): string {
  try { return new URL(url).host.toLowerCase(); } catch { return ""; }
}

/**
 * 同类同主机在一批里最多派几条。
 *
 * 默认不限（保持历史行为：auth_wall 等 kind 一直是一批内多条同时派）；
 * `content_review` 限 2 —— 它是"逐页看一眼"，18 个业务页若一批全派出去，
 * 3 个任务名额会被同一类巡检吃光，idor/业务接口的假设就排不上了。
 *
 * 注意这与 `options.occupied` 是两回事：occupied 看的是**任务簿里已有的**在办任务，
 * 看不到本批刚 push 的（实测 3 条同主机巡检一次全派了出去）。
 */
const CONCURRENT_PER_HOST: Record<string, number> = { content_review: 2 };

export function concurrencyOf(kind: string): number {
  return CONCURRENT_PER_HOST[kind] ?? Number.POSITIVE_INFINITY;
}

export function hypothesisTasks(
  active: Hypothesis[],
  options: {
    existing?: (id: string) => boolean;
    limit?: number;
    /**
     * 同一 host 上是否已有同类推断的验证任务在办。
     *
     * 假设是**按端点对**生成的：一轮里 6 条 "验证 .env 与 .git/HEAD 之间的数据流" 会变成
     * 6 条任务、6 份焦点预算，而每条只打 1–3 发、结论同源。实跑 7d81883963ea09f3 在
     * turn 14 一次性灌入 6 条 H_data_flow_*，任务簿从 5 涨到 11，pending 一下顶满。
     * 同类同主机只留一条在办，其余留在图的 active 列表里等下一轮——这正是本模块
     * "只入前 N 条"的原意。
     */
    occupied?: (kind: string, host: string) => boolean;
  } = {},
): HypothesisTaskSpec[] {
  const limit = Math.max(0, options.limit ?? 3);
  const existing = options.existing || (() => false);
  const occupied = options.occupied || (() => false);
  const out: HypothesisTaskSpec[] = [];
  /** 本批已派的 `${kind}@${host}` 计数（见 take 里的注释）。 */
  const takenInBatch = new Map<string, number>();
  // 高优先：idor/object_enum 先于 auth_wall（后者需要身份或墙，前置条件更多）。
  //
  // content_review 排在 auth_wall **之前**（2026-11-05）：两轮实测里 auth_wall 把 3 个名额
  // 全占了（6/6、17 条里 10 条），而它们锚定的都是 attestation 挑战页，一条也没产出；
  // 同时 18 个站点自报业务页 0 次访问。业务页至少能带回新接口/新参数，先给它让路。
  const order: Record<string, number> = { idor: 0, logic_bypass: 1, object_enum: 2, content_review: 3, data_flow: 4, auth_wall: 5, stall: 6, retest_for_status: 7 };
  // stall 是"别再在这条路上换 payload"的提醒，不是待验证目标：不该占验证任务的名额。
  // 2026-10-31 实测：一轮里 29 条 stall 假设把 3 个名额全占了，真假设排不上。
  const take = (hypothesis: Hypothesis): boolean => {
    if (out.length >= limit) return false;
    const id = hypothesisTaskId(hypothesis);
    if (existing(id)) return true; // 已存在：占过位，跳过但不报错
    const target = urlOfNode(hypothesis.nodes.find(node => node.startsWith("ep:")) || "");
    if (occupied(hypothesis.kind, hostOf(target))) return true;
    // 本批已派的同类同主机任务（occupied 只看任务簿、看不到本批，得单独记）。
    const bucket = `${hypothesis.kind}@${hostOf(target)}`;
    const used = takenInBatch.get(bucket) || 0;
    if (used >= concurrencyOf(hypothesis.kind)) return true; // 本批已满，留到下一轮
    takenInBatch.set(bucket, used + 1);
    out.push({
      id,
      target,
      purpose: purposeOf(hypothesis),
      reason: `假设驱动：${hypothesis.kind}（${hypothesis.severity}，${hypothesis.id}）`,
      // 补测任务要的不是 verdict，是一个真实状态码：判据必须跟着换，否则模型会拿
      // "无差异"这种越权口径去交差（2026-11-03 硬出路段 2）。
      ...(hypothesis.kind === "retest_for_status" ? {
        completion_criteria: "用 http.request（或 browser.open）对该目标发一发，拿到真实状态码并写入结论",
        deliverables: ["status_code:number"],
        success_criteria: "响应里出现明确的状态码（含 404/403：那也是结论，说明这条路由存在且被拒绝）",
        fallback_strategy: "再失败就记 inconclusive 并写明失败方式（超时/被墙/连接重置），不要换 payload 重打",
      } : hypothesis.kind === "content_review" ? {
        /**
         * 业务面巡检的验收口径（2026-11-05）。
         *
         * 不能用通用口径：通用文案是"替换 id / 与 baseline 对照"，对静态业务页毫无意义，
         * 模型会照抄成一次无意义的越权尝试。这里要的是"取回正文并说出看到了什么"。
         * positive 不等于"有漏洞"，而是"页面里有新的可打面"——这样结案时能直接产出线索。
         */
        completion_criteria: "取回该页面真实正文（1–2 发），记录状态码/长度，并写出页面里的新攻击面（API 路径 / 表单 action / JS 接口 / 敏感信息）",
        deliverables: ["verdict:positive|negative|inconclusive"],
        success_criteria: "positive=页面里有新的可打面（接口/表单/数据/版本号）；negative=纯静态且无新面；inconclusive=被墙或被鉴权挡",
        fallback_strategy: "被墙就换通道（browser.open / burp.entry）再取一次；仍拿不到就记 inconclusive 并写清挡住它的状态码，不要在同一路径上换 payload 爆破",
      } : {
        completion_criteria: "对假设目标完成 1–3 发最小验证，并在 task_outcomes.reason 里写明 verdict 与两发对照结果",
        deliverables: ["verdict:positive|negative|inconclusive"],
        success_criteria: "verdict 有对照事实支撑（baseline vs 变体；或身份 A vs 身份 B）",
        fallback_strategy: "被墙/被鉴权挡住就记 inconclusive 并写清挡住它的状态码，不要在同一端点上反复重试",
      }),
      source: "hypothesis",
      hypothesis_id: hypothesis.id,
    });
    return true;
  };
  // 双保险：调用方通常已经传 activeHypotheses() 的结果，但这个函数是纯函数，
  // 别处直接传 state.hypotheses 时也不能把冷宫/已定案的派出去。
  // severity 参与排序：同为 auth_wall 时，high 的那条先占名额（配额把 kind 压到 6 条，
  // 实际每轮只有 3 个名额，同 kind 内部必须有次序）。
  const severityRank = (item: Hypothesis): number => (item.severity === "high" ? 0 : 1);
  for (const hypothesis of [...active].filter(item => isActiveHypothesis(item) && item.kind !== "stall" && item.kind !== "retest_for_status")
    .sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || severityRank(a) - severityRank(b))) {
    if (!take(hypothesis)) break;
  }
  // 补测是**低优先级**：高价值假设先把名额占满时，它就留在图的 active 列表里等下一轮
  // （那就是 parked 池——任务簿满时不丢弃，也不挤掉 idor/auth_wall）。
  for (const hypothesis of active.filter(item => isActiveHypothesis(item) && item.kind === "retest_for_status")) {
    if (out.length >= limit) break;
    take(hypothesis);
  }
  return out;
}
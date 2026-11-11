/**
 * 协议回填（Protocol Backfill）
 *
 * 问题：`rebuildProjectBlackboxGraph` 只重建图，不重放 2026-10-28 新增的四个协议。
 * 于是翻历史会话时看到的还是"241 个 untested 节点"的尸检报告——
 * 今天已有的判断力（主权转移 / SPA 缴械 / 字典折叠）无法用来复盘昨天。
 *
 * 这个模块做的事：拿**历史 tool-result 事件**，在内存里按时间顺序喂给四个纯函数协议，
 * 算出"如果当时有这些协议，会在第几条调用转向"，并且**只读**——不改历史账本的任何状态，
 * 输出是一组可写入 `historical_inference` 事件的结论。
 */

import { applySovereignty, redirectOf } from "./sovereignty.js";
import { spaFingerprint } from "./spa.js";
import { planProbes, probeTask } from "./graph/cluster.js";


export type ReplayEvent = {
  id: string;
  kind: string;
  source?: string;
  summary?: string;
  created_at: number;
  data: Record<string, unknown>;
};

export type ReplayFinding = {
  at: number;
  round: number;
  kind: "sovereignty_transfer" | "spa_disarm" | "dict_collapse" | "traffic_waste";
  /** 当时是第几条 tool-result（1-based），用来对齐原始时间轴。 */
  call_index: number;
  text: string;
  data: Record<string, unknown>;
};

export type ReplayResult = {
  session_id: string;
  events_scanned: number;
  tool_results: number;
  /** 重放区间（unix 秒）。 */
  window: { from: number; to: number };
  findings: ReplayFinding[];
  summary: {
    sovereignty: { from_host: string; to_host: string; at_call: number; migrated_targets: number } | null;
    spa: { host: string; bytes: number; at_call: number } | null;
    dict: { host: string; total: number; probes: string[]; at_call: number } | null;
    /** 完全相同的请求重复了多少次（新协议下会被判死 / 域锁拒收）。 */
    duplicates: { url: string; times: number }[];
    /** 历史真实调用数 vs 新协议下的估计调用数。 */
    calls_actual: number;
    calls_with_protocols: number;
  };
  /** 建议追加到账本的事件（kind=historical_inference）。 */
  inferred_events: Array<{ kind: string; text: string; data: Record<string, unknown> }>;
};

function hostOf(url: string): string {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * 纯函数重放：输入按时间排序的 tool-result 事件，输出结论。
 *
 * 不读数据库、不写状态——调用方（desk）负责取事件与落 `historical_inference`。
 */
export function replayProtocols(sessionId: string, events: ReplayEvent[]): ReplayResult {
  const toolResults = events
    .filter(event => String(event.kind) === "tool-result")
    .sort((left, right) => left.created_at - right.created_at);

  const findings: ReplayFinding[] = [];
  const taskState: { tasks?: Record<string, { status?: string; target?: string }>; sovereignty?: never } = {
    tasks: {},
  };
  const requestCounts = new Map<string, number>();
  const dictPaths = new Set<string>();

  let sovereignty: ReplayResult["summary"]["sovereignty"] = null;
  let spa: ReplayResult["summary"]["spa"] = null;
  let dict: ReplayResult["summary"]["dict"] = null;
  let callIndex = 0;

  for (const event of toolResults) {
    callIndex += 1;
    const data = event.data || {};
    const url = String(data.url || "");
    // ① 请求计数：重复打同一 URL 就是新协议下最先被拦掉的那批。
    if (url) requestCounts.set(url, (requestCounts.get(url) || 0) + 1);

    // ② 主权转移
    const hop = redirectOf(data, url);
    if (hop && !sovereignty) {
      // 历史账本里没有任务，这里用一个占位任务看它会不会被搬走
      taskState.tasks = { "T@historical": { status: "running", target: hop.from } };
      const moved = applySovereignty(taskState as never, hop, event.created_at);
      sovereignty = {
        from_host: moved?.from_host || "",
        to_host: moved?.to_host || "",
        at_call: callIndex,
        migrated_targets: moved?.rewrites.length || 0,
      };
      findings.push({
        at: event.created_at, round: callIndex, kind: "sovereignty_transfer", call_index: callIndex,
        text: `第 ${callIndex} 条结果：${hostOf(hop.from)} ${hop.code} → ${hostOf(hop.to)}；新协议会在此时把任务目标搬到新 host 并锁死旧 host`,
        data: { from: hop.from, to: hop.to, code: hop.code, evidence_id: event.id },
      });
    }

    // ③ SPA 外壳
    const print = spaFingerprint(data);
    if (print.is_spa && !spa && url) {
      spa = { host: hostOf(url), bytes: print.bytes, at_call: callIndex };
      findings.push({
        at: event.created_at, round: callIndex, kind: "spa_disarm", call_index: callIndex,
        text: `第 ${callIndex} 条结果：${hostOf(url)} 是 ${print.bytes}B SPA 外壳（${print.signals.slice(0, 3).join("、")}）；新协议会缴步兵的械并强征 browser.open / exec.python`,
        data: { url, bytes: print.bytes, signals: print.signals, evidence_id: event.id },
      });
    }

    // ④ 字典折叠：一次结果里出现 ≥30 个端点
    // 真实 tool-result 的键名不统一：content_discovery 用 hits/paths，api_routes 用 endpoints，
    // 有的嵌在 result 里。这里一次性把它们都摊平，否则回放会漏掉真正的字典轮。
    const asList = (value: unknown): Array<Record<string, unknown> | string> =>
      Array.isArray(value) ? (value as Array<Record<string, unknown> | string>) : [];
    const nested = (data.result && typeof data.result === "object" ? data.result : {}) as Record<string, unknown>;
    const discovered = [
      ...asList(data.endpoints), ...asList(data.hits), ...asList(data.paths),
      ...asList(data.results), ...asList(data.found), ...asList(data.urls),
      // content_discovery 的命中列表叫 items（note.yun 实测 224 条）
      ...asList(data.items),
      ...asList(nested.endpoints), ...asList(nested.hits), ...asList(nested.paths),
      ...asList(nested.results), ...asList(nested.items),
      // 注意：**不要**把 burp.history 的 entries 算进字典——
      // 那是流量记录（本来就是打过一遍的请求），算进去会把"历史流量"当成"新发现的路径"。
    ];
    const toPath = (raw: unknown): string => {
      const value = String(raw ?? "").trim();
      if (!value) return "";
      try { return new URL(value).pathname; } catch { /* 不是绝对 URL，继续 */ }
      const bare = value.split("?")[0]!;
      if (bare.startsWith("/")) return bare;
      // "host/path" 形态：丢掉 host 部分
      const slash = bare.indexOf("/");
      return slash >= 0 ? bare.slice(slash) : `/${bare}`;
    };
    // items 可能是字符串数组（ffuf 的命中列表就是纯路径），也可能是对象数组 —— 两种都要吃。
    const rawOf = (item: Record<string, unknown> | string): unknown => {
      if (typeof item === "string") return item;
      return item.path ?? item.url ?? item.target ?? item.name ?? "";
    };
    const paths = discovered
      .map(item => toPath(rawOf(item)))
      .filter(path => path.startsWith("/") && path.length > 1);
    for (const path of paths) dictPaths.add(path);
    if (paths.length >= 30 && !dict) {
      const host = hostOf(String(rawOf(discovered[0]!) || url || "")) || "UNKNOWN";
      const plan = planProbes([...dictPaths], host, { maxBuckets: 4 });
      const task = probeTask(plan, "replay");
      dict = { host, total: plan.total, probes: plan.buckets.map(bucket => bucket.probe), at_call: callIndex };
      findings.push({
        at: event.created_at, round: callIndex, kind: "dict_collapse", call_index: callIndex,
        text: `第 ${callIndex} 条结果：一次吐出 ${paths.length} 个端点；新协议会折叠成 ${plan.buckets.length} 个探针（${dict.probes.join("、")}）并生成 ${task.id}`,
        data: { host, total: plan.total, probes: dict.probes, task: task.id, evidence_id: event.id },
      });
    }
  }

  const duplicates = [...requestCounts.entries()]
    .filter(([, times]) => times >= 2)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 10)
    .map(([url, times]) => ({ url, times }));

  if (duplicates.length) {
    const worst = duplicates[0]!;
    findings.push({
      at: toolResults[0]?.created_at || 0, round: 0, kind: "traffic_waste", call_index: 0,
      text: `重复请求：${worst.url} 共 ${worst.times} 次；新协议下其中 ${worst.times - 1} 次会被域锁/签名熔断拒收`,
      data: { duplicates },
    });
  }

  const wasted = duplicates.reduce((sum, item) => sum + (item.times - 1), 0);

  return {
    session_id: sessionId,
    events_scanned: events.length,
    tool_results: toolResults.length,
    window: {
      from: toolResults[0]?.created_at || 0,
      to: toolResults[toolResults.length - 1]?.created_at || 0,
    },
    findings,
    summary: {
      sovereignty, spa, dict, duplicates,
      calls_actual: toolResults.length,
      calls_with_protocols: Math.max(0, toolResults.length - wasted),
    },
    inferred_events: findings
      .filter(finding => finding.kind !== "traffic_waste")
      .map(finding => ({
        kind: "historical_inference",
        text: `【回填·${finding.kind}】${finding.text}`,
        data: {
          replay: true,
          inference: finding.kind,
          call_index: finding.call_index,
          at: finding.at,
          ...finding.data,
        },
      })),
  };
}

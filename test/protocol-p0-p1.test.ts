import { describe, expect, it } from "vitest";
import {
  classifyIssues, envelopeSummary, rejectEnvelope, snapshotIssues,
} from "../src/blackbox/validation-envelope.js";
import { expandFromProbe, planProbes } from "../src/blackbox/graph/cluster.js";
import { SPECIALIST_KITS, renderKit, specialistKit } from "../src/blackbox/specialist_kits.js";
import { replayProtocols, type ReplayEvent } from "../src/blackbox/replay_protocols.js";

/**
 * 这一组钉的是 P0/P1 五项：
 *  ① required_tasks 被丢时不再只说 "(item): Invalid input"，而是缺什么键/哪个值错；
 *  ② 聚类展开规则（200 展开 / 412 收敛）；
 *  ③ 特种兵骨架（SPA 逆向模板）；
 *  ④ 协议回填（历史会话离线重放）。
 * ⑤ 零熵熔断（zero_diff_streak ≥2 → blocked）的判据在 desk 里，这里只钉它依赖的差分语义。
 */

describe("结构化校验回执：从「Invalid input」到「缺哪个键」", () => {
  it("把 invalid_type + received=undefined 归为缺键，而不是值错", () => {
    const issues = snapshotIssues([
      { code: "invalid_type", path: ["deliverables"], expected: "array", received: "undefined", message: "Required" },
      { code: "invalid_type", path: ["success_criteria"], expected: "string", received: "undefined", message: "Required" },
    ]);
    const stats = classifyIssues(issues);
    expect(stats.missing).toEqual(["deliverables", "success_criteria"]);
    expect(stats.invalid).toEqual({});
  });

  it("值错写清 expected / received，未知键单独列", () => {
    const issues = snapshotIssues([
      { code: "invalid_type", path: ["priority"], expected: "number", received: "string", message: "Expected number, received string" },
      { code: "unrecognized_keys", path: [], keys: ["priority_hint"], message: "Unrecognized key(s)" },
    ]);
    const stats = classifyIssues(issues);
    expect(stats.invalid.priority).toBe("expected number, got string");
    expect(stats.unknown).toEqual(["priority_hint"]);
  });

  it("union 全灭时报告「最接近成功」的那一支（缺键最少）", () => {
    const issues = snapshotIssues([{
      code: "invalid_union",
      path: [],
      message: "Invalid input",
      unionErrors: [
        { issues: [
          { code: "invalid_type", path: ["id"], expected: "string", received: "undefined", message: "Required" },
          { code: "invalid_type", path: ["target"], expected: "string", received: "undefined", message: "Required" },
          { code: "invalid_type", path: ["purpose"], expected: "string", received: "undefined", message: "Required" },
        ] },
        { issues: [
          { code: "invalid_type", path: ["id"], expected: "string", received: "undefined", message: "Required" },
        ] },
      ],
    }]);
    const stats = classifyIssues(issues);
    // 第二支只缺 id，应被选中
    expect(stats.missing).toEqual(["id"]);
  });

  it("回执带 target / 示例 / 人话 hint（模型照着填空就能过）", () => {
    const envelope = rejectEnvelope(
      snapshotIssues([{ code: "invalid_type", path: ["deliverables"], expected: "array", received: "undefined", message: "Required" }]),
      { field: "required_tasks", index: 2, example: { id: "T_x", deliverables: ["js_content"] } },
    );
    expect(envelope.status).toBe("rejected");
    expect(envelope.target).toBe("required_tasks[2]");
    expect(envelope.missing_keys).toEqual(["deliverables"]);
    expect(envelope.correct_shape_example).toEqual({ id: "T_x", deliverables: ["js_content"] });
    expect(envelope.hint).toContain("只改这一条");
    expect(envelopeSummary(envelope)).toBe("required_tasks[2]: 缺 deliverables");
  });

  it("条目级错误（不是对象）也有可读说明，而不是空回执", () => {
    const envelope = rejectEnvelope(
      snapshotIssues([{ code: "invalid_type", path: [], expected: "object", received: "string", message: "Expected object, received string" }]),
      { field: "findings", index: 0 },
    );
    expect(envelope.invalid_keys["(item)"]).toContain("expected object");
    expect(envelopeSummary(envelope)).toContain("findings[0]");
  });
});

describe("聚类展开规则：探针结果决定下一步，而不是重新抽样", () => {
  const plan = planProbes(
    ["/.env", "/.git/config", "/backup.zip", "/config.php", "/graphql", "/v3/api-docs", "/openapi.json", "/redoc", "/admin", "/login", "/druid/index.html"],
    "cloud.oppo.com",
    { maxBuckets: 3 },
  );

  it("412 → 整类收敛（同类剩余一条都不打）", () => {
    const expansion = expandFromProbe(plan, { probe: "/.env", status: 412, blocked: true });
    expect(expansion.verdict).toBe("collapse");
    expect(expansion.bucket).toBe("sensitive");
    expect(expansion.collapse).toEqual(["/.git/config", "/backup.zip", "/config.php"]);
    expect(expansion.reason).toContain("泛化拦截");
  });

  it("200 → 展开同类下 3 条并交给下一轮焦点", () => {
    // 代表是按"最短路径"选的（确定性），所以这里从 plan 里取真实代表，不硬编 /graphql
    const apiDocProbe = plan.buckets.find(bucket => bucket.name === "api_doc")!.probe;
    const expansion = expandFromProbe(plan, { probe: apiDocProbe, status: 200 });
    expect(expansion.verdict).toBe("expand");
    expect(expansion.bucket).toBe("api_doc");
    expect(expansion.expand.length).toBe(3);
    expect(expansion.expand).not.toContain(apiDocProbe);
  });

  it("catch-all 同形响应 → 视为不可判定，整类标灰而不是当命中", () => {
    const expansion = expandFromProbe(plan, { probe: "/admin", status: 200, catch_all: true });
    expect(expansion.verdict).toBe("collapse");
    expect(expansion.reason).toContain("catch-all");
  });

  it("404 之类不产生动作（换下一个类别的代表）", () => {
    const expansion = expandFromProbe(plan, { probe: "/graphql", status: 404 });
    expect(expansion.verdict).toBe("skip");
    expect(expansion.expand).toEqual([]);
    expect(expansion.collapse).toEqual([]);
  });
});

describe("特种兵骨架：SPA 逆向不再要求模型现场写脚本", () => {
  it("首选骨架是 Playwright 抓 XHR，且占位符可替换", () => {
    const kit = specialistKit();
    expect(kit.id).toBe("spa_xhr_capture");
    expect(kit.tool).toBe("exec.python");
    const code = renderKit(kit, "https://cloud.oppo.com/");
    expect(code).toContain('TARGET = "https://cloud.oppo.com/"');
    expect(code).not.toContain("{{TARGET_URL}}");
    expect(code).toContain("networkidle");
  });

  it("零依赖的内联常量提取作为备选", () => {
    const kit = SPECIALIST_KITS.find(item => item.id === "spa_inline_constants")!;
    expect(kit.code).toContain("apiBase");
    expect(renderKit(kit, "https://x.test/")).toContain("https://x.test/");
  });

  it("每份骨架都声明交付物，能对任务契约", () => {
    for (const kit of SPECIALIST_KITS) expect(kit.deliverable.length).toBeGreaterThan(6);
  });
});

describe("协议回填：用今天的判据复盘昨天的会话", () => {
  const events: ReplayEvent[] = [
    { id: "ev-1", kind: "tool-result", created_at: 1, data: { url: "http://note.yun.oppo.com/", status: 301, location: "https://cloud.oppo.com/" } },
    { id: "ev-2", kind: "tool-result", created_at: 2, data: {
      url: "https://cloud.oppo.com/", status: 200, content_type: "text/html", body_bytes: 5158,
      body: '<div id="root"></div><script>window.__CFG__={}</script>' } },
    { id: "ev-3", kind: "tool-result", created_at: 3, data: {
      url: "https://cloud.oppo.com/", status: 200, content_type: "text/html", body_bytes: 5158,
      body: '<div id="root"></div><script>window.__CFG__={}</script>' } },
    { id: "ev-4", kind: "tool-result", created_at: 4, data: {
      url: "https://cloud.oppo.com/", status: 200,
      endpoints: Array.from({ length: 40 }, (_, index) => ({ path: `/p${index}.js`, url: `https://cloud.oppo.com/p${index}.js` })) } },
    { id: "ev-5", kind: "tool-result", created_at: 5, data: { url: "http://note.yun.oppo.com/flag", status: 301, location: "https://cloud.oppo.com/" } },
    { id: "ev-6", kind: "agent-analysis", created_at: 6, data: { summary: "not a tool result" } },
  ];
  const result = replayProtocols("sess-1", events);

  it("只扫 tool-result，并按时间顺序推进", () => {
    expect(result.events_scanned).toBe(6);
    expect(result.tool_results).toBe(5);
    expect(result.window).toEqual({ from: 1, to: 5 });
  });

  it("三条结论都出来了：主权转移 / SPA 缴械 / 字典折叠", () => {
    expect(result.summary.sovereignty).toMatchObject({ from_host: "note.yun.oppo.com", to_host: "cloud.oppo.com", at_call: 1 });
    expect(result.summary.spa?.bytes).toBe(5158);
    expect(result.summary.dict?.total).toBeGreaterThanOrEqual(40);
    expect(result.summary.dict?.probes.length).toBeGreaterThan(0);
    expect(result.findings.map(item => item.kind)).toEqual(expect.arrayContaining(["sovereignty_transfer", "spa_disarm", "dict_collapse"]));
  });

  it("重复请求被单独统计，并折算出「新协议下会省掉多少次」", () => {
    const dup = result.summary.duplicates.find(item => item.url === "https://cloud.oppo.com/");
    expect(dup?.times).toBe(3);
    expect(result.summary.calls_actual).toBe(5);
    expect(result.summary.calls_with_protocols).toBeLessThan(5);
  });

  it("回填事件是 historical_inference，带 replay 标记（前端据此画虚线）", () => {
    expect(result.inferred_events.length).toBeGreaterThanOrEqual(3);
    for (const event of result.inferred_events) {
      expect(event.kind).toBe("historical_inference");
      expect(event.data.replay).toBe(true);
      expect(String(event.text)).toContain("【回填·");
    }
  });

  it("空会话不崩，也不编结论", () => {
    const empty = replayProtocols("sess-2", []);
    expect(empty.tool_results).toBe(0);
    expect(empty.findings).toEqual([]);
    expect(empty.summary.sovereignty).toBeNull();
    expect(empty.inferred_events).toEqual([]);
  });
});
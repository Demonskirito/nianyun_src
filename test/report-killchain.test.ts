import { describe, expect, it } from "vitest";
import { blackboxReport } from "../src/blackbox/findings.js";
import { ingestToolResult, graphState, applyHypotheses, deriveHypotheses, killChainForTarget } from "../src/blackbox/graph/index.js";

/** 3 节点 1 边：入口 → 订单详情（漏洞端点）。报告必须把这条路画出来。 */
function graphOf(): ReturnType<typeof graphState> {
  const state = graphState(undefined);
  ingestToolResult(state, { tool: "katana.crawl", evidence_id: "ev-1",
    links: [{ from: "https://t.example/", to: "https://t.example/order/detail" }] });
  ingestToolResult(state, { tool: "http.diff", evidence_id: "ev-2",
    endpoints: [{ url: "https://t.example/order/detail", status_code: 200 }],
    vulnerabilities: [{ url: "https://t.example/order/detail", kind: "idor" }] });
  applyHypotheses(state, deriveHypotheses(state));
  return state;
}

function sessionWith(graph?: unknown): Record<string, unknown> {
  return {
    id: "s-1", target: "https://t.example/", status: "paused",
    checkpoint: {
      stopReason: "budget",
      tasks: { t1: { status: "completed", evidence_ids: ["ev-1"] } },
      findings: {
        f1: {
          id: "f1", title: "订单详情越权", type: "idor", target: "https://t.example/order/detail",
          description: "跨用户读取订单", impact: "泄露他人订单", severity: "high",
          reproduction_steps: ["用 A 的 cookie 请求 B 的 order_id", "对比响应体"],
          evidence_ids: ["ev-2"], remediation: "校验归属", confidence: "high", status: "confirmed",
        },
      },
      ...(graph ? { graph } : {}),
    },
    evidence: [{ id: "ev-2", kind: "tool-result", data: { ok: true, url: "https://t.example/order/detail" } }],
    events: [],
  };
}

describe("P0-1：报告接入 Kill Chain", () => {
  it("confirmed finding 的复现步骤前出现 mermaid 攻击路径", () => {
    const { markdown } = blackboxReport(sessionWith(graphOf()));
    expect(markdown).toContain("攻击路径（历程图）：");
    expect(markdown).toContain("```mermaid");
    expect(markdown).toContain("graph LR");
    expect(markdown).toContain("ep:t.example/");
    expect(markdown).toContain("vuln:idor@t.example/order/detail");
    // 路径在复现步骤之前
    expect(markdown.indexOf("攻击路径（历程图）：")).toBeLessThan(markdown.indexOf("复现步骤："));
  });

  it("json 里带 kill_chain 数组（下游能直接消费）", () => {
    const { json } = blackboxReport(sessionWith(graphOf()));
    const finding = (json.findings as Array<Record<string, unknown>>)[0]!;
    const chain = finding.kill_chain as string[];
    expect(Array.isArray(chain)).toBe(true);
    expect(chain.length).toBeGreaterThan(1);
    expect(chain[chain.length - 1]).toBe("vuln:idor@t.example/order/detail");
  });

  it("没有图时退回纯步骤形态，且不编造路径", () => {
    const { markdown, json } = blackboxReport(sessionWith(undefined));
    expect(markdown).not.toContain("```mermaid");
    expect((json.findings as Array<Record<string, unknown>>)[0]!.kill_chain).toEqual([]);
    expect(markdown).toContain("复现步骤：");
  });

  it("图里没有该资产时也不编路径", () => {
    const state = graphState(undefined);
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: "https://other.example/x", status_code: 200 }] });
    const { markdown } = blackboxReport(sessionWith(state));
    expect(markdown).not.toContain("```mermaid");
  });

  it("killChainForTarget 优先从 vuln_state 回溯", () => {
    const state = graphOf();
    const result = killChainForTarget(state, "https://t.example/order/detail");
    expect(result?.node).toBe("vuln:idor@t.example/order/detail");
    expect(result?.chain[0]).toBe("ep:t.example/");
    expect(killChainForTarget(state, "https://t.example/absent")).toBeNull();
  });

  it("报告渲染不因 malformed graph 崩", () => {
    const { markdown } = blackboxReport(sessionWith({ version: 99, nodes: {} }));
    expect(markdown).toContain("复现步骤：");
  });
});
describe("报告要写出\"申报未达成\"的交付物（第五/七场都是靠豁免才结案的）", () => {
  const session = (): Record<string, unknown> => ({
    id: "s-2", target: "https://t.example/", status: "paused",
    checkpoint: {
      stopReason: "budget",
      tasks: { t1: { status: "completed", outcome_reason: "verified_negative: 敏感路径全 404 同指纹" } },
      findings: {},
      deliverables_waived: [{ at: 1, task_id: "t1", items: ["exposed_endpoint", "sensitive_path_probe_result"] }],
    },
    evidence: [], events: [],
  });

  it("markdown 有独立的\"部分交付物未达成\"段落并逐条列出", () => {
    const { markdown } = blackboxReport(session());
    expect(markdown).toContain("## 部分交付物未达成");
    expect(markdown).toContain("- `t1` · 未达成：`exposed_endpoint`, `sensitive_path_probe_result`");
    // 段落位置必须在"任务覆盖"之后、"候选发现"之前：先看做了什么，再看缺口在哪。
    expect(markdown.indexOf("## 部分交付物未达成")).toBeGreaterThan(markdown.indexOf("## 任务覆盖"));
    expect(markdown.indexOf("## 部分交付物未达成")).toBeLessThan(markdown.indexOf("## 候选发现与复核"));
  });

  it("JSON 里也带 deliverables_waived，便于下游按任务过滤", () => {
    const { json } = blackboxReport(session());
    expect(json.deliverables_waived).toEqual([{ task_id: "t1", items: ["exposed_endpoint", "sensitive_path_probe_result"] }]);
  });

  it("没有豁免时不出现该段落（避免空标题）", () => {
    const s = session();
    (s.checkpoint as Record<string, unknown>).deliverables_waived = [];
    expect(blackboxReport(s).markdown).not.toContain("部分交付物未达成");
  });
});

describe("报告不写单次调用的记账伪任务", () => {
  it("action:<hash> 不进\"任务覆盖\"（它们是内部记账，读者只看得到一串哈希）", () => {
    const { markdown, json } = blackboxReport({
      id: "s-3", target: "https://t.example/", status: "cancelled",
      checkpoint: {
        stopReason: "operator_cancelled",
        tasks: {
          T1: { status: "completed", outcome_reason: "verified_negative: 全 404" },
          "action:8ce5a2ac5a79ae7a4862d6849642555116e373606c4e99ed04bdbb11ae67fc0f": { status: "blocked", reason: "interrupted_unknown_outcome" },
        },
        findings: {},
      },
      evidence: [], events: [],
    });
    expect(markdown).not.toContain("action:");
    expect((json.tasks as Array<{ id: string }>).map(task => task.id)).toEqual(["T1"]);
  });
});

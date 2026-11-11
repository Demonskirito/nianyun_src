import { describe, expect, it } from "vitest";
import { deriveHypotheses } from "../src/blackbox/graph/hypotheses.js";
import { ingestToolResult } from "../src/blackbox/graph/builder.js";
import { EMPTY_GRAPH, type AttackGraphState } from "../src/blackbox/graph/types.js";
import { hypothesisTasks, hypothesisTaskId } from "../src/blackbox/hypothesis_tasks.js";
import { computeFocus } from "../src/blackbox/focus.js";
import { splitToolInput } from "../src/blackbox/protocol.js";
import type { RunCheckpoint } from "../src/blackbox/progress.js";

function fresh(): AttackGraphState {
  return { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
}

describe("假设语义门（2026-10-31）", () => {
  it("构建产物里的 {id} 不产生 IDOR 假设", () => {
    const graph = fresh();
    ingestToolResult(graph, {
      tool: "katana.crawl",
      endpoints: [
        { url: "https://webresource.c-ctrip.com/NFES/mfe_compose/{id}/compose.preact.js", origin: "js" },
        { url: "https://webresource.c-ctrip.com/NFES/car/{id}/_next/static/css/4f190fb7.css", origin: "js" },
      ],
    });
    const hypotheses = deriveHypotheses(graph);
    expect(hypotheses.filter(item => item.kind === "idor")).toHaveLength(0);
  });

  it("带对象语义的接口路径仍然产生 high IDOR，并提示先做身份对照", () => {
    const graph = fresh();
    ingestToolResult(graph, {
      tool: "browser.network",
      endpoints: [{ url: "https://m.ctrip.com/webapp/order/{id}/detail", origin: "api", requested: true, status_code: 200 }],
    });
    const hypotheses = deriveHypotheses(graph);
    const idor = hypotheses.find(item => item.kind === "idor");
    expect(idor).toBeDefined();
    expect(idor!.severity).toBe("high");
    expect(idor!.text).toContain("匿名");
  });

  it("既非静态也非接口的页面路径降级成 object_enum（medium，不占 high 权重）", () => {
    const graph = fresh();
    ingestToolResult(graph, {
      tool: "katana.crawl",
      endpoints: [{ url: "https://pages.ctrip.com/commerce/promote/{id}/vacation/bzh/index.html", origin: "link" }],
    });
    const hypotheses = deriveHypotheses(graph);
    expect(hypotheses.some(item => item.kind === "idor")).toBe(false);
    const enumHypothesis = hypotheses.find(item => item.kind === "object_enum");
    expect(enumHypothesis).toBeDefined();
    expect(enumHypothesis!.severity).toBe("medium");
  });
});

describe("假设 → 验证任务（2026-10-31）", () => {
  it("为活跃假设生成 H_ 任务，带 verdict 交付物，且不重复入园", () => {
    const graph = fresh();
    ingestToolResult(graph, {
      tool: "browser.network",
      endpoints: [{ url: "https://m.ctrip.com/webapp/order/{id}/detail", origin: "api", requested: true, status_code: 200 }],
    });
    const hypotheses = deriveHypotheses(graph);
    const specs = hypothesisTasks(hypotheses, { limit: 1 });
    expect(specs).toHaveLength(1);
    expect(specs[0]!.id).toBe(hypothesisTaskId(hypotheses.find(item => item.kind === "idor")!));
    expect(specs[0]!.id.startsWith("H_")).toBe(true);
    expect(specs[0]!.deliverables).toEqual(["verdict:positive|negative|inconclusive"]);
    expect(specs[0]!.purpose).toContain("verdict");
    // 已入库的假设不再生成第二次
    const again = hypothesisTasks(hypotheses, { limit: 1, existing: id => id === specs[0]!.id });
    expect(again).toHaveLength(0);
  });
});

describe("排他任务与焦点锁对齐（2026-10-31）", () => {
  it("exclusive_task 存在时焦点自动切到它，避免请求被整批 skip", () => {
    const state = {
      tasks: {
        T_old: { status: "pending", target: "https://m.ctrip.com/", purpose: "旧焦点" },
        T_post: { status: "pending", target: "https://m.ctrip.com/", purpose: "排他任务" },
      },
      focus_task_id: "T_old",
      exclusive_task: "T_post",
      graph: EMPTY_GRAPH,
    } as unknown as RunCheckpoint;
    const choice = computeFocus(state);
    expect(choice?.task_id).toBe("T_post");
    expect(choice?.reason).toBe("exclusive");
  });
});

describe("工具输入契约（2026-10-31）", () => {
  it("exec.* 的 code/script/timeout_s 不再被摘键", () => {
    const { clean, ignored } = splitToolInput({ code: "print(1)", script: "echo hi", timeout_s: 60, memory_mb: 512, network: true });
    expect(clean.code).toBe("print(1)");
    expect(clean.script).toBe("echo hi");
    expect(clean.timeout_s).toBe(60);
    expect(ignored).toEqual([]);
  });

  it("browser.network 的过滤键与 burp 的 host 过滤键都被接受", () => {
    const { clean, ignored } = splitToolInput({ host: "m.ctrip.com", resource_type: "xhr", since_ms: 60000, include_post_data: true });
    expect(clean.host).toBe("m.ctrip.com");
    expect(clean.resource_type).toBe("xhr");
    expect(ignored).toEqual([]);
  });
});
describe("同类推断在同一主机上只留一条在办（7d81883963ea09f3 的 6 条 H_data_flow_*）", () => {
  const hypo = (id: string, kind: "data_flow" | "idor", nodes: string[]) => ({
    id, kind, text: "假设文本", nodes, severity: "medium" as const, created_at: 0,
  });

  it("同类同主机已有在办任务时不再入队，办完才轮下一条", () => {
    const active = [
      hypo("data_flow:ep:im.ctrip.com/.env|ep:im.ctrip.com/.git/HEAD", "data_flow", ["ep:im.ctrip.com/.env", "ep:im.ctrip.com/.git/HEAD"]),
      hypo("data_flow:ep:im.ctrip.com/.git/HEAD|ep:im.ctrip.com/actuator/health", "data_flow", ["ep:im.ctrip.com/.git/HEAD", "ep:im.ctrip.com/actuator/health"]),
      hypo("data_flow:ep:im.ctrip.com/.env|ep:im.ctrip.com/actuator/health", "data_flow", ["ep:im.ctrip.com/.env", "ep:im.ctrip.com/actuator/health"]),
    ];
    // 账上已经有一条 im.ctrip.com 的 data_flow 在办 → 这一轮一条都不该再入队
    const busyHosts = ["im.ctrip.com"];
    const specs = hypothesisTasks(active as never, {
      limit: 3,
      occupied: (kind, host) => kind === "data_flow" && busyHosts.includes(host),
    });
    expect(specs).toHaveLength(0);
    // 那条办完了：下一轮才轮到下一条，一次只放一条
    const next = hypothesisTasks(active as never, { limit: 3, occupied: () => false });
    expect(next).toHaveLength(3);
  });

  it("不同 kind 或不同主机的假设照旧各占一条", () => {
    const active = [
      hypo("idor:ep:im.ctrip.com/a", "idor", ["ep:im.ctrip.com/a"]),
      hypo("data_flow:ep:im.ctrip.com/.env|ep:im.ctrip.com/.git/HEAD", "data_flow", ["ep:im.ctrip.com/.env"]),
      hypo("data_flow:ep:im3.ctrip.com/x|ep:im3.ctrip.com/y", "data_flow", ["ep:im3.ctrip.com/x"]),
    ];
    const occupiedHosts: string[] = [];
    const specs = hypothesisTasks(active as never, {
      limit: 3,
      occupied: (kind, host) => kind === "data_flow" && occupiedHosts.includes(host),
    });
    expect(specs.map(spec => spec.id).filter(id => id.startsWith("H_"))).toHaveLength(3);
  });
});

/**
 * 消费侧 #6-1：`origin` / `status_unknown` 必须进 prompt，且默认态要压缩掉。
 *
 * 为什么值得单独立测试：这两个字段是假设生成、漂移巡检的判定依据，
 * 但模型看不到它们时，"我为什么被拦"对模型就是黑箱。同时 500 个节点每个带一遍
 * `origin:discovery` 是纯浪费——所以既要"看得见"，又要"默认态不占字符"。
 */
import { describe, expect, it } from "vitest";
import {
  ATTACK_GRAPH_FIELD_LEGEND, graphContextView, graphState, ingestToolResult, upsertNode,
} from "../src/blackbox/graph/index.js";

const fresh = () => graphState(undefined);

describe("serialize：事实层字段进上下文", () => {
  it("真打过的节点显式带 origin:request，被动发现的省略 origin", () => {
    const state = fresh();
    upsertNode(state, {
      id: "ep:t.example/api/order",
      type: "endpoint",
      status: "testing",
      properties: { method: "GET", status_code: 200, origin: "request", status_unknown: false },
    });
    upsertNode(state, {
      id: "ep:t.example/help",
      type: "endpoint",
      status: "untested",
      properties: { origin: "discovery" },
    });

    const view = graphContextView(state);
    const request = view.nodes.find(node => node.id === "ep:t.example/api/order")!;
    const discovery = view.nodes.find(node => node.id === "ep:t.example/help")!;

    expect(request.props?.origin).toBe("request");
    expect(discovery.props?.origin).toBeUndefined();
    // 压缩是"省略默认态"，不是丢掉事实：节点的 status 仍然区分得开两种来源。
    expect(request.status).toBe("testing");
    expect(discovery.status).toBe("untested");
  });

  it("status_unknown 只在 true 时出现，false 被压缩掉", () => {
    const state = fresh();
    upsertNode(state, {
      id: "ep:t.example/api/probe",
      type: "endpoint",
      status: "testing",
      properties: { origin: "request", status_unknown: true },
    });
    upsertNode(state, {
      id: "ep:t.example/api/ok",
      type: "endpoint",
      status: "testing",
      properties: { origin: "request", status_code: 200, status_unknown: false },
    });

    const view = graphContextView(state);
    const probe = view.nodes.find(node => node.id === "ep:t.example/api/probe")!;
    const ok = view.nodes.find(node => node.id === "ep:t.example/api/ok")!;

    expect(probe.props?.status_unknown).toBe(true);
    expect(probe.props?.status_code).toBeUndefined(); // 绝不编一个 200
    expect(ok.props?.status_unknown).toBeUndefined();
    expect(ok.props?.status_code).toBe(200);
  });

  it("图例在视图最前，且 counts 里能数出「打了没回」的端点", () => {
    const state = fresh();
    upsertNode(state, { id: "ep:t.example/a", type: "endpoint", status: "testing", properties: { origin: "request", status_unknown: true } });
    upsertNode(state, { id: "ep:t.example/b", type: "endpoint", status: "testing", properties: { origin: "request", status_unknown: true } });
    upsertNode(state, { id: "ep:t.example/c", type: "endpoint", status: "testing", properties: { origin: "request", status_code: 200 } });

    const view = graphContextView(state);
    expect(view.field_legend).toEqual(ATTACK_GRAPH_FIELD_LEGEND);
    expect(Object.keys(view)[0]).toBe("field_legend");
    expect(view.field_legend.join("\n")).toContain("origin:request");
    expect(view.field_legend.join("\n")).toContain("status_unknown:true");
    expect(view.counts.probed_unknown).toBe(2);
  });

  it("ingest 的 probe 证据会落成 status_unknown（不是 200，也不是 discovery）", () => {
    const state = fresh();
    // nuclei 命中：确实发了包，但结果里没有状态码字段。
    // 注意 endpointNodeId 会把 /api/user/1 折叠成 /api/user/{id}。
    ingestToolResult(state, {
      tool: "nuclei",
      endpoints: [{ url: "https://t.example/api/user/1", origin: "request", requested: true, status_unknown: true }],
    });
    const node = state.nodes["ep:t.example/api/user/{id}"]!;
    expect(node.properties.origin).toBe("request");
    expect(node.properties.status_unknown).toBe(true);
    expect(node.properties.status_code).toBeUndefined();
    // 动过 → testing，不会重复派"首打"任务。
    expect(node.status).toBe("testing");

    const view = graphContextView(state);
    expect(view.nodes.find(item => item.id === "ep:t.example/api/user/{id}")?.props?.status_unknown).toBe(true);
  });

  it("后来拿到真状态码时，旧的 status_unknown 必须被清掉", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "nuclei",
      endpoints: [{ url: "https://t.example/api/user/1", origin: "request", requested: true, status_unknown: true }],
    });
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/api/user/1", origin: "request", requested: true, status_code: 200 }],
    });
    const node = state.nodes["ep:t.example/api/user/{id}"]!;
    expect(node.properties.status_code).toBe(200);
    // 浅合并会留下旧 true —— 不清掉的话这个节点会被永远当成"没拿到状态"。
    expect(node.properties.status_unknown).toBe(false);
    expect(graphContextView(state).counts.probed_unknown).toBe(0);
  });
});

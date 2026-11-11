import { describe, expect, it } from "vitest";
import { identityDirective, resolveIdentity } from "../src/blackbox/identity.js";
import { objectValuesOf } from "../src/blackbox/graph/endpoint.js";
import { ingestToolResult } from "../src/blackbox/graph/builder.js";
import { deriveHypotheses } from "../src/blackbox/graph/hypotheses.js";
import { EMPTY_GRAPH, type AttackGraphState } from "../src/blackbox/graph/types.js";
import type { CookieRecord } from "../src/blackbox/cookies.js";

function cookie(name: string, domain: string): CookieRecord {
  return { name, value: "x", domain, path: "/", hostOnly: false, secure: true, httpOnly: true, expires: Math.floor(Date.now() / 1000) + 3600 };
}

describe("身份接线（2026-10-31）", () => {
  it("显式身份优先于 Cookie 判定", () => {
    const state = resolveIdentity({ explicit: "user_b", cookies: [cookie("UQID", "m.ctrip.com")], target: "https://m.ctrip.com/" });
    expect(state.role).toBe("user_b");
    expect(state.source).toBe("explicit");
    expect(state.cookie_names).toContain("UQID");
  });

  it("目标 host 的会话类 Cookie 判定为 auth", () => {
    const state = resolveIdentity({ cookies: [cookie("UQID", "ctrip.com"), cookie("cticket", "m.ctrip.com")], target: "https://m.ctrip.com/webapp/" });
    expect(state.role).toBe("auth");
    expect(state.source).toBe("cookie");
    expect(state.cookie_names).toContain("cticket");
  });

  it("非会话类 Cookie 不构成登录态（_pd 这类埋点不算）", () => {
    const state = resolveIdentity({ cookies: [cookie("_pd", "m.ctrip.com"), cookie("GUID", "ctrip.com")], target: "https://m.ctrip.com/" });
    expect(state.role).toBe("anon");
    expect(state.source).toBe("anon");
  });

  it("别的域的会话 Cookie 不会把当前 host 判成 auth", () => {
    const state = resolveIdentity({ cookies: [cookie("JSESSIONID", "gray-push-intl.oppo.com")], target: "https://m.ctrip.com/" });
    expect(state.role).toBe("anon");
  });

  it("身份一句话把越权结论的前提写清楚", () => {
    expect(identityDirective({ role: "anon", source: "anon", host: "m.ctrip.com", cookie_names: [] })).toContain("匿名");
    const auth = identityDirective({ role: "auth", source: "cookie", host: "m.ctrip.com", cookie_names: ["cticket"] });
    expect(auth).toContain("双身份对照");
    expect(auth).toContain("cticket");
  });
});

describe("对象模型：被观测到的 {id} 值", () => {
  it("从具体 URL 与模板对齐出对象值", () => {
    expect(objectValuesOf("https://m.ctrip.com/webapp/order/8817263/detail", "/webapp/order/{id}/detail")).toEqual(["8817263"]);
    expect(objectValuesOf("https://m.ctrip.com/api/user/9f8e7d6c5b4a3210/profile", "/api/user/{id}/profile")).toEqual(["9f8e7d6c5b4a3210"]);
  });

  it("段数不一致或没有模板段时返回空（不猜）", () => {
    expect(objectValuesOf("https://m.ctrip.com/webapp/order/detail", "/webapp/order/{id}/detail")).toEqual([]);
    expect(objectValuesOf("https://m.ctrip.com/webapp/order/1/detail", "/webapp/order/detail")).toEqual([]);
  });

  it("ingest 把对象值累积进节点属性并去重", () => {
    const graph: AttackGraphState = { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
    const url = "https://m.ctrip.com/webapp/order/{id}/detail";
    for (const value of ["8817263", "8817264", "8817263"]) {
      ingestToolResult(graph, {
        tool: "http.request",
        endpoints: [{
          url, requested: true, origin: "request", status_code: 200,
          object_values: objectValuesOf(`https://m.ctrip.com/webapp/order/${value}/detail`, "/webapp/order/{id}/detail"),
        }],
      });
    }
    const node = graph.nodes["ep:m.ctrip.com/webapp/order/{id}/detail"]!;
    expect(node.properties.object_ids).toEqual(["8817263", "8817264"]);
    expect(node.properties.object_id).toBe("8817264");
  });

  it("IDOR 假设带上已观测对象值，两身份对照有同一对象可比", () => {
    const graph: AttackGraphState = { ...EMPTY_GRAPH, nodes: {}, edges: [], hypotheses: [], stats: { ...EMPTY_GRAPH.stats } };
    ingestToolResult(graph, {
      tool: "http.request",
      endpoints: [{
        url: "https://m.ctrip.com/webapp/order/{id}/detail", requested: true, origin: "request", status_code: 200,
        object_values: ["8817263"],
      }],
    });
    const idor = deriveHypotheses(graph).find(hypothesis => hypothesis.kind === "idor");
    expect(idor).toBeDefined();
    expect(idor!.text).toContain("已观测对象值 8817263");
  });
});
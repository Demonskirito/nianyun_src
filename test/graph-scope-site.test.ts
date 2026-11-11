/**
 * 站点边界（2026-11-04）。
 *
 * 实测背景：9cb376 会话首页抓一次链接就入图 170 条，其中 **161 条**是
 * `*.console.aliyun.com`（ecs / vpc / oss / slb / pai / bailian … 阿里云产品控制台
 * 的导航外链），占端点总数 92%，而目标本体 `wanxiaozhi.aliyun.com` 只剩 4 个静态端点。
 *
 * 根因是 `inScope` 用 registrable（host 后两段）判"同注册域"：
 * `registrable("wanxiaozhi.aliyun.com") === "aliyun.com"`，于是整个 aliyun.com 都算同站点。
 * 共享注册域 ≠ 共享攻击面 —— `ecs.console.aliyun.com` 和 `wanxiaozhi.aliyun.com`
 * 是两个完全不同的应用。
 *
 * 新判据两条：
 *   ① 站点边界 = 同 host 或其**子域**，不向父域扩张、不放兄弟子域；
 *   ② 跨站的业务面（form / api / js）仍放行 —— 登录、支付、接口落在独立域是常态。
 */
import { describe, expect, it } from "vitest";
import { graphState, ingestToolResult, type IngestInput } from "../src/blackbox/graph/builder.js";

function ingest(input: Partial<IngestInput>) {
  const state = graphState(undefined);
  const result = ingestToolResult(state, { tool: "browser.open", ...input });
  return { state, result };
}

describe("站点边界：同 host / 子域放行，兄弟子域与父域不放", () => {
  it("同 host 与它的子域入图", () => {
    const { state } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/",
      links: [
        { from: "https://wanxiaozhi.aliyun.com/", to: "https://wanxiaozhi.aliyun.com/help/1.html", kind: "link" },
        { from: "https://wanxiaozhi.aliyun.com/", to: "https://api.wanxiaozhi.aliyun.com/v1/user", kind: "link" },
      ],
    });
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/help/1.html"]).toBeTruthy();
    expect(state.nodes["ep:api.wanxiaozhi.aliyun.com/v1/user"]).toBeTruthy();
  });

  it("兄弟子域（*.console.aliyun.com）全部挡在 skipped 里，不是静默丢弃", () => {
    const { state, result } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/",
      links: [
        { from: "https://wanxiaozhi.aliyun.com/", to: "https://ecs.console.aliyun.com/", kind: "link" },
        { from: "https://wanxiaozhi.aliyun.com/", to: "https://oss.console.aliyun.com/", kind: "link" },
      ],
    });
    expect(state.nodes["ep:ecs.console.aliyun.com/"]).toBeUndefined();
    expect(state.nodes["ep:oss.console.aliyun.com/"]).toBeUndefined();
    expect(result.skipped.map(item => item.url)).toEqual([
      "https://ecs.console.aliyun.com/",
      "https://oss.console.aliyun.com/",
    ]);
    expect(result.skipped.every(item => item.reason === "out_of_scope")).toBe(true);
  });

  it("父域不放行（aliyun.com 是另一个站点，不是本目标的上级应用）", () => {
    const { state } = ingest({
      parent: "ep:wanxiaozhi.aliyun.com/",
      links: [{ from: "https://wanxiaozhi.aliyun.com/", to: "https://aliyun.com/", kind: "link" }],
    });
    expect(state.nodes["ep:aliyun.com/"]).toBeUndefined();
  });

  it("跨站的表单 action 与 API 调用照常入图（业务面本来就可能跨域）", () => {
    const { state } = ingest({
      parent: "ep:shop.test/",
      links: [{ from: "https://shop.test/login", to: "https://sso.other.test/oauth/login", kind: "form" }],
      api_calls: [{ from: "https://shop.test/", to: "https://api.other.test/v1/order", kind: "api" }],
    });
    expect(state.nodes["ep:sso.other.test/oauth/login"]).toBeTruthy();
    expect(state.nodes["ep:api.other.test/v1/order"]).toBeTruthy();
  });

  it("同样是跨站，导航链接 kind=link 仍然被挡", () => {
    const { state } = ingest({
      parent: "ep:shop.test/",
      links: [{ from: "https://shop.test/", to: "https://friend.other.test/", kind: "link" }],
    });
    expect(state.nodes["ep:friend.other.test/"]).toBeUndefined();
  });

  it("多级后缀不再因为后两段相同而互相放行（co.uk 双向误判）", () => {
    const { state, result } = ingest({
      parent: "ep:a.foo.co.uk/",
      links: [{ from: "https://a.foo.co.uk/", to: "https://b.bar.co.uk/", kind: "link" }],
    });
    expect(state.nodes["ep:b.bar.co.uk/"]).toBeUndefined();
    expect(result.skipped).toHaveLength(1);
  });

  it("真发过的请求是事实，跨站也必须入图（scope 只管被动发现）", () => {
    const { state } = ingest({
      parent: "ep:a.test/",
      endpoints: [{ url: "https://ecs.console.aliyun.com/", requested: true, origin: "request", status_code: 200 }],
    });
    expect(state.nodes["ep:ecs.console.aliyun.com/"]).toBeTruthy();
  });

  it("被动发现的端点按来源 kind 判 scope：navigation 挡、api 放", () => {
    const { state } = ingest({
      parent: "ep:a.test/",
      endpoints: [
        { url: "https://nav.other.test/", origin: "link" },
        { url: "https://api.other.test/v1", origin: "api" },
      ],
    });
    expect(state.nodes["ep:nav.other.test/"]).toBeUndefined();
    expect(state.nodes["ep:api.other.test/v1"]).toBeTruthy();
  });
});

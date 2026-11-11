import { describe, expect, it } from "vitest";
import { wallOf } from "../src/blackbox/graph/extract.js";
import { DEAD_END_REPEATS, endpointNodeId, graphState, ingestToolResult } from "../src/blackbox/graph/builder.js";

/**
 * 2026-10-28 note.yun 会话（`1cdf92d4816b72bf`）暴露的两个断点：
 *
 *   ① 9 条 `412` + 2681B `securityfs.oppo.com/waf` 阻断页在图里全落成 `testing`
 *      —— 图上看不出“被墙挡住”，agent 也没有换武器的依据；
 *   ② 43 次调用只有 22 个唯一请求（重复率 49%），`https://cloud.oppo.com/` 打了 17 次
 *      每次都是 200，旧逻辑只在 blocked 时累计 `repeats`，重复永远判不了死胡同。
 *
 * 这里把两条判据钉死：状态必须落 blocked + wall 标记，重复签名必须落 dead_end。
 */

describe("WAF 墙识别", () => {
  it("412 直接算墙（正常业务几乎不用这个码）", () => {
    const wall = wallOf({ status: 412, body: "blocked" });
    expect(wall?.kind).toBe("waf_412");
    expect(wall?.marker).toBe(false);
  });

  it("OPPO WAF 阻断页靠正文指纹认出来，即使状态码不是 412", () => {
    const wall = wallOf({ status: 200, body: "<title>您的访问被阻断！- 412错误</title> securityfs.oppo.com/waf" });
    expect(wall?.kind).toBe("waf_oppo");
    expect(wall?.marker).toBe(true);
  });

  it("普通 429 限流不算墙（没有指纹就不该判死）", () => {
    expect(wallOf({ status: 429, body: "too many requests" })).toBeUndefined();
  });

  it("200 的正常页面不是墙", () => {
    expect(wallOf({ status: 200, body: "<html>ok</html>" })).toBeUndefined();
  });

  it("Cloudflare 指纹能认出来", () => {
    expect(wallOf({ status: 403, body: "cf-error-details Attention Required" })?.kind).toBe("waf_cloudflare");
  });
});

describe("WAF 墙进图", () => {
  it("落 blocked + wall 属性，且不生成 identity 节点（412 不是身份墙）", () => {
    const state = graphState(undefined);
    const url = "https://cloud.oppo.com/.env";
    const wall = wallOf({ status: 412, body: "securityfs.oppo.com/waf 您的访问被阻断" });
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, requested: true, status_code: 412, wall: wall?.kind, blocked: true }],
    });
    const node = state.nodes[endpointNodeId(url)]!;
    expect(node.status).toBe("blocked");
    expect(node.properties.wall).toBe("waf_oppo");
    expect(node.properties.status_code).toBe(412);
    expect(Object.keys(state.nodes).filter(id => id.startsWith("id:"))).toHaveLength(0);
    expect(state.edges.filter(edge => edge.type === "requires_auth")).toHaveLength(0);
  });

  it("401 仍然按身份墙处理（不能因为加了 WAF 判据就丢掉鉴权语义）", () => {
    const state = graphState(undefined);
    const url = "https://cloud.oppo.com/api/me";
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, requested: true, status_code: 401, auth_required: true, blocked: true }],
    });
    expect(state.nodes[endpointNodeId(url)]!.status).toBe("blocked");
    expect(state.edges.some(edge => edge.type === "requires_auth")).toBe(true);
  });
});

describe("重复请求判死胡同", () => {
  const url = "https://cloud.oppo.com/";
  const signature = "aaaa1111";

  it(`同一签名连续 ${DEAD_END_REPEATS} 次后落 dead_end`, () => {
    // 用业务路径而不是 `/`：站点根自 2026-11-05 起豁免（它是基线/匿名对照/状态漂移
    // 的唯一参照面，实测被"重复 10 次"封死后整场 run 做不了对照），
    // 见 test/graph-site-root-dead-end.test.ts。同一条判据在深路径上照旧成立。
    const target = "https://cloud.oppo.com/dashboard";
    const state = graphState(undefined);
    for (let index = 0; index < DEAD_END_REPEATS; index += 1) {
      ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url: target, requested: true, status_code: 200, content_length: 5158, signature }],
      });
    }
    const node = state.nodes[endpointNodeId(target)]!;
    expect(node.status).toBe("dead_end");
    expect(node.properties.signature_repeats).toBe(DEAD_END_REPEATS);
    expect(String(node.properties.note || "")).toContain("同一请求已重复");
  });

  it("换了请求签名的重打不会累计（改了 payload 就是新动作）", () => {
    const state = graphState(undefined);
    for (const sig of ["sig-a", "sig-a", "sig-b"]) {
      ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url, requested: true, status_code: 200, content_length: 5158, signature: sig }],
      });
    }
    const node = state.nodes[endpointNodeId(url)]!;
    // 2026-10-28：signature_repeats 记的是**峰值**而不是当前连续值。同一条路径常被
    // 不同签名的请求交替重打（GET/HEAD、带/不带 payload），当前值会在 1 与 N 之间跳，
    // 峰值才说明“这条重复到什么程度”。这里两次 sig-a 已经把峰值抬到 2。
    expect(node.properties.signature_repeats).toBe(2);
    expect(node.status).not.toBe("dead_end");
  });

  it("两次相同签名仍在阈值内，不判死", () => {
    const state = graphState(undefined);
    for (let index = 0; index < DEAD_END_REPEATS - 1; index += 1) {
      ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url, requested: true, status_code: 200, content_length: 5158, signature }],
      });
    }
    expect(state.nodes[endpointNodeId(url)]!.status).not.toBe("dead_end");
  });
});

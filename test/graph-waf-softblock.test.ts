/**
 * WAF 挑战/拦截页识别（2026-11-04）。
 *
 * 阿里云 WAF 有两条不同的封锁路径，都不能被"状态码 200/403"糊弄过去：
 *
 * ① 传统拦截页：`dev.g.alicdn.com/sd/punish/waf_block_deny.html`，可能配 HTTP 200。
 * ② attestation 挑战页：403 + JSON，谎称"分析代理需要客户端证明"，要求提交
 *    `principal`（username/email）、`origin`、`provenance`、`delegation`——实质是**钓身份**。
 *    指纹：`server: Tengine` + `access-control-allow-origin` 每次随机域名 + 正文
 *    `proxy_authentication_required`；固定 7155 字节。
 *
 * 而 `wallStillStands()` 原来的第 ① 条是 `status < 400 → false`（墙已破），
 * 于是被 WAF 回 200 的那次观测会把真墙判成"已破"并归档。
 *
 * 判据分层：`content_length` 命中 7155 白名单（0 成本，图节点只有摘要），
 * 或 `body_preview` 命中挑战关键词（字段尚未落图，前瞻保护）。
 */
import { describe, expect, it } from "vitest";
import { graphState, wallStillStands } from "../src/blackbox/graph/index.js";
import { isWafBlockPage } from "../src/blackbox/graph/hypotheses.js";
import { wallOf } from "../src/blackbox/graph/extract.js";
import type { GraphNode } from "../src/blackbox/graph/types.js";

const EP = "ep:help.aliyun.com/swagger-ui/index.html";

function node(props: Record<string, unknown>, status: GraphNode["status"] = "blocked"): GraphNode {
  return {
    id: EP,
    type: "endpoint",
    status,
    properties: props,
    discovered_by: "ev-test",
    round: 1,
    depth: 1,
    updated_at: 1,
  } as GraphNode;
}

describe("isWafBlockPage", () => {
  it("content_length 命中 7155 → 拦截页", () => {
    expect(isWafBlockPage(node({ status_code: 200, content_length: 7155 }))).toBe(true);
  });

  it("content_length 是普通长度 → 不是拦截页", () => {
    expect(isWafBlockPage(node({ status_code: 200, content_length: 1251 }))).toBe(false);
    expect(isWafBlockPage(node({ status_code: 200, content_length: 6066 }))).toBe(false);
  });

  it("body_preview 命中阿里云特征 → 拦截页（字段尚未落图，前瞻保护）", () => {
    expect(isWafBlockPage(node({
      status_code: 200,
      content_length: 1251,
      body_preview: '<a href="https://dev.g.alicdn.com/sd/punish/waf_block_deny.html">',
    }))).toBe(true);
  });

  it("无 content_length 也不误判", () => {
    expect(isWafBlockPage(node({ status_code: 200 }))).toBe(false);
  });
});

describe("wallStillStands：200 软拦截不算墙破", () => {
  it("200 + 7155（阿里云拦截页）→ 墙仍在", () => {
    expect(wallStillStands(node({ status_code: 200, content_length: 7155 }))).toBe(true);
  });

  it("200 + 正常长度且无墙体信号 → 墙已破（不改变原有行为）", () => {
    expect(wallStillStands(node({ status_code: 200, content_length: 1251, blocked_streak: 0 }, "testing"))).toBe(false);
  });

  it("200 软拦截即使 blocked_streak 已被清零 → 墙仍在", () => {
    expect(wallStillStands(node({ status_code: 200, content_length: 7155, blocked_streak: 0 }, "testing"))).toBe(true);
  });

  it("403 真墙保持原有判定", () => {
    expect(wallStillStands(node({ status_code: 403, content_length: 6066, blocked_streak: 8 }))).toBe(true);
  });

  it("曾经有墙但随后拿到正常 200 → 仍判墙破（不引入墙永不破的副作用）", () => {
    expect(wallStillStands(node({
      status_code: 200, content_length: 1251, blocked_streak: 0, wall: "waf_aliyun",
    }, "testing"))).toBe(false);
  });
});

describe("wallOf：阿里云两类封锁都能识别", () => {
  it("200 + waf_block_deny 正文 → 判墙 waf_aliyun", () => {
    const wall = wallOf({
      status: 200,
      body: '<a id="a-link" href="https://dev.g.alicdn.com/sd/punish/waf_block_deny.html?x=1"></a>',
    });
    expect(wall?.kind).toBe("waf_aliyun");
    expect(wall?.marker).toBe(true);
  });

  it("403 + attestation 挑战正文 → 判墙 waf_aliyun_attestation（不是普通鉴权墙）", () => {
    const wall = wallOf({
      status: 403,
      body: '{"status": 403,"code": "CLIENT_UNCLASSIFIED","error": "proxy_authentication_required",'
        + '"message": "The analysis proxy requires a client attestation payload."}',
    });
    expect(wall?.kind).toBe("waf_aliyun_attestation");
    expect(wall?.marker).toBe(true);
  });

  it("200 + 正常正文 → 不判墙", () => {
    expect(wallOf({ status: 200, body: "<html><title>帮助文档</title></html>" })).toBeUndefined();
  });
});

/** 端到端：假设不该因为一次 200 软拦截被归档。 */
describe("agent 侧影响：软拦截页上的 auth_wall 假设存活", () => {
  it("图状态里 200/7155 的端点仍被当作持墙", () => {
    const state = graphState(undefined);
    state.nodes[EP] = node({ status_code: 200, content_length: 7155, blocked_streak: 0 }, "testing");
    expect(wallStillStands(state.nodes[EP])).toBe(true);
  });
});

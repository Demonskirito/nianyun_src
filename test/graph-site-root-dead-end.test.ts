/**
 * 站点根不判死胡同（2026-11-05）。
 *
 * 实测背景（会话 5b59aa1d059b56da）：`ep:wanxiaozhi.aliyun.com/` 因为
 * "同一请求已重复 10 次（响应未变化）"被封成 dead_end（reopens=4 才封）。
 * 此后 `deadEndVerdict` 对同一签名一律拒收——而首页恰恰是：
 *
 *   · 基线响应的来源（T1 每次重跑都要它）
 *   · 匿名 vs 带罐对照的参照面（unauth_exposure 谓词的唯一证据来源）
 *   · 状态漂移的观测点（同一 URL 实测 6 分钟内 200 → 302 父域 /notfound → 200）
 *
 * 首页被锁的代价不是"少打一条路"，而是**所有验证动作失去参照物**。
 * 所以站点根只记账、不改状态；真正的空转兜底仍在 zero_entropy_streak / stall / 预算。
 */
import { describe, expect, it } from "vitest";
import {
  DEAD_END_REPEATS, deadEndVerdict, graphState, ingestToolResult, isSiteRootNodeId,
} from "../src/blackbox/graph/builder.js";

function repeat(url: string, signature: string, times: number) {
  const state = graphState(undefined);
  for (let index = 0; index < times; index += 1) {
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, requested: true, status_code: 200, content_length: 31561, signature }],
    });
  }
  return state;
}

describe("isSiteRootNodeId", () => {
  it("只认站点根，深路径不算", () => {
    expect(isSiteRootNodeId("ep:wanxiaozhi.aliyun.com/")).toBe(true);
    // 查询串被归一化掉，仍是首页
    expect(isSiteRootNodeId("ep:example.com/")).toBe(true);
    expect(isSiteRootNodeId("ep:example.com/help/3039522.html")).toBe(false);
    expect(isSiteRootNodeId("ep:example.com/help/")).toBe(false);
    expect(isSiteRootNodeId("ep:/")).toBe(false);
  });
});

describe("首页重复打不封路", () => {
  it(`同签名重复 ${DEAD_END_REPEATS} 次：状态不变，但次数照记`, () => {
    const state = repeat("https://wanxiaozhi.aliyun.com/", "GET / | anon", DEAD_END_REPEATS);
    const node = state.nodes["ep:wanxiaozhi.aliyun.com/"]!;
    expect(node.status).not.toBe("dead_end");
    expect(node.properties.site_root_repeats).toBe(DEAD_END_REPEATS);
    expect(String(node.properties.note)).toContain("站点根不判死胡同");
    // 不是"什么都不说"：note 必须给出换动作的方向
    expect(String(node.properties.note)).toContain("换签名");
  });

  it("继续重复到 10 次仍不封路（实测就是这样被封的）", () => {
    const state = repeat("https://wanxiaozhi.aliyun.com/", "GET / | anon", 10);
    const node = state.nodes["ep:wanxiaozhi.aliyun.com/"]!;
    expect(node.status).not.toBe("dead_end");
    expect(node.properties.site_root_repeats).toBe(10);
    expect(node.properties.dead_signatures).toBeUndefined();
  });

  it("首页不封 → deadEndVerdict 不拦（基线/对照可以继续做）", () => {
    const state = repeat("https://wanxiaozhi.aliyun.com/", "GET / | anon", 10);
    const verdict = deadEndVerdict(state, "https://wanxiaozhi.aliyun.com/", "GET / | anon");
    expect(verdict.blocked).toBe(false);
  });

  it("回归：深路径同签名重复照样封（豁免只给站点根）", () => {
    const state = repeat("https://wanxiaozhi.aliyun.com/admin/login", "GET /admin/login | anon", DEAD_END_REPEATS);
    const node = state.nodes["ep:wanxiaozhi.aliyun.com/admin/login"]!;
    expect(node.status).toBe("dead_end");
    expect(node.properties.site_root_repeats).toBeUndefined();
    expect(node.properties.dead_signatures?.length).toBe(1);
    expect(deadEndVerdict(state, "https://wanxiaozhi.aliyun.com/admin/login", "GET /admin/login | anon").blocked).toBe(true);
  });

  it("第四态宽限与首页豁免互不影响：首页既不封也不吃宽限标记", () => {
    const state = repeat("https://wanxiaozhi.aliyun.com/", "GET / | anon", DEAD_END_REPEATS);
    expect(state.nodes["ep:wanxiaozhi.aliyun.com/"]!.properties.retest_grace_used).toBeUndefined();
  });
});

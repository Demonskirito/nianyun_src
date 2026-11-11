import { describe, expect, it } from "vitest";
import { mainSchema } from "../src/blackbox/protocol.js";

const parseTasks = (required_tasks: unknown[]) =>
  mainSchema.safeParse({ summary: "s", required_tasks, tool_requests: [] });

describe("required_tasks 宽容化（2026-10-31）", () => {
  it("接受模型实际写过的别名形态", () => {
    for (const task of [
      { id: "T1", url: "https://m.ctrip.com/html5/", goal: "抓 SSR 接口", why: "history 里只有壳" },
      { task_id: "T2", target: "https://m.ctrip.com/restapi/x", purpose: "验证 restapi 前缀", reason: "robots 泄露", criteria: "拿到 200 + JSON" },
      { id: "T3", purpose: "打 https://m.ctrip.com/webapp/hotel/ 的鉴权边界", description: "匿名 vs 登录对照" },
    ]) {
      const result = parseTasks([task]);
      expect(result.success, JSON.stringify(task)).toBe(true);
      if (!result.success) continue;
      const parsed = result.data.required_tasks[0] as Record<string, unknown>;
      expect(String(parsed.purpose || "").length).toBeGreaterThan(3);
      expect(String(parsed.reason || "").length).toBeGreaterThan(1);
      expect(parsed.completion_criteria).toBeTruthy();
    }
  });

  it("纯字符串任务保持原样（旧语义：由 progress.merge 解析），不因宽容化改道", () => {
    const result = parseTasks(["T_SPA 逆出 https://m.ctrip.com/html5/ 的渲染期 XHR"]);
    expect(result.success).toBe(true);
    if (!result.success) return;
    // 放进 union 第一位的仍是 text：字符串任务走老路径，避免每轮都新建哈希 id 的重复任务。
    expect(typeof result.data.required_tasks[0]).toBe("string");
  });

  it("连 purpose 都没有的对象仍然被拒，不把噪声当任务", () => {
    expect(parseTasks([{ foo: "bar" }]).success).toBe(false);
  });
});

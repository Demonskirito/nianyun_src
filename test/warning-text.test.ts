import { describe, expect, it } from "vitest";
import { supervisorWarningText } from "../src/blackbox/warning-text.js";

/**
 * 监督器告警文案。
 *
 * 事故：gray-push 会话 14:53:52 那条 supervisor-warning 写的是"本批有工具失败已记入证据账本"，
 * 但同一时刻工具健康度是 42 次执行 / 0 失败，证据账本里 42 条 tool-result 的 ok 全是 true。
 * 真实 warnings 是 ["repairable_task_rejections"]——任务完成声明被拒（可自纠），与工具无关。
 *
 * 旧实现用 if/else 兜底分支硬编码"有工具失败"，任何非 budget 的告警都会变成这句假话。
 */
describe("监督器告警文案", () => {
  it("只有可自纠的任务拒绝时，不能说成工具失败", () => {
    const { kind, text } = supervisorWarningText(["repairable_task_rejections"]);
    expect(kind).toBe("supervisor-warning");
    expect(text).toContain("任务完成声明被拒");
    expect(text).not.toContain("工具失败");
  });

  it("真工具失败时才出现工具失败文案", () => {
    const { text } = supervisorWarningText(["tool_failure"]);
    expect(text).toContain("本批有工具失败");
  });

  it("预算告警单独出现时用 budget-warning 类型", () => {
    const { kind, text } = supervisorWarningText(["budget_warning"]);
    expect(kind).toBe("budget-warning");
    expect(text).toContain("预算接近阈值");
  });

  it("预算 + 工具失败两条并列", () => {
    const { kind, text } = supervisorWarningText(["budget_warning", "tool_failure"]);
    expect(kind).toBe("budget-warning");
    expect(text).toContain("预算接近阈值");
    expect(text).toContain("本批有工具失败");
  });

  it("未知告警码原样带出，不臆造原因", () => {
    const { text } = supervisorWarningText(["something_new"]);
    expect(text).toContain("未映射告警（something_new）");
    expect(text).not.toContain("工具失败");
  });

  it("空告警只留下推进语", () => {
    expect(supervisorWarningText([]).text).toBe("监督器继续推进，不重复相同调用。");
  });
});
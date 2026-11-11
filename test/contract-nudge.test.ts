import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";

/**
 * R6 提示：缺结构化契约的任务必须被点名，补齐后必须自动出列。
 *
 * 2026-10-28 实测：模型 40 条任务 0 条写 deliverables/success_criteria，
 * 结案审计永远没有可审对象（closureAudit 直接返回 undefined）。
 */
const target = "https://app.example.test/";

describe("contract_nudges：缺契约点名与出列", () => {
  it("不带 deliverables 的任务进清单，带的不进", () => {
    const p = new BlackboxProgress();
    p.merge({ required_tasks: [
      { id: "T_a", target, purpose: "a", reason: "a", completion_criteria: "c" },
      { id: "T_b", target, purpose: "b", reason: "b", completion_criteria: "c", deliverables: ["js_content"] },
    ] });
    expect(p.pendingContractNudges()).toEqual(["T_a"]);
  });

  it("同名重新声明补上契约后出列", () => {
    const p = new BlackboxProgress();
    p.merge({ required_tasks: [{ id: "T_a", target, purpose: "a", reason: "a", completion_criteria: "c" }] });
    expect(p.pendingContractNudges()).toEqual(["T_a"]);
    p.merge({ required_tasks: [{ id: "T_a", target, purpose: "a", reason: "a", completion_criteria: "c", deliverables: ["js_content"] }] });
    expect(p.pendingContractNudges()).toEqual([]);
  });

  it("任务终态后不再点名（不再打扰已死的任务）", () => {
    const p = new BlackboxProgress();
    p.merge({ required_tasks: [{ id: "T_a", target, purpose: "a", reason: "a", completion_criteria: "c" }] });
    p.state.tasks.T_a!.status = "blocked";
    expect(p.pendingContractNudges()).toEqual([]);
  });

  it("清单有上限，不会把上下文撑爆", () => {
    const p = new BlackboxProgress();
    // purpose 必须互不相同，否则会先被语义去重吞掉（这本身是正确行为）。
    const tasks = Array.from({ length: 9 }, (_, index) => ({
      id: `T_${index}`, target: `${target}p${index}`, purpose: `第 ${index} 条独立验证面：编号 ${index}`, reason: `理由 ${index}`, completion_criteria: `判据 ${index}`,
    }));
    p.merge({ required_tasks: tasks });
    expect(p.pendingContractNudges(6)).toHaveLength(6);
  });
});
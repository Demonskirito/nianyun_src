import { describe, expect, it } from "vitest";
import { PLAYBOOKS, PLAYBOOK_IDS, playbookIndex, stepLayer } from "../src/blackbox/playbooks.js";
import { ROUTE_PRECEDENCE, ROUTE_STEPS, routePrompt } from "../src/blackbox/route-manifest.js";
import { BLACKBOX_TOOL_NAMES } from "../src/blackbox/tools.js";

/**
 * 路线（会话级）与打法库（任务级）都在 system prompt 里，写歪了就是两套指令互相抢。
 * 这组守卫专门盯这类冲突，不测业务逻辑。
 */
describe("路线 × 打法库一致性", () => {
  it("每条路线都要在 prompt 里带上优先级声明", () => {
    const prompt = routePrompt();
    expect(prompt).toContain(ROUTE_PRECEDENCE);
    expect(ROUTE_PRECEDENCE).toContain("具体者优先");
  });

  it("打法库声明的每个工具都必须真实存在（防止写成已删/改名的工具）", () => {
    const known = new Set<string>(BLACKBOX_TOOL_NAMES);
    const missing: string[] = [];
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) {
        if (!known.has(step.tool)) missing.push(`${playbook.id}.${step.id} → ${step.tool}`);
      }
    }
    expect(missing, `打法库引用了不存在的工具：${missing.join("、")}`).toEqual([]);
  });

  it("竞态打法必须用控制面的 race 工具（沙箱并发会被代理抹平）", () => {
    const race = PLAYBOOKS.find(playbook => playbook.id === "race_condition");
    expect(race).toBeTruthy();
    const fanout = race!.steps.find(step => step.id === "fanout");
    expect(fanout?.tool).toBe("recon.race_condition");
    expect(race!.confirm.evidence).toContain("fanout");
  });

  it("没有任何打法再把\"唯一正确姿势\"指向非 race 工具", () => {
    const offenders: string[] = [];
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) {
        if (step.purpose.includes("唯一正确姿势") && step.tool !== "recon.race_condition") {
          offenders.push(`${playbook.id}.${step.id} → ${step.tool}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("路线里提到的竞态工具与打法库一致", () => {
    const selectStep = ROUTE_STEPS.find(step => step.id === "select");
    expect(selectStep?.detail).toContain("recon.race_condition");
    expect(PLAYBOOK_IDS).toContain("race_condition");
  });
});
describe("打法库原生分层（layer）", () => {
  it("strategic 步骤必须显式声明 layer 且用 exec.*，并给出 state_out", async () => {
    const { PLAYBOOKS, stepLayer } = await import("../src/blackbox/playbooks.js");
    const problems: string[] = [];
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) {
        if (stepLayer(step) !== "strategic") continue;
        if (step.layer !== "strategic") problems.push(`${playbook.id}.${step.id} 未显式声明 layer`);
        if (!step.tool.startsWith("exec.")) problems.push(`${playbook.id}.${step.id} 不是 exec.*`);
        if (!step.state_out) problems.push(`${playbook.id}.${step.id} 缺 state_out`);
      }
    }
    expect(problems).toEqual([]);
  });

  it("tactical_rpc 步骤的工具必须在 RPC 白名单里，且确实需要控制面发射", async () => {
    const { PLAYBOOKS, stepLayer, layerIssue } = await import("../src/blackbox/playbooks.js");
    const { RPC_WHITELIST } = await import("../src/blackbox/sandbox_rpc.js");
    const problems: string[] = [];
    let rpcSteps = 0;
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) {
        const issue = layerIssue(step, RPC_WHITELIST);
        if (issue) problems.push(issue);
        if (stepLayer(step) === "tactical_rpc") {
          rpcSteps += 1;
          if (!step.state_out && playbook.id !== "race_condition") problems.push(`${playbook.id}.${step.id} RPC 步骤最好声明 state_out`);
        }
      }
    }
    expect(problems).toEqual([]);
    expect(rpcSteps).toBeGreaterThan(0);
  });

  it("prompt 的 playbook 索引里每一步都带层标记", () => {
    const index = playbookIndex();
    for (const playbook of PLAYBOOKS) {
      for (const step of playbook.steps) {
        const tag = stepLayer(step) === "strategic" ? "S" : stepLayer(step) === "tactical_rpc" ? "R" : "T";
        expect(index, `${playbook.id}.${step.id} 缺少层标记`).toContain(`${step.id}|${tag}`);
      }
    }
  });

  it("路线声明：层看 playbook，路线只兜底", () => {
    const prompt = routePrompt();
    expect(prompt).toContain("层就写在打法库里");
    expect(prompt).toContain("|R");
  });
});
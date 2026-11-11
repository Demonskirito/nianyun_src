import { describe, expect, it } from "vitest";
import { graphSignalFingerprint, graphSignalGate, resetGraphSignalGate, type GraphSignal } from "../src/blackbox/graph/index.js";

/**
 * graph-signal 事件门禁（2026-11-09，P2）。
 *
 * 现场：15 分钟 7 条 graph-signal，其中几条正文完全相同、roots 一模一样。
 * 根因是门禁用了 `addInterrupts` 的返回值——插话池被一次性条目挤出后重新插入也算"新增"。
 * 现在门禁只看语义指纹：拓扑没变、quiet 已经报过、又没到汇总轮次，就不写事件。
 */

const drift = (roots: string[], blocks = roots.length): GraphSignal => ({
  kind: "component_drift", severity: "medium",
  text: `图是裂开的：先打这些 URL：${roots.join("、")}（图裂成 ${blocks} 块）`,
  data: { roots, blocks },
});

const quiet = (rounds = 4): GraphSignal => ({
  kind: "graph_no_new_nodes", severity: "medium",
  text: `已连续多轮（≥3）没有新节点进图`,
  data: { quiet_rounds: rounds },
});

describe("graph-signal 门禁：只看语义变化", () => {
  it("首次出现漂移 → 写一条", () => {
    const result = graphSignalGate(undefined, [drift(["https://t.example/a", "https://t.example/b"])]);
    expect(result.emit).toBe(true);
    expect(result.gate.prints).toHaveLength(1);
  });

  it("同一批 roots、只有块数变了 → 不再写", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"], 60)]);
    expect(first.emit).toBe(true);
    const second = graphSignalGate(first.gate, [drift(["https://t.example/a"], 61)]);
    expect(second.emit).toBe(false);
    // 指纹不能被块数污染。
    expect(second.gate.prints).toEqual(first.gate.prints);
  });

  it("roots 顺序变化不算换批", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/b", "https://t.example/a"])]);
    const second = graphSignalGate(first.gate, [drift(["https://t.example/a", "https://t.example/b"])]);
    expect(second.emit).toBe(false);
  });

  it("换了一批 roots → 写一条", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"])]);
    const second = graphSignalGate(first.gate, [drift(["https://t.example/c"])]);
    expect(second.emit).toBe(true);
  });

  it("quiet 信号首次出现写一次，之后反复出现不再写", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"]), quiet(3)]);
    expect(first.emit).toBe(true);

    const flicker = graphSignalGate(first.gate, [drift(["https://t.example/a"])]);
    expect(flicker.emit).toBe(false);
    // 拓扑没变，quiet 中途消失也不清账——它下次回来不该再写一条。
    expect(flicker.gate.quiet).toBe(true);

    const again = graphSignalGate(flicker.gate, [drift(["https://t.example/a"]), quiet(5)]);
    expect(again.emit).toBe(false);
  });

  it("只有 quiet 信号时，首次要写（否则静默）", () => {
    const first = graphSignalGate(undefined, [quiet(4)]);
    expect(first.emit).toBe(true);
    const second = graphSignalGate(first.gate, [quiet(5)]);
    expect(second.emit).toBe(false);
  });

  it("按图轮次汇总：满 20 轮写一条", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"])], { graphRound: 5 });
    expect(first.emit).toBe(true);
    expect(first.gate.summary_round).toBe(5); // 首轮只上表，不汇总

    const notDue = graphSignalGate(first.gate, [drift(["https://t.example/a"])], { graphRound: 24 });
    expect(notDue.emit).toBe(false);
    const summary = graphSignalGate(notDue.gate, [drift(["https://t.example/a"])], { graphRound: 25 });
    expect(summary.emit).toBe(true);
    expect(summary.gate.summary_round).toBe(25);

    const notYet = graphSignalGate(summary.gate, [drift(["https://t.example/a"])], { graphRound: 26 });
    expect(notYet.emit).toBe(false);
  });

  it("默认汇总间隔是 20，且可被显式覆盖", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"])], { graphRound: 1 });
    expect(graphSignalGate(first.gate, [drift(["https://t.example/a"])], { graphRound: 20 }).emit).toBe(false);
    expect(graphSignalGate(first.gate, [drift(["https://t.example/a"])], { graphRound: 21 }).emit).toBe(true);
    // 显式传入时以传入值为准（测试与特殊会话可调）
    expect(graphSignalGate(first.gate, [drift(["https://t.example/a"])], { graphRound: 5, summaryEvery: 4 }).emit).toBe(true);
  });

  it("采纳清零不会饿死汇总（旧的 driftRounds 口径会）", () => {
    // 模拟：第 19 轮之前这批一直被采纳，drift rounds 每轮都被清零；
    // 用 graphRound 计时，第 21 轮照样出体检条目。
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"])], { graphRound: 1 });
    const at19 = graphSignalGate(first.gate, [drift(["https://t.example/a"])], { graphRound: 19 });
    expect(at19.emit).toBe(false);
    const at21 = graphSignalGate(at19.gate, [drift(["https://t.example/a"])], { graphRound: 21 });
    expect(at21.emit).toBe(true);
  });

  it("指纹不取正文里的数字", () => {
    const a = graphSignalFingerprint(drift(["https://t.example/a"], 60));
    const b = graphSignalFingerprint(drift(["https://t.example/a"], 99));
    expect(a).toBe(b);
  });
});

/**
 * quiet 的复位也要进指纹（2026-11-10）。
 *
 * 旧实现：信号清空时门禁被整条改写成 `{prints: [], quiet: false}`，quiet 的账一起没了。
 * 下一轮 `graph_no_new_nodes` 再出现就是"首次"，正文与上一条逐字相同——12 轮里那条
 * 看起来重复的 graph-signal 就是这么来的。现在复位只清 `prints`，quiet 的段号跨复位保留。
 */
describe("quiet 复位纳入指纹", () => {
  it("复位只清拓扑，不清 quiet 账本与汇总计时", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"]), quiet(3)], { graphRound: 7 });
    expect(first.emit).toBe(true);
    expect(first.gate.quiet).toBe(true);

    const reset = resetGraphSignalGate(first.gate);
    expect(reset.prints).toEqual([]);
    expect(reset.quiet).toBe(true);
    expect(reset.quiet_epoch).toBe(first.gate.quiet_epoch);
    // 复位不该把体检计时归零，否则每复位一次就要重新等 20 轮。
    expect(reset.summary_round).toBe(7);
  });

  it("复位后 quiet 再来 → 不写（不是新段）", () => {
    const first = graphSignalGate(undefined, [quiet(3)]);
    expect(first.emit).toBe(true);
    // 模拟控制面：信号空一轮 → 复位
    const reset = resetGraphSignalGate(first.gate);
    const again = graphSignalGate(reset, [quiet(4)]);
    expect(again.emit).toBe(false);
    expect(again.gate.quiet_epoch).toBe(0);
  });

  it("复位后同一批 roots 的漂移回来 → 要写（拓扑变了）", () => {
    const first = graphSignalGate(undefined, [drift(["https://t.example/a"])]);
    const reset = resetGraphSignalGate(first.gate);
    const again = graphSignalGate(reset, [drift(["https://t.example/a"])]);
    expect(again.emit).toBe(true);
  });

  it("单轮缺失算抖动：不换段、不重报", () => {
    const first = graphSignalGate(undefined, [quiet(3)]);
    const blink = graphSignalGate(first.gate, []);
    expect(blink.emit).toBe(false);
    expect(blink.gate.quiet).toBe(true);
    expect(blink.gate.quiet_gap).toBe(1);

    const back = graphSignalGate(blink.gate, [quiet(4)]);
    expect(back.emit).toBe(false);
    expect(back.gate.quiet_epoch).toBe(0);
  });

  it("连续两轮没有 quiet（图真长过）→ 换段，再停摆时报一次", () => {
    const first = graphSignalGate(undefined, [quiet(3)]);
    const gone1 = graphSignalGate(first.gate, []);
    const gone2 = graphSignalGate(gone1.gate, []);
    expect(gone2.gate.quiet).toBe(false);
    expect(gone2.gate.quiet_epoch).toBe(1);

    // 图长过之后的**新**一段停摆：报一次
    const restalled = graphSignalGate(gone2.gate, [quiet(3)]);
    expect(restalled.emit).toBe(true);
    expect(restalled.gate.quiet_epoch).toBe(1);

    // 同一段里继续停摆：不再报
    const keep = graphSignalGate(restalled.gate, [quiet(6)]);
    expect(keep.emit).toBe(false);
  });

  it("换段后复位的段号仍然保留（连续两段停摆不会互相吞）", () => {
    const first = graphSignalGate(undefined, [quiet(3)]);
    const gone1 = graphSignalGate(first.gate, []);
    const gone2 = graphSignalGate(gone1.gate, []);
    const reset = resetGraphSignalGate(gone2.gate);
    expect(reset.quiet_epoch).toBe(1);
    const restalled = graphSignalGate(reset, [quiet(3)]);
    // 段号还是 1，但复位前账本已被清（quiet=false），所以这一段要报。
    expect(restalled.emit).toBe(true);
  });
});

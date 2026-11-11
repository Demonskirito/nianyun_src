import { describe, expect, it } from "vitest";
import { ObserverDaemon, observerModeFrom, renderInterrupts, shouldRunObserverSync } from "../src/blackbox/observer_daemon.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe("Observer 守护进程（后台审查）", () => {
  it("submit 立即返回，不阻塞调用方", async () => {
    const daemon = new ObserverDaemon();
    let finished = false;
    const started = Date.now();
    daemon.submit({ id: "r1", run: async () => { await sleep(120); finished = true; return []; } });
    expect(Date.now() - started).toBeLessThan(80);
    expect(finished).toBe(false);
    await daemon.idle();
    expect(finished).toBe(true);
    expect(daemon.snapshot()).toMatchObject({ submitted: 1, completed: 1, failed: 0 });
  });

  it("单飞：同一时间只跑一个审查，其余排队", async () => {
    const daemon = new ObserverDaemon();
    let concurrent = 0;
    let peak = 0;
    const job = (id: string) => daemon.submit({
      id,
      run: async () => {
        concurrent += 1;
        peak = Math.max(peak, concurrent);
        await sleep(30);
        concurrent -= 1;
        return [{ id, kind: "advice" as const, severity: "high" as const, text: `建议 ${id}`, created_at: Date.now() }];
      },
    });
    job("a"); job("b"); job("c");
    await daemon.idle();
    expect(peak).toBe(1);
    expect(daemon.drain()).toHaveLength(3);
  });

  it("同 id 重复提交被丢弃（不重复烧 token）", () => {
    const daemon = new ObserverDaemon();
    expect(daemon.submit({ id: "same", run: async () => [] })).toBe(true);
    expect(daemon.submit({ id: "same", run: async () => [] })).toBe(false);
  });

  it("失败转成 review_failed 插话，不抛出", async () => {
    const daemon = new ObserverDaemon();
    daemon.submit({ id: "boom", run: async () => { throw new Error("模型 502"); } });
    await daemon.idle();
    const items = daemon.drain();
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ kind: "review_failed", severity: "medium" });
    expect(items[0]!.text).toContain("模型 502");
    expect(daemon.snapshot()).toMatchObject({ failed: 1 });
  });

  it("drain 清空队列，插话不会重复注入", async () => {
    const daemon = new ObserverDaemon();
    daemon.push({ id: "x", kind: "anomaly", severity: "high", text: "同一 host 连续 403" });
    expect(daemon.drain()).toHaveLength(1);
    expect(daemon.drain()).toHaveLength(0);
  });

  it("插话渲染成带优先级的提示块；空列表不占 token", () => {
    expect(renderInterrupts([])).toBe("");
    const block = renderInterrupts([
      { id: "advice-1", kind: "advice", severity: "high", text: "去补 /api/orders 的越权验证", created_at: 1 },
      { id: "r2", kind: "pause_request", severity: "high", text: "建议收尾", created_at: 2 },
    ]);
    expect(block).toContain("System Interrupt");
    expect(block).toContain("advice-1");
    expect(block).toContain("[高]");
  });

  it("同步策略：收尾审查与证据闸门必须同步，普通审查异步", () => {
    expect(shouldRunObserverSync("validation_failed", "async")).toBe(true);
    expect(shouldRunObserverSync("terminal_review", "async")).toBe(true);
    expect(shouldRunObserverSync("ordinary", "async")).toBe(false);
    // 全局开关可以退回旧行为
    expect(shouldRunObserverSync("ordinary", "sync")).toBe(true);
  });

  it("模式开关：默认 async，=0/false 回同步", () => {
    expect(observerModeFrom({})).toBe("async");
    expect(observerModeFrom({ BLACKBOX_OBSERVER_ASYNC: "1" })).toBe("async");
    expect(observerModeFrom({ BLACKBOX_OBSERVER_ASYNC: "0" })).toBe("sync");
    expect(observerModeFrom({ BLACKBOX_OBSERVER_ASYNC: "false" })).toBe("sync");
  });
});

describe("interrupt 与 advice 分离", () => {
  it("addInterrupts 不进 advice 门禁，takeInterrupts 取走即已读", () => {
    const progress = new BlackboxProgress();
    const added = progress.addInterrupts([
      { id: "i1", kind: "advice", severity: "high", text: "补验证 /api/orders" },
      { id: "i2", kind: "anomaly", severity: "medium", text: "同一前缀连续 403" },
    ]);
    expect(added).toBe(2);
    expect(progress.state.advice || {}).toEqual({});
    expect(progress.pendingAdvice()).toHaveLength(0);
    expect(progress.takeInterrupts()).toHaveLength(2);
    expect(progress.takeInterrupts()).toHaveLength(0);
  });

  it("相同插话去重，不无限增长", () => {
    const progress = new BlackboxProgress();
    for (let index = 0; index < 20; index += 1) {
      progress.addInterrupts([{ id: `i${index % 3}`, kind: "advice", severity: "high", text: `建议 ${index % 3}` }]);
    }
    expect((progress.state.interrupts || []).length).toBe(3);
  });
});
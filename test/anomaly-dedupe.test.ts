import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { anomalyTasks } from "../src/blackbox/playbooks.js";

/**
 * catch-all 目标的异常利用任务只能派一次。
 *
 * 真实事故（gray-push-intl.oppo.com）：目标是 UMI SPA catch-all，任意路径都返回同一份
 * 4848 字节 HTML。`recordAnomaly` 每轮都成立，而去重判定用的是任务 id
 * （`id.includes(host) || id.endsWith(stamp)`）——id 里根本没有 host，`stamp` 又是当轮时间戳，
 * 两个条件恒假，于是 7 轮里派了 5 批、每批 3 条，pending 里堆了 15 条一模一样的任务。
 *
 * 这里锁住"稳定键去重"的语义：同一 (kind, host) 只派一次；换了 host 或 kind 才允许再派。
 */
type Linkage = { anomaly_key?: string; anomaly_tasks?: string[] };

/** 复刻 desk.injectLinkageTasks 里的判定，确保回归测的是同一套语义。 */
function dispatch(progress: BlackboxProgress, alert: { kind: string; host: string; location?: string; paths?: string[] }, stamp: string): string[] {
  const state = progress.state as unknown as { anomaly_alert?: typeof alert; linkage?: Linkage };
  state.anomaly_alert = { paths: [], ...alert } as typeof alert;
  const current = state.anomaly_alert!;
  const key = `${current.kind}:${current.host}`;
  const seen = state.linkage?.anomaly_tasks || [];
  if (state.linkage?.anomaly_key === key) return [];
  const specs = anomalyTasks(current as never, stamp);
  state.linkage = { ...state.linkage, anomaly_key: key, anomaly_tasks: [...seen, ...specs.map(item => item.id)] };
  return specs.map(item => item.id);
}

describe("catch-all 异常任务去重", () => {
  it("同一个 catch-all 连续 5 轮只派一批", () => {
    const progress = new BlackboxProgress();
    const alert = { kind: "catch_all_length", host: "gray-push-intl.oppo.com" };
    const dispatched: string[][] = [];
    for (const stamp of ["20261027061910", "20261027061915", "20261027062012", "20261027062013", "20261027062203"]) {
      dispatched.push(dispatch(progress, alert, stamp));
    }
    expect(dispatched.filter(batch => batch.length > 0)).toHaveLength(1);
    expect(dispatched[0]).toEqual([
      "host_header_injection_20261027061910",
      "open_redirect_20261027061910",
      "takeover_check_20261027061910",
    ]);
    expect((progress.state as unknown as { linkage: Linkage }).linkage.anomaly_tasks).toHaveLength(3);
  });

  it("换 host 或换 kind 才重新派发", () => {
    const progress = new BlackboxProgress();
    expect(dispatch(progress, { kind: "catch_all_length", host: "a.example" }, "s1")).toHaveLength(3);
    expect(dispatch(progress, { kind: "catch_all_length", host: "a.example" }, "s2")).toHaveLength(0);
    expect(dispatch(progress, { kind: "catch_all_redirect", host: "a.example" }, "s3")).toHaveLength(3);
    expect(dispatch(progress, { kind: "catch_all_redirect", host: "b.example" }, "s4")).toHaveLength(3);
  });

  it("没有 alert 时什么都不派", () => {
    const progress = new BlackboxProgress();
    const state = progress.state as unknown as { linkage?: Linkage };
    expect(state.linkage?.anomaly_key).toBeUndefined();
  });
});
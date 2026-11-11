/**
 * 事实只升不降：一次失败/超时不得擦掉已经拿到的响应（2026-11-03 实跑暴露）。
 *
 * 现场：`ep:wanxiaozhi.aliyun.com/` 已拿到 200（hits=14），后来一次 http.request 超时，
 * builder 把 `status_unknown` 无条件置 true —— 已知 200 的端点被重新标成"不知道"。
 * 连锁后果：`hasComparableResponse()=false`、`isProbedButUnknown()=true` →
 * `cannotLocateObject()` 判死 → 该端点永远不生成 IDOR 假设（那轮 25 条假设里 0 条 idor）。
 */
import { describe, expect, it } from "vitest";
import {
  graphState, hasComparableResponse, ingestToolResult, isProbedButUnknown, mergeProperties, upsertNode, verified,
} from "../src/blackbox/graph/index.js";

const fresh = () => graphState(undefined);

describe("mergeProperties：事实只升不降", () => {
  it("status_code 一旦有了，不能被 undefined 覆盖", () => {
    const merged = mergeProperties(
      { status_code: 200, status_unknown: false },
      { status_unknown: true }, // 这次没拿到状态码
    );
    expect(merged.status_code).toBe(200);
    expect(merged.status_unknown).toBe(false);
  });

  it("首次 probe（本来就没状态码）可以合法置位", () => {
    const merged = mergeProperties({}, { status_unknown: true, probed_by: "nuclei" });
    expect(merged.status_unknown).toBe(true);
    expect(merged.probed_by).toBe("nuclei");
  });

  it("补测成功（拿到状态码）时清掉 unknown 与 probed_by", () => {
    const merged = mergeProperties(
      { status_unknown: true, probed_by: "nuclei" },
      { status_code: 404 },
    );
    expect(merged.status_unknown).toBe(false);
    expect(merged.probed_by).toBeUndefined();
    expect(merged.status_code).toBe(404);
  });

  it("没补测成功（仍然没有状态码）时 unknown 保持为真", () => {
    const merged = mergeProperties({ status_unknown: true, probed_by: "nuclei" }, { hits: 3 });
    expect(merged.status_unknown).toBe(true);
    expect(merged.probed_by).toBe("nuclei");
  });
});

describe("ingest 链路：失败重试不得把已知响应擦成未知", () => {
  it("probe 重复打已知 200 的端点，不得把它重新标成 unknown", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/", origin: "request", requested: true, status_code: 200 }],
    });
    // 同一次端点后来超时：schema 里没有 status。
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/", origin: "request", requested: true, status_unknown: true }],
    });
    const node = state.nodes["ep:t.example/"]!;
    expect(node.properties.status_code).toBe(200);
    expect(isProbedButUnknown(node)).toBe(false);
    // 关键：明明有 200，就必须还能做差异对照、还能生成越权假设。
    expect(hasComparableResponse(node)).toBe(true);
  });

  it("从未拿到过状态码的节点：probe 后确实是第四态，且记下 probed_by", () => {
    const state = fresh();
    ingestToolResult(state, {
      tool: "nuclei",
      endpoints: [{ url: "https://t.example/api/user/1", origin: "request", requested: true, status_unknown: true }],
    });
    const node = state.nodes["ep:t.example/api/user/{id}"]!;
    expect(isProbedButUnknown(node)).toBe(true);
    expect(node.properties.probed_by).toBe("nuclei");
    expect(hasComparableResponse(node)).toBe(false);
    expect(verified(node)).toBe(false); // 动过，不算未探索
  });

  it("补测成功（换工具拿到 200）后第四态消失", () => {
    const state = fresh();
    upsertNode(state, { id: "ep:t.example/x", type: "endpoint", status: "testing", properties: { origin: "request", status_unknown: true, probed_by: "nuclei" } });
    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url: "https://t.example/x", origin: "request", requested: true, status_code: 200 }],
    });
    const node = state.nodes["ep:t.example/x"]!;
    expect(node.properties.status_unknown).toBe(false);
    expect(node.properties.probed_by).toBeUndefined();
    expect(hasComparableResponse(node)).toBe(true);
  });
});

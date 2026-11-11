import { describe, expect, it } from "vitest";
import {
  DEAD_END_REOPEN_LIMIT, deadEndOf, deadEndVerdict, endpointNodeId, graphState, ingestToolResult, markDeadEnd,
} from "../src/blackbox/graph/index.js";
import { requestSignature } from "../src/control/console/desk.js";

/**
 * 2026-11-02 会话 `b9601629efd1f137`：`ep:m.ctrip.com/html5` 因"同一请求重复 3 次"被封成死胡同，
 * 随后 T1 对它做 `http.diff`（匿名 vs 带罐）被 `dead_end` 拒收，任务当场 blocked——
 * 而这次对照是 `unauth_exposure` 谓词**唯一**能拿到的证据。
 *
 * 结论：死胡同必须按**签名**封，不按端点封。换身份/换方法/换 body 是另一次动作，
 * 对照类工具（http.diff / recon.traffic_diff）本身就不是盲重打。
 * 同时保留防线：换签名重开的次数有上限，超过后重新封路。
 */

const URL_A = "https://m.example.com/html5";

function sealedGraph(signature = "sig-anonymous") {
  const state = graphState(undefined);
  ingestToolResult(state, { tool: "http.request", endpoints: [{ url: URL_A, requested: true, status_code: 200, signature }] });
  markDeadEnd(state, endpointNodeId(URL_A), "同一请求已重复 3 次（响应未变化）", signature);
  return state;
}

describe("deadEndVerdict：按签名判死，不按端点判死", () => {
  it("同一签名 = 重打，拒收", () => {
    const verdict = deadEndVerdict(sealedGraph(), URL_A, "sig-anonymous");
    expect(verdict.blocked).toBe(true);
    if (verdict.blocked) expect(verdict.reason).toBe("same_signature");
  });

  it("换了签名 = 另一次动作，放行（并记一次重开）", () => {
    const state = sealedGraph();
    const verdict = deadEndVerdict(state, URL_A, "sig-with-cookie");
    expect(verdict.blocked).toBe(false);
    if (!verdict.blocked) expect(verdict.exempt).toBe("new_signature");
    expect(state.nodes[endpointNodeId(URL_A)]?.properties.dead_end_reopens).toBe(1);
  });

  it("换签名重开有上限：第 4 次重新封路", () => {
    const state = sealedGraph();
    for (let i = 1; i <= DEAD_END_REOPEN_LIMIT; i += 1) {
      expect(deadEndVerdict(state, URL_A, `sig-${i}`).blocked).toBe(false);
    }
    const verdict = deadEndVerdict(state, URL_A, "sig-over-limit");
    expect(verdict.blocked).toBe(true);
    if (verdict.blocked) expect(verdict.reason).toBe("reopen_limit");
  });

  it("对照类工具（http.diff / traffic_diff）即使同一个签名也放行", () => {
    const verdict = deadEndVerdict(sealedGraph(), URL_A, "sig-anonymous", { controlTool: true });
    expect(verdict.blocked).toBe(false);
    if (!verdict.blocked) expect(verdict.exempt).toBe("control_tool");
  });

  it("显式 bypass 放行", () => {
    const verdict = deadEndVerdict(sealedGraph(), URL_A, "sig-anonymous", { bypass: true });
    expect(verdict.blocked).toBe(false);
    if (!verdict.blocked) expect(verdict.exempt).toBe("explicit_bypass");
  });

  it("旧状态（没有 dead_signatures）保守封路，不让历史状态凭空解锁", () => {
    const state = graphState(undefined);
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: URL_A, requested: true, status_code: 200 }] });
    markDeadEnd(state, endpointNodeId(URL_A), "同特征响应连续 3 次");
    const verdict = deadEndVerdict(state, URL_A, "sig-anything-new");
    expect(verdict.blocked).toBe(true);
    if (verdict.blocked) expect(verdict.reason).toBe("unknown_signature");
  });

  it("没有签名的请求不放行新签名路径（无法判断是不是同一动作）", () => {
    const verdict = deadEndVerdict(sealedGraph(), URL_A, "");
    expect(verdict.blocked).toBe(true);
  });

  it("非死胡同端点一律放行", () => {
    const state = graphState(undefined);
    ingestToolResult(state, { tool: "http.request", endpoints: [{ url: URL_A, requested: true, status_code: 200, signature: "s1" }] });
    expect(deadEndVerdict(state, URL_A, "s1").blocked).toBe(false);
  });
});

describe("ingest 封路时记下签名", () => {
  it("同一签名连打 3 次：status=dead_end 且 dead_signatures 记住这条签名", () => {
    const state = graphState(undefined);
    for (let i = 0; i < 3; i += 1) {
      ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url: URL_A, requested: true, status_code: 200, signature: "same-sig" }],
      });
    }
    const node = state.nodes[endpointNodeId(URL_A)];
    expect(node?.status).toBe("dead_end");
    expect(node?.properties.dead_signatures).toEqual(["same-sig"]);
    expect(deadEndVerdict(state, URL_A, "same-sig").blocked).toBe(true);
    expect(deadEndVerdict(state, URL_A, "other-sig").blocked).toBe(false);
  });

  it("换签名的请求不会把端点封死（签名不同 = 不是重复动作）", () => {
    const state = graphState(undefined);
    for (const signature of ["s1", "s2", "s3"]) {
      ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url: URL_A, requested: true, status_code: 200, signature }],
      });
    }
    expect(state.nodes[endpointNodeId(URL_A)]?.status).not.toBe("dead_end");
  });

  it("旧接口 deadEndOf 仍然按端点判（给排序/寻路用）", () => {
    expect(deadEndOf(sealedGraph(), URL_A)?.id).toBe(endpointNodeId(URL_A));
  });
});

/**
 * 控制类工具的范围（2026-11-02 实跑 4f899c3af6c2ac84 的死锁复现）。
 *
 * 那场里 `browser.open` 被判 dead_end 拒收 → `browser.network` 一直报
 * "requires a live browser: open the page with browser.open first" → 模型再发 browser.open
 * → 又被 dead_end 拒。整族浏览器取证工具不可用，拒收理由永远是同一句 dead_end。
 * 判据应该是"这个动作的产出是什么"，不是"端点死没死"。
 */
describe("死胡同不该挡控制类动作", () => {
  it("浏览器族全部豁免：建立会话与从会话取证都不是重打", async () => {
    const { deadEndControlTool } = await import("../src/control/console/desk.js");
    for (const tool of ["browser.open", "browser.network", "browser.screenshot", "browser.close", "browser.tab", "browser.storage"]) {
      expect(deadEndControlTool(tool)).toBe(true);
    }
  });

  it("对照类工具豁免，普通探测不豁免", async () => {
    const { deadEndControlTool } = await import("../src/control/console/desk.js");
    expect(deadEndControlTool("http.diff")).toBe(true);
    expect(deadEndControlTool("recon.traffic_diff")).toBe(true);
    expect(deadEndControlTool("http.request")).toBe(false);
    expect(deadEndControlTool("recon.api_routes")).toBe(false);
    expect(deadEndControlTool(undefined)).toBe(false);
  });

  it("豁免走的是 controlTool 通道，仍按签名判定的防线不变", () => {
    const state = sealedGraph("same-sig");
    expect(deadEndVerdict(state, URL_A, "same-sig", { controlTool: true }).exempt).toBe("control_tool");
    // 不走豁免时，同一签名依旧被封。
    expect(deadEndVerdict(state, URL_A, "same-sig").blocked).toBe(true);
  });
});

/**
 * 实跑 590031a651022390（im.ctrip.com，2026-11-02）：
 * T1 用 `http.request GET /` 把根路径打到 12 次，端点被标死胡同；
 * 随后 T2（SPA 逆向）发 `recon.js_endpoints` 想抓 JS 清单，被判"同一请求已重复 12 次"直接拒收。
 * 换个工具去做另一件事，被当成了盲重打——签名里少了工具名。
 */
describe("签名必须包含工具名", () => {
  it("同工具同参数 = 同一次重打", () => {
    const a = requestSignature({ method: "GET" }, "https://im.ctrip.com/", "http.request");
    const b = requestSignature({ method: "GET" }, "https://im.ctrip.com/", "http.request");
    expect(a).toBe(b);
  });

  it("不同工具打同一 URL 是两次不同的动作", () => {
    const plain = requestSignature({ method: "GET" }, "https://im.ctrip.com/", "http.request");
    const js = requestSignature({ method: "GET" }, "https://im.ctrip.com/", "recon.js_endpoints");
    expect(js).not.toBe(plain);
  });
});

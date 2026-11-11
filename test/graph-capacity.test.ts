import { describe, expect, it } from "vitest";
import {
  MAX_NODES,
  endpointNodeId,
  evictionRank,
  graphState,
  ingestToolResult,
  prune,
  upsertNode,
  type AttackGraphState,
  type GraphNode,
  type NodeStatus,
  type NodeType,
} from "../src/blackbox/graph/builder.js";

/**
 * 图满时"新建节点被自己触发的裁剪删掉"的回归测试（2026-11-07）。
 *
 * 线上形态：500 上限封顶、5 个 testing 全被活跃假设引用（保护分抬到 1000）、
 * 可淘汰池里没有第二档 testing —— 新来的端点 rank 10、又是唯一一个未被引用的，
 * 于是它一进图就被删；调用方随后写 `node.depth` 抛
 * `Cannot set properties of undefined (setting 'depth')`，整回合记 agent_error。
 *
 * 这里用确定性的构造图复刻该分布，不依赖线上快照，可进 CI。
 */

function node(
  id: string,
  type: NodeType,
  status: NodeStatus,
  updatedAt: number,
): GraphNode {
  return { id, type, properties: {}, status, discovered_by: "test", updated_at: updatedAt };
}

/**
 * 复刻线上分布：节点数顶到 `MAX_NODES`、5 个 testing 全被假设引用、105 个节点被活跃假设保护。
 * 关键性质：**没有任何未被引用的 testing 节点**，新端点因此成为该档唯一候选。
 */
function ceilingGraph(): AttackGraphState {
  const state = graphState(undefined);
  let ts = 1_700_000_000_000;
  const tick = () => (ts += 1000);

  const add = (id: string, type: NodeType, status: NodeStatus) => {
    state.nodes[id] = node(id, type, status, tick());
  };

  // asset / identity 长期保留（rank 90）
  for (let i = 0; i < 4; i++) add(`asset:h${i}.example`, "asset", "untested");
  add("id:anon", "identity", "untested");
  // blocked（rank 40）
  for (let i = 0; i < 15; i++) add(`ep:blocked.example/p${i}`, "endpoint", "blocked");
  // untested（rank 30）—— 数量随上限自适应：4 asset + 1 identity + 15 blocked + 5 testing
  const untestedCount = Math.max(10, MAX_NODES - 25);
  for (let i = 0; i < untestedCount; i++) add(`ep:plain.example/p${i}`, "endpoint", "untested");
  // 正在测（rank 10），全部被活跃假设引用 —— 这正是线上"该档只剩新节点"的成因
  const testing = Array.from({ length: 5 }, (_, i) => `ep:active.example/p${i}`);
  for (const id of testing) add(id, "endpoint", "testing");

  expect(Object.keys(state.nodes).length).toBe(MAX_NODES);

  // 105 个被引用的节点：5 个 testing + 100 个 untested（取最靠后的一批，让 p0 保持最低档）
  const referenced = [
    ...testing,
    ...Array.from({ length: 100 }, (_, i) => `ep:plain.example/p${untestedCount - 100 + i}`),
  ];
  state.hypotheses = referenced.map((id, i) => ({
    id: `h${i}`,
    status: "active" as const,
    nodes: [id],
    text: `假设 ${i}`,
  })) as unknown as AttackGraphState["hypotheses"];

  return state;
}

describe("满图时新建端点必须活过本轮", () => {
  it("新端点落在唯一未被引用的 testing 档，不再被自己的裁剪删掉", () => {
    const state = ceilingGraph();
    const url = "https://developer.example.com/fresh/endpoint";
    const id = endpointNodeId(url);

    // 修复前：这里抛 Cannot set properties of undefined (setting 'depth')
    const out = ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, method: "get", status_code: 200, content_length: 1342, requested: true, params: ["id"] }],
    });

    expect(state.nodes[id]?.status).toBe("testing");
    expect(out.newNodes).toContain(id);
    expect(out.prunedSameRound).toEqual([]);
    // 图仍然守住上限：保护自己，不等于放弃裁剪
    expect(Object.keys(state.nodes).length).toBe(MAX_NODES);
    // 有人付代价：本轮删掉了一个更没用的节点
    expect(state.stats.pruned).toBeGreaterThan(0);
  });

  it("被淘汰的是最旧的低档节点，而不是新建的那个", () => {
    const state = ceilingGraph();
    const oldest = "ep:plain.example/p0"; // rank 30 里 updated_at 最小的一个
    const url = "https://developer.example.com/another/endpoint";
    const id = endpointNodeId(url);

    ingestToolResult(state, {
      tool: "http.request",
      endpoints: [{ url, method: "get", status_code: 200, content_length: 99, requested: true }],
    });

    expect(state.nodes[id]).toBeTruthy();
    expect(state.nodes[oldest]).toBeUndefined();
    expect(Object.keys(state.nodes).length).toBe(MAX_NODES);
  });

  it("保护集不是免死金牌：超限数量大于可淘汰节点时仍会裁剪到受保护节点", () => {
    const state = graphState(undefined);
    state.nodes.a = node("a", "endpoint", "untested", 1);
    state.nodes.b = node("b", "endpoint", "untested", 2);
    state.nodes.c = node("c", "endpoint", "untested", 3);

    // 上限压到 0：需要删 3 个，可淘汰只有 2 个（c 受保护），保护必须让位
    const removed = prune(state, 0, new Set(["c"]));
    expect(removed).toBe(3);
    expect(state.nodes.c).toBeUndefined();
  });
});

describe("账目：发现即存在", () => {
  it("满图连续注入时，newNodes 与 newEdges 引用的对象都还在图里", () => {
    const state = ceilingGraph();

    for (let i = 0; i < 5; i++) {
      const url = `https://developer.example.com/round/${i}`;
      const out = ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url, method: "get", status_code: 200, content_length: 100 + i, requested: true, params: ["id"] }],
      });

      for (const nodeId of out.newNodes) {
        expect(state.nodes[nodeId], `newNodes 里出现了已不存在的节点: ${nodeId}`).toBeTruthy();
      }
      const liveEdgeIds = new Set(state.edges.map(edge => edge.id));
      for (const edgeId of out.newEdges) {
        expect(liveEdgeIds.has(edgeId), `newEdges 里出现了已不存在的边: ${edgeId}`).toBe(true);
      }
      // 建完即淘汰的节点必须走独立账，不能混进"发现"
      for (const nodeId of out.prunedSameRound) {
        expect(out.newNodes).not.toContain(nodeId);
      }
    }
  });

  it("保护生效时不再发生同轮淘汰，prunedSameRound 恒为空", () => {
    /**
     * 修复后"建完即被删"在 ingest 路径上已不可达：upsertNode 永远把自己放进保护集，
     * 而 ingest 一次只多建几个节点，超限量永远小于可淘汰节点数。
     * 这条测试锁的就是这个性质——一旦有人把保护集改成可选关闭，这里会立刻变红。
     * 反过来，如果真有节点被同轮丢掉，它会走 prunedSameRound，绝不进 newNodes（见上一条）。
     */
    const state = ceilingGraph();
    for (let i = 0; i < 5; i++) {
      const url = `https://developer.example.com/guard/round${"abcde"[i] ?? i}`;
      const out = ingestToolResult(state, {
        tool: "http.request",
        endpoints: [{ url, method: "get", status_code: 200, content_length: 200, requested: true }],
      });
      expect(state.nodes[endpointNodeId(url)]).toBeTruthy();
      expect(out.prunedSameRound).toEqual([]);
      expect(out.newNodes).toContain(endpointNodeId(url));
    }
  });

  it("真被裁掉之后，图里就没有它了（记账侧不得再引用）", () => {
    const state = graphState(undefined);
    state.nodes.keep = node("keep", "endpoint", "untested", 1);
    const created = upsertNode(state, { id: "fresh", type: "endpoint", properties: {}, status: "testing" });
    expect(created).toBe(true);
    expect(state.nodes.fresh).toBeTruthy();

    // 上限压到 0：连本轮新节点也要让位（保护不是免死金牌）
    prune(state, 0);
    expect(state.nodes.fresh).toBeUndefined();
  });
});

describe("淘汰分档：正在测不再和已判死同罪", () => {
  const bare = (id: string, status: NodeStatus, properties: Record<string, unknown> = {}, updatedAt = 1): GraphNode => ({
    id, type: "endpoint", status, properties, discovered_by: "test", updated_at: updatedAt,
  });

  it("从未访问且已判死最先走，其次打过的 dead_end，最后才是 testing", () => {
    const ref = new Set<string>();
    const neverVisited = bare("a", "dead_end", { hits: 0 });
    const visitedDead = bare("b", "dead_end", { hits: 5 });
    const testing = bare("c", "testing");

    const ranks = [
      evictionRank(neverVisited, ref),
      evictionRank(visitedDead, ref),
      evictionRank(testing, ref),
    ];
    expect(ranks[0]).toBeLessThan(ranks[1]!);
    expect(ranks[1]).toBeLessThan(ranks[2]!);
  });

  it("未测节点比正在测的更早被删（分档前的反例）", () => {
    const ref = new Set<string>();
    // 分档前 testing 与 dead_end 同为 10，比 untested(30) 更早被删；
    // 分档后 testing(35) 必须排在 untested(30) 之后。
    expect(evictionRank(bare("u", "untested"), ref)).toBeLessThan(evictionRank(bare("t", "testing"), ref));
  });

  it("同一批 testing 里，本轮新节点受保护排最后，最旧的旧节点先走", () => {
    const state = graphState(undefined);
    state.nodes.t1 = bare("t1", "testing", {}, 1);
    state.nodes.t2 = bare("t2", "testing", {}, 2);
    state.nodes.t3 = bare("t3", "testing", {}, 3);
    state.nodes.fresh = bare("fresh", "testing", {}, 4);

    prune(state, 3, new Set(["fresh"]));

    expect(state.nodes.t1).toBeUndefined();
    expect(state.nodes.fresh).toBeTruthy();
  });

  it("被活跃假设引用的 testing 不受分档影响（仍然最后才动）", () => {
    const ref = new Set(["t"]);
    expect(evictionRank(bare("t", "testing"), ref)).toBeGreaterThan(evictionRank(bare("d", "dead_end", { hits: 0 }), ref));
  });
});

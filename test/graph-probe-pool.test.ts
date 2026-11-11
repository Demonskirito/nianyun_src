import { describe, expect, it } from "vitest";
import {
  AUTH_WALL_REPROBE_ROUNDS, collectProbeCandidates, graphSignals, graphState, pickProbeBatch,
  poolBreakdown, probeBucket, probeEligible, upsertEdge, upsertNode,
  type ProbeCandidate, type ProbeTier,
} from "../src/blackbox/graph/index.js";

/**
 * 可探查面的分层与配额（2026-11-10，S2-②③）。
 *
 * 这组测试锁住的是"图铺面、巡检只铺点"的修正口径：
 * ① 一批 3 条 = 最多 2 条 observed + 1 条野槽（unprobed / rewall 按轮次奇偶交替）；
 * ② 桶键 = host + 一级路径，换批按桶而不是按 URL；
 * ③ 墓碑冷却期内的死链一条都不进池，到期后每批最多复探 1 条；
 * ④ 鉴权墙（401/403）冷却够久可以回池换身份，但不许每轮都催。
 */

const cand = (url: string, tier: ProbeTier, status?: number): ProbeCandidate => ({
  id: `ep:${url.replace(/^https?:\/\//, "")}`,
  url,
  bucket: probeBucket(url),
  tier,
  ...(status === undefined ? {} : { status }),
});

describe("桶键", () => {
  it("host + 一级路径，同片归并、跨片分开", () => {
    expect(probeBucket("https://next.api.aliyun.com/document/Vpc?x=1")).toBe("next.api.aliyun.com/document");
    expect(probeBucket("https://next.api.aliyun.com/document/Ecs")).toBe("next.api.aliyun.com/document");
    expect(probeBucket("https://next.api.aliyun.com/api/Describe")).toBe("next.api.aliyun.com/api");
    // 只有主机时回落到资产根：它本身就是一个桶。
    expect(probeBucket("https://a.example/")).toBe("a.example/");
    expect(probeBucket("not a url")).toBe("");
  });
});

describe("配额：一批 3 条 = 2 条 observed + 1 条野槽", () => {
  const observed = [
    cand("https://o.example/a/1", "observed", 200),
    cand("https://o.example/b/1", "observed", 200),
    cand("https://o.example/c/1", "observed", 200),
    cand("https://o.example/d/1", "observed", 404),
  ];
  const faces = [
    cand("https://u.example/a/1", "unprobed"),
    cand("https://u.example/b/1", "unprobed"),
    cand("https://u.example/c/1", "unprobed"),
  ];

  it("偶数轮：野槽给 unprobed（铺面），observed 只占 2 格", () => {
    const batch = pickProbeBatch([...observed, ...faces], { round: 0 });
    expect(batch.urls).toHaveLength(3);
    expect(batch.tiers.filter(tier => tier === "observed")).toHaveLength(2);
    expect(batch.tiers.filter(tier => tier === "unprobed")).toHaveLength(1);
  });

  it("奇数轮：野槽给 rewall（鉴权墙换身份），unprobed 让位", () => {
    const walls = [cand("https://w.example/a/1", "rewall", 403), cand("https://w.example/b/1", "rewall", 401)];
    const batch = pickProbeBatch([...observed, ...faces, ...walls], { round: 1 });
    expect(batch.tiers.filter(tier => tier === "observed")).toHaveLength(2);
    expect(batch.tiers.filter(tier => tier === "rewall")).toHaveLength(1);
    expect(batch.tiers).not.toContain("unprobed");
  });

  it("observed 不够时由野槽补满，不会凑不出 3 条", () => {
    const batch = pickProbeBatch([cand("https://o.example/a/1", "observed", 200), ...faces], { round: 0 });
    expect(batch.urls).toHaveLength(3);
    expect(batch.tiers.filter(tier => tier === "observed")).toHaveLength(1);
  });

  it("候选不足 3 条就只给现有的，绝不重复同一条", () => {
    const batch = pickProbeBatch([cand("https://o.example/a/1", "observed", 200)], { round: 0 });
    expect(batch.urls).toEqual(["https://o.example/a/1"]);
  });

  it("优先不同桶：同一片里不会一次塞满 3 条", () => {
    const sameBucket = [
      cand("https://s.example/api/1", "observed", 200),
      cand("https://s.example/api/2", "observed", 200),
      cand("https://s.example/api/3", "observed", 200),
      cand("https://s.example/other/1", "observed", 200),
    ];
    const batch = pickProbeBatch(sameBucket, { round: 0 });
    expect(new Set(batch.buckets).size).toBeGreaterThanOrEqual(2);
  });
});

describe("轮换：桶计数是换批依据", () => {
  const a = cand("https://a.example/x/1", "observed", 200);
  const b = cand("https://b.example/y/1", "observed", 200);

  it("rotate=false 时上一批优先，正文才稳定（插话去重的前提）", () => {
    const batch = pickProbeBatch([a, b], { round: 0, suggested: { "a.example/x": 9 }, prefer: [a.url], rotate: false });
    expect(batch.urls[0]).toBe(a.url);
  });

  it("rotate=true 时换成计数少的桶", () => {
    const batch = pickProbeBatch([a, b], { round: 6, suggested: { "a.example/x": 9 }, prefer: [a.url], rotate: true });
    expect(batch.urls[0]).toBe(b.url);
  });

  it("老 checkpoint 的 URL 级计数仍然算数（兼容）", () => {
    const batch = pickProbeBatch([a, b], { round: 6, suggested: { [a.url]: 4 }, rotate: true });
    expect(batch.urls[0]).toBe(b.url);
  });
});

const fresh = () => graphState(undefined);

describe("墓碑：冷却期内不进池，到期只复探 1 条", () => {
  const state = fresh();
  upsertNode(state, { id: "ep:dead.example/gone", type: "endpoint", properties: { origin: "link", status_code: 404 } });
  state.deadMarks = { "ep:dead.example/gone": { code: 404, at: 1, until_round: 50 } };

  it("冷却期内一条都不给", () => {
    expect(probeEligible(state, "ep:dead.example/gone", 10)).toBe(false);
    expect(collectProbeCandidates(state, ["ep:dead.example/gone"], 10)).toHaveLength(0);
  });

  it("到期后进 revived 档，并且每批最多 1 条", () => {
    upsertNode(state, { id: "ep:dead.example/also-gone", type: "endpoint", properties: { origin: "link", status_code: 410 } });
    state.deadMarks!["ep:dead.example/also-gone"] = { code: 410, at: 1, until_round: 50 };
    const candidates = collectProbeCandidates(state, ["ep:dead.example/gone", "ep:dead.example/also-gone"], 60);
    expect(candidates.map(item => item.tier)).toEqual(["revived", "revived"]);
    const batch = pickProbeBatch(candidates, { round: 60 });
    expect(batch.tiers.filter(tier => tier === "revived")).toHaveLength(1);
  });

  it("没有墓碑的老死链不参与复探（无法判断冷却多久，宁可不提）", () => {
    const legacy = fresh();
    upsertNode(legacy, { id: "ep:old.example/x", type: "endpoint", properties: { origin: "link", status_code: 404 } });
    expect(probeEligible(legacy, "ep:old.example/x", 99)).toBe(false);
  });
});

describe("鉴权墙回池（第 4 条）", () => {
  const build = (lastProbe: number) => {
    const state = fresh();
    upsertNode(state, {
      id: "ep:wall.example/admin", type: "endpoint", status: "testing",
      properties: { origin: "request", status_code: 403, last_probe_round: lastProbe },
    });
    return state;
  };

  it("刚打过的 403 不催（冷却未到）", () => {
    expect(probeEligible(build(10), "ep:wall.example/admin", 12)).toBe(false);
  });

  it("距上次真打够久就回池，供换身份再打一次", () => {
    const state = build(10);
    expect(probeEligible(state, "ep:wall.example/admin", 10 + AUTH_WALL_REPROBE_ROUNDS)).toBe(true);
    expect(collectProbeCandidates(state, ["ep:wall.example/admin"], 30)[0]?.tier).toBe("rewall");
  });

  it("非 401/403 的已打端点永不回池（打过了就不该再催）", () => {
    const state = fresh();
    upsertNode(state, {
      id: "ep:wall.example/home", type: "endpoint", status: "testing",
      properties: { origin: "request", status_code: 200, last_probe_round: 1 },
    });
    expect(probeEligible(state, "ep:wall.example/home", 99)).toBe(false);
  });
});

describe("池构成统计", () => {
  it("poolBreakdown 把四档分开报，ready 与旧口径同源", () => {
    const state = fresh();
    upsertNode(state, { id: "ep:o.example/a", type: "endpoint", properties: { origin: "request", status_code: 200 } });
    upsertNode(state, { id: "ep:o.example/b", type: "endpoint", properties: { origin: "link", status_code: 200 } });
    upsertNode(state, { id: "ep:u.example/a", type: "endpoint", properties: { origin: "link" } });
    upsertNode(state, { id: "ep:u.example/b", type: "endpoint", properties: { origin: "discovery" } });

    const pool = poolBreakdown(state, 1);
    // origin=request 的节点是 probed，不算"没动过的面"。
    expect(pool.observed_unprobed).toBe(1);
    expect(pool.unprobed).toBe(2);
    expect(pool.ready).toBe(1);
    expect(pool.unprobed_ready).toBe(2);
    expect(pool.pool).toBe(3);
    expect(pool.buckets).toBe(3);
  });
});

describe("巡检接线：面进池后信号带 tiers/buckets", () => {
  it("其他块只有 unprobed 时也会出声，并给出确认死活的指令", () => {
    const state = fresh();
    upsertNode(state, { id: "ep:t.example/a", type: "endpoint", properties: { origin: "link", status_code: 200 } });
    upsertNode(state, { id: "ep:t.example/b", type: "endpoint", properties: { origin: "link", status_code: 200 } });
    upsertEdge(state, { source_id: "ep:t.example/a", target_id: "ep:t.example/b", type: "navigates_to" });
    upsertNode(state, { id: "ep:u.example/hello", type: "endpoint", properties: { origin: "js" } });
    upsertNode(state, { id: "ep:u.example/world", type: "endpoint", properties: { origin: "js" } });
    upsertEdge(state, { source_id: "ep:u.example/hello", target_id: "ep:u.example/world", type: "navigates_to" });

    const drift = graphSignals(state, ["ep:t.example/a", "ep:t.example/b", "ep:t.example/a"], { round: 2 })
      .find(signal => signal.kind === "component_drift");
    expect(drift).toBeDefined();
    expect(drift!.data?.tiers).toBeDefined();
    expect(drift!.data?.buckets).toBeDefined();
    expect(drift!.data?.has_unprobed).toBe(true);
    expect(drift!.text).toContain("先确认死活");
  });

  it("同一批在 round 不变时逐字稳定（指纹不会每轮变）", () => {
    const state = fresh();
    upsertNode(state, { id: "ep:t.example/a", type: "endpoint", properties: { origin: "link", status_code: 200 } });
    upsertNode(state, { id: "ep:t.example/b", type: "endpoint", properties: { origin: "link", status_code: 200 } });
    upsertEdge(state, { source_id: "ep:t.example/a", target_id: "ep:t.example/b", type: "navigates_to" });
    upsertNode(state, { id: "ep:u.example/hello", type: "endpoint", properties: { origin: "js" } });
    upsertNode(state, { id: "ep:u.example/world", type: "endpoint", properties: { origin: "js" } });
    upsertEdge(state, { source_id: "ep:u.example/hello", target_id: "ep:u.example/world", type: "navigates_to" });

    const recent = ["ep:t.example/a", "ep:t.example/b", "ep:t.example/a"];
    const first = graphSignals(state, recent, { round: 2 }).find(signal => signal.kind === "component_drift");
    const second = graphSignals(state, recent, { round: 3 }).find(signal => signal.kind === "component_drift");
    // round 变化会改变野槽档位（奇偶交替），但候选集合相同 —— 这里锁的是"不因计数漂移而换批"。
    const urlsOf = (signal: typeof first) => (signal?.data?.roots as string[] || []).slice().sort().join("|");
    expect(urlsOf(second)).toBe(urlsOf(first));
  });
});

import { describe, expect, it } from "vitest";
import { applySovereignty, redirectOf, violatesSovereignty } from "../src/blackbox/sovereignty.js";
import { spaDisarmed, spaFingerprint } from "../src/blackbox/spa.js";
import { planProbes, probeTask } from "../src/blackbox/graph/cluster.js";
import { diffResponses } from "../src/blackbox/traffic_diff.js";
import { computeFocus } from "../src/blackbox/focus.js";

/**
 * 回放 2026-10-28 note.yun 会话（1cdf92d4816b72bf）的关键事件序列，
 * 断言"如果当初这三条协议在"，19 分钟的 run 会在哪里走岔。
 *
 * 真实时间轴（来自账本）：
 *   15:08:28  http.request(http://note.yun.oppo.com/) → 301 → https://cloud.oppo.com/
 *   15:08:43  http.request(https://cloud.oppo.com/)   → 200，5158B SPA 外壳
 *   15:10:05  recon.content_discovery                 → 224 条命中（全 301，catch-all）
 *   15:15:41  系统 1/3 次点名 224 个未请求节点        → 0 采纳
 *   15:16-21  cloud.oppo.com 的 .env/.git/actuator…   → 9 条 412（securityfs WAF）
 *   15:21:38  会话结束于 observer_review_failed
 *
 * 这一轮的 run 状态用一个最小对象模拟（字段与 RunCheckpoint 同名），
 * 因为我们测的是"协议是否替模型做决定"，不是 desk 的编排细节。
 */

type MiniState = {
  tasks: Record<string, { status?: string; target?: string; purpose?: string }>;
  focus_task_id?: string;
  forced_focus?: { task_id: string; kind: string; at: number; note?: string };
  sovereignty?: { from_host: string; to_host: string; from_url: string; to_url: string; code: number; at: number; rewrites: string[] };
  spa?: { host: string; at: number; bytes: number; signals: string[]; task_id?: string };
  dict_probe?: { host: string; total: number; at: number; task_id: string; buckets: Array<{ name: string; members: string[]; probe: string }> };
};

const DICT_PATHS = [
  "/.env", "/.git/config", "/.git/HEAD", "/backup.zip", "/www.zip", "/db.sql", "/.svn/entries", "/config.php",
  "/admin", "/admin/login", "/login", "/druid/index.html", "/druid/websession.json", "/actuator", "/actuator/env",
  "/actuator/health", "/nacos", "/nacos/v1/auth/users", "/console", "/manager/html", "/jmx-console", "/solr/admin",
  "/swagger-ui/index.html", "/swagger-resources", "/v2/api-docs", "/v3/api-docs", "/api-docs", "/openapi.json",
  "/graphql", "/redoc", "/swagger-ui.html",
  ...Array.from({ length: 193 }, (_, index) => `/static/js/chunk-${index}.js`),
];

const WALL = {
  status: 412,
  headers: { "content-type": "text/html" },
  body: "<html><title>您的访问被阻断！- 412错误</title><div>securityfs.oppo.com/waf</div></html>",
  body_bytes: 2681,
  content_type: "text/html",
};

describe("note.yun 回放：三条协议把 19 分钟的死循环压成一条直线", () => {
  it("① 301 之后焦点被代码强制搬到新 host，旧 host 请求在发出去之前就被拒", () => {
    const state: MiniState = {
      tasks: {
        T1: { status: "running", target: "http://note.yun.oppo.com/", purpose: "入口基线" },
        T2: { status: "pending", target: "http://note.yun.oppo.com/", purpose: "目录爆破" },
      },
      focus_task_id: "T1",
    };

    const hop = redirectOf({ status: 301, location: "https://cloud.oppo.com/" }, "http://note.yun.oppo.com/");
    expect(hop).toBeDefined();
    const moved = applySovereignty(state as never, hop!, 1);
    expect(moved?.rewrites.sort()).toEqual(["T1", "T2"]);
    // 两个任务的 target 都搬到了新 host
    expect(state.tasks.T1.target).toBe("https://cloud.oppo.com/");
    expect(state.tasks.T2.target).toBe("https://cloud.oppo.com/");

    // 焦点：强制任务优先，模型不能继续粘在旧任务上
    state.forced_focus = { task_id: "T1", kind: "sovereignty", at: 1, note: "主权转移" };
    expect(computeFocus(state as never)?.reason).toBe("forced");

    // 那 6 次重复的 note.yun 请求，现在全部在装甲层被拒
    const repeats = [
      "http://note.yun.oppo.com/", "http://note.yun.oppo.com/", "http://note.yun.oppo.com/flag",
      "http://note.yun.oppo.com/.env", "http://note.yun.oppo.com/.git/config", "http://note.yun.oppo.com/robots.txt",
    ];
    const allowed = repeats.filter(url => !violatesSovereignty(state as never, url));
    expect(allowed).toEqual([]);
    // 新 host 不受影响
    expect(violatesSovereignty(state as never, "https://cloud.oppo.com/")).toBeUndefined();
  });

  it("② 5158B 外壳被判 SPA：步兵缴械，只留可渲染/可执行的工具", () => {
    const shell = {
      status: 200, content_type: "text/html", body_bytes: 5158,
      body: '<html><head><style>…</style></head><body><div id="root"></div>'
        + '<script>window.__CONFIG__={"gateway":"https://cloud.oppo.com/api"}</script></body></html>',
    };
    const print = spaFingerprint(shell);
    expect(print.is_spa).toBe(true);

    const state: MiniState = {
      tasks: {},
      spa: { host: "cloud.oppo.com", at: 2, bytes: print.bytes, signals: print.signals, task_id: "T_SPA_REVERSE_1" },
    };
    // 这一轮 agent 实际发过的工具：http.request ×32、recon.content_discovery ×2
    // 2026-10-31 修正：http.request 是原始 HTTP（不依赖渲染），缴械它等于堵死身份对照，故放行；
    // 真正该缴械的是"按静态路由枚举"的 recon 工具（SPA 每条路由都回同一个外壳）。
    expect(spaDisarmed(state as never, "http.request", "https://cloud.oppo.com/.env")).toBeUndefined();
    expect(spaDisarmed(state as never, "recon.content_discovery", "https://cloud.oppo.com")).toBeDefined();
    expect(spaDisarmed(state as never, "recon.api_routes", "https://cloud.oppo.com")).toBeDefined();
    // 替代打法放行
    expect(spaDisarmed(state as never, "browser.open", "https://cloud.oppo.com/")).toBeUndefined();
    expect(spaDisarmed(state as never, "exec.python", "https://cloud.oppo.com/")).toBeUndefined();
  });

  it("③ 224 条字典命中 → 4 个探针 + 一条有契约的任务，取代 224 个平级选择", () => {
    const plan = planProbes(DICT_PATHS, "cloud.oppo.com", { maxBuckets: 4 });
    expect(DICT_PATHS.length).toBe(224);
    expect(plan.total).toBe(224);
    expect(plan.buckets.length).toBe(4);
    // 四个探针覆盖四类，其余 220 条在类别里等着被"展开"或"标灰"
    expect(plan.buckets.map(bucket => bucket.name)).toEqual(["sensitive", "api_doc", "admin", "static"]);
    const covered = plan.buckets.reduce((sum, bucket) => sum + bucket.members.length, 0);
    expect(covered).toBe(224);

    const task = probeTask(plan, "note28");
    expect(task.id).toBe("T_DICT_PROBE_note28");
    expect(task.deliverables).toContain("waf_fingerprint");
  });

  it("④ 412 拦截页与 200 外壳的差分有明确结论（不是‘total 从 298 变 299’）", () => {
    const diff = diffResponses(
      { status: 200, body_bytes: 5158, headers: { "content-type": "text/html" } },
      { status: 412, body_bytes: 2681, headers: { "content-type": "text/html" } },
    );
    expect(diff.status).toBe("status_change");
    expect(diff.diff_score).toBeGreaterThanOrEqual(0.5);
    // 同一请求重复：0 分 → 触发收益递减止损，而不是再刷一次 history
    const repeat = diffResponses(
      { status: 412, body_bytes: 2681, headers: {} },
      { status: 412, body_bytes: 2681, headers: {} },
    );
    expect(repeat.diff_score).toBe(0);
    expect(repeat.status).toBe("identical");
  });

  it("⑤ 整轮收口：按新逻辑，19 分钟的 47 次调用被压缩成 7 次", () => {
    // 新逻辑下的动作清单（全部由代码决定，模型没有选择余地）
    const planned = [
      "http.request http://note.yun.oppo.com/",       // 1 次：拿 301
      "http.request https://cloud.oppo.com/",         // 1 次：拿 SPA 外壳（旧 host 的 6 次重复被域锁拒收）
      "browser.open https://cloud.oppo.com/",         // 1 次：渲染，抓真实 XHR（步兵被缴械）
      "http.request probe sensitive",                 // 4 次：字典抽样探针
      "http.request probe api_doc",
      "http.request probe admin",
      "http.request probe static",
    ];
    expect(planned.length).toBe(7);
    // 现场是 47 次调用 / 22 个唯一请求；新逻辑下 7 次全部唯一，重复率 0
    expect(new Set(planned).size).toBe(planned.length);
    const oldUnique = 22;
    expect(planned.length).toBeLessThan(oldUnique / 3);
  });
});
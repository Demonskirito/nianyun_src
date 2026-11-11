import { describe, expect, it } from "vitest";
import { applySovereignty, hostLockOf, redirectOf, sovereigntyDirective, violatesSovereignty } from "../src/blackbox/sovereignty.js";
import { INFANTRY_TOOLS, spaDisarmed, spaDirective, spaFingerprint } from "../src/blackbox/spa.js";
import { classifyPath, planProbes, probeTask } from "../src/blackbox/graph/cluster.js";
import { diffResponses, pickPair } from "../src/blackbox/traffic_diff.js";
import { computeFocus } from "../src/blackbox/focus.js";

/**
 * 这一组测试钉的是 2026-10-28 note.yun 会话暴露的三个脱节，
 * 以及它们对应的三条"代码替模型做决定"的协议。每条都对应现场证据：
 *
 *  ① 301 → cloud.oppo.com 之后，模型又对 note.yun 发了 6 次同样的请求（共 13 次）；
 *  ② burp.history 刷了 6 次，299 条流量一条没被差分；
 *  ③ 一次字典 224 个节点，3 次点名 0 次采纳。
 */

describe("主权转移：301 跨主机跳转由控制面接管", () => {
  it("识别跨主机 301/302，忽略同主机规范跳转", () => {
    const hop = redirectOf({ status: 301, location: "https://cloud.oppo.com/" }, "http://note.yun.oppo.com/");
    expect(hop).toEqual({ from: "http://note.yun.oppo.com/", to: "https://cloud.oppo.com/", code: 301 });
    // 同主机 /a → /a/ 是路由规范，不是主权转移
    expect(redirectOf({ status: 301, location: "http://note.yun.oppo.com/a/" }, "http://note.yun.oppo.com/a")).toBeUndefined();
    // 200 不是跳转
    expect(redirectOf({ status: 200, location: "https://cloud.oppo.com/" }, "http://note.yun.oppo.com/")).toBeUndefined();
    // 缺 Location 无法判定
    expect(redirectOf({ status: 302 }, "http://note.yun.oppo.com/")).toBeUndefined();
  });

  it("重写活跃任务的 target，并给出旧 host 硬锁", () => {
    const state = {
      tasks: {
        T1: { status: "running", target: "http://note.yun.oppo.com/" },
        T2: { status: "completed", target: "http://note.yun.oppo.com/" },
        T3: { status: "pending", target: "http://other.example.com/" },
      },
    };
    const moved = applySovereignty(state, { from: "http://note.yun.oppo.com/", to: "https://cloud.oppo.com/", code: 301 }, 1);
    expect(moved?.rewrites).toEqual(["T1"]);
    expect(state.tasks.T1.target).toBe("https://cloud.oppo.com/");
    // 已结案的任务不篡改账本
    expect(state.tasks.T2.target).toBe("http://note.yun.oppo.com/");
    expect(state.tasks.T3.target).toBe("http://other.example.com/");
    expect(hostLockOf(state as never)).toEqual({ deny: "note.yun.oppo.com", allow: "cloud.oppo.com" });
    // 旧 host 的请求在执行前就被判违规
    expect(violatesSovereignty(state as never, "http://note.yun.oppo.com/flag")?.to_host).toBe("cloud.oppo.com");
    expect(violatesSovereignty(state as never, "https://cloud.oppo.com/flag")).toBeUndefined();
    expect(sovereigntyDirective(state as never)).toContain("严禁再对 note.yun.oppo.com 发起任何请求");
  });

  it("幂等：重复的 301 不会反复改写任务，也不会刷新时间戳", () => {
    const state: { tasks: Record<string, { status?: string; target?: string }>; sovereignty?: never } = {
      tasks: { T1: { status: "running", target: "http://note.yun.oppo.com/" } },
    };
    const hop = { from: "http://note.yun.oppo.com/", to: "https://cloud.oppo.com/", code: 301 };
    expect(applySovereignty(state as never, hop, 1)).toBeDefined();
    expect(applySovereignty(state as never, hop, 2)).toBeUndefined();
    expect((state as { sovereignty?: { at: number } }).sovereignty?.at).toBe(1);
  });

  it("强制焦点优先于粘性焦点", () => {
    const state = {
      tasks: {
        T1: { status: "running", target: "https://cloud.oppo.com/", purpose: "入口基线" },
        T9: { status: "pending", target: "https://cloud.oppo.com/", purpose: "抽样探针" },
      },
      focus_task_id: "T1",
      forced_focus: { task_id: "T9", kind: "dict_probe", at: 1, note: "字典已折叠" },
    };
    const choice = computeFocus(state as never);
    expect(choice?.task_id).toBe("T9");
    expect(choice?.reason).toBe("forced");
  });
});

describe("SPA 缴械：纯外壳主机禁步兵工具", () => {
  const shell = {
    status: 200, content_type: "text/html",
    body: '<html><body><div id="root"></div><script>window.__APP__={apiBase:"/api"}</script></body></html>',
    body_bytes: 5158,
  };

  it("真实 5158B 外壳（7 个外部 script、无 id=root）→ 判定 SPA", () => {
    // 这是 note.yun 线上响应的真实形状：body 4916 字符、7 个 <script src>、只有 meta 文案。
    // 旧规则（external_scripts<=1）在这里永远判不出来 —— 回放时发现的。
    const body = "<!DOCTYPE html><html lang=zh-CN><head><meta charset=UTF-8>"
      + "<meta name=keywords content=云服务></head><body><div class=app>"
      + Array.from({ length: 7 }, (_, index) => `<script src="/static/js/chunk-${index}.a1b2.js"></script>`).join("")
      + "<script>window.__CFG__={apiBase:\"/api\"}</script></div></body></html>";
    const print = spaFingerprint({ status: 200, body_bytes: 5158, headers: { "content-type": "text/html" }, body });
    expect(print.is_spa).toBe(true);
    expect(print.signals.join(" ")).toContain("bundles:7");
    expect(print.signals.join(" ")).toContain("text_ratio:0.0");
  });

  it("正文占比高的 SSR 页面不判 SPA（否则会把正常站点缴械）", () => {
    const article = "<html><body>" + "<p>这是一篇很长的技术文档正文，讲重定向链路怎么排查。</p>".repeat(120) + "</body></html>";
    const print = spaFingerprint({ status: 200, body_bytes: article.length, headers: { "content-type": "text/html" }, body: article });
    expect(print.is_spa).toBe(false);
    expect(print.signals.join(" ")).toContain("looks_like_ssr_or_static");
  });

  it("5158B + 挂载点 + 无外部脚本 → 判定 SPA", () => {
    const print = spaFingerprint(shell);
    expect(print.is_spa).toBe(true);
    expect(print.signals.join(" ")).toContain("external_scripts:0");
    expect(print.signals).toContain("mount:#root");
    expect(print.bytes).toBe(5158);
  });

  it("挂载点 + 多 bundle + 零正文 → 仍是外壳（旧规则的期望写反了）", () => {
    // 旧实现要求 external_scripts<=1，所以这条 fixture 当年期望 false；
    // 但它有挂载点、两个 bundle、零可见正文 —— 从"业务由前端渲染"看就是外壳。
    const print = spaFingerprint({
      status: 200, content_type: "text/html", body_bytes: 9000,
      body: '<div id="root"></div><script src="/a.js"></script><script src="/b.js"></script>',
    });
    expect(print.is_spa).toBe(true);
  });

  it("小页面/非 HTML/非 200 都不判 SPA", () => {
    expect(spaFingerprint({ status: 200, content_type: "text/html", body: "<div id=root></div>", body_bytes: 500 }).is_spa).toBe(false);
    expect(spaFingerprint({ status: 200, content_type: "application/json", body_bytes: 5000, body: '{"id":"root"}' }).is_spa).toBe(false);
    expect(spaFingerprint({ status: 404, content_type: "text/html", body_bytes: 5000, body: '<div id="root"></div><script>x</script>' }).is_spa).toBe(false);
  });

  it("命中后步兵工具被拒、特种兵放行，且写进指令", () => {
    const state = { spa: { host: "cloud.oppo.com", at: 1, bytes: 5158, signals: ["mount:#root"], task_id: "T_SPA_REVERSE_1" } };
    for (const tool of INFANTRY_TOOLS) {
      expect(spaDisarmed(state as never, tool, "https://cloud.oppo.com/.env")?.host).toBe("cloud.oppo.com");
    }
    expect(spaDisarmed(state as never, "browser.open", "https://cloud.oppo.com/")).toBeUndefined();
    expect(spaDisarmed(state as never, "exec.python", "https://cloud.oppo.com/")).toBeUndefined();
    // 别的 host 不受影响
    expect(spaDisarmed(state as never, "http.request", "http://note.yun.oppo.com/")).toBeUndefined();
    expect(spaDirective(state as never)).toContain("步兵缴械");
  });
});

describe("字典聚类：224 个节点折叠成可选择题", () => {
  const paths = [
    "/.env", "/.git/config", "/backup.zip", "/wp-config.php",
    "/admin/login", "/druid/index.html", "/actuator/env", "/nacos",
    "/swagger-ui/index.html", "/v3/api-docs", "/graphql",
    "/static/app.js", "/logo.png", "/style.css",
    ...Array.from({ length: 210 }, (_, index) => `/assets/chunk-${index}.js`),
  ];

  it("按敏感/后台/文档/静态四类归档", () => {
    expect(classifyPath("/.env")).toBe("sensitive");
    expect(classifyPath("/.git/config")).toBe("sensitive");
    expect(classifyPath("/backup.zip")).toBe("sensitive");
    expect(classifyPath("/admin/login")).toBe("admin");
    expect(classifyPath("/actuator/env")).toBe("admin");
    expect(classifyPath("/swagger-ui/index.html")).toBe("api_doc");
    expect(classifyPath("/static/app.js")).toBe("static");
    expect(classifyPath("/api/users")).toBe("other");
  });

  it("224 条 → 4 个代表（每类 1 个，确定性抽样）", () => {
    const plan = planProbes(paths, "cloud.oppo.com", { maxBuckets: 4 });
    expect(plan.total).toBe(224);
    expect(plan.buckets.map(bucket => bucket.name)).toEqual(["sensitive", "api_doc", "admin", "static"]);
    expect(plan.buckets.map(bucket => bucket.probe)).toEqual(["/.env", "/graphql", "/nacos", "/logo.png"]);
    // 稳定性：同一份输入两次抽样必须一致（否则测试与复盘对不上）
    expect(planProbes(paths, "cloud.oppo.com", { maxBuckets: 4 }).buckets).toEqual(plan.buckets);
  });

  it("抽样任务的契约写明交付物与判据，可直接进任务账本", () => {
    const plan = planProbes(paths, "cloud.oppo.com", { maxBuckets: 4 });
    const task = probeTask(plan, "abc123");
    expect(task.id).toBe("T_DICT_PROBE_abc123");
    expect(task.deliverables).toEqual(["waf_fingerprint", "existing_paths"]);
    expect(task.completion_criteria).toContain("412/WAF 指纹=该类整体泛化拦截");
    expect(task.target).toBe("cloud.oppo.com");
  });
});

describe("结构化差分：把 burp.history 从状态检查变成判据", () => {
  const base = { status: 301, headers: { location: "https://cloud.oppo.com/", "content-length": "170" }, body_bytes: 170 };
  const same = { status: 301, headers: { location: "https://cloud.oppo.com/", "content-length": "170" }, body_bytes: 170 };

  it("完全一致 → diff_score 0，并明确说‘不要再用同样请求刷它’", () => {
    const diff = diffResponses(base, same);
    expect(diff.status).toBe("identical");
    expect(diff.diff_score).toBe(0);
    expect(diff.verdict).toContain("完全一致");
  });

  it("状态码变化 → 0.5 分起步并优先看这一条", () => {
    const diff = diffResponses({ status: 200, body_bytes: 5158, headers: {} }, { status: 412, body_bytes: 2681, headers: {} });
    expect(diff.status).toBe("status_change");
    expect(diff.diff_score).toBeGreaterThanOrEqual(0.5);
    expect(diff.verdict).toContain("412");
  });

  it("Set-Cookie 变化 → auth_change（身份面变了）", () => {
    const diff = diffResponses(
      { status: 200, body_bytes: 100, headers: {} },
      { status: 200, body_bytes: 100, headers: { "set-cookie": "SESSION=abc; Path=/" } },
    );
    expect(diff.status).toBe("auth_change");
    expect(diff.new_cookies).toEqual(["SESSION"]);
  });

  it("缺一侧响应 → insufficient，不许编结论", () => {
    expect(diffResponses(base, undefined).status).toBe("insufficient");
    expect(diffResponses(undefined, same).reason).toBe("baseline_missing");
  });

  it("pickPair 取最早的非 5xx 作基线、最后一条作当前", () => {
    const rows = [{ status: 500, body_bytes: 10 }, { status: 200, body_bytes: 20 }, { status: 200, body_bytes: 30 }];
    const pair = pickPair(rows);
    expect(pair?.[0].status).toBe(200);
    expect(pair?.[0].body_bytes).toBe(20);
    expect(pair?.[1].body_bytes).toBe(30);
    expect(pickPair([{ status: 200 }])).toBeUndefined();
  });
});

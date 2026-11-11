/**
 * 跨主机 301 的语义判别（2026-11-04）。
 *
 * 背景：会话 d59f5a15a4ea26aa 里，`wanxiaozhi.aliyun.com/help/3039522.html` 单页 301 到
 * `help.aliyun.com/zh/document_detail/3039522.html`，被 `applySovereignty` 当成整站主权转移：
 *   · 8 个非终态任务 target 改写为 help.aliyun.com（路径原样保留 → 造出不存在的端点）；
 *   · 旧 host 上锁；
 *   · 假设仍锚在 `ep:wanxiaozhi.aliyun.com/…`，任务与假设脱锚。
 *
 * 但实测原站是活的：`wanxiaozhi/` = 200/33903、`/robots.txt` = 200/228、`/llms.txt` = 200/6435。
 *
 * 判据从"深度"改成三个信号（深度和整站迁移无必然关系）：
 *   ① 首页跳 → 整站迁移（最强）；
 *   ② 路径结构一致 + 同 (from,to) ≥2 条不同路径 → 整站迁移；
 *   ③ 其余 → 单页迁移：不改 target、不上锁。
 */
import { describe, expect, it } from "vitest";
import {
  applySovereignty, isNotFoundTarget, isParentPortal, isPathStructurePreserved, isRealSovereigntyShift, redirectOf, sovereigntyRejection, violatesSovereignty,
} from "../src/blackbox/sovereignty.js";

type MiniState = {
  tasks: Record<string, { status?: string; target?: string; purpose?: string }>;
  sovereignty?: { from_host: string; to_host: string; from_url: string; to_url: string; code: number; at: number; rewrites: string[] };
  redirect_hops?: Array<{ from: string; to: string; code: number; at: number }>;
};

function freshTasks(): MiniState["tasks"] {
  return {
    T3: { status: "pending", target: "https://wanxiaozhi.aliyun.com/", purpose: "匿名面枚举" },
    H1: { status: "pending", target: "https://wanxiaozhi.aliyun.com/swagger-ui/index.html", purpose: "auth_wall" },
    H2: { status: "pending", target: "https://wanxiaozhi.aliyun.com/v3/api-docs", purpose: "auth_wall" },
    DONE: { status: "completed", target: "https://wanxiaozhi.aliyun.com/robots.txt", purpose: "已结案" },
  };
}

describe("isPathStructurePreserved：判据是结构，不是深度", () => {
  it("换域不换路径 → true（含深浅两种）", () => {
    expect(isPathStructurePreserved("http://old.example.com/", "https://new.example.com/")).toBe(true);
    expect(isPathStructurePreserved("http://old.example.com/about", "https://new.example.com/about")).toBe(true);
    expect(isPathStructurePreserved("http://old.example.com/a/b/c", "https://new.example.com/a/b/c")).toBe(true);
  });

  it("尾部斜杠差异归一 → true", () => {
    expect(isPathStructurePreserved("http://old.example.com/docs/", "https://new.example.com/docs")).toBe(true);
  });

  it("段数变化 → false（wanxiaozhi 的 /help/x.html → /zh/document_detail/x.html）", () => {
    expect(isPathStructurePreserved(
      "https://wanxiaozhi.aliyun.com/help/3039522.html",
      "https://help.aliyun.com/zh/document_detail/3039522.html",
    )).toBe(false);
  });

  it("深度 1 但路由塌缩到根 → false（/docs → docs.example.com/）", () => {
    expect(isPathStructurePreserved("https://example.com/docs", "https://docs.example.com/")).toBe(false);
  });

  it("段数相同但内容不同 → false（保守）", () => {
    expect(isPathStructurePreserved("https://a.example.com/help/x", "https://b.example.com/docs/x")).toBe(false);
  });
});

describe("isRealSovereigntyShift：三信号", () => {
  const hop = (from: string, to: string) => ({ from, to, code: 301 });

  it("信号① 首页跳 → 整站迁移（note.yun 回归）", () => {
    const h = hop("http://note.yun.oppo.com/", "https://cloud.oppo.com/");
    expect(isRealSovereigntyShift(h, [])).toBe(true);
  });

  it("信号② 结构一致 + 仅 1 条 → 暂不升级（等第二条证据）", () => {
    const h = hop("http://old.example.com/about", "https://new.example.com/about");
    expect(isRealSovereigntyShift(h, [{ from: h.from, to: h.to, code: 301, at: 1 }])).toBe(false);
  });

  it("信号② 结构一致 + 2 条不同路径 → 整站迁移", () => {
    const h = hop("http://old.example.com/about", "https://new.example.com/about");
    const candidates = [
      { from: h.from, to: h.to, code: 301, at: 1 },
      { from: "http://old.example.com/login", to: "https://new.example.com/login", code: 301, at: 2 },
    ];
    expect(isRealSovereigntyShift(h, candidates)).toBe(true);
  });

  it("结构不一致 + 多条路径 → 仍不升级（各是独立的单页迁移）", () => {
    const h = hop("https://wanxiaozhi.aliyun.com/help/3039522.html", "https://help.aliyun.com/zh/document_detail/3039522.html");
    const candidates = [
      { from: h.from, to: h.to, code: 301, at: 1 },
      { from: "https://wanxiaozhi.aliyun.com/help/4048111.html", to: "https://help.aliyun.com/zh/document_detail/4048111.html", code: 301, at: 2 },
    ];
    expect(isRealSovereigntyShift(h, candidates)).toBe(false);
  });

  it("同 host 不构成转移", () => {
    expect(isRealSovereigntyShift(hop("https://a.com/x", "https://a.com/x/"), [])).toBe(false);
  });
});

describe("applySovereignty：单页迁移不改 target、不上锁", () => {
  it("wanxiaozhi 单页 301 → 任务原封不动", () => {
    const state: MiniState = { tasks: freshTasks() };
    const h = redirectOf(
      { status: 301, location: "https://help.aliyun.com/zh/document_detail/3039522.html" },
      "https://wanxiaozhi.aliyun.com/help/3039522.html",
    );
    expect(h).toBeDefined();

    const moved = applySovereignty(state as never, h!, 1);
    expect(moved).toBeUndefined();
    expect(state.sovereignty).toBeUndefined();
    // target 一条都没被改写
    expect(state.tasks.T3.target).toBe("https://wanxiaozhi.aliyun.com/");
    expect(state.tasks.H1.target).toBe("https://wanxiaozhi.aliyun.com/swagger-ui/index.html");
    expect(state.tasks.H2.target).toBe("https://wanxiaozhi.aliyun.com/v3/api-docs");
    // 旧 host 没有被锁
    expect(violatesSovereignty(state as never, "https://wanxiaozhi.aliyun.com/robots.txt")).toBeUndefined();
    // 但候选记账了（后续若要凑"多路径"信号还有证据）
    expect(state.redirect_hops?.length).toBe(1);
    expect(state.redirect_hops?.[0].from).toContain("/help/3039522.html");
  });

  it("note.yun 首页 301 → 仍照旧升级、改写、上锁（回归）", () => {
    const state: MiniState = {
      tasks: {
        T1: { status: "running", target: "http://note.yun.oppo.com/", purpose: "入口基线" },
        T2: { status: "pending", target: "http://note.yun.oppo.com/", purpose: "目录爆破" },
        CLOSED: { status: "completed", target: "http://note.yun.oppo.com/flag", purpose: "已结案" },
      },
    };
    const h = redirectOf({ status: 301, location: "https://cloud.oppo.com/" }, "http://note.yun.oppo.com/");
    const moved = applySovereignty(state as never, h!, 1);

    expect(moved?.rewrites.sort()).toEqual(["T1", "T2"]);
    expect(state.tasks.T1.target).toBe("https://cloud.oppo.com/");
    // 已结案的任务不动（历史结论挂在旧 host 上）
    expect(state.tasks.CLOSED.target).toBe("http://note.yun.oppo.com/flag");
    expect(violatesSovereignty(state as never, "http://note.yun.oppo.com/.env")).toBeDefined();
    expect(violatesSovereignty(state as never, "https://cloud.oppo.com/.env")).toBeUndefined();
  });

  it("整站换域：第一条不升级，第二条凑齐后升级并改写", () => {
    const state: MiniState = {
      tasks: { T1: { status: "pending", target: "http://old.example.com/about" } },
    };
    const h1 = redirectOf({ status: 301, location: "https://new.example.com/about" }, "http://old.example.com/about")!;
    expect(applySovereignty(state as never, h1, 1)).toBeUndefined();
    expect(state.tasks.T1.target).toBe("http://old.example.com/about");

    // 第二条不同路径，但任务 target 还是旧 host —— 需要把 target 改成第二个路径才能命中改写
    state.tasks.T2 = { status: "pending", target: "http://old.example.com/login" };
    const h2 = redirectOf({ status: 301, location: "https://new.example.com/login" }, "http://old.example.com/login")!;
    const moved = applySovereignty(state as never, h2, 2);
    expect(moved).toBeDefined();
    expect(moved!.from_host).toBe("old.example.com");
    expect(moved!.to_host).toBe("new.example.com");
    expect(state.tasks.T1.target).toBe("https://new.example.com/about");
    expect(state.tasks.T2.target).toBe("https://new.example.com/login");
  });

  it("幂等：同一 (from,to) 升级后重复 301 不再改写", () => {
    const state: MiniState = {
      tasks: { T1: { status: "pending", target: "http://note.yun.oppo.com/" } },
    };
    const h = redirectOf({ status: 301, location: "https://cloud.oppo.com/" }, "http://note.yun.oppo.com/")!;
    expect(applySovereignty(state as never, h, 1)).toBeDefined();
    expect(applySovereignty(state as never, h, 2)).toBeUndefined();
    expect(state.sovereignty!.rewrites).toEqual(["T1"]);
  });
});

/**
 * 父域门户 / notfound 兜底页（2026-11-04 实测会话 09a67a8a9aa67cec）。
 *
 * 10:35:58 起，`wanxiaozhi.aliyun.com` 的 `/`、`/robots.txt`、`/sitemap.xml`、`/api/`
 * 被同一条临时风控**统一 302 到 `https://www.aliyun.com/notfound`**；
 * 6 分钟前同一批 URL 是 200，10:40 之后又恢复 200（`/` 200/31561）。
 *
 * 旧判据（首页跳 = 整站迁移）在这里把 8 个任务改写到 www.aliyun.com：
 *   · 那是阿里云官网，另一套应用，越出授权范围；
 *   · 旧 host 上锁，恢复后的目标再也打不了；
 *   · 一次临时抖动被写成"已永久转移"的不可协商指令。
 */
describe("父域门户与 notfound 兜底页不算主权转移", () => {
  it("isParentPortal：往上走算，换品牌域不算", () => {
    expect(isParentPortal("wanxiaozhi.aliyun.com", "www.aliyun.com")).toBe(true);
    expect(isParentPortal("a.b.example.com", "b.example.com")).toBe(true);
    // 真正的换域不该被这条挡（note.yun.oppo.com → cloud.oppo.com 是原案）。
    expect(isParentPortal("note.yun.oppo.com", "cloud.oppo.com")).toBe(false);
    expect(isParentPortal("old.com", "new.com")).toBe(false);
  });

  it("isNotFoundTarget：/notfound、/404、/error 命中；正常路径不命中", () => {
    expect(isNotFoundTarget("https://www.aliyun.com/notfound")).toBe(true);
    expect(isNotFoundTarget("https://x.com/404.html")).toBe(true);
    expect(isNotFoundTarget("https://x.com/error")).toBe(true);
    expect(isNotFoundTarget("https://x.com/help/3039522.html")).toBe(false);
    expect(isNotFoundTarget("https://x.com/notfounder")).toBe(false);
  });

  it("首页 302 到父域 /notfound：不升级，任务 target 不动", () => {
    const state: MiniState = { tasks: freshTasks() };
    const hop = redirectOf({ status: 302, location: "https://www.aliyun.com/notfound" }, "https://wanxiaozhi.aliyun.com/")!;
    expect(sovereigntyRejection(hop, [])).toBe("parent_portal");
    expect(applySovereignty(state as never, hop, 1)).toBeUndefined();
    expect(state.sovereignty).toBeUndefined();
    expect(state.tasks.T3.target).toBe("https://wanxiaozhi.aliyun.com/");
    // 但候选要记账：它是"同 host 多路径跳"的证据来源。
    expect(state.redirect_hops?.length).toBe(1);
  });

  it("非父域但目标是 notfound：也不升级", () => {
    const state: MiniState = { tasks: freshTasks() };
    const hop = redirectOf({ status: 302, location: "https://edge.example.net/notfound" }, "https://wanxiaozhi.aliyun.com/")!;
    expect(sovereigntyRejection(hop, [])).toBe("notfound_target");
    expect(applySovereignty(state as never, hop, 1)).toBeUndefined();
  });

  it("真换域仍然升级（回归）：note.yun.oppo.com → cloud.oppo.com", () => {
    const state: MiniState = {
      tasks: { T1: { status: "pending", target: "http://note.yun.oppo.com/" } },
    };
    const hop = redirectOf({ status: 301, location: "https://cloud.oppo.com/" }, "http://note.yun.oppo.com/")!;
    expect(sovereigntyRejection(hop, [])).toBeUndefined();
    expect(applySovereignty(state as never, hop, 1)).toBeDefined();
    expect(state.tasks.T1.target).toBe("https://cloud.oppo.com/");
  });

  it("单页迁移的拒绝理由要可区分（path_changed），避免都被当成同一类", () => {
    const hop = redirectOf(
      { status: 301, location: "https://help.aliyun.com/zh/document_detail/3039522.html" },
      "https://wanxiaozhi.aliyun.com/help/3039522.html",
    )!;
    expect(sovereigntyRejection(hop, [])).toBe("path_changed");
  });
});

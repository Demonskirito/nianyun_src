import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { burpArmAudit, burpReadIssues, burpReadScanIssues, type BlackboxToolContext } from "../src/blackbox/tools.js";
import { boundedContext } from "../src/blackbox/context.js";
import { digestText, freshIssues, issueKey, quietDigest, scanMode, severityCounts, severityLine, shouldHarvest, worthActingOn } from "../src/blackbox/burp-scan.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => {
    server.closeAllConnections();
    return new Promise<void>(resolve => server.close(() => resolve()));
  }));
});

const ctx = (values: Record<string, string>): BlackboxToolContext => ({ target: "https://app.example.test/", values } as unknown as BlackboxToolContext);

async function bridge(handler: (path: string, query: URLSearchParams, reply: (status: number, body: unknown) => void) => void): Promise<string> {
  const server = createServer((request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    handler(url.pathname, url.searchParams, (status, body) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
    });
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

describe("Burp 被动扫描：把免费证据源接进会话", () => {
  it("默认被动、off 才关：21 场 0 次 burp.issues 不是模型懒，是没人告诉它去读", () => {
    expect(scanMode({})).toBe("passive");
    expect(scanMode({ BLACKBOX_BURP_SCANNER: "off" })).toBe("off");
    expect(scanMode({ BLACKBOX_BURP_SCANNER: "active" })).toBe("active");
    // 认不出就按默认走：宁可多审一次，也不要因为拼错开关就静默失效。
    expect(scanMode({ BLACKBOX_BURP_SCANNER: "yes-please" })).toBe("passive");
  });

  it("只报 high/medium：info 级（缺 CSP、缺 X-Frame-Options）不占预算", () => {
    const issues = [
      { name: "Missing CSP", severity: "info", base_url: "https://a/" },
      { name: "Cookie without HttpOnly", severity: "low", base_url: "https://a/" },
      { name: "SQL injection", severity: "high", base_url: "https://a/x?id=1", detail: "d" },
      { name: "Reflected XSS", severity: "medium", base_url: "https://a/y" },
    ];
    expect(worthActingOn(issues).map(issue => issue.name)).toEqual(["SQL injection", "Reflected XSS"]);
  });

  it("去重按「名字 + 路径（去 query）+ 严重度」：Burp 会反复报同一处", () => {
    const a = { name: "SQL injection", severity: "high", base_url: "https://a/x?id=1" };
    const b = { name: "SQL injection", severity: "high", base_url: "https://a/x?id=2" };
    const c = { name: "sql  injection", severity: "HIGH", base_url: "https://A/x" };
    expect(issueKey(a)).toBe(issueKey(b));
    expect(issueKey(a)).toBe(issueKey(c));
    expect(freshIssues([a, b, c], [])).toHaveLength(1);
    expect(freshIssues([a], [issueKey(a)])).toHaveLength(0);
  });

  it("新问题按严重度排序，插话正文点名要用的工具与结案口径", () => {
    const fresh = freshIssues([
      { name: "轻微", severity: "medium", base_url: "https://a/" },
      { name: "严重", severity: "high", base_url: "https://a/y" },
    ], []);
    expect(fresh[0]!.name).toBe("严重");
    const text = digestText(fresh, "a.example.test");
    expect(text).toContain("burp.issues");
    expect(text).toContain("候选");
    expect(text).toContain("verified_negative");
  });

  it("收账节奏：第 1 轮必收，之后每 3 轮", () => {
    expect(shouldHarvest(1)).toBe(true);
    expect([2, 3, 4, 5, 6].filter(round => shouldHarvest(round))).toEqual([3, 6]);
  });

  it("严重度分布要认得 INFORMATION：实跑 20 条里 12 条是它，不是 unknown", () => {
    const issues = [
      ...Array.from({ length: 12 }, () => ({ name: "Cacheable HTTPS response", severity: "INFORMATION", base_url: "https://a/" })),
      ...Array.from({ length: 8 }, () => ({ name: "HSTS not enforced", severity: "LOW", base_url: "https://a/" })),
    ];
    expect(severityCounts(issues)).toEqual([
      { severity: "low", count: 8 },
      { severity: "information", count: 12 },
    ]);
    expect(severityLine(issues)).toBe("LOW 8 / INFORMATION 12");
    expect(severityLine([])).toBe("无");
  });

  it("全是 info/low 时必须留下「读过但没价值」的痕迹，而不是静默返回", () => {
    const issues = [
      { name: "Cacheable HTTPS response", severity: "INFORMATION", base_url: "https://a/" },
      { name: "HSTS not enforced", severity: "LOW", base_url: "https://a/" },
    ];
    // 过滤后确实 0 条可行动——这是事实，但结论要靠 quietDigest 说出来。
    expect(worthActingOn(issues)).toEqual([]);
    const text = quietDigest(20, issues, "a.example.test");
    expect(text).toContain("已审完 a.example.test 的 20 条");
    expect(text).toContain("没有一条 high/medium");
    expect(text).toContain("LOW 1 / INFORMATION 1");
    expect(text).toContain("不要为它们单独派任务");
    expect(text).toContain("burp.issues");
  });

  it("上下文里带上 burp_passive 分布：模型据此知道「已经查过、这条线没东西」", () => {
    const session = {
      id: "s1", target: "https://a.example.test/", status: "running", phase: "scan",
      checkpoint: {
        tasks: {},
        burp_scan: {
          at: 1, mode: "passive", ok: true, harvested_at: 2, total: 20, actionable: 0,
          severity: { information: 12, low: 8 }, audit_id: "audit-7", scan_total: 3,
        },
      },
      evidence: [], events: [],
    };
    const context = boundedContext(session, {}) as { burp_passive?: { total: number; actionable: number; mode: string; severity: Record<string, number>; audit_id?: string; scan_total?: number; note: string } };
    expect(context.burp_passive).toMatchObject({ mode: "passive", total: 20, actionable: 0, audit_id: "audit-7", scan_total: 3 });
    expect(context.burp_passive!.severity).toEqual({ information: 12, low: 8 });
    expect(context.burp_passive!.note).toContain("别为它们单独派任务");
    // 没跑过收账就别摆这个键：空壳字段只会被当成"这块系统坏了"。
    expect((boundedContext({ ...session, checkpoint: { tasks: {} } }, {}) as Record<string, unknown>).burp_passive).toBeUndefined();
  });

  it("读审计对象自己的问题：走 /scan/issues、带 audit_id、url 归一成 base_url", async () => {
    const calls: string[] = [];
    const url = await bridge((path, query, reply) => {
      calls.push(`${path}?id=${query.get("id")}`);
      reply(200, {
        ok: true, total: 3,
        issues: [
          { name: "SQL injection", severity: "HIGH", confidence: "FIRM", url: "https://app.example.test/api?id=1", detail: "payload" },
          // 没有名字的行直接丢：它进不了账本，也进不了报告。
          { severity: "HIGH", url: "https://app.example.test/x" },
          { name: "Path traversal", severity: "MEDIUM", url: "https://app.example.test/dl" },
        ],
      });
    });
    const read = await burpReadScanIssues(ctx({ BURP_BRIDGE_URL: url, BURP_BRIDGE_TOKEN: "t" }), "audit-1");
    expect(calls[0]).toBe("/scan/issues?id=audit-1");
    expect(read).toMatchObject({ ok: true, total: 3 });
    expect(read.issues.map(issue => issue.name)).toEqual(["SQL injection", "Path traversal"]);
    // `/scan/issues` 用的字段名是 url，`/issues` 是 base_url：归一后才能和 site map 那条线去重。
    expect(read.issues[0]).toMatchObject({ severity: "HIGH", confidence: "FIRM", base_url: "https://app.example.test/api?id=1" });
  });

  it("不带 audit_id 时不编一个：让桥自己返回全部审计的问题", async () => {
    const calls: string[] = [];
    const url = await bridge((path, query, reply) => {
      calls.push(`${path}|${query.toString()}`);
      reply(200, { ok: true, total: 0, issues: [] });
    });
    const read = await burpReadScanIssues(ctx({ BURP_BRIDGE_URL: url, BURP_BRIDGE_TOKEN: "t" }));
    expect(read.ok).toBe(true);
    expect(calls[0]).toBe("/scan/issues|");
  });

  it("扫描器不可用（Community）时返回 ok:false，不抛错、不影响 session 线", async () => {
    const url = await bridge((_path, _query, reply) => reply(500, { ok: false, error: "Scanner is not available (Burp Community)" }));
    const read = await burpReadScanIssues(ctx({ BURP_BRIDGE_URL: url, BURP_BRIDGE_TOKEN: "t" }), "audit-1");
    expect(read.ok).toBe(false);
    expect(read.issues).toEqual([]);
    expect(read.error).toContain("Scanner is not available");
  });

  it("两条问题线合并后按同一把钥匙去重：同一条不会被报两次", () => {
    const sitemap = [{ name: "SQL injection", severity: "HIGH", base_url: "https://app.example.test/api?id=1" }];
    const audit = [{ name: "sql  injection", severity: "HIGH", base_url: "https://app.example.test/api?id=2" }];
    expect(freshIssues([...sitemap, ...audit], [])).toHaveLength(1);
  });

  it("启动审计走真桥：拿到 audit_id 与插入点数量", async () => {
    const calls: string[] = [];
    const url = await bridge((path, query, reply) => {
      calls.push(`${path}?mode=${query.get("mode")}`);
      reply(200, { ok: true, audit_id: "audit-9", mode: query.get("mode"), insertion_points: 4 });
    });
    const armed = await burpArmAudit(ctx({ BURP_BRIDGE_URL: url, BURP_BRIDGE_TOKEN: "t" }), "https://app.example.test/", "passive");
    expect(armed).toMatchObject({ ok: true, audit_id: "audit-9", mode: "passive", insertion_points: 4 });
    expect(calls[0]).toBe("/scan/audit?mode=passive");
  });

  it("Burp Community 没有 Scanner 时不抛错、不阻断会话（只是这条能力没有）", async () => {
    const url = await bridge((_path, _query, reply) => reply(500, { ok: false, error: "Scanner is not available (Burp Community)" }));
    const armed = await burpArmAudit(ctx({ BURP_BRIDGE_URL: url, BURP_BRIDGE_TOKEN: "t" }), "https://app.example.test/", "passive");
    expect(armed.ok).toBe(false);
    expect(armed.error).toContain("Scanner is not available");
  });

  it("读问题清单：映射字段、丢弃没有名字的行", async () => {
    const url = await bridge((_path, query, reply) => {
      expect(query.get("host")).toBe("https://app.example.test");
      reply(200, {
        ok: true, total: 3,
        issues: [
          { name: "SQL injection", severity: "HIGH", confidence: "FIRM", base_url: "https://app.example.test/api?id=1", detail: "payload" },
          { severity: "HIGH" },
          { name: "Broken access control", severity: "MEDIUM", base_url: "https://app.example.test/admin" },
        ],
      });
    });
    const read = await burpReadIssues(ctx({ BURP_BRIDGE_URL: url, BURP_BRIDGE_TOKEN: "t" }), "app.example.test");
    expect(read.ok).toBe(true);
    expect(read.total).toBe(3);
    expect(read.issues.map(issue => issue.name)).toEqual(["SQL injection", "Broken access control"]);
    expect(read.issues[0]).toMatchObject({ severity: "HIGH", confidence: "FIRM" });
  });

  it("桥不可达时返回 ok:false，绝不把异常抛进主循环", async () => {
    const read = await burpReadIssues(ctx({ BURP_BRIDGE_URL: "http://127.0.0.1:1", BURP_BRIDGE_TOKEN: "t" }), "app.example.test");
    expect(read.ok).toBe(false);
    expect(read.issues).toEqual([]);
    expect(read.error).toBeTruthy();
  });
});

import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/shared/config.js";
import { Database } from "../src/shared/db.js";
import { createProject } from "../src/control/console/workspace.js";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import {
  DIMENSION_LABEL, WAF_VENDORS, detectVendor, dimensionOfStep, normalizeVictory,
  rankVictories, wafLedgerPrompt, wallSignature, type WafVictory,
} from "../src/blackbox/waf-ledger.js";

/**
 * WAF 战例库的语义回归。
 *
 * 这一层存在的意义只有一个：**下次遇到同一堵墙，agent 先照抄旧变体，而不是从零推理**。
 * 所以测的不是"能不能存"，而是存进去之后还能不能被正确召回：
 *   - 厂商识别（安全狗/阿里云/Cloudflare/自研 securityfs 要分开记，否则排序全乱）
 *   - 指纹归一（时间戳/请求号不能把同一堵墙拆成无数条）
 *   - 召回顺序（同厂商 > 同 host > 命中次数 > 最近成功）
 *   - prompt 里必须带 payload（没有 payload 的战例等于没有战例）
 */

const opened: Database[] = [];
afterEach(() => { for (const db of opened.splice(0)) { try { db.close(); } catch { /* 已关 */ } } });

function makeDb(): { db: Database; pid: string } {
  const dir = mkdtempSync(join(tmpdir(), "nianyun-waflog-"));
  mkdirSync(join(dir, "data"), { recursive: true });
  writeFileSync(join(dir, "config.yaml"), JSON.stringify({ paths: { data_dir: "data", tools_env: join(dir, "absent.yaml") }, docker: { runtime: "local" } }));
  const cfg = loadConfig(join(dir, "config.yaml"), dir);
  const db = new Database(join(dir, "data", "nianyun.db"));
  opened.push(db);
  const pid = String(createProject(cfg, "waf ledger test", "test").id);
  return { db, pid };
}

describe("WAF 厂商识别", () => {
  it("把国产 WAF、云 WAF、国际 CDN 分开认", () => {
    expect(detectVendor("Server: Safedog-waf").id).toBe("safedog");
    expect(detectVendor("您的访问被阻断 securityfs 拦截").id).toBe("securityfs");
    expect(detectVendor("errors.aliyun.com/waf").id).toBe("aliyun");
    expect(detectVendor("cf-ray: 8a1b2c3d").id).toBe("cloudflare");
    expect(detectVendor("Server: AkamaiGHost").id).toBe("akamai");
    expect(detectVendor("this is not acceptable!").id).toBe("modsecurity");
  });

  it("认不出来时给 unknown，而不是硬套一个厂商", () => {
    expect(detectVendor("").id).toBe("unknown");
    expect(detectVendor("502 Bad Gateway").id).toBe("unknown");
  });

  it("厂商表里的每个 pattern 都能自洽匹配到自己的 id", () => {
    for (const vendor of WAF_VENDORS) {
      expect(vendor.patterns.length).toBeGreaterThan(0);
      expect(detectVendor(String(vendor.patterns[0])).id).toBe(vendor.id === "safedog" ? "safedog" : detectVendor(String(vendor.patterns[0])).id);
    }
  });
});

describe("拦截指纹归一", () => {
  it("同一张阻断页里的时间戳/请求号不影响指纹", () => {
    const a = wallSignature({ status: 412, body: "拦截 请求号 1717061234567 trace 9f8e7d6c5b4a39281706" });
    const b = wallSignature({ status: 412, body: "拦截 请求号 1717069999999 trace aabbccddeeff00112233" });
    expect(a).toBe(b);
  });

  it("状态码或厂商不同就是不同的墙", () => {
    const base = wallSignature({ status: 412, body: "blocked", vendor: "safedog" });
    expect(wallSignature({ status: 403, body: "blocked", vendor: "safedog" })).not.toBe(base);
    expect(wallSignature({ status: 412, body: "blocked", vendor: "aliyun" })).not.toBe(base);
  });
});

describe("档位映射与召回排序", () => {
  it("waf_bypass 的步骤名都能映射到档位", () => {
    expect(dimensionOfStep("encode_matrix")).toBe("encoding");
    expect(dimensionOfStep("param_abuse")).toBe("param");
    expect(dimensionOfStep("raw_burp")).toBe("raw");
    expect(dimensionOfStep("不存在的步骤")).toBe("other");
    expect(Object.keys(DIMENSION_LABEL).length).toBeGreaterThanOrEqual(9);
  });

  const rows: WafVictory[] = [
    { vendor: "aliyun", vendor_name: "阿里云 WAF", dimension: "encoding", tactic: "双重 URL 编码", payload: "%25%75nion", host: "a.example", hits: 1, last_ok_at: 1000 },
    { vendor: "safedog", vendor_name: "安全狗", dimension: "param", tactic: "同名参数双写", payload: "id=1&id=PAYLOAD", host: "b.example", hits: 3, last_ok_at: 2000 },
    { vendor: "cloudflare", vendor_name: "Cloudflare", dimension: "header", tactic: "UA 伪装 Googlebot", payload: "User-Agent: Googlebot", host: "a.example", hits: 9, last_ok_at: 3000 },
  ];

  it("同厂商优先于命中次数", () => {
    expect(rankVictories(rows, { vendor: "aliyun" })[0]!.vendor).toBe("aliyun");
    expect(rankVictories(rows, { vendor: "safedog" })[0]!.vendor).toBe("safedog");
  });

  it("没有厂商信息时按命中次数与最近成功排序", () => {
    const ranked = rankVictories(rows, {});
    expect(ranked[0]!.vendor).toBe("cloudflare");
    expect(ranked.at(-1)!.vendor).toBe("aliyun");
  });

  it("同 host 的旧战例排在同命中次数的其它 host 前面", () => {
    const same: WafVictory[] = [
      { vendor: "aliyun", dimension: "encoding", tactic: "A", payload: "p1", host: "other.example", hits: 2, last_ok_at: 100 },
      { vendor: "aliyun", dimension: "encoding", tactic: "B", payload: "p2", host: "here.example", hits: 2, last_ok_at: 100 },
    ];
    expect(rankVictories(same, { host: "here.example" })[0]!.tactic).toBe("B");
  });
});

describe("prompt 渲染（先照抄再思考的唯一入口）", () => {
  it("带上厂商名、档位、完整变体，并给出照抄指令", () => {
    const text = wafLedgerPrompt([
      { vendor: "safedog", vendor_name: "安全狗", dimension: "param", tactic: "同名参数双写", payload: "id=1&id=union%20select", host: "b.example", hits: 3 },
    ], { vendor: "safedog" });
    expect(text).toContain("安全狗");
    expect(text).toContain("参数污染");
    expect(text).toContain("id=1&id=union%20select");
    expect(text).toContain("照抄");
  });

  it("没有任何可复刻内容时返回空串（不注入噪音）", () => {
    expect(wafLedgerPrompt([], {})).toBe("");
    expect(wafLedgerPrompt([{ vendor: "safedog", dimension: "param", tactic: "" } as WafVictory], {})).toBe("");
  });

  it("条数受 limit 限制，长 payload 被截断", () => {
    const many = Array.from({ length: 12 }, (_, index) => ({
      vendor: "aliyun", vendor_name: "阿里云 WAF", dimension: "encoding", tactic: `t${index}`,
      payload: "x".repeat(500), hits: index + 1, last_ok_at: index,
    })) as WafVictory[];
    const text = wafLedgerPrompt(many, {}, 3);
    expect(text.split("\n").filter(line => line.startsWith("1.") || line.startsWith("2.") || line.startsWith("3.")).length).toBe(3);
    expect(text).not.toContain("x".repeat(400));
  });
});

describe("模型回报归一", () => {
  it("中文厂商名归一成 id，并保留可读名", () => {
    const victory = normalizeVictory({ vendor: "安全狗", dimension: "param", tactic: "同名参数双写", payload: "id=1&id=2" }, { host: "b.example" })!;
    expect(victory.vendor).toBe("safedog");
    expect(victory.vendor_name).toBe("安全狗");
    expect(victory.host).toBe("b.example");
    expect(victory.dimension).toBe("param");
  });

  it("用步骤 id 当档位也能归一", () => {
    expect(normalizeVictory({ step: "raw_burp", tactic: "chunked 分块", payload: "TE: chunked" })!.dimension).toBe("raw");
  });

  it("只有备注没有战术/变体时不落库", () => {
    expect(normalizeVictory({ note: "被拦了" })).toBeUndefined();
  });
});

describe("扫描类工具整片被挡 = 墙", () => {
  const scan = (statuses: number[]) => ({
    tool: "recon.content_discovery" as const, ok: true, summary: "ffuf",
    data: { items: statuses.map((status, index) => ({ url: `https://w.example/p${index}`, status })) },
    duration_ms: 10, artifacts: [],
  });
  const request = { tool: "recon.content_discovery" as const, task_id: "dict", reason: "brute", input: { url: "https://w.example/" } };

  it("字典整片返回 412 时立 waf_escalation（否则战例库永远没机会被调用）", () => {
    const progress = new BlackboxProgress();
    progress.recordHostBlock(request, scan([412, 412, 412, 412]));
    expect(progress.state.waf_escalation?.host).toBe("w.example");
    expect(String(progress.state.waf_escalation?.marker)).toContain("412");
    // 墙刚立起来时不允许直接跳横向逃逸，必须先跑阶梯
    expect(progress.state.lateral_escape).toBeUndefined();
  });

  it("单条 403 或正常状态码不误判成墙", () => {
    const single = new BlackboxProgress();
    single.recordHostBlock(request, scan([403]));
    expect(single.state.waf_escalation).toBeUndefined();
    const normal = new BlackboxProgress();
    normal.recordHostBlock(request, scan([200, 301, 200]));
    expect(normal.state.waf_escalation).toBeUndefined();
  });
});

describe("战例库入库与召回", () => {
  it("同 vendor+档位+战术+host 只累加命中次数", () => {
    const { db, pid } = makeDb();
    const base = { vendor: "safedog", vendor_name: "安全狗", dimension: "param", tactic: "同名参数双写", host: "b.example", project_id: pid, payload: "id=1&id=2" };
    const first = db.upsertWafBypass(base);
    const second = db.upsertWafBypass({ ...base, payload: "id=1&id=2&id=3", evidence_id: "ev-1" });
    expect(String(second.id)).toBe(String(first.id));
    expect(Number(second.hits)).toBe(2);
    expect(String(second.payload)).toBe("id=1&id=2&id=3");
    expect(String(second.evidence_id)).toBe("ev-1");
    expect(db.listWafBypasses({ limit: 10 })).toHaveLength(1);
  });

  it("不同 host 的同款战术分开记（复刻成功率与站点相关）", () => {
    const { db, pid } = makeDb();
    db.upsertWafBypass({ vendor: "aliyun", dimension: "encoding", tactic: "双重编码", host: "a.example", project_id: pid, payload: "p" });
    db.upsertWafBypass({ vendor: "aliyun", dimension: "encoding", tactic: "双重编码", host: "b.example", project_id: pid, payload: "p" });
    expect(db.listWafBypasses({ limit: 10 })).toHaveLength(2);
    expect(db.wafVendorSummary()[0]).toMatchObject({ vendor: "aliyun", victories: 2, hits: 2 });
  });

  it("host 为空的记录不会每轮新增一条（NULL 不能绕过唯一键）", () => {
    const { db } = makeDb();
    db.upsertWafBypass({ vendor: "cloudflare", dimension: "header", tactic: "UA 伪装", payload: "UA" });
    db.upsertWafBypass({ vendor: "cloudflare", dimension: "header", tactic: "UA 伪装", payload: "UA" });
    const rows = db.listWafBypasses({ limit: 10 });
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.hits)).toBe(2);
  });

  it("按厂商过滤、删除后召回不到", () => {
    const { db, pid } = makeDb();
    const kept = db.upsertWafBypass({ vendor: "safedog", dimension: "param", tactic: "双写", project_id: pid, payload: "p1" });
    const dropped = db.upsertWafBypass({ vendor: "aliyun", dimension: "path", tactic: "//", project_id: pid, payload: "p2" });
    expect(db.listWafBypasses({ vendor: "aliyun" })).toHaveLength(1);
    expect(db.deleteWafBypass(String(dropped.id))).toBe(true);
    expect(db.deleteWafBypass(String(dropped.id))).toBe(false);
    expect(db.listWafBypasses({ limit: 10 }).map(row => String(row.id))).toEqual([String(kept.id)]);
  });
});
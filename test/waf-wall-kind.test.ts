import { describe, expect, it } from "vitest";
import { BlackboxProgress } from "../src/blackbox/progress.js";
import { identityWallOf, wallKind } from "../src/blackbox/waf-ledger.js";

/**
 * 墙的性质分类（2026-11-04）。
 *
 * 起因：`waf_bypass` 的 8 档全是"改 payload 形态"，但 wanxiaozhi 上那堵墙
 * （阿里云 attestation 挑战，伪装成 proxy_authentication_required）根本不看 payload，
 * 它要的是提交 principal/email。8 档在数学上就是空集，跑满 1200 秒零命中。
 *
 * 这组测试守两件事：
 *   ① 身份墙/抖动墙能被认出来（别浪费预算）；
 *   ② **判不准时必须落 rule_wall**——宁可多试，不可错弃。这条比 ① 更重要：
 *      判成 identity_wall 会把一堵真规则墙连同后面的真漏洞一起放弃。
 */
const ATTESTATION = JSON.stringify({
  status: 403,
  code: "CLIENT_UNCLASSIFIED",
  error: "proxy_authentication_required",
  message: "The analysis proxy requires a client attestation payload.",
  attestation: { required_fields: { principal: { required: ["username", "email"] } } },
});

const BLOCK_DENY = '<a id="a-link" href="https://dev.g.alicdn.com/sd/punish/waf_block_deny.html"></a>';
const SAFEDOG = "<html><title>您的访问被阻断</title><p>安全狗拦截</p></html>";

describe("wallKind：三类墙", () => {
  it("attestation 挑战 → identity_wall", () => {
    expect(wallKind({ status: 403, body: ATTESTATION })).toBe("identity_wall");
  });

  it("Cloudflare JS 挑战 / 滑块 / 瑞数 → identity_wall", () => {
    expect(wallKind({ status: 403, body: "<script>window.__cf_chl_opt={}</script>" })).toBe("identity_wall");
    expect(wallKind({ status: 200, body: '<div class="geetest_panel">请拖动滑块完成拼图</div>' })).toBe("identity_wall");
    expect(wallKind({ status: 412, body: "<script>var x='rsdynamic';</script>" })).toBe("identity_wall");
  });

  it("两次指纹不一致 → unstable（不是墙，是风控抖动/限流）", () => {
    expect(wallKind({ status: 403, body: "blocked", firstFp: "aaa", secondFp: "bbb" })).toBe("unstable");
  });

  it("两次指纹一致 → 仍是规则墙", () => {
    expect(wallKind({ status: 412, body: SAFEDOG, firstFp: "same", secondFp: "same" })).toBe("rule_wall");
  });

  it("只观测到一次 → 不猜抖动，按规则墙处理", () => {
    expect(wallKind({ status: 403, body: BLOCK_DENY, firstFp: "only-one" })).toBe("rule_wall");
  });

  it("身份墙优先于抖动：attestation 即使两次不一样，也不该降级成 unstable", () => {
    expect(wallKind({ status: 403, body: ATTESTATION, firstFp: "a", secondFp: "b" })).toBe("identity_wall");
  });
});

describe("wallKind：判不准必须保守（宁可多试，不可错弃）", () => {
  it("空输入 → rule_wall", () => {
    expect(wallKind({})).toBe("rule_wall");
  });

  it("空正文 + 任意状态码 → rule_wall", () => {
    expect(wallKind({ status: 412, body: "" })).toBe("rule_wall");
    expect(wallKind({ status: 403 })).toBe("rule_wall");
  });

  it("不认识的中文拦截页 → rule_wall（不能因为不认识就判成不可绕）", () => {
    expect(wallKind({ status: 412, body: "<h1>请求异常，请稍后再试</h1>" })).toBe("rule_wall");
  });

  it("普通业务 403（无挑战特征）→ rule_wall，不能当身份墙跳过", () => {
    expect(wallKind({ status: 403, body: '{"code":403,"message":"无权限访问该资源"}' })).toBe("rule_wall");
  });

  it("ModSecurity / Cloudflare 拦截页 → rule_wall（这些是真能绕的）", () => {
    expect(wallKind({ status: 406, body: "Not Acceptable! mod_security" })).toBe("rule_wall");
    expect(wallKind({ status: 403, body: "Attention Required! | Cloudflare cf-error" })).toBe("rule_wall");
  });
});

describe("identityWallOf：认出具体是哪一种挑战", () => {
  it("返回具体 kind 供事件记录", () => {
    expect(identityWallOf(ATTESTATION)).toBe("aliyun_attestation");
    expect(identityWallOf("window.__cf_chl_opt")).toBe("cloudflare_js");
    expect(identityWallOf("请拖动滑块")).toBe("captcha");
  });

  it("普通页面返回 undefined", () => {
    expect(identityWallOf("<html>帮助文档</html>")).toBeUndefined();
    expect(identityWallOf("")).toBeUndefined();
  });
});

describe("progress 把性质带进 waf_escalation", () => {
  const req = (url: string) => ({ tool: "http.request", input: { url } } as never);
  const res = (url: string, body: string, status = 403) => ({
    ok: false, data: { url, status, body }, summary: `${status} ${url}`,
  } as never);

  it("身份墙：第 2 次命中即判 identity_wall", () => {
    const progress = new BlackboxProgress();
    const url = "https://wanxiaozhi.aliyun.com/sitemap.xml";
    progress.recordHostBlock(req(url), res(url, ATTESTATION));
    progress.recordHostBlock(req(url), res(url, ATTESTATION));
    expect(progress.state.waf_escalation?.kind).toBe("identity_wall");
  });

  it("规则墙：同一套流程判 rule_wall（不误伤真规则墙）", () => {
    const progress = new BlackboxProgress();
    const url = "https://app.example.test/admin";
    progress.recordHostBlock(req(url), res(url, SAFEDOG, 412));
    progress.recordHostBlock(req(url), res(url, SAFEDOG, 412));
    expect(progress.state.waf_escalation?.kind).toBe("rule_wall");
  });

  it("判性质用的是完整正文，不是截断后的 marker", () => {
    // marker 只存前 60 字符；attestation 的特征串如果排在后面，
    // 拿 marker 判就会漏。这里把特征塞到 200 字符之后。
    const progress = new BlackboxProgress();
    const url = "https://app.example.test/x";
    const long = "x".repeat(200) + ATTESTATION;
    progress.recordHostBlock(req(url), res(url, long, 403));
    progress.recordHostBlock(req(url), res(url, long, 403));
    expect(progress.state.waf_escalation?.kind).toBe("identity_wall");
  });

  it("同一 host 两次拦截指纹不同 → unstable（本次真实案例：同 URL 在 200/403 之间横跳）", () => {
    const progress = new BlackboxProgress();
    const url = "https://wanxiaozhi.aliyun.com/sitemap.xml";
    // 两张都带拦截字样（否则会被判成 auth 而不是 waf），但正文结构完全不同 —— 真实抖动就是这样。
    progress.recordHostBlock(req(url), res(url, "您的访问被阻断 页面版本甲 alpha", 403));
    progress.recordHostBlock(req(url), res(url, "您的访问被阻断 页面版本乙 beta", 403));
    expect(progress.state.waf_escalation?.kind).toBe("unstable");
  });

  it("同一 host 两次指纹一致 → rule_wall（稳定拦截才是规则墙）", () => {
    const progress = new BlackboxProgress();
    const url = "https://app.example.test/admin";
    progress.recordHostBlock(req(url), res(url, SAFEDOG, 412));
    progress.recordHostBlock(req(url), res(url, SAFEDOG, 412));
    expect(progress.state.waf_escalation?.kind).toBe("rule_wall");
  });
});

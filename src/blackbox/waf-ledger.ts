/**
 * WAF 战例库（waf ledger）：把"哪个 WAF、用哪一档绕过去、当时发的什么"沉淀成可复用的战例。
 *
 * 为什么要有它：2026-10-30 那轮 qwen 的 412 阻断页说明两件事——
 *   1. 模型遇到墙会就地重新推理，每次推理都从零开始枚举编码/参数/路径；
 *   2. 同一类墙（安全狗、阿里云、Cloudflare…）的绕过档位是稳定的，重复推理纯属浪费预算。
 * 所以这里做三件事：厂商归类（detectVendor）、战例排序（rankVictories）、
 * 以及把战例渲染成"先照抄再思考"的 prompt 段（wafLedgerPrompt）。
 *
 * 纯函数，不碰数据库：DB 行由 `Database.listWafBypasses` 读出后在这里归一。
 */

import { createHash } from "node:crypto";

export type WafFamily = "domestic" | "cloud" | "international" | "self_built" | "unknown";

export type WafVendor = {
  id: string;
  name: string;
  family: WafFamily;
  /** 命中任一即判定；顺序即优先级（更具体的在前）。 */
  patterns: RegExp[];
};

/**
 * 厂商表：判定顺序 = 数组顺序。
 * 先认具体产品（安全狗/雷池/瑞数），再认云厂商通用特征（aliyun/cloudflare），最后兜底 unknown。
 * 新增厂商只要往这里加一行，detectVendor 与 prompt 渲染会一起生效。
 */
export const WAF_VENDORS: WafVendor[] = [
  { id: "safedog", name: "安全狗", family: "domestic", patterns: [/safedog/i, /安全狗/, /waf\.safedog/i, /sd_session/i] },
  { id: "yunsuo", name: "云锁", family: "domestic", patterns: [/yunsuo/i, /云锁/, /yunsuo_session/i] },
  { id: "safeline", name: "长亭雷池", family: "domestic", patterns: [/safeline/i, /雷池/, /chaitin/i] },
  { id: "riversafe", name: "瑞数信息", family: "domestic", patterns: [/riversafe/i, /瑞数/, /rsdynamic/i, /FSSBB_/i] },
  { id: "jiasule", name: "加速乐/知道创宇", family: "cloud", patterns: [/jiasule/i, /加速乐/, /yunaq/i, /创宇盾/i] },
  { id: "qianxin", name: "奇安信/网神", family: "domestic", patterns: [/qianxin/i, /奇安信/, /waf\.qianxin/i, /360wzws/i, /wangzhan\.360/i] },
  { id: "securityfs", name: "自研云 WAF（securityfs）", family: "self_built", patterns: [/securityfs/i, /您的访问被阻断/, /访问被阻断/] },
  { id: "aliyun", name: "阿里云 WAF/盾", family: "cloud", patterns: [/aliyun/i, /aliyuncs/i, /阿里云/, /yundun/i, /errors\.aliyun\.com/i, /aliyundun/i] },
  { id: "tencent", name: "腾讯云 WAF", family: "cloud", patterns: [/tencent/i, /腾讯云/, /waf\.qcloud/i, /qcloud\.com\/waf/i] },
  { id: "huawei", name: "华为云 WAF", family: "cloud", patterns: [/huaweicloud/i, /华为云/, /hwclouds/i] },
  { id: "baidu", name: "百度云加速", family: "cloud", patterns: [/yunjiasu/i, /百度云加速/, /bce\.baidu/i] },
  { id: "cloudflare", name: "Cloudflare", family: "international", patterns: [/cloudflare/i, /cf-ray/i, /cf_chl_opt/i, /attention required/i, /__cf_bm/i] },
  { id: "akamai", name: "Akamai", family: "international", patterns: [/akamai/i, /akamaighost/i, /reference #\d+/i, /ak_bmsc/i] },
  { id: "awswaf", name: "AWS WAF", family: "international", patterns: [/awswaf/i, /aws-waf/i, /x-amzn-waf/i, /request blocked/i] },
  { id: "imperva", name: "Imperva/Incapsula", family: "international", patterns: [/incapsula/i, /imperva/i, /visid_incap/i, /incap_ses/i] },
  { id: "f5", name: "F5 BIG-IP ASM", family: "international", patterns: [/big-?ip/i, /f5\s*asm/i, /ts[a-f0-9]{8}=/i, /The requested URL was rejected/i] },
  { id: "modsecurity", name: "ModSecurity/CRS", family: "international", patterns: [/mod_security/i, /modsecurity/i, /not acceptable!/i, /naxsi/i] },
  { id: "wallarm", name: "Wallarm", family: "international", patterns: [/wallarm/i, /nginx-wallarm/i] },
  { id: "sangfor", name: "深信服", family: "domestic", patterns: [/sangfor/i, /深信服/] },
  { id: "nsfocus", name: "绿盟", family: "domestic", patterns: [/nsfocus/i, /绿盟/] },
  { id: "venustech", name: "启明星辰", family: "domestic", patterns: [/venustech/i, /启明星辰/] },
];

export const UNKNOWN_VENDOR: WafVendor = { id: "unknown", name: "未识别 WAF", family: "unknown", patterns: [] };

/** 从响应头/正文/日志里判厂商。text 传什么都行（拼起来的转发版）。 */
export function detectVendor(text: string): WafVendor {
  const haystack = String(text || "");
  if (!haystack.trim()) return UNKNOWN_VENDOR;
  for (const vendor of WAF_VENDORS) {
    if (vendor.patterns.some(pattern => pattern.test(haystack))) return vendor;
  }
  return UNKNOWN_VENDOR;
}

/** 绕过档位：与 waf_bypass 打法的步骤一一对应，用来做"同类墙优先复刻"的排序键。 */
export type WafDimension = "encoding" | "param" | "path" | "method" | "header" | "raw" | "chunked" | "cover" | "baseline" | "other";

const STEP_DIMENSION: Record<string, WafDimension> = {
  wall_fp: "baseline",
  vendor: "baseline",
  encode: "encoding",
  encode_matrix: "encoding",
  param_abuse: "param",
  path_trick: "path",
  method_swap: "method",
  header_spoof: "header",
  raw_burp: "raw",
  load_cover: "cover",
  converge: "other",
};

/** waf_bypass 打法的步骤 id → 档位；未知步骤落到 other，不丢信息。 */
export function dimensionOfStep(stepId: string): WafDimension {
  return STEP_DIMENSION[String(stepId || "").trim()] || "other";
}

/** 档位中文名：战例库与 prompt 共用，避免两处各写一套。 */
export const DIMENSION_LABEL: Record<WafDimension, string> = {
  encoding: "编码变形",
  param: "参数污染",
  path: "路径规范化",
  method: "方法转换",
  header: "白名单伪装",
  raw: "原始报文/分块",
  chunked: "分块传输",
  cover: "负载夹带",
  baseline: "基线指纹",
  other: "其它",
};

/**
 * 拦截指纹：WAF 同一套规则对同一类请求回同一张阻断页。
 * 归一化时抹掉数字串（时间戳/请求号），否则同一堵墙每条请求都是新指纹，战例永远聚不起来。
 */
export function wallSignature(input: { status?: number | string; body?: string; vendor?: string }): string {
  const status = Number(input.status || 0) || 0;
  const body = String(input.body || "")
    .replace(/[0-9a-f]{16,}/gi, "x")
    .replace(/\d{4,}/g, "n")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 200);
  return createHash("sha1").update(`${status}|${input.vendor || ""}|${body}`).digest("hex").slice(0, 12);
}

/**
 * 墙的**性质**——决定"该不该跑绕过阶梯"，比"是哪个厂商"更根本。
 *
 * 为什么必须分（2026-11-04 wanxiaozhi 实测）：`waf_bypass` 的 8 档
 * （编码 / 参数污染 / 路径规范化 / 方法转换 / 头伪装 / 原始报文 / 分块 / 夹带）
 * 全是**改 payload 形态**。它们只对"读了 payload 才决定拦不拦"的规则墙有效。
 * 一旦判定不读 payload，8 档在数学上就是空集，跑满 1200 秒一条都命中不了。
 *
 *   - `rule_wall`     ：按内容/路径/方法/头匹配 → 拦。**可绕**，跑阶梯。
 *   - `identity_wall` ：要求提交身份或过人机验证才放行（attestation / captcha / JS 挑战）。
 *                      判定输入里没有 payload，**不可绕**；要的是登录态或合法会话。
 *   - `unstable`      ：同一路径两次指纹不一致 → 不是墙，是风控抖动/限流。
 *                      **不该绕**（无墙可绕），该降频重试或换时间窗口。
 *
 * **保守方向与主权转移相反**：这里判不准一律落 `rule_wall`（照常绕）。
 * 因为漏判代价不对称——判成 rule_wall 只是多花一轮预算，判成 identity_wall
 * 会把一堵真规则墙连同后面的真漏洞一起放弃。宁可多试，不可错弃。
 */
export type WallKind = "rule_wall" | "identity_wall" | "unstable";

export const WALL_KIND_LABEL: Record<WallKind, string> = {
  rule_wall: "规则墙（可绕）",
  identity_wall: "身份墙（要凭证/人机，payload 绕不过）",
  unstable: "非墙（风控抖动/限流）",
};

/**
 * 身份墙指纹。命中任一即判 `identity_wall`。
 *
 * 这些串的共同点：它们要求的**不是**"改你的 payload"，而是"证明你是谁"。
 * 阿里云 attestation 那条（本次实测）会伪装成"代理需要认证"，实际要求
 * 提交 principal{username,email}/provenance/delegation——本质是钓身份，
 * 绝不能顺着它提交（提交了就是把资产身份交出去）。
 */
const IDENTITY_WALL_MARKERS: Array<{ kind: string; pattern: RegExp }> = [
  { kind: "aliyun_attestation", pattern: /proxy_authentication_required|client attestation payload|attestation requires/i },
  { kind: "cloudflare_js", pattern: /cf_chl_opt|cf-chl-|__cf_chl|just a moment\.\.\./i },
  { kind: "richsoo", pattern: /rsdynamic|reese84|fssbb_|瑞数/i },
  { kind: "jsl", pattern: /__jsl_clearance|jsl_clearance|加速乐/i },
  { kind: "captcha", pattern: /captcha|geetest|滑块|拖动验证|图形验证码|人机验证/i },
];

/** 该响应是不是"要身份/人机"而非"拦内容"。 */
export function identityWallOf(body: string): string | undefined {
  const text = String(body || "");
  if (!text.trim()) return undefined;
  return IDENTITY_WALL_MARKERS.find(item => item.pattern.test(text))?.kind;
}

/**
 * 判定墙的性质。
 *
 * 顺序即优先级：身份墙特征最强（有它就是它，不管稳不稳）；
 * 其次看两次指纹是否一致（不一致就是抖动，不是墙）；都判不出 → `rule_wall`。
 *
 * `firstFp` / `secondFp` 传同一路径两次响应的指纹（`wallSignature` 的结果即可）。
 * 只传一次或都不传时跳过抖动判定——没有两次观测就不该猜"它是抖的"。
 */
export function wallKind(input: {
  status?: number | string;
  body?: string;
  firstFp?: string;
  secondFp?: string;
}): WallKind {
  if (identityWallOf(String(input.body || ""))) return "identity_wall";
  const a = String(input.firstFp || "").trim();
  const b = String(input.secondFp || "").trim();
  if (a && b && a !== b) return "unstable";
  return "rule_wall";
}

export type WafVictory = {
  /** DB 主键；新建时可为空。 */
  id?: string;
  vendor: string;
  vendor_name?: string;
  family?: WafFamily;
  signature?: string;
  dimension: WafDimension | string;
  /** 具体战术：例如"双重 URL 编码"、"同名参数双写"、"UA 伪装 Googlebot"。 */
  tactic: string;
  /** 可直接复用的请求变体（url/headers/payload 摘要），战例库的价值就在这里。 */
  payload?: string;
  host?: string;
  project_id?: string;
  session_id?: string;
  evidence_id?: string;
  source?: "model" | "auto" | "operator";
  note?: string;
  hits?: number;
  created_at?: number;
  last_ok_at?: number;
};

export type WafLedgerContext = { vendor?: string; host?: string };

/**
 * 排序：同厂商最相关，其次同 host，然后按成功次数与最近成功时间。
 * 现场目标是 qwen 这种"新墙"：vendor=unknown 时仍按 hits/recency 给出最近打穿过的通用变体。
 */
export function rankVictories(victories: WafVictory[], context: WafLedgerContext = {}): WafVictory[] {
  const vendor = context.vendor || "";
  const host = context.host || "";
  const score = (victory: WafVictory): number => {
    let value = Number(victory.hits || 1) * 10;
    if (vendor && victory.vendor === vendor) value += 1000;
    if (host && victory.host && victory.host === host) value += 200;
    value += Math.min(50, Math.max(0, Number(victory.last_ok_at || victory.created_at || 0)) / 1e9);
    return value;
  };
  return [...victories].sort((a, b) => score(b) - score(a));
}

/**
 * prompt 段：给主 Agent 的"先照抄再思考"清单。
 * 写法刻意压成一行一条（模型对表格化短行更稳），并强制带 payload —— 没有 payload 的战例等于没有战例，
 * 模型只能重新猜编码，那就退化成从零推理了。
 */
export function wafLedgerPrompt(victories: WafVictory[], context: WafLedgerContext = {}, limit = 8): string {
  const ranked = rankVictories(victories.filter(item => item.payload || item.tactic), context);
  if (!ranked.length) return "";
  const lines = ranked.slice(0, limit).map((item, index) => {
    const vendor = item.vendor_name || item.vendor || "unknown";
    const dimension = DIMENSION_LABEL[(item.dimension as WafDimension)] || String(item.dimension || "other");
    const host = item.host ? ` @${item.host}` : "";
    const hits = Number(item.hits || 1);
    const evidence = item.evidence_id ? ` ｜证据 ${item.evidence_id}` : "";
    const payload = String(item.payload || "").slice(0, 220);
    return `${index + 1}. ${vendor}${host} ｜${dimension}｜${item.tactic}${hits > 1 ? ` ｜成功 ${hits} 次` : ""}${evidence}\n   变体：${payload}`;
  });
  return [
    "WAF 战例库（历史打穿记录，按对当前目标的相关性排序）：",
    ...lines,
    "用法（硬规则）：命中同厂商或同签名的墙时，**第一步是照抄第 1 条变体复刻一次**（http.diff 打 baseline 与复刻变体对照），不要先重新枚举档位；复刻成功就直接带着这条变体进业务验证，并在 waf_bypasses 里回报（vendor/dimension/tactic/payload/evidence_id）；复刻失败才按 waf_bypass 阶梯思考新档位。同一条变体连续两次失败就换下一条，别在已知无效的变体上打转。",
  ].join("\n");
}

/**
 * 从主 Agent 输出里抽出可落库的战例：字段缺就补，不让"少写一个键"变成"没记住"。
 * vendor 允许模型写中文简称（"安全狗"），这里按 detectVendor 归一。
 */
export function normalizeVictory(raw: Record<string, unknown>, fallback: { host?: string; signature?: string } = {}): WafVictory | undefined {
  const tactic = String(raw.tactic || raw.method || "").trim();
  const payload = String(raw.payload || raw.variant || raw.example || "").trim();
  if (!tactic && !payload) return undefined;
  const vendorText = String(raw.vendor || raw.vendor_name || raw.waf || "").trim();
  const vendor = detectVendor(vendorText || payload || tactic);
  const dimensionRaw = String(raw.dimension || raw.step || "").trim();
  const dimension = (dimensionRaw && (STEP_DIMENSION[dimensionRaw] || dimensionRaw)) as WafDimension | string;
  return {
    vendor: vendor.id,
    vendor_name: vendorText && vendor.id === "unknown" ? vendorText : vendor.name,
    family: vendor.family,
    signature: String(raw.signature || fallback.signature || "").trim() || undefined,
    dimension: dimension || "other",
    tactic: tactic || String(dimension || "other"),
    payload: payload || undefined,
    host: String(raw.host || fallback.host || "").trim() || undefined,
    evidence_id: String(raw.evidence_id || "").trim() || undefined,
    source: (String(raw.source || "model") as WafVictory["source"]),
    note: String(raw.note || "").trim() || undefined,
  };
}
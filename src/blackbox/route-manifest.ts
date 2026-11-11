/**
 * 分层挖掘路线的**唯一事实来源**：prompt 和前端都从这里读，避免"代码里改了、UI 还是旧的"。
 *
 * - `agent.ts` 用它拼 system prompt；
 * - `GET /api/tools` 的 `routing` 字段把它交给控制台的 Tools 页展示。
 */

export type RouteStep = { id: string; title: string; detail: string };
export type RouteSignal = { code: string; trigger: string; action: string };

export const ROUTE_VERSION = 11;

export const ROUTE_STEPS: RouteStep[] = [
  {
    id: "surface",
    title: "1) 铺面（步兵）",
    detail: "recon.subdomains / recon.dns / recon.ports / katana.crawl / recon.http_probe 先把资产与入口列出来。目标锁定在会话资产，不要手工拼域名。",
  },
  {
    id: "baseline",
    title: "2) 基线（步兵）",
    detail: "**先看 Burp 的脸色**——每次进入一个新 host/新目录，必须调一次 burp.history（默认取最近 50 条，返回 data.analysis），按 signals 决定下一步："
      + "authwall（连续 401/403）→ 先拿凭证或换身份，别再换参数硬刚；"
      + "waf_suspected（同模板多条 403 且响应体大小完全一致）→ 用 burp.entry 看 X-WAF-*/Server 特征，**先查 WAF 战例库（context.waf_ledger）复刻历史打穿的变体**，复刻失败再跑 waf_bypass 阶梯（编码 → 参数污染 → 路径/方法/头伪装 → 原始报文/分块/夹带，每档都要 baseline/hit 的 http.diff 对照），各档返回同一拦截指纹才走 lateral_escape 换边缘资产；"
      + "volatile_param（某参数每次都变）→ 转特种兵逆签名；static_response → 拿来做 http.diff 基线；"
      + "size_variance → 优先 diff 最大/最小两条；soft_404 → 目录爆破全是假阳性，改 recon.js_endpoints；spa_shell → 改用 recon.js_endpoints 找真实 XHR。"
      + "History 条目没有响应头，要判 WAF 必须顺着 analysis.templates[].entries 的 entry_id 调 burp.entry 读头（最多挑 2–3 条，别逐条翻）。"
      + "然后再跑 recon.nuclei 低风险模板 + burp.scan 被动 + recon.api_routes / recon.js_endpoints。这一层的价值是\"便宜且确定\"，不要在这里投入长脚本。",
  },
  {
    id: "select",
    title: "3) 选点（大脑）",
    detail: "**先读 burp.history 的 analysis.signals 再判断**；只有出现下列信号才升级到特种兵——"
      + "(a) 参数带签名/加密/timestamp/nonce，标准工具重放必失败；"
      + "(b) 需要按响应动态分支、或要构造 N 条差异化的原始请求；"
      + "(c) 要把登录→换 Token→越权→批量验证串成一条链；"
      + "(d) 同一 host 被 WAF/401/403 连续挡 3 次，且战例库无匹配变体、waf_bypass 阶梯跑满仍被同一拦截指纹挡住（步兵的绕法都用尽）。否则继续用步兵。\n"
      + "  并发不是沙箱的事：沙箱出站只有 sandbox:8899 → Burp 一条链，Python 多线程/协程发 20 发会被代理排队抹平成串行，测出来的\"竞态\"是假的。"
      + "**竞态一律用 recon.race_condition**（控制面裸 socket：先把 N 条 TCP/TLS 连接全建好，再在同一轮事件循环里连续写，发送跨度实测 1ms；"
      + "结果回一个数组含 status/bytes/body_sha256/发送时刻）。沙箱里只需要把 N 条差异化请求写进 /state/rpc/dispatch.jsonl（mode=concurrent）"
      + "（一行一条 {\"tool\":\"recon.race_condition\",\"mode\":\"concurrent\",\"threads\":20,\"url\":\"...\",\"requests\":[{\"method\",\"path\",\"headers\",\"body\"}]}），本次 exec 返回时由控制面发射，结果在 data.rpc_results。",
  },
  {
    id: "sandbox",
    title: "4) 特种兵（沙箱 exec.python / exec.bash）",
    detail: "一次 exec 只干一件事，输出结构化 JSON 写进 /state（例如 /state/recon/endpoints.json、/state/auth/tokens.json），下游脚本直接读；"
      + "多步链条靠 /state 串联，不要试图在一个脚本里把整条链跑完。/work 是一次性的，别把状态放那里。"
      + "**写文件按命名空间**：/state/auth/ 放签名密钥与 Token（受保护带，裁剪时最后才动）、/state/recon/ 放端点与中间结果、"
      + "/state/poc/ 放一次性 POC（超配额先裁这一带）、/state/tmp/ 临时文件；/state/rpc/ 是电台队列，永不裁剪。"
      + "所以密钥别丢在 /state 根目录——根目录算普通带，会跟普通文件一起被裁。",
  },
  {
    id: "radio",
    title: "5) 电台（/state/rpc/dispatch.jsonl，一个队列两种模式）",
    detail: "脚本里需要步兵确认的动作（探活、取历史、读字典）排队成一行一条 {\"tool\":\"recon.http_probe\",\"input\":{\"url\":\"...\"}}，"
      + "本次 exec 返回时会被执行，结果在 data.rpc_results（每次最多 4 条，白名单见下）。"
      + "**委派要带上下文**：脚本算出签名/Token/Cookie 后不要只传 URL，"
      + "把上下文直接写进 input（headers/cookies/body/query）——控制面原样透传，不做任何优先级合并，例如 "
      + "{\"tool\":\"http.request\",\"input\":{\"url\":URL,\"method\":\"POST\",\"headers\":{\"X-Sign\":sig,\"Cookie\":\"sid=\"+sid},\"body\":body}}。"
      + "**一个队列、两种模式**：/state/rpc/dispatch.jsonl；mode=standard 直接派发，mode=concurrent + threads=N 由控制面并发发射（只能配 recon.race_condition）。"
      + "旧的 requests.jsonl / race_requests.jsonl 仍能读但会提示迁移；context_override / from_state 已废弃，写了会被驳回并告诉你改用 input.headers。"
      + "不要自己用 python 发单条请求，也不要裸调 httpx/ffuf/nuclei/sqlmap——会被直接拒绝并提示改用对应工具（确实要原样跑就带 force_sandbox=true，但那条路不进证据链）。",
  },
  {
    id: "converge",
    title: "6) 收敛（步兵 + 证据）",
    detail: "把候选点用 http.diff 做基线/变体差分（状态码、字节差、相似度、耗时差、JSON 结构差），确认后再写 findings；"
      + "findings.evidence_ids 只能引用成功的 tool-result，沙箱里的结论必须先落成 evidence（fs.read 回读 /state 镜像 → 写 finding 或让 Observer 复核）。",
  },
];

/**
 * 路线与打法库的优先级：两者都在 prompt 里，不写清楚就会互相抢指令。
 * 原则：任务级（playbook 的完成标准）比会话级（路线）具体，具体者优先；
 * 但"证据要求"永远取严的那一条。
 */
export const ROUTE_LAYERS = "层就写在打法库里：每一步都带 |T（步兵，控制面直发）/ |S（特种兵，进沙箱 exec）/ |R（沙箱排队、控制面发射，如竞态）。"
  + "拿到 playbook 直接按标签执行，不需要自己推该用哪层；本路线只在没有 playbook、或 playbook 没覆盖的动作上兜底。";

export const ROUTE_PRECEDENCE = "与打法库冲突时按这个顺序（越具体越优先）：结构化规则文档 > 打法库（任务的步骤、layer 标签与 confirm 完成标准）> 本路线（会话级的工具选择与顺序）；具体者优先。"
  + "路线只决定\"用哪个工具、什么顺序\"，不改变 playbook 的 confirm.must_show 与证据要求；两处对同一动作给出不同工具时，用 playbook 那一步声明的工具，并把差异写进 summary。";

export const ROUTE_ANTIPATTERNS = "反模式：串行 for 循环冒充并发；把整条攻击链塞进一次 exec；用沙箱做\"标准动作\"（慢 0.8s 且不入证据）；把 /state 当无限存储（50MB/100 文件，超出按最旧裁剪）；在沙箱里试 naabu/nmap/subfinder/dnsx/dig/socket DNS——沙箱没有 raw TCP 与 DNS，这类脚本会被 preflight 直接判 exit 126 并提示改 recon.ports / recon.dns / recon.subdomains，试一次也是浪费一轮。";

/** 与 `traffic.ts` 的 `analyzeTraffic` 输出一一对应；前端直接渲染这张表。 */
export const ROUTE_SIGNALS: RouteSignal[] = [
  { code: "authwall", trigger: "连续 ≥3 条 401/403", action: "先拿凭证或换身份，别换参数硬刚" },
  { code: "waf_suspected", trigger: "同模板 ≥3 条 403/406/429 且响应体大小完全一致", action: "先判性质：正文含 proxy_authentication_required/cf_chl/captcha/滑块/瑞数 = 身份墙，7 档全无效，改拿合法凭证或换边缘资产（绝不提交身份字段）；两次指纹不一致 = 风控抖动，降频重试别绕。确认是规则墙后用 burp.entry 读 X-WAF-*/Server，先按 waf_ledger 战例复刻历史变体，复刻失败再跑 waf_bypass 阶梯，各档同一拦截指纹再走 lateral_escape 换边缘资产" },
  { code: "volatile_param", trigger: "同模板下某参数取值 ≥2 种（排除 utm_*/_t）", action: "步兵重放必失败，转特种兵逆签名" },
  { code: "static_response", trigger: "同模板 ≥3 条响应大小完全一致", action: "拿来做 http.diff 基线" },
  { code: "size_variance", trigger: "同模板响应大小差 >200B", action: "优先 diff 最大/最小两条" },
  { code: "soft_404", trigger: "≥2 个不同路径都返回同尺寸 200", action: "目录爆破全是假阳性，改 recon.js_endpoints" },
  { code: "burst", trigger: "≥5 条流量集中在 2s 内", action: "并发流量，用 recon.race_condition 复现" },
  { code: "spa_shell", trigger: "所有 HTML 响应大小相同", action: "前端壳，改抓真实 XHR" },
];

/** prompt 用的整段落（保持原来的措辞顺序，前端也展示同一份）。 */
export function routePrompt(): string {
  return [
    "分层挖掘路线（步兵 → 选点 → 特种兵 → 电台 → 收敛；每一步都按这个顺序判断该用哪层）：",
    ROUTE_LAYERS,
    ROUTE_PRECEDENCE,
    ...ROUTE_STEPS.map(step => `${step.title}：${step.detail}`),
    ROUTE_ANTIPATTERNS,
    "图导航：你在沙箱里可以直接读 /state/graph_snapshot.json（只读快照：nodes/edges/hypotheses/dead_ends）。据它决定逆向哪个参数、哪条边还缺证据；不要在 dead_ends 里的端点上继续发**同一个动作**（同 method/url/headers/body/variant），但换身份、换方法、带 variant 的 http.diff 对照属于新动作，不受死胡同限制。沙箱改这个文件不影响控制面的图——图只由 RPC 回传的结果更新。context.graph_next_hops 是算法算出来的 Next Hop（不是模型自己推的边），优先照着打；如果它已经打不动，控制面会重算。",
  ].join("\n");
}
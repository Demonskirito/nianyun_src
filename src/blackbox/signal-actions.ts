/**
 * 信号→动作映射：把账本里已出现、但主 Agent 还没验证/结案的高价值信号，翻译成
 * 「本轮该打什么」的具体动作，注入主 Agent 上下文（context.signal_actions）。
 *
 * 目的：阻止 agent「只复述信号、不行动」——这正是会话里 H_idor / SOA2 网关被漏掉的根因。
 * 信号分三类：
 *   ① waf_suspected     —— WAF 拦截页（envoy waf / 访问被拒绝），本身是攻击面，必须踩阶梯或复刻战例；
 *   ② authwall          —— 连续 401/403 / 未登录，需要凭证或走未授权放行通道，反复重试同前缀无效；
 *   ③ soa2_exception_echo —— 网关匿名可达且回显内部异常类名 + 追踪 ID（NotFoundRouteException / rootMessageId / statusMsg），
 *                           是高价值信息泄露 / 路由探测入口，必须把网关当新攻击面，抠真实 appid 做分层对照。
 */

export type SignalAction = {
  signal: string;
  evidence_ids: string[];
  action: string;
  why: string;
};

type Marker = { signal: string; re: RegExp; action: string; why: string };

const MARKERS: Marker[] = [
  {
    signal: "waf_suspected",
    re: /waf[-_ ]?suspected|waf-block|blocked by (?:envoy )?waf|security[-_ ]?fs|访问被拒绝|access denied|cloudflare|akamai/i,
    action: "对命中路径先复刻 context.waf_ledger 战例（同厂商/同拦截指纹），baseline 与复刻变体各取一份 http.diff；未命中战例再跑 waf_bypass 阶梯，每档留 baseline/hit 对照。",
    why: "WAF 拦截页本身是攻击面，不是『打不动』；必须踩满阶梯或拿到 baseline/hit 对照才允许结案。",
  },
  {
    signal: "authwall",
    re: /authwall|连续 (?:401|403)|未登录|token 失效|1040[13]|login required|unauthorized/i,
    action: "走 auth_token 链取凭证，或用 unauth_exposure / bypass_auth_wall:true 打敏感路径字典；被拦的同前缀不要换 URL 重试。",
    why: "鉴权墙需要凭证或走未授权放行通道，反复重试同前缀是无效动作。",
  },
  {
    signal: "soa2_exception_echo",
    re: /NotFoundRouteException|rootMessageId|statusMsg|StackTrace|Exception\b|traceId|rootCause|internal server error/i,
    action: "网关匿名可达且回显内部异常类/追踪ID：把它当新攻击面。从已取回的 sw.js / hotels 页抠真实 appid 路径，对真实 appid 做 SOA2 分层对照（无 appid / 真实 appid+空 body / 真实 appid+JSON body），用三态差异判断哪些接口匿名可达、哪些走鉴权。",
    why: "404 信封证明 /restapi/soa2/ 是真实路由分发栈且匿名可达，异常回显泄露内部异常类名与请求追踪ID，是高价值信息泄露 / 路由探测入口，必须跟进而非置之不理。",
  },
];

/**
 * 从（最近的）证据账本里抽取未闭环的高价值信号动作。
 * 只扫最近 80 条，避免大账本下每轮全量扫描。
 */
export function signalActions(_state: unknown, evidence: Record<string, unknown>[]): SignalAction[] {
  const recent = (evidence || []).slice(-80);
  const out: SignalAction[] = [];
  for (const m of MARKERS) {
    const hits: string[] = [];
    for (const e of recent) {
      const id = String(e.id || "");
      if (!id || hits.includes(id)) continue;
      const data = e.data && typeof e.data === "object" ? JSON.stringify(e.data).slice(0, 2000) : "";
      const blob = `${String(e.summary || "")} ${data}`;
      if (m.re.test(blob)) hits.push(id);
    }
    if (hits.length) out.push({ signal: m.signal, evidence_ids: hits.slice(0, 6), action: m.action, why: m.why });
  }
  return out;
}

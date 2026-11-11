import { useEffect, useMemo, useState } from "react";
import { Alert, Button, Input, Tag } from "antd";
import { api } from "../api";
import { useDesk } from "../store";
import { Flash } from "../components/Flash";

type RulesDocument = { version: number; budgets: Record<string, number>; tool_weights: Record<string, number>; loop_control: Record<string, number>; request: { methods: string[]; max_redirects: number; max_timeout_ms: number; max_body_bytes: number; max_request_body_bytes: number; max_output_bytes: number }; auth_wall: { streak_limit: number; codes: string[]; safe_paths: string[]; allow_unauth_playbook: boolean; allow_bypass: boolean }; tools: Record<string, { allow_credential_attack?: unknown; allow_active_scan?: unknown }>; evidence: Record<string, boolean>; report: Record<string, boolean>; text: Record<string, string> };
const DEFAULT_RULES: RulesDocument = {
  version: 1, budgets: { time_sec: 900, wall_clock_sec: 1800, tool_calls: 120, agent_turns: 24, tokens: 0, cost: 0, retries: 5 },
  tool_weights: { "http.request": 1, "http.diff": 1, "browser.open": 2, "recon.subdomains": 2, "recon.nuclei": 5, "recon.sql": 5, "katana.crawl": 5, "burp.scan": 3 },
  loop_control: { task_retry_limit: 2, repeat_limit: 2, stall_batch_limit: 3, stage_timeout_sec: 600 },
  request: { methods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
 max_redirects: 5, max_timeout_ms: 60000, max_body_bytes: 262144, max_request_body_bytes: 5242880, max_output_bytes: 2097152 },
  auth_wall: { streak_limit: 3, codes: ["10403", "10401", "10402", "401"], safe_paths: [".env", ".git/", "/swagger", "/v3/api-docs", "/actuator", "/druid", "/nacos", "/graphql"], allow_unauth_playbook: true, allow_bypass: true },
  tools: { "recon.ports": {}, "recon.content_discovery": {}, "recon.nuclei": {}, "recon.interactsh": {}, "recon.parameters": {}, "recon.js_endpoints": {}, "recon.tls": {}, "recon.api_routes": {}, "recon.xss": {}, "recon.sql": {}, "recon.jwt": {}, "recon.graphql": {}, "recon.cms": {}, "recon.secrets": {}, "recon.sast": {}, "burp.scan": { allow_active_scan: true } },
  evidence: { require_ids: true, save_raw_results: true }, report: { require_task_outcomes: true, distinguish_incomplete: true },
  text: { "任务与预算": "按资产规模拆分任务；持续执行直到必需任务完成、预算耗尽或安全停止。", "任务状态与恢复": "任务必须有领取、执行、完成、失败或受阻状态；每批保存检查点。", "重复与停滞": "相同目标和参数且没有新信息的动作不得无限重试。", "授权与请求": "只处理授权目标；按任务需要使用各种 HTTP 方法，状态变更动作先评估影响。", "证据与发现": "发现必须引用成功工具结果和证据 ID。", "主 Agent 与 Observer": "主 Agent 推进任务；Observer 只读检查并提出建议。", "工具与审批": "所有已注册工具都可直接调用，没有逐动作人工审批；工具没有整体启停开关；只有凭据爆破等高风险能力默认关闭。", "验收与报告": "报告区分已完成、失败、受阻和未执行。", "JSON 输出协议": "输出必须符合主 Agent / Observer 的 JSON 协议。" },
};
const pretty = (value: unknown) => JSON.stringify(value, null, 2);
const FIELD_GUIDE: Array<[string, string, string]> = [
  ["version", "规则版本", "每次规则结构或含义发生变化时递增。会话启动时会记录版本和 hash，便于复盘。"],
  ["budgets.time_sec", "调度预算（秒）", "单个黑盒会话里 **Agent 思考与调度** 的上限；工具执行耗时不计入（跑 300 秒的 nuclei 不会吃掉思考预算）。0 表示不单独限制。"],
  ["budgets.wall_clock_sec", "墙钟上限（秒）", "整次 run 的真实耗时的硬上限，含工具执行；防的是卡死的模型调用或慢工具把容器挂住。默认 1800。到点以 wall_clock_exhausted 停止。"],
  ["budgets.tool_calls", "工具调用预算（权重）", "按权重累计：http.request/http.diff=1，browser.open=2，扫描类=3，nuclei/sqlmap/katana=5。一条 katana 顶 5 条普通请求，逼 Agent 把预算花在能出结论的动作上。0 表示不单独限制。"],
  ["tool_weights", "工具权重表", "覆盖具体工具的权重，例如 {\"recon.nuclei\": 5}。未列出的工具按 1 计。数值越大越「贵」，装批时会先被挤出。"],
  ["budgets.agent_turns", "Agent 回合预算", "主 Agent 规划回合数量上限；0 表示不单独限制。"],
  ["budgets.tokens / cost", "Token / 费用预算", "按模型返回的用量或费用累计；0 表示不单独限制。"],
  ["budgets.retries", "全局重试预算", "所有失败重试的总上限；调高可提高恢复能力，也会增加运行时间和成本。"],
  ["loop_control.task_retry_limit", "单任务重试上限", "同一任务失败后的最多重试次数，防止单点故障拖住会话。"],
  ["loop_control.repeat_limit", "重复动作上限", "相同工具、目标、参数和目的且没有新信息时的重复次数；不是禁止同一工具检查不同端点。"],
  ["loop_control.stall_batch_limit", "无进展批数", "连续没有新证据、状态变化或有效结论的批次数；超过后进入停滞终态。"],
  ["loop_control.stage_timeout_sec", "阶段超时（秒）", "单个工具批次允许运行的总时间（默认 600）。单个工具另有最低时长要求：批次剩余时间不足时该工具不启动，而是标为 deferred 留到下一批；工具超时只丢结果、不计重试。"],
  ["request.methods", "允许 HTTP 方法", "允许工具发出的 HTTP 方法列表，默认 GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE；删除某项会阻止该方法。"],
  ["request.max_redirects", "最大重定向次数", "单次请求允许跟随的重定向数量，超过后失败。"],
  ["request.max_timeout_ms", "最大请求超时（毫秒）", "工具请求可申请的超时上限，防止 Agent 通过参数无限等待。"],
  ["request.max_body_bytes / max_request_body_bytes", "响应体 / 请求体上限", "限制写入证据库的响应体大小，以及 json/form/body/multipart 请求体大小。"],
  ["request.max_output_bytes", "工具输出上限", "限制外部工具写入证据库的单次输出大小。"],
  ["tools.<tool>.allow_credential_attack", "凭据爆破开关", "默认关闭。设为 true 后该工具才允许 --passwords/--usernames，且密码表必须位于批准字典目录（NIANYUN_WORDLIST_ROOT）；仍在 tool-rejected 之外单独校验，越界路径会被拒绝。所有工具本身始终可用，没有整体启停开关。"],
  ["tools.<tool>.allow_active_scan", "主动扫描开关", "默认关闭，仅对 burp.scan 生效：设为 true 后允许主动扫描（会发送攻击载荷）；被动审核不需要该开关。开启前确认目标在授权范围内。"],
  ["auth_wall.streak_limit / codes", "鉴权墙判定", "同一主机连续多少个不同入口返回同样鉴权码（codes）就判墙；判墙后同前缀的无凭证请求会被拦成 auth_wall_requires_token。"],
  ["auth_wall.safe_paths", "墙内放行的敏感路径", "子串匹配。命中即放行：.env/.git/swagger/actuator/druid/nacos/graphql 这些正是「未授权访问」该验的东西，墙不该挡。置空 [] 表示完全关闭这条通道。"],
  ["auth_wall.allow_unauth_playbook", "墙内放行未授权打法", "true 时绑定 unauth_exposure / jwt_auth 打法的任务不受墙限制；关掉会让墙连正路一起堵死。"],
  ["auth_wall.allow_bypass", "允许显式 bypass", "true 时 Agent 可用 input.bypass_auth_wall=true 声明「这是未授权验证」，墙放行并记录一次 bypass。关闭后该字段被忽略。"],
  ["evidence.require_ids / save_raw_results", "证据规则", "要求结论引用证据 ID，以及是否保存原始工具结果。"],
  ["report.require_task_outcomes / distinguish_incomplete", "报告规则", "要求任务有结果说明，并明确区分完成、失败、受阻和未执行。"],
  ["text.<主题>", "规则主题文本", "提供给 Agent 的推理指导。修改后影响主 Agent/Observer 的决策说明，但不替代上面的程序化执行约束。"],
];

export function RulesPage() {
  const { llm, flash, setFlash, loadSettings } = useDesk();
  const [document, setDocument] = useState(pretty(DEFAULT_RULES)); const [main, setMain] = useState(""); const [observer, setObserver] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  // The rules route can be opened directly, without Home or Settings loading the LLM snapshot first.
  useEffect(() => { void loadSettings(); }, [loadSettings]);
  useEffect(() => { const group = (llm.blackbox || {}) as Record<string, { value?: string }>; const raw = group.BLACKBOX_RULES_DOCUMENT?.value; try { setDocument(raw ? pretty(JSON.parse(raw)) : pretty(DEFAULT_RULES)); setError(""); } catch { setDocument(raw || pretty(DEFAULT_RULES)); setError("当前规则文档不是有效 JSON，请修复后再保存。"); } setMain(group.BLACKBOX_RUNTIME_RULES?.value || ""); setObserver(group.BLACKBOX_OBSERVER_RUNTIME_RULES?.value || ""); }, [llm]);
  const parsed = useMemo(() => { try { return JSON.parse(document) as RulesDocument; } catch { return null; } }, [document]);
  async function save() { if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) { setError("规则文档必须是 JSON 对象。"); return; } setBusy(true); try { const rec = await api<{ ok?: boolean; error?: string }>("/api/settings", { method: "POST", body: JSON.stringify({ llm: { BLACKBOX_RULES_DOCUMENT: JSON.stringify(parsed), BLACKBOX_RUNTIME_RULES: main, BLACKBOX_OBSERVER_RUNTIME_RULES: observer } }) }); setFlash("rules", rec.ok ? "规则文档已保存，新建或恢复的会话将使用新版本" : rec.error || "保存失败", rec.ok ? "ok" : "bad"); if (rec.ok) await loadSettings(); } catch (cause) { setFlash("rules", String(cause), "bad"); } finally { setBusy(false); } }
  const credentialTools = useMemo(() => {
    if (!parsed || typeof parsed.tools !== "object" || !parsed.tools) return [];
    return Object.entries(parsed.tools).filter(([, policy]) => policy && typeof policy === "object" && (policy as { allow_credential_attack?: unknown }).allow_credential_attack === true).map(([name]) => name);
  }, [parsed]);
  return <section className="page rules-page"><Flash id="rules" flash={flash} /><section className="rules-hero"><div><span className="rules-eyebrow">SYSTEM / AGENT CONTROL</span><h1>规则中心</h1><p>这里编辑的是调度器、工具执行器、主 Agent 和 Observer 共同读取的真实规则文档，不是只展示给前端的说明文本。</p></div><div className="rules-stats"><div><strong>{parsed ? "OK" : "!"}</strong><span>JSON 状态</span></div><div><strong>{Object.keys(parsed?.text || {}).length}</strong><span>规则主题</span></div><div><strong>{Object.keys(parsed?.tools || {}).length}</strong><span>工具规则</span></div><div><strong>{credentialTools.length}</strong><span>凭据爆破开启</span></div></div></section>
    <section className="sheet rules-editor"><header className="sheet-head"><div><span className="rules-eyebrow">AUTHORITATIVE DOCUMENT</span><h2>结构化执行规则</h2><p className="sheet-lede">可直接编辑完整 JSON：预算、循环控制、请求约束、逐工具风险开关、证据、报告和规则文本都在这里。</p></div><Tag color={parsed ? "green" : "red"}>{parsed ? "可保存" : "JSON 无效"}</Tag>{credentialTools.length ? <Tag color="volcano">凭据爆破：{credentialTools.join("、")}</Tag> : null}</header>{error && <Alert type="error" showIcon message={error} />}{!error && credentialTools.length ? <Alert type="warning" showIcon message={`这些工具已开启凭据爆破：${credentialTools.join("、")}`} description="允许 --passwords/--usernames；密码表必须位于批准字典目录内。请确认目标授权范围内允许口令测试，并注意账号锁定与流量影响。" /> : null}<Input.TextArea className="rules-json-editor" value={document} onChange={(event) => { setDocument(event.target.value); setError(""); }} autoSize={{ minRows: 24, maxRows: 42 }} spellCheck={false} /><div className="sheet-foot"><Button onClick={() => setDocument(pretty(DEFAULT_RULES))}>恢复默认文档</Button><Button type="primary" loading={busy} disabled={!parsed} onClick={() => void save()}>保存真实规则</Button></div></section>
    <section className="sheet rules-guide"><header className="sheet-head"><div><span className="rules-eyebrow">FIELD REFERENCE</span><h2>JSON 字段说明</h2><p className="sheet-lede">修改值前先看这里：每个字段的作用、修改影响和 0 值语义都集中说明。</p></div></header><div className="rules-guide-list">{FIELD_GUIDE.map(([path, name, meaning]) => <article className="rules-guide-row" key={path}><code>{path}</code><strong>{name}</strong><p>{meaning}</p></article>)}</div></section>
    <section className="sheet rules-editor"><div className="subsheet"><header className="subsheet-head"><span className="rules-eyebrow">AGENT PREFERENCES</span><h2>Agent 补充规则</h2><p>保留现有 Prompt 配置入口；它们只表达偏好，不覆盖上面的结构化执行规则。</p></header><div className="field"><label htmlFor="rules-main">主 Agent 补充规则</label><Input.TextArea id="rules-main" value={main} rows={6} onChange={(event) => setMain(event.target.value)} /></div><div className="field"><label htmlFor="rules-observer">Observer 补充规则</label><Input.TextArea id="rules-observer" value={observer} rows={6} onChange={(event) => setObserver(event.target.value)} /></div><div className="sheet-foot"><Button type="primary" loading={busy} disabled={!parsed} onClick={() => void save()}>保存全部规则</Button></div></div></section>
  </section>;
}

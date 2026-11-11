import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Row, Space, Statistic, Tag, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { api } from "../api";

type Tool = { id: string; name: string; purpose: string; family: string; agent: string; built_in: boolean; configured: boolean; status: string; risk?: string };
type Agent = { id: string; name: string; purpose: string; status: string; tools: string[] };
type Session = { id: string; project_name: string; target: string; status: string; phase?: string; updated_at: number; used_tools?: string[] };
type RulesState = { version: number; hash: string; credential_tools: string[]; issues: string[]; valid: boolean; fallback: boolean };
type ToolPayload = { ok?: boolean; rules?: RulesState; tools?: Tool[]; agents?: Agent[]; sessions?: Session[]; error?: string };

const statusText: Record<string, string> = { ready: "就绪", available: "可用", running: "运行中", unconfigured: "未配置", idle: "空闲" };
const statusColor: Record<string, string> = { ready: "green", available: "blue", running: "processing", unconfigured: "red", idle: "default" };

export function ToolsPage() {
  const [data, setData] = useState<ToolPayload>({});
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await api<ToolPayload>("/api/tools")); } finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { const timer = window.setInterval(() => void load(), 5000); return () => window.clearInterval(timer); }, [load]);

  const tools = data.tools || [];
  const agents = data.agents || [];
  const sessions = data.sessions || [];
  const configured = tools.filter((tool) => tool.configured).length;
  const rules = data.rules;
  const credentialTools = rules?.credential_tools?.length ? rules.credential_tools : [];
  const running = sessions.filter((session) => session.status === "running").length;
  const toolGroups = useMemo(() => ({
    browser: "浏览器",
    proxy: "代理流量",
    http: "HTTP",
    evidence: "证据",
    exec: "沙箱执行",
    fs: "沙箱文件",
    katana: "爬虫",
    recon: "资产发现",
    burp: "Burp",
  }), []);

  return <main className="page tools-page">
    <div className="page-head">
      <div><p className="kicker">SYSTEM TOOLING</p><Typography.Title level={1}>工具导航</Typography.Title><p className="page-lede">黑盒会话当前可用的 {tools.length} 个工具（由 tool manifest 生成）、用途、配置状态与 Agent 使用关系。</p></div>
      <Space><Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>刷新状态</Button><Button href="#/route">挖掘路线</Button><Button href="#/health">工具健康度</Button></Space>
    </div>
    {data.error && <Alert type="error" showIcon message={data.error} />}
    {rules?.fallback && <Alert type="error" showIcon message="规则文档无法解析，当前已回退到默认规则：所有工具可用、默认预算生效。" description={rules.issues.join(" ")} />}
    {!rules?.fallback && rules?.issues?.length ? <Alert type="warning" showIcon message="规则文档有被忽略的配置项" description={rules.issues.join(" ")} /> : null}
    {credentialTools.length ? <Alert type="warning" showIcon message={`已开启凭据爆破：${credentialTools.join("、")}`} description="凭据爆破属于高影响能力，请确认目标在授权范围内并留意账号锁定风险。" /> : null}
    <Row gutter={[12, 12]} className="tools-metrics">
      <Col xs={12} md={6}><Card><Statistic title="工具总数" value={tools.length} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="已配置" value={configured} suffix={`/ ${tools.length}`} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="凭据爆破开启" value={credentialTools.length} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="运行中会话" value={running} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="Agent" value={agents.length} /></Card></Col>
    </Row>
    <Card title="Agent 与工具关系" className="tools-section">
      <div className="agent-tool-list">{agents.map((agent) => <div className="agent-tool-row" key={agent.id}><div><div className="tool-title"><strong>{agent.name}</strong><Tag color={statusColor[agent.status] || "default"}>{statusText[agent.status] || agent.status}</Tag></div><p>{agent.purpose}</p></div><div className="tool-chip-list">{agent.tools.length ? agent.tools.map((tool) => <code key={tool}>{tool}</code>) : <span className="help">只读监督，不直接调用执行工具</span>}</div></div>)}</div>
    </Card>
    <Card title="黑盒会话工具状态" className="tools-section">
      <div className="tool-navigation-grid">{tools.map((tool) => <div className={`tool-navigation-card ${tool.configured ? "ready" : "missing"}`} key={tool.id}><div className="tool-card-head"><span className={`status-dot ${tool.configured ? "online" : "offline"}`}>●</span><strong>{tool.name}</strong><Tag color={statusColor[tool.status] || "default"}>{statusText[tool.status] || tool.status}</Tag></div><span className="tool-family">{toolGroups[tool.family as keyof typeof toolGroups] || tool.family} · {tool.agent === "main" ? "主 Agent" : tool.agent}</span><p>{tool.purpose}</p><div className="tool-card-tags"><Tag color={tool.risk === "medium" ? "orange" : "green"}>{tool.risk === "medium" ? "中风险" : "低风险"}</Tag><Tag color="green">直接调用</Tag></div><span className="help">{tool.configured ? (tool.built_in ? "内置能力，受会话授权和资源限制约束" : "已检测到配置，主 Agent 可直接调用") : "缺少配置，当前不可用"}</span></div>)}</div>
    </Card>
    <Card title={<div className="card-title-row"><span>会话状态</span><span className="section-note">自动刷新</span></div>} className="tools-section">
      {!sessions.length ? <p className="empty-hint">暂无黑盒会话。</p> : <div className="tool-session-list">{sessions.map((session) => <div className="tool-session-row" key={`${session.project_name}:${session.id}`}><div><strong>{session.target}</strong><span>{session.project_name} · {session.phase || "等待"}</span>{session.used_tools?.length ? <div className="tool-chip-list">{session.used_tools.map((tool) => <code key={tool}>{tool}</code>)}</div> : <span className="help">尚未产生工具结果</span>}</div><Tag color={session.status === "running" ? "processing" : session.status === "completed" ? "green" : "default"}>{session.status}</Tag></div>)}</div>}
    </Card>
  </main>;
}
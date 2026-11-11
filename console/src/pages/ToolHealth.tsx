import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Input, Progress, Row, Segmented, Select, Statistic, Table, Tag, Tooltip, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import type { TableProps } from "antd";
import { api } from "../api";
import { useDesk } from "../store";
import type { ToolHealthPayload, ToolHealthRow, ToolHealthState } from "../types";

const STATE_META: Record<ToolHealthState, { text: string; color: string; rank: number }> = {
  failing: { text: "异常", color: "red", rank: 0 },
  degraded: { text: "不稳定", color: "orange", rank: 1 },
  unconfigured: { text: "未配置", color: "volcano", rank: 2 },
  healthy: { text: "正常", color: "green", rank: 3 },
  idle: { text: "未使用", color: "default", rank: 4 },
};

const WINDOWS = [
  { label: "24 小时", value: "24h" },
  { label: "7 天", value: "7d" },
  { label: "30 天", value: "30d" },
  { label: "全部", value: "all" },
];

function duration(ms: number): string {
  if (!ms) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60000).toFixed(1)} min`;
}

function when(seconds: number | null): string {
  if (!seconds) return "—";
  const delta = Math.max(0, Math.round(Date.now() / 1000 - seconds));
  if (delta < 60) return "刚刚";
  if (delta < 3600) return `${Math.round(delta / 60)} 分钟前`;
  if (delta < 86400) return `${Math.round(delta / 3600)} 小时前`;
  return `${Math.round(delta / 86400)} 天前`;
}

export function ToolHealthPage() {
  const { projects } = useDesk();
  const [data, setData] = useState<ToolHealthPayload>({});
  const [range, setRange] = useState("7d");
  const [project, setProject] = useState("");
  const [state, setState] = useState<"all" | ToolHealthState>("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ window: range });
      if (project) params.set("project", project);
      setData(await api<ToolHealthPayload>(`/api/tool-health?${params.toString()}`));
    } finally {
      setLoading(false);
    }
  }, [range, project]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { const timer = window.setInterval(() => void load(), 30000); return () => window.clearInterval(timer); }, [load]);

  const rows = data.tools || [];
  const totals = data.totals;
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rows.filter((row) => (state === "all" || row.state === state)
      && (!needle || row.tool.toLowerCase().includes(needle) || row.name.toLowerCase().includes(needle) || row.family.toLowerCase().includes(needle)));
  }, [rows, state, query]);
  const problemCount = rows.filter((row) => row.state === "failing" || row.state === "degraded").length;

  const columns: TableProps<ToolHealthRow>["columns"] = [
    {
      title: "工具", dataIndex: "tool", key: "tool", width: 240,
      render: (_value, row) => <div className="health-tool"><strong>{row.name}</strong><code>{row.tool}</code><span>{row.family}</span></div>,
    },
    {
      title: "状态", dataIndex: "state", key: "state", width: 100,
      render: (value: ToolHealthState) => <Tag color={STATE_META[value].color}>{STATE_META[value].text}</Tag>,
    },
    { title: "执行", dataIndex: "executions", key: "executions", width: 74, align: "right" },
    { title: "成功", dataIndex: "successes", key: "successes", width: 74, align: "right" },
    { title: "失败", dataIndex: "failures", key: "failures", width: 74, align: "right", render: (value: number) => <span className={value ? "health-bad" : undefined}>{value}</span> },
    { title: "超时", dataIndex: "timeouts", key: "timeouts", width: 74, align: "right", render: (value: number) => <span className={value ? "health-warn" : undefined}>{value}</span> },
    { title: "拒绝", dataIndex: "rejections", key: "rejections", width: 74, align: "right" },
    {
      title: "成功率", dataIndex: "success_rate", key: "success_rate", width: 150,
      render: (value: number, row) => row.executions
        ? <Progress percent={value} size="small" status={value < 50 ? "exception" : value < 80 ? "active" : "success"} format={(percent) => `${percent}%`} />
        : <span className="help">无执行</span>,
    },
    { title: "平均耗时", dataIndex: "avg_ms", key: "avg_ms", width: 110, align: "right", render: (value: number) => duration(value) },
    {
      title: "P95", dataIndex: "p95_ms", key: "p95_ms", width: 110, align: "right",
      render: (value: number, row) => <Tooltip title={`基于 ${row.executions} 次执行（含超时）`}>{duration(value)}</Tooltip>,
    },
    { title: "会话", dataIndex: "sessions", key: "sessions", width: 74, align: "right" },
    { title: "最近使用", dataIndex: "last_used_at", key: "last_used_at", width: 120, render: (value: number | null) => when(value) },
    {
      title: "最近错误", dataIndex: "last_error", key: "last_error", ellipsis: true,
      render: (value: string | null) => value ? <Tooltip title={value}><span className="health-error">{value}</span></Tooltip> : <span className="help">—</span>,
    },
  ];

  return <main className="page tools-page health-page">
    <div className="page-head">
      <div>
        <p className="kicker">TOOL HEALTH</p>
        <Typography.Title level={1}>工具健康度</Typography.Title>
        <p className="page-lede">按证据账本聚合每个工具的执行次数、成功率、超时与拒绝情况。数据来自真实的 tool-result / tool-error，可切换时间窗口和项目。</p>
      </div>
      <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>刷新</Button>
    </div>

    {data.error && <Alert type="error" showIcon message={data.error} />}
    {problemCount > 0 && <Alert type="warning" showIcon message={`${problemCount} 个工具近期成功率偏低`} description="成功率按「成功 / (成功 + 失败 + 超时)」计算，被规则或配置拒绝的请求不计入分母。" />}

    <div className="health-filters">
      <Segmented options={WINDOWS} value={range} onChange={(value) => setRange(String(value))} />
      <Select
        allowClear
        placeholder="全部项目"
        style={{ minWidth: 220 }}
        value={project || undefined}
        onChange={(value) => setProject(value || "")}
        options={projects.map((item) => ({ label: item.name, value: item.id }))}
      />
      <Segmented
        value={state}
        onChange={(value) => setState(value as "all" | ToolHealthState)}
        options={[{ label: "全部", value: "all" }, ...(["failing", "degraded", "healthy", "unconfigured", "idle"] as ToolHealthState[]).map((value) => ({ label: STATE_META[value].text, value }))]}
      />
      <Input.Search allowClear placeholder="搜索工具或用途分类" style={{ maxWidth: 260 }} value={query} onChange={(event) => setQuery(event.target.value)} />
    </div>

    <Row gutter={[12, 12]} className="tools-metrics">
      <Col xs={12} md={6}><Card><Statistic title="执行总数" value={totals?.executions ?? 0} suffix={`/ ${totals?.tools ?? 0} 个工具`} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="整体成功率" value={totals?.success_rate ?? 0} precision={1} suffix="%" valueStyle={(totals?.success_rate ?? 0) < 80 && (totals?.executions ?? 0) > 0 ? { color: "#cf1322" } : undefined} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="超时 / 失败" value={`${totals?.timeouts ?? 0} / ${totals?.failures ?? 0}`}></Statistic></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="被拒绝" value={totals?.rejections ?? 0} valueStyle={{ color: "#8c8c8c" }} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="平均耗时" value={duration(totals?.avg_ms ?? 0)} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="覆盖会话" value={totals?.sessions ?? 0} suffix={`/ ${totals?.projects ?? 0} 个项目`} /></Card></Col>
    </Row>

    <Card title={<div className="card-title-row"><span>各工具明细</span><span className="section-note">{visible.length} / {rows.length} 个工具 · 每 30 秒刷新</span></div>} className="tools-section">
      {!rows.length && <p className="empty-hint">暂无工具执行记录。发起一次黑盒会话后，这里会按证据账本生成统计。</p>}
      {rows.length > 0 && <Table<ToolHealthRow>
        rowKey="tool"
        size="small"
        loading={loading}
        columns={columns}
        dataSource={[...visible].sort((a, b) => STATE_META[a.state].rank - STATE_META[b.state].rank || b.executions - a.executions || a.tool.localeCompare(b.tool))}
        pagination={{ pageSize: 20, hideOnSinglePage: true, showSizeChanger: false }}
        scroll={{ x: 1180 }}
      />}
    </Card>

    <Card title="口径说明" className="tools-section">
      <ul className="health-notes">
        <li><strong>执行</strong>：成功 + 失败 + 超时。未配置、高风险能力未开启或参数被拒绝的请求不计入执行，也不扣工具调用预算。</li>
        <li><strong>成功</strong>：工具正常退出且返回 ok。部分工具的非零退出码按各自语义视为成功。</li>
        <li><strong>超时</strong>：到达阶段或工具截止时间被杀，保留部分结果，不计入重试。</li>
        <li><strong>成功率</strong>：成功 ÷ 执行。样本少于 2 次时不判定异常，状态显示为「正常」或「未使用」。</li>
        <li><strong>P95</strong>：第 95 百分位耗时，包含超时样本，用于识别拖慢阶段的工具。</li>
      </ul>
    </Card>
  </main>;
}
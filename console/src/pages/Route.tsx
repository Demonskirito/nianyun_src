import { useCallback, useEffect, useState } from "react";
import { Alert, Button, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { api } from "../api";

type RouteStep = { id: string; title: string; detail: string };
type RouteSignal = { code: string; trigger: string; action: string };
type Radio = {
  queues: string[]; legacy_queues?: string[]; modes?: string[]; max_per_call: number;
  whitelist: string[]; enrichment?: string; bundled_cli_redirects: Record<string, string>;
};
type Playbook = {
  id: string; title: string; priority: number; when: string[]; steps: number;
  timebox_sec?: number; layers: Record<string, number>;
  confirm?: { evidence: string[]; must_show: string } | null;
};
type Routing = {
  version: number; steps: RouteStep[]; antipatterns: string; signals: RouteSignal[];
  radio: Radio; race: { tool: string; via: string; max_requests: number }; playbooks?: Playbook[];
};
type Payload = { routing?: Routing; error?: string };

const layerTag: Record<string, { label: string; color: string; hint: string }> = {
  T: { label: "T", color: "blue", hint: "tactical：控制面出口（经 Burp）" },
  S: { label: "S", color: "purple", hint: "strategic：沙箱容器内执行" },
  R: { label: "R", color: "gold", hint: "tactical_rpc：沙箱排队、控制面齐发" },
};

/** 分层挖掘路线：从工具导航里拆出来的一页。 */
export function RoutePage() {
  const [data, setData] = useState<Payload>({});
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await api<Payload>("/api/tools")); } finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const routing = data.routing;
  const playbooks = routing?.playbooks || [];
  const stepCount = playbooks.reduce((sum, book) => sum + book.steps, 0);

  return <main className="page route-page">
    <div className="page-head">
      <div>
        <p className="kicker">EXPLOITATION ROUTE</p>
        <Typography.Title level={1}>挖掘路线</Typography.Title>
        <p className="page-lede">Agent 的执行顺序、打法库分层、反模式与电台协议。这一页与 system prompt 同源，改代码就变，不靠手抄。</p>
      </div>
      <Space>
        <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>刷新</Button>
        <Button href="#/tools">工具导航</Button>
      </Space>
    </div>

    {data.error && <Alert type="error" showIcon message={data.error} />}

    <Row gutter={[12, 12]} className="tools-metrics">
      <Col xs={12} md={6}><Card><Statistic title="路线版本" value={routing?.version ?? "—"} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="执行步骤" value={routing?.steps.length ?? 0} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="打法库" value={playbooks.length} suffix={`/ ${stepCount} 步`} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="电台白名单" value={routing?.radio.whitelist.length ?? 0} /></Card></Col>
    </Row>

    {routing ? <Card title={<div className="card-title-row"><span>一轮到底发生什么</span><span className="section-note">v{routing.version} · 与 system prompt 同源</span></div>} className="tools-section">
      <div className="route-steps">{routing.steps.map((step) => <div className="route-step" key={step.id}><strong>{step.title}</strong><p>{step.detail}</p></div>)}</div>
    </Card> : null}

    <Card title={<div className="card-title-row"><span>打法库（按层标注）</span><span className="section-note">T 控制面 · S 沙箱 · R 电台齐发</span></div>} className="tools-section">
      {!playbooks.length ? <p className="empty-hint">未取到打法库。</p> : <Table<Playbook>
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={playbooks}
        expandable={{
          expandedRowRender: (book) => <div className="route-playbook-detail">
            <p><span className="help">适用条件</span> {book.when.length ? book.when.join("；") : "—"}</p>
            {book.confirm ? <p><span className="help">确认要求</span> {book.confirm.must_show}</p> : <p><span className="help">确认要求</span> <Tag color="red">缺失（永远无法 completed）</Tag></p>}
            {book.confirm?.evidence?.length ? <p><span className="help">证据项</span> {book.confirm.evidence.map((item) => <code key={item}>{item}</code>)}</p> : null}
          </div>,
        }}
        columns={[
          { title: "打法", dataIndex: "id", render: (_: string, book) => <span className="tool-title"><code>{book.id}</code><span className="help">{book.title}</span></span> },
          { title: "步数", dataIndex: "steps", width: 80, render: (value: number) => <span>{value}</span> },
          {
            title: "分层", dataIndex: "layers", width: 150, render: (layers: Record<string, number>) => <span className="route-layer-tags">
              {Object.entries(layers).filter(([, count]) => count > 0).map(([layer, count]) =>
                <Tag key={layer} color={layerTag[layer]?.color || "default"} title={layerTag[layer]?.hint}>{layerTag[layer]?.label || layer}×{count}</Tag>)}
            </span>,
          },
          {
            title: "确认门禁", dataIndex: "confirm", width: 120,
            render: (confirm: Playbook["confirm"]) => confirm?.must_show
              ? <Tag color="green">已定义</Tag>
              : <Tag color="red">缺失</Tag>,
          },
        ]}
      />}
    </Card>

    {routing ? <Card title="反模式（出现即换打法，不要硬撞）" className="tools-section">
      <Alert type="info" showIcon message="反模式" description={routing.antipatterns} />
    </Card> : null}

    {routing ? <Card title="Burp History 信号（burp.history 的 data.analysis.signals）" className="tools-section">
      <div className="route-signals">{routing.signals.map((signal) => <div className="route-signal" key={signal.code}><code>{signal.code}</code><span>{signal.trigger}</span><em>→ {signal.action}</em></div>)}</div>
    </Card> : null}

    {routing ? <Card title="电台与并发" className="tools-section">
      <div className="route-radio">
        <p><span className="help">队列</span> {routing.radio.queues.map((queue) => <code key={queue}>/state/{queue}</code>)} <span className="help">每次最多 {routing.radio.max_per_call} 条</span></p>
        <p><span className="help">模式</span> {(routing.radio.modes || ["standard", "concurrent"]).map((mode) => <code key={mode}>{mode}</code>)}</p>
        <p><span className="help">载荷</span> {routing.radio.enrichment || "脚本把算好的值直接写进 input，控制面原样透传"}</p>
        {routing.radio.legacy_queues?.length ? <p><span className="help">遗留队列（仍可读，会提示迁移）</span> {routing.radio.legacy_queues.map((queue) => <code key={queue}>/state/{queue}</code>)}</p> : null}
        <p><span className="help">竞态</span> <code>{routing.race.tool}</code> <span className="help">via={routing.race.via}，单次 ≤{routing.race.max_requests} 发；沙箱里排 dispatch.jsonl（mode=concurrent）</span></p>
        <p><span className="help">沙箱裸调这些 CLI 会被拒绝并重定向：</span> {Object.entries(routing.radio.bundled_cli_redirects).map(([cli, tool]) => <code key={cli}>{cli}→{tool}</code>)}</p>
        <p><span className="help">白名单（可走电台的工具）</span> {routing.radio.whitelist.map((tool) => <code key={tool}>{tool}</code>)}</p>
      </div>
    </Card> : null}
  </main>;
}
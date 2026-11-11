import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Popconfirm, Row, Space, Statistic, Table, Tag, Typography } from "antd";
import { ReloadOutlined, ThunderboltOutlined } from "@ant-design/icons";
import { api } from "../api";

type Victory = {
  id: string; vendor: string; vendor_name: string; family?: string; signature?: string;
  dimension: string; tactic: string; payload: string; host: string;
  project_id: string; session_id: string; evidence_id: string; source: string; note: string;
  hits: number; created_at: number; last_ok_at: number;
};
type VendorRow = { vendor: string; vendor_name: string; family: string; victories: number; hits: number; last_ok_at: number };
type Payload = {
  items?: Victory[]; vendors?: VendorRow[]; stats?: { total: number; vendors: number; hits: number; last_ok_at: number };
  dimension_labels?: Record<string, string>;
  known_vendors?: Array<{ id: string; name: string; family: string }>;
  error?: string;
};

const familyLabel: Record<string, { label: string; color: string }> = {
  domestic: { label: "国产硬件/软件 WAF", color: "volcano" },
  cloud: { label: "云 WAF", color: "geekblue" },
  international: { label: "国际 CDN/WAF", color: "purple" },
  self_built: { label: "自研云 WAF", color: "magenta" },
  unknown: { label: "未识别", color: "default" },
};

function when(seconds: number): string {
  if (!seconds) return "—";
  const date = new Date(seconds * 1000);
  const diff = Date.now() / 1000 - seconds;
  if (diff < 3600) return `${Math.max(1, Math.round(diff / 60))} 分钟前`;
  if (diff < 86400) return `${Math.round(diff / 3600)} 小时前`;
  return date.toLocaleString();
}

/**
 * WAF 战例库：agent 打穿过哪些墙、用的哪一档、留下什么变体。
 *
 * 这一页不是"战绩陈列"，而是 agent 的复用入口：
 * 库里第 1 条会被写进下一轮 prompt，命中同厂商/同签名的墙时先照抄，复刻失败才重新思考。
 * 所以每行都必须能追溯到证据（evidence_id），错的记录要能立刻删掉。
 */
export function WafLedgerPage() {
  const [data, setData] = useState<Payload>({});
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await api<Payload>("/api/waf-bypasses?limit=300")); } finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const items = data.items || [];
  const vendors = data.vendors || [];
  const labels = data.dimension_labels || {};
  const stats = data.stats;
  const known = useMemo(() => new Set((data.known_vendors || []).map(item => item.id)), [data.known_vendors]);

  const remove = async (id: string) => {
    await api(`/api/waf-bypasses/${encodeURIComponent(id)}`, { method: "DELETE" });
    void load();
  };

  return <main className="page waf-page">
    <div className="page-head">
      <div>
        <p className="kicker">WAF EVASION LEDGER</p>
        <Typography.Title level={1}>WAF 战例库</Typography.Title>
        <p className="page-lede">
          agent 每打穿一堵墙就记一条：哪家 WAF、走的哪一档、当时用的完整变体。
          下次遇到同厂商或同拦截指纹的墙，会先复刻这里的第 1 条，复刻失败才重新设计——所以记录越准，后面省下的回合越多。
        </p>
      </div>
      <Space>
        <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>刷新</Button>
        <Button href="#/route">挖掘路线</Button>
      </Space>
    </div>

    {data.error && <Alert type="error" showIcon message={data.error} />}

    <Row gutter={[12, 12]} className="tools-metrics">
      <Col xs={12} md={6}><Card><Statistic title="战例数" value={stats?.total ?? 0} prefix={<ThunderboltOutlined />} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="WAF 厂商" value={stats?.vendors ?? 0} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="累计打穿次数" value={stats?.hits ?? 0} /></Card></Col>
      <Col xs={12} md={6}><Card><Statistic title="最近一次成功" value={when(stats?.last_ok_at || 0)} /></Card></Col>
    </Row>

    <Card title={<div className="card-title-row"><span>已打穿的墙</span><span className="section-note">按累计命中排序 · 命中次数越多越靠前被复用</span></div>} className="tools-section">
      {!vendors.length ? <p className="empty-hint">还没有战例：agent 打穿一堵墙并在输出里回报 waf_bypasses（vendor/dimension/tactic/payload/evidence_id）后会自动入库。</p> : <Table<VendorRow>
        size="small"
        rowKey="vendor"
        pagination={false}
        dataSource={vendors}
        columns={[
          {
            title: "WAF", dataIndex: "vendor_name", render: (_: string, row) => <span className="tool-title">
              <code>{row.vendor}</code><span className="help">{row.vendor_name}</span>
              {!known.has(row.vendor) && <Tag color="orange">表外厂商</Tag>}
            </span>,
          },
          {
            title: "类型", dataIndex: "family", width: 170,
            render: (family: string) => <Tag color={familyLabel[family]?.color || "default"}>{familyLabel[family]?.label || family}</Tag>,
          },
          { title: "战例", dataIndex: "victories", width: 90 },
          { title: "命中", dataIndex: "hits", width: 90, render: (hits: number) => <strong>{hits}</strong> },
          { title: "最近成功", dataIndex: "last_ok_at", width: 140, render: (value: number) => when(value) },
        ]}
      />}
    </Card>

    <Card title={<div className="card-title-row"><span>变体明细（下次直接复刻的就是这些）</span><span className="section-note">{items.length} 条</span></div>} className="tools-section">
      {!items.length ? <p className="empty-hint">暂无明细。</p> : <Table<Victory>
        size="small"
        rowKey="id"
        pagination={{ pageSize: 20, hideOnSinglePage: true }}
        dataSource={items}
        expandable={{
          expandedRowRender: (row) => <div className="route-playbook-detail">
            <p><span className="help">完整变体</span></p>
            <pre className="waf-payload">{row.payload || "（未记录变体：只能记录档位，复刻时需重新构造）"}</pre>
            {row.note ? <p><span className="help">备注</span> {row.note}</p> : null}
            <p>
              <span className="help">宿主</span> <code>{row.host || "—"}</code>
              <span className="help"> 拦截指纹</span> <code>{row.signature || "—"}</code>
              <span className="help"> 证据</span> <code>{row.evidence_id || "—"}</code>
            </p>
            <p>
              <span className="help">来源</span> {row.source === "auto" ? <Tag color="gold">自动推断（仅档位）</Tag> : row.source === "operator" ? <Tag color="blue">人工录入</Tag> : <Tag color="green">模型回报</Tag>}
              <span className="help"> 会话</span> <code>{row.session_id || "—"}</code>
            </p>
          </div>,
        }}
        columns={[
          {
            title: "WAF", dataIndex: "vendor_name", width: 200,
            render: (_: string, row) => <span className="tool-title">
              <code>{row.vendor}</code><span className="help">{row.vendor_name}</span>
            </span>,
          },
          {
            title: "档位", dataIndex: "dimension", width: 120,
            render: (dimension: string) => <Tag color="blue">{labels[dimension] || dimension}</Tag>,
          },
          { title: "战术", dataIndex: "tactic", ellipsis: true },
          { title: "命中", dataIndex: "hits", width: 70, render: (hits: number) => <strong>{hits}</strong> },
          { title: "宿主", dataIndex: "host", width: 180, ellipsis: true },
          { title: "最近成功", dataIndex: "last_ok_at", width: 130, render: (value: number) => when(value) },
          {
            title: "", dataIndex: "id", width: 70,
            render: (id: string) => <Popconfirm title="删掉这条战例？" description="后续会话不会再复用它。" onConfirm={() => void remove(id)}>
              <Button size="small" danger type="text">删除</Button>
            </Popconfirm>,
          },
        ]}
      />}
    </Card>

    <Card title="怎么用（与 agent 的规则一致）" className="tools-section">
      <Alert
        type="info"
        showIcon
        message="先照抄，打不动才思考"
        description={<div className="route-radio">
          <p>① 命中同厂商或同拦截指纹 → 第一步复刻本库第 1 条变体（http.diff 与 baseline 对照一次），成功就带着这条变体进业务验证。</p>
          <p>② 复刻失败 → 换下一条；同一变体最多两次，不在已知无效的变体上打转。</p>
          <p>③ 战例全部失效 → 才按 waf_bypass 阶梯重新枚举（编码 → 参数 → 路径/方法/头 → 原始报文/分块 → 夹带）。</p>
          <p>④ 打穿后必须回报 waf_bypasses（vendor / dimension / tactic / payload / host / evidence_id），否则下次还得从零开始。</p>
        </div>}
      />
    </Card>
  </main>;
}
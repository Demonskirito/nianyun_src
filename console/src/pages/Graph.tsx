/**
 * 攻击历程图（`#/graph`）。
 *
 * 设计目标（按用户三个问题的顺序）：
 *   1. Agent 到底懂了没有 → 节点 id（归一化后）、身份节点、假设列表
 *   2. Agent 为什么卡住 → dead_end 灰掉、环路/停滞由 hypotheses 面板说、分量数
 *   3. 这个漏洞怎么复现 → Kill Chain 高亮 + Mermaid 复制
 *
 * 刻意没做的：大屏那种会自动旋转的力导向图。这里每一条连线都要能被指着念出来。
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Col, Empty, Input, Modal, Row, Segmented, Select, Space, Statistic, Table, Tag, Tooltip, Typography } from "antd";
import { ReloadOutlined, CopyOutlined, AimOutlined } from "@ant-design/icons";
import { CytoscapeGraph, type GraphHandle } from "./graph/CytoscapeGraph";
import { formatForCytoscape, killChainSelection, toMermaid, type GraphView } from "./graph/adapter";

const { Text, Paragraph } = Typography;

type SessionRow = { id: string; target?: string; status?: string; phase?: string; created_at?: number; updated_at?: number };

const STATUS_COLOR: Record<string, string> = {
  vulnerable: "red", dead_end: "default", blocked: "gold", testing: "cyan", untested: "blue",
};

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return (await response.json()) as T;
}

export function GraphPage(): JSX.Element {
  const [projects, setProjects] = useState<Array<{ id: string; name?: string }>>([]);
  const [projectId, setProjectId] = useState<string>("");
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [sessionId, setSessionId] = useState<string>("");
  const [view, setView] = useState<GraphView | null>(null);
  const [error, setError] = useState<string>("");
  const [mode, setMode] = useState<"all" | "rpc" | "dead">("all");
  const [chain, setChain] = useState<string>("");
  const [selected, setSelected] = useState<{ id: string; data: Record<string, unknown> } | null>(null);
  const [handle, setHandle] = useState<GraphHandle | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  // 布局：默认"历程"（横轴=第几轮）。dagre 只在想看拓扑时选。
  const [layoutMode, setLayoutMode] = useState<"journey" | "dagre">("journey");
  const [rebuilding, setRebuilding] = useState(false);
  const [rebuildNote, setRebuildNote] = useState<string>("");

  // 项目列表
  useEffect(() => {
    void getJson<{ items?: Array<{ id: string; name?: string }>; projects?: Array<{ id: string; name?: string }> }>("/api/projects")
      .then(data => {
        const list = data.items || data.projects || [];
        setProjects(list);
        if (list.length && !projectId) setProjectId(list[0]!.id);
      })
      .catch(cause => setError(String(cause)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 会话列表
  useEffect(() => {
    if (!projectId) return;
    void getJson<{ items?: SessionRow[]; sessions?: SessionRow[] }>(`/api/projects/${projectId}/blackbox-sessions?limit=100`)
      .then(data => {
        const list = data.items || data.sessions || [];
        setSessions(list);
        if (list.length && !list.some(item => item.id === sessionId)) setSessionId(list[0]!.id);
      })
      .catch(cause => setError(String(cause)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const load = useCallback(async () => {
    if (!projectId || !sessionId) return;
    try {
      const data = await getJson<GraphView>(`/api/projects/${projectId}/blackbox-sessions/${sessionId}/graph?max_nodes=400`);
      setView(data);
      setError("");
      if (data.kill_chains.length && !data.kill_chains.some(item => item.node === chain)) setChain(data.kill_chains[0]!.node);
    } catch (cause) {
      setError(String(cause));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, sessionId]);

  useEffect(() => { void load(); }, [load]);

  // 轮询：Agent 跑轮次，图是长出来的；5s 足够，比 SSE 简单且不吃连接
  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => { void load(); }, 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, load]);

  const filtered = useMemo<GraphView | null>(() => {
    if (!view) return null;
    if (mode === "dead") return { ...view, nodes: view.nodes.filter(node => node.status === "dead_end") };
    return view;
  }, [view, mode]);

  const elements = useMemo(() => (filtered ? formatForCytoscape(filtered, { rpcOnly: mode === "rpc" }) : []), [filtered, mode]);
  const highlight = useMemo(() => (view && chain ? killChainSelection(view, chain) : null), [view, chain]);

  const stats = view?.stats || {};
  const mermaid = view && chain ? toMermaid(view, { chain }) : "";

  return (
    <div className="graph-page">
      <Card size="small" className="graph-toolbar" style={{ marginBottom: 12 }}>
        <Space wrap>
          <Select
            style={{ minWidth: 200 }} placeholder="项目" value={projectId || undefined}
            onChange={value => { setProjectId(value); setView(null); }}
            options={projects.map(item => ({ value: item.id, label: item.name || item.id }))}
          />
          <Select
            style={{ minWidth: 320 }} placeholder="会话" value={sessionId || undefined}
            onChange={value => { setSessionId(value); setView(null); }}
            options={sessions.map(item => ({
              value: item.id,
              label: `${item.target || item.id} · ${item.status || "?"}${item.phase ? ` · ${item.phase}` : ""}`,
            }))}
          />
          <Segmented
            value={mode} onChange={value => setMode(value as typeof mode)}
            options={[{ label: "全局视图", value: "all" }, { label: "RPC 视图", value: "rpc" }, { label: "只看死胡同", value: "dead" }]}
          />
          <Select
            style={{ minWidth: 280 }} placeholder="Kill Chain" value={chain || undefined}
            onChange={value => setChain(value)}
            options={(view?.kill_chains || []).map(item => ({
              value: item.node, label: `${item.severity} · ${item.target}（${item.chain.length} 跳）`,
            }))}
          />
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>刷新</Button>
          <Button icon={<AimOutlined />} onClick={() => handle?.fit()}>适应画布</Button>
          <Button
            icon={<CopyOutlined />} disabled={!mermaid}
            onClick={() => void navigator.clipboard?.writeText(mermaid)}
          >复制 Mermaid</Button>
          <Segmented
            value={autoRefresh ? "on" : "off"} onChange={value => setAutoRefresh(value === "on")}
            options={[{ label: "实时刷新 5s", value: "on" }, { label: "暂停", value: "off" }]}
          />
        </Space>
      </Card>

      {error ? <Alert type="warning" showIcon message="图数据加载失败" description={error} style={{ marginBottom: 12 }} /> : null}

      <Row gutter={12}>
        <Col xs={24} xl={17}>
          <Card
            size="small"
            title="攻击历程图"
            extra={(
              <Space size={8}>
                <Segmented
                  size="small"
                  value={layoutMode}
                  onChange={value => setLayoutMode(value as "journey" | "dagre")}
                  options={[{ label: "历程（横轴=轮次）", value: "journey" }, { label: "拓扑（左→右）", value: "dagre" }]}
                />
                <Tooltip title="把账本里已发生的工具调用按时间重放进图（抽取规则修好之后，老会话需要这一步才能看到历程）">
                  <Button
                    size="small"
                    icon={<ReloadOutlined />}
                    loading={rebuilding}
                    onClick={async () => {
                      if (!projectId || !sessionId) return;
                      setRebuilding(true);
                      setRebuildNote("");
                      try {
                        const response = await fetch(`/api/projects/${projectId}/blackbox-sessions/${sessionId}/graph/rebuild`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
                        const result = (await response.json()) as { ok?: boolean; nodes?: number; edges?: number; max_depth?: number; ingested?: number; error?: string };
                        setRebuildNote(result.ok ? `回放 ${result.ingested ?? 0} 条结果 → ${result.nodes ?? 0} 节点 / ${result.edges ?? 0} 边 / 最深 ${result.max_depth ?? 1} 跳` : `重建失败：${result.error || response.status}`);
                        await load();
                      } catch (cause) {
                        setRebuildNote(`重建失败：${String(cause)}`);
                      } finally {
                        setRebuilding(false);
                      }
                    }}
                  >重建历程</Button>
                </Tooltip>
              </Space>
            )}
          >
            {elements.length ? (
              <CytoscapeGraph
                elements={elements}
                layout={layoutMode}
                highlight={highlight}
                onReady={setHandle}
                onSelect={(nodeId, data) => setSelected({ id: nodeId, data })}
              />
            ) : (
              <Empty description={view ? "这个会话还没有图（还没跑过工具，或图被裁剪光了）" : "选择项目与会话"} style={{ padding: 48 }} />
            )}
            <Row gutter={8} style={{ marginTop: 10 }}>
              {[
                ["节点", stats.nodes], ["边", stats.edges], ["漏洞", stats.vulnerable], ["死胡同", stats.dead_end],
                ["鉴权墙", stats.blocked], ["身份", stats.identities], ["活跃假设", stats.hypotheses],
                ["已降级假设", stats.hypotheses_closed], ["假设线", stats.hypothesis_edges], ["RPC 边", stats.rpc_edges], ["图上裁剪", stats.pruned],
              ].map(([label, value]) => (
                <Col span={4} key={String(label)}><Statistic title={String(label)} value={Number(value || 0)} valueStyle={{ fontSize: 16 }} /></Col>
              ))}
            </Row>
            {rebuildNote ? <Text type="secondary" style={{ display: "block", marginTop: 6 }}>{rebuildNote}</Text> : null}
          </Card>
        </Col>

        <Col xs={24} xl={7}>
          <Card size="small" title="Kill Chain" style={{ marginBottom: 12 }}>
            {highlight && highlight.nodes.length > 1 ? (
              <ol className="kill-chain-list">
                {highlight.nodes.map((node, index) => (
                  <li key={node}>
                    <Tag color={index === highlight.nodes.length - 1 ? "red" : "blue"}>{index + 1}</Tag>
                    <Text code style={{ fontSize: 12 }}>{node}</Text>
                  </li>
                ))}
              </ol>
            ) : <Text type="secondary">还没有确认的漏洞节点；图上有漏洞后这里会出现从入口到沦陷的路径。</Text>}
          </Card>

          <Card size="small" title={`假设（${view?.hypotheses.length || 0}）`} style={{ marginBottom: 12 }}>
            {view?.hypotheses.length ? view.hypotheses.map(item => (
              <Paragraph key={item.id} style={{ marginBottom: 8 }}>
                <Tag color={item.severity === "high" ? "red" : "gold"}>{item.kind}</Tag>
                <Tag>尝试 {item.attempts}/3</Tag>
                <Text style={{ fontSize: 12 }}>{item.text}</Text>
              </Paragraph>
            )) : <Text type="secondary">暂无活跃假设。</Text>}
            {view?.closed_hypotheses.length ? (
              <Alert
                type="info" showIcon style={{ marginTop: 8 }}
                message={`已降级 ${view.closed_hypotheses.length} 条`}
                description={<Text type="secondary" style={{ fontSize: 12 }}>打不动被自动关掉，避免继续空转。</Text>}
              />
            ) : null}
          </Card>

          <Card size="small" title={`子图（${view?.components.length || 0}）`}>
            {view?.components.length ? (
              <Space wrap>
                {view.components.map(component => (
                  <Tag key={component.id} color={component.has_vuln ? "red" : "default"}>
                    {component.id} · {component.size} 节点{component.has_vuln ? " · 含漏洞" : ""}
                  </Tag>
                ))}
              </Space>
            ) : <Text type="secondary">暂无。</Text>}
          </Card>
        </Col>
      </Row>

      <Modal
        open={Boolean(selected)} onCancel={() => setSelected(null)} footer={null}
        title={<Text code>{selected?.id}</Text>} width={640}
      >
        {selected ? <NodeInspector data={selected.data} /> : null}
      </Modal>
    </div>
  );
}

function NodeInspector({ data }: { data: Record<string, unknown> }): JSX.Element {
  const props = (data.props || {}) as Record<string, unknown>;
  const rows = Object.entries(props).filter(([, value]) => value !== undefined && value !== null && value !== "");
  return (
    <div>
      <Space style={{ marginBottom: 10 }} wrap>
        <Tag color={STATUS_COLOR[String(data.status)] || "default"}>{String(data.status)}</Tag>
        <Tag>{String(data.type)}</Tag>
        {data.evidence ? <Tag color="geekblue">证据 {String(data.evidence)}</Tag> : null}
      </Space>
      <Input.TextArea readOnly rows={6} value={rows.map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`).join("\n")} />
      <Paragraph type="secondary" style={{ fontSize: 12, marginTop: 10 }}>
        证据原文在会话证据账本里（`discovered_by` 是首次发现它的那条），控制台黑盒页可按 id 查。
        图里只放摘要（状态码、长度、参数名），响应体从不进图——这是刻意的。
      </Paragraph>
    </div>
  );
}

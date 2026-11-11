import { useEffect, useRef, useState } from "react";
import { Button, Card, Checkbox, Drawer, Input, Modal, Pagination, Progress, Select, Segmented, Statistic, Tag } from "antd";
import { useNavigate } from "react-router-dom";
import { DeleteGroupModal, type DeleteGroupTarget } from "../components/DeleteGroupModal";
import { Flash } from "../components/Flash";
import { useDesk } from "../store";
import { api } from "../api";
import type { AssetCandidate, AssetProbeJob, AssetReviewJob } from "../types";

const labels: Record<string, string> = { candidate: "待探活", queued: "排队中", running: "探活中", completed: "已完成", review: "待复核", selected: "已选择", rejected: "已排除", failed: "失败", paused: "已暂停", cancelled: "已取消" };
type Result = { ok?: boolean; error?: string; items?: AssetCandidate[]; accepted?: AssetCandidate[]; rejected?: unknown[]; candidates?: AssetCandidate[]; task_ids?: string[]; targets?: string[]; target?: string; wildcard?: boolean; strategies?: string[]; queries?: { strategy?: string; query?: string; hits?: number }[]; filtered?: number; pending?: boolean; pending_status?: string[]; tasks?: { status?: string }[]; reviewed?: AssetCandidate[]; job?: AssetProbeJob | AssetReviewJob | null; queued?: number; discovered?: number; failed?: number; retried?: number; skipped?: number; rule_version?: string; message?: string; pages?: number; query?: string; remain_query?: number; total?: number; aggregates?: Record<string, number>; tags?: string[]; ids?: string[] };
function check(result: { ok?: boolean; error?: string }) {
  if (result.error || result.ok === false) throw new Error(result.error || "请求失败");
}
function download(content: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function csvCell(value: unknown): string {
  const text = String(value ?? "");
  return `"${(/^[=+@\-\t\r]/.test(text) ? "'" : "") + text.replace(/"/g, '""')}"`;
}

export function AssetsPage() {
  const { projects, currentProject, selectProject, loadWorkspace, setFlash, flash } = useDesk();
  const nav = useNavigate();
  const [projectId, setProjectId] = useState("");
  const [candidates, setCandidates] = useState<AssetCandidate[]>([]);
  const [jobs, setJobs] = useState<AssetProbeJob[]>([]);
  const [reviewJobs, setReviewJobs] = useState<AssetReviewJob[]>([]);
  const [jobId, setJobId] = useState("");
  const [status, setStatus] = useState("");
  const [tag, setTag] = useState("");
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [minScore, setMinScore] = useState("");
  const [onlyReachable, setOnlyReachable] = useState(false);
  const [view, setView] = useState<"cards" | "list">("cards");
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState("");
  const [reviewVersion, setReviewVersion] = useState("");
  const [arlTarget, setArlTarget] = useState("");
  const [arlBrute, setArlBrute] = useState<"big" | "small" | "test">("small");
  const [arlTasks, setArlTasks] = useState<string[]>([]);
  const [submittedTarget, setSubmittedTarget] = useState("");
  const [discoveryNote, setDiscoveryNote] = useState("");
  const [provider, setProvider] = useState<"arl" | "fofa">("arl");
  const [fofaTarget, setFofaTarget] = useState("");
  const [fofaQuery, setFofaQuery] = useState("");
  const [fofaNote, setFofaNote] = useState("");
  const [detail, setDetail] = useState<AssetCandidate | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [groupOpen, setGroupOpen] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [purgeTarget, setPurgeTarget] = useState<DeleteGroupTarget | null>(null);
  const [total, setTotal] = useState(0);
  const [aggregates, setAggregates] = useState<null | Record<string, number>>(null);
  const [optionTags, setOptionTags] = useState<string[]>([]);
  const etagRef = useRef<Record<string, string>>({});
  const loadCandidatesRef = useRef<(use304: boolean) => void>(() => {});
  const loadJobsRef = useRef<() => void>(() => {});
  const job = jobs.find((item) => item.id === jobId) || jobs[0];

  // 搜索框防抖：避免每次按键都打后端。
  useEffect(() => { const t = setTimeout(() => setDebouncedQuery(query), 300); return () => clearTimeout(t); }, [query]);

  /** 删除整个资产分组（含其下全部会话/证据/产物/候选）。 */
  async function purgeGroup() {
    if (!purgeTarget) return;
    setBusy("purge");
    try {
      const result = await api<{ ok?: boolean; error?: string; deleted?: { sessions?: number; candidates?: number } }>(
        `/api/projects/${encodeURIComponent(purgeTarget.id)}`,
        { method: "DELETE" },
      );
      if (!result.ok) { setFlash("work", result.error || "删除分组失败", "bad"); return; }
      setFlash("work", `已删除分组「${purgeTarget.name}」（会话 ${result.deleted?.sessions ?? 0} · 候选 ${result.deleted?.candidates ?? 0}）`, "ok");
      setPurgeTarget(null);
      await loadWorkspace();
      setProjectId("");
    } finally { setBusy(""); }
  }

  useEffect(() => { loadWorkspace(); }, [loadWorkspace]);
  useEffect(() => {
    const id = projectId || currentProject()?.id || projects[0]?.id || "";
    if (id && id !== projectId) setProjectId(id);
  }, [projectId, projects, currentProject]);

  // 服务端分页加载器。每次渲染刷新引用，让 effect / 轮询 / 处理器都能取到最新 state。
  const buildParams = (extra?: Record<string, string>) => {
    const p = new URLSearchParams();
    if (status) p.set("status", status);
    if (tag) p.set("tag", tag);
    if (debouncedQuery) p.set("query", debouncedQuery);
    if (minScore) p.set("min_score", minScore);
    if (onlyReachable) p.set("reachable", "1");
    if (extra) for (const [k, v] of Object.entries(extra)) p.set(k, v);
    return p;
  };
  const loadCandidates = async (use304: boolean) => {
    if (!projectId) return;
    const pageSize = view === "cards" ? 24 : 50;
    const params = buildParams({ limit: String(pageSize), offset: String((page - 1) * pageSize) });
    const sig = `${projectId}|${params.toString()}`;
    try {
      const r = await fetch(`/api/projects/${encodeURIComponent(projectId)}/candidates?${params.toString()}`, {
        headers: use304 && etagRef.current[sig] ? { "If-None-Match": etagRef.current[sig] } : {},
      });
      // 未变化：304 无响应体，直接复用当前页，不重新解析 / 排序 / 渲染。
      if (r.status === 304) return;
      const data = await r.json() as Result;
      if (!data.ok) { setFlash("work", data.error || "加载资产失败", "bad"); return; }
      setCandidates(data.items || []);
      setTotal(data.total || 0);
      if (data.aggregates) setAggregates(data.aggregates);
      if (data.tags) setOptionTags(data.tags);
      const etag = r.headers.get("ETag");
      if (etag) etagRef.current[sig] = etag;
    } catch (error) {
      setFlash("work", error instanceof Error ? error.message : String(error), "bad");
    }
  };
  const loadJobs = async () => {
    if (!projectId) return;
    try {
      const [tasks, reviews] = await Promise.all([
        api<{ ok?: boolean; error?: string; items?: AssetProbeJob[] }>(`/api/projects/${encodeURIComponent(projectId)}/probe-jobs`),
        api<{ ok?: boolean; error?: string; items?: AssetReviewJob[] }>(`/api/projects/${encodeURIComponent(projectId)}/asset-review-jobs`),
      ]);
      if (tasks.ok) setJobs(tasks.items || []);
      if (reviews.ok) setReviewJobs(reviews.items || []);
    } catch { /* 瞬时错误忽略，下次轮询自愈 */ }
  };
  loadCandidatesRef.current = loadCandidates;
  loadJobsRef.current = loadJobs;

  // 进入分组：恢复 ARL 任务快照并启轮询。任务进度数据量小，资产页走 304 协商（未变即零传输）。
  useEffect(() => {
    if (!projectId) return;
    selectProject(projectId);
    setCandidates([]); setJobs([]); setReviewJobs([]); setJobId(""); setDetail(null);
    setArlTasks([]); setSubmittedTarget(""); setArlTarget(""); setDiscoveryNote(""); setFofaNote("");
    setAggregates(null); setTotal(0); setOptionTags([]);
    void api<Result & { target?: string }>(`/api/projects/${encodeURIComponent(projectId)}/arl/tasks`).then((result) => {
      if (result.ok && result.task_ids?.length) {
        setArlTasks(result.task_ids); setSubmittedTarget(result.target || ""); setArlTarget(result.target || "");
        setDiscoveryNote("已恢复该分组最近的 ARL 任务，可继续收集结果。");
      }
    }).catch((error) => { setFlash("work", String(error), "bad"); });
    const timer = setInterval(() => { loadJobsRef.current(); loadCandidatesRef.current(true); }, 5000);
    return () => clearInterval(timer);
  }, [projectId, selectProject, setFlash]);

  // 筛选 / 分页变化：立即重新请求当前页（不走 304，确保拿到新页）。
  useEffect(() => {
    loadCandidatesRef.current(false);
    loadJobsRef.current();
  }, [status, tag, debouncedQuery, minScore, onlyReachable, view, page, projectId]);

  async function refreshPool() { loadCandidatesRef.current(false); loadJobsRef.current(); }

  /** 取当前筛选范围内匹配的候选 id（用于探活 / 删除 / 评分等批量动作）。 */
  async function fetchFilteredIds(scope: "all" | "pending" | "retry" = "all", ignoreFilters = false): Promise<string[]> {
    if (!projectId) return [];
    const params = ignoreFilters ? new URLSearchParams() : buildParams();
    params.set("ids", "1");
    params.set("scope", scope);
    const r = await api<{ ok?: boolean; error?: string; ids?: string[] }>(`/api/projects/${encodeURIComponent(projectId)}/candidates?${params.toString()}`);
    if (!r.ok) throw new Error(r.error || "获取资产列表失败");
    return r.ids || [];
  }
  /** 取当前筛选范围内全部候选（仅用于显式导出，不在轮询路径上）。 */
  async function fetchAllFiltered(): Promise<AssetCandidate[]> {
    if (!projectId) return [];
    const params = buildParams({ limit: "100000", offset: "0" });
    const r = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/candidates?${params.toString()}`);
    if (!r.ok) throw new Error(r.error || "获取资产失败");
    return r.items || [];
  }
  async function perform(label: string, action: () => Promise<void>) {
    if (busy) return;
    setBusy(label);
    try { await action(); }
    catch (error) { setFlash("work", error instanceof Error ? error.message : String(error), "bad"); }
    finally { setBusy(""); }
  }
  async function probe(ids: string[]) {
    if (!ids.length) return;
    const base = `/api/projects/${encodeURIComponent(projectId)}/probe-jobs`;
    const created = await api<Result>(base, { method: "POST", body: JSON.stringify({ candidate_ids: ids }) });
    check(created);
    if (!created.job?.id) throw new Error("探活任务创建失败");
    setJobId(created.job.id);
    await refreshPool();
    const result = await api<Result>(`${base}/${encodeURIComponent(created.job.id)}/run`, { method: "POST", body: "{}" });
    check(result);
    await refreshPool();
  }
  async function reviewAssets(mode: "pending" | "retry" | "rescore" = "pending") {
    const scope = mode === "retry" ? "retry" : mode === "rescore" ? "all" : "pending";
    await perform(mode === "retry" ? "重试评分中" : mode === "rescore" ? "重新评分中" : "Agent 评分中", async () => {
      const ids = await fetchFilteredIds(scope);
      if (!ids.length) {
        setFlash("work", mode === "retry" ? "没有评分失败的资产" : mode === "rescore" ? "当前筛选结果为空" : "所有候选资产都已评分", "bad");
        return;
      }
      const base = { candidate_ids: ids };
      const payload = mode === "retry" ? { ...base, retry_failed: true } : mode === "rescore" ? { ...base, rescore: true } : base;
      const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/asset-review`, { method: "POST", body: JSON.stringify(payload) });
      check(result);
      setReviewVersion(result.rule_version || (result.job as AssetReviewJob | undefined)?.rule_version || "");
      if (result.message) setFlash("work", result.message, result.queued ? "ok" : "bad");
      else setFlash("work", `本次排队 ${result.queued} 个${result.skipped ? `，跳过 ${result.skipped} 个已评分/评分失败` : ""}`, "ok");
      await refreshPool();
    });
  }
  function deleteCandidates(ids: string[]) {
    if (!ids.length) return;
    Modal.confirm({ title: ids.length === candidates.length ? "清空当前项目候选池？" : `删除 ${ids.length} 个候选资产？`, content: "候选记录和已保存截图都会删除，删除后不可恢复。", okText: "确认删除", okButtonProps: { danger: true }, cancelText: "取消", onOk: async () => {
      await perform("删除资产", async () => { const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/candidates`, { method: "DELETE", body: JSON.stringify({ candidate_ids: ids }) }); check(result); setDetail(null); await refreshPool(); });
    } });
  }
  function deleteProbeJob(id: string, status: string) {
    if (["queued", "running", "paused"].includes(status)) { setFlash("work", "运行中的探活任务请先取消，再删除。", "bad"); return; }
    Modal.confirm({ title: "删除探活任务？", content: "只删除任务记录，不删除候选资产。", okText: "确认删除", okButtonProps: { danger: true }, cancelText: "取消", onOk: async () => { await perform("删除探活任务", async () => { const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/probe-jobs/${encodeURIComponent(id)}`, { method: "DELETE" }); check(result); if (jobId === id) setJobId(""); await refreshPool(); }); } });
  }
  function submitArl() {
    if (!projectId || !arlTarget.trim()) { setFlash("work", "请选择资产分组并输入域名或通配符", "bad"); return; }
    void perform("提交 ARL 任务", async () => {
      const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/arl/discover`, { method: "POST", body: JSON.stringify({ target: arlTarget.trim(), brute: arlBrute, wait: false }) });
      check(result);
      const targets = result.targets || [];
      setArlTasks(result.task_ids || []); setSubmittedTarget((targets.length ? targets : [arlTarget.trim()]).join(", "));
      setDiscoveryNote(`ARL 任务已提交（${targets.length || 1} 个目标 · ${arlBrute === "big" ? "big 字典 + 证书 / DNS 数据集" : `${arlBrute} 字典`}${result.wildcard ? " · 通配符展开" : ""}）。可稍后收集结果，扫描期间可重复收集。`);
    });
  }
  function collectArl() {
    void perform("收集 ARL 结果并探活", async () => {
      const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/arl/discover`, { method: "POST", body: JSON.stringify({ target: submittedTarget, task_ids: arlTasks, wait: true }) });
      check(result);
      const statuses = (result.tasks || []).map((task) => task.status || "未知").join("、") || "未知";
      const count = result.candidates?.length || 0;
      setDiscoveryNote(result.pending
        ? `ARL 仍在 ${statuses} 阶段，当前产出 ${count} 个资产（其中新增/更新 ${count}）。爆破与证书/DNS 枚举完成后再点一次「收集 ARL 结果」。`
        : `本次收集 ${count} 个有效资产（含子域名与 IP 资产）。ARL 状态：${statuses}。`);
      await refreshPool();
      await probe((result.candidates || []).map((item) => item.id));
    });
  }
  function submitFofa() {
    if (!projectId || !fofaTarget.trim()) { setFlash("work", "请选择资产分组并输入域名、通配符或 IP", "bad"); return; }
    void perform("FOFA 查询中", async () => {
      const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/fofa/discover`, { method: "POST", body: JSON.stringify({ target: fofaTarget.trim(), query: fofaQuery.trim() || undefined }) });
      check(result);
      const count = result.candidates?.length || 0;
      const perStrategy = (result.queries || []).map((item) => `${item.strategy || "?"} ${item.hits ?? 0}`).join(" / ");
      setFofaNote(`FOFA 目标 ${result.target || fofaTarget}${result.wildcard ? "（通配符展开）" : ""}：命中 ${result.discovered ?? count} 条${perStrategy ? `（${perStrategy}）` : ""}，新增/更新 ${count} 个资产${result.filtered ? `，已剔除 ${result.filtered} 个范围外主机` : ""}${result.pages ? `，${result.pages} 页` : ""}${result.remain_query === undefined ? "" : `，剩余配额 ${result.remain_query}`}。`);
      await refreshPool();
      await probe((result.candidates || []).map((item) => item.id));
    });
  }
  function importTargets() {
    void perform("导入资产", async () => {
      const targets = importText.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
      const result = await api<Result>(`/api/projects/${encodeURIComponent(projectId)}/candidates/import`, { method: "POST", body: JSON.stringify({ candidates: targets.map((value) => ({ value, source: "manual" })) }) });
      check(result);
      setFlash("work", `导入 ${result.accepted?.length || 0} 个资产，拒绝 ${result.rejected?.length || 0} 个输入`, result.rejected?.length ? "bad" : "ok");
      if (!result.rejected?.length) { setImportOpen(false); setImportText(""); }
      await refreshPool();
    });
  }
  function createGroup() {
    void perform("创建资产分组", async () => {
      const result = await api<{ ok?: boolean; error?: string; project?: { id: string } }>("/api/projects", { method: "POST", body: JSON.stringify({ name: groupName.trim() }) });
      check(result);
      if (!result.project?.id) throw new Error("资产分组创建失败");
      await loadWorkspace(); setProjectId(result.project.id); setGroupOpen(false); setGroupName("");
    });
  }

  const unscored = aggregates?.unscored ?? 0;
  const reviewFailed = aggregates?.review_failed ?? 0;
  const pageSize = view === "cards" ? 24 : 50;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => { if (page > pageCount) setPage(pageCount); }, [page, pageCount]);
  useEffect(() => { setPage(1); }, [status, tag, debouncedQuery, minScore, onlyReachable, view, projectId]);
  function openBlackbox(candidate: AssetCandidate) {
    // Create (or reuse) the session here, so the blackbox session list already has this URL
    // when the page opens instead of waiting for a second click there.
    void perform("送至黑盒", async () => {
      const rec = await api<{ ok?: boolean; error?: string; session?: { id: string }; reused?: boolean }>(
        `/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions`,
        { method: "POST", body: JSON.stringify({ candidate_id: candidate.id }) },
      );
      if (!rec.ok || !rec.session?.id) throw new Error(rec.error || "创建黑盒会话失败");
      nav(`/blackbox?${new URLSearchParams({ project: projectId, candidate: candidate.id, session: rec.session.id })}`);
      if (rec.reused) setFlash("work", "该资产已有黑盒会话，已切换过去", "ok");
    });
  }
  async function exportPool(format: "url" | "csv") {
    if (!projectId) return;
    setBusy("导出中");
    try {
      const items = await fetchAllFiltered();
      const lines = format === "url" ? items.map((item) => item.url || item.value).join("\r\n")
        : "\uFEFF" + [["资产", "标题", "来源", "状态", "探活分数（非 Agent 评分）", "HTTP", "技术", "标签"], ...items.map((item) => [item.url || item.value, item.title, item.source, labels[item.status || "candidate"], item.score ?? 0, item.http_status, item.technologies?.join(";"), item.tags?.join(";")])].map((row) => row.map(csvCell).join(",")).join("\r\n");
      download(lines, `assets-${projectId}.${format === "url" ? "txt" : "csv"}`, format === "url" ? "text/plain;charset=utf-8" : "text/csv;charset=utf-8");
    } catch (error) {
      setFlash("work", error instanceof Error ? error.message : String(error), "bad");
    } finally { setBusy(""); }
  }

  return <main className="asset-center">
    <Flash id="work" flash={flash} />
    <div className="asset-center-head">
      <div><p className="kicker">SRC ASSET INTEL</p><h1>SRC 资产识别</h1><p className="page-lede">发现资产、汇总特征、筛选目标，再进入黑盒分析。</p></div>
      <div className="asset-head-actions"><Button onClick={() => setImportOpen(true)} disabled={!projectId || !!busy}>导入域名 / IP / URL</Button><Button type="primary" onClick={() => document.getElementById("asset-target")?.focus()} disabled={!!busy}>新建发现</Button></div>
    </div>
    <div className="asset-pipeline"><span>01 域名 / IP</span><span>02 资产发现 <Tag>ARL / FOFA</Tag></span><span>03 特征汇总 <Tag>Agent 评分</Tag></span><span>04 黑盒分析入口</span></div>
    <Card size="small" className="asset-group-bar"><div className="asset-toolbar"><strong>资产分组</strong><Select disabled={!!busy} value={projectId || undefined} placeholder="选择资产分组" onChange={setProjectId} options={projects.map((p) => ({ value: p.id, label: p.name }))} style={{ minWidth: 220 }} /><Button onClick={() => setGroupOpen(true)} disabled={!!busy}>新建分组</Button><Button danger disabled={!!busy || !projectId} onClick={() => setPurgeTarget({ id: projectId, name: currentProject()?.name || projectId })}>删除分组</Button></div></Card>
    <Card
      className="asset-discovery"
      title="资产发现"
      size="small"
      extra={<Segmented value={provider} onChange={(value) => setProvider(value as "arl" | "fofa")} options={[{ label: "ARL（本地灯塔）", value: "arl" }, { label: "FOFA（搜索引擎）", value: "fofa" }]} />}
    >
      {provider === "arl" ? <>
        <div className="asset-toolbar"><Tag color="blue">ARL</Tag><Input id="asset-target" value={arlTarget} disabled={!!busy} onChange={(event) => setArlTarget(event.target.value)} placeholder="根域名或通配符，例如 *.qwen.ai（逗号分隔多个）" onPressEnter={submitArl} style={{ maxWidth: 420 }} /><Select disabled={!!busy} value={arlBrute} onChange={(value) => setArlBrute(value as "big" | "small" | "test")} style={{ minWidth: 190 }} options={[{ value: "small", label: "中等：small 字典（数分钟）" }, { value: "big", label: "深度：big 字典（20-60 分钟）" }, { value: "test", label: "快速：test 字典" }]} /><Button type="primary" loading={busy === "提交 ARL 任务"} disabled={!projectId || !!busy || !arlTarget.trim()} onClick={submitArl}>开始发现</Button><Button loading={busy === "收集 ARL 结果并探活"} disabled={!arlTasks.length || !!busy} onClick={collectArl}>收集 ARL 结果</Button></div>
        <p className="asset-discovery-note">输入 <code>*.qwen.ai</code> 会按通配符基域 <code>qwen.ai</code> 建任务：字典爆破 + DNS 数据集 + 证书 + DNS 插件 + 站点识别，收集时同时拉取域名、站点与 IP 资产；字典大小决定耗时（small 数分钟，big 可能要一小时）。ARL 是异步流水线，任务没跑完时收集为空属正常，稍后再点「收集 ARL 结果」。</p>
        {discoveryNote && <p className="asset-discovery-result">{discoveryNote}</p>}
        {!!arlTasks.length && <p className="asset-discovery-note">目标：{submittedTarget} · ARL 任务：{arlTasks.join("、")}</p>}
      </> : <>
        <div className="asset-toolbar"><Tag color="purple">FOFA</Tag><Input value={fofaTarget} disabled={!!busy} onChange={(event) => setFofaTarget(event.target.value)} placeholder="根域名、通配符或 IP，例如 *.qwen.ai" onPressEnter={submitFofa} style={{ maxWidth: 320 }} /><Button type="primary" loading={busy === "FOFA 查询中"} disabled={!projectId || !!busy || !fofaTarget.trim()} onClick={submitFofa}>开始发现</Button></div>
        <div className="asset-toolbar"><Input value={fofaQuery} disabled={!!busy} onChange={(event) => setFofaQuery(event.target.value)} placeholder='可选自定义查询，例如 title="后台"；留空则同时跑 domain / host / cert 三种锚定查询' onPressEnter={submitFofa} style={{ maxWidth: 620 }} /></div>
        <p className="asset-discovery-note">输入 <code>*.qwen.ai</code> 会展开为 <code>domain</code>、<code>host</code>、<code>cert</code> 三条查询并合并去重，覆盖子域名、主机名与证书 SAN；默认只保留 <code>*.qwen.ai</code> 范围内的主机，自定义查询会追加目标条件。每次查询消耗 FOFA API 配额。</p>
        {fofaNote && <p className="asset-discovery-result">{fofaNote}</p>}
      </>}
    </Card>
    <div className="asset-stats"><Card><Statistic title="候选资产" value={total} /></Card><Card><Statistic title="HTTP 可达" value={aggregates?.reachable ?? 0} /></Card><Card><Statistic title="待探活" value={aggregates?.pending ?? 0} /></Card><Card><Statistic title="探活失败" value={aggregates?.failed ?? 0} /></Card></div>
    <div className="asset-workbench">
      <Card className="asset-task-panel" title="探活任务" size="small" extra={<span>{jobs.length}</span>}>
        {!jobs.length ? <p className="empty-hint">发现或导入资产后，可创建探活任务。</p> : jobs.map((item) => <div className="asset-task-row-wrap" key={item.id}><button type="button" className={`asset-task-row ${job?.id === item.id ? "active" : ""}`} onClick={() => setJobId(item.id)}><strong>{item.id}</strong><span>{labels[item.status] || item.status} · {item.completed + item.failed + item.skipped}/{item.total}</span><Progress percent={item.total ? Math.round((item.completed + item.failed + item.skipped) / item.total * 100) : 0} size="small" showInfo={false} /></button><Button size="small" danger onClick={() => deleteProbeJob(item.id, item.status)}>删除</Button></div>)}
      </Card>
      <section className="asset-results">
        <Card size="small" className="asset-progress-panel">
          <div className="asset-toolbar"><strong>{busy || "资产候选池"}</strong><span>共 {total} 个资产</span><Tag>按探活分数降序</Tag><Button onClick={() => void perform("刷新", refreshPool)} disabled={!projectId || !!busy}>刷新</Button><Button onClick={() => void perform("探活中", async () => { const ids = await fetchFilteredIds("all"); if (!ids.length) { setFlash("work", "当前筛选结果为空", "bad"); return; } await probe(ids); })} disabled={!total || !!busy}>探活筛选结果（{total}）</Button></div>
          {job && <div className="asset-job-progress"><Progress percent={job.total ? Math.round((job.completed + job.failed + job.skipped) / job.total * 100) : 0} status={job.status === "failed" ? "exception" : job.status === "completed" ? "success" : "normal"} /><span>选中任务：{labels[job.status]} · 成功 {job.completed} · 失败 {job.failed} · 跳过 {job.skipped} · 并发 {job.concurrency}</span></div>}
          <div className="asset-toolbar"><p className="asset-discovery-note">先探活，再用 Playwright 采集首屏和页面证据，由设置中的资产 Agent 评分；已评分和评分失败的资产默认都不会重复消耗 token。</p><Button type="primary" onClick={() => void reviewAssets("pending")} disabled={!unscored || !!busy}>Agent 评分（未评分 {unscored}）</Button><Button onClick={() => void reviewAssets("retry")} disabled={!reviewFailed || !!busy}>重试评分失败（{reviewFailed}）</Button><Button onClick={() => void reviewAssets("rescore")} disabled={!total || !!busy}>重新评分筛选结果（{total}）</Button></div>
          {reviewVersion && <p className="asset-discovery-note">评分规则版本：{reviewVersion}</p>}
          {!!reviewJobs.length && <div className="asset-job-progress"><Progress percent={reviewJobs[0]!.total ? Math.round((reviewJobs[0]!.completed + reviewJobs[0]!.failed) / reviewJobs[0]!.total * 100) : 0} status={reviewJobs[0]!.failed ? "exception" : reviewJobs[0]!.status === "completed" ? "success" : "normal"} /><span>Agent 评分：{reviewJobs[0]!.completed + reviewJobs[0]!.failed}/{reviewJobs[0]!.total} · 成功 {reviewJobs[0]!.completed} · 失败 {reviewJobs[0]!.failed} · {reviewJobs[0]!.status}</span></div>}
        </Card>
        <Card className="asset-pool" title="发现结果" extra={<Segmented value={view} onChange={(v) => setView(v as "cards" | "list")} options={[{ label: "卡片", value: "cards" }, { label: "列表", value: "list" }]} />}>
          <div className="asset-filters"><Input placeholder="搜索资产、标题、技术或标签" value={query} onChange={(e) => setQuery(e.target.value)} /><Select allowClear placeholder="状态" value={status || undefined} onChange={(v) => setStatus(v || "")} options={Object.entries(labels).filter(([v]) => !["paused", "cancelled"].includes(v)).map(([value, label]) => ({ value, label }))} /><Select allowClear placeholder="标签" value={tag || undefined} onChange={(v) => setTag(v || "")} options={optionTags.map((v) => ({ value: v, label: v }))} /><Input placeholder="最低探活分" value={minScore} onChange={(e) => setMinScore(e.target.value.replace(/[^0-9]/g, ""))} /></div>
          <div className="asset-result-toolbar"><Checkbox checked={onlyReachable} onChange={(e) => setOnlyReachable(e.target.checked)}>仅 HTTP 可达</Checkbox><span>共 {total} 条</span><div><Button size="small" danger disabled={!total} onClick={async () => { const ids = await fetchFilteredIds("all"); deleteCandidates(ids); }}>删除筛选结果</Button><Button size="small" danger disabled={!total} onClick={async () => { const ids = await fetchFilteredIds("all", true); deleteCandidates(ids); }}>清空候选池</Button><Button size="small" disabled={!total} onClick={() => void exportPool("url")}>导出 URL / 目标</Button><Button size="small" disabled={!total} onClick={() => void exportPool("csv")}>导出 CSV</Button></div></div>
          {!projectId ? <p className="empty-hint">新建资产分组，开始发现。</p> : !total ? <p className="empty-hint">当前没有匹配的候选资产，可开始 ARL 发现或导入已有目标。</p> : <div className={view === "cards" ? "asset-card-grid" : "asset-table-list"}>
            {candidates.map((candidate) => <article className={`asset-card ${candidate.tags?.includes("reachable") ? "reachable" : ""}`} key={candidate.id}>
              <div className="asset-card-top"><div><span className="asset-score">{candidate.agent_score ?? (candidate.http_status ? candidate.score ?? 0 : "—")}</span><span className="asset-score-label">{candidate.agent_score != null ? "Agent 分" : Number(candidate.review_attempts || 0) > 0 ? "评分失败" : "探活分"}</span></div><Tag>{labels[candidate.status || "candidate"]}</Tag></div>
              <div className="asset-preview">{candidate.screenshot_path ? <img src={`/api/projects/${encodeURIComponent(projectId)}/candidates/${encodeURIComponent(candidate.id)}/screenshot`} alt="页面首屏截图" /> : null}<strong>{candidate.title || candidate.hostname || "待识别资产"}</strong><span>{candidate.technologies?.join(" · ") || "尚未获取技术指纹"}</span><small>{candidate.screenshot_path ? "已保存首屏截图" : candidate.agent_score == null && Number(candidate.review_attempts || 0) > 0 ? "评分失败，需手动重试" : "尚未评分"}</small></div>
              <h3 title={candidate.url || candidate.value}>{candidate.url || candidate.value}</h3>
              <div className="asset-tags">{[...new Set([...(candidate.technologies || []), ...(candidate.tags || [])])].map((item) => <Tag key={item}>{item}</Tag>)}</div>
              <div className="asset-meta">{candidate.source || "import"} · {candidate.http_status ? `HTTP ${candidate.http_status}` : "待探活"}{candidate.response_time_ms != null ? ` · ${candidate.response_time_ms} ms` : ""}</div>
              {candidate.error && <p className="asset-error">{candidate.error}</p>}
              {candidate.agent_score == null && candidate.review_error && <p className="asset-error">评分失败（{Number(candidate.review_attempts || 1)} 次）：{candidate.review_error}</p>}
              <div className="asset-card-actions"><Button size="small" onClick={() => setDetail(candidate)}>资产详情</Button><Button size="small" onClick={() => openBlackbox(candidate)}>送至黑盒</Button><Button size="small" danger onClick={() => deleteCandidates([candidate.id])}>删除</Button></div>
            </article>)}
          </div>}
          {total > 0 && <Pagination
            style={{ marginTop: 12, textAlign: "right" }}
            size="small"
            current={page}
            pageSize={pageSize}
            total={total}
            showSizeChanger={false}
            showTotal={(t, range) => `第 ${range[0]}-${range[1]} 条 / 共 ${t} 条 · ${pageSize} 条每页`}
            onChange={setPage}
          />}
        </Card>
      </section>
    </div>
    <Drawer title="资产详情" open={!!detail} onClose={() => setDetail(null)} width={560}>
      {detail && <div className="asset-detail"><h3>{detail.title || detail.hostname}</h3><p>{detail.url || detail.value}</p><p>来源：{detail.source} · 状态：{labels[detail.status || "candidate"]}</p><p>HTTP：{detail.http_status ?? "未探活"} · 探活分：{detail.score ?? 0}</p><p>Agent 评分：{detail.agent_score ?? "尚未评分"} · 规则：{detail.score_rule_version || "—"}</p>{detail.screenshot_path && <img className="asset-detail-shot" src={`/api/projects/${encodeURIComponent(projectId)}/candidates/${encodeURIComponent(detail.id)}/screenshot`} alt="页面首屏截图" />}<div>{detail.technologies?.map((value) => <Tag key={value}>{value}</Tag>)}</div>{detail.score_reasons && <><h4>评分理由</h4><pre>{JSON.stringify(detail.score_reasons, null, 2)}</pre></>}{detail.error && <p className="asset-error">{detail.error}</p>}<h4>采集证据</h4><pre>{JSON.stringify({ ...detail.evidence, page: detail.page_evidence }, null, 2)}</pre><Button onClick={() => openBlackbox(detail)}>送至黑盒</Button></div>}
    </Drawer>
    <Modal title="导入域名 / IP / URL" open={importOpen} onCancel={() => setImportOpen(false)} onOk={importTargets} okText="导入" confirmLoading={busy === "导入资产"} okButtonProps={{ disabled: !!busy || !importText.trim() }}><p>每行一个目标，例如 example.com、192.0.2.10 或 https://example.com。</p><Input.TextArea rows={8} value={importText} onChange={(e) => setImportText(e.target.value)} /></Modal>
    <Modal title="新建资产分组" open={groupOpen} onCancel={() => setGroupOpen(false)} onOk={createGroup} okText="创建" confirmLoading={busy === "创建资产分组"} okButtonProps={{ disabled: !!busy || !groupName.trim() }}><Input placeholder="分组名称" value={groupName} onChange={(e) => setGroupName(e.target.value)} onPressEnter={() => { if (groupName.trim()) createGroup(); }} /></Modal>
    <DeleteGroupModal target={purgeTarget} busy={busy === "purge"} onCancel={() => setPurgeTarget(null)} onConfirm={() => void purgeGroup()} />
  </main>;
}

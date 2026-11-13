import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Dropdown, Input, Modal, Select, Tag, Tooltip, Typography } from "antd";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Flash } from "../components/Flash";
import { useDesk } from "../store";
import { DeleteOutlined, MoreOutlined, ReloadOutlined } from "@ant-design/icons";
import { DeleteGroupModal, type DeleteGroupTarget } from "../components/DeleteGroupModal";
import type { AssetCandidate, BlackboxSession } from "../types";

const statusLabel: Record<string, string> = {
  pending: "待检查", ready: "环境就绪", running: "运行中", paused: "已暂停", failed: "失败", completed: "已完成", cancelled: "已取消",
};
const actorLabel: Record<string, string> = { system: "系统", operator: "操作员", agent: "主 Agent", observer: "Observer" };

/** 焦点仪表盘数据（`GET .../focus`）：看得见消耗才不会瞎打。 */
type FocusState = {
  focus_task_id: string;
  reason: string;
  detail: string;
  usage: {
    turns: number; max_turns: number; tp: number; max_tp: number; tool_calls: number;
    value_score: number; high_value: number; medium_value: number; noise: number;
    no_progress_rounds: number; appeals_used: number;
  } | null;
  convergence: { reason: string; detail: string; appealed?: boolean } | null;
  macro_interrupt: { count: number; limit: number; text: string } | null;
  session_convergences: number;
  limits: { max_turns_per_task?: number; max_tp_per_task?: number; stall_rounds: number; appeal_pool: number; appeal_potential_max: number; max_session_convergences: number };
  /** 势能：焦点任务到最近高价值目标的成本（越小越近；没有 = 不通）。 */
  potential?: { goals: number; best?: number; focus?: number; focus_node?: string };
  /** 延迟通胀：慢目标上所有工具变贵。 */
  latency?: { avg_ms: number; multiplier: number };
  appeals_left?: number;
  tasks: Array<{ id: string; status: string; target: string; purpose: string }>;
  /** 被操作员亲手收口的任务（可撤销）。 */
  operator_blocked?: string[];
  /** 工具价目表（nuclei 5 / http 1 …），仪表盘脚注会引用。 */
  tp_table?: Array<{ tool: string; tp: number }>;
  directive: string;
};

/** 仪表盘刻度：0–100 的占用百分比（上限为 0 表示"不限"，这时不给进度语义）。 */
function pct(used: number, cap: number): number {
  if (!cap || cap <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((used / cap) * 100)));
}

/** 条形色调：安全 / 警告 / 危险。阈值按"还能不能再来两轮"来定。 */
function toneOf(ratio: number): "ok" | "warn" | "bad" {
  if (ratio >= 0.99) return "bad";
  if (ratio >= 0.7) return "warn";
  return "ok";
}

type FocusMetricProps = {
  label: string;
  value: string;
  suffix?: string;
  /** 条形占用百分比（0–100）；不传就不画条。 */
  percent?: number;
  tone?: "ok" | "warn" | "bad" | "flat";
  note?: string;
  emphasis?: boolean;
};

/** 单个指标块：大号数字 + 彩色进度条 + 一行注释。 */
function FocusMetric({ label, value, suffix, percent, tone = "flat", note, emphasis }: FocusMetricProps) {
  return (
    <div className={`focus-metric${emphasis ? " emphasis" : ""}`} data-tone={tone}>
      <span className="focus-metric-label">{label}</span>
      <span className="focus-metric-value">{value}{suffix ? <em>{suffix}</em> : null}</span>
      {percent !== undefined && (
        <div className="focus-bar" data-tone={tone} role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
          <span style={{ width: `${percent}%` }} />
        </div>
      )}
      {note ? <span className="focus-metric-note">{note}</span> : null}
    </div>
  );
}


type BEvent = NonNullable<BlackboxSession["events"]>[number];
type BEvidence = NonNullable<BlackboxSession["evidence"]>[number];

export function BlackboxPage() {
  const { projects, loadWorkspace, setFlash, flash, status: consoleStatus } = useDesk();
  const [params, setParams] = useSearchParams();
  const [sessions, setSessions] = useState<BlackboxSession[]>([]);
  const [candidates, setCandidates] = useState<AssetCandidate[]>([]);
  const [candidateLoading, setCandidateLoading] = useState(false);
  const [selectedId, setSelectedId] = useState(new URLSearchParams(window.location.search).get("session") || "");
  const [selectedCandidateId, setSelectedCandidateId] = useState(params.get("candidate") || "");
  const [current, setCurrent] = useState<BlackboxSession | null>(null);
  const [prompt, setPrompt] = useState("");
  const [busy, setBusy] = useState("");
  const [review, setReview] = useState<{ kind: string; id: string; action: string } | null>(null);
  const [reviewReason, setReviewReason] = useState("");
  /** 会话列表多选（批量删除用）。 */
  const [picked, setPicked] = useState<string[]>([]);
  /** 待删除的整个分组（资产分组 = 项目，含其下全部会话）。 */
  const [purgeTarget, setPurgeTarget] = useState<DeleteGroupTarget | null>(null);
  // 时光机（快照 fork）：同一账本起点跑两条平行宇宙，用来做"改前 / 改后"对照。
  const [forkOpen, setForkOpen] = useState(false);
  const [forkBusy, setForkBusy] = useState("");
  const [checkpoints, setCheckpoints] = useState<Array<{ id: number; run_index: number; label: string; created_at: number; bytes: number }>>([]);
  const [focus, setFocus] = useState<FocusState | null>(null);
  const [focusSwitchTo, setFocusSwitchTo] = useState("");
  /** 焦点接口的错误：不再静默吞掉——吞掉的后果就是"仪表盘看不见"。 */
  const [focusError, setFocusError] = useState("");
  // 时间线 / 证据改为分页按需加载（避免一次性渲染上万条导致卡死）。
  const [events, setEvents] = useState<BEvent[]>([]);
  const [evidence, setEvidence] = useState<BEvidence[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [evidenceTotal, setEvidenceTotal] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  // 粘顶模式：时间线最新在上、自动刷；新事件从顶部进入，视口停在顶部即"跟随最新"。
  // firstId/lastId 用 ref 存，避免轮询闭包拿到过期值；events 数组恒为"新→旧"。
  const EVENTS_LIMIT = 50;
  const EVIDENCE_LIMIT = 24;
  const eventsFirstIdRef = useRef(0); // 已加载窗口里最旧的 id（翻更早的游标）
  const eventsLastIdRef = useRef(0);  // 已加载窗口里最新的 id（拉更新的游标）
  const eventsScrollRef = useRef<HTMLDivElement | null>(null);
  const evidenceScrollRef = useRef<HTMLDivElement | null>(null);
  const [newEventCount, setNewEventCount] = useState(0); // 滚去看历史时又到达的新事件数（顶部小药丸）
  const projectId = params.get("project") || projects[0]?.id || "";
  const selectedCandidate = candidates.find((item) => item.id === selectedCandidateId);

  /**
   * 拉焦点仪表盘数据。
   *
   * 以前这里 `.catch(() => null)`：接口一失败卡片就整块消失，操作员只会觉得"功能没做"。
   * 现在把失败原因留在 focusError 里，卡片照常渲染并显示原因 + 重试按钮。
   */
  async function loadFocus(sessionId: string): Promise<FocusState | null> {
    if (!projectId || !sessionId) { setFocus(null); return null; }
    try {
      const rec = await api<FocusState & { ok?: boolean; error?: string }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(sessionId)}/focus`);
      if (rec && rec.ok === false) {
        setFocusError(String(rec.error || "焦点接口返回失败"));
        setFocus(null);
        return null;
      }
      setFocusError("");
      const next = rec && rec.focus_task_id !== undefined ? rec : null;
      setFocus(next);
      return next;
    } catch (error) {
      setFocusError(error instanceof Error ? error.message : String(error));
      setFocus(null);
      return null;
    }
  }

  // 候选下拉改为服务端远程搜索：只拉当前页（默认 50 条），不再一次性拉 5000 条全量池。
  const loadCandidates = useCallback(async (query?: string) => {
    if (!projectId) return;
    setCandidateLoading(true);
    try {
      const q = query ? `&query=${encodeURIComponent(query)}` : "";
      const rec = await api<{ items?: AssetCandidate[] }>(`/api/projects/${encodeURIComponent(projectId)}/candidates?limit=50&offset=0${q}`);
      setCandidates(rec.items || []);
    } finally { setCandidateLoading(false); }
  }, [projectId]);

  // 预选的候选（来自 URL 或会话）可能不在当前已加载的页里，按需单条补齐，保证下拉能显示它的标签。
  const ensureCandidate = useCallback(async (id: string) => {
    if (!id || candidates.some((item) => item.id === id)) return;
    try {
      const rec = await api<{ ok?: boolean; item?: AssetCandidate }>(`/api/projects/${encodeURIComponent(projectId)}/candidates/${encodeURIComponent(id)}`);
      if (rec.ok && rec.item) setCandidates((prev) => (prev.some((item) => item.id === rec.item!.id) ? prev : [rec.item!, ...prev]));
    } catch { /* 单条缺失不阻塞 */ }
  }, [projectId, candidates]);

  // 会话时间线：dir=desc 取"新→旧"；newer 用 since 游标拉新，older 用 before 游标翻历史。
  // events 数组恒为"新→旧"，新事件从数组头部进入，配合粘顶视口即"自动跟随最新"。
  const loadEvents = useCallback(async (sessionId: string, mode: "newest" | "newer" | "older" = "newest") => {
    if (!projectId) return;
    if (mode === "newer" && eventsLastIdRef.current === 0) return;
    if (mode === "older" && eventsFirstIdRef.current === 0) return;
    setEventsLoading(true);
    try {
      let q = `events?dir=desc&limit=${EVENTS_LIMIT}`;
      if (mode === "newer") q += `&since=${eventsLastIdRef.current}`;
      else if (mode === "older") q += `&before=${eventsFirstIdRef.current}`;
      const rec = await api<{ items?: BEvent[]; total?: number }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(sessionId)}/${q}`);
      const items = rec.items || [];
      if (mode === "newer") {
        if (items.length) {
          setEvents((prev) => {
            const seen = new Set(prev.map((e) => e.id));
            const fresh = items.filter((e) => !seen.has(e.id));
            if (!fresh.length) return prev;
            return [...fresh, ...prev]; // 新→旧，插到头部
          });
          eventsLastIdRef.current = Math.max(eventsLastIdRef.current, ...items.map((e) => Number(e.id)));
          const el = eventsScrollRef.current;
          const atTop = !el || el.scrollTop <= 4; // 用户停在顶部就让他继续看最新
          if (!atTop) setNewEventCount((c) => c + items.length);
        }
      } else if (mode === "older") {
        if (items.length) {
          setEvents((prev) => {
            const seen = new Set(prev.map((e) => e.id));
            const fresh = items.filter((e) => !seen.has(e.id));
            if (!fresh.length) return prev;
            return [...prev, ...fresh]; // 更旧的接到底部
          });
          eventsFirstIdRef.current = Math.min(eventsFirstIdRef.current || Number.MAX_SAFE_INTEGER, ...items.map((e) => Number(e.id)));
        }
      } else {
        // newest：重置窗口到最新一屏
        setEvents(items);
        if (items.length) {
          eventsLastIdRef.current = Math.max(...items.map((e) => Number(e.id)));
          eventsFirstIdRef.current = Math.min(...items.map((e) => Number(e.id)));
        }
        setNewEventCount(0);
        requestAnimationFrame(() => { if (eventsScrollRef.current) eventsScrollRef.current.scrollTop = 0; });
      }
      setEventsTotal(Number(rec.total ?? 0));
    } finally { setEventsLoading(false); }
  }, [projectId]);

  // 分页拉取 Evidence Ledger（后端已 new→old）。追加更旧的一页到底部，按 id 去重防重复。
  const loadEvidence = useCallback(async (sessionId: string, reset = false) => {
    if (!projectId) return;
    setEvidenceLoading(true);
    try {
      const offset = reset ? 0 : evidence.length;
      const rec = await api<{ items?: BEvidence[]; total?: number }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(sessionId)}/evidence?limit=${EVIDENCE_LIMIT}&offset=${offset}`);
      const items = rec.items || [];
      setEvidence((prev) => {
        if (reset) return items;
        const seen = new Set(prev.map((e) => e.id));
        const fresh = items.filter((e) => !seen.has(e.id));
        return fresh.length ? [...prev, ...fresh] : prev;
      });
      setEvidenceTotal(Number(rec.total ?? 0));
    } finally { setEvidenceLoading(false); }
  }, [projectId, evidence.length]);

  // 时间线滚到接近底部时自动翻更早（替代手动"加载更多"）；滚回顶部则清掉"新事件"药丸。
  const onEventsScroll = () => {
    const el = eventsScrollRef.current;
    if (!el) return;
    if (el.scrollTop <= 4 && newEventCount) setNewEventCount(0);
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 240 && !eventsLoading && events.length < eventsTotal && eventsFirstIdRef.current > 0) {
      void loadEvents(current!.id, "older");
    }
  };
  // 证据台账滚到底部自动加载更早一页。
  const onEvidenceScroll = () => {
    const el = evidenceScrollRef.current;
    if (!el) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 240 && !evidenceLoading && evidence.length < evidenceTotal) {
      void loadEvidence(current!.id);
    }
  };

  // 拉单个会话详情。light=true 只取状态/环境/checkpoint（不含 events/evidence 巨量数组），
  // 用于轮询与首屏秒开；合并时保留已分页加载的 events/evidence，避免实时进度被清空。
  // 完整详情后端已不再内联 events/evidence，改为 loadEvents/loadEvidence 分页按需加载。
  const loadCurrentDetail = useCallback(async (sessionId: string, light = false): Promise<BlackboxSession | null> => {
    if (!projectId) return null;
    const rec = await api<{ session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(sessionId)}${light ? "?light=1" : ""}`);
    if (!rec.session) return null;
    const session = rec.session;
    if (light) {
      const { events: _e, evidence: _v, ...rest } = session as BlackboxSession & Record<string, unknown>;
      setCurrent((prev) => (prev && prev.id === sessionId ? { ...prev, ...rest } : session));
    } else {
      const { events: _e, evidence: _v, ...rest } = session as BlackboxSession & Record<string, unknown>;
      setCurrent((prev) => (prev && prev.id === sessionId ? { ...prev, ...rest } : rest as BlackboxSession));
      setEvents([]); setEvidence([]); setEventsTotal(0); setEvidenceTotal(0);
      void loadEvents(sessionId, "newest");
      void loadEvidence(sessionId, true);
    }
    return session;
  }, [projectId, loadEvents, loadEvidence]);

  const loadSessions = useCallback(async (preferredId?: string) => {
    if (!projectId) return;
    const rec = await api<{ items?: BlackboxSession[] }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions`);
    const items = rec.items || [];
    setSessions(items);
    const fromUrl = new URLSearchParams(window.location.search).get("session") || "";
    const nextId = preferredId || fromUrl || selectedId || items.find((item) => item.candidate_id === selectedCandidateId)?.id || items[0]?.id || "";
    setSelectedId(nextId);
    if (!nextId) { setCurrent(null); return; }
    // 首屏先用 light 详情秒开（状态/焦点仪表盘立即可见），非运行中的会话后台再升级为完整详情。
    const cur = await loadCurrentDetail(nextId, true);
    if (cur?.candidate_id) {
      setSelectedCandidateId(cur.candidate_id);
      void ensureCandidate(cur.candidate_id);
    }
    if (cur && cur.status !== "running" && cur.phase !== "stopping") {
      void loadCurrentDetail(nextId, false);
    }
    await loadFocus(nextId);
  }, [projectId, selectedCandidateId, selectedId, loadCurrentDetail, ensureCandidate]);

  useEffect(() => { void loadWorkspace(); }, [loadWorkspace]);
  useEffect(() => {
    if (!projectId) return;
    setSelectedId(params.get("session") || ""); setCurrent(null);
    // 候选池改为远程搜索：初始只拉第一页，不再 limit=5000 全量。
    void loadCandidates();
    const fromUrl = params.get("candidate") || "";
    if (fromUrl) { setSelectedCandidateId(fromUrl); void ensureCandidate(fromUrl); }
    void loadSessions();
    // The URL is the source of truth when switching projects.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => {
    if (!current || (current.status !== "running" && current.phase !== "stopping")) return;
    const sessionId = current.id;
    // 运行中轮询：brief 详情（仅标量状态/环境，几 KB）+ 焦点仪表盘（/focus，小），避免每 1.5s 下载数十 MB。
    const timer = window.setInterval(async () => {
      try {
        const detail = await api<{ session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(sessionId)}?brief=1`);
        if (detail.session) {
          const session = detail.session;
          setCurrent((prev) => (prev ? { ...prev, status: session.status, phase: session.phase, environment: session.environment, cookie_count: session.cookie_count } : session));
        }
        const list = await api<{ items?: BlackboxSession[] }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions`);
        setSessions(list.items || []);
        void loadFocus(sessionId);
        // 时间线粘顶自动刷：拉取最新事件；若用户在顶部则自然跟随，否则累加"新事件"药丸。
        void loadEvents(sessionId, "newer");
      } catch { /* 瞬时网络抖动忽略，下一轮再试 */ }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [current?.id, current?.status, current?.phase, projectId]);

  async function selectSession(id: string) {
    setSelectedId(id);
    // 用户主动点开：拉完整详情（含 events/evidence），用于审阅。
    const detail = await loadCurrentDetail(id, false);
    if (detail?.candidate_id) { setSelectedCandidateId(detail.candidate_id); void ensureCandidate(detail.candidate_id); }
    await loadFocus(id);
  }

  async function createSession() {
    if (!projectId || !selectedCandidateId) { setFlash("work", "请先选择资产", "bad"); return; }
    setBusy("create");
    try {
      const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions`, {
        method: "POST", body: JSON.stringify({ candidate_id: selectedCandidateId }),
      });
      if (!rec.ok || !rec.session) { setFlash("work", rec.error || "创建失败", "bad"); return; }
      await checkEnvironment(rec.session.id, false);
      await loadSessions(rec.session.id);
      setFlash("work", "黑盒会话已创建", "ok");
    } finally { setBusy(""); }
  }

  // A session created from the asset page arrives at phase=environment_check; run the
  // check once so the operator does not have to click it again after the jump.
  const autoChecked = useRef("");
  useEffect(() => {
    if (!current || current.status !== "pending" || busy) return;
    if (autoChecked.current === current.id) return;
    autoChecked.current = current.id;
    void checkEnvironment(current.id, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current?.id, current?.status, busy]);

  async function checkEnvironment(sessionId = current?.id || "", showFlash = true) {
    if (!sessionId) return;
    setBusy("check");
    const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(sessionId)}/check`, { method: "POST", body: "{}" });
    if (rec.session) setCurrent(rec.session);
    if (showFlash) setFlash("work", rec.ok ? (rec.session?.environment?.ready ? "环境检查通过" : "Burp 不可用，会话已暂停") : rec.error || "检查失败", rec.ok && rec.session?.environment?.ready ? "ok" : "bad");
    setBusy("");
  }

  async function changeState(action: "pause" | "resume" | "cancel") {
    if (!current) return;
    setBusy(action);
    const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/${action}`, { method: "POST", body: "{}" });
    if (rec.session) { setCurrent(rec.session); await loadSessions(rec.session.id); }
    if (!rec.ok) setFlash("work", rec.error || "操作失败", "bad");
    setBusy("");
  }

  /** 批量删除：会话列表多选、或清空项目里所有非运行中会话。 */
  async function deleteSessions(payload: { ids?: string[]; all?: boolean }): Promise<void> {
    setBusy("delete");
    try {
      const rec = await api<{ ok?: boolean; error?: string; deleted?: string[]; skipped?: Array<{ id: string; reason: string }> }>(
        `/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions`,
        { method: "DELETE", body: JSON.stringify(payload) },
      );
      if (!rec.ok) { setFlash("work", rec.error || "删除失败", "bad"); return; }
      const deleted = (rec.deleted || []).length;
      const skipped = rec.skipped || [];
      if (payload.all || (rec.deleted || []).includes(current?.id || "")) {
        // 当前打开的那个被删了（或被清空），回到空状态
        if (!current || payload.all || (rec.deleted || []).includes(current.id)) {
          setCurrent(null);
          setSelectedId("");
          const next = new URLSearchParams(params);
          next.delete("session");
          setParams(next, { replace: true });
        }
      }
      setPicked(prev => prev.filter(id => !(rec.deleted || []).includes(id)));
      await loadSessions("");
      setFlash(
        "work",
        skipped.length
          ? `已删除 ${deleted} 个会话；${skipped.length} 个跳过（${skipped[0]!.reason}）`
          : `已删除 ${deleted} 个会话`,
        skipped.length ? "bad" : "ok",
      );
    } finally { setBusy(""); }
  }

  /** 删除整个资产分组：连会话、证据、产物、候选一起没。 */
  async function purgeGroup(): Promise<void> {
    if (!purgeTarget) return;
    setBusy("purge");
    try {
      const rec = await api<{ ok?: boolean; error?: string; deleted?: { sessions?: number } }>(
        `/api/projects/${encodeURIComponent(purgeTarget.id)}`, { method: "DELETE" },
      );
      if (!rec.ok) { setFlash("work", rec.error || "删除分组失败", "bad"); return; }
      setFlash("work", `已删除分组「${purgeTarget.name}」（含 ${rec.deleted?.sessions ?? 0} 个会话）`, "ok");
      setPurgeTarget(null);
      setCurrent(null); setSelectedId(""); setPicked([]);
      const next = new URLSearchParams(params);
      next.delete("session"); setParams(next, { replace: true });
      await loadWorkspace();
      await loadSessions("");
    } finally { setBusy(""); }
  }

  async function deleteSession() {
    if (!current) return;
    setBusy("delete");
    try {
      const rec = await api<{ ok?: boolean; error?: string }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}`, { method: "DELETE" });
      if (!rec.ok) { setFlash("work", rec.error || "删除失败", "bad"); return; }
      setCurrent(null);
      setSelectedId("");
      const next = new URLSearchParams(params);
      next.delete("session");
      setParams(next, { replace: true });
      await loadSessions("");
      setFlash("work", "会话已删除", "ok");
    } finally { setBusy(""); }
  }


  async function clearCookies() {
    if (!current) return;
    setBusy("cookies");
    const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/cookies`, { method: "DELETE", body: "{}" });
    if (rec.session) setCurrent(rec.session);
    if (!rec.ok) setFlash("work", rec.error || "清空 Cookie 失败", "bad");
    else setFlash("work", "项目 Cookie 已清空（所有会话共享）", "ok");
    setBusy("");
  }

  /** 焦点仪表盘的人工干预：强制收口 / 手动延期 1 轮 / 切换焦点。 */
  async function focusAction(action: "converge" | "extend" | "switch" | "restore", taskId = "") {
    if (!current) return;
    setBusy(`focus:${action}`);
    try {
      const rec = await api<FocusState & { ok?: boolean; error?: string }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/focus`, {
        method: "POST", body: JSON.stringify({ action, task_id: action === "switch" ? focusSwitchTo : taskId }),
      });
      if (!rec.ok) { setFlash("work", rec.error || "焦点操作失败", "bad"); return; }
      setFocus(rec);
      const label = action === "converge" ? "已强制收口，焦点将自动切换"
        : action === "extend" ? "已延期 1 轮"
        : action === "restore" ? `已撤销收口：${(rec as { restored?: string[] }).restored?.join("、") || "全部"}`
        : `焦点已切到 ${focusSwitchTo}`;
      setFlash("work", label, "ok");
      await loadSessions();
    } finally { setBusy(""); }
  }

  async function addInstruction() {
    if (!current || !prompt.trim()) return;
    setBusy("instruction");
    const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/instruction`, {
      method: "POST", body: JSON.stringify({ text: prompt.trim() }),
    });
    if (rec.session) { setCurrent(rec.session); setPrompt(""); await loadSessions(rec.session.id); }
    if (!rec.ok) setFlash("work", rec.error || "指令保存失败", "bad");
    setBusy("");
  }

  async function runAgents() {
    if (!current) return;
    setBusy("run");
    const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/run`, { method: "POST", body: "{}" });
    if (rec.session) { setCurrent(rec.session); await loadSessions(rec.session.id); }
    setFlash("work", rec.ok ? "动态任务已启动，主 Agent 将持续推进" : rec.error || "Agent 启动失败", rec.ok ? "ok" : "bad");
    setBusy("");
  }

  async function openFork() {
    if (!current) return;
    setForkBusy("list");
    const rec = await api<{ ok?: boolean; error?: string; items?: Array<{ id: number; run_index: number; label: string; created_at: number; bytes: number }> }>(
      `/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/checkpoints`);
    setForkBusy("");
    if (!rec.ok) { setFlash("work", rec.error || "读取快照失败", "bad"); return; }
    setCheckpoints(rec.items || []);
    setForkOpen(true);
  }

  async function doFork(checkpointId: number) {
    if (!current) return;
    setForkBusy(`fork-${checkpointId}`);
    const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(
      `/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/fork`,
      { method: "POST", body: JSON.stringify({ checkpoint_id: checkpointId }) });
    setForkBusy("");
    if (!rec.ok || !rec.session) { setFlash("work", rec.error || "fork 失败", "bad"); return; }
    setForkOpen(false);
    await loadSessions(rec.session.id);
    setFlash("work", `已从快照 fork 出新会话 ${rec.session.id}（账本一致，可直接点「持续执行任务」）`, "ok");
  }

  async function submitReview() {
    if (!current || !review || !reviewReason.trim()) return;
    setBusy("review");
    try {
      const rec = await api<{ ok?: boolean; error?: string; session?: BlackboxSession }>(`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/review`, { method: "POST", body: JSON.stringify({ ...review, reason: reviewReason.trim() }) });
      if (!rec.ok) { setFlash("work", rec.error || "复核失败", "bad"); return; }
      if (rec.session) setCurrent(rec.session);
      setReview(null); setReviewReason("");
      setFlash("work", "复核已保存", "ok");
    } finally { setBusy(""); }
  }

  // 控制面可能跑在只读模式（inspect/serve）：此时检查环境与执行都会被后端拒绝，
  // 按钮必须先禁用并说明原因，而不是点下去等一个 403。
  const executionMode = (consoleStatus?.execution?.mode as string) || "serve";
  const canExecute = executionMode === "execute";

  const candidateOptions = useMemo(() => candidates.map((item) => ({ value: item.id, label: `${item.title || item.hostname || item.value} · ${item.agent_score ?? item.score ?? 0}分` })), [candidates]);
  const environment = current?.environment;
  const status = current ? (statusLabel[current.status] || current.status) : "等待选择";
  const evidenceCount = evidenceTotal || current?.evidence_count || 0;
  const eventCount = eventsTotal || current?.event_count || 0;
  const runSummary = current?.run_summary;
  const runBudget = (runSummary?.data?.budget || {}) as Record<string, number | string>;
  const taskGroups = [
    ["completed_tasks", "已完成"], ["failed_tasks", "失败"], ["blocked_tasks", "受阻"], ["pending_tasks", "未执行 / 未完成"],
  ] as const;
  // 主 Agent 上报的工具缺口（checkpoint.linkage.tool_gaps）：missing=true 表示 74 项清单里确实没有。
  const toolGaps = ((current?.checkpoint as unknown as {
    linkage?: { tool_gaps?: Array<{ need: string; tool?: string; alternative?: string; why?: string; missing?: boolean }> };
  })?.linkage?.tool_gaps) || [];

  // ── 仪表盘派生值：一处算清，JSX 里只做展示 ──
  const focusMaxTurns = focus?.usage?.max_turns || focus?.limits?.max_turns_per_task || 0;
  const focusMaxTp = focus?.usage?.max_tp || focus?.limits?.max_tp_per_task || 0;
  const focusStall = focus?.limits?.stall_rounds || 0;
  const focusTpOf = (tool: string): string => {
    const hit = (focus?.tp_table || []).find(row => row.tool === tool);
    return hit ? `${hit.tp} TP` : "—";
  };
  const focusTone = focus?.macro_interrupt ? "bad" : focus?.convergence ? "warn" : focus ? "ok" : "flat";
  const focusState = focus?.macro_interrupt ? "frozen" : focus?.convergence ? "closing" : focus ? "normal" : "unknown";
  const focusStateLabel = focus
    ? (focus.macro_interrupt ? "宏观熔断" : focus.convergence ? (focus.convergence.appealed ? "申诉宽限中" : "待收口") : "正常")
    : focusError ? "接口不可用" : "加载中";

  return <main className="blackbox-page">
      <Modal title="时光机：从历史 run 的快照 fork" open={forkOpen} footer={null} onCancel={() => setForkOpen(false)}>
        <p className="section-note">每次点「持续执行任务」前都会归档一份账本快照。fork 出来的是**新会话**：账本一致、证据不复制，用来做改前/改后对照。</p>
        {!checkpoints.length ? <p className="empty-hint">还没有快照：先点一次「持续执行任务」，快照会自动归档。</p> : (
          <div className="session-list">
            {checkpoints.map((item) => (
              <div key={item.id} className="session-row">
                <span>第 {item.run_index} 次 run · {new Date(item.created_at * 1000).toLocaleString("zh-CN")} · {Math.round(item.bytes / 1024)} KB</span>
                <Button size="small" loading={forkBusy === `fork-${item.id}`} onClick={() => void doFork(item.id)}>从这里 fork</Button>
              </div>
            ))}
          </div>
        )}
      </Modal>
    <Modal title="记录人工决策" open={Boolean(review)} onCancel={() => { setReview(null); setReviewReason(""); }} onOk={() => void submitReview()} confirmLoading={busy === "review"} okButtonProps={{ disabled: !reviewReason.trim() }}><p>{review?.id} · {review?.action}</p><Input.TextArea value={reviewReason} onChange={event => setReviewReason(event.target.value)} maxLength={2000} rows={4} placeholder="说明确认、拒绝或需要补充证据的依据；漏洞确认需结合复现证据。" /></Modal>
    <Flash id="work" flash={flash} />
    {canExecute ? null : (
      <Alert
        type="warning" showIcon style={{ marginBottom: 14 }}
        message={`控制面当前是 ${executionMode} 模式（只读）：「检查环境」和「持续执行任务」会被后端拒绝`}
        description={<span>需要执行能力时，用 <Typography.Text code>NIANYUN_MODE=execute</Typography.Text> 重启控制面容器（compose 里设同名的环境变量）。只读模式下仍可查看会话、证据和历史报告。</span>}
      />
    )}
    <div className="blackbox-head"><div><p className="kicker">AUTHORIZED BLACKBOX WORKSPACE</p><h1>黑盒会话</h1><p className="page-lede">围绕一个目标持续积累页面、请求、截图与 Agent 判断。<span className="section-note"> · 前端构建 {typeof __NIANYUN_BUILD__ === "string" ? __NIANYUN_BUILD__ : "dev"}</span></p></div><div className="blackbox-head-actions"><Tag color={focus?.focus_task_id ? "blue" : "default"} className="focus-badge">{focus?.focus_task_id ? `焦点 ${focus.focus_task_id} · ${focus.usage?.turns || 0}/${focus.usage?.max_turns || focus?.limits?.max_turns_per_task || "∞"} 轮 · ${focus.usage?.tp || 0}/${focus.usage?.max_tp || focus?.limits?.max_tp_per_task || "∞"} TP` : focusError ? "焦点接口不可用" : "焦点 —"}</Tag>{busy === "check" ? <span className="section-note">检查中：连通性 + 每个工具空跑校验，约 5–10 秒…</span> : null}<Button type="primary" onClick={() => void runAgents()} loading={busy === "run"} disabled={!canExecute || !current || !environment?.ready || current.status === "running" || current.status === "cancelled" || current.phase === "stopping"}>持续执行任务</Button><Button onClick={() => void openFork()} loading={forkBusy === "list"} disabled={!current}>时光机</Button><Button onClick={() => void checkEnvironment()} loading={busy === "check"} disabled={!canExecute || !current || current.status === "running" || current.phase === "stopping"}>检查环境</Button>{current?.status === "paused" ? <Button onClick={() => void changeState("resume")} loading={busy === "resume"} disabled={current.phase === "stopping"}>恢复会话</Button> : <Button onClick={() => void changeState("pause")} loading={busy === "pause"} disabled={!current || current.status === "cancelled" || current.phase === "stopping"}>暂停会话</Button>}<Button onClick={() => Modal.confirm({ title: "清空项目 Cookie？", content: "将清空该项目的共享 Cookie jar，影响所有黑盒会话；已写入证据的请求记录不会改变。", onOk: () => void clearCookies() })} loading={busy === "cookies"} disabled={!current || current.status === "running" || current.phase === "stopping"}>清空项目 Cookie</Button></div></div>
    <div className="blackbox-createbar"><div><span className="blackbox-create-label">从资产候选池创建会话</span><Select value={selectedCandidateId || undefined} onChange={setSelectedCandidateId} options={candidateOptions} showSearch filterOption={false} loading={candidateLoading} onSearch={(value) => void loadCandidates(value)} placeholder="搜索并选择目标资产" notFoundContent={candidateLoading ? "加载中…" : "无匹配资产"} /></div><Button type="primary" onClick={() => void createSession()} loading={busy === "create"} disabled={!selectedCandidateId}>新建会话</Button></div>
    <div className="blackbox-grid">
      <Card className="blackbox-sessions" title={<div className="card-title-row"><span>会话列表</span><span className="count-badge">{sessions.length}</span></div>}>
        <Select value={projectId || undefined} onChange={(value) => setParams({ project: value })} options={projects.map((item) => ({ value: item.id, label: item.name }))} placeholder="选择资产分组" style={{ width: "100%", marginBottom: 12 }} />
        {!sessions.length ? <p className="empty-hint">从资产候选池选择资产并创建会话。</p> : <>
          <div className="session-toolbar">
            <Checkbox
              className="session-all"
              checked={picked.length > 0 && picked.length === sessions.length}
              indeterminate={picked.length > 0 && picked.length < sessions.length}
              onChange={(event) => setPicked(event.target.checked ? sessions.map((item) => item.id) : [])}
            >全选</Checkbox>
            <span className="session-tally">{picked.length ? `${picked.length}/${sessions.length}` : `${sessions.length} 个会话`}</span>
            <Dropdown
              trigger={["click"]}
              placement="bottomRight"
              menu={{
                items: [
                  { key: "picked", danger: true, disabled: !picked.length, icon: <DeleteOutlined />, label: picked.length ? `删除选中 ${picked.length} 个` : "删除选中" },
                  { key: "all", danger: true, icon: <DeleteOutlined />, label: "清空本组会话" },
                  { type: "divider" as const },
                  { key: "group", danger: true, icon: <DeleteOutlined />, label: "删除整个资产分组" },
                ],
                onClick: ({ key }) => {
                  if (key === "picked") Modal.confirm({ title: `删除选中的 ${picked.length} 个会话？`, content: "时间线、证据和产物文件会一起删除，不可恢复。运行中的会话会被跳过。", okText: "确认删除", okButtonProps: { danger: true }, cancelText: "取消", onOk: () => void deleteSessions({ ids: picked }) });
                  if (key === "all") Modal.confirm({ title: "清空本组所有会话？", content: `共 ${sessions.length} 个会话会被删除（时间线、证据、产物一起清掉），不可恢复。运行中的会话会被跳过。`, okText: "全部删除", okButtonProps: { danger: true }, cancelText: "取消", onOk: () => void deleteSessions({ all: true }) });
                  if (key === "group") setPurgeTarget({ id: projectId, name: projects.find((item) => item.id === projectId)?.name || projectId, sessions: sessions.length });
                },
              }}
            >
              <Button size="small" icon={<MoreOutlined />} aria-label="批量操作">批量</Button>
            </Dropdown>
          </div>
          <div className="session-list">
            {sessions.map((item) => (
              <div className={`session-card ${item.id === current?.id ? "active" : ""}`} key={item.id}>
                <Checkbox
                  className="session-pick"
                  checked={picked.includes(item.id)}
                  onChange={(event) => setPicked((prev) => event.target.checked ? [...prev, item.id] : prev.filter((id) => id !== item.id))}
                />
                <button type="button" className="session-main" onClick={() => void selectSession(item.id)} title={item.target}>
                  <span className="session-target">{item.target}</span>
                  <span className="session-meta">
                    <span className={`status-pill ${item.status}`}>{statusLabel[item.status] || item.status}</span>
                    <span className="session-time">{new Date(item.updated_at * 1000).toLocaleString()}</span>
                  </span>
                </button>
                <Tooltip title="删除该会话（含时间线、证据、产物）">
                  <Button
                    className="session-del" type="text" size="small" danger icon={<DeleteOutlined />}
                    aria-label={`删除会话 ${item.target}`}
                    disabled={busy === "delete" || item.status === "running" || item.phase === "stopping"}
                    onClick={() => Modal.confirm({ title: "删除该黑盒会话？", content: `目标 ${item.target} 的时间线、证据和产物文件都会删除，删除后不可恢复。`, okText: "确认删除", okButtonProps: { danger: true }, cancelText: "取消", onOk: () => void deleteSessions({ ids: [item.id] }) })}
                  />
                </Tooltip>
              </div>
            ))}
          </div>
        </>}
      </Card>
      <section className="blackbox-main">
        {current && (current.checkpoint?.rule_issues || []).some(issue => String(issue).includes("已废弃")) && (
          <Alert
            type="warning" showIcon banner style={{ marginBottom: 12 }}
            message="检测到已废弃的规则项"
            description={<>{current.checkpoint?.rule_issues?.filter(issue => String(issue).includes("已废弃")).map((issue, index) => <div key={index}>{issue}</div>)}</>}
          />
        )}
        {current && (
          <section className="focus-dashboard" data-state={focusState}>
            <header className="focus-head">
              <div className="focus-head-main">
                <span className="focus-eyebrow">FOCUS LOCK · 微观预算</span>
                <div className="focus-head-title">
                  <h3 className="focus-task"><span className="focus-task-id">{focus?.focus_task_id || "—"}</span></h3>
                  <span className="focus-pill" data-tone={focusTone}>{focusStateLabel}</span>
                  <span className="focus-head-note">{focus?.reason || ""}</span>
                </div>
                <p className="focus-head-detail">{focus?.detail || (focusError ? `焦点接口不可用：${focusError}` : "正在读取焦点数据…")}</p>
              </div>
              <button type="button" className="focus-refresh" onClick={() => void loadFocus(current.id)} title="重新读取焦点数据">
                <ReloadOutlined /> 刷新
              </button>
            </header>

            {!focus && (
              <Alert
                type={focusError ? "error" : "info"} showIcon className="focus-alert"
                message={focusError ? `焦点接口不可用：${focusError}` : "正在读取焦点数据…"}
                action={<Button size="small" onClick={() => void loadFocus(current.id)}>重试</Button>}
              />
            )}

            <div className="focus-metrics">
              <FocusMetric
                label="轮数" emphasis
                value={`${focus?.usage?.turns || 0}`} suffix={`/ ${focusMaxTurns || "∞"}`}
                percent={focusMaxTurns ? pct(focus?.usage?.turns || 0, focusMaxTurns) : undefined}
                tone={focusMaxTurns ? toneOf(pct(focus?.usage?.turns || 0, focusMaxTurns) / 100) : "flat"}
                note="达到上限即强制收口"
              />
              <FocusMetric
                label="战术点数" emphasis
                value={`${focus?.usage?.tp || 0}`} suffix={`/ ${focusMaxTp || "∞"} TP`}
                percent={focusMaxTp ? pct(focus?.usage?.tp || 0, focusMaxTp) : undefined}
                tone={focusMaxTp ? toneOf(pct(focus?.usage?.tp || 0, focusMaxTp) / 100) : "flat"}
                note={`nuclei ${focusTpOf("recon.nuclei")} · http ${focusTpOf("http.request")} · 慢目标自动涨价`}
              />
              <FocusMetric
                label="停滞轮数"
                value={`${focus?.usage?.no_progress_rounds || 0}`} suffix={`/ ${focusStall || "∞"}`}
                percent={focusStall ? pct(focus?.usage?.no_progress_rounds || 0, focusStall) : undefined}
                tone={focusStall ? toneOf(pct(focus?.usage?.no_progress_rounds || 0, focusStall) / 100) : "flat"}
                note={focusStall && (focus?.usage?.no_progress_rounds || 0) + 1 >= focusStall ? "下一轮无增益即收口" : "连续无增益计数"}
              />
              <FocusMetric
                label="证据增益" emphasis
                value={`+${focus?.usage?.value_score || 0}`}
                note={`高价值 ${focus?.usage?.high_value || 0} · 中价值 ${focus?.usage?.medium_value || 0} · 噪音 ${focus?.usage?.noise || 0}`}
              />
              <FocusMetric
                label="拓扑势能"
                value={focus?.potential?.focus !== undefined ? `${focus.potential.focus}` : "不可达"}
                note={`目标 ${focus?.potential?.goals ?? 0} 个 · 全场最优 ${focus?.potential?.best ?? "-"}（越小越近核心）`}
              />
              <FocusMetric
                label="延迟通胀"
                value={`${focus?.latency?.multiplier || 1}×`}
                note={`均延迟 ${Math.round(focus?.latency?.avg_ms || 0)} ms / 基准 500 ms，上限 3×`}
              />
              <FocusMetric
                label="本场收口"
                value={`${focus?.session_convergences ?? 0}`} suffix={`/ ${focus?.limits?.max_session_convergences || "∞"}`}
                percent={focus?.limits?.max_session_convergences ? pct(focus?.session_convergences || 0, focus.limits.max_session_convergences) : undefined}
                tone={focus?.limits?.max_session_convergences ? toneOf(pct(focus?.session_convergences || 0, focus.limits.max_session_convergences) / 100) : "flat"}
                note={`申诉池剩余 ${focus?.appeals_left ?? focus?.limits?.appeal_pool ?? 0} 次（全局共享）`}
              />
            </div>

            {focus && !focus.usage && (
              <p className="focus-hint">这条会话还没在新预算下跑过：轮数 / TP / 增益从下一次「持续执行任务」开始记账。</p>
            )}

            {focus?.directive && (
              <div className="focus-directive-block">
                <span className="focus-directive-tag">当前指令</span>
                <p className="focus-directive-text">{focus.directive}</p>
              </div>
            )}

            <footer className="focus-actions">
              <Button
                danger size="small" loading={busy === "focus:converge"} disabled={!focus?.focus_task_id}
                onClick={() => focus?.focus_task_id && Modal.confirm({
                  title: `强制收口 ${focus.focus_task_id}？`,
                  content: "收口 = 把这条任务标记为 blocked（原因记作 operator_blocked），焦点自动切到下一条。它不结束会话、不删证据；之后可以用「撤销收口」退回 pending。",
                  okText: "收口", cancelText: "取消", okButtonProps: { danger: true },
                  onOk: () => void focusAction("converge"),
                })}
              >强制收口</Button>
              <Button size="small" loading={busy === "focus:extend"} disabled={!focus?.focus_task_id} onClick={() => void focusAction("extend")}>手动延期 1 轮</Button>
              {(focus?.operator_blocked?.length || 0) > 0 && (
                <Button
                  size="small" type="primary" ghost loading={busy === "focus:restore"}
                  onClick={() => Modal.confirm({
                    title: `撤销 ${focus?.operator_blocked?.length} 条被收口的任务？`,
                    content: `退回 pending 并让焦点回到第一条：${(focus?.operator_blocked || []).join("、")}`,
                    okText: "撤销收口", cancelText: "取消",
                    onOk: () => void focusAction("restore"),
                  })}
                >撤销收口 ({focus?.operator_blocked?.length})</Button>
              )}
              <span className="focus-actions-spacer" />
              <Select
                size="small" style={{ minWidth: 240 }} placeholder="切换焦点至…" value={focusSwitchTo || undefined}
                onChange={(value) => setFocusSwitchTo(value)}
                options={(focus?.tasks || []).map(task => ({ value: task.id, label: `${task.id} · ${task.target || task.purpose || ""}`.slice(0, 72) }))}
              />
              <Button size="small" loading={busy === "focus:switch"} disabled={!focusSwitchTo} onClick={() => void focusAction("switch")}>切换</Button>
            </footer>
          </section>
        )}
        {current && <Card title="执行控制"><div className="blackbox-head-actions"><Button danger disabled={current.status === "cancelled" || current.phase === "stopping"} onClick={() => Modal.confirm({ title: "取消当前会话？", content: "停止执行，保留证据与检查点。取消后请新建会话继续测试。", onOk: () => changeState("cancel") })}>取消会话</Button><Button danger loading={busy === "delete"} disabled={current.status === "running" || current.phase === "stopping"} onClick={() => Modal.confirm({ title: "删除该黑盒会话？", content: `目标 ${current.target} 的时间线、证据和产物文件都会删除，删除后不可恢复。`, okText: "确认删除", okButtonProps: { danger: true }, cancelText: "取消", onOk: () => deleteSession() })}>删除会话</Button><Button href={`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/report?format=markdown`} target="_blank">查看 / 导出 Summary</Button><Button href={`/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/report`} target="_blank">JSON 报告</Button></div><p className="help">所有已注册工具都由主 Agent 直接调用，没有逐动作人工审批；仅受规则文档、预算、重复检测和会话状态约束。</p>{current.checkpoint?.credential_tools?.length ? <p className="help">本次运行开启凭据爆破：{current.checkpoint.credential_tools.join("、")}</p> : null}{current.checkpoint?.rule_issues?.length ? <p className="asset-error">规则文档问题：{current.checkpoint.rule_issues.join(" ")}</p> : null}</Card>}
        {current && <Card title="候选漏洞与人工复核"><p className="help">Observer 只读审阅证据一致性；漏洞最终确认需人工复现。报告区分候选、缺少证据、已审阅、人工确认和拒绝。</p><div className="agent-events">{Object.values(current.checkpoint?.findings || {}).map(finding => <details className="evidence-card" key={finding.id}><summary><Tag>{finding.status}</Tag><Tag>{finding.severity}</Tag>{finding.title}</summary><p>{finding.target}</p><p>{finding.description}</p><p>影响：{finding.impact}</p><ol>{finding.reproduction_steps.map((step, index) => <li key={index}>{step}</li>)}</ol><p>证据：{finding.evidence_ids.join(", ")}</p><p>修复：{finding.remediation}</p><p>复核：{finding.review?.actor} · {finding.review?.reason}</p>{(["confirm", "needs_evidence", "reject"] as const).map(action => <Button key={action} disabled={current.status === "running" || current.status === "cancelled" || current.phase === "stopping" || (action === "confirm" && finding.status !== "reviewed")} onClick={() => setReview({ kind: "finding", id: finding.id, action })}>{action === "confirm" ? "人工确认" : action === "reject" ? "拒绝" : "需要补证"}</Button>)}</details>)}{!Object.keys(current.checkpoint?.findings || {}).length && <p className="empty-hint">尚无候选发现，不代表目标安全。</p>}</div></Card>}
        <div className="blackbox-overview"><Card className="blackbox-target"><div className="target-kicker">当前目标</div><Typography.Text className="target-url" strong>{current?.target || selectedCandidate?.url || selectedCandidate?.value || "未选择资产"}</Typography.Text><div className="target-tags">{selectedCandidate?.tags?.map((item) => <Tag key={item}>{item}</Tag>)}</div>{current && <div className="target-meta"><span className={`status-pill ${current.status}`}>{status}</span><span>{current.phase}</span><span>更新于 {new Date(current.updated_at * 1000).toLocaleTimeString()}</span><span>Cookie {current.cookie_count || 0}</span></div>}</Card><div className="blackbox-metrics"><div><strong>{eventCount}</strong><span>时间线事件</span></div><div><strong>{evidenceCount}</strong><span>证据条目</span></div></div></div>
        <Card className="blackbox-status"><div className="proxy-status"><span className={`status-dot ${environment?.burp?.reachable ? "online" : "offline"}`}>●</span><div><strong>Burp 代理</strong><span>{environment?.burp?.proxy_url || "尚未检查"}</span></div><Tag color={environment?.burp?.reachable ? "green" : "gold"}>{environment?.burp?.reachable ? "已连接" : "未连接"}</Tag></div>{environment?.burp?.error && <p className="asset-error">{environment.burp.error}</p>}<div className="proxy-status"><span className={`status-dot ${environment?.burp?.bridge_reachable ? "online" : "offline"}`}>●</span><div><strong>Burp Bridge 扩展</strong><span>{environment?.burp?.bridge_url || "尚未检查"}</span></div><Tag color={environment?.burp?.bridge_reachable ? "green" : "gold"}>{environment?.burp?.bridge_reachable ? "可读 History / Site map / Issues" : environment?.burp?.bridge_configured ? "不可达" : "未配置 Token"}</Tag></div>{environment?.burp?.bridge_error && <p className="asset-error">{environment.burp.bridge_error}</p>}<div className="proxy-status"><span className={`status-dot ${environment?.target?.reachable ? "online" : "offline"}`}>●</span><div><strong>目标可达性</strong><span>{environment?.target ? (environment.target.url || current?.target || "") : "尚未检查"}</span></div><Tag color={environment?.target?.reachable ? "green" : environment?.target ? "red" : "gold"}>{!environment?.target ? "未检查" : environment.target.reachable ? (environment.target.code === "skipped" ? "已跳过检查" : `HTTP ${environment.target.status ?? "?"} · ${environment.target.bytes ?? 0}B · ${environment.target.elapsed_ms ?? 0}ms`) : "不可达"}</Tag></div>{environment?.target?.reason && <p className="asset-error">{environment.target.reason}</p>}<p className="help">代理用于记录 Agent 的 HTTP/浏览器流量；Bridge 用于读取 Burp 已捕获的 History、Site map 和 Scanner Issues；目标可达性用同一条代理对目标发一次 GET——连不上就不开跑，否则整场预算会烧在代理错误页上。</p></Card>
        {!environment?.ready && current && <div className="blackbox-callout"><strong>运行前需要完成环境检查</strong><span>确认 Burp 代理、目标可达性与工具状态后，才能启动 Agent 分析。</span><Button size="small" onClick={() => void checkEnvironment()} loading={busy === "check"}>立即检查</Button></div>}
        {runSummary && <Card title="最近一次任务验收"><div className="blackbox-run-summary"><Tag>{String(runBudget.stopReason || "unknown")}</Tag><span>工具 {Number(runBudget.toolCalls || 0)} 次</span><span>Agent {Number(runBudget.agentTurns || 0)} 回合</span><span>Token {Number(runBudget.tokens || 0)}</span><span>耗时 {Math.round(Number(runBudget.elapsedMs || 0) / 1000)} 秒</span><span>失败调用 {Number(runBudget.retries || 0)} 次</span></div><p className="help">{runSummary.summary}。恢复执行沿用检查点及累计预算；预算耗尽时需要先提高相应预算。</p><div className="checkpoint-tasks">{taskGroups.map(([key, label]) => {
          const tasks = Array.isArray(runSummary.data?.[key]) ? runSummary.data[key] as string[] : [];
          const states = (runSummary.data?.tasks || {}) as Record<string, { reason?: string; status?: string; outcome_code?: string; outcome_reason?: string; outcome_evidence_ids?: string[]; evidence_ids?: string[] }>;
          /**
           * 结案说明优先 outcome_reason（"为什么被阻止"），`reason` 是创建意图。
           * 两者都空且状态是终态失败时明写"未记录"，不要拿创建理由冒充结果说明。
           */
          const whyOf = (state?: { status?: string; outcome_reason?: string; reason?: string }) => {
            const settled = String(state?.status || "") === "blocked" || String(state?.status || "") === "failed";
            return String(state?.outcome_reason || "").trim() || (settled ? "未记录结案原因" : String(state?.reason || "").trim());
          };
          return <details key={key}><summary>{label} · {tasks.length}</summary><ul>{tasks.map(task => {
            const state = states[task];
            const proof = state?.outcome_evidence_ids?.length ? state.outcome_evidence_ids : state?.evidence_ids;
            return <li key={task}>{task}<span className="help"> — {state?.outcome_code ? `[${state.outcome_code}] ` : ""}{whyOf(state)}{proof?.length ? ` · 证据 ${proof.join(", ")}` : ""}</span></li>;
          })}</ul></details>;
        })}</div></Card>}
        <Card title="给主 Agent 的指令"><Input.TextArea value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="例如：优先梳理登录后的公开接口，只做只读请求，并关注权限边界。" rows={3} /><div className="prompt-footer"><span>指令会写入当前会话上下文</span><Button type="primary" onClick={() => void addInstruction()} loading={busy === "instruction"} disabled={!current || !prompt.trim()}>发送指令</Button></div></Card>
        <Card title={`任务与事实 · 计划版本 ${current?.checkpoint?.planRevision || 0}`}><div className="agent-events"><div className="checkpoint-tasks">
          {Object.entries(current?.checkpoint?.tasks || {}).map(([id, task]) => {
            const record = task as typeof task & { outcome_code?: string; outcome_evidence_ids?: string[] };
            const settled = task.status === "blocked" || task.status === "failed";
            // 终态失败却没有任何说明时不能显示"待处理"：那会让读者以为还有后续动作。
            const why = String(record.outcome_reason || "").trim() || (settled ? "未记录（只标了状态，没写原因）" : "待处理");
            const proof = record.outcome_evidence_ids?.length ? record.outcome_evidence_ids : task.evidence_ids;
            return <details key={id}><summary><Tag>{task.status}</Tag>{id}{record.outcome_code ? <span className="help"> · {record.outcome_code}</span> : null}</summary><p>{task.target} · {task.purpose}</p><p className="help">创建原因：{task.reason || "历史任务未记录"}<br />完成条件：{task.completion_criteria || "历史任务未记录"}<br />结果说明：{why}<br />证据：{proof?.join(", ") || "尚未关联完成证据"}</p></details>;
          })}
          <details><summary>Observer 建议处理 · {Object.keys(current?.checkpoint?.advice || {}).length}</summary>{Object.entries(current?.checkpoint?.advice || {}).map(([id, advice]) => <p key={id}><Tag>{advice.status === "accepted" ? "已采纳" : advice.status === "rejected" ? "已拒绝" : "待决策"}</Tag>{id} · {advice.reason || "等待主 Agent 判断"} · {advice.task_ids?.join(", ")}</p>)}</details>
          <details><summary>端点清单 · {Object.keys(current?.checkpoint?.endpoints || {}).length}</summary>{Object.entries(current?.checkpoint?.endpoints || {}).map(([url, fact]) => <p key={url}>{url}<span className="help"> · 证据 {fact.evidence_ids.length} · 任务 {fact.task_ids.join(", ")}</span></p>)}</details>
          <details><summary>工具缺口 · {toolGaps.length}</summary>{toolGaps.length ? toolGaps.map((gap) => <p key={gap.need}><Tag color={gap.missing ? "red" : "gold"}>{gap.missing ? "清单里没有" : "已注册但不够用"}</Tag>{gap.need}<span className="help"> · 点名 {gap.tool || "无"} · 现在兜底 {gap.alternative || "无"}{gap.why ? ` · ${gap.why}` : ""}</span></p>) : <p className="empty-hint">主 Agent 尚未上报工具缺口：缺能力时会写进 tool_gaps，这里列出可采购/可配置的清单。</p>}</details>
        </div></div></Card>
        <Card title={<div className="card-title-row"><span>会话时间线</span><span className="count-badge">{eventCount}</span><span className="section-note">主 Agent / Observer / 工具</span></div>}>
          <div className="agent-events" ref={eventsScrollRef} onScroll={onEventsScroll}>
            {newEventCount > 0 && (
              <button type="button" className="new-events-pill" onClick={() => { if (eventsScrollRef.current) eventsScrollRef.current.scrollTop = 0; setNewEventCount(0); void loadEvents(current!.id, "newer"); }}>
                ↑ {newEventCount} 条新事件
              </button>
            )}
            {events.length ? events.map((event) => <div className={`agent-event ${event.actor}`} key={event.id}><div className="event-marker">●</div><div className="event-body"><div className="event-head"><strong>{actorLabel[event.actor] || event.actor}</strong><Tag>{event.kind}</Tag><span>{new Date(event.created_at * 1000).toLocaleTimeString()}</span></div><p>{event.text}</p></div></div>) : <p className="empty-hint">尚无会话事件。</p>}
            {events.length < eventsTotal && (
              <div className="load-more-bar">
                <Button size="small" loading={eventsLoading} onClick={() => current && void loadEvents(current.id, "older")}>
                  {eventsLoading ? "加载中…" : `加载更早（已显示 ${events.length}/${eventsTotal}）`}
                </Button>
              </div>
            )}
          </div>
        </Card>
        <Card title={<div className="card-title-row"><span>Evidence Ledger</span><span className="count-badge">{evidenceCount}</span></div>}>
          <div className="blackbox-evidence" ref={evidenceScrollRef} onScroll={onEvidenceScroll}>
            {evidence.length ? evidence.map((item) => {
              const filename = item.artifact_path?.split("/").pop();
              const artifactUrl = filename && current ? `/api/projects/${encodeURIComponent(projectId)}/blackbox-sessions/${encodeURIComponent(current.id)}/artifacts/${encodeURIComponent(filename)}` : "";
              return <div className="evidence-card" key={item.id}><div className="evidence-head"><Tag>{item.kind}</Tag><span>{item.source}</span><span>{item.confidence}</span><code>{item.id}</code></div><p>{item.summary}</p>{artifactUrl && item.artifact_path?.endsWith(".png") && <a href={artifactUrl} target="_blank" rel="noreferrer"><img className="blackbox-evidence-image" src={artifactUrl} alt={item.summary} /></a>}{artifactUrl && !item.artifact_path?.endsWith(".png") && <a href={artifactUrl} target="_blank" rel="noreferrer">查看原始工具输出</a>}</div>;
            }) : <p className="empty-hint">环境检查、工具输出、截图与请求响应将在这里留存。</p>}
            {current && evidenceTotal > evidence.length && (
              <div className="load-more-bar">
                <Button size="small" loading={evidenceLoading} onClick={() => current && void loadEvidence(current.id)}>
                  {evidenceLoading ? "加载中…" : `加载更多证据（已显示 ${evidence.length}/${evidenceTotal}）`}
                </Button>
              </div>
            )}
          </div>
        </Card>
      </section>
    </div>
    <DeleteGroupModal target={purgeTarget} busy={busy === "purge"} onCancel={() => setPurgeTarget(null)} onConfirm={() => void purgeGroup()} />
  </main>;
}

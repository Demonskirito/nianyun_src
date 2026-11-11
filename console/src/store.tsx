import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { I18N, translate, type Lang } from "./i18n";
import { api } from "./api";
import type { ConsoleStatus, LlmSettings, Project, ToolsPayload } from "./types";

type Flash = { id: string; msg: string; kind?: string } | null;

type ConsoleState = {
  theme: "light" | "dark";
  lang: Lang;
  t: (key: string, vars?: Record<string, string | number>) => string;
  setTheme: (theme: "light" | "dark") => void;
  setLang: (lang: Lang) => void;
  projects: Project[];
  projectId: string;
  status: ConsoleStatus;
  llm: LlmSettings;
  tools: ToolsPayload | null;
  flash: Flash;
  setFlash: (id: string, msg: string, kind?: string) => void;
  currentProject: () => Project | null;
  displayProjectName: (p: Project | null | undefined) => string;
  displayProjectNote: (p: Project | null | undefined) => string;
  selectProject: (id: string) => Promise<void>;
  loadWorkspace: () => Promise<void>;
  loadStatus: () => Promise<void>;
  loadSettings: () => Promise<void>;
};

const Ctx = createContext<ConsoleState | null>(null);

function readTheme(): "light" | "dark" {
  const v = localStorage.getItem("nianyun-theme");
  return v === "light" ? "light" : "dark";
}

function readLang(): Lang {
  const v = localStorage.getItem("nianyun-lang");
  return v === "en" ? "en" : "zh";
}

export function DeskProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<"light" | "dark">(readTheme);
  const [lang, setLangState] = useState<Lang>(readLang);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState(localStorage.getItem("nianyun-project") || "");
  const [status, setStatus] = useState<ConsoleStatus>({});
  const [llm, setLlm] = useState<LlmSettings>({});
  const [tools, setTools] = useState<ToolsPayload | null>(null);
  const [flash, setFlashState] = useState<Flash>(null);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => translate(I18N[lang], key, vars),
    [lang]
  );

  const setTheme = useCallback((next: "light" | "dark") => {
    setThemeState(next);
    localStorage.setItem("nianyun-theme", next);
    document.documentElement.setAttribute("data-theme", next);
    document.documentElement.style.colorScheme = next;
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute("content", next);
  }, []);

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    localStorage.setItem("nianyun-lang", next);
    document.documentElement.lang = next === "en" ? "en" : "zh-CN";
  }, []);

  useEffect(() => {
    setTheme(theme);
    document.documentElement.lang = lang === "en" ? "en" : "zh-CN";
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const currentProject = useCallback(
    () => projects.find((p) => p.id === projectId) || projects[0] || null,
    [projects, projectId]
  );

  const displayProjectName = useCallback(
    (p: Project | null | undefined) => {
      if (p && p.name === "Ledger" && p.note === "Default book") return t("defaultProject");
      return p ? p.name : t("noProject");
    },
    [t]
  );

  const displayProjectNote = useCallback(
    (p: Project | null | undefined) => {
      if (p && p.note === "Default book") return t("defaultNote");
      return (p && p.note) || t("noNote");
    },
    [t]
  );

  const setFlash = useCallback((id: string, msg: string, kind?: string) => {
    setFlashState({ id, msg, kind });
  }, []);

  const loadStatus = useCallback(async () => {
    try {
      const rec = await api<ConsoleStatus>("/api/status");
      setStatus(rec || {});
    } catch {
      /* keep last */
    }
  }, []);

  const loadWorkspace = useCallback(async () => {
    const rec = await api<{ items?: Project[]; error?: string }>("/api/projects");
    if (!Array.isArray(rec.items)) {
      setFlash("work", rec.error || "无法加载项目数据", "bad");
      return;
    }
    const items = rec.items;
    setProjects(items);
    setProjectId((current) => {
      const next = current && items.some((p) => p.id === current) ? current : (items[0] && items[0].id) || "";
      if (next) localStorage.setItem("nianyun-project", next);
      return next;
    });
  }, [setFlash]);

  const selectProject = useCallback(async (id: string) => {
    if (!id) return;
    setProjectId(id);
    localStorage.setItem("nianyun-project", id);
  }, []);

  const loadSettings = useCallback(async () => {
    const rec = await api<{ llm?: LlmSettings; tools?: ToolsPayload; error?: string }>("/api/settings");
    setLlm(rec.llm || {});
    setTools(rec.tools || null);
  }, []);

  const value = useMemo<ConsoleState>(
    () => ({
      theme,
      lang,
      t,
      setTheme,
      setLang,
      projects,
      projectId,
      status,
      llm,
      tools,
      flash,
      setFlash,
      currentProject,
      displayProjectName,
      displayProjectNote,
      selectProject,
      loadWorkspace,
      loadStatus,
      loadSettings,
    }),
    [
      theme, lang, t, setTheme, setLang, projects, projectId, status, llm, tools, flash, setFlash,
      currentProject, displayProjectName, displayProjectNote, selectProject, loadWorkspace, loadStatus, loadSettings,
    ]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDesk() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useDesk outside provider");
  return ctx;
}

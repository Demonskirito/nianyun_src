import { Suspense, lazy, useEffect } from "react";
import { HashRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import enUS from "antd/locale/en_US";
import { DeskProvider, useDesk } from "./store";
import { antdThemeFor } from "./theme";
import { Shell } from "./components/Shell";
import { HomePage } from "./pages/Home";
import { AssetsPage } from "./pages/Assets";
import { BlackboxPage } from "./pages/Blackbox";
import { SettingsPage } from "./pages/Settings";
import { AuthSeedsPage } from "./pages/AuthSeeds";
import { ToolsPage } from "./pages/Tools";
import { RoutePage } from "./pages/Route";
import { WafLedgerPage } from "./pages/WafLedger";
// Cytoscape 约 500KB：只在真的打开图谱页时才加载，别让其他页面陪着一起下。
const GraphPage = lazy(() => import("./pages/Graph").then(module => ({ default: module.GraphPage })));
import { ToolHealthPage } from "./pages/ToolHealth";
import { RulesPage } from "./pages/Rules";

function Poller() {
  const loc = useLocation();
  const { loadWorkspace, loadStatus } = useDesk();
  const page = loc.pathname.split("/")[1] || "home";

  useEffect(() => {
    void loadWorkspace();
    void loadStatus();
  }, [loadWorkspace, loadStatus]);

  useEffect(() => {
    if (page !== "home") return;
    const tick = () => {
      if (document.visibilityState !== "visible") return;
      void loadWorkspace();
      void loadStatus();
    };
    const id = window.setInterval(tick, 5000);
    return () => window.clearInterval(id);
  }, [page, loadWorkspace, loadStatus]);
  return null;
}

function Themed() {
  const { theme, lang } = useDesk();
  return (
    <ConfigProvider locale={lang === "en" ? enUS : zhCN} theme={antdThemeFor(theme)} button={{ autoInsertSpace: false }}>
      <Poller />
      <Routes>
        <Route element={<Shell />}>
          <Route path="/" element={<Navigate to="/home" replace />} />
          <Route path="/home" element={<HomePage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/blackbox" element={<BlackboxPage />} />
          <Route path="/tools" element={<ToolsPage />} />
          <Route path="/route" element={<RoutePage />} />
          <Route path="/waf" element={<WafLedgerPage />} />
          <Route path="/graph" element={<Suspense fallback={<div style={{ padding: 48 }}>加载图谱引擎…</div>}><GraphPage /></Suspense>} />
          <Route path="/health" element={<ToolHealthPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/auth-seeds" element={<AuthSeedsPage />} />
          <Route path="*" element={<Navigate to="/home" replace />} />
        </Route>
      </Routes>
    </ConfigProvider>
  );
}

export default function App() {
  return (
    <HashRouter>
      <DeskProvider>
        <Themed />
      </DeskProvider>
    </HashRouter>
  );
}

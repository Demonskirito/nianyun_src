import { useNavigate, useLocation, Outlet } from "react-router-dom";
import { Layout, Menu, Typography } from "antd";
import {
  HomeOutlined,
  RadarChartOutlined,
  DesktopOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  ToolOutlined,
  DashboardOutlined,
  NodeIndexOutlined, DeploymentUnitOutlined, ThunderboltOutlined,
  KeyOutlined,
} from "@ant-design/icons";
import { useDesk } from "../store";

const { Sider, Content } = Layout;

const NAV = [
  {
    group: "navGroupWork",
    items: [
      { key: "home", labelKey: "navHome", icon: <HomeOutlined /> },
      { key: "assets", labelKey: "navAssets", icon: <RadarChartOutlined /> },
      { key: "blackbox", labelKey: "navBlackbox", icon: <DesktopOutlined /> },
      { key: "auth-seeds", labelKey: "navAuthSeeds", icon: <KeyOutlined /> },
      { key: "route", labelKey: "navRoute", icon: <NodeIndexOutlined /> },
      { key: "graph", labelKey: "navGraph", icon: <DeploymentUnitOutlined /> },
      { key: "waf", labelKey: "navWaf", icon: <ThunderboltOutlined /> },
    ],
  },
  {
    group: "navGroupSystem",
    items: [
      { key: "tools", labelKey: "navTools", icon: <ToolOutlined /> },
      { key: "health", labelKey: "navHealth", icon: <DashboardOutlined /> },
      { key: "rules", labelKey: "navRules", icon: <SafetyCertificateOutlined /> },
      { key: "settings", labelKey: "navSettings", icon: <SettingOutlined /> },
    ],
  },
] as const;

export function Shell() {
  const { t, theme, setTheme } = useDesk();
  const nav = useNavigate();
  const loc = useLocation();
  const page = loc.pathname.split("/")[1] || "home";
  const activeItem = NAV.map((group) => group.items.find((item) => item.key === page)).find(Boolean);

  return (
    <Layout className="hd-shell">
      <a className="skip" href="#stage">{t("skip")}</a>
      <Sider theme="light" width={220} breakpoint="lg" collapsedWidth={64} className="hd-sider">
        <div className="hd-logo">
          <img src="/mark.jpg?v=coc1" width={32} height={32} alt="" />
          <div>
            <strong>Nianyun</strong>
            <span>{t("brandSub")}</span>
          </div>
        </div>
        <Menu
          theme="light"
          mode="inline"
          selectedKeys={[page]}
          onClick={({ key }) => nav("/" + key)}
          items={NAV.map((g) => ({
            type: "group" as const,
            key: g.group,
            label: t(g.group),
            children: g.items.map((item) => ({
              key: item.key,
              icon: item.icon,
              label: t(item.labelKey),
            })),
          }))}
        />
        <div className="hd-sider-foot">
          <p className="hd-mark" aria-hidden="true">Circle of Circles</p>
        </div>
      </Sider>
      <Layout className="hd-main">
        <header className="hd-toolbar">
          <Typography.Title level={3} className="hd-toolbar-title">{t(activeItem?.labelKey || "navHome")}</Typography.Title>
          <button
            type="button"
            className="theme-toggle"
            aria-label={theme === "dark" ? t("themeToLight") : t("themeToDark")}
            title={theme === "dark" ? t("themeToLight") : t("themeToDark")}
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            <svg className="icon-sun" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <circle cx="12" cy="12" r="4" />
              <path d="M12 2v2m0 16v2M2 12h2m16 0h2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" />
            </svg>
            <svg className="icon-moon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <path d="M20.9 13.1A9 9 0 0 1 10.9 3.1a9 9 0 1 0 10 10Z" />
            </svg>
          </button>
        </header>
        <Content className="hd-content" id="stage">
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
}

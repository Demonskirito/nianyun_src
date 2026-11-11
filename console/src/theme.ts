import type { ThemeConfig } from "antd";
import { theme as antdTheme } from "antd";

export function antdThemeFor(mode: "light" | "dark"): ThemeConfig {
  const dark = mode === "dark";
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: {
      colorPrimary: dark ? "#d0d0d0" : "#4f4f4f",
      colorSuccess: "#52c41a",
      colorWarning: "#fa8c16",
      colorError: "#ff4d4f",
      colorInfo: dark ? "#d0d0d0" : "#4f4f4f",
      borderRadius: 8,
      fontSize: 14,
      fontFamily:
        "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', 'PingFang SC', 'Microsoft YaHei', sans-serif",
      fontFamilyCode: "SFMono-Regular, Consolas, 'Liberation Mono', Menlo, Courier, monospace",
      colorBgLayout: dark ? "#000000" : "#f5f5f5",
      colorText: dark ? "rgba(255, 255, 255, 0.88)" : "rgba(0, 0, 0, 0.88)",
      colorTextSecondary: dark ? "rgba(255, 255, 255, 0.75)" : "rgba(0, 0, 0, 0.65)",
      colorTextTertiary: dark ? "rgba(255, 255, 255, 0.55)" : "rgba(0, 0, 0, 0.45)",
      colorTextDescription: dark ? "rgba(255, 255, 255, 0.65)" : "rgba(0, 0, 0, 0.55)",
    },
    components: {
      Layout: {
        siderBg: dark ? "#1f1f1f" : "#f4f5f7",
        headerBg: dark ? "#141414" : "#ffffff",
        headerHeight: 56,
        headerPadding: "0 24px",
        bodyBg: dark ? "#000000" : "#f5f5f5",
        triggerBg: dark ? "#1f1f1f" : "#f4f5f7",
        triggerColor: dark ? "rgba(255,255,255,0.65)" : "rgba(0,0,0,0.45)",
      },
      Menu: {
        itemBg: "transparent",
        itemColor: dark ? "rgba(255,255,255,0.72)" : "rgba(0,0,0,0.62)",
        itemHoverBg: dark ? "rgba(255,255,255,0.08)" : "#ffffff",
        itemSelectedBg: dark ? "rgba(255,255,255,0.12)" : "#ffffff",
        itemSelectedColor: dark ? "rgba(255,255,255,0.92)" : "#3a3a3a",
        itemActiveBg: dark ? "rgba(255,255,255,0.12)" : "#ffffff",
        itemBorderRadius: 8,
        itemMarginInline: 10,
        itemMarginBlock: 4,
        groupTitleColor: dark ? "rgba(255,255,255,0.35)" : "rgba(0,0,0,0.35)",
        iconSize: 16,
      },
      Card: {
        headerFontSize: 14,
      },
      Statistic: {
        titleFontSize: 14,
      },
      Button: {
        primaryShadow: "none",
        defaultShadow: "none",
        dangerShadow: "none",
        fontWeight: 500,
      },
      Progress: {
        defaultColor: dark ? "#d0d0d0" : "#4f4f4f",
      },
    },
  };
}

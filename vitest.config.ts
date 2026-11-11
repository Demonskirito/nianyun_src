import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts", "console/src/**/*.test.tsx"],
    pool: "forks",
    server: { deps: { external: ["sqlite", "node:sqlite"] } },
    /**
     * 2026-11-07：LLM 出口解耦后会读标准 env 代理。开发机常把 HTTPS_PROXY 指向本地
     * 调试代理，导致 agent 改走 requestThroughProxy() 而绕过测试里的 fetch 桩，
     * 整批 desk 测试拿不到模型响应。单测环境必须是干净的直连；生产容器由
     * compose.control.yaml 显式注入 HTTPS_PROXY，不受这里影响。
     * 代理行为本身在 test/agent-proxy.test.ts 里显式传 env 对象验证。
     */
    env: {
      HTTP_PROXY: "", HTTPS_PROXY: "", http_proxy: "", https_proxy: "",
      ALL_PROXY: "", all_proxy: "", NO_PROXY: "", no_proxy: "",
    },
  },
  ssr: { external: ["node:sqlite", "sqlite"] },
  resolve: {
    alias: [{ find: /^sqlite$/, replacement: "node:sqlite" }],
  },
});

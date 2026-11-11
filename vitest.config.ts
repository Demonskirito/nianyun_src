import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "vitest/config";

// startSandboxService 默认在 /var/lib/nianyun-sandbox/{state,jobs} 建目录。
// 生产容器以 root 运行没问题，但 CI runner 是非 root，直接 EACCES。
// 测试统一指到临时目录；生产路径由 compose / SANDBOX_* 环境变量决定，不受影响。
const sandboxTestRoot = join(tmpdir(), "nianyun-sandbox-test");

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
      SANDBOX_STATE_ROOT: join(sandboxTestRoot, "state"),
      SANDBOX_JOBS_DIR: join(sandboxTestRoot, "jobs"),
    },
  },
  ssr: { external: ["node:sqlite", "sqlite"] },
  resolve: {
    alias: [{ find: /^sqlite$/, replacement: "node:sqlite" }],
  },
});

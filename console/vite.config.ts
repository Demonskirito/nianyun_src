import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 构建戳：控制台页头会显示它，用来回答"我现在跑的是不是新前端"。
// 没有它的时候，判断"焦点仪表盘为什么看不见"只能靠猜浏览器缓存。
const buildStamp = new Date().toISOString().slice(0, 16).replace("T", " ");

export default defineConfig({
  plugins: [react()],
  define: { __NIANYUN_BUILD__: JSON.stringify(buildStamp) },
  publicDir: "public",
  build: {
    outDir: "spa",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8700",
    },
  },
});
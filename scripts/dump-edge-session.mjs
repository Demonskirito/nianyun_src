#!/usr/bin/env node
/**
 * 从你已登录的 Edge 浏览器抽取认证种子，写入 data/auth/<host>.storageState.json。
 *
 * ⚠️ 2026-11 起首选 `scripts/dump-cdp-session.mjs`。本脚本保留是为了兼容旧用法，
 *    两者的 CDP 路线已经共用同一套实现（scripts/lib/session-dump.mjs）。
 *
 * 用法（在仓库根目录执行）：
 *   node scripts/dump-edge-session.mjs --host wanxiaozhi.aliyun.com
 *   # 可选：--port 9222                        DevTools 端口
 *   # 可选：--out  data/auth/xxx.storageState.json
 *   # 可选：--copy-profile                     显式启用「复制资料目录」路线（见下）
 *   # 可选：--edge "C:\...\msedge.exe"         仅在 --copy-profile 时需要
 *
 * 两条路线的现状：
 *
 * 1. **CDP 路线（默认）**——连接已在 9222 端口开启远程调试的浏览器。零拷贝、零重登，
 *    能读到内存里的**会话级 cookie**（登录票据通常就是这一类，且它们从不落盘）。
 *    启动方式见 `node scripts/dump-cdp-session.mjs --help` 或直接跑一次看提示。
 *
 * 2. **复制资料目录路线（--copy-profile）**——把 Edge 用户数据目录复制到临时位置，
 *    用 msedge 本体启动副本再取 storageState。这条路在 **Edge 136+ 上必然失效**：
 *    App-Bound Encryption 把解密密钥绑定到 user-data-dir 的真实路径，路径一变就拒绝
 *    解密全部 cookie，最后只剩明文 localStorage。2026-11 实测 Edge 148 只导出 2 条
 *    WAF 标识、零票据。因此**不再自动回退**到这条路，必须显式 --copy-profile。
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chromium } from "playwright";
import {
  collectStorageState,
  devtoolsJson,
  filterBySiteFamily,
  hasFlag,
  parseArg,
  printLaunchHint,
  report,
} from "./lib/session-dump.mjs";

const argv = process.argv.slice(2);
const host = parseArg(argv, "host");
if (!host) {
  console.error(
    "用法: node scripts/dump-edge-session.mjs --host <主机> [--port 9222] [--out <path>] [--copy-profile] [--edge <msedge.exe>]",
  );
  process.exit(2);
}

const port = Number(parseArg(argv, "port") || 9222);
const wantCopy = hasFlag(argv, "copy-profile");
const out = parseArg(argv, "out") || path.resolve(process.cwd(), "data", "auth", `${host}.storageState.json`);
fs.mkdirSync(path.dirname(out), { recursive: true });

// 逐文件容错复制：正在运行的 Edge 会锁定部分运行时目录（Network / GPUCache / Crashpad 等），
// 这些与登录态无关，跳过即可，不能因为锁文件就让整次导出失败。
function copyDirRobust(src, dst) {
  try {
    fs.mkdirSync(dst, { recursive: true });
  } catch {
    return;
  }
  let entries;
  try {
    entries = fs.readdirSync(src, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const s = path.join(src, e.name);
    const d = path.join(dst, e.name);
    if (e.isDirectory()) copyDirRobust(s, d);
    else {
      try {
        fs.copyFileSync(s, d);
      } catch {
        /* 跳过被锁 / 不可读的文件 */
      }
    }
  }
}

let tmp = null;
let state = null;
let route = "";

try {
  // ---- 路线 1：CDP（默认）----
  let version = null;
  try {
    version = await devtoolsJson(port, "/json/version");
  } catch (e) {
    if (!wantCopy) {
      console.error(`无法连接 DevTools 端口 ${port}: ${e.message}`);
      printLaunchHint(port);
      console.error("\n若确实想走旧的「复制资料目录」路线（Edge 136+ 会失败），加 --copy-profile 重试。");
      process.exit(2);
    }
  }

  if (version) {
    route = "cdp";
    console.log(`已连接 ${version.Browser || "浏览器"}（DevTools ${port}），直接抽取会话。`);
    // 用 ws 地址直连：Playwright 若自己去 fetch /json/version，会被系统代理改写端口。
    const browser = await chromium.connectOverCDP(version.webSocketDebuggerUrl);
    const raw = await collectStorageState(browser);
    state = filterBySiteFamily(raw, host, {});
    // 只读：不调用 browser.close()，那会关掉用户的浏览器。进程退出即可。
  } else {
    // ---- 路线 2：复制资料目录（需显式开启）----
    route = "copy-profile";
    const edgeExe = [
      parseArg(argv, "edge"),
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ]
      .filter(Boolean)
      .find((p) => fs.existsSync(p));
    if (!edgeExe) {
      console.error("找不到 msedge.exe，请用 --edge 指定完整路径");
      process.exit(2);
    }
    const edgeUserData = path.join(process.env.LOCALAPPDATA || "", "Microsoft", "Edge", "User Data");
    if (!fs.existsSync(edgeUserData)) {
      console.error("找不到 Edge 用户数据目录:", edgeUserData);
      process.exit(2);
    }

    tmp = path.join(os.tmpdir(), `nianyun-edge-${Date.now()}`);
    copyDirRobust(edgeUserData, tmp);
    for (const lock of ["SingletonLock", "SingletonCookie", "lockfile"]) {
      for (const base of [tmp, path.join(tmp, "Default")]) {
        try {
          fs.rmSync(path.join(base, lock), { force: true });
        } catch {}
      }
    }
    console.log("已复制 Edge 用户数据到临时目录，用 Edge 本体无头导出。");

    const context = await chromium.launchPersistentContext(tmp, {
      executablePath: edgeExe,
      headless: true,
      args: ["--no-sandbox", "--disable-gpu"],
    });
    try {
      // 副本要先真正打开一次目标站，localStorage 才会被登记、cookie 才会进入状态。
      const probe = await context.newPage();
      await probe.goto(`https://${host}`, { waitUntil: "domcontentloaded", timeout: 30000 }).catch(() => {});
      // persistent context 自己就是 context，直接取它的 storageState。
      const self = await context.storageState();
      state = filterBySiteFamily(
        { contexts: 1, cookies: self.cookies || [], origins: self.origins || [], storageSkipped: [] },
        host,
        {},
      );
    } finally {
      await context.close().catch(() => {});
    }
  }

  fs.writeFileSync(out, JSON.stringify({ cookies: state.cookies, origins: state.origins }, null, 2), "utf8");
  const stats = report(state, { host });
  console.log(`\n已写出: ${out}  (${(fs.statSync(out).size / 1024).toFixed(1)} KB)`);

  if (route === "copy-profile" && stats.session === 0) {
    console.error(`
[诊断] 复制资料目录路线没有抽到任何会话级 cookie —— Edge 136+ 的 App-Bound Encryption
       会拒绝为「换了路径的资料目录」解密 cookie，这是该路线的硬限制，改不了。
       请改用 CDP 路线：
         node scripts/dump-cdp-session.mjs --host ${host}
       （按它打印的启动参数开一个独立资料目录的浏览器，在里面登录后重跑）`);
    process.exitCode = 1;
  } else if (stats.total === 0) {
    console.error(`
[诊断] 该站点家族下没有任何 cookie。浏览器里很可能未登录，或登录的是另一个资料目录。`);
    process.exitCode = 1;
  }
} catch (e) {
  console.error("导出失败:", e instanceof Error ? e.message : e);
  process.exitCode = 1;
} finally {
  if (tmp) {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {}
  }
}

// CDP 的 ws 连接会一直保持，不显式退出进程就会挂在这里。
// （不能靠 browser.close() 收尾——那会真的关掉用户的浏览器。）
process.exit(process.exitCode ?? 0);

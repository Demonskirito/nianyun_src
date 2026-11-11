#!/usr/bin/env node
/**
 * 从**正在运行的**浏览器（Edge / Chrome）里抽取认证种子，写入
 * data/auth/<host>.storageState.json，供黑盒会话开局自动注入。
 *
 * 为什么需要这个脚本，而不是直接读浏览器的 Cookies 数据库：
 *
 *   登录票据（如 aliyun 的 `login_aliyunid_ticket`）通常是 **session cookie**，
 *   即 `expires: -1`。Chromium/Edge 对这类 cookie 只放内存、**从不写入磁盘数据库**。
 *   所以「登录 → 关浏览器 → 读 Cookies 库」这条路拿到的永远是持久 cookie，
 *   一张票都没有。关浏览器这个动作本身就把票销毁了。
 *
 *   唯一可靠的做法是连上**仍在运行**的浏览器，通过 CDP 读内存状态。
 *   而 Edge/Chrome 136+ 又禁止对默认资料目录开 `--remote-debugging-port`，
 *   因此必须用独立资料目录启动，端口作为启动参数传入。
 *
 * 用法（仓库根目录执行）：
 *
 *   # 1) 用独立目录 + 启动参数打开浏览器（只需一次）
 *   & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" `
 *     --user-data-dir="E:\edge-nianyun" --remote-debugging-port=9222 --no-first-run
 *
 *   # 2) 在这个窗口里登录目标站，确认页面显示已登录，**不要关窗口**
 *
 *   # 3) 抽取
 *   node scripts/dump-cdp-session.mjs --host whois.aliyun.com
 *
 * 可选参数：
 *   --port <n>               DevTools 端口，默认 9222
 *   --out <path>             输出路径，默认 data/auth/<host>.storageState.json
 *   --extra-domain <d>       额外保留某站点的 cookie（可重复）。例：--extra-domain alibabacloud.com
 *   --all                    不做站点家族过滤，导出浏览器里全部 cookie（调试用，会混入无关站点）
 *   --quiet                  只打印认证类 cookie，不逐条列出全部
 *   --max-storage-value <n>  localStorage 单条 value 上限（字节），默认 16384。
 *                            埋点 SDK 常塞进上百 KB 缓存，超限的会跳过并在报告里列出
 *
 * 注意：
 *   - 脚本**只读**，不会关闭也不会改动你的浏览器窗口。
 *   - 抽完可以关掉那个浏览器；种子文件里的会话级 cookie 注入新上下文后依然有效，
 *     直到服务端票据过期（这个期限只能实测，无法从 cookie 推算）。
 */

import fs from "node:fs";
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
const port = Number(parseArg(argv, "port") || 9222);
const quiet = hasFlag(argv, "quiet");
const all = hasFlag(argv, "all");
const maxStorageValue = Number(parseArg(argv, "max-storage-value") || 16 * 1024);

if (hasFlag(argv, "help") || argv.includes("-h")) {
  console.log(`从正在运行的浏览器抽取认证种子 → data/auth/<host>.storageState.json

用法:
  node scripts/dump-cdp-session.mjs --host <主机> [选项]

选项:
  --host <主机>            目标主机名（也决定输出文件名），必填
  --port <n>               DevTools 端口，默认 9222
  --out <path>             输出路径，默认 data/auth/<host>.storageState.json
  --extra-domain <d>       额外保留某站点家族的 cookie，可重复
  --all                    不过滤，导出浏览器里全部 cookie（调试用）
  --quiet                  只列认证类 cookie
  --max-storage-value <n>  localStorage 单条上限（字节），默认 16384

前置条件（会话级登录票据只存在于内存，必须趁浏览器开着抽取）:
  & "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" \`
    --user-data-dir="E:\\edge-nianyun" --remote-debugging-port=9222 --no-first-run

  在该窗口登录目标站 → 不要关窗口 → 回到这里执行本脚本。
  脚本只读，不会关闭浏览器。`);
  process.exit(0);
}

// --extra-domain 允许出现多次
const extras = [];
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i] === "--extra-domain") extras.push(argv[i + 1]);
  else if (argv[i].startsWith("--extra-domain=")) extras.push(argv[i].slice("--extra-domain=".length));
}

if (!host) {
  console.error(
    "用法: node scripts/dump-cdp-session.mjs --host <主机> [--port 9222] [--out <path>] [--extra-domain <d>] [--all] [--quiet]",
  );
  process.exit(2);
}

const out = parseArg(argv, "out") || path.resolve(process.cwd(), "data", "auth", `${host}.storageState.json`);

// 1) 探测端口。直连，不走系统代理 —— 见 lib/session-dump.mjs 顶部说明。
let version;
try {
  version = await devtoolsJson(port, "/json/version");
} catch (e) {
  console.error(`无法连接 DevTools 端口 ${port}: ${e.message}`);
  printLaunchHint(port);
  process.exit(2);
}

console.log(`已连接 ${version.Browser || "浏览器"}（DevTools ${port}）`);

// 2) 连接并读取。用 ws 地址直连，避免 Playwright 再去 fetch 一次而被代理改写。
let browser;
try {
  browser = await chromium.connectOverCDP(version.webSocketDebuggerUrl);
} catch (e) {
  console.error(`CDP 连接失败: ${e.message}`);
  printLaunchHint(port);
  process.exit(2);
}

let state;
try {
  const raw = await collectStorageState(browser, { maxValueBytes: maxStorageValue });
  if (!raw.contexts) {
    console.error("连上了浏览器但没有任何 context，无法抽取。");
    process.exit(1);
  }
  state = filterBySiteFamily(raw, host, { extras, all });
} catch (e) {
  console.error("抽取失败:", e.message);
  process.exit(1);
}

// 3) 落盘
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify({ cookies: state.cookies, origins: state.origins }, null, 2), "utf8");

const stats = report(state, { host, quiet });

console.log(`\n已写出: ${out}  (${(fs.statSync(out).size / 1024).toFixed(1)} KB)`);

// 4) 给出导入与后续判据
if (stats.total === 0) {
  console.log(`
[下一步] 抽到 0 条，种子无用。检查：
  - 那个浏览器窗口里是否真的登录了（页面上要看到账号名，不是「登录/注册」）；
  - --host 是否写成了目标站点的主机名；
  - 若登录的是日常浏览器而非 --user-data-dir 指定的窗口，那边读不到。`);
} else if (stats.session === 0 && stats.auth === 0) {
  console.log(`
[下一步] 有 cookie 但没有任何凭据迹象，大概率是匿名态。
  登录后**不要关浏览器**再跑一次；关掉窗口会销毁内存里的会话 cookie。`);
} else {
  console.log(`
[导入黑盒容器] 宿主机 data/auth/ 与容器 /opt/nianyun/data/auth/ 是两个位置：
  docker cp "${out}" nianyun-control-nianyun-1:/opt/nianyun/data/auth/
或控制台 → 左侧「认证种子」→ 填 host + 粘贴 JSON。
注入发生在每次会话打开目标页时，读盘无缓存，导入即生效。`);
}

// 只读操作：绝不调用 browser.close()，那会关掉用户的浏览器。进程直接退出即可。
process.exit(0);

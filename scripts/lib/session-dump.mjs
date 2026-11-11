/**
 * 认证种子抽取的共享逻辑。
 *
 * 这里集中三件容易写错、且两个入口脚本都要用的事：
 *
 * 1. **连本地 DevTools 端口必须绕过系统代理**。
 *    宿主机常把 HTTP_PROXY 指向抓包代理（Burp / nianyun 的 sandbox-cli）。
 *    Node 22 的 fetch 会读这些环境变量，把 `127.0.0.1:9222` 的请求也交给代理；
 *    而 CDP 的 `/json/version` 返回的 `webSocketDebuggerUrl` 用的是**请求的 Host 头**，
 *    于是 ws 地址被改写成代理端口，连接直接 `socket hang up`。
 *    用 node:http 直连（它不读代理环境变量）就绕开了。
 *
 * 2. **CM 连接不能 close**。`chromium.connectOverCDP()` 拿到的 browser 调用
 *    `browser.close()` 会真的关掉用户的浏览器窗口（连带未保存的登录态）。
 *    抽取是只读操作，读完让进程自己退出即可。
 *
 * 3. **过滤要按站点家族，而不是字符串后缀**。
 *    `"notaliyun.com".endsWith("aliyun.com")` 是 true，会被误留。
 */

import http from "node:http";

/** 解析 `--name value` / `--name=value` 两种写法。 */
export function parseArg(argv, name) {
  const i = argv.findIndex((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i === -1) return undefined;
  const token = argv[i];
  return token.includes("=") ? token.slice(token.indexOf("=") + 1) : argv[i + 1];
}

export function hasFlag(argv, name) {
  return argv.some((a) => a === `--${name}`);
}

/** 取可注册域（approximation：末两段）。co.uk 这类多段后缀走 --registrable 覆盖。 */
export function registrableDomain(host) {
  const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : parts.join(".");
}

/** host 是否落在 domain 上（domain 可带前导点）。带边界判断，避免 notaliyun.com 误命中。 */
export function domainMatchesHost(host, domain) {
  const h = String(host || "").toLowerCase();
  const d = String(domain || "").replace(/^\./, "").toLowerCase();
  if (!h || !d) return false;
  return h === d || h.endsWith(`.${d}`);
}

/**
 * 直连本地 DevTools 的 HTTP 端点，不经过系统代理。
 * 显式指定 host/port 而不是传 URL 字符串，node:http 就不会去查 HTTP_PROXY。
 */
export function devtoolsJson(port, pathname = "/json/version", timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path: pathname, method: "GET", timeout: timeoutMs },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          if (res.statusCode !== 200) {
            reject(new Error(`DevTools 端点返回 HTTP ${res.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error("DevTools 端点返回的不是 JSON"));
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error(`连接 127.0.0.1:${port} 超时`)));
    req.on("error", reject);
    req.end();
  });
}

/**
 * 合并浏览器里所有 context 的 storageState。
 * 用户可能开着 InPrivate/多窗口，各自有独立 context，漏掉一个就少一批 cookie。
 * 同一 (domain, path, name) 后者覆盖前者。
 *
 * 注意 `origins`（localStorage / sessionStorage）：Playwright 在 connectOverCDP 下
 * `storageState()` **只回 cookies，origins 恒为空**——它不会替你翻每个页面的 Web Storage。
 * 而纯前端 token 鉴权的 SPA 恰恰只把凭据放在 localStorage 里，漏了这份种子等于废的。
 * 所以这里按页面补读一次（只读 getItem，不写入、不触发任何业务逻辑）。
 */
export async function collectStorageState(
  browser,
  { includeStorage = true, maxPages = 60, maxValueBytes = 16 * 1024 } = {},
) {
  const contexts = browser.contexts();
  const cookies = new Map();
  const origins = new Map();
  const storageSkipped = [];

  for (const ctx of contexts) {
    let state;
    try {
      state = await ctx.storageState();
    } catch {
      continue; // 单个 context 读不到不致命
    }
    for (const c of state.cookies || []) {
      cookies.set(`${c.domain}|${c.path || "/"}|${c.name}`, c);
    }
    for (const o of state.origins || []) {
      const prev = origins.get(o.origin) || { origin: o.origin, localStorage: [] };
      // 同一 origin 在多 context 出现时按名字合并，本地优先保留先读到的值
      const seen = new Set(prev.localStorage.map((it) => it.name));
      for (const it of o.localStorage || []) if (!seen.has(it.name)) prev.localStorage.push(it);
      origins.set(o.origin, prev);
    }
  }

  if (includeStorage) {
    const seenPages = new Set();
    let budget = maxPages;
    for (const ctx of contexts) {
      for (const page of ctx.pages()) {
        if (budget <= 0) break;
        let url = "";
        try {
          url = page.url();
        } catch {
          continue;
        }
        if (!/^https?:/i.test(url) || seenPages.has(url)) continue;
        seenPages.add(url);
        budget -= 1;

        const origin = (() => {
          try {
            return new URL(url).origin;
          } catch {
            return "";
          }
        })();
        if (!origin) continue;

        let data;
        try {
          // 体积过滤放在浏览器侧做：埋点 SDK 常把上百 KB 的缓存塞进 localStorage，
          // 传回宿主再丢掉等于白传一趟，还会把种子文件撑大十几倍。
          data = await page.evaluate((limit) => {
            const skipped = [];
            const dump = (store, tag) => {
              const out = [];
              try {
                for (let i = 0; i < store.length; i += 1) {
                  const k = store.key(i);
                  if (k == null) continue;
                  const v = String(store.getItem(k) ?? "");
                  if (v.length > limit) {
                    skipped.push({ name: k, bytes: v.length, store: tag });
                    continue;
                  }
                  out.push({ name: k, value: v });
                }
              } catch {
                /* 隐私模式或被策略禁用 */
              }
              return out;
            };
            return {
              localStorage: dump(window.localStorage, "localStorage"),
              sessionStorage: dump(window.sessionStorage, "sessionStorage"),
              skipped,
            };
          }, maxValueBytes);
        } catch {
          continue; // 页面正在跳转 / 被 CSP 限制 / 已关闭
        }

        for (const s of data.skipped || []) storageSkipped.push({ ...s, origin });

        const prev = origins.get(origin) || { origin, localStorage: [], sessionStorage: [] };
        const mergeInto = (key, items) => {
          const names = new Set((prev[key] || []).map((it) => it.name));
          for (const it of items || []) if (!names.has(it.name)) (prev[key] ||= []).push(it);
        };
        mergeInto("localStorage", data.localStorage);
        mergeInto("sessionStorage", data.sessionStorage);
        origins.set(origin, prev);
      }
    }
  }

  return { contexts: contexts.length, cookies: [...cookies.values()], origins: [...origins.values()], storageSkipped };
}

/**
 * 按站点家族过滤：保留「host 的祖先域」和「同一可注册域下的其它子域」。
 *
 * 为什么保留同族子域：用户要的往往是 `*.aliyun.com` 这一整片登录态，
 * 而不是单个 whois 页面的几十条 cookie。注入端只按目标 host 匹配，
 * 多留的不会串味，少留的却要重新导一次。
 */
export function filterBySiteFamily(state, host, { extras = [], all = false } = {}) {
  if (all) return state;

  const roots = new Set([registrableDomain(host), ...extras.map((e) => String(e).replace(/^\./, "").toLowerCase())]);

  const inFamily = (value) => {
    const d = String(value || "").replace(/^\./, "").toLowerCase();
    if (!d) return false;
    for (const r of roots) {
      if (d === r || d.endsWith(`.${r}`) || r.endsWith(`.${d}`)) return true;
    }
    return false;
  };

  return {
    contexts: state.contexts,
    cookies: state.cookies.filter((c) => inFamily(c.domain)),
    origins: state.origins.filter((o) => {
      try {
        return inFamily(new URL(o.origin).hostname);
      } catch {
        return false;
      }
    }),
    storageSkipped: (state.storageSkipped || []).filter((s) => inFamily(new URL(s.origin).hostname)),
  };
}

/** 认证类 cookie 的启发式判定——只用于高亮，不用于过滤。 */
const AUTH_HINT = /ticket|token|auth|sso|session|hssid|login|cookie2|munb|jwt|sid/i;

export function classifyCookie(cookie) {
  const expires = Number(cookie.expires ?? -1);
  const isSession = !Number.isFinite(expires) || expires <= 0;
  return {
    name: String(cookie.name || ""),
    domain: String(cookie.domain || ""),
    bytes: String(cookie.value || "").length,
    httpOnly: cookie.httpOnly === true,
    secure: cookie.secure === true,
    isSession,
    expiresAt: isSession ? null : new Date(expires * 1000),
    looksAuth: AUTH_HINT.test(String(cookie.name || "")),
  };
}

/**
 * 打印诊断。抽取脚本最容易出现「看起来成功、其实什么都没抽到」，
 * 所以这里把判定依据直接摊开：多少条、几条会话级、哪些像票据、什么时候过期。
 */
export function report(state, { host, quiet = false } = {}) {
  const rows = state.cookies.map(classifyCookie);
  const sessionRows = rows.filter((r) => r.isSession);
  const authRows = rows.filter((r) => r.looksAuth);
  const persistent = rows.filter((r) => !r.isSession).sort((a, b) => a.expiresAt - b.expiresAt);

  console.log(`\n主机: ${host}`);
  console.log(`cookie 合计: ${rows.length} 条（会话级 ${sessionRows.length} 条）   origins: ${state.origins.length}`);
  const lsKeys = state.origins.reduce((n, o) => n + (o.localStorage?.length || 0), 0);
  const ssKeys = state.origins.reduce((n, o) => n + (o.sessionStorage?.length || 0), 0);
  console.log(`Web Storage: localStorage ${lsKeys} 键 / sessionStorage ${ssKeys} 键`);
  if (state.storageSkipped?.length) {
    const bytes = state.storageSkipped.reduce((n, s) => n + s.bytes, 0);
    console.log(`  已跳过 ${state.storageSkipped.length} 个体积超限的键（合计 ${(bytes / 1024).toFixed(0)} KB，多为埋点缓存）`);
    for (const s of state.storageSkipped.slice(0, 5)) {
      console.log(`    - ${s.name.slice(0, 40)} ${(s.bytes / 1024).toFixed(0)} KB @ ${s.origin}`);
    }
  }

  if (!rows.length) {
    console.log("\n[判定] 该站点家族下没有任何 cookie —— 浏览器里很可能未登录，或登录的是另一个浏览器资料目录。");
    return { total: 0, session: 0, auth: 0 };
  }

  if (!quiet) {
    console.log("\n--- 全部 cookie（按过期时间升序，会话级在末尾）---");
    const ordered = [...persistent, ...sessionRows];
    for (const r of ordered) {
      const when = r.isSession ? "会话级(不落盘)" : r.expiresAt.toISOString().slice(0, 19).replace("T", " ");
      const mark = r.looksAuth ? "✓" : " ";
      console.log(
        `  ${mark} ${r.domain.padEnd(26)} ${r.name.padEnd(30)} len=${String(r.bytes).padEnd(4)} ` +
          `httpOnly=${String(r.httpOnly).padEnd(5)} exp=${when}`,
      );
    }
  } else {
    console.log("\n--- 认证类 cookie ---");
    for (const r of authRows) {
      const when = r.isSession ? "会话级(不落盘)" : r.expiresAt.toISOString().slice(0, 19).replace("T", " ");
      console.log(`  ✓ ${r.domain.padEnd(26)} ${r.name.padEnd(30)} len=${String(r.bytes).padEnd(4)} exp=${when}`);
    }
  }

  console.log("\n--- 判定 ---");
  if (authRows.length) {
    console.log(`  ✓ 命中 ${authRows.length} 条疑似认证凭据: ${[...new Set(authRows.map((r) => r.name))].join(", ")}`);
  } else {
    console.log("  ✗ 没有任何名字像凭据的 cookie（ticket/token/session/...），很可能只是匿名态");
  }
  if (sessionRows.length) {
    console.log(`  ✓ 含 ${sessionRows.length} 条会话级 cookie —— 这正是只读磁盘 Cookie 库拿不到的那部分`);
  } else {
    console.log("  ! 没有会话级 cookie。若目标站登录态就是持久的则正常；否则说明票据没抽到");
  }
  if (persistent.length) {
    const first = persistent[0];
    console.log(`  最早过期的持久 cookie: ${first.name} @ ${first.domain} → ${first.expiresAt.toISOString().slice(0, 19).replace("T", " ")}`);
  }

  return { total: rows.length, session: sessionRows.length, auth: authRows.length };
}

/** 把 http://127.0.0.1:<port> 的启动指引打印出来（两个脚本共用措辞）。 */
export function printLaunchHint(port) {
  const candidates = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ];
  console.error(`
没有在 127.0.0.1:${port} 上找到 DevTools 端口。请用一个**独立资料目录**启动浏览器并把端口作为启动参数：

  & "${candidates[0]}" \`
    --user-data-dir="E:\\edge-nianyun" \`
    --remote-debugging-port=${port} \`
    --no-first-run

要点：
  - 端口必须是启动参数。Edge/Chrome 136+ 拒绝对**默认**资料目录开调试端口，所以必须换目录。
  - 换目录后是干净配置，需要在这个窗口里重新登录一次。
  - 登录后**不要关这个窗口**，回到这里重跑本脚本。会话级 cookie 只在内存里，
    关掉浏览器就没了 —— 这也是一开始「一关就得重新登录」的原因。`);
}

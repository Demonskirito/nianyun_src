#!/usr/bin/env node
/**
 * 沙箱 egress 专项探针（2026-11-07，两阶段）。
 *
 * 用法（在控制面容器内，能解析 sandbox:8790）：
 *   node /tmp/egress-probe.mjs
 *   SANDBOX_URL=http://sandbox:8790 TARGET=https://developer.aliyun.com/ node egress-probe.mjs
 *
 * Phase 1 (python)：把「exec.python 自建 HTTPS 请求被 403 / 7149B 拦截页」拆成变量：
 *   裸 UA / prelude 补头 / 完整 Chrome 头 / 历史脚本头 / 明文 HTTP。
 * Phase 2 (python)：分离混淆变量 —— X-Nianyun-No-UA 豁免头本身、UA 单独、非浏览器 UA、跨域目标。
 * Phase 3 (bash + curl)：验证 egress 代理对明文 HTTP 的 injected_headers 落账
 *   （bashPrelude 不 patch requests，代理能看到裸请求）。
 * 最后读 /sandbox/egress-log 验证 injected_headers 与 JA3(SNI)。
 * 只读探测：不写会话证据、不改任何状态。
 */

const SANDBOX_URL = process.env.SANDBOX_URL || "http://sandbox:8790";
const TARGET = process.env.TARGET || "https://developer.aliyun.com/";
const TIMEOUT_S = Number(process.env.TIMEOUT_S || 180);
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";

function pythonProbe(groups) {
  return String.raw`
import json, os, warnings
warnings.filterwarnings("ignore")
import requests

TARGET = ${JSON.stringify(TARGET)}
UA = ${JSON.stringify(UA)}
proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
proxies = {"http": proxy, "https": proxy} if proxy else None
FULL = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
}
HISTORIC = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Referer": "https://www.aliyun.com/", "Cache-Control": "no-cache",
}
BARE = {"X-Nianyun-No-UA": "1"}
GROUPS = ${JSON.stringify(groups)}

def headers_for(kind):
    if kind == "none": return None
    if kind == "bare": return dict(BARE)
    if kind == "bare_plus_browser_ua": return {"X-Nianyun-No-UA": "1", "User-Agent": UA}
    if kind == "bare_plus_python_ua": return {"X-Nianyun-No-UA": "1", "User-Agent": "python-requests/2.34.2"}
    if kind == "python_ua": return {"User-Agent": "python-requests/2.34.2"}
    if kind == "curl_ua": return {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
    if kind == "browser_ua_only": return {"X-Nianyun-No-UA": "1", "User-Agent": UA, "Accept": "*/*"}
    if kind == "accept_only": return {"X-Nianyun-No-UA": "1", "User-Agent": "python-requests/2.34.2", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    if kind == "full": return dict(FULL)
    if kind == "historic": return dict(HISTORIC)
    return None

def probe(spec):
    if spec["kind"] == "raw_proxy":
        # 绕开 requests（prelude 只 patch Session.request），用 http.client 发绝对 URI，
        # 让 egress 代理看到一份完全没有 User-Agent/Accept 的明文请求，验证 injected_headers。
        try:
            import http.client
            from urllib.parse import urlparse
            pp = urlparse(proxy)
            conn = http.client.HTTPConnection(pp.hostname, pp.port, timeout=20)
            # 必须保留 Host：Node 的 HTTP server 对 HTTP/1.1 无 Host 直接回 400，不进代理 handler。
            conn.putrequest("GET", spec["url"], skip_accept_encoding=True)
            conn.endheaders()
            r = conn.getresponse(); body = r.read()
            return {"group": spec["group"], "kind": spec["kind"], "url": spec["url"],
                    "status": r.status, "bytes": len(body),
                    "snippet": body[:120].decode("utf-8", "replace").replace("\n", " ")}
        except Exception as e:
            return {"group": spec["group"], "kind": spec["kind"],
                    "error": type(e).__name__ + ": " + str(e)[:180]}
    try:
        r = requests.get(spec["url"], headers=headers_for(spec["kind"]), timeout=20,
                         proxies=proxies, verify=False, allow_redirects=False)
        body = r.content or b""
        item = {
            "group": spec["group"], "kind": spec["kind"], "url": spec["url"],
            "status": r.status_code, "bytes": len(body), "server": r.headers.get("server"),
            "request_ua": r.request.headers.get("User-Agent"),
            "snippet": body[:180].decode("utf-8", "replace").replace("\n", " "),
        }
        if r.status_code >= 400:
            item["body_full"] = body[:1400].decode("utf-8", "replace")
        return item
    except Exception as e:
        return {"group": spec["group"], "kind": spec["kind"], "url": spec["url"],
                "error": type(e).__name__ + ": " + str(e)[:180]}

print("PROBE_JSON=" + json.dumps({
    "proxy_env": proxy,
    "patched_session_request": requests.sessions.Session.request.__name__,
    "requests_version": requests.__version__,
    "results": [probe(spec) for spec in GROUPS],
}, ensure_ascii=False))
`;
}

const plain = TARGET.replace("https://", "http://", 1);
const PHASE1 = [
  { group: "G0_bare_https", kind: "bare", url: TARGET },
  { group: "G1_prelude_https", kind: "none", url: TARGET },
  { group: "G2_chrome_full_https", kind: "full", url: TARGET },
  { group: "G3_historic_https", kind: "historic", url: TARGET },
  { group: "G4_prelude_http", kind: "none", url: plain },
  { group: "G5_bare_http", kind: "bare", url: plain },
];
const PHASE2 = [
  { group: "P0_bare_header_plus_browser_ua", kind: "bare_plus_browser_ua", url: TARGET },
  { group: "P1_bare_header_plus_python_ua", kind: "bare_plus_python_ua", url: TARGET },
  { group: "P2_python_ua_no_exempt", kind: "python_ua", url: TARGET },
  { group: "P3_curl_ua", kind: "curl_ua", url: TARGET },
  { group: "P4_browser_ua_only", kind: "browser_ua_only", url: TARGET },
  { group: "P5_python_ua_plus_accept", kind: "accept_only", url: TARGET },
  { group: "P6_other_host_bare", kind: "bare", url: "https://next.api.aliyun.com/" },
  { group: "P7_other_host_prelude", kind: "none", url: "https://next.api.aliyun.com/" },
  { group: "P8_cdn_prelude", kind: "none", url: "https://g.alicdn.com/alicloud-sdk/alicloud-api-doc/0.0.236/assets/docs.css" },
  { group: "P9_raw_proxy_plaintext", kind: "raw_proxy", url: plain },
];
const BASH = String.raw`
echo "PROXY_ENV=$HTTPS_PROXY"
echo "CURL_HTTP_NATIVE_HEADERS:"
curl -sS -o /dev/null -w 'status=%{http_code} bytes=%{size_download}\n' -H 'User-Agent:' -H 'Accept:' --max-time 20 "${plain}" || true
echo "CURL_HTTP_WITH_BROWSER_UA:"
curl -sS -o /dev/null -w 'status=%{http_code} bytes=%{size_download}\n' -H 'User-Agent: ${UA}' -H 'Accept: */*' --max-time 20 "${plain}" || true
echo "CURL_HTTPS_BARE:"
curl -sk -o /tmp/body -w 'status=%{http_code} bytes=%{size_download}\n' --max-time 20 "${TARGET}" || true
echo "CURL_HTTPS_BROWSER_UA:"
curl -sk -o /tmp/body2 -w 'status=%{http_code} bytes=%{size_download}\n' -H 'User-Agent: ${UA}' -A '${UA}' --max-time 20 "${TARGET}" || true
`;

async function post(path, body) {
  const res = await fetch(`${SANDBOX_URL}${path}`, body === undefined
    ? { method: "GET" }
    : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text();
  try { return { status: res.status, body: JSON.parse(text) }; }
  catch { return { status: res.status, body: text.slice(0, 500) }; }
}

async function runExec(lang, code, label) {
  // 服务端 normalizeRequest 只认 `code`（bash 的 script 字段是工具层的别名）。
  const out = (await post("/sandbox/exec", {
    lang, code, timeout_s: TIMEOUT_S, memory_mb: 512, network: true,
  })).body || {};
  console.log(`\n[${label}] ok=${out.ok} exit=${out.exit_code} timed_out=${out.timed_out} egress=${out.egress} ms=${out.duration_ms}`);
  const line = String(out.stdout || "").split("\n").find(item => item.startsWith("PROBE_JSON="));
  if (line) {
    const parsed = JSON.parse(line.slice("PROBE_JSON=".length));
    console.log(`  proxy=${parsed.proxy_env} patched=${parsed.patched_session_request} requests=${parsed.requests_version}`);
    console.table(parsed.results.map(item => ({
      group: item.group, status: item.status ?? "ERR", bytes: item.bytes ?? "-",
      ua: String(item.request_ua || "-").slice(0, 28), detail: item.error || item.snippet,
    })));
    const denied = parsed.results.filter(item => item.body_full);
    if (denied.length) console.log(`  FULL_403_BODY[${denied[0].group}]: ${denied[0].body_full}`);
  } else {
    console.log("  STDOUT", String(out.stdout || "").slice(0, 1600));
  }
  if (out.stderr) console.log("  STDERR", String(out.stderr).slice(0, 500));
  return out;
}

async function main() {
  const health = await post("/health");
  console.log("HEALTH", health.status, "egress_proxy=", health.body?.egress_proxy || health.body);
  await runExec("python", pythonProbe(PHASE1), "PHASE1 python");
  await runExec("python", pythonProbe(PHASE2), "PHASE2 isolate");
  await runExec("bash", BASH, "PHASE3 bash/curl");
  const log = await post("/sandbox/egress-log?limit=100");
  const entries = log.body?.entries || [];
  console.log("\nEGRESS_LOG", entries.length, "entries");
  const injected = entries.filter(item => (item.injected_headers || []).length);
  console.log("INJECTED_ENTRIES", JSON.stringify(injected.slice(-6).map(item => ({
    kind: item.kind, target: item.target, injected: item.injected_headers,
  }))));
  const ja3 = [...new Set(entries.filter(item => item.ja3_hash).map(item => item.ja3_hash))];
  console.log("JA3_HASHES", JSON.stringify(ja3), "connect_count=", entries.filter(item => item.kind === "connect").length);
}

main().catch(error => { console.error("PROBE_FAILED", error); process.exitCode = 1; });

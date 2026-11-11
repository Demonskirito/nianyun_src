/**
 * 特种兵装配模板（Specialist Kits）
 *
 * 背景：`spa.ts` 缴了步兵的械、生成了 `T_SPA_REVERSE_*`，但 note.yun 那轮的实测是
 * `recon.js_endpoints` 两次都回 `no_script_references` —— 外壳里没有外部 bundle。
 * 光说"用 Playwright"不够：模型要现场写一段能跑的脚本，写错就是再烧一轮。
 *
 * 这里给的是**经过验证的骨架**：只留一个 TODO，模型填 URL 与过滤条件即可。
 * 骨架写进上下文（context.spa_mode.kit），不写进 system prompt 全文，避免每轮都占 token。
 */

export type SpecialistKit = {
  id: string;
  tool: string;
  title: string;
  /** 可直接用 exec.python 执行的最小脚本；{{TARGET_URL}} 由控制面替换。 */
  code: string;
  /** 跑完要交的结论，用来对齐任务契约。 */
  deliverable: string;
  notes: string[];
};

const PLAYWRIGHT_XHR = `# 控制面注入的骨架：只填 {{TARGET_URL}}，其余照抄即可跑
# 目标：把 SPA 外壳真正发出去的 XHR/fetch 全部抓下来（外壳里没有 <script src>，
#       静态扫描一定返回 no_script_references，这是 note.yun 那轮的实测结论）
import json
from playwright.sync_api import sync_playwright

TARGET = "{{TARGET_URL}}"
KEEP = ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")

def extract_apis(url: str) -> dict:
    seen, requests_log = set(), []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page()
        page.on("request", lambda req: requests_log.append({
            "url": req.url, "method": req.method,
            "resource": req.resource_type,
            "post_data": (req.post_data or "")[:500],
        }))
        page.goto(url, wait_until="networkidle", timeout=45000)
        # 有些站点首屏后才发请求：等一等再抓
        page.wait_for_timeout(3000)
        title = page.title()
        # TODO（可选）：如果接口是渲染后才拼出来的，在这里补 evaluate 提取 window 上的 baseURL
        html = page.content()
        browser.close()
    for item in requests_log:
        if any(key in item["url"] for key in KEEP):
            seen.add(json.dumps(item, ensure_ascii=False, sort_keys=True))
    apis = [json.loads(line) for line in sorted(seen)]
    return {"title": title, "html_bytes": len(html), "apis": apis, "total_requests": len(requests_log)}

print(json.dumps(extract_apis(TARGET), ensure_ascii=False, indent=2))
`;

const CURL_INLINE_SCRIPT = `# 控制面注入的骨架：外壳自带内联脚本时，先把里面的常量抠出来（比渲染快，0 依赖）
import re, json, urllib.request

TARGET = "{{TARGET_URL}}"
req = urllib.request.Request(TARGET, headers={"User-Agent": "Mozilla/5.0"})
html = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")

# 常见的"接口前缀"写法：apiBase/apiUrl/baseURL/gateway + 引号里的路径
patterns = [
    r'(?:apiBase|apiUrl|baseURL|baseUrl|API_BASE|gateway|prefix)\\s*[:=]\\s*["\\']([^"\\']{2,80})["\\']',
    r'["\\'](/[a-z0-9_-]{2,20}/api/[a-z0-9_/-]{0,60})["\\']',
    r'["\\'](https?://[a-z0-9.-]+/api[a-z0-9_/-]{0,60})["\\']',
]
found = []
for pattern in patterns:
    found.extend(re.findall(pattern, html, flags=re.I))
print(json.dumps({"bytes": len(html), "candidates": sorted(set(found))[:40]}, ensure_ascii=False, indent=2))
`;

export const SPECIALIST_KITS: SpecialistKit[] = [
  {
    id: "spa_xhr_capture",
    tool: "exec.python",
    title: "Playwright 抓 XHR（SPA 外壳首选）",
    code: PLAYWRIGHT_XHR,
    deliverable: "apis[]：至少 1 条带 method 的真实接口路径（例如 GET /api/user/info）",
    notes: [
      "容器内若未装 playwright，先跑 exec.bash `pip install playwright && playwright install chromium`（一次即可）。",
      "wait_until=networkidle 之后仍要 wait_for_timeout 3s：多数 SPA 在首屏之后才拉业务接口。",
      "拿到的 url 直接喂给 http.request 复核；参数名从 post_data 里看，别猜。",
    ],
  },
  {
    id: "spa_inline_constants",
    tool: "exec.python",
    title: "内联脚本常量提取（零依赖，最快）",
    code: CURL_INLINE_SCRIPT,
    deliverable: "candidates[]：脚本里出现的接口前缀/路径常量",
    notes: [
      "先跑这个再跑 Playwright：很多外壳把 apiBase 直接写在 window.__CONFIG__ 里。",
      "命中 candidates 后立刻用 http.request 验证其中 1 条，别直接当结论。",
    ],
  },
];

/** 按 id 取模板；不传则返回首选（Playwright）。 */
export function specialistKit(id?: string): SpecialistKit {
  return SPECIALIST_KITS.find(kit => kit.id === id) || SPECIALIST_KITS[0]!;
}

/** 控制面替换占位符后的可执行代码。 */
export function renderKit(kit: SpecialistKit, targetUrl: string): string {
  return kit.code.replace(/\{\{TARGET_URL\}\}/g, targetUrl);
}
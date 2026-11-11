import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { chromium, type Browser } from "playwright";
import type { Config } from "../shared/config.js";
import type { Database } from "../shared/db.js";
import { probeProxy } from "../shared/outbound.js";

export const ASSET_RULE_VERSION = "asset-page-v2";
export const DEFAULT_ASSET_RULE = `你是资产页面识别 Agent。根据页面截图、标题、可见文本、HTTP 状态、URL 形态和技术特征判断页面业务价值。

【优先加分：接口面优先于展示面】
- URL 或页面里出现 /api/、/graphql、/rest/、/v1~v3/、swagger、api-docs、doc.html、actuator、druid、nacos → 80-100（这些是黑盒阶段能直接旋参数的地方，价值远高于静态页）
- 登录/认证/SSO、注册、找回密码 → 85-100（能拿到 Token 就等于拿到业务层）
- 管理后台、用户中心、订单/支付/退款、上传、导入导出、消息/工单 → 80-100
- 带查询参数（?id=、?userId=、?orderId=、?file=）的页面 → 75-95（参数即漏洞面，越权/SQLi/SSRF 都在这里）
- 纯静态页、Vue/React 空壳、CDN 资源、404/错误页、默认 nginx 欢迎页 → 0-25

【扣分】只有一个 logo 的门户页、纯营销页、需要 JS 才能渲染但没有任何接口迹象的页面，即使标题好看也不要超过 40。

score 为 0-100：高价值业务入口/接口 80-100，普通业务页面 40-79，静态/错误/无关页面 0-39。只返回 JSON：{score:0-100,business_type:string,reasons:string[],confidence:string}`;

type ReviewConfig = { baseUrl: string; model: string; key: string; prompt: string; ruleVersion: string; browserProxy: string };

/**
 * Chromium does not consume the same proxy settings as node:fetch and, without one, its requests
 * from the control-plane container die on the (proxied) egress path - every page.goto then burns
 * the full 20s timeout. `src/control/cli.ts` clears the process proxy env on purpose, so the proxy
 * has to come from configuration (BROWSER_PROXY / NIANYUN_BROWSER_PROXY) rather than process.env.
 */
function launchOptions(proxy: string): { headless: boolean; args: string[] } {
  const args = ["--no-sandbox", "--disable-dev-shm-usage"];
  if (proxy) args.push(`--proxy-server=${proxy}`);
  return { headless: true, args };
}

function reviewConfig(values: Record<string, string>): ReviewConfig {
  return {
    baseUrl: String(values.ASSET_AGENT_BASE_URL || values.NIANYUN_LOOP_BASE_URL || values.ANTHROPIC_BASE_URL || "").trim().replace(/\/$/, ""),
    model: String(values.ASSET_AGENT_MODEL || values.NIANYUN_LOOP_MODEL || values.ANTHROPIC_MODEL || "").trim(),
    key: String(values.ASSET_AGENT_API_KEY || values.NIANYUN_LOOP_API_KEY || values.ANTHROPIC_API_KEY || "").trim(),
    prompt: String(values.ASSET_AGENT_PROMPT || DEFAULT_ASSET_RULE).trim(),
    ruleVersion: String(values.ASSET_AGENT_RULE_VERSION || ASSET_RULE_VERSION).trim() || ASSET_RULE_VERSION,
    browserProxy: String(values.BROWSER_PROXY || values.NIANYUN_BROWSER_PROXY || "").trim(),
  };
}

function chatUrl(baseUrl: string): string {
  if (/\/chat\/completions$/i.test(baseUrl)) return baseUrl;
  if (/\/v1$/i.test(baseUrl)) return `${baseUrl}/chat/completions`;
  return `${baseUrl}/v1/chat/completions`;
}

function isAnthropic(baseUrl: string): boolean {
  return /anthropic\.com/i.test(baseUrl) || /\/messages$/i.test(baseUrl);
}

function anthropicUrl(baseUrl: string): string {
  if (/\/messages$/i.test(baseUrl)) return baseUrl;
  return `${baseUrl}/v1/messages`;
}

function targetUrl(candidate: Record<string, unknown>): string | null {
  if (candidate.url) return String(candidate.url);
  const host = String(candidate.hostname || candidate.value || "");
  if (!host) return null;
  const protocol = String(candidate.protocol || "http");
  const port = Number(candidate.port || 0);
  return `${protocol}://${host}${port ? `:${port}` : ""}`;
}

function textFeatures(text: string, html: string): string[] {
  const features: string[] = [];
  const checks: Array<[string, RegExp]> = [
    ["login", /\b(sign[ -]?in|log[ -]?in|登录|认证)\b/i],
    ["admin", /\b(admin|管理后台|控制台|dashboard)\b/i],
    ["api", /\b(api|swagger|openapi|graphql)\b/i],
    ["shop", /\b(cart|checkout|product|商品|购物车|订单)\b/i],
    ["upload", /\b(upload|上传|附件)\b/i],
    ["docs", /\b(documentation|docs|文档|开发者)\b/i],
  ];
  for (const [name, pattern] of checks) if (pattern.test(text)) features.push(name);
  if (/<form\b/i.test(html)) features.push("form");
  if (/<script\b/i.test(html)) features.push("javascript");
  return [...new Set(features)];
}

async function askAgent(cfg: ReviewConfig, evidence: Record<string, unknown>, screenshotFile: string): Promise<Record<string, unknown>> {
  if (!cfg.baseUrl || !cfg.model || !cfg.key) throw new Error("资产 Agent 尚未在设置中配置地址、模型和 API Key");
  const instruction = cfg.prompt || DEFAULT_ASSET_RULE;
  const anthropic = isAnthropic(cfg.baseUrl);
  const response = await fetch(anthropic ? anthropicUrl(cfg.baseUrl) : chatUrl(cfg.baseUrl), {
    method: "POST",
    headers: anthropic
      ? { "Content-Type": "application/json", "x-api-key": cfg.key, "anthropic-version": "2023-06-01" }
      : { "Content-Type": "application/json", Authorization: `Bearer ${cfg.key}` },
    body: JSON.stringify({
      model: cfg.model,
      ...(anthropic ? { max_tokens: 1200, system: `${instruction}\n只返回 JSON：{score:0-100,business_type:string,reasons:string[],confidence:string}` } : { temperature: 0, response_format: { type: "json_object" } }),
      messages: [
        ...(anthropic ? [] : [{ role: "system", content: `${instruction}\n只返回 JSON：{score:0-100,business_type:string,reasons:string[],confidence:string}` }]),
        { role: "user", content: [
          { type: "text", text: JSON.stringify(evidence) },
          { type: "image_url", image_url: { url: `data:image/png;base64,${readFileSync(screenshotFile).toString("base64")}` } },
        ] },
      ],
    }),
    signal: AbortSignal.timeout(60_000),
  });
  const body = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!response.ok) throw new Error(`资产 Agent HTTP ${response.status}`);
  const choices = Array.isArray(body.choices) ? body.choices : [];
  const content = choices[0] && typeof choices[0] === "object" ? (choices[0] as Record<string, unknown>).message : null;
  const rawContent = anthropic ? body.content : content && typeof content === "object" ? (content as Record<string, unknown>).content : "";
  const raw = Array.isArray(rawContent) ? rawContent.filter((item) => item && typeof item === "object" && (item as Record<string, unknown>).type === "text").map((item) => String((item as Record<string, unknown>).text || "")).join("\n") : rawContent;
  const clean = String(raw || "{}").replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const parsed = JSON.parse(clean) as Record<string, unknown>;
  const score = Math.max(0, Math.min(100, Number(parsed.score) || 0));
  return { score, business_type: String(parsed.business_type || "unknown"), reasons: Array.isArray(parsed.reasons) ? parsed.reasons.map(String).slice(0, 12) : [], confidence: String(parsed.confidence || "unknown") };
}

async function captureEvidence(
  browser: Browser,
  screenshotDir: string,
  projectId: string,
  candidate: Record<string, unknown>,
): Promise<{ evidence: Record<string, unknown>; screenshotFile: string }> {
  const url = targetUrl(candidate);
  if (!url) throw new Error("candidate has no HTTP URL");
  const stamp = Date.now();
  const screenshotFile = join(screenshotDir, `${String(candidate.id)}-${stamp}.png`);
  // IP endpoints (certificate names a domain) and self-signed hosts are common in a wildcard
  // harvest; a certificate mismatch is not a reason to drop the page from scoring.
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  try {
    const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20_000 });
    await page.waitForTimeout(1200);
    // Some pages keep a navigation pending after domcontentloaded, which makes page.content() throw
    // "Unable to retrieve content because the page is navigating"; the serialized DOM is equivalent
    // for scoring, so fall back instead of losing the whole candidate.
    const html: string = await page.content().catch(async () => String(
      await page.evaluate("document.documentElement ? document.documentElement.outerHTML : ''").catch(() => ""),
    ));
    const visibleText = (await page.locator("body").innerText({ timeout: 5000 }).catch(() => "")).slice(0, 12000);
    const title = await page.title();
    const finalUrl = page.url();
    const features = textFeatures(visibleText, html);
    await page.screenshot({ path: screenshotFile, fullPage: false });
    const pageHeight = Number(await page.evaluate("Math.max(document.body?.scrollHeight || 0, document.documentElement?.scrollHeight || 0)"));
    const fullScreenshot = pageHeight > 1800 ? join(screenshotDir, `${String(candidate.id)}-${stamp}-full.png`) : null;
    if (fullScreenshot) await page.screenshot({ path: fullScreenshot, fullPage: true });
    return {
      screenshotFile,
      evidence: {
        requested_url: url,
        final_url: finalUrl,
        http_status: response?.status() || null,
        title,
        visible_text: visibleText,
        features,
        content_type: response?.headers()["content-type"] || null,
        viewport: { width: 1440, height: 900 },
        screenshot: `asset-screenshots/${projectId}/${String(candidate.id)}-${stamp}.png`,
        ...(fullScreenshot ? { full_screenshot: `asset-screenshots/${projectId}/${String(candidate.id)}-${stamp}-full.png` } : {}),
      },
    };
  } finally {
    await context.close().catch(() => undefined);
  }
}

async function scoreWithAgent(
  cfg: Config,
  db: Database,
  projectId: string,
  candidate: Record<string, unknown>,
  evidence: Record<string, unknown>,
  screenshotFile: string,
): Promise<Record<string, unknown>> {
  const rule = reviewConfig(cfg.tools_env.values);
  const agent = await askAgent(rule, evidence, screenshotFile);
  return db.updateAssetAgentReview(projectId, String(candidate.id), {
    agentScore: Number(agent.score), scoreReasons: agent, screenshotPath: String(evidence.screenshot), ruleVersion: rule.ruleVersion, pageEvidence: evidence,
  }) || { ...candidate, agent_score: agent.score, score_reasons: agent, screenshot_path: evidence.screenshot, page_evidence: evidence };
}

export async function reviewAssetCandidate(cfg: Config, db: Database, projectId: string, candidate: Record<string, unknown>): Promise<Record<string, unknown>> {
  const screenshotDir = join(cfg.data_dir, "asset-screenshots", projectId);
  mkdirSync(screenshotDir, { recursive: true });
  const rule = reviewConfig(cfg.tools_env.values);
  const proxyError = await probeProxy(rule.browserProxy);
  if (proxyError) throw new Error(proxyError);
  const browser = await chromium.launch(launchOptions(rule.browserProxy));
  try {
    const { evidence, screenshotFile } = await captureEvidence(browser, screenshotDir, projectId, candidate);
    return await scoreWithAgent(cfg, db, projectId, candidate, evidence, screenshotFile);
  } finally {
    await browser.close();
  }
}

export type ReviewOutcome = { ok: boolean; error?: string };

/**
 * Scores a batch with one shared browser and a small worker pool. Launching a Chromium per
 * candidate made a 99-asset queue crawl; the browser is the expensive part, not the page.
 */
export async function reviewAssetCandidates(
  cfg: Config,
  db: Database,
  projectId: string,
  candidates: Record<string, unknown>[],
  concurrency = 2,
): Promise<Map<string, ReviewOutcome>> {
  const outcomes = new Map<string, ReviewOutcome>();
  if (!candidates.length) return outcomes;
  const screenshotDir = join(cfg.data_dir, "asset-screenshots", projectId);
  mkdirSync(screenshotDir, { recursive: true });
  const batchRule = reviewConfig(cfg.tools_env.values);
  // One probe for the whole batch: a closed proxy must fail the job immediately, not per candidate.
  const proxyError = await probeProxy(batchRule.browserProxy);
  if (proxyError) throw new Error(proxyError);
  const browser = await chromium.launch(launchOptions(batchRule.browserProxy));
  const workers = Math.max(1, Math.min(4, Math.floor(concurrency)));
  let cursor = 0;
  try {
    await Promise.all(Array.from({ length: workers }, async () => {
      while (true) {
        const index = cursor++;
        const candidate = candidates[index];
        if (!candidate) return;
        const id = String(candidate.id);
        try {
          const { evidence, screenshotFile } = await captureEvidence(browser, screenshotDir, projectId, candidate);
          await scoreWithAgent(cfg, db, projectId, candidate, evidence, screenshotFile);
          outcomes.set(id, { ok: true });
        } catch (error) {
          outcomes.set(id, { ok: false, error: String(error instanceof Error ? error.message : error).slice(0, 500) });
        }
      }
    }));
  } finally {
    await browser.close().catch(() => undefined);
  }
  return outcomes;
}

# 新一轮攻击会话记录：note.yun.oppo.com（会话 `1cdf92d4816b72bf`）

- 会话：`1cdf92d4816b72bf`（项目 `p_06db586d65`）
- 目标：`http://note.yun.oppo.com/`（资产画像里已标注 301 → `https://cloud.oppo.com`）
- 窗口：2026-10-28 **15:07:37 → 15:21:38**，实际墙钟 **1146s（19 分钟）**
- 结局：`paused / awaiting_operator`，`stopReason = observer_review_failed`
- 用量：`toolCalls 47 / agentTurns 29 / tokens 1,092,502 / toolMs 87,405 / session_convergences 3`
- 账本：43 条 `tool-request` + 43 条 `tool-result` + 28 条 `agent-analysis` + 3 条 `observer-review`

---

## 1. 时间轴（逐条，UTC+8）

### 第一轮焦点 T1：基线 & 重定向（15:08–15:13，18 次调用）

| # | 时间 | 工具 | 任务 | 目标 | 结果 |
|---|---|---|---|---|---|
| 1 | 15:08:28 | `burp.history` | T1 | note.yun/ | `total=0`（代理里还没有记录） |
| 2 | 15:08:28 | `http.request` | T1 | note.yun/ | **301** → cloud.oppo.com |
| 3 | 15:08:42 | `burp.history` | T1 | note.yun/ | `total=1`，301×1 |
| 4 | 15:08:42 | `http.request` | T1 | note.yun/ | 301（与 #2 完全重复） |
| 5 | 15:08:43 | `http.request` | T1 | **cloud.oppo.com/** | **200**，5158B SPA 外壳 ← 本轮唯一有效纵深 |
| 6 | 15:09:01 | `burp.history` | T1 | note.yun/ | `total=2` |
| 7–9 | 15:09:01–02 | `http.request` ×3 | T1 | note.yun/ | 301 ×3（重复） |
| 10–11 | 15:09:20 | `http.request` ×2 | T1 | note.yun/ | 301 ×2（重复） |
| 12 | 15:09:21 | `http.request` | T1 | cloud.oppo.com/ | 200（重复 #5） |
| 13 | 15:09:21 | `burp.history` | T1 | note.yun/ | `total=7`，`301:7`，方法见 GET/HEAD/OPTIONS |
| 14 | 15:09:36 | `http.request` | T1 | note.yun/ | 301（重复） |
| 15 | 15:10:05 | **`recon.content_discovery`** | T1 | note.yun/ | **`count=224`**，`items` 只是相对路径、**不带状态码** |
| 16 | 15:10:32 | `burp.history` | T1 | note.yun/ | `total=298`，返回 50 条，`301:30 / 412:20` |
| 17 | 15:10:32 | `http.request` | T1 | note.yun/ | 301（重复） |
| 18 | 15:10:34 | `burp.send` | T1 | note.yun/ | 301 |
| 19 | 15:11:04 | `http.request` | T1 | cloud.oppo.com/ | 200（重复） |
| 20 | 15:11:05 | `burp.history` | T1 | note.yun/ | `total=299`（同上窗口） |

**T1 收口**：15:12:29 `focus-convergence`（9 轮 / 28 TP / 17.5 分 / 高价值 2 / 噪声 11）→ 15:13:05 `focus-appeal` 从全局池取 1 次（剩 2）→ 15:13:29 模型没结案，控制面强制 `blocked`（`focus_budget_exhausted`）。

### 第二轮焦点 T2：cloud.oppo.com 前端资产（15:15:41–15:18:59，4 次调用）

| # | 时间 | 工具 | 任务 | 目标 | 结果 |
|---|---|---|---|---|---|
| 21 | 15:15:41 | `http.request` | T2 | note.yun/.env | **412**（WAF，2681B） |
| 22 | 15:15:54 | `http.request` | T2 | cloud.oppo.com/ | 200（重复） |
| 23 | 15:16:20 | `recon.js_endpoints` | T2 | cloud.oppo.com/ | `count=0`，`reason=no_script_references` |
| 24 | 15:16:42 | `recon.js_endpoints` | T2 | cloud.oppo.com/ | **同样的 0**（重复） |

同期 Observer 打回 11 次 `review-stale`（结果对应旧快照），并连发 3 条 advice：换 `browser` 抓 network、`evidence.read` 用 `limit:900`、结案 T2。
**T2 收口**：15:18:59 `focus-convergence`（`focus_stalled`：连续 3 轮无高价值证据）→ 强制 `blocked`；本轮 3 条请求被 `tool-requests-rejected` 丢弃（其中 `evidence.read`、`katana.crawl` 从未执行）。

### 第三轮焦点 T3：敏感路径未授权探测（15:20:30–15:21:38，19 次调用）

| # | 时间 | 工具 | 目标 | 结果 |
|---|---|---|---|---|
| 25 | 15:20:30 | `recon.content_discovery` | note.yun/ | `count=224`（**与 #15 完全相同，图零新增**） |
| 26 | 15:20:30 | `http.request` | cloud/.git/config | **412** |
| 27 | 15:20:30 | `http.request` | cloud/.env | **412** |
| 28 | 15:20:30 | `http.request` | cloud/robots.txt | 404 |
| 29 | 15:20:31 | `http.request` | cloud/swagger-ui/index.html | **412** |
| 30 | 15:20:31 | `http.request` | cloud/v3/api-docs | 404 |
| 31 | 15:20:31 | `http.request` | cloud/actuator | **412** |
| 32 | 15:20:31 | `http.request` | cloud/druid/index.html | **412** |
| 33 | 15:20:32 | `http.request` | cloud/nacos/ | **412** |
| 34 | 15:20:32 | `http.request` | cloud/graphql | 404 |
| 35 | 15:20:32 | `http.request` | cloud/sitemap.xml | 404 |
| 36–42 | 15:21:36–37 | `http.request` ×7 | cloud/robots.txt、.git/config、swagger-ui、actuator/env、v3/api-docs、druid、graphql | **几乎逐条重复 #28–#34**（404×3 / 412×4） |
| 43 | 15:21:38 | `http.request` | note.yun/.git/config | **412** |

**T3 未收口**：15:22:05 之后 Observer 复查失败（`review-failed` 1 次、`review-stale` 累计 11 次），会话以 `observer_review_failed` 停止。

---

## 2. 任务状态机：声明了多少、废了多少

| 任务 | 意图 | 终态 | 备注 |
|---|---|---|---|
| `T1` | 301 基线 + Host 头/开放重定向面 | `blocked` | 焦点预算 9 轮耗尽（`focus_budget_exhausted`） |
| `T2` | cloud.oppo.com 真实前端资产与 API 枚举 | `blocked` | `focus_stalled`（连续 3 轮无高价值证据） |
| `T3` | 敏感路径未授权/信息泄露 | `blocked` | 同上，且结论未落 finding |
| `T4` | POST 面枚举（method 与字段名） | `pending` | 一次都没执行（`tool_calls: 0`） |
| `T2_unauth_exposure_cloud` | 落地站未授权面 | `pending` | 未执行 |
| `recon_baseline` | 301 跳转 + Host 注入 + catch-all | `pending` | 未执行 |
| `js_api_extract` | cloud JS 提取接口/AK | `pending` | 未执行（`js_endpoints` 全 0） |
| `recon_identity_chain` | 追 OPPO 统一登录/Token 域名 | `pending` | 未执行 |
| `post_surface_20261028072032` | POST 功能面 | `pending` | `ignored_turns=7` 后被升级提醒 |

**计划版本**：`planRevision` 从 12 涨到 16（5 个 plan 快照）；**任务合并 12 次共 20 条**——`T1 ×8`、`T2 ×8`、`T3 ×8` 被反复重新声明后合并回原任务。`T1.merged_from` 长度 = 8。

**这意味着**：模型的 29 个 turn 里有相当一部分在“重新声明已经存在的任务”，而不是推进。

---

## 3. 协议层摩擦（每一类都有对策）

| 类别 | 次数 | 原文样例 | 代价 |
|---|---|---|---|
| `required_tasks` 条目被丢弃 | **13 条** | `(item): Invalid input`（7 次 `protocol-warning`，13 条任务项） | 声明失败 → 只能下一轮重声明 → 任务合并 20 次 |
| 未登记键被摘掉 | **15 类 31 次** | `host`×13、`domain`×3、`match_status`、`threads`、`rate_limit`、`timeout_s`×2、`match_codes`、`js_crawl`、`headless`、`duration`、`probe_sensitive`、`max_results`、`target`、`record_types` | 扫描器参数**被静默忽略**：`content_discovery` 的 `match_status` 本可以只回 200 的路径，结果回 224 条噪声 |
| `evidence.read` 取值超限 | 2 | `input.limit: Too big: expected number to be <=1000` | 两条读取指令被丢 |
| `target: Invalid URL` | 1 | — | 一条任务项被丢 |
| 请求被焦点锁/收口拒收 | **34 条**（7 批） | `焦点锁定在 T1…`、`【强制收口】…` | 34 次调用的意图从未执行 |
| 协议校验失败整轮丢弃 | 1 | `summary: Invalid input: expected string, received undefined` | 整轮动作未执行 |
| `action-skipped` | 16 | — | — |

---

## 4. Observer / 门禁

- `review-trigger 14 / review-running 15 / review-pending 15 / review-result 3 / **review-stale 11** / review-failed 1`
- 11 次 stale 的原因一致：**Observer 审查的是旧状态快照**（`expected` 与 `actual` 指纹不匹配），门禁一直保持 → 最终 `observer_review_failed` 终止。
- `supervision.coverage = 0.33`，`acceptance.reason_codes = ["TASKS_NOT_TERMINAL","TERMINAL_REVIEW_PENDING"]`。

---

## 5. 28 条 agent-analysis 的自我叙述（关键症状）

按内容分类：

| 类型 | 条数 | 表现 |
|---|---|---|
| “会话启动 / 会话就绪 / 冷启动 / 接管会话”式开头 | **10** | 明明账本里已有 15+ 条证据、3 个任务，仍然按“空账本”重新规划 |
| 围绕 T2 的重复叙述 | 4 | 每轮都把同一句“ev-72dfbe492227ded4 是 5158B SPA 外壳”再讲一遍 |
| 围绕 T3 的重复叙述 | 7 | “412 WAF 2681B”“404 三类指纹”反复叙述，但每轮**再打一遍**同样的路径 |
| 强制收口语义（明确不发射工具） | 3 | 只有这 3 轮真正遵守了收口 |

第 21–27 条分析的原文已经能自己写出正确判断（“412 是 OPPO WAF 阻断页，需换武器”），但**下一轮的实际动作仍然是继续探测同一批路径**——这是本轮最刺眼的“知行不一”。

---

## 6. 唯一一次真正的“顺延”

15:08:43，第 5 次调用把目标从 `note.yun.oppo.com` 换成 `https://cloud.oppo.com/`（依据是 301 的 `Location` 头）。

- 这一步让图里出现了 `ep:cloud.oppo.com/`（最短路径成本 0），并被 `evidence-value` 判为 `+5 势能提升`。
- 但从那一刻到会话结束（13 分钟、38 次调用），agent 再也没有从这个新节点上**抽出任何新节点**：`js_endpoints` 两次 0 结果，`browser` 从未使用，`katana.crawl` 被焦点锁拒收。

---

## 7. 与上一轮（`20ea56baa4569b8d`，gray-push-intl）的横向对比

| 指标 | 上一轮 | 本轮 |
|---|---|---|
| 工具调用 | 165 | 43 |
| 唯一请求 | 未统计（重复严重） | 22 / 43（**重复率 49%**） |
| 图节点 / 边 | 269 / 270 | 241 / 239 |
| `parameter` 节点 | 10 | **0** |
| 状态 `testing` | 37 | 15 |
| 轮次（run 数） | 8 | **1** |
| 落 finding | 0 | 0 |
| 强制收口次数 | 未统计 | 2（T1、T2）+ 1 次 appeal |

两轮共同点：**字典/爆破类工具一跑就出几百个节点，但 agent 从不回头消费这些节点**。上一轮是 221 个未测端点，本轮是 224 个，一模一样。

---

## 8. 结论（供能力评估用）

1. **侦察工具链是通的**：`burp.history` 拿到了 299 条真实代理记录（其中 20 条 412），`content_discovery` 拿到 224 条路径，`http.request` 稳定返回状态码。
2. **判断力也在**：28 条分析里对 412 WAF、catch-all、SPA 外壳的判断都是对的。
3. **执行层是断的**：判断正确之后动作不跟随（三次 `component_drift` 点名 → 三次不采纳），且重复率 49%。
4. **协议摩擦吃掉了一半产能**：34 条请求被拒收、13 条任务项被丢、31 次参数被静默摘掉——模型在这些摩擦上反复消耗 turn，这也是它反复“重新声明任务”的原因。
5. **收口机制有效但太快**：T1 9 轮、T2 6 轮就被强制 `blocked`，而 412 墙的绕过恰恰需要更多轮。这两者的相互作用把这一轮压成了 19 分钟。
---

## 9. 这一轮暴露的能力缺口 → 已做的修改

按“证据 → 判据 → 代码位置”列，避免只写结论：

| # | 缺口（有证据） | 改成什么 | 位置 |
|---|---|---|---|
| 1 | `content_discovery` 对 catch-all 目标返回 224 条假命中（§1 第 15 条、图里 224 个 untested） | ffuf 加 `-ac` 自动校准 + `-mc` 状态码白名单 | `src/blackbox/tools.ts` |
| 2 | 9 条 412 全落 `testing`，图上无“墙”语义 | `wallOf()` 判墙（412/418/1020 + 阻断页指纹），状态落 `blocked`、记 `wall` 属性、**不**生成 identity 节点 | `src/blackbox/graph/extract.ts`、`builder.ts`、`desk.ts` |
| 3 | 43 次调用 / 22 个唯一请求，重复不复用 | 请求签名（method+url+body/headers，url 用节点 id 归一）连续 3 次同签名 → `dead_end`，执行前拒收；`dead_end` 改为不可被后续 ingest 覆盖 | `desk.ts`、`builder.ts` |
| 4 | `component_drift` 连发 3 次、agent 0 次采纳 | 记成“欠账”：第 2 次起升 high，并在上下文里给**可直接复制的 tool_requests 模板**（`graph_drift.template`） | `progress.ts`、`desk.ts`、`context.ts` |

复算结果（同一会话重放）：`blocked 0 → 9`、`dead_end 0 → 2`、`wall` 节点 `0 → 9`。详见 `docs/report-2026-10-28-note-yun-graph.md` §9。

**仍未修**：`required_tasks` 校验失败仍然只回 `(item): Invalid input`（这一轮 13 条任务项因此被丢，是“反复重新声明任务”的直接原因）——这条留到下一轮，因为它要求把 Zod 的 issue path 结构化成“缺哪个键/哪个键类型错”，改动面比前四项大。
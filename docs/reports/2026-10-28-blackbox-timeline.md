# 2026-10-28 黑盒执行时间线（会话 `20ea56baa4569b8d`）

> 数据源：容器内 `nianyun.db` —— `blackbox_events`（752 条，其中今日 261 条）+ `blackbox_sessions.checkpoint_json`。
> 所有时间均为北京时间（UTC+8）。事件原文取自 `kind`/`text`/`data_json`，未做改写，摘录用 `…` 断开。
> 导出方式见 §5，可逐条复核。

| 项 | 值 |
|---|---|
| 项目 / 会话 | `Ledger` / `p_06db586d65` / `20ea56baa4569b8d` |
| 会话目标 | `http://gray-push-intl.oppo.com/` |
| 今日实际触及 | `gray-push-intl.oppo.com`、`push-intl.oppo.com`、`gray-oversea-push.heytapimg.com`（仅引用，未直连） |
| 时间窗 | 10:15:59 → 12:09:53（1 小时 54 分） |
| Run 次数 | 6（10:23:40 / 10:34:11 / 11:52:40 / 11:59:43 / 12:01:56 / 12:06:13） |
| Run 结束方式 | `validation_failed` ×5、`observer_review_failed` ×1 —— **没有一次正常收口** |
| 工具调用 | 17 次：`http.request` 10、`burp.send` 3、`fs.list` 2、`browser.open` 1、`browser.storage` 1（全部 `ok=true`） |
| 证据增益 | 6 条 `evidence-value`，合计 +7 分（+2/+1/+1/+1/+1/+1，全落在 host_header 任务） |
| Observer | 建议 11 条、审查 12 次、审查失败 1 次 |
| 人工干预 | `focus-lock` 3 次、强制收口 9 次、撤销收口 1 次 |
| 任务表（38） | `blocked` 26 / `pending` 7 / `completed` 3 / `failed` 2，`planRevision` 19 |
| 结论 | 两个技术面判完（T30 verified-negative、T3 认证链不可达），第三面（Host 头注入）在没有真正发出 Host 头的情况下耗掉 5 轮，最终由模型改判 completed |

---

## 1. 时间线

### A 段 10:15–10:22 · 人工焦点抖动（与攻击无关，但吃掉了开场 8 分钟）

| 时刻 | 事件 | 说明 |
|---|---|---|
| 10:15:59 | `focus-lock` | 操作员切到 T30 |
| 10:16:15–10:16:33 | `focus-convergence` ×9 | 连续收口 T30 / T3 / host_header / open_redirect / takeover / T_WAF_PROBE / T6_cors_verify / T7_api_auth_code / T_CDN_JS |
| 10:16:43 | `focus-lock` | 又切回已被收口的 T30（死节点） |
| 10:20:05 | `focus-restore` | 撤销 9 条收口，焦点回 T3 |
| 10:22:24 | `focus-lock` | 再次切到 T30 |

这 9 次收口是误操作，已由 `focus-restore` 全部退回（详见 §41.4）。现在的护栏：收口要二次确认、`switch` 拒绝死节点、`operator_blocked` 非空时出现「撤销收口」。

### B 段 10:23:40–10:26:13 · run1：T30，判「兄弟主机是同一空壳」

| 时刻 | 动作 / 结果 |
|---|---|
| 10:23:25 | `preflight` 冒烟通过，13 个工具可用 |
| 10:23:57 | `GET https://push-intl.oppo.com/api/user/info` → 200 |
| 10:23:58 | `GET /v3/api-docs` → 200；`GET /actuator/health` → **412**；`GET /` → 200 |
| 10:23:58 | `anomaly-exploit`：3 条路径响应同长度 → 停止目录遍历，派生 Host 头注入 / 开放重定向 / 子域接管三条任务 |
| 10:25:18 | `validation-failed`：summary 声称"本轮尚未产生新的证据 ID"，而账本已有 4 条（`ev-0e8312c6…`、`ev-95540c11…`、`ev-9313c163…`、`ev-710f83f8…`） |
| 10:25:48 | `advice-disposal-round`：补跑一回合处置建议 |
| 10:26:13 | T30 结案 `verified-negative`（同构 SPA 空壳），run 结束 |

Observer 在这一轮就点出了后面 1.5 小时的关键情报，但没被采纳：

> 三个主机的 index 都只有 dns-prefetch + 两个 CSS，无可用 `<script src>`，且 publicPath 指向 oversea-push.heytapimg.com（非 gray- 前缀）——此前所有 404 都在 gray-oversea-push.heytapimg.com 上试，命名族试错方向本身错了。…必须换打法。

### C 段 10:34:11–10:37:17 · run2：T3 认证链，判「不可达」

| 时刻 | 动作 / 结果 |
|---|---|
| 10:34:39 | `browser.open /login` → 200，title=`OPush Operation Platform`，可见文本只有 `Loading....`，`forms=[]` |
| 10:34:39 | `browser.storage`：注入 0 Cookie，localStorage 仅 1 项 |
| 10:34:39 | `graph-hypothesis-closed`：**假设降级（stall）：换攻击面，别再打这条** |
| 10:34:40 | `GET /login` → 200（body 与首页同构，净 4848B） |
| 10:35:24 / 10:36:35 | Observer 两次指出同类重复动作；`supervisor-pause` |
| 10:37:17 | 模型自行把 T3 判 `blocked`（认证链不可达），run 结束 |

### D 段 11:52:40–11:55:39 · run3：host_header，5 条请求全落空

| 时刻 | 动作 / 结果 |
|---|---|
| 11:53:00–11:53:02 | `GET http://gray-push-intl.oppo.com/` ×4 → 301，Location 恒为 `https://gray-push-intl.oppo.com/?<随机>`；`GET https://…/` → 200 |
| 11:53:00–11:53:02 | `evidence-value` +2/+1/+1/+1/+1 —— 增益来自"301 vs 200"这类状态码变化，不是注入生效 |
| 11:54:12 | Observer：证据里只有响应段，**没有 request_headers，也没有 http.diff verdict**，因此无法证明 Host 真被发出 |
| 11:55:01 | Observer 追加：该批 `tool_requests` 里投递了 `input.baseline/variant` 的非法字段被丢弃 |
| 11:55:39 | `action-skipped`：建议处置回合不执行工具（3 个请求登记延后），run 结束 |

### E 段 11:59:43–12:01:28 · run4：改用 Burp 重发，仍然 301

| 时刻 | 动作 / 结果 |
|---|---|
| 12:00:02–12:00:05 | `burp.send` ×3 → 全部 `301 in ~1200ms (0 bytes)` |
| 12:00:57 | Observer 点名：**「焦点任务本身已经可结案，但主 Agent 仍在用『再造几条伪造头请求』的方式延长它」**；并指出真正瓶颈是 CDN 上 umi 主 bundle 的真实文件名 |
| 12:01:09 | `review-failed`：Observer 响应为空或协议校验失败 |
| 12:01:28 | run 结束（`observer_review_failed`），`action-skipped` 1 个请求延后 |

### F 段 12:02:18–12:05:01 · run5/run6：http.diff 三条全被 schema 丢弃

| 时刻 | 动作 / 结果 |
|---|---|
| 12:02:18 | 模型声称发起 3 条 `http.diff` 对照 |
| 12:03:11 | Observer：架构判定已明确（nginx 静态壳 + umi 全路径 catch-all + `/actuator` WAF 412 + 前端产物在跨域 CDN） |
| 12:04:24 | Observer 点名：3 条 `http.diff` 全部落在 `_dropped(Unrecognized keys: baseline/variant/label)`，**请求根本没有发出**，summary 里"待 verdict"是事实性错误 |
| 12:05:00 | 模型改判该任务 `completed`（verified-negative），run 结束（仍是 `validation_failed`） |

### G 段 12:06:13–12:09:53 · run7/run8：在工作区里找 http.diff 的写法

| 时刻 | 动作 / 结果 |
|---|---|
| 12:07:08 | `fs.list .` → 3 项；`fs.list state` → 0 项；`fs.grep` 因 `pattern` 被拒 |
| 12:07:55 | Observer：**主 Agent 从未真正发出过 `Host: evil.example`**（`ev-57a5896d…`、`ev-7b1d7362…`、`ev-83cb154e…` 的 `input.headers` 只有 `user-agent`），所以那是「XFH verified-negative」，不是「Host 注入 verified-negative」 |
| 12:09:13 | Observer：连续第 3 轮停滞；`ev-f14d97cf1ec3fcbd` 的 4848 字节首页已在账上，`evidence.read` 就能拿到 `<script src>`，**连续多轮未做** |
| 12:09:53 | `action-skipped` 3 个请求延后，run 结束 |

### 今天真正没打的三张牌（Observer 逐轮点名，全程未动）

1. `evidence.read` 读回 `ev-f14d97cf1ec3fcbd` 的 4848B 首页体，取 `<script src>` —— 这是唯一能穿透全路径 catch-all 拿到真实后端路由的入口；
2. `https://gray-oversea-push.heytapimg.com/?prefix=umi.&max-keys=100` 返回 200（`ev-52cfbb82edf8d151`），**响应体至今没人读**；若是 `ListBucketResult`，猜 bundle 文件的死循环当场终结；
3. 生产 CDN `oversea-push.heytapimg.com`（无 `gray-` 前缀）从未被请求过，而 SPA 的 `publicPath` 正指向它。

---

## 2. 为什么「聚焦了也集中不了」——五条根因

焦点锁解决的是"打哪条任务"，今天证明这不够：**任务粒度过粗、结案判据缺失、协议层反复自伤**，三者叠加后，模型在同一技术上原地转 5 轮。

### R1 Host 头被我们自己的过滤器静默丢掉（P0，已修）

`tools.ts` 的 `BLOCKED_REQUEST_HEADERS` 含 `host`，`requestHeaders()` 命中就 `continue`；
`progress.ts` 的 `identity()` 记录的是**过滤后**的头，所以证据里只剩 `user-agent`。
于是模型"发了 Host"→ 执行器删了 → 响应不变 → 模型以为"注入无效"→ 换变体重发。

这不是模型蠢，是我们让它无法自证。已改：

| 改动 | 位置 |
|---|---|
| 新增 `requestHeadersWithDropped()`，返回 `{headers, dropped}` | `src/blackbox/tools.ts:405` |
| 新增 `droppedHeaderNote()`：把"谁被丢、为什么、该换哪个工具"写进 summary | `src/blackbox/tools.ts:426` |
| `http.request` 结果带 `headers_dropped` 字段 + summary 追加 `⚠ 已忽略受限头 host…`（两个返回分支都加） | `src/blackbox/tools.ts:1098`、`1122` |
| 证据身份记录保留 `headers_dropped`，账本可对账 | `src/blackbox/progress.ts:554`、`607` |

### R2 提示词教错了参数名（P0，已修）

`agent.ts:228/230` 原文写「idor → http.diff 的 `baseline_self` + `diff_auth`」，而这两个是 **playbook 步骤 id**，不是 `http.diff` 的入参（真实入参是 `url` + `variant:{url,headers,cookie}`）。模型照抄成 `baseline/variant/label`。

`protocol.ts:79` 的 `toolRequestSchema` 是 `.strict()`，未知键 → 整条 `tool_request` 被丢弃。三次尝试、三条请求、一轮 run 全部作废，而模型只收到一句"本轮有 N 个条目格式无效"。

已改：提示词改为 playbook 步骤名 + 真实参数样式，并注明 `http.request` 不能改写 Host、Host 类验证走 `burp.send`（`src/blackbox/agent.ts:228`、`230`）。

### R3 丢弃回执不告诉模型「正确键是什么」（P0，未改）

`agent.ts:87 salvageItems()` 只回 `{field, index, message}`，`message` 是 zod 原文（"Unrecognized key(s)…"）。模型拿到了错，但拿不到"该写什么"，所以连着 3 轮写同一批错键。

建议：回执里附**该工具允许的键清单 + 一条最小正确示例**（从 `tool_docs.ts` 取），并在 `protocol-warning` 事件里落盘。这样一次丢弃 = 一次教学，而不是一次空转。

### R4 摘要与账本脱钩（P0，未改）

今日两次硬矛盾：

- 10:25:18 "本轮尚未产生新的证据 ID"，账本 4 条；
- 12:04:24 "本批结果尚未返回 / 待 verdict 落账"，请求根本没发出。

两次都直接触发 `validation_failed`，整轮作废。模型凭记忆写 summary，没有任何机制强制它引用本轮 `tool-result` 返回的 evidence id。

建议：summary 增加机器校验——本轮有 `tool-result` 但 summary 未引用其 evidence id、或声称"未产生证据"而账本有新增，则该轮**不入账**并回灌一条"请引用 `ev-…`"。

### R5 任务粒度是"技术面"，但缺"结案三件套"（P1，未改）

`host_header_injection` 的任务描述是"发伪造 Host / XFH / XFF，对比 Location/body"。可它有 6 种做法、5 种判据，没有一条"做到什么程度算结案"。

结果：5 条 http.request + 3 条 burp.send + 3 条 http.diff 之后仍 `pending`；Observer 三次说"早已可结案"，模型两次自判 completed/blocked，第四次才定。任务表被 `superseded_duplicate` 撑到 26 blocked、`planRevision` 19。

建议：`verified-negative` 落账必须同时具备——(a) 一条 `http.diff` verdict；(b) `request_headers` 或 Burp 原始报文（证明载荷真的发出）；(c) 否定证据（响应不随载荷变化的具体字段）。三缺一 → 只允许 `blocked(reason=缺少X)`，不允许 `completed`。

### R6 焦点锁只锁"哪条"，不锁"这轮交什么"（P1，未改）

6 次 run 的产出是：4 条同构 200、3 条 301、1 条 412、0 个新入口。焦点从未切走，但每轮的"交付物"是模型自己随手定的，于是"再试一个变体"永远是最省力的选择。

建议：每轮开始时模型必须声明 1 个可验证产出（`evidence.read` 取 `<script src>` / 读 CDN 列举体 / 一次 http.diff verdict），该字段进 checkpoint，收口时核对；连续两轮未交付同一类产出 → 直接换面。

### 结构性对照

```
焦点锁住了"打 T30"            → 4 条 200/4803，判空壳完成（✅ 有效）
焦点锁住了"打 host_header"     → 请求没发出，5 轮空转（❌ 无效）
差别不在焦点，在"这一轮能不能被证伪"
```

---

## 3. 下一步（按优先级，未实施部分等你点头）

| 级别 | 事项 | 影响 |
|---|---|---|
| P0 已完成 | R1 Host 头丢弃可见、R2 提示词参数名 | 直接止住今天最大的空转 |
| P0 待批 | R3 丢弃回执带允许键 + 示例 | 一次丢弃=一次教学，省 1–2 轮/次 |
| P0 待批 | R4 summary 强制引用 evidence id | 消掉 `validation_failed` 的主因之一 |
| P1 | R5 结案三件套 | 任务表不再被 `superseded_duplicate` 撑爆 |
| P1 | R6 每轮交付物字段 | 把"聚焦"升级成"聚焦 + 可证伪" |
| P1 | 任务去重：`task_duplicate` 直接合并而非报警 | `planRevision` 19 → 个位数 |
| P2 | 把今天没打的三张牌（首页 `<script src>`、CDN 列举体、生产 CDN）写进 playbook 的"优先级兜底" | 下次同类架构不再从 Host 头开始 |

---

## 4. 附：今日证据索引（按任务）

| 任务 | 状态 | 关键证据 |
|---|---|---|
| `T30`（兄弟主机同构判定） | completed | `ev-9313c1635ccef58a` `/` 200/4803；`ev-0e8312c67f357b39` `/api/user/info` 200/4803；`ev-95540c11d700e5b0` `/v3/api-docs` 200/4803；`ev-710f83f814a47503` `/actuator/health` 412 |
| `T3`（认证链） | blocked | `ev-bdc407bfaad4b478` `/login` 200/4848；`ev-6174fe2bdca4fac8`、`ev-412f5a19f725bb92`、`ev-26998fe10fdc05e3` 浏览器三渲染 `Loading....`；`ev-90dcd55502916c4f` localStorage 仅 `umi_locale` |
| `host_header_injection_20261027061910` | completed（判据不足，见 R5） | `ev-cf0c69f3f514f15f`、`ev-358632cc9ea0e4e2`、`ev-6793df1f0d2fc006`、`ev-1bc9c92e34780f70`（http.request 侧）；`ev-e103f296418d0068`、`ev-fa4be2cc647868ba`、`ev-ba0609e5aa170c45`（Burp 三变体）；**缺**：Host 真正进入报文的证据 |
| `T_CDN_JS` 等 6 条 | pending | `ev-52cfbb82edf8d151`（`?prefix=umi.&max-keys=100` 返回 200，体未读）、`ev-d23df0fd877b3a60` 等 4 条 umi.`*`.js 404 |

---

## 4.5 落地记录（本轮已改并部署）

| 项 | 状态 | 证据 |
|---|---|---|
| R1 Host 头丢弃可见 | ✅ 部署 | `requestHeadersWithDropped` + `droppedHeaderNote`（`tools.ts:405/426`），`http.request` 结果带 `headers_dropped`；容器验证 `PROBE dropped=["host"]` |
| R2 提示词参数名 | ✅ 部署 | `agent.ts:228/230` 改为 playbook 步骤名 + 真实 `variant` 参数 |
| R3 丢弃回执带允许键 + 示例 | ✅ 部署 | `tool-guide.ts` 新模块；`protocol-warning` 附纠错文本；`checkpoint.drop_receipts` 回灌上下文 |
| R4 结论必须点名 ev-id | ✅ 部署 | `evidenceReferenceIds` + 结案/受阻两条门禁（`progress.ts:432/496`） |
| R5 结案审计 | ✅ 部署（口径见下） | `closureAudit`：声明了 deliverables 必须逐条认领 |
| R6 结构化任务契约 | ✅ 部署 | `deliverables / success_criteria / fallback_strategy` 进协议、账本、上下文、提示词 |
| 任务去重自动吞噬 | ✅ 部署 | 不再 `reject(task_duplicate)`；`absorbTaskSpec` + `task-merged` 事件 + `planMergeLog` |

两处与方案原文的偏离（已写进 §42.5）：契约缺失不硬拦（硬拦会让每条新任务多花一轮，实测 7 个生命周期用例因此挂），
R4 不覆盖「没写 outcome」的结案（避免两道门重复拒绝）。测试：683 passed / 2 skipped，2 个失败为既有红项。

## 5. 复现方式

```powershell
# 1) 导出事件与 checkpoint（容器内）
docker cp .tmp-probe/export-events.mjs nianyun-control-nianyun-1:/opt/nianyun/probe-export.mjs
docker exec -w /opt/nianyun nianyun-control-nianyun-1 node probe-export.mjs
docker cp nianyun-control-nianyun-1:/opt/nianyun/export-events.json .tmp-probe/export-events.json

# 2) 统计 + 全文
python .tmp-probe/digest.py      # → .tmp-probe/digest.md（事件分类、任务排名、工具分布）
python .tmp-probe/critical.py    # → .tmp-probe/critical.md（analysis/advice 全文）
python .tmp-probe/quotes.py      # → .tmp-probe/quotes.md（关键建议原文）
```

---

## 6. 诚实备注

- 今日事件数按 `created_at >= 2026-10-28T00:00+08:00` 统计为 261；`updated_at` 视角会多 1 条边界外事件，差异不影响结论。
- 全部引用为库内原文，未改写；摘要信息来自 `checkpoint_json`，不含模型未落账的内心活动。
- R1/R2 的代码改动已 `tsc --noEmit` 通过、全量测试 670 passed / 2 skipped（2 个失败为既有红项 `assets.test.ts`、`candidates.test.ts`），**尚未在真实 run 中验证效果** —— 下一场会话跑起来后要看的是：`headers_dropped` 是否出现在 tool-result，以及 `_dropped` 是否归零。
- 本文只做归因与修复，未改动任何判定逻辑；`T3` 与 `host_header` 的最终状态仍是模型自判，按 R5 的标准都属"判据不足"。
# 会话记录报告：support.oppo.com（会话 `463dd72637d195c6`）

项目 `p_06db586d65` ｜ 目标 `http://support.oppo.com/` → 302 → `https://support.oppo.com/cn/`
最终状态 `paused / awaiting_operator`，原始终止原因 `observer_review_failed`；续跑两轮（22:06:31、22:10:50）的停止原因是 `required_review_pending`
窗口 **18:59:57 → 20:52:49（112.9 分钟）**，其中 **19:05:36 → 20:31:53 是门禁空转（86 分钟）**，真正干活 10 分钟。
预算消耗：**16 轮 / 14 次工具调用计数（9 实跑 + 5 装甲拒收）/ 554,886 tokens / 工具耗时 109.8 s / 累计 elapsed 782 s**。

**会话之后**（详见 §1「会话之后」小节）：21:40–21:49 离线修了“字典命中当端点”并重放账本，图从 127 节点/120 块降到 16 节点/8 块；
22:06:31、22:10:50 两次续跑各 **0 次工具调用**、各 77–108 秒，仍被 `review-stale` + 主权假阳性双重锁死。

> 同一会话的图结构见 [历程图报告](report-2026-10-28-support-oppo-graph.md)。

---

## 1. 时间轴（UTC+8，逐条）

### 第一段：铺面（19:00:07 – 19:05:36，4 分 29 秒，2 次工具调用）

| 时间 | 事件 | 结果 |
|---|---|---|
| 18:59:57 | `lifecycle` | 会话创建 |
| 18:59:57 / 19:00:05 | `environment` + `preflight` | **跑了两遍**（13 工具可用、Burp 可达） |
| 19:00:07 | `lifecycle` | 开始按任务状态机推进 |
| 19:00:25 | `analysis` #1 | 声明 4 条任务 `T1_surface_map / T2_unauth_exposure / T3_js_secrets / T4_api_routes_probe` |
| 19:00:25 | `protocol-note` | 3 条请求带未登记键：`burp.history.host`、`katana.duration`、`content_discovery.extensions/match_codes` |
| 19:00:26 | `focus-lock` | 锁定 T1：拒收 1、放行 3 |
| 19:00:26 | `armor-reject` | `burp.history` 无过滤条件被拒（`bare_history_use`） |
| 19:01:31 | `tool-result` | katana 抓到 **6 条 URL** → 图 +8 节点 |
| 19:01:41 | `tool-result` | `js_endpoints`：`/cn` **未引用可分析的 JS** → `/cn` 判 `dead_end` |
| 19:01:41 | `linkage-burp` | 自动投递 `burp_scan_20261028110141` 任务 |
| 19:01:54 – 19:02:39 | `analysis` #2–#5 | 连续 4 轮“重新声明任务”，`task-merged` 4 次（并入 1+3+2+3 条） |
| 19:02:39 | `focus-convergence` | T1 已耗 5 轮 / 9 TP，连续 3 轮无高价值证据 → 强制收口 |
| 19:04:39 | `protocol-error` | 主 Agent 输出校验失败，**整轮动作作废** |
| 19:04:55 | `protocol-warning` | 4 条条目无效，首条报错 `required_tasks[0]: invalid_union: Invalid input` |
| 19:05:10 | `terminal-review-trigger` | 阶段结束前要求 Observer 终审 |
| 19:05:36 | `lifecycle` + `review-stale` | **停止：`observer_review_stale_snapshot`**，门禁保持 |

### 空转：19:05:36 → 20:31:53（86 分 17 秒）

会话卡在 `awaiting_operator`：Observer 结果对不上快照（`review-stale`），门禁不放行，主 Agent 不推进。
这 86 分钟没有任何工具调用。

### 第二段：恢复后的 5 分钟（20:31:53 – 20:40:03，7 次工具调用）

| 时间 | 事件 | 结果 |
|---|---|---|
| 20:32:06–20:32:10 | 5 × `http.request` | `/robots.txt` **200**；`/.git/config` **412**；`/.env` **412**；`/actuator/env` **412**；`/v3/api-docs` **301** → `/v3/api-docs/?zhyk1j2=1` |
| 20:32:10 → 20:32:40 | `content_discovery` | 29.8 s，**113 行命中**（`-s -ac -mc 200,201,…,500`） |
| 20:32:40 | `dict-probe` | 113 → **4 个抽样探针**（`sensitive:/.env~`、`api_doc:/openapi.json`、`admin:/admin.jsp`、`other:/`），生成 `T_DICT_PROBE_90760571` 并劫持焦点 |
| 20:32:40 | `graph-signal` #1 | 图裂成 119 块，112 块没动过，Root 建议 `flag.php`/`flag.txt`/`.env.local` |
| 20:33:09 | `http.request` | `/.env~` → **302 `https://www.oppo.com//404/`** |
| 20:33:09 | `sovereignty-transfer` | **主权转移**：改写 10 条任务到 `www.oppo.com`，旧 host 上锁 |
| 20:33:09 | `cluster-expand` | sensitive 类展开 3 条（`/.env.local`、`/backup.zip`、`/www.zip`），排队给下一轮 |
| 20:33:09 | `armor-reject` ×4 | 同一轮剩下的 `openapi.json`、`admin.jsp`、`/`、`http.diff /.env~` **全部被旧 host 域锁拒收** |
| 20:33:13 – 20:35:31 | `review-stale` ×3 + Observer 插话 | 【先结案焦点】【先解死锁】两条建议 |
| 20:33:56 – 20:35:13 | `analysis` #10–#12 | 三轮都在解释“为什么探针打不出去” |
| 20:35:13 | `action-skipped` ×14 | `exclusive_task:post_surface_…` 重复动作被抑制 |
| 20:36:02 | `review-result` | Observer 审查结果已持久化（唯一一次成功） |
| 20:36:23 / 20:37:25 | `tool-requests-rejected` | 分别忽略 **7** 条、**5** 条“无法归属任务”的请求（合计 12 条请求作废） |
| 20:37:26 | `terminal-review-trigger` | 再次要求终审 |
| 20:38:03 / 20:39:26 / 20:40:03 | `review-failed` ×3 | “Observer 响应为空或协议校验失败” |
| 20:39:26 | `lifecycle` | **停止：`observer_review_failed`** |

### 会话之后：离线修复与两次续跑（21:40 – 22:13）

会话暂停后不再由 Agent 驱动，这一段全部是人工触发的离线操作与续跑，时间取自 `blackbox_events`。

| 时间 | 事件 | 结果 |
|---|---|---|
| 21:40:51 / 21:41:34 / 21:42:06 / 21:42:32 / 21:42:40 / 21:49:01 | `graph-rebuilt` ×6 | 部署“命中降级为候选”后重放账本：**127 节点 → 16 节点**，**120 块 → 8 块**（最大块 9），113 条命中挂到 `asset:support.oppo.com` 的 `candidates`，不建节点 |
| 21:47:07 | `protocol-backfill` + `historical_inference` ×2 | 协议回放：9 条 tool-result / 历史 9 次调用 → 新协议下 8 次；`dict_collapse` 指出第 8 条应折叠成 4 个探针（`/.env~`、`/openapi.json`、`/admin.jsp`、`/cn/`），`sovereignty_transfer` 指出第 9 条会搬 host |
| 22:06:31 | `checkpoint-archived`（第 3 次 run）+ `lifecycle` | 续跑 #1 开始；Observer 遗留审查被重置为待审（`review-recovered`） |
| 22:07:08 | `protocol-note` | 模型仍在猜键名：`exec.python` 忽略 `timeout_s/memory_mb/code`（可用：`url, params`） |
| 22:07:08 | `analysis` + `graph-rank` | 焦点 `T3_js_secrets`，**仍只对 `www.oppo.com` 发请求**（主权假阳性未消解），4 条请求全部 0 分、未绑定打法 |
| 22:07:08 | `action-skipped` ×4 | `exclusive_task:post_surface_…` 重复动作抑制 |
| 22:07:45 | `review-result` + `advice` | Observer 认为方向对，但点名两条被忽略的硬线索（CORS 反射 `ev-f7cf…`、`/jimu/` bundle） |
| 22:07:56 | `review-stale` | **Observer 结果对不上快照 → 门禁保持** |
| 22:08:19 | `action-skipped` + `lifecycle` | “建议处置回合不执行工具：3 个请求已登记延后” → **停止：`required_review_pending`**（run3 = 108 秒，0 次工具调用） |
| 22:10:50 | `checkpoint-archived`（第 4 次 run）+ `lifecycle` | 续跑 #2 开始，焦点仍是 `T3_js_secrets` |
| 22:11:06 | `evidence-query` + `analysis` | 先查历史证据再定题（本轮新增动作），结论仍是“support 侧配置类路径被 WAF 整类拦截，转 www 的 bundle” |
| 22:11:49 / 22:11:51 | `review-result` + `advice` / `review-stale` | 同一个循环再来一次：建议产出 → 快照对不上 → 门禁保持 |
| 22:12:07 | `action-skipped` + `lifecycle` | 3 个请求延后 → **停止：`required_review_pending`**（run4 = 77 秒，0 次工具调用） |
| 22:13:05 | `graph-rebuilt` | 又一次重放（16 节点 / 14 边 / 8 块，`graph_drift=null`） |

两次续跑的合计：**2 轮、0 次工具调用、9 次 `action-skipped`、6 条请求延后、2 次 `review-stale`、2 次 `required_review_pending` 停止**。

**修复有没有生效，看一个数就够**：`graph-signal` 在旧图上一共触发 **8 次**（20:32:40–20:37:25，全部在催 `flag.php`/`flag.txt`/`.env.local`），
续跑两轮里 **0 次**——图不再裂，也不再往上下文里灌字典条目。但这两轮同样 0 次工具调用，说明真正锁死会话的不是图，是主权假阳性和 `review-stale`。

---

## 2. 9 次工具调用逐条

| # | 时间 | 工具 | 输入 | 结果 | 证据 |
|---|---|---|---|---|---|
| 1 | 19:00:26 | `katana.crawl` | `https://support.oppo.com/cn` | 6 URL（`/cn`、2 个 asset、3 个 `jimu/*.js|css`、`www` 侧 2 个）| `ev-38464a3a5587ba05` |
| 2 | 19:01:31 | `recon.js_endpoints` | `/cn` | “页面未引用可分析的 JavaScript 文件” | `ev-dd2068b78d1dfca9` |
| 3 | 20:32:06 | `http.request` | `/robots.txt` | **200** | `ev-f7cfc51bff9a1e1a` |
| 4 | 20:32:07 | `http.request` | `/.git/config` | **412**（WAF） | `ev-d97c25e1dda56bd4` |
| 5 | 20:32:09 | `http.request` | `/.env` | **412** | `ev-d95d0d0018f01289` |
| 6 | 20:32:09 | `http.request` | `/actuator/env` | **412** | `ev-6127693203332a6d` |
| 7 | 20:32:10 | `http.request` | `/v3/api-docs` | **301** → 自身带随机参数 | `ev-b08d7f6b82c3a97c` |
| 8 | 20:32:10 | `recon.content_discovery` | `https://support.oppo.com`（默认 `paths.txt` 290 行） | 113 命中，29.8 s | `ev-426a8a3ac54823da` |
| 9 | 20:33:08 | `http.request` | `/.env~` | **302** → `https://www.oppo.com//404/` | `ev-31c116ca7b67087d` |

工具错误 6 条（`tool-error`），其中 `burp.history` 因宝箱式调用被装甲拒；`tool-result` 9 条全部 `ok:true`。

---

## 3. 任务状态机：声明 19 条，完成 0 条

| 状态 | 数量 | 说明 |
|---|---|---|
| `blocked` | **8** | `T1_surface_map`（`focus_stalled`）、`T2_unauth_exposure`（`focus_stalled`）、`T_DICT_PROBE_90760571`、5 条 `action:<hash>` |
| `pending` | **11** | `T3_js_secrets`、`T4_api_routes_probe`、`burp_scan_…`、`T1/T2/T3`、`surface_baseline`、`unauth_exposure_probe`、`T1_surface_recon_support`、`post_surface_…` |
| `completed` / `failed` | 0 / 0 | 交付物 0 条 |

三个结构性问题：

1. **重声明成瘾**：`task-merged` 5 次，累计并入 **11** 条重复任务（`T2` 被并入 4 次、`T3` 3 次、`T1` 2 次）。
   每轮都在“重新声明同一批任务”，而不是推进。
2. **`action:<sha256>` 任务是垃圾**：5 条任务的 `target` 是 `undefined`、`deliverables` 为空、永久 `blocked`。
   它们来自把 agent 的“动作”误判成任务，只会让终验的 `TASKS_NOT_TERMINAL` 永远挂着。
3. **主权转移改写后的任务契约自相矛盾**：`T2_unauth_exposure.target` 被改成 `https://www.oppo.com/`，
   但 `purpose`/`completion_criteria` 仍在讲 support 的鉴权墙（Observer 也点了这一条）。
   改写只改了字段 `target`，没有改契约文本。

---

## 4. 协议层摩擦：51 条请求被挡、9 条实跑（5.7 : 1）

| 拦截类型 | 条数 | 出处 |
|---|---|---|
| 焦点锁拒收 | **34** | `focus-lock` 9 次（1+4+2+2+3+4+3+6+… ） |
| 装甲拒收 | **5** | `armor-reject`：1 次 `bare_history_use` + 4 次 `sovereignty_moved` |
| 无法归属任务的请求 | **12** | `tool-requests-rejected`：7 + 5 |
| 未登记键被摘 | **7 轮** | `protocol-note`：`host`、`duration`、`extensions/match_codes`、`probe_sensitive`、`include_keys`、`max_urls`、`max_body_bytes`、`reason` |

### 4.1 未登记键：模型一直在猜参数名

| 模型想传 | 使用的工具 | 真实可用键 |
|---|---|---|
| `host` | `burp.history` | `url, params` |
| `duration`、`max_urls` | `katana.crawl` | `url, params` |
| `extensions`、`match_codes`、`probe_sensitive` | `recon.content_discovery` | `url, params` |
| `include_keys` | `recon.js_endpoints` | `url, params` |
| `max_body_bytes`、`reason` | `http.request` | 12 个键，但没有这两个 |

`burp.history` 的 `host` 是**合理需求**（按主机过滤），`katana.duration` 也是合理需求（限时爬取）：
不是模型乱写，而是 schema 太窄。这条与 note.yun 那轮完全同型。

### 4.2 结构化回执只解决了一半

`required_tasks[0]: invalid_union: Invalid input` —— 上一轮做的结构化回执在这里**退化回旧文案**：
`invalid_union` 分支没带出“缺哪个键”。原因在 zod 版本差异：v4 的 `invalid_union` 用 `errors`（issue 数组的数组），
我读的是 v3 的 `unionErrors`。这条要修（`src/blackbox/validation-envelope.ts` 的 `snapshotIssues`）。

### 4.3 一次整轮丢弃

`19:04:39 protocol-error`：主 Agent 输出校验失败 → **整轮动作未执行**（含已规划的多条请求）。
这是纯粹的产能损失，且没有任何局部挽救（比如保留合法条目）。

---

## 5. 主权转移：一次假阳性如何连锁毁掉整轮

### 5.1 触发

`/ .env~` 返回 `302 → https://www.oppo.com//404/`。协议按“跨主机 301/302 = 主权转移”判定，
改写了 **10 条任务** 到 `www.oppo.com`，并把 `support.oppo.com` 上锁。

### 5.2 但这是一个 catch-all 吸收跳转，不是主权转移

证据（都在同一份账本里）：

| 观测 | 含义 |
|---|---|
| 非关键字路径统一 `302 → https://www.oppo.com//404/` | 边缘把未知路径统一吞到 404 页（注意 `//` 双斜杠） |
| 配置类路径统一 `412`（2681B，`securityfs.oppo.com`） | 关键字命中的 WAF 阻断页 |
| `/robots.txt` 200、`/v3/api-docs` 301 到自身加随机参数 | 边缘随机回显特征 |

真正的“主权转移”应当是：旧 host 的所有路径都跳到同一个**真实站点落地页**（200 + HTML + 导航）。
这里跳到的是 `/404/` 吸收页——正确的分类是 `absorb_redirect`，动作应当是“标记该前缀为 catch-all，停止逐条打文件名”，
而不是“把整个会话搬到 www.oppo.com”。

### 5.3 连锁后果（同秒发生，自相矛盾）

```
20:33:09  sovereignty-transfer  → 改写 10 条任务到 www.oppo.com，support.oppo.com 上锁
20:33:09  cluster-expand        → 排队给下一轮 3 条 support.oppo.com 路径
20:33:09  armor-reject ×4       → 本轮剩余 4 条 support.oppo.com 请求按“已探过 + 域锁”拒收
```

- **展开与上锁同时发生**：`cluster-expand` 安排的 `/.env.local`、`/backup.zip`、`/www.zip` 下一轮**必然**被同一把锁拒收；
- **装甲判定理由不成立**：拒收文案说“这条路径已探过”，但 `/openapi.json`、`/admin.jsp`、`/` 从未发过请求
  ——它们只是被 `content_discovery` 灌进图里（113 条 `untested` 节点），而装甲把“节点存在”当成了“已探过”
  （`src/control/console/desk.ts:506`）；
- **跨资产偏离**：`support.oppo.com`（客服子系统）被整体让位给 `www.oppo.com`（主站），
  7 条任务的 `target` 变成主站，2 条变成 `www.oppo.com/cn/`——这是一次**未经确认的资产切换**；
- **无路可走**：旧 host 上锁、新 host 上没有任何已验证路径、字典探针任务又拿不到请求 → 只能把任务写成 `blocked`；
  之后 12 条请求被判“无法归属任务”，14 条“停止重复动作”。

Operator 在这个死锁后把会话挂起 87 分钟，恢复后仍然没有解开——最后以 `observer_review_failed` 收场。

### 5.4 三条必修

| # | 缺陷 | 位置 | 补丁方向 |
|---|---|---|---|
| 1 | catch-all 吸收跳转被当成主权转移 | `applySovereignty`（`src/blackbox/protocol.ts`） | 目标路径命中 `/404|/error|/notfound/i`、或目标响应非 200 HTML → 记 `absorb_redirect`，不改写任务、不上锁 |
| 2 | 装甲把“节点存在”当“已请求过” | `src/control/console/desk.ts:506` | `known = hits > 0 \|\| status !== "untested"` |
| 3 | 主权改写与聚类展开互相打架 | `src/control/console/desk.ts`（cluster expand 段） | 上锁时同步清空/迁移 `dict_probe.buckets`，并让 expand 的目标 host 跟随主权 host |

---

## 6. Observer / 门禁：10 次投递，3 次给出结论

| 结果 | 次数 |
|---|---|
| `review-stale`（结果对不上快照，门禁保持） | **6**（20:33–20:35 四次 + 续跑 22:07:56、22:11:51 各一次） |
| `review-failed`（响应为空 / 协议校验失败） | **3** |
| `review-result`（成功持久化） | **3**（20:36:02 一次 + 续跑 22:07:45、22:11:49 各一次） |
| `terminal-review-trigger`（终审要求） | 2 |

Observer 唯一一次成功给出的三条纠正**全部正确**，而且比主 Agent 的判断准：

1. **113 条不是“已确认存在的路径”**（推理有误，结论正确，见 §7.1）；
2. **CORS 线索被高估**：`robots.txt` / `.env~` / `v3/api-docs` 三次回三个**互不相同的随机域名**（`x850ke8ggj7.com`、`zbjaf4.com`、`zhyk1j2.com`），
   判定标准应写死为“ACAO 精确等于我们送的 Origin 且 `Allow-Credentials:true`”；
3. **架构特征**：support 侧未知路径统一 302 到 `www.oppo.com//404/`，配置类路径统一 412，
   页面资源全走 `/jimu/oppo-global-service/client/*.js`——AEM / Edge Delivery 型 CDN 静态壳。

门禁本身的失效模式值得记：`review-stale` 的定义是“Observer 结果基于旧快照，但仍有未解决阻塞项”，
一旦出现**阻塞项无法被消解**（本轮是“旧 host 上锁 + 任务全部 blocked”），它就会无限保持，
把会话钉在 `awaiting_operator` 86 分钟。需要一个“阻塞项不可消解 → 主动降级或请求人工”的出口。

**续跑两轮把这个失效模式又验了一遍**（22:06:31、22:10:50）：

| 轮次 | Observer 动作 | 门禁判定 | 结果 |
|---|---|---|---|
| run3（108 秒） | 22:07:45 给出 1 条 `advice`（点名被忽略的 CORS 反射 + `/jimu/` bundle） | 22:07:56 `review-stale` | 建议进不了执行：`advice-disposal-round` 只补跑一回合、3 条请求登记延后 → `required_review_pending` |
| run4（77 秒） | 22:11:49 再给 1 条 `advice`（本轮先 `evidence-query` 查账本再定题） | 22:11:51 `review-stale` | 同上：3 条请求延后 → `required_review_pending` |

也就是说：**Observer 的产出是有价值的，但 `review-stale` 把它变成了“只能读、不能执行”的死信**。
两轮里主 Agent 一次工具都没发出去，`action-skipped` 反而增长 9 次。

---

## 7. 真实战果（0 个漏洞，4 条可用结论）

| # | 结论 | 证据 | 可复用性 |
|---|---|---|---|
| 1 | OPPO 边缘 WAF：`{env,git,actuator}` 关键字命中 → 统一 412（2681B，`securityfs.oppo.com` 模板） | `ev-d95d…`/`ev-d97c…`/`ev-6127…` | 与 note.yun 那轮**同一模板**，可跨资产复用 |
| 2 | 未知路径统一 `302 → https://www.oppo.com//404/`（catch-all 吸收） | `ev-31c116…` + 113 条命中 | 决定了“逐条打文件名”是低产出策略 |
| 3 | 前端资源全在 `/jimu/oppo-global-service/client/*.js|css`（AEM/Edge Delivery 静态壳），页面本身无外部 JS 引用 | `ev-38464…`、`ev-dd20…` | 真正的攻击面在 `/jimu/` 前缀与边缘 Host 改写，而不是文件名 |
| 4 | 边缘对随机参数/随机 ACAO 的回显不可利用（三次三个随机域名） | Observer 逐条比对 | 可写成判定规则，避免后续把噪声当 CORS 配置错误 |

### 7.1 关于 113 条的一处纠正

Observer 说“count=113 与 dict_probe.total=113 相等 → 字典回显”，这是**循环论证**（total 就是从这 113 条算的）。
实际是 **ffuf 命中 113 / 字典 290 行**。但结论仍然成立，理由不同：
`-s` 静默模式只打印路径不打印状态码，所以这 113 条里混着“真 200”和“catch-all 302”，下游无法区分。
（`src/blackbox/tools.ts:1897`）

**21:40 之后**：这 113 条不再进图（`src/blackbox/graph/extract.ts` 的 `CANDIDATE_TOOLS`），改为 `asset:support.oppo.com` 上的
`candidates`（去重、上限 200），只有真发过请求才会建端点节点。图因此从 120 块回到 8 块。
状态码仍然缺——`-s` 那条没修，所以候选里哪条是 200、哪条是 catch-all 302，仍旧只能靠单发探针确认。

---

## 8. 和 note.yun 那轮的横向对比

| 维度 | note.yun `1cdf92d4816b72bf` | support.oppo.com `463dd72637d195c6` |
|---|---|---|
| 工具调用 | 47（成功执行） | **9** |
| 轮次 / tokens | 29 轮 / 1,092,502 | 16 轮 / 554,886 |
| 被挡请求 | 34 拒 + 13 条目丢弃 | **51**（34 焦点 + 5 装甲 + 12 无法归属） |
| 完成 / 受阻任务 | 0 完成 / 3 受阻 | 0 完成 / **8 受阻** |
| 有效结论 | 3（301 架构、WAF 412、SPA 壳） | 4（WAF 412、catch-all 302、`/jimu/` 静态壳、CORS 噪声）|
| 会话终结 | `observer_review_failed` | `observer_review_failed` |
| 协议副作用 | 无 | **主权转移假阳性 → 跨资产偏离 + 自我死锁** |

两轮的共同病根没变：**声明任务的时间 > 发请求的时间**（note.yun 29 轮 47 调用；本轮 16 轮 9 调用，其中 12 条请求因“无法归属任务”作废）。

---

## 9. 能力缺口 → 待修清单（9 条，1 条已修）

| # | 缺口 | 位置 | 现状（22:13） |
|---|---|---|---|
| 1 | catch-all 吸收跳转误判为主权转移（本轮唯一致命项） | `applySovereignty` / `src/blackbox/protocol.ts` | **未修**：续跑两轮仍在“只对 www.oppo.com 发请求” |
| 2 | 装甲把“节点存在”当“已探过” | `src/control/console/desk.ts:506` | 未修 |
| 3 | 主权改写与聚类展开互相打架（同秒自相矛盾） | `src/control/console/desk.ts` cluster expand 段 | 未修 |
| 4 | `invalid_union` 回执退化（zod v4 用 `errors` 非 `unionErrors`） | `src/blackbox/validation-envelope.ts` | 未修 |
| 5 | `action:<hash>` 任务无 target、永久 blocked，拖死终验 | 任务抽取（`agent.ts` salvage/declaration 段） | 未修（19 条任务里 8 条 blocked） |
| 6 | ffuf `-s` 丢状态码 | `src/blackbox/tools.ts:1897` | 未修 |
| 7 | `review-stale` 无“不可消解”出口 | 门禁（`review` 决策段） | 未修：续跑 2/2 轮都死在这里 |
| 8 | 合理参数（`burp.history.host`、`katana.duration`）schema 不支持 | `src/blackbox/tools.ts` 各工具参数表 | 未修（续跑还在丢 `exec.python` 的 `timeout_s/memory_mb/code`） |
| 9 | 字典命中被当端点写进图，图裂成 120 块 | `graph/extract.ts` / `graph/builder.ts` / `graph/analyze.ts` | **已修并部署**（8f9b08558b73）：127→16 节点、120→8 块、漂移提醒 8 次→0 次 |

第 9 条的细节与回归测试见 [历程图报告 §11](report-2026-10-28-support-oppo-graph.md)，自造缺陷记在 [约束审计 §49](agent-constraints-audit.md)。
它修完之后续跑两轮一次 `graph-signal` 都没触发，这条可以结案；剩下 8 条按 §10 的优先级继续。

---

## 10. 结论

- **产能**：10 分钟有效作业、9 次调用，拿到 4 条可用结论，0 个漏洞；
- **最大损失**：不是“没打出漏洞”，而是**协议自己制造了一次资产偏离**——
  `/.env~` 的 302 被读成主权转移，10 条任务被改写、旧 host 上锁、剩余探针被自家装甲拒收、展开的 3 条路径永远打不出去；
- **最值得修的一条**：`absorb_redirect` 与 `sovereignty_transfer` 必须分开。
  catch-all 目标的正确动作是“停止逐条打文件名，转 `/jimu/` 服务接口 + 边缘 Host 改写”，
  而不是“把会话搬到另一个 host”；
- **已经证实的一条**：图不区分“观测到的面”和“猜出来的面”是万恶之源。把 113 条命中降级成候选之后，
  图 120 块 → 8 块、漂移提醒 8 次 → 0 次，上下文里再没出现过 `flag.php` 这种字典条目；
- **同时也证伪了一条**：“修好图就能推进”。续跑两轮（22:06:31、22:10:50）合计 **0 次工具调用**，
  两次都停在 `required_review_pending`，模型依旧只在 `www.oppo.com` 上打转。
  真正的锁是 **主权假阳性（catch-all 302 被读成资产转移）+ `review-stale` 无出口**，图的噪声只是把这两条盖住了；
- **下一步优先级**：`absorb_redirect` 与 `sovereignty_transfer` 拆分 > `review-stale` 的“不可消解”出口 > 其余。
  只要这两条不动，续跑多少次都是 77–108 秒一轮、0 次调用。
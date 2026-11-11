# m.ctrip.com 会话复盘：历程图为何碎成 54 块、路线为何空转、WAF 与工具缺口

> 对象：`https://m.ctrip.com/` · 项目 `p_06db586d65` · 会话 `ca82c7689b5ec7f3`
> 时间：2026-10-31 11:55:59 → 12:45:21（44 分钟，7 个 run）
> 原始记录：[report-2026-10-31-m-ctrip-session.md](report-2026-10-31-m-ctrip-session.md)（315 条事件全文导出）
> 数据来源：`data/nianyun.db` 的 `blackbox_sessions` / `blackbox_events` / `blackbox_evidence` / `blackbox_checkpoints`，以及运行容器的 `/opt/nianyun/data`。

---

## 0. 结论先行

| 问题 | 结论 |
|---|---|
| 历程图为什么分裂成很多块 | 不是模型"乱跑"造成的，是图构建器两条规则 + 一次跨域爬取叠加的必然结果：**53 个 `asset:*` host 卡片没有任何边**（视觉上 54 块）；按"可走边"计算则是 **310 个连通分量**，因为 `discovered_from` 被排除在 `WALKABLE` 之外，256 个真实页面在语义上互不可达。 |
| 主 agent 的规划有没有错 | 有，且是连续的：任务槽位爆到 12/12、`exec.python` 连续 5 次以空 `input:{}` 提交、`force_armored` 连续 3 次提交一个不存在的键、在 `exclusive_task` 与 `focus_lock` 双锁冲突下反复发注定被 skip 的请求。44 分钟只成功执行 3 次工具。 |
| Observer 的规划有没有错 | 方向大体正确（合并任务、换 `burp.send`、用 katana 已有 URL 复测、先平账再取数），但有两处实质误导：把 UA 差异说成"风控墙已绕开、应记 `waf_bypass(header/ua)`"；把 `code` 塞进 `params` 的建议本身违反执行器白名单（`exec.*` 在 `NO_PARAM_TOOLS`）。 |
| 路径有没有纠结 | 有明确死锁：`post_surface_20261031035800` 被提权为 `exclusive_task`，而焦点锁在 `T_DICT_PROBE`，两者互斥 → 12:06 起 16 条请求被 `action-skipped`；焦点任务 4 轮零产出，系统两次下 `focus-convergence` 要求收口，主 agent 到会话结束都没写 `task_outcomes`。 |
| 触发 WAF 有没有绕过尝试 | **没有触发，也没有绕过**。`waf_bypasses` 表 0 行，全程无 403/412/418/1020 类拦截证据；UA/编码/路径变体一次没发。唯一相关动作是 12:10:19 尝试写入一条 `waf_bypass` 战例，因 `dimension` 枚举值非法导致整轮输出作废。 |
| 有没有向管理员提出缺工具 | 提了 1 次（12:23:45 `tool-gap`）：缺"能把 SPA 渲染期真实 XHR/fetch（含 method 与 post_data）直接返回"的能力，点名 `browser.network` 或带 Playwright 的 `exec.python`，并标 `blocked_task=T_SPA_REVERSE_19018807`。但这条上报**半误报**：`exec.python` 本来就在 74 个工具里，真正的问题是输入 schema 没登记 `code`。 |

---

## 1. 这轮到底发生了什么（压缩时间线）

| 时间 | 事件 | 性质 |
|---|---|---|
| 11:55:59 | 会话创建；Burp `host.docker.internal:8080`、sandbox、13 个工具冒烟通过 | 环境正常 |
| 11:56:32 | 第一批请求带未登记键（`burp.history.host`），被摘键后执行 | 契约不符，首次 |
| 11:56:58 | `http.request` ×2 成功：根 `302 → /html5/`（48B Express）、`/html5/ 200`（41728B、`x-powered-by: NFES`） | 唯一有效基线 |
| 11:56:58 | SPA 判定（`mount:#__next`、`framework:reacti`、`text_ratio:0.01`）→ **缴械** `http.request`/`content_discovery`/`nuclei`/`api_routes`，生成 `T_SPA_REVERSE_19018807` | 正确的自动化判断 |
| 11:58:00 | `katana` 返回 277 URL，图一次 +377 节点（54 asset / 257 endpoint / 69 parameter）、+327 边；`vacations.ctrip.com` 102 条字典命中折叠成 `T_DICT_PROBE` 并**劫持焦点** | 图爆炸的起点 |
| 11:58:28 | 主 agent 声明 4 个任务并派 6 条请求 → 全部被 `focus_lock` 拒收（焦点在 `T_DICT_PROBE`） | 规划与调度冲突 |
| 11:58:49 | `post_surface_20261031035800` 被提权为 `exclusive_until_done` | 埋下死锁 |
| 12:04:21/23 | 两次 `graph/rebuild`：380/327 → **311/258**，69 个 parameter 节点消失 | 重建不一致 |
| 12:06:38 | 3 条 vacations 探针被 `exclusive_task` **skip**；触发 `task_backlog_full 12/12` | 死锁生效 |
| 12:07–12:12 | Observer 5 连评：认可方向、要求合并任务、提出 `waf_bypass` 归因（后被驳回） | 监督有效但有一次误导 |
| 12:08:34 | 第 1 次 `protocol-error`：`waf_bypasses.0.dimension` 值非法，整轮作废 | WAF 入账失败 |
| 12:10:43 | `focus-convergence`：`T_DICT_PROBE` 4 轮/3TP 零高价值证据，强制收口 | 系统兜底 |
| 12:13:45 | 主 agent 终于平账：12 个任务并到 5 个，`T_DICT_PROBE → blocked` | 迟到的正确动作 |
| 12:17:44 | 第 2 次 `protocol-error`：缺 `summary` 字段 | 输出契约 |
| 12:18:51 | `browser.open` + `exec.python` 被 `exclusive_task` skip；`exec.python` 的 `code/timeout_s/memory_mb/network` 被 schema 摘掉 | 空转开始 |
| 12:19–12:25 | Observer 连续指出：`exec.python` 空 `input:{}`、`force_armored` 不存在、应换 `burp.send`、应复测 katana 已有 URL | 建议正确，未被采纳 |
| 12:23:45 | `tool-gap` 上报缺渲染期 XHR 捕获；关闭 `T1_surface_map` 被 `CLOSURE_DELIVERABLES_UNMET` 拒 | 账不平 |
| 12:26–12:45 | 又 3 个 run：`exec.python` 第 4/5 次空跑、`focus-convergence` 第二次、6 次 `supervisor-pause`，最终 `review-pending` 未收口 | 会话停在半空 |

**硬指标**：工具调用 6 次（成功 3）｜证据 39 条（有效工具结果 3 条）｜findings 0｜`validation-failed` 7 次｜`transition-rejected` 7 次｜`supervisor-pause` 6 次｜`action-skipped` 16 条｜`protocol-error` 2 次｜13 个任务里 9 个 blocked、4 个 pending、0 个 completed 的验收面。

---

## 2. 历程图为什么分裂（根因，带实测数据）

### 2.1 快照

最新检查点（id=30）：

- 节点 **311**，边 **258**
- 边类型：`discovered_from` ×257，`navigates_to` ×1（`asset:m.ctrip.com → ep:m.ctrip.com/`）
- 节点类型：`endpoint` ×257，`asset` ×54
- 状态：`untested` ×309，`testing` ×2
- 54 个 host：`vacations.ctrip.com`(102)、`m.ctrip.com`(34)、`webresource.c-ctrip.com`(21)、`pages.ctrip.com`(16)、`bd-s.tripcdn.cn`(8)、`car.ctrip.com`(7)…外加 `www.iqiyi.com`、`www.mafengwo.cn`、`www.qyer.com`、`beian.miit.gov.cn`、`www.12377.cn`、`www.creditchina.gov.cn` 等完全无关的页脚/备案外链。

### 2.2 实测分裂程度

| 口径 | 结果 | 含义 |
|---|---|---|
| 视觉（Cytoscape 用全部 258 条边布局） | **54 块**：1 棵 258 节点的树 + 53 个单点 | 用户看到的"分裂成这么多块" |
| 语义（`connectedComponents` 只走 `navigates_to/calls_api/flows_data_to`） | **310 块**：1 个 2 节点 + 309 个单点，其中 256 个是非 asset 的真实 endpoint | Explorer 眼里 256 个页面互不可达 |
| `asset:*` 节点度数 | **53 / 54 个 degree = 0** | 每发现一个新 host 就多一块孤立卡片 |

### 2.3 四个叠加机制（代码级）

**A. `asset` 节点只创建、不连线。** `src/blackbox/graph/builder.ts:288` 为每个 endpoint 创建 `asset:<host>`，但只有 `edgeSource = parentId || assetId`（`:321-333`）——当 endpoint 有父页面（katana 给的 `ep:m.ctrip.com/html5`）时，边连父页面，asset 永远没有边。于是"每多一个 host = 多一个孤立点"，54 块里 53 块是这么来的。

**B. katana 的跨域链接被当成攻击面。** 277 条 URL 里有 20+ 个与携程 SRC 无关的域（爱奇艺、马蜂窝、穷游、备案/举报网站），builder 在 `for (const link of input.links || [])`（`builder.ts:398`）里全部建 `endpoint`，再各自派生一个孤立 `asset`。这既是碎片来源，也是"图看起来很大、实际不可打"的原因。

**C. `discovered_from` 不算可走边。** `src/blackbox/graph/analyze.ts:14` 的 `WALKABLE` 只含 `navigates_to/calls_api/flows_data_to`。katana 的"页面→链接"关系被标成 `discovered_from`，所以 255 个通过链接发现的页面在语义图上全部是孤岛。`planRoutes`/`potential` 基于同一连通性假设，结果就是"从当前节点走不到任何新页面"，主 agent 只能在 `html5` 附近打转——这是"路径纠结"的图论层原因，不只是 prompt 问题。

**D. rebuild 与实时 ingest 不一致。** 12:04 的两次重建只重放 3 条 `tool-result`：380/327（含 69 个 `parameter` 节点）变成 311/258，参数节点全丢，且没有补任何 host 边（`graph-rebuilt` 事件原文：`nodes:311, edges:258, edges_by_type:{navigates_to:1, discovered_from:257}, max_depth:3`）。`src/blackbox/replay_protocols.ts` 已记录过"rebuild 只重建图、不重放新协议"的问题，这次是同一类缺陷的另一个表现：重建只回放了 ingest 的一半语义。

### 2.4 修复建议（按优先级）

1. **P0** `builder.ts`：`upsertNode(asset)` 后立即建 `endpoint → asset`（或 `asset → endpoint`）的 host 边；或把 asset 作为 endpoint 的第二父节点。目标：asset 度数 = 该 host 端点数的下界，不再出现 degree 0。
2. **P0** `analyze.ts`：把 `discovered_from`（以及 `links_to`）纳入 `WALKABLE`，或新增 `links_to` 类型专门表示"页面可导航"，避免 256 个孤岛。
3. **P0** 入图前做 scope 过滤：与 `target_host` 不同且不在 SRC 白名单的 host 只进 `discoveries`/噪声桶，不建 endpoint/asset（否则 54 块里 20+ 是纯噪声）。
4. **P1** `rebuildProjectBlackboxGraph` 走与实时 `ingestToolResult` 相同的路径，并回填 `parameter` 节点；对同一 session 的重建结果与实时结果做断言（节点/边数量差 > 5% 即告警）。
5. **P1** Graph 页面（`console/src/pages/Graph.tsx:243` 显示 `view.components.length`，而 `src/blackbox/graph/visual.ts:237` 做了 `.slice(0, 12)`）会把"子图数"永远显示成 ≤12；应显示真实分量数，或明确标注"仅展示前 12 个分量"。
6. **P2** 视觉层把孤立 asset 折叠成"域簇"（按 `asset:<host>` 聚合），否则任何一次跨域爬取都会把画布打散。

---

## 3. 主 agent 与 Observer 的路线复盘

### 3.1 主 agent 的 6 个可指认错误

| # | 错误 | 证据 | 后果 |
|---|---|---|---|
| 1 | **任务契约与槽位**：先声明 4 个任务，随后一批请求挂到未声明/非焦点 task_id 上 | 11:56:32 摘键、11:58:28 `focus-lock` 拒收 6 条 | 首轮全部请求未执行 |
| 2 | **任务簿爆到 12/12**，且 12 个任务实际只有约 4 个独立目标 | 11:58:49 起 7 次 `validation-failed`/`transition-rejected` 全是 `task_backlog_full:12/12`；12:23/12:39/12:43 关闭 `T1_surface_map` 均被 `CLOSURE_DELIVERABLES_UNMET` 拒 | 验收门禁整场报错，无法收口 |
| 3 | **`exec.python` 空跑 5 次**：`code/timeout_s/memory_mb/network` 被 schema 摘掉，`input` 变成 `{}` | 12:18:51、12:39:11 `protocol-note` 原文；Observer 12:19/12:20/12:40/12:40:50 四次点名 | 焦点任务 4 轮 22TP 零证据 |
| 4 | **`force_armored` 连续 3 次**：该键在工具 schema 中不存在 | 12:23:45 `protocol-note` 的 `valid_keys` 清单；Observer 12:24:32/12:25:47 两次点名 | 打 `/webapp/myctrip/` 的请求必然被 `spa_disarmed` 拒 |
| 5 | **无视 `exclusive_task` 死锁**：`post_surface` 提权后仍反复派其他任务请求 | 12:06:38 ×3、12:18:51 ×2、12:23:46 ×4、12:39:11 ×3 全被 `action-skipped: exclusive_task:post_surface_...` | 16 条请求零执行 |
| 6 | **收口理由陈旧**：`T1_surface_map` 的 reason 写"节点/边/假设均为 0"，但 11:56:58 图已有 3 节点 | `tasks.T1_surface_map.reason` vs `graph-node` 事件 | 任务状态与实际账本脱节 |

另有一处"半对"：主 agent 正确驳回了 Observer 的 `waf_bypass(header/ua)` 归因（12:08:09、12:13:45 的 `advice_decisions` 写明"无 UA 的匿名请求同样 302→/html5/，差异来自出口 IP/时间窗"）。这是整场里最像"技术判断"的一次动作。

### 3.2 Observer 的对与错

**对的（且被反复忽略）：**
- 11:58–12:00：指出"资产侧 302→verify 是首见快照，不是持续风控墙"，`surface_baseline` 可判 `no_wall`。
- 12:07 起连续要求：把 12 个任务合并到 3–5 个，先平账再取数。
- 12:20–12:25：指出 `browser.open` 不会返回 network 列表、`exec.python` 空 `input` 是硬伤，建议改为 `burp.send`（不在 `spa_disarmed` 名单）并直接复测 katana 已有的 `/html5/trains/*/manifest.json`。
- 12:40–12:45：明确"架构结论已成立，缺的不是再渲染一次，而是把已有 URL 落成复测请求"，并点名 `returnUrl/ref/bgref` 参数面。

**错的：**
- 12:07:22：把"资产 302→verify、本会话 302→/html5/"解读为"风控墙在 UA/出口维度已被绕开，应入账 `waf_bypass`"。事实是这只证明"当前出口下没有强制墙"，不构成任何绕过动作，归因到 header/ua 会污染战例库。主 agent 的驳回是对的。
- 12:19:38：建议"`exec.python` 的代码必须塞进 `params`"。但 `exec.*` 在 `src/blackbox/tools.ts:1786` 的 `NO_PARAM_TOOLS` 中，`params` 会被直接拒绝——这条建议把主 agent 引向第 4/5 次空跑。
- 12:45 的 `next_steps` 用 `exec.bash` + `input.cmd`，同样不在 `toolInputObject` 白名单（只有 `script`/`code` 是执行器读的键，而 schema 两者都没登记）；建议本身仍不可执行。

### 3.3 系统层死锁（不是模型能靠 prompt 修的）

1. `exclusive_task` 与 `focus_lock` 同时生效且互斥：`post_surface` 要求"只准打我"，焦点锁要求"只准打 T_DICT_PROBE"，执行器的 `action-skipped` 分支先判 exclusive → 所有请求被丢弃。正确语义应是"exclusive 任务自动成为焦点"，或提权前先解除旧焦点。
2. `task_backlog_full 12/12` 与"合并任务"互相卡死：合并后 `deliverables` 契约没有一起合并，于是关闭时 `CLOSURE_DELIVERABLES_UNMET`；不合并则 12/12 拒收任何新声明。需要在 merge 时合并 `deliverables/success_criteria`，并把 `task_backlog_full` 从"拒绝一切"降级为"拒绝新增、允许关闭"。
3. `focus-convergence` 只发指令、不写状态：系统两次要求"标 blocked/focus_stalled"，但 `task_outcomes` 仍为空，`focus_lock` 继续 sticky。应收口指令直接落 `blocked`（带 `focus_stalled`），而不是等模型自觉。

---

## 4. WAF：事实、误判与"绕过尝试"的真相

### 4.1 事实

- `waf_bypasses` 表：**0 行**。
- 会话事件：无 `403/412/418/1020`、无 `waf`/`armor` 拦截记录；唯一带"装甲"字样的是 11:56:58 的 `armor-reject`：`burp.history` 未带过滤条件被拒（工具使用规范，不是 WAF）。
- 资产侧（FOFA 首见快照）有一条 `302 → verify.ctrip.com/static/ctripVerify.html?returnUrl=…&ref=…&bgref=…`；本会话实测：根 `302 → /html5/`、`/html5/ 200`。说明该风控**不是全站规则墙**，与 UA/出口/上下文相关；当前出口没撞上。
- Observer 12:07 提议按 `header/ua` 记 `waf_bypass`；主 agent 12:08/12:13 两次拒绝，理由是可复核的（无 UA 请求同样 302→/html5/）。
- 12:10:19 主 agent 尝试写入一条 `waf_bypass`，`dimension` 用了枚举外的值 → `protocol-error`，整轮输出作废。这是全场唯一一次"绕过入账尝试"，且没有对应请求。

### 4.2 判断

- **触发 WAF？** 没有证据。连"墙是否存在"都只在资产快照里出现过一次，且与实测矛盾。
- **绕过尝试？** 没有执行。规划里出现过 UA/Referer 伪装、路径变体、编码矩阵（`advice`/`playbook` 文本），但 `http.request`/`burp.send` 一次都没发这些变体；`verify.ctrip.com` 的 `returnUrl/ref/bgref` 参数面 0 次请求。
- **正确做法**：这轮应该先落一条 `no_wall` 结论（`waf-probe-negative`），再做 `verify.ctrip.com?returnUrl=` 的参数矩阵（`//evil.example`、`https://evil.example`、`\evil.example`、`@evil.example`、双重编码），用 `burp.request`（不受 `spa_disarmed` 约束）而不是继续在 `m.ctrip.com` 上撞 `http.request`。

---

## 5. 工具缺口：提了什么、漏了什么、哪些是误报

### 5.1 唯一一次正式上报（12:23:45）

```json
{
  "need": "能把 SPA 渲染期真实发起的 XHR/fetch（含 method 与 post_data）直接作为工具结果返回的能力",
  "tool": "browser.network 或 exec.python(内置 Playwright 镜像)",
  "missing": true,
  "alternative": "改用 recon.js_endpoints 静态提取 + burp.history 已捕获 XHR 兜底",
  "blocked_task": "T_SPA_REVERSE_19018807"
}
```

### 5.2 核账

| 说法 | 是否成立 | 说明 |
|---|---|---|
| 缺 `browser.network`（渲染期网络事件列表） | **成立** | 工具目录只有 `browser.open/screenshot/close/storage/tab`，`open` 返回截图/状态，不返回 request 列表；这是真实缺口。 |
| 缺 `exec.python(内置 Playwright)` | **半成立** | `exec.python` 在 74 项注册表里（`protocol.ts:211`），不是"没有这个工具"；缺的是沙箱镜像里的 Playwright（本轮未验证）+ **输入 schema 没登记 `code`**（`protocol.ts:45-107` 无 `code/script/requirements/timeout_s/memory_mb/network`）。所以 `missing:true` 的归因错了。 |
| 兜底 `recon.js_endpoints` + `burp.history` | 成立但没执行 | `recon.js_endpoints` 在 12:23 被 `exclusive_task` skip；`burp.history` 因 `host` 键非法（只认 `url/params`）从未成功取数。 |

### 5.3 被 schema/协议摘掉的键（都不是"缺工具"，是"工具契约不一致"）

| 时间 | 工具 | 被摘键 | 应写位置 |
|---|---|---|---|
| 11:56:32 / 11:58:49 | `burp.history` | `host` | 只认 `url/params`；应传 `url` 前缀过滤 |
| 11:56:58 | `katana.crawl` | `duration` | `duration_seconds` |
| 11:56:58 | `recon.content_discovery` | `rate_limit` | `params.rate` |
| 11:58:49 | `recon.js_endpoints` | `max_files` | 未登记（真实缺口） |
| 12:18/12:39 | `exec.python` | `timeout_s/memory_mb/network/code` | 全部未登记（P0 缺陷） |
| 12:23 | `http.request` | `force_armored` | SPA 指令自相矛盾：指令让传，schema 不认 |
| 12:45 | `exec.bash`（Observer 建议） | `cmd` | 应走 `script`，但 schema 未登记 |

### 5.4 建议管理员补的清单

1. `browser.network`：`browser.open` 后返回 `requests[]`（url/method/resource_type/post_data/status），这是把 SPA 逆向从"猜 bundle"变成"看流量"的关键。
2. `exec.*` 输入 schema：登记 `code/script/requirements/timeout_s/memory_mb/network`，并让 `test/tool-input-schema.test.ts` 同时扫 `sandbox_tools.ts`（当前只扫 `tools.ts`，所以 `input.code` 一直没被测到）。
3. `burp.history` 的 `host` 过滤别名（或在文档里明确"只认 url"）。
4. `tool-gap` 去重时核对注册表：`exec.python` 存在就不该报 `missing:true`，应改为"schema 不匹配"分类，否则管理员会去买已经有的东西。
5. `recon.js_endpoints` 的 `max_files`（或明确上限）。

---

## 6. 下一步：把 44 分钟的空转换成 5 个可执行动作

> 全部走 `burp.request`/`burp.send`（不在 `spa_disarmed` 名单），或对非 `m.ctrip.com` 主机用 `http.request`。

1. **判 catch-all（最高性价比）**：对 katana 已给的静态 JSON 发一次 GET：
   `https://m.ctrip.com/html5/trains/guiyang-wenzhou/manifest.json`，再对随机不存在路径发一次对照。200+JSON ⇒ `/html5/` 不是全站外壳，`T1_surface_map` 可结案。
2. **verify 跳转参数面**：对资产快照的 `verify.ctrip.com/static/ctripVerify.html?returnUrl=…&ref=…&bgref=…` 做 5 个变体（`//evil.example`、`https://evil.example`、`\evil.example`、`@evil.example`、`%2f%2fevil.example`），看 302 的 `Location` 是否被改写；这是 open redirect / Host 注入的唯一直接入口。
3. **鉴权入口归属**：`burp.send` 打 `/webapp/myctrip/`、`/webapp/servicechatv3/messagelist`，`follow_redirects=false`，看 `Location` 是 `passport` 还是 `verify`，落 `auth_entry`。
4. **bundle 静态取数**：`/html5/trains/js/{53d8dd8,34b5756,f4f9407,0f04a5c}.js` + `webresource.c-ctrip.com/NFES/...` 落盘，`grep -oE '/(restapi|h5api|soa2|gateway)/[^"'"'"']+'`，产出接口前缀清单。
5. **平账 + 重建图**：把 `T_SPA_REVERSE`、`surface_baseline`、`T1/T2/T3`、`sensitive_probe`、`api_route_enum`、`T1_history_baseline` 一次性给终态（blocked + reason），把 12/12 压到 ≤4；然后按第 2 节修 builder 后 rebuild，确认 `components` 从 54/310 降到 2–3（`m.ctrip.com` 主树 + `vacations.ctrip.com` 星）。

---

## 7. 需要修的 Bug（带文件位置）

| 级别 | 位置 | 问题 | 修法 |
|---|---|---|---|
| P0 | `src/blackbox/graph/builder.ts:288,321-333` | asset 节点无出边，53 个 host 成孤岛 | asset 建边（endpoint→asset 或 asset→endpoint） |
| P0 | `src/blackbox/graph/analyze.ts:14` | `WALKABLE` 不含 `discovered_from`，256 个页面语义孤立 | 纳入 `discovered_from`，或新增 `links_to` 并纳入 |
| P0 | `src/blackbox/graph/builder.ts:398` | 跨域外链全部入图 | 入图前 host scope 过滤，外域进噪声桶 |
| P0 | `src/control/console/desk.ts` 的 `focus/exclusive` 调度 | `exclusive_task` 与 `focus_lock` 互斥导致全量 skip | exclusive 自动接管焦点；`action-skipped` 前先解除对立锁 |
| P1 | `src/blackbox/protocol.ts:45-107` | `toolInputObject` 缺 `code/script/requirements/timeout_s/memory_mb/network` | 登记这些键；测试扫 `sandbox_tools.ts` |
| P1 | `src/control/console/desk.ts:785`（rebuild） | 重建丢 parameter 节点、与实时 ingest 不一致 | 复用 `ingestToolResult`，回填参数节点，加一致性断言 |
| P1 | 任务合并逻辑 | 合并丢 `deliverables`，关闭被 `CLOSURE_DELIVERABLES_UNMET` 拒 | merge 时合并 deliverables/success_criteria；backlog 满时允许关闭 |
| P2 | `src/blackbox/graph/visual.ts:237` + `console/src/pages/Graph.tsx:243` | `components.slice(0,12)` 让"子图（N）"永远 ≤12 | 返回真实分量数并标注截断 |
| P2 | 项目报告 | `data/projects/p_06db586d65/{run,summary,report}` 仍是 `support.oppo.com` 的旧产物，ctrip 会话没有落报告 | 会话结束时按 session 写报告；或禁止跨目标复用 project |

---

## 8. 一句话总结

这轮不是"模型不会打 SPA"，而是**图的表示先把路走断了**（asset 无连接、discovered_from 不可走、跨域噪声 54 块），**调度再把请求锁死了**（exclusive × focus 互斥、12/12 backlog），**工具契约最后把取数通道摘空了**（`exec.python` 的 `code` 不在 schema）。WAF 没触发、也没绕过；工具缺口报了一次但报偏了。修完第 7 节前三条，同样的 44 分钟至少能产出 3 条可复测的接口结论，而不是 311 个 untested 节点。
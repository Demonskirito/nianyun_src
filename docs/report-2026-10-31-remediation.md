# 2026-10-31 修复与实测报告：m.ctrip.com 黑盒会话（第二轮：身份/对象模型 + 调度收口）

> 对象：Nianyun 控制面（`src/blackbox/*`、`src/control/console/desk.ts`）
> 目标：`https://m.ctrip.com/`，项目 `p_06db586d65`，候选 `659a870d95522ac3`
> 修复前基线：`ca82c7689b5ec7f3`（44 分钟 / 6 次工具调用 / 0 发现）
> 本轮实测：`6af9c71725ffb46b`、`3eed109246c6d18c`、`d87c3ea2c2d8eeba`、`efe916a2c414f9eb`、`277a31c5647c7864`、`e1ac3b04161d4402`、`2b92c7fad2779398`
> 环境：容器 `nianyun-control-nianyun-1`，预算 `tool_calls 240 / agent_turns 40 / wall_clock 2700s / task_pending_limit 16`

---

## 1. 结论

上一版修好了"动作发不出去"（输入契约、`browser.network`、图吸收 burp 历史、假设进任务簿）。这一轮修的是**"动作发出去了，但控制面在错误的地方停手、在错误的地方记账"**：

- 一台 SPA 主机会被 `spa_disarmed` 缴械 `http.request` —— 原始 HTTP 压根不依赖渲染，缴械它等于堵死唯一的"匿名 baseline + 身份对照"路径。实测一场 24 分钟的 run 里 `http.request` 只放行 1 次，模型只好连打 14 发 `burp.send`，还反过来上报"清单里没有发原始请求的工具"。
- 终审（terminal review）一跑完就 `required_review_pending` 停 —— 5 次调用、10 个待办、终审已完成，账本却写"等审查"。
- 判 `stalled` 没有调用地板 —— 3 次调用、8 回合就收尾，把"还没开始"当成"打不动"。
- 死胡同拒收只警告不换路 —— `http.request` 被连拒 11 次，调用数直接冻在 14。
- 任务条目不宽容 —— 7 分钟内 8 次 `required_tasks[0]: invalid_union`，整批任务被丢。
- **身份是假的**：图里 `id:` 节点只由 401/403 触发、role 恒为模型随手写的 `anon`，Cookie jar 里有没有登录态不参与判断；`{id}` 端点也从不记录"实际打过的对象值"，两身份对照没有同一个对象可比。

改完之后同一目标：**调用从 6 涨到 65（最好一场）、真实请求 27 发、图 135 节点 391 边、身份账本识别到 `anon → auth` 的中途切换、对象模型记下真实对象值、Observer 建议被采纳（accepted+applied）**。仍未产出可用漏洞——原因在第 6 节写清，是环境/身份缺口，不是调度缺口。

---

## 2. 本轮改动

### 2.1 身份接线（新增 `src/blackbox/identity.ts`）

| 文件 | 改动 |
|---|---|
| `src/blackbox/identity.ts`（新） | `resolveIdentity()`：显式 `input.identity` > 目标 host 的**会话类** Cookie → `auth` > `anon`；`identityDirective()` 输出一句话（匿名时强调"匿名可读≠越权"，auth 时强调"必须同对象双身份对照"） |
| 同上 | 设备/埋点 Cookie 黑名单 `DEVICE_COOKIE`（`GUID`/`UUID`/`_pd`/`_ga`/`uqid`…）。携程的 `GUID` 会命中 `uid` 正则，没有这张名单就会把匿名会话误判成登录态 |
| `src/control/console/desk.ts` | `identityOf()` / `recordIdentity()` / `primaryIdentity()`：ingest 前按 Cookie jar 判定身份、写入 `checkpoint.identities` 账本、首次出现发 `identity` 事件；`graphContext()` 把身份一句话塞进 `graph_view.identity` |
| `src/blackbox/progress.ts` | `RunCheckpoint.identities` |

**实测证据**（会话 `6af9c71725ffb46b`）：

```
09:12:07  身份接线：当前身份 anon（m.ctrip.com 无会话 Cookie）：IDOR/越权只能先做匿名对照…
09:24:07  身份接线：当前身份 auth（Cookie: JSESSIONID,JSESSIONID）：越权结论必须做同对象双身份对照…
```

`identities=anon|auth` —— 中途确实抓到了登录态出现，而旧版这里永远是 `anon`。

### 2.2 对象模型：把"打过的对象值"记进图

| 文件 | 改动 |
|---|---|
| `src/blackbox/graph/endpoint.ts` | `objectValuesOf(url, templatePath)`：把 `/webapp/order/8817263/detail` 与模板 `/webapp/order/{id}/detail` 对齐，取出 `8817263` |
| `src/blackbox/graph/types.ts` | `NodeProperties.object_id` / `object_ids`（去重、最多 6 个） |
| `src/blackbox/graph/builder.ts` | ingest 时累积对象值：`object_ids` 排列保留最近 6 个，`object_id` 为最后一次 |
| `src/blackbox/graph/hypotheses.ts` | IDOR 假设文本带上"已观测对象值 X、Y（两身份对照必须打同一个）" |

**实测证据**（同一场）：

```
ep:m.ctrip.com/html5/mkt/hotels/brand/{id} {"object_ids":["361"],"object_id":"361"}
→ H_object_enum_5496c745（deliverables: verdict:positive|negative|inconclusive）
```

假设第一次以"带对象值 + 带 verdict 交付物"的形式变成任务。

### 2.3 SPA 缴械误伤原始 HTTP

`src/blackbox/spa.ts`：`INFANTRY_TOOLS` 移除 `http.request`，只保留"按静态路由枚举"的 `recon.content_discovery` / `recon.nuclei` / `recon.api_routes`。

依据：会话 `6af9c71725ffb46b` 的 `tool-gap` 原文——"在不被 spa_disarmed 缴械的前提下对 m.ctrip.com 发原始 HTTP 请求（含响应头采集）的能力（清单里无对应工具）"，以及同场 `http.request=1` vs `burp.send=14`。改后会话 `d87c3ea2c2d8eeba`/`e1ac3b04161d4402` 的 `http.request` 分别为 11 / 9 次。

### 2.4 调度收口：四处"在错误的地方停手"

| 位置 | 改动 | 依据 |
|---|---|---|
| `desk.ts` 进退场 `stalled`（3 处） | 加 `STALL_CALL_FLOOR = 12`：少于 12 次真实调用不判 `stalled` | 会话 `277a31c5647c7864`：3 次调用 / 8 回合判 `stalled`，10 个待办未跑 |
| `desk.ts` 退场门禁 | 终审已完成、无阻塞错误、无未处置建议、只剩 `TASKS_NOT_TERMINAL` 时，停止原因记 **`tasks_pending`** 而不是 `required_review_pending` | 会话 `efe916a2c414f9eb` / `277a31c5647c7864`：账本说"等审查"，其实终审早就 completed |
| `desk.ts` 退场前 `review-continue` | 终审留下未处置建议（或终审因补跑处置而过期）且还有待办、预算 ≥5 时，清掉 `reviewPending` 继续跑，最多 2 次（`review_continue_count`） | 会话 `3eed109246c6d18c`：终审产出三条强信号后 4 分钟就 paused |
| `desk.ts` 死胡同拒收 | 同一节点第 2 次被拒：把指向它的 pending 任务收口（`reason: dead_end:<node>`），发 `dead-end-redirect` 事件 + 高优先插话，附 3 个还活着的替代节点 | 会话 `d87c3ea2c2d8eeba`：`http.request` 被 `dead_end` 连拒 11 次，调用数冻结在 14 |

实测确认：会话 `e1ac3b04161d4402` 出现 `dead-end-redirect 死胡同连拒 2 次：ep:m.ctrip.com/html5 任务 T1 收口，替代节点 3 个`。

### 2.5 任务条目宽容化（8 次/7 分钟的协议浪费）

`src/blackbox/protocol.ts`：新增 `coercedTaskSchema`（`z.preprocess` 包 `taskSchema`），在 `required_tasks` 里优先使用：

- 别名映射：`url/target_url/link → target`，`goal/title/description/objective → purpose`，`why/rationale → reason`，`criteria/success_criteria/deliverable → completion_criteria`，`task_id/key/name → id`；
- 纯字符串任务：抽 URL、抽 `T*` 形式的 id、补默认 `reason` / `completion_criteria`；
- 缺 `id` 时用文本哈希生成 `T_xxxxxxxx`；
- `target` 改为可选（模型常把 URL 写在 purpose 里）；
- 仍然拒绝"连 purpose 都没有"的对象——宽容不等于把噪声当任务。

依据：会话 `e1ac3b04161d4402` 的 8 条 `protocol-warning`（`required_tasks[0]: invalid_union`）。

---

## 3. 实测时间线（10 场，每场暴露什么 → 当场修什么）

| # | 会话 | 时长 | 调用 | 工具成功 | 图 | 暴露的问题 | 当场修复 |
|---|---|---|---|---|---|---|---|
| 0 | `ca82c7689b5ec7f3` | 44m | 6 | 3 ok | 311/258 | 基线：0 假设入簿、16 次 skip、`http.request` 2 次 | — |
| 1 | `6cd638eb971d81d1` | 7m | 10 | — | 73/149 | `post_surface` 排他后请求全 skip | `tickPostSurface` 释放 + `computeFocus` 对齐 |
| 2 | `1bd07be666b7f668` | 9m | 17 | — | 29/77 | `burp.sitemap` 100 条历史没进图 | `LINK_KEYS` 加 `entries/records/history/results` |
| 3 | `98b6e1f48970d4e0` | 4m | 2 | — | 31/87 | `task_id` 未登记 → 整批拒收，5 分钟停滞 | 未登记 id 归并到焦点任务（哨兵仍拒收） |
| 4 | `200a50ca1a8a2d03` | 22m | 44 | 40 ok / 10 bad (80%) | 126/365 | 31 条 `stall` 假设占满验证名额 | `hypothesisTasks` 过滤 `stall`；`task_pending_limit` 16 |
| 5 | `6af9c71725ffb46b` | 24m | **65** | 55 ok / 11 bad (83%) | **135/391** | `http.request` 被缴械、身份恒为 anon、对象值不落图 | 2.1 / 2.2 / 2.3 |
| 6 | `3eed109246c6d18c` | 4m | 6 | 5 ok | 34/93 | 终审产出 3 条强信号后立刻 paused；`http.request` 已可用（3 次） | 2.4 的 `review-continue` |
| 7 | `d87c3ea2c2d8eeba` | 14m | 14 | 11 ok / 17 拒 | 85/175 | `http.request` 被 `dead_end` 连拒 11 次，调用冻结 | 2.4 的死胡同换路 |
| 8 | `efe916a2c414f9eb` | 6m | 5 | 5 ok | 31/87 | 终审 completed 仍判 `required_review_pending`，11 待办未跑 | 2.4 的停止原因诚实化 |
| 9 | `277a31c5647c7864` | 5m | 3 | 3 ok | 32/89 | **3 次调用就判 `stalled`** | 2.4 的 `STALL_CALL_FLOOR` |
| 10 | `e1ac3b04161d4402` | 7m | **18** | 17 ok / 3 bad (85%) | 31/87 | 8 次 `required_tasks invalid_union`；死胡同换路生效 | 2.5 任务宽容化 |
| 11 | `2b92c7fad2779398` | 见 §4 | | | | 验证任务宽容化 + 死胡同换路 + `http.request` 放行 | — |

第 5 场工具分布（`checkpoint.tool_calls`）：
`burp.send=14, evidence.read=16, browser.open=7, burp.history=7, browser.network=4, http.diff=3, http.request=1, burp.sitemap=2, burp.send_batch=1`

第 10 场工具分布：`http.request=9, burp.history=7, recon.js_endpoints=1` —— 原始 HTTP 已成为主力，不再靠 burp 桥接硬撑。

---

## 4. 前后对比（同项目 / 同目标 / 同模型）

| 指标 | 修复前 `ca82c768` | 第 5 场 `6af9c717` | 第 10 场 `e1ac3b04` |
|---|---|---|---|
| 墙钟 | 1553s | 1277s | 420s（人为 7 分钟即停） |
| 工具调用 | 6 | **65** | 18 |
| 真实请求（http.request + burp.send + burp.request） | 2 | 27 | 9 |
| 工具成功率（ok / (ok+bad)） | 3/3（样本太小） | 55/66 = **83%** | 17/20 = **85%** |
| `action-skipped` | 16 | **1** | 0 |
| `task-id-merged` | 0 | 0 | 0 |
| `focus-lock` 事件 | 3 | 18 | 6 |
| `tool-gap` | 1 | **1**（误报，2.3 已修） | 0 |
| 图节点 / 边 | 311 / 258（53 个孤立块） | 136 / 391 | 31 / 87 |
| 假设（种类） | idor 17 + logic 1 + stall 1 | stall 32 + object_enum 1 | stall 29 |
| 假设 → 任务 | **0** | 1（带 verdict 交付物） | 3（data_flow） |
| 身份账本 | 无 | **anon → auth（2 条 identity 事件）** | anon |
| 对象值落图 | 0 | **1 个节点带 object_ids["361"]** | 0 |
| Observer 建议 | accepted 12 / applied 2，review `validation_failed`×14 | accepted 1 / **applied 1**，ordinary×17 + terminal×1 | ordinary×1 + terminal×1 |
| findings | 0 | 0 | 0 |
| stopReason | `validation_failed_review_required` | `required_review_pending` | `observer_review_stale_snapshot` |

### Observer 监测质量（第 5 场终审原文摘录）

> 目标架构已明确：m.ctrip.com 是纯 SPA 外壳（41638B、`#__next`、19 个外链 JS），根路径由人机验证墙接管（302→verify.ctrip.com）……另有两条关键信号主 Agent 没用上：①robots.txt（2447B）明确泄露 `/restapi/*` 前缀与按 UA 区分的 Allow 白名单（Googlebot: `/webapp/hotel/*`、Baiduspider: `/webapp/mkt/*` …）；②任意路径 `/v3/api-docs` 都被 302 到 `/webapp/`，符合 catch-all 路由特征，但缺一条随机路径对照，尚不能定性。

这已经是可执行的情报（前缀 + UA 白名单 + catch-all 对照方法），而不是"建议多收集信息"。第 6 场终审更进一步指出主 Agent 的三处重复（`recon.js_endpoints` 同参重跑 0 产出等）。

---

## 5. 仍然没解决（如实记录）

1. **0 发现**。匿名根路径 302 到 `verify.ctrip.com` 人机验证；能 200 的深页要么是 SPA 外壳，要么要登录态。第 5 场虽然抓到 `auth`（JSESSIONID），但没有可用的**第二个身份**做归属对照，也没有过验证码能力。这是环境缺口。
2. **`evidence.read` 16 次**（第 5 场）。模型反复回读证据工件，说明上下文里的证据摘要不够"自足"。应把关键响应摘要直接压进 `attack_graph` 节点属性，而不是让它回读。
3. **`focus-lock` 仍会拒"已声明但非焦点"的请求**（第 5 场 18 次）。归并只救"未登记 id"。
4. **任务结案率 0**。`H_*` 任务带 `verdict` 交付物、产生了，但一场 run 内没有一个走完（`hypTasks=1/0`）。门禁只在结案时审计，模型直接放着不结案就没有代价。
5. **`observer_review_stale_snapshot`**（第 10 场）成为新的停止原因：终审看到的是旧快照。需要"审查快照版本"与"继续跑"解耦，否则又是一条停手路径。
6. **`tool-gap` 误报**已修（`http.request` 不再被缴械），但上报机制本身仍可能把"配置关闭"误报成"清单里没有"。

---

## 6. 复现与回滚

```bash
npm run build:server
docker cp dist/. nianyun-control-nianyun-1:/opt/nianyun/dist/
docker restart nianyun-control-nianyun-1

# 会话
POST /api/projects/p_06db586d65/blackbox-sessions {"candidate_id":"659a870d95522ac3","force":true}
POST /api/projects/p_06db586d65/blackbox-sessions/<sid>/check
POST /api/projects/p_06db586d65/blackbox-sessions/<sid>/run

# 回滚
docker exec nianyun-control-nianyun-1 sh -c 'rm -rf dist && mv dist.prev dist'
```

预算覆盖（容器内 `/opt/nianyun/data/config/tools.env.yaml`）：

```
BLACKBOX_RULES_DOCUMENT: '{"budgets":{"tool_calls":240,"agent_turns":40,"wall_clock_sec":2700,"time_sec":1200},"focus_lock":{"max_turns_per_task":10,"max_session_convergences":8},"loop_control":{"task_pending_limit":16}}'
```

---

## 7. 测试

`npx vitest run`：99 个文件 / 827 项，**821 通过、2 跳过、4 失败**。失败项全部落在本轮未触碰的 `src/asset` 与 Windows 临时目录：

- `test/assets.test.ts` ×1：`listAssetObservations` 期望 2 条、实得 1 条；
- `test/candidates.test.ts` ×2：`tags: ["portal"]` 未生成、HEAD 探测 `fetch` 未被调用；
- `test/sandbox-service.test.ts` ×1：`EBUSY`（偶发，重跑即过）。

新增测试：

- `test/identity-object-model.test.ts`（9 项）：显式/Cookie/设备 Cookie/跨域 Cookie 的身份判定、`objectValuesOf` 对齐、`object_ids` 累积去重、IDOR 假设带对象值；
- `test/protocol-task-coerce.test.ts`（3 项）：别名形态、纯字符串任务、无 purpose 的对象仍被拒。

被测试挡住并已修的两处：

- `test/blackbox-lifecycle.test.ts`「missing finding review」曾因"停止原因诚实化"把 `required_review_pending` 改成 `tasks_pending`（当时还有 0 个待办）；已加 `pendingCount() > 0` 前置条件；
- `test/note-yun-replay.test.ts` / `test/protocol-hardening.test.ts` 按"SPA 缴械不含 `http.request`"改写。
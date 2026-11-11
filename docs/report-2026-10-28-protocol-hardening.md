# 四个致命脱节的修复：主权转移 / 差分探针 / 字典折叠 / SPA 缴械

**会话依据**：`1cdf92d4816b72bf`（`http://note.yun.oppo.com/`，2026-10-28 15:07:37–15:21:38，19 分钟，47 次调用，29 turn，结束于 `observer_review_failed`）
**配套记录**：[历程图分析](report-2026-10-28-note-yun-graph.md) · [会话记录](report-2026-10-28-note-yun-session.md) · [约束审计 §46](agent-constraints-audit.md)
**本轮改动**：4 个新模块 + 3 处编排接线 + 21 个新测试

---

## 0. 一句话结论

上一轮修的是"图记不记得住"（`blocked 0→9`、`dead_end 0→2`）；这一轮修的是**"记不住也照样得按它行动"**——把三个"模型有权自己判断"的地方改成控制面直接接管：301 之后它**不允许**继续碰旧 host；SPA 外壳上它**不允许**再用步兵工具；224 个字典节点它**看不到**，只看到 4 个抽样探针；`burp.history` 不带过滤条件**发不出去**。

---

## 1. 脱节一：301 没有引发主权转移

### 现场证据

| 时间 | 事实 |
|---|---|
| 15:08:28 | `http.request GET http://note.yun.oppo.com/` → `301`，`Location: https://cloud.oppo.com/` |
| 15:08:43 | `http.request GET https://cloud.oppo.com/` → `200`，5158B SPA 外壳（全场唯一有效纵深） |
| 15:09–15:21 | 又对 `note.yun.oppo.com/` 发了 **6 次**同样的请求；该节点 `hits=20`、最终被判 `dead_end（重复 13 次）` |
| 全程 | 账本里 `T1.Target` 始终是 `http://note.yun.oppo.com/`，`current_focus` 始终是 T1 |

### 修法：控制面接管，模型没有决定权

| 组件 | 行为 | 位置 |
|---|---|---|
| `redirectOf(data, requestUrl)` | 只认 301/302/303/307/308 且 **host 变化**；同 host 的 `/a → /a/` 是路由规范，不算转移 | `sovereignty.ts:60` |
| `applySovereignty(state, hop)` | 把**活跃**任务（pending/running/blocked）的 `target` 从旧 host 重写到新 host；已结案任务不动（改它就是篡改账本）；幂等，重复 301 不重复改写 | `sovereignty.ts:87` |
| `violatesSovereignty` + `hostLockOf` | 旧 host 请求在**进工具之前**被拒（`sovereignty_moved`），并回一句替代动作 | `sovereignty.ts:142`、`desk.ts:500` |
| `sovereigntyDirective` | 注入上下文：`【主权转移】…严禁再对 note.yun.oppo.com 发起任何请求…你现在的目标是 https://cloud.oppo.com/` | `sovereignty.ts:151` |
| `forced_focus` | ingest 时立刻把焦点设为被迁移的任务，`computeFocus` 的 ⓪ 分支优先于 sticky | `focus.ts:101` |

### 一个刻意的例外（否则会误杀真信号）

域锁不是一刀切：**图上没有的旧 host 新路径**最多放行 3 条。原因很实在——`anomaly-scheduler` 的 catch-all 判定需要"3 条不同路径跳同一个地方"才能成立，锁死第一跳就把"这站所有路径都 301"这个真结论也挡掉了（本轮实测：一刀切版本让 `test/anomaly-scheduler.test.ts` 直接红）。

规则收敛为：**同名路径重复 = 拒；新路径 = 3 条采样后拒**。

---

## 2. 脱节二：`burp.history` 变成安慰剂

### 现场证据

| 次数 | 返回 | 模型反应 |
|---|---|---|
| 4 次 | `total 0 / 1 / 2 / 7` | 无动作 |
| 2 次 | `total 298 / 299`（窗口内 301:30、412:20） | 无动作 |

299 条流量里"哪些路径被 WAF 拦了"是完整可得的，但它把 history 当 `ls -l` 用了。

### 修法：两个动作，一个加闸一个换枪

| 动作 | 内容 | 位置 |
|---|---|---|
| 闸：裸调不发出去 | `burp.history` 未带 `url/method/status/status_code/path/host` 任一过滤 → 拒收 `bare_history_use`，并指向 `recon.traffic_diff` | `desk.ts:543` |
| 枪：`recon.traffic_diff` | 输入 `url` 或 `evidence_id_a/b`，控制面从账本取两行响应比对，只回结构化物 | `desk.ts:558`、`traffic_diff.ts:88` |

`diffResponses` 的打分口径（透明可复算）：状态码变化 `+0.5`、头部差异 `+0.15×n`（上限 0.3）、body 长度差比例 `+0.4×ratio`、同长度正文不同 `+0.2`、Set-Cookie 增减 `+0.1×n`（上限 0.2）。`diff_score=0` 连续两次即可交给既有的收益递减止损。

实测（容器内用部署后的 dist 跑）：

```
[4] 200->412: status_change score 0.69 | 状态码 200 → 412：行为变了，优先看这一条
[4] 412->412: identical score 0     | 完全一致（412 / 2681B）：不要再用同样请求刷它
```

---

## 3. 脱节三：224 个字典节点的冷启动瘫痪

### 现场证据

两轮同一个病：gray-push 221 个、note.yun 224 个端点一次 `recon.content_discovery` 产出，**全部 `untested`**，系统三次点名"另有 224 块没动过"，0 次采纳。这不是懒，是**选择过载**——"去看看它们"没告诉它先看哪一个。

### 修法：在图这一侧就折叠

| 步骤 | 行为 | 位置 |
|---|---|---|
| ① 聚类 | 正则分 5 类：`sensitive`（.env/.git/备份/config）、`admin`（admin/login/druid/nacos/actuator/jmx/solr…）、`api_doc`（swagger/api-docs/graphql/openapi/redoc）、`static`（css/js/图片字体）、`other` | `cluster.ts:49` |
| ② 抽样 | 每类取**最短路径**作代表（确定性，同一份账本重放必得同一组探针），上限 4-5 个 | `cluster.ts:67` |
| ③ 合成任务 | `T_DICT_PROBE_<stamp>`，带 `deliverables: [waf_fingerprint, existing_paths]` 与分类判据（200/30x=展开、401/403=需身份、412/WAF=整类标灰、404=换该类的下一个） | `cluster.ts:100` |
| ④ 劫持焦点 | 一次性把 `forced_focus` 指向该任务 | `desk.ts:690` |
| ⑤ 上下文 | `dict_probe` 里只列 4 个 probe + 每类规模，**不列 224 条** | `context.ts:265` |

实测（224 条字典 fixture）：

```
[3] dict: 224 paths -> 4 probes: sensitive=/.env(4) | api_doc=/graphql(4) | admin=/admin(8) | static=/static/js/chunk-0.js(208)
[3] task: T_DICT_PROBE_note28 | deliverables: waf_fingerprint,existing_paths
```

---

## 4. 脱节四：5158B SPA 外壳没人管

### 现场证据

15:08:43 拿到外壳后，模型对它做了 **2 次 `recon.js_endpoints`，都返回 `no_script_references`**——因为外壳里一个 `<script src>` 都没有，工具按外部 bundle 找，自然找不到。此后 18 次调用继续在 301/412/字典上打转。

### 修法：认指纹 → 缴步兵的械 → 只留特种兵

| 判定 | 条件（与） | 位置 |
|---|---|---|
`is_spa` | `200` ∧ HTML ∧ `≥2KB` ∧ （挂载点 `#root/#app/#__next/__NUXT__/__INITIAL_STATE__` 或框架特征）∧ `inline ≥1` ∧ `外部 <script src> ≤1` | `spa.ts:43` |

命中后：

- `http.request` / `recon.content_discovery` / `recon.nuclei` / `recon.api_routes` 在该 host 上被拒（`spa_disarmed`），确需强制要显式 `input.force_armored=true`；
- 生成 `T_SPA_REVERSE_<stamp>` 并劫持焦点，指令写明用 `browser.open(wait_until=networkidle)` / `exec.python(Playwright)` / 内联脚本抠 `baseURL`；
- 上下文新增 `spa_mode`（含 `infantry_disabled` 列表）。

实测：

```
[2] spa: true | signals: mount:#root,inline_scripts:1,external_scripts:0
[2] http.request disarmed: true | browser.open disarmed: false
```

---

## 5. 改完之后的 19 分钟长什么样

| 时间 | 现场（47 次调用） | 新逻辑下 |
|---|---|---|
| 15:08:28 | `http.request note.yun` → 301 | 同 —— **但这一条同时触发主权转移** |
| 15:08:29 | （无动作） | 焦点自动移到 `cloud.oppo.com`；`T1/T2.Target` 已重写；旧 host 上锁 |
| 15:08:30 | `http.request cloud.oppo.com` → 200 | `http.request cloud.oppo.com` → 200（**旧 host 的 6 次重复全部被域锁拒收**） |
| 15:08:31 | （无动作） | SPA 指纹命中 → 步兵缴械 → 生成 `T_SPA_REVERSE` |
| 15:08:32 | （无动作） | 字典 224 → 折叠 4 → 生成 `T_DICT_PROBE` 并劫持焦点 |
| 15:08:35 | 继续打 `cloud.oppo.com/.env` 等 | 只打 4 个 probe：`/.env`→412（整类标灰）、`/graphql`→?、`/admin`→?、`/static/js/chunk-0.js`→? |
| 15:09:00 | （无动作） | 命中类别展开（如 api_doc 200 → 剩余 3 条进待办）；`recon.traffic_diff` 出 `diff_score` |
| 15:09:10 | （无动作） | `browser.open` 渲染外壳，抓真实 XHR |

**调用量**：现场 47 次 / 22 个唯一请求（重复率 49%）；新逻辑下同类目标预期 **7-9 次全唯一**（1 次 301 + 1 次新 host + 1 次渲染 + 4 次探针，视展开再 +n）。这一点在测试 `note-yun-replay` 里是可断言的：`planned.length < oldUnique / 3`。

---

## 6. 测试

| 文件 | 用例 | 钉住什么 |
|---|---|---|
| `test/protocol-hardening.test.ts` | 16 | 跨主机 301 识别（同 host 不误判）、任务重写与"已结案不改"、幂等、域锁、`forced` 优先于 `sticky`；SPA 四类反例（小页面/非 HTML/非 200/多 bundle）；聚类四类 + 确定性抽样 + 任务契约；差分 identical/status_change/auth_change/insufficient + `pickPair` |
| `test/note-yun-replay.test.ts` | 5 | 用**现场事件序列**回放：①301 后 6 次旧 host 请求全被拒 ②5158B 判 SPA、步兵禁用 ③224→4 探针 ④412 与 200 的 `diff_score` ⑤整轮压缩到 7 次且 0 重复 |
| `test/tool-params.test.ts`（既有） | — | ffuf `-ac` / `-mc` 参数序列 |
| `test/anomaly-scheduler.test.ts`（既有） | 1 | catch-all 仍能被证明（域锁的 3 条采样例外就是为它留的） |

全量：**89 个文件通过 / 2 个失败（`assets`、`candidates`，本轮之前就红）**，`tsc --noEmit` 干净。

新增工具登记做了四件事（漏一件测试就红）：`protocol.ts` 枚举、`tools.ts` 注册表、`tool_docs.ts` 文案、`weights.ts` 成本 + `generated/tool-manifest.json` 重算（73→74）。

---

## 7. 本轮自造问题（照实记）

| # | 问题 | 怎么发现 | 怎么修 |
|---|---|---|---|
| 1 | 用 PowerShell 生成接线脚本时，JS 字符串里嵌了中文双引号，`node -e` 直接语法错，**imports 没插进去**，但方法体插进去了 → 一堆 `Cannot find name` | `tsc` 一次性报 8 个未定义 | 改用索引式插入 imports |
| 2 | `context.ts` 的类型收窄用 `$i=-1` 当锚点，`$lines[0..-1]` 在 PowerShell 里是**取 0、-1、-2 三行**（负数索引回绕），结果声明被插到文件头、还复制了尾行 → 出现两个 `boundedMainOutput` | `TS2451 Cannot redeclare` | 按内容定位重插，删掉尾部重复行 |
| 3 | 收窄声明插进了 `return { ... }` 对象字面量内部，`TS1005 ':' expected` ×4 | `tsc` | 移到位（`return {` 之前） |
| 4 | `tool_docs.ts` 替换时按 `$lines[$i..$i+4]` 删了 5 行，把 `recon.sast` 的文案整条删掉 | manifest 测试报"`recon.sast` 没有用途文案" | 恢复该条 |
| 5 | `rules.ts` 里加了 `"recon.traffic_diff": {}`，与"风险开关清单长度 16"的文档守恒测试冲突 | `blackbox-approval` 红 | 去掉（它没有风险开关，本来就不该进表） |
| 6 | 主权域锁一刀切 → `anomaly-scheduler` 的 catch-all 判定拿不到 3 条样本 | 该测试由绿变红 | 加"新路径 3 条采样"例外，并写进注释说明为什么 |
| 7 | `spa.ts` 的挂载点特征把正则源码当信号名（`mount_point:/id=["']root["']/i`） | 容器内回放打印出来才看见 | 改成 `[正则, 可读名]` 表，信号变 `mount:#root` |

规律和前几轮一样：**7 个里 5 个是"改完没验"（1、2、4、5、7），2 个是"语义冲突"（3、6）**。

---

## 8. 部署与实测

- `docker build` 依旧报 `mount options is too long`（老问题，本轮未动）；部署走 `tsc → docker cp dist → restart`；
- 容器内确认新模块存在：`sovereignty.js` / `spa.js` / `traffic_diff.js` / `graph/cluster.js` 均在 `/opt/nianyun/dist/blackbox/`；
- 容器内用**部署后的 dist** 重放 note.yun 事件（见 §1-§4 的 `[1]~[4]` 输出），四条全部按设计生效；
- 旧会话图重放未受影响：`note.yun` 仍是 `241 节点 / 239 边`，`status={untested:226, dead_end:2, blocked:9, testing:4}`；
- `/health = true`。

---

## 9. 仍未做（下一轮候选）

1. **`required_tasks` 的 `(item): Invalid input`** 仍是这一轮最贵的缺陷（13 条任务项被丢 → 反复重声明任务）。需要把 Zod 的 issue path 结构化输出"缺哪个键/哪个键类型错"。
2. **`post_surface` 的 POST 面枚举**在 note.yun 里一次没跑（`T4` 一直 pending）；本轮没碰它的优先级。
3. **`traffic_diff` 的收益递减联动**：`diff_score=0` 连续两次应直接触发 `plateau` 收口，目前只是把分数交回去，没有硬绑到 `convergeFocus`。
4. **rebuild 路径没有跑协议**：`rebuildProjectBlackboxGraph` 只重建图，不重放主权/SPA/折叠。历史会话因此无法"回填"这四条结论——要做的话得在 rebuild 里也调 `applyProtocolHooks`（本轮刻意没做，避免影响既有 11 轮的历史读数）。
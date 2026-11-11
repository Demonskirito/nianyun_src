# 攻击历程图详解：support.oppo.com（会话 `463dd72637d195c6`）

目标 `http://support.oppo.com/` → 302 → `https://support.oppo.com/cn/`（OPPO 官方客服站，AEM/Edge Delivery 型静态壳）
窗口：**2026-10-28 18:59:57 → 20:52:49**（112.9 分钟），实际动手只有 **9 次工具调用**，中间被门禁挂了 87 分钟。
事件 **304** 条，证据账本 38 条（tool-request 9 / tool-result 9 / tool-error 6 / agent-analysis 15 / observer-review 1 / run-summary 2 / playbook-coverage 2 / artifact 2 / environment 2）。

> 同一会话的执行过程另见 [会话记录报告](report-2026-10-28-support-oppo-session.md)。

---

## 1. 总量

| 指标 | 值 |
|---|---|
| 节点 | **127**（asset 2 + endpoint 125） |
| 边 | **126**（`discovered_from` 119、`navigates_to` 7） |
| 去重合并 | **139** 次（katana 那批就吃掉 14 次） |
| 剪枝 | 0 |
| 假设 | 1（`idor:ep:www.oppo.com/{id}\|path_id`） |
| 状态 | `untested 119` / `testing 4` / `dead_end 1` / `blocked 3` |
| 主机 | `support.oppo.com 123`、`www.oppo.com 4` |
| 重放 | `graph-rebuilt` **4** 次（每次“9 条工具结果重放进图，最深 3 跳”） |

对比 note.yun 那轮（241 节点 / 239 边 / 129 untested）：节点更少，但**未验证比例更高**——119/127 = 93.7%，note.yun 是 53.5%。

---

## 2. 节点是在哪里新建的（4 个批次）

| 批次 | 证据 | 节点数 | 内容 |
|---|---|---|---|
| katana.crawl | `ev-38464a3a5587ba05` | 8 | `/cn`、2 个 `oppo.com` asset、support 侧 `jimu/oppo-global-service/client/oppo_main.*.js` + `oppo_vendor_libs.*.js` + `oppo_main.*.css`、www 侧 `jquery-3.5.1.min.js` + `oppo-site-nav/oppo_nav_main.*.js` |
| http.request ×5 | `ev-f7cf…`/`ev-d97c…`/`ev-d95d…`/`ev-6127…`/`ev-b08d…` | 5 | `/robots.txt`(200)、`/.git/config`(412)、`/.env`(412)、`/actuator/env`(412)、`/v3/api-docs`(301) |
| recon.content_discovery | `ev-426a8a3ac54823da` | **113** | ffuf 命中 113 条路径，全部 `untested` |
| 主权转移 | `ev-31c116ca7b67087d` | 1 | `ep:www.oppo.com/{id}`（来自 302 目标 `https://www.oppo.com//404/`） |

一句话：**89% 的节点来自一次字典扫描，而且那 113 条没有任何状态码。**

### 2.1 113 条到底是什么

- ffuf 命令（`src/blackbox/tools.ts:1897`）：
  ```
  ffuf -u https://support.oppo.com/FUZZ -w resources/wordlists/paths.txt -s -ac \
       -mc 200,201,202,204,206,301,302,303,307,308,401,403,405,500 -rate 10 -maxtime 120
  ```
- 字典 `paths.txt` 是 **290** 行，`count=113` → 这是 **113 条命中**，不是字典回显。
  （Observer 在 `advice` 事件里推的是“113 = dict_probe.total = 字典回显”，那是**循环论证**：`dict_probe.total` 就是用这 113 条算出来的。结论“别当成已确认路径”对，理由错。）
- 但 `-s`（silent）只打印匹配到的**路径**，不带 `[Status: 302, Size: …]`。所以：
  - 113 条命中里混着“真 200”和“catch-all 302 到 `https://www.oppo.com//404/`”；
  - 图上这 113 个节点全部停在 `untested`，**没有任何下游能区分**；
  - 后来单发探针 `/openapi.json`、`/admin.jsp`、`/` 全被装甲拒收（见 §5），一次都没验过。

这是本轮图最严重的结构缺陷：**图把“服务器对任意路径都回 302”记录成了 113 个端点。**

---

## 3. 图的形状：一根柱子 + 113 片叶子

度数分布：

| 度数 | 节点数 |
|---|---|
| 0 | 1 |
| 1 | 121 |
| 2 | 2 |
| >2 | 3 |

度数最高：

| 节点 | 度数 | 为什么 |
|---|---|---|
| `ep:support.oppo.com/` | **114** | 113 条字典命中全部 `discovered_from` 挂在它下面 |
| `asset:support.oppo.com` | 7 | 7 条 `navigates_to`（`/cn`、`/robots.txt`、`/.git/config`、`/.env`、`/actuator/env`、`/v3/api-docs`、`/`） |
| `ep:support.oppo.com/cn` | 6 | katana 从它展开 6 条静态资源 |

7 条 `navigates_to` 全部是 `asset → endpoint` 单跳，**没有一条 `endpoint → endpoint`**：
`/cn` 爬到静态资源、`/v3/api-docs` 301 到带随机参数的自身、`/` 是 catch-all 吸收点——这三条本可以串起来的链路，图上都没连。

> 结论：这张图**没有攻击路径**，只有“一个入口 + 一堆并列文件名”。历次 graph-signal 说的“图裂成 120 块”是准确的（120 块 ≈ 113 叶子 + 7 个簇）。

---

## 4. 图上真实站得住的 8 个结论

| 节点 | 状态 | 依据 |
|---|---|---|
| `ep:support.oppo.com/cn` | `dead_end` | `js_endpoints` 返回“页面未引用可分析的 JavaScript 文件”，同一条响应重复 3 次（`signature_repeats:3`） |
| `ep:support.oppo.com/robots.txt` | `testing` | 200，2 次命中 |
| `ep:support.oppo.com/.git/config` | `blocked` | 412，`wall=waf_oppo` |
| `ep:support.oppo.com/.env` | `blocked` | 412，`wall=waf_oppo` |
| `ep:support.oppo.com/actuator/env` | `blocked` | 412，`wall=waf_oppo` |
| `ep:support.oppo.com/v3/api-docs` | `testing` | 301 → `/v3/api-docs/?zhyk1j2=1`（随机参数，边缘回显特征） |
| `ep:support.oppo.com/.env~` | `testing` | 302 → `https://www.oppo.com//404/` |
| `ep:support.oppo.com/` | `testing` | 2 次命中，`signature_repeats:2` |

3 条 412 是**同一个 WAF 模板**（2681B，`securityfs.oppo.com` 图床），这与 note.yun 那轮完全一致——同一个边缘 WAF。
真正可复用的结论只有一条：**OPPO 边缘对 `.{env,git,actuator}` 关键字命中式 412，非关键字路径落到 catch-all 302**。这条本轮没有被写成 finding。

---

## 5. 图上的两个假节点

### 5.1 113 条未验证路径（见 §2.1）

后果链条：

1. 它们让 `graph_drift` 以为有 112 个“从没动过的块”，于是 **连续 8 次** 提醒“下一轮必须至少发 1 条打这些 Root”；
2. roots 是 `ep:support.oppo.com/flag.php`、`/flag.txt`、`/.env.local` —— 全是字典条目，不是服务器证据；
3. 模型一次都没采纳（正确），但这条提醒一直挂在上下文里，白烧 token；
4. 更要命的是装甲把“节点存在”当成“已探过”（`src/control/console/desk.ts:506`：`known = Boolean(graphState(...).nodes[endpointNodeId(url)])`），于是字典探针剩下的 3 个代表全被拒 —— 见会话报告 §5。

### 5.2 `ep:www.oppo.com/{id}` + 假 IDOR 假设

`https://www.oppo.com//404/` 是 catch-all 吸收页，但路径模板提取器把 `404` 当成对象 id，生成：

```json
{"id":"idor:ep:www.oppo.com/{id}|path_id","kind":"idor","severity":"high",
 "text":"ep:www.oppo.com/{id} 路径里带对象 id：换相邻 id（±1）对比响应差异…"}
```

一个 **404 吸收页**变成了 severity=high 的 IDOR 假设。这条假设如果进入下一轮，会直接产生 3 条打 `www.oppo.com/405/`、`/403/` 的请求——既离题又无意义。
判据缺陷：模板化只要求“段是数字”，没有排除 `404/403/500` 这类状态码段，也没有要求该 URL 的响应不是 catch-all。

---

## 6. `graph-signal`：8 次漂移告警，0 次采纳

| 次 | 内容（原文摘要） |
|---|---|
| 1 | 图裂成 119 块，你在同一块（8 节点），112 块没动过，从 `flag.php`/`flag.txt`/`.env.local` 开始 |
| 2–8 | 同上，逐次追加「（第 N 次提醒，一直没采纳）下一轮必须至少发 1 条打这些 Root 的请求」 |

设计意图没问题（防止模型在局部打转），但**roots 选错了**：图上的孤立节点绝大部分是“从未验证的字典条目”，不是“高价值未探索面”。在 catch-all 目标上，按 `flag.php` 去发请求只会再拿一个 302。

正确做法：漂移提醒的候选 Root 必须经过 `properties.status_code` 或 `hits > 0` 过滤；`untested` 且无状态的节点不配当 Root。

---

## 7. `graph-rebuilt` 4 次：图确实可从账本重建

4 次重建都是“9 条工具结果重放进图，最深 3 跳”，重建后节点/边数与增量写入一致（127/126），说明：

- 增量写图与全量重放**收敛**（不会因为重放长出重复节点，`merged=139` 记录的是去重次数）；
- 但**重建只重放抓取类工具**，不重放 4 个协议模块（主权/SPA/字典折叠/零熵）——这一点与 note.yun 一致，仍待补（`rebuildProjectBlackboxGraph` 未接 `replayProtocols`）。

---

## 8. 和 note.yun 那轮的图对比

| 维度 | note.yun `1cdf92d4816b72bf` | support.oppo.com `463dd72637d195c6` |
|---|---|---|
| 节点 / 边 | 241 / 239 | 127 / 126 |
| untested 占比 | 53.5% | **93.7%** |
| 单次字典灌入 | 224（同样是 `-s` 无状态） | 113（同） |
| WAF 墙 | 9 × 412（2681B，securityfs） | 3 × 412（同一模板） |
| 死胡同 | 有（`/`） | 有（`/cn`） |
| 图上有攻击链 | 无 | 无 |
| 漂移告警 | 有 | 8 次（更凶） |
| 协议副作用 | 无 | **主权转移误判 → 跨资产偏离** |

两轮共同的病根是同一个：**字典扇出把“不确定”写成了“端点”**，然后图统计、漂移提醒、装甲判定全部跟着错。

---

## 9. 需要修的 4 处（带位置）

| # | 问题 | 位置 | 补丁方向 |
|---|---|---|---|
| 1 | ffuf `-s` 丢状态码，113 条命中无状态入库 | `src/blackbox/tools.ts:1897` | 去掉 `-s`，按 `path [Status: N, Size: N]` 解析，把 `status` 写进 item 与节点 `properties` |
| 2 | 字典命中节点没有“未验证”标记，漂移提醒拿它当 Root | 图 ingest（`content_discovery` 分支）+ `graph_drift` 选 Root | 节点打 `properties.unverified=true`；Root 候选要求 `status_code` 存在或 `hits>0` |
| 3 | 装甲把“节点存在”当“已探过” | `src/control/console/desk.ts:506` | `known` 改为 `node.properties.hits > 0 \|\| node.status !== "untested"` |
| 4 | 路径模板化把 `404` 当 id，生成假 IDOR | 模板提取（`{id}` 生成处） | 排除 `/(\d{3})/` 状态码段与纯数字 `<1000`，并要求该响应不是 catch-all |

第 3 条是本轮唯一“直接掐死会话”的那条，详见会话报告 §5。

---

## 10. 一句话结论

这张图**记录了 8 条真实探测、3 面 WAF 墙、1 个死胡同，以及 114 个从未验证过的文件名**；
它最大的价值不是“发现了什么”，而是暴露了三个连坐缺陷：字典命中不带状态码 → 图把不确定当端点 → 装甲把节点存在当已探测。
不修这三处，任何 catch-all 目标上的图都会长成同一副样子：一根柱子，113 片叶子，和 8 条没人理的漂移提醒。
---

## 11. 追查：为什么第一轮图是好的，第二轮直接裂成 120 块

### 11.1 两个耗时点的分量数

| 时刻 | 节点 | 连通分量 | 说明 |
|---|---|---|---|
| 19:01:31（katana 之后，第一轮结束） | 8 | 1 | 2 个 asset + 6 个端点，全部走 `navigates_to` |
| 20:32:40（`content_discovery` 之后） | 121 | **119→120** | +113 个节点，每个都自成一个分量 |

`graph-signal` 原文：“图裂成 119 块，你一直在同一块里（8 个节点）。另有 112 块没动过。”

### 11.2 根因是两件事叠在一起

**① `discovered_from` 不是可走边。**
`src/blackbox/graph/analyze.ts:14`：

```ts
const WALKABLE = new Set<GraphEdge["type"]>(["navigates_to", "calls_api", "flows_data_to"]);
```

字典命中的节点只能从父节点连一条 `discovered_from`（`builder.ts:286`），这条边不在 WALKABLE 里，
所以并查集不会合并它们——**每个命中都是一个孤立点**。第一轮没有命中，所以只有 1 块。

**② 命中被当成了端点节点。**
`content_discovery` 的 `items`（113 条）进了 `endpoints`，于是 113 个 `ep:` 节点被建出来。
在 catch-all 目标上，这 113 条命中大概率都是同一个 `302 → https://www.oppo.com//404/`，
但 `-s` 静默模式不带状态码（`src/blackbox/tools.ts:1897`），下游连“同不同形”都判断不了。

一句话：**图不是“裂开”，是“把不确定的东西当成了节点”。**

### 11.3 修法：命中降级为候选路径

| 位置 | 改动 |
|---|---|
| `src/blackbox/graph/extract.ts` | 新增 `CANDIDATE_TOOLS`（content_discovery / api_routes / wordlists / vhosts）、`isCandidateTool()`、`candidatePathOf()` |
| `src/blackbox/graph/builder.ts` | `IngestInput.candidates` → 挂在父节点的 `properties.candidates`（去重、上限 200）；返回 `candidates` 供协议使用，**不建节点、不建边** |
| `src/blackbox/graph/types.ts` | `NodeProperties.candidates / candidate_count`；新增 `origin`（request / link / js / api / item） |
| `src/control/console/desk.ts` | 两条 ingest 路径（实时 + 历史回放）对候选工具走 `candidates`；协议三改读候选（`candidates ≥ 30` 也触发聚类）；重放时清空 `graph_drift` |
| `src/blackbox/graph/analyze.ts` | 漂移 Root 必须“验证过”：有状态码，或 `origin ∈ {request, link, js, api}`；`hits` 不再算（字典入库也会累加 hits） |

### 11.4 实测前后对比（同一份账本，`POST …/graph/rebuild` 重放）

| 会话 | 修复前 | 修复后 | 候选保留 |
|---|---|---|---|
| support.oppo.com `463dd72637d195c6` | 127 节点 / 126 边 / **120 块** | **16 节点 / 14 边 / 8 块**（最大块 9） | 113 条挂在 `asset:support.oppo.com` |
| note.yun `1cdf92d4816b72bf` | 241 节点 / 239 边 / **227 块** | **17 节点 / 15 边 / 3 块**（最大块 12） | 200 条挂在 `ep:note.yun.oppo.com/`（224 封顶 200） |

note.yun 的 227 块是同一毛病的更严重版本：224 条命中全是 `301` 同形，图上却成了 224 个“没动过的块”。

### 11.5 回归测试

`test/graph-candidates.test.ts`（6 条，全过）：

1. 候选工具识别；
2. 路径归一（整条 URL → `/path`）；
3. 113 条命中 → `newNodes` 为空、`candidate_count=113`、节点数不变、连通分量仍为 1；
4. 候选去重 + 上限 200；
5. 50 个未验证孤立端点 → **不**报漂移；
6. 有状态码但没打的端点 → **仍然**报漂移（提醒不能被一起禁掉）。

`test/graph-analyze-pathfind.test.ts` 的 fixture 补上 `origin: "link"`（契约变了：漂移 Root 认“观测面”，不认“存在过”）。

### 11.6 仍然没修的一条

ffuf `-s` 丢状态码（`src/blackbox/tools.ts:1897`）。候选现在有路径没有状态，
所以“这条命中是 200 还是 catch-all 302”仍然只能靠单发探针确认。
下一步应改成非静默输出 + 解析 `path [Status: N, Size: N]`，让候选本身带状态，
catch-all 才可能在入库阶段就被判定。
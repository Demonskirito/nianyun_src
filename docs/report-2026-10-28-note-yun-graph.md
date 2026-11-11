# 新一轮攻击历程图详解：note.yun.oppo.com（会话 `1cdf92d4816b72bf`）

- 会话：`1cdf92d4816b72bf`
- 项目：`p_06db586d65`（Ledger）
- 目标（会话入口）：`http://note.yun.oppo.com/`
- 运行窗口：2026-10-28 15:07:37 → 15:21:38（本地时间，下同）
- 结束状态：`paused / awaiting_operator`，`stopReason = observer_review_failed`
- 图来源：先取运行期实时图，再用 `POST …/graph/rebuild` 按账本回放重算（43 条工具结果），两次结果一致（241 节点 / 239 边），下表用回放值。

> 说明：本文只描述**图上的事实**。每一条结论都对应节点 id / 边 / 事件，不做推测性美化。

---

## 1. 总量

| 指标 | 值 | 说明 |
|---|---|---|
| 节点 | **241** | `asset` 2 + `endpoint` 239 |
| 边 | **239** | `discovered_from` **225**、`navigates_to` **14** |
| `parameter` / `identity` / `vuln_state` 节点 | **0 / 0 / 0** | 参数、身份、漏洞态全空 |
| 状态分布 | `testing` **15**、`untested` **226** | 没有任何 `blocked`、`dead_end`、`vulnerable` |
| 深度直方图 | `{1: 14, 2: 225, 未标注: 2}` | **最长链 2 跳** |
| 轮次（`round`） | 全部 = 1 | 本次只有 1 次 run（`lifecycle` 3 条 = 创建/开跑/停止） |
| 假设 | 2 条，均 `stall`，均已 `unreachable`（各 3 次尝试） | `stall:ep:cloud.oppo.com/`、`stall:ep:note.yun.oppo.com/` |
| 图巡检信号 | `component_drift` **3 次** | 每次都在喊“224 块没动过”，详见 §4 |

---

## 2. 节点是在哪里新建的（按发现批次）

`discovered_by` 字段就是发现它的那次 ingest 的时间戳，因此可以直接排出创建顺序：

| # | 批次（`discovered_by`） | 时间 | 新增节点 | 内容 | 来源工具 |
|---|---|---|---|---|---|
| 1 | `ev-1793171308744` | 15:08:28 | **+4** | `asset:note.yun.oppo.com`、`asset:cloud.oppo.com`、`ep:note.yun.oppo.com/`、`ep:cloud.oppo.com/` | `http.request` |
| 2 | `ev-1793171405254` | 15:10:05 | **+224** | `ep:note.yun.oppo.com/<字典路径>`（`/flag`、`/flag.txt`、`/flag.php`、`/robots.txt`、`/backup.zip`、`/admin/login` …） | `recon.content_discovery` |
| 3 | `ev-1793171741195` | 15:15:41 | +1 | `ep:note.yun.oppo.com/.env` | `http.request` |
| 4–13 | `ev-1793172030451` … `ev-1793172032734` | 15:20:30–15:20:32 | **+12** | `ep:cloud.oppo.com/{.git/config, .env, robots.txt, swagger-ui/index.html, v3/api-docs, actuator, druid/index.html, nacos, graphql, sitemap.xml}` | `http.request` |
| 14 | `ev-1793172097004` | 15:21:37 | +1 | `ep:cloud.oppo.com/actuator/env` | `http.request` |
| 15 | `ev-1793172098065` | 15:21:38 | +1 | `ep:note.yun.oppo.com/.git/config` | `http.request` |

**关键事实**：241 个节点里，**224 个（93%）来自一次 `recon.content_discovery`**，而且是**同一次前缀字典**扫出来的相对路径。它们全部停在 `depth=2`、`status=untested`。

**另一个事实**：15:20:30 第二次跑 `recon.content_discovery` 时，图**一个节点都没新增**（224 个全部命中已有节点，`hits` 从 1 变 2）。也就是说这 224 个节点里 `hits=2` 的那 224 个，是“同一份结果被灌了两次”，不是“被打了两次”。

---

## 3. agent 在哪里真正“顺延”下去了

把 `discovered_from` 边按“父 → 子”排出来，整张图只有 **1 条真实的顺延链**：

```
asset:note.yun.oppo.com
  └─ ep:note.yun.oppo.com/            (301, hits=13)
        └─ ep:cloud.oppo.com/         (200, hits=17)   ← 唯一一次真正的顺延：响应头 Location
        └─ 224 × ep:note.yun.oppo.com/<字典路径>       ← 一次字典爆破的产物，之后再没碰
```

| 顺延动作 | 证据 | 结果 |
|---|---|---|
| 识别 301 并改打跳转终点 `cloud.oppo.com` | 15:08:43 第 5 次调用 `http.request https://cloud.oppo.com/` → 200 | ✅ **这是本图唯一的有效纵深**（`ep:cloud.oppo.com/` 是最短路径成本 0 的节点） |
| 对 `cloud.oppo.com` 做 JS 提取 | `recon.js_endpoints` 两次，均 `reason=no_script_references`、`count=0` | ❌ 没顺延出任何接口 |
| 顺着字典结果继续打 | — | ❌ **0 次**：224 个节点一个都没被请求过（`status_code` 字段在 224 个节点上全部缺失） |
| 顺着 412 的 WAF 页换武器 | — | ❌ 412 只被记为 `testing`，图上没有任何“墙”的标记（详见 §5） |

### 3.1 “采纳”了什么、丢弃了什么

| 系统给的信号 | 出现在 | agent 是否采纳 |
|---|---|---|
| `graph-signal` component_drift：图裂成 227 块，另有 **224 块没动过**，建议从 `ep:note.yun.oppo.com/flag`、`/flag.txt`、`/flag.php` 开始 | 15:15:41 | ❌ 下一轮去打的是 `note.yun.oppo.com/.env` 和 `cloud.oppo.com/` |
| 同上（第二次） | 15:20:32 | ❌ 下一轮打了 10 条 `cloud.oppo.com` 敏感路径 |
| 同上（第三次） | 15:21:38 | ❌ 会话到这里被 Observer 判 `observer_review_failed` 停住，之后再没动过那 224 块 |
| `focus-appeal`：T1 出现临界信号（跳转 cloud.oppo.com）、拓扑势能 2 ≤ 6，从全局池取 1 次（剩 2） | 15:13:05 | ⚠️ 采纳了 1 次，但 T1 仍在 15:13:29 被强制 `blocked` |
| Observer advice：停止第 3 次 `recon.js_endpoints`，改用 `browser` 抓 network | 15:18:42 | ⚠️ 没再跑 `js_endpoints`，但也**没改用 browser**（后续是 `katana.crawl` 请求被焦点锁拒收） |
| `stall` 假设（`ep:note.yun.oppo.com/` 请求 4 次无变化） | 15:09:01 生成，15:09:20 降级 | ✅ 生成有效；但它只是“标记别再打”，没有驱动换面 |
| `post-surface` 投递：没有任何 POST 打法被跑过 → 建 `post_surface_20261028072032` | 15:20:32 | ❌ 一直是 `pending`，`ignored_turns=7` 后升级 |

---

## 4. 为什么这张图“宽而扁”：224 个孤岛

`discovered_from` 225 条边里，**224 条**是 `ep:note.yun.oppo.com/ → ep:note.yun.oppo.com/<某路径>`。这是一次“一个父亲 + 224 个孩子”的星形，所以：

- 图裂成 **227 个连通块**（系统巡检原文），最大块 12 个节点；
- `depth` 直方图只有 1 和 2 两档；
- 在 dagre 里就是“入口一列 + 224 个孩子一列”，不管你用 LR 还是 TB 都一样；
- 换成历程布局（横轴=轮次）也一样——因为**这次只有 1 轮**，所有节点同列。

所以本轮图的“扁”，根因不是布局，而是：**发现很多、顺延为零**。

---

## 5. 图上缺失的三类语义（都是可修的）

| 缺失 | 证据 | 后果 |
|---|---|---|
| **WAF 墙没有节点语义** | 15:20:31–15:21:37 共 **9 条** `412` 响应，正文统一 2681B、`securityfs.oppo.com/waf`（“您的访问被阻断！- 412错误”） | 412 落成 `status=testing`，`blocked` 计数 0，图上看不出“这条被 WAF 挡住”，agent 也没有“换武器”的依据 |
| **重复请求没有闸门** | `ep:note.yun.oppo.com/` `hits=13`、`ep:cloud.oppo.com/` `hits=17`；43 次调用只有 **22 个唯一请求**（重复率 49%） | `repeats`/死胡同只在 `blocked` 时才累加，200/301 的重复永远不判死 |
| **参数面全空** | `parameter` 节点 0；`cloud.oppo.com/` 返回的 5158B SPA 外壳里没提取出任何 `?param`；POST 面任务一直 pending | 逻辑漏洞/越权评价无从谈起 |

---

## 6. 图上的“墙”清单（本轮全部战果）

| 端点 | 状态码 | 说明 |
|---|---|---|
| `ep:note.yun.oppo.com/` | 301 | → `https://cloud.oppo.com/`（catch-all 重定向） |
| `ep:cloud.oppo.com/` | 200 | 5158B SPA 外壳（`nginx`，内联脚本，无外部 bundle 引用） |
| `ep:cloud.oppo.com/{.git/config,.env,swagger-ui/index.html,actuator,actuator/env,druid/index.html,nacos}` | 412 | **OPPO WAF 阻断页**（2681B 统一指纹） |
| `ep:cloud.oppo.com/{robots.txt,v3/api-docs,graphql,sitemap.xml}` | 404 | 不存在（等价负向） |
| `ep:note.yun.oppo.com/{.env,.git/config}` | 412 | 同一 WAF 指纹 |

**确认漏洞：0。验证过的负向结论：0（都还没写成 finding）。**

---

## 7. 和上一轮（`20ea56baa4569b8d`）的图对比

| 指标 | 上一轮（gray-push-intl） | 本轮（note.yun） |
|---|---|---|
| 节点 / 边 | 269 / 270 | 241 / 239 |
| `discovered_from` | 224 | 225 |
| `parameter` | 10 | **0** |
| `testing` | 37 | **15** |
| 轮次数（图上有几列） | 8（1,2,3,4,13,15,20,21） | **1** |
| 最长链 | 4（含参数节点） | **2** |

结论：**抽取层是好的**（两轮都稳定产出 `discovered_from`），**瓶颈完全在调度层**——本轮 agent 端只有 22 个唯一请求，其中能真正延伸图的只有 1 个（301 → cloud），其余全在同一个入口上反复。

---

## 8. 一句话结论

> 这张图不是“画不出来”，是**这一轮确实没有从左到右推进**：241 个节点里 224 个是一次字典的静态产物，节点之间真正的“挖到 → 再看”只发生了 1 次（301 → cloud.oppo.com）；系统三次点名那 224 个未触动的根，agent 三次都没采纳。
---

## 9. 修复后复算（同一会话，`POST …/graph/rebuild` 重放 43 条结果）

针对本文 §5 指出的三类缺失，本轮改了四处代码（详见 `docs/agent-constraints-audit.md` §46）。用同一份账本重放后：

| 指标 | 修复前 | 修复后 | 变化原因 |
|---|---|---|---|
| 节点 ro 边 | 241 / 239 | 241 / 239 | 不变（数据没变，只是判据变准） |
| `blocked` | **0** | **9** | 412 + `securityfs.oppo.com/waf` 指纹现在判墙 |
| 带 `wall` 属性的节点 | 0 | **9**（全部 `waf_oppo`） | 图上终于能区分“被 WAF 挡住”和“200 正常” |
| `dead_end` | **0** | **2** | `ep:note.yun.oppo.com/`（同一请求 13 次）、`ep:cloud.oppo.com/`（8 次） |
| `testing` | 15 | **4** | 其中 9 个被重新归类为 blocked，2 个判死 |
| `untested` | 226 | 226 | 那 224 个字典节点仍然没被请求过（这是 agent 的问题，不是图的问题） |

图上的 `dead_end` 文案现在是「同一请求已重复 13 次（响应未变化）」——这条路径下次会**在执行前被直接拒收**（`deadEndOf` 闸门），不再消耗调用额度。

同时把 `content_discovery` 的 ffuf 调用加了 `-ac`（自动校准）+ `-mc`（状态码白名单）：这个目标对任意路径都回 301，`-ac` 会先打一个随机路径做基线，把同形的 301 全部滤掉。**下一轮这一处不会再凭空多出 224 个假节点。**

仍未修的（诚实记录）：`depth` 还是 2、`parameter` 还是 0。前者因为这一轮确实没挖到第 3 跳（`recon.js_endpoints` 两次都是 0 结果），后者因为 `https://cloud.oppo.com/` 返回的是 5158B 的 SPA 外壳、里面没有可提取的 query 参数。
# Nianyun 黑盒 SRC 挖掘 — 实测会话审计与优化建议

> 审计对象：当前工作目录登记目标 `https://support.oppo.com/cn/`（已授权 SRC）
> 实测入口：`nianyun run`，`execution.mode: execute`
> 实测会话：`p_4acf93c7ec` / `784b64a1e0835449`
> 关键约束：`tools.env.yaml` 模型 key 全空 → **自动回落本地确定性规划器 `local_plan.ts`，零 LLM 调用**
> 会话结果：5.5s 跑完 · 7 次工具调用 · 5 轮 · tokens=0 · cost=0 · `stop_reason=blocked` → 被验收门提升为 `tasks_completed`（`acceptance_ready=true`）

---

## 0. 一句话结论

**这台机器现在跑出来的不是"漏洞挖掘"，而是一份只读的配置合规体检。**
你的架构图描述的是 LLM 驱动的理想路径（7 阶段 / 16 打法 / 攻击图 / 战术型 Observer），但**当前无模型环境里这条路径整体休眠**：16 个 playbook 实际执行 0 个，13 个侦察/攻击工具全死，Observer 退化为"证据引用核对器"且全程 0 条建议，唯一被识别出的真实攻击面（Vue SPA 逆向）被 spawn 后又放弃。最终产出的 3 条发现全是 curl 级别能拿到的配置问题（CORS 反射、缺响应头、Server 头泄露），没有任何注入/越权/逻辑/鉴权类漏洞被触及。

---

## 1. 主 Agent（本地规划器）实际干了什么

来自 `blackbox_events` 的真实轨迹：

| 轮 | 动作 | 证据 |
|---|---|---|
| 1 | 派发 2 条只读请求：`GET /cn/`（200）、`GET /`（302→/cn/） | ev-58a57b… / ev-… |
| 1 | **SPA 缴械**：判定 support.oppo.com 为 Vue SPA 外壳（135359B，framework:vuei，inline_scripts:8，external_scripts:8）→ 生成系统任务 `T_SPA_REVERSE_38538276`（playbook=unauth_exposure，deliverables=api_endpoints+auth_entry） | spa-disarm |
| 2 | `GET /cn/`（T1 基线,200）、`GET /`（T2 头审计,302） | 势能 +5 |
| 2 | **反停滞假设触发**：`ep:/cn/ 已被请求 4 次仍无状态变化：停止换 payload，改换攻击面` | graph-hypothesis |
| 3 | `GET /robots.txt`（200）、`GET /jimu/.../oppo_vendor.*.js`（200） | T3/T4 完成 |
| 4 | `GET /cn/?nianyun_cors=1`（200）→ 标记 dead-end | T5 CORS |
| 5 | 5 任务结案，产出 3 条候选发现 | 本地规划完成 |

固定 5 步清单：`T1 baseline / T2 headers / T3 robots / T4 js-surface / T5 cors`。**全部是 GET/HEAD + 1 次 Origin 变异，无任何写操作、无爆破、无参数测试。** 这正好符合 `local_plan.ts` 注释自述："它是'能跑完'，不是'能打穿'"。

### SPA 逆向任务为何被放弃（关键）
系统正确识别了 Vue 外壳并 spawn 了 `T_SPA_REVERSE_38538276`，但本地规划器的 `adoptSystemTask` 只从 JS 正文里正则抠 `/api|/v{n}|/graphql|/gateway|/service` 形态的字符串。实测 JS（`oppo_vendor.*.js`）里没匹配到 → 判 `blocked` → 原因写"交回人工/模型处理"。**即：唯一能通向真实 API 面的打法，被一个脆弱正则判死并丢弃。**

---

## 2. Observer 实际干了什么

共触发 4 次审查（`blackbox_events` actor=observer）：

- 3 次 ordinary 审查（触发原因 `no_progress` / `PARTIAL_TASK_OUTCOME`）：输出"复核 0 条候选发现，确认 0 条"。
- 1 次 terminal_review：输出"复核 3 条候选发现，确认 3 条"。
- **4 次审查的 `concerns` 与 `suggestions` 全部为空数组。**

也就是说，本地 Observer（`runLocalObserverPlan`）只做一件事：**核对"发现引用的证据 id 是否落在成功的 tool-result 上"**。它：
- 没有识别任何架构特征（WAF / OSS / 10403 统一鉴权码）—— 这些"战术型 Observer"规则（`TACTICAL_OBSERVER_RULES`，见 `agent.ts`）**只存在于 LLM 路径**；
- 没有对 CORS "high" 发现提出"需要链式验证实际数据暴露"；
- 没有对"唯一真实攻击面 SPA 逆向被放弃"提出任何告警；
- 没有执行去重 / 止损 / 证据质量复核（这些是你图里给 Observer 列的职责）。

**Observer 在无模型模式下是一个橡皮图章。**

---

## 3. 环境漂移：13 个攻击/侦察工具全死

冒烟校验（`warning` 事件 1475）判定不可用工具：

```
recon.nuclei, recon.secrets, recon.sast, recon.graphql, recon.cms,
katana.crawl, recon.content_discovery, recon.sql, recon.xss,
recon.tls, recon.ports, recon.api_routes, browser.open
```

失败原因全部是 `spawn /usr/local/bin/<tool> ENOENT`——路径写的是 **Linux/Docker 路径，跑在 Windows 上**。即：**子域枚举、端口扫描、内容爆破、参数发现、SQLMap、Dalfox、GraphQL Cop、CMS 识别、TLS 审计、浏览器渲染——全部不存在。**

`playbook-coverage` 事件显示：16 个 playbook 里**只有 `unauth_exposure` 被绑定，且 calls=0 / ok=0**。换言之，**0 个打法真正执行**。

最致命的是：**这 13 个工具死亡只是以一条低优先级 warning 事件记录，会话照样 `tasks_completed`**。操作员拿到的报告看起来"完整"，实则覆盖面被砍掉 90% 却无人告警。

---

## 4. 四个维度的问题诊断

### 4.1 打法（Tactics）
- **16 个 playbook 实际执行 0 个**；跑的是写死的 5 步只读清单。图里画的"15/16 杆打法"在本环境完全休眠。
- **唯一真实漏洞（CORS 反射 + 凭证）被直接定为 high**，但没有任何链式验证：反射源 + `Access-Control-Allow-Credentials: true` 要真正可利用，必须证明该源下存在"登录态能读到敏感数据的接口"。对一个 `/cn/` 营销页，影响通常有限。专业猎手会把 CORS 反射当**线索**去验证"能否读到账户/订单数据"，而不是直接定 high 结案。当前 severity 仅由单条响应头推导 → **严重高估配置类问题**。
- **SPA 逆向打法（2026-11-01 最新加入、对现代 Vue 站最关键的一招）不可达**：本地规划器用脆弱正则判死它。真实 Vue 项目的 API 常在 chunk 文件 / 经网关封装 / 被混淆，正则几乎必漏。
- playbook 优先级（未授权>越权>SQLi>…）是死代码——本地规划器有自己固定清单，从不consult。

### 4.2 预算（Budget）
- 配置预算 `timeMs=900000`（15min）/ `wallClockMs=1800000`（30min），**实际用了 5.5s**。预算在这里只是天花板，没有任何"按期望价值分配深度"的 allocator。
- **没有"为高价值线索追加预算"的机制**：CORS 命中 high 后没触发深挖；SPA 逆向被识别为主攻击面后没分配任何预算（直接放弃）。
- `tokens=0 / cost=0`：本应做分诊的 LLM 智能层缺席，预算系统是为一个不存在的 LLM 设计的。

### 4.3 路径（Pathing / Coverage）
- 覆盖 = 单源根路径 + 1 个 JS 文件 + robots.txt。**无子域枚举、无端口扫描、无参数发现、无内容爆破**——图里"铺面/Surface"阶段在此完全失效。
- 攻击图（历程图）只长出 4–5 个节点（asset、ep:/cn/、ep:/、ep:/robots.txt、ep:js、param:nianyun_cors）+ 1 个 dead-end，是玩具级图。
- **`graph-rank` 反复给 `http.request` 打 0 分并标注"未绑定打法"**：攻击图的"图加成"在本地模式下不产生任何引导作用，是失效功能。
- 最有价值的一条路径（Vue bundle → vendor API）被打开后又关上，无后续。

### 4.4 控制（Control / Observer / 验收）
- **Observer 是 no-op（见 §2）**：无模型时其全部战术职责蒸发。
- **环境漂移静默通过**：13 个工具死亡仅是 warning，会话仍 `tasks_completed`。控制面没有"覆盖骤降即阻断/升级"的机制。
- **验收门过宽**：仅 1 个任务 `blocked`（恰好是唯一真实攻击面 SPA 逆向），却被提升为 `tasks_completed` / "评估完成"。操作员会被"完成"误导，以为主攻击面已测，**实则核心面未测**。
- 证据闸门（validation_failed 必须同步）设计是好东西，但本次未触发，因为本地发现总能引用到合法证据——闸门没机会暴露"覆盖空洞"。

---

## 5. 与专业 SRC 猎手的对比

| 维度 | 专业猎手拿到 support.oppo.com/cn/ | 当前 Nianyun（无模型运行） |
|---|---|---|
| 资产面 | 子域/同网段资产枚举，定位真实 API 主机 | 仅根域 + robots + 1 个 JS |
| 前端面 | 拉取并逆向 Vue bundle，枚举 vendor/global-service API | 正则抠 5 类路径失败 → 放弃 |
| 鉴权面 | 区分匿名/登录端点，测 IDOR/逻辑/越权 | 未触及任何鉴权流 |
| 漏洞链 | CORS 反射→验证能否读到账户数据→定级 | CORS 反射直接定 high 结案 |
| 工具链 | nuclei/ffuf/sqlmap/dalfox 全开 | 13 个工具全死，0 个 playbook 执行 |
| 复核 | 人工验证 POC + 影响面 | Observer 只核对证据引用，0 建议 |
| 产出 | 带 POC 与影响评语的可用报告 | 配置体检报告（curl 级） |

**本质差距**：专业猎手做"假设—验证—链式利用"；当前系统做"固定清单—打卡—引用核对"。前者产出可提交的漏洞，后者产出可自动化的合规扫描。两者不是同一个工种。

---

## 6. 专业优化建议（按优先级）

1. **重命名/重定位本地规划器**：它本质是"合规/冒烟扫描"，不该被当作"漏洞挖掘"交付。要么在报告头明确标注 `mode=local-smoke, not vuln-mining`，要么给它在无重型 CLI 时的最小真实侦察路径（用 `http.request`+字典做内容发现、用 JS 静态解析做 API 提取，替代那套脆弱正则）。
2. **SPA 逆向不可用必须修**：把 `adoptSystemTask` 的正则换成真正的 JS 端点提取（AST 或宽泛模式：匹配 fetch/axios/uni.request 的 URL 字面量、`./api/`、网关前缀、chunk 文件名），否则现代 SPA 全漏。这是当前**性价比最高的一处修复**——它本已是 spawn 出来的正确任务，只毁在收口逻辑。
3. **环境漂移要升级为阻断/显式降级**：侦察与攻击工具大面积缺失时，控制面应**拒绝以"完成"交付**，改为 `partial / coverage-degraded` 并在报告首页红字提示"以下能力不可用：recon.subdomains, recon.ports, katana…"，让操作员一眼看到覆盖空洞。
4. **补一个离线可用的规则型战术 Observer**：架构特征识别（全站 301、统一 10403、WAF 页、OSS 直链）+ 自动 follow-up 建议生成（"CORS 反射→验证源下鉴权接口是否泄露数据"），别让战术职责完全依赖 LLM。至少让 Observer 在发现 high 时强制追加一条"待验证影响"的 supplemental_task。
5. **收紧验收门**：存在 `blocked` 的真实攻击面任务（尤其 system:spa / 主 playbook 任务）时，不应报 `tasks_completed`，应报 `partial — 主攻击面未测`。
6. **severity 必须绑定"影响证明"**：CORS/响应头这类配置项，在证明"能读到敏感数据"前最高定 medium；high 需要 POC 级影响证据。当前"单响应头→high"会严重虚高噪声。
7. **让攻击图在本地模式也有用**：给 `http.request` 绑定一个默认侦察 playbook，或明确标注"图加成需 LLM"；否则 `graph-rank` 打 0 分是失效代码。
8. **预算要驱动深度分配**：用"期望价值"而非固定清单分配轮次——高价值线索（命中 high、识别到 SPA/鉴权入口）应自动获得更多探测预算，而不是和 robots.txt 一样只发一条请求就结案。

---

## 附：本次会话关键证据索引
- 会话：`blackbox_sessions.id = 784b64a1e0835449`，项目 `p_4acf93c7ec`
- 报告：`data/projects/p_4acf93c7ec/report.md`、`summary.json`、`run.json`
- 不可用工具 warning：`blackbox_events` kind=warning（"冒烟校验发现不可用工具…"）
- SPA 缴械：`blackbox_events` kind=spa-disarm
- Observer 复核：`blackbox_events` actor=observer kind=advice（4 条，concerns/suggestions 均为空）
- 打法覆盖：`blackbox_events` kind=playbook-coverage（仅 unauth_exposure 绑定，calls=0）

# 从一个 URL 到 SRC 挖掘：Nianyun 全链路说明

本文按"数据怎么流动"讲清楚 Nianyun 从拿到一个 URL 开始，到产出可提交的候选漏洞为止的每一步：谁产生数据、谁校验、失败会怎样。所有环节都可以在代码里对上名字。

---

## 0. 总览

```
URL / 域名
  │ ① 资产发现（ARL / FOFA / HTTP 种子）
  ▼
assets + observations（资产台账，去重、指纹、截图）
  │ ② 候选池筛选与 Agent 评分
  ▼
asset_candidates（可挖候选：分数、理由、复核状态）
  │ ③ 送至黑盒 = 建 session（绑定 candidate + target）
  ▼
blackbox_session（环境检查 → 跑 → 检查点 → 证据 → 发现）
  │ ④ 任务状态机 + 工具批执行 + 证据台账
  ▼
checkpoint（tasks / evidence / advice / findings / acceptance）
  │ ⑤ 机械监督 + Observer 审查 + 门禁
  ▼
report（项目级报告：资产、候选、已确认发现、未完成说明）
```

三条贯穿全链路的原则：

1. **一切可回溯**：每个结论都要挂在证据 ID 上（`ev-…`），证据不可篡改，只能追加。
2. **只有代码做判定**：模型只提方案，能不能算完成、算确认，由确定性校验器决定（`acceptance.ts`、`task-evidence.ts`、`findings.ts`）。
3. **停下要说出理由**：每次停都写 `stopReason` + 检查点，操作员能看到"为什么停、下一步是什么"。

---

## 1. 资产发现：URL 从哪来

`src/asset/arl.ts`、`src/asset/fofa.ts`、`src/asset/discover.ts`

| 来源 | 输入 | 产出 |
|---|---|---|
| ARL（资产灯塔） | 域名（严格要求纯域名） | 子域、IP、站点、指纹 |
| FOFA | 查询语法（`domain=…`、`cert=…`、`body=…`） | 同上，支持分页与规模上限 |
| HTTP 种子 | 已知 URL 列表 | 直接进入探测 |

发现结果先落 `assets` 表：按 `host+port+scheme` 归一化去重，`observations` 记录每次观测到的标题、指纹、状态码、证书、截图。**没有资产台账就不会有候选池**——这是整个流程的地基。

## 2. 候选池与评分：哪些 URL 值得挖

`src/asset/candidates.ts`、`src/asset/review.ts`、`console/src/pages/Assets.tsx`

- `importAssetCandidates()` 把资产变成候选：规则先过滤（活、可访问、非静态资源、非重复入口），再落 `asset_candidates`。
- **Agent 评分**（`reviewAssetCandidates`）：把候选的关键观测（URL、标题、指纹、响应特征）交模型打分，产出 `score` + `reason`。批量 6 个/批、并发 2，单条失败只标记该条（`review_attempts` / `review_error`），不会整批回滚。
- 操作员看板按三档展示：未评分（`pending`）、评分失败（可"重试评分失败"）、已评分（可"重新评分筛选结果"）。
- **评分不会因为重跑而失效**：已评分的候选不会被重置；发现源从 ARL 换成 FOFA 也不重算历史分数。

到这里，一个 URL 已经有"值不值得挖"的排序依据，可以被操作员挑进黑盒。

## 3. 送至黑盒：会话即战场

`src/control/console/desk.ts` → `createProjectBlackboxSession()`

- 点"送至黑盒"= 用该候选建（或复用）一条 `blackbox_session`：`{project_id, candidate_id, target}`。
- **幂等**：`findBlackboxSessionByCandidate` 命中就返回已有会话（`reused: true`），不会一次点击堆出一堆会话。
- 会话可以删除（`DELETE /api/projects/:pid/blackbox-sessions/:sid`）：运行中的会话拒绝删除（409），删除时连带清理浏览器会话与产物目录，DB 里保留审计痕迹。
- 环境检查（`environment_check`）：浏览器、Burp、工具二进制的可用性。不通过就不允许 `run`——避免把"工具没装"记成"挖不动"。

## 4. 跑起来：任务状态机 + 工具批

`src/control/console/desk.ts` → `runProjectBlackboxAgents()`，`src/blackbox/*`

一轮（round）的结构：

```
读检查点 → 组装上下文 → 主 Agent 返回 JSON（required_tasks / tool_requests / task_outcomes / advice_decisions / findings）
        → 执行工具批（每个 tool_request 一条证据）
        → 写证据 + 更新任务状态
        → supervise()（机械监督：预算、停滞、证据完整性、校验错误）
        → 需要时 Observer 审查（只读，不改台账）→ 建议入账
        → 检查点落库（内容不变则不写事件）
```

**任务状态机**（`progress.ts`）：`pending → completed | blocked | failed`，外加 `task_outcomes` 声明与 `taskOutcomeResults` 拒绝明细。完成一个任务必须给出**属于该任务的、成功的 tool-result 证据**；引用错 id 会被拒绝并保留 `path / evidence_id / rule` 供下一轮修正。

**工具面**（`tools.ts`，24 个带 spec 的工具 + Burp 全量桥接）：

| 组 | 工具 |
|---|---|
| 直连 HTTP | `http.request`（重定向/超时/大小上限、代理） |
| 浏览器 | `browser.open` / `browser.screenshot` / `browser.close`（支持 click/fill/press/select/hover/wait/scroll 与 `evaluate`） |
| 侦察 | `katana.crawl`、`recon.subdomains`、`recon.dns`、`recon.http_probe`、`recon.ports`、`recon.historical_urls`、`recon.content_discovery`、`recon.parameters`、`recon.js_endpoints`、`recon.tls`、`recon.api_routes`、`recon.secrets` |
| 漏洞类 | `recon.nuclei`、`recon.xss`、`recon.sql`、`recon.jwt`、`recon.graphql`、`recon.cms`、`recon.sast`、`recon.interactsh`（带外验证） |
| Burp | `burp.check/history/sitemap/entry/issues/repeater/send/scan…`（读类只读，动作类按目标主机校验） |

**预算与阶段**（`src/blackbox/rules.ts`）：

```yaml
budgets:      { time_sec: 900, tool_calls: 50, agent_turns: 24, retries: 5 }
loop_control: { task_retry_limit: 2, repeat_limit: 2, stall_batch_limit: 3,
                stage_timeout_sec: 900, stage_rollover_limit: 4 }
request:      { max_timeout_ms: 60000, max_redirects, max_body_bytes, max_output_bytes }
```

- `stage_timeout_sec` 是一段的时间片，`stage_rollover_limit` 是"这一段用完还能再开几段"。两者配合的效果：**单个慢工具不能掐死整轮 run**，只有 run 自己的预算（时间/工具/回合）才终止它。
- 任何一次工具调用的超时都不会超过"剩余阶段的 60%"（下限 30s），防止 nuclei 这类工具独占时间片。

## 5. 证据台账：一切结论的锚点

`src/shared/db.ts`（`addBlackboxEvidence`）、`src/blackbox/task-evidence.ts`

- 每次工具执行落两条证据：`tool-request`（意图）与 `tool-result`（结果，含 `ok`、`task_id`、状态码、体积、产物路径）。另有 `artifact`（落盘文件）、`body`、`screenshot`、`target-list`、`agent-analysis`、`candidate-finding`、`operator-review`、`run-summary` 等。
- **证据分级使用**：
  - `evidence_ids`（任务完成依据）：只认**本任务**的、`ok: true` 的 `tool-result`。
  - `audit_ids`（审计引用）：审查/纠正记录，或产生该结果的 `tool-request`。
  - 两者不可互换；证据不会被"静默过滤"，引用错了就报错并保留明细。
- 会话级证据条数是"这轮到底干了多少活"的唯一硬指标——不是模型说了什么，而是台账里有什么。

## 6. 监督与审查：谁来否决模型

`src/blackbox/supervision.ts`、`observer`（`blackbox/agent.ts` 第二角色）、`acceptance.ts`

1. **机械监督**（无模型）：预算预警、无进展、工具连续失败、证据完整性、校验错误 → 给出 `continue / observer / pause`。
   - 其中"可自纠的完成声明"（`task_outcomes.*` 路径下的拒绝）不再打断整轮，交回给下一轮修正；真正的证据失真才升级为 `validation_failed`。
2. **Observer 审查**（只读，不调用工具）：判合规、判证据是否支撑结论、提补充任务，**并对发现做裁决**——证据可复现且排除了误报置 `confirmed`，证据不足置 `needs_evidence` 并点名缺哪一步，被证伪置 `rejected`。建议进 `advice`，主 Agent 必须逐条 `accepted/rejected` 并给理由。
   - Observer 的 `confirmed` 不是自由心证：desk 侧要求 `evidence_ids` 非空、全部落在该发现自己的证据里、且 `validateFinding()` 通过（同一目标、至少一条成功 `tool-result`）；不满足就拒绝写入。操作员仍可覆盖。
   - 预算按 **每轮 run** 计：`time_sec`/`tool_calls`/`agent_turns`/`tokens`/`cost`/`retries` 从本轮开始时归零，会话 `usage` 只做累计展示。否则一个跑满 900s 的会话会永久 `time_budget_exhausted`。
3. **验收门禁**（`evaluateAcceptance`）：任务是否全终态、证据是否完整、发现是否已复核、建议是否已处置、校验错误是否为 0。任一条不满足就不许"完成"，`stopReason` 会如实写明（`required_review_pending`、`validation_failed_review_required`、`stalled`、`time_budget_exhausted`…）。

**中断语义**：操作员暂停/取消不会消耗 Observer 的重试额度（审查回到 pending，次数归还）；进程被杀留下的 `running` 审查会在下次运行被重置；只有人工 `resume` 才会清理"指向不存在建议 id"的不可达错误。这些是"会话被锁死、再也跑不动"的根因修复。

## 7. 发现：候选到确认

`src/blackbox/findings.ts`

```
candidate ──(Observer 复核证据一致)──► reviewed / needs_evidence
   └──(人工确认)──► confirmed        └──(驳回)──► rejected
```

- 工具输出（nuclei 命中、Burp issue、可疑响应）**只是候选**，不能自动算漏洞；必须写明复现步骤、影响、修复建议，并把证据 ID 挂上。
- `validateFinding()` 校验：目标一致、证据存在且属于该目标、复现步骤非空、严重级别合法。`confirmed` 由 Observer 依据可复现证据裁决，操作员可覆盖；报告里明确写"确认不代表已复测第三方系统"。

## 8. 报告

`src/report/project.ts`、`src/risk/scoring.ts`

项目报告汇总：资产与候选统计、已确认/待复核发现、每轮 run 的预算与证据、未完成任务的原因（`blocked`/`failed` 的 `outcome_reason`）。风险评分按资产暴露面与发现严重级别加权，用于排序而不是定罪。

---

## 9. 一次真实运行的读数（bdev.oppo.com）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 单轮时长 | 377s 就停 | 900s+ 跑满预算 |
| 工具调用 / 回合 | 4 / 2 | 33 / 15 |
| 完成任务 | 1 / 4 | 16 / 22 |
| 证据条数 | 12 | 113 |
| 停止原因 | `required_review_pending`（且之后永久锁死） | `required_review_pending`（可继续，且不再锁死） |

同时可见的真实动作：`burp.sitemap` 分页 100 条枚举、`GET /api`、`/user/getLoginInfo`、`/api/order/prodOrderList`、`/api/user/agent/listCorporate` 均 200，主包 JS 65KB 正文入账——这才是"挖"的证据。


---

## 10. 打法库：把"手工验证"变成 Agent 的分步套路（2026 版流水线落点）

外部流水线（阶段 1–8 + 6 条硬规律）里，测绘/存活/指纹/接口提取我们已经有了；缺的是**手工验证这一层的固定打法**。现在它被写成了代码：`src/blackbox/playbooks.ts`。

### 10.1 每个 playbook 的字段

```ts
{ id, title, priority,          // 排序：未授权1 → 越权2 → SQLi3 → 上传4 → cmdi5 → SSRF6 → 反序列化7 → JWT8 → 云9 → 逻辑10 → GraphQL/WS11 → XSS12
  when: string[],               // 什么指纹/接口形态该用它
  timebox_sec,                  // 单条线的时间盒（到点没确认就换线）
  steps: [{ id, tool, purpose, input?, expect? }],
  confirm: { evidence: stepId[], must_show },   // 什么证据才算"确认"
  stop: string[],               // 什么时候判定走不通
  report: string[] }            // 确认后报告必须写的内容
```

### 10.2 与外部流水线的映射

| 外部阶段 / 手法 | Nianyun 里对应的东西 |
|---|---|
| 子域 / 空间测绘 / 企业维度 | `recon.subdomains`、`recon.dns`、资产发现 provider（ARL / FOFA）+ `recon.http_probe` |
| 存活 + 端口 | `recon.http_probe`、`recon.ports`（naabu/nmap） |
| 指纹 | `recon.cms`、`recon.tls`、`recon.nuclei -tags tech`，指纹决定 playbook（`recommendPlaybooks`） |
| 目录/接口/JS | `recon.content_discovery`、`katana.crawl`、`recon.historical_urls`、`recon.js_endpoints`(subjs)、`recon.parameters`(arjun)、`recon.api_routes` |
| 自动化低垂果实 | `recon.nuclei`（critical/high + exposure/unauth/default-login/takeover） |
| 未授权/信息泄露 | playbook `unauth_exposure`：`recon.content_discovery` → `http.request` → **`http.diff`** → `browser.open` |
| 越权/IDOR | playbook `idor`：A 账号取自己 → 换 B 的 id → **`http.diff`** → 垂直越权对照 |
| SQL 注入 | playbook `sqli`：布尔对照 → **`http.diff`** → 报错注入 → `recon.sql`(sqlmap) → OAST 盲注 |
| 上传/RCE | playbook `upload_rce`：合法文件探接口 → 双扩展/图片马（`http.request` 的 `multipart`）→ 访问验证回显 |
| 命令注入 | playbook `cmdi`：四种分隔符回显 → **`http.diff` 比耗时** → OAST |
| SSRF | playbook `ssrf`：`recon.interactsh` 起监听 → 注入 → poll 回连 → 云元数据 |
| 反序列化/SSTI | playbook `deserialization`：指纹 → OAST → `http.request` 的 `body_base64` 投递 → `{{7*7}}` 算术回显 |
| JWT | playbook `jwt_auth`：`recon.jwt` → **`http.diff`** 对比真实/伪造 token |
| 云与供应链 | playbook `cloud_supply`：`recon.secrets`(trufflehog) → bucket 列举 → 元数据 |
| 业务逻辑 | playbook `logic`：基线请求 → 篡改数量/价格 → **`http.diff`** 看状态变化 → 回调重放 |
| GraphQL/WS | playbook `graphql_ws`：`recon.graphql` → 手工查询 → `browser.open` 验 WS |
| XSS | playbook `xss`：回显探测 → `recon.xss`(dalfox) → `browser.open` 的 evaluate 验执行 → OAST 盲打 |
| 无回显一律 OAST | 所有盲打类 playbook 都引用 `recon.interactsh`（start → payload → poll） |
| 登录后再扫 | 项目级共享 Cookie jar（`context.ts` / `cookies.ts`），登录一次后续请求与浏览器自动带 |
| 单目标时间盒 | 每个 playbook 的 `timebox_sec`（10–25 分钟），到点没 confirm 就按 `stop` 换线 |

### 10.3 新增的确认原语：`http.diff`

外部流水线里"对比登录态/未登录态""A 的 Cookie 打 B 的资源""布尔真假两次响应"全靠人眼看两段 body，这正是误报和自我欺骗的来源。现在一次调用返回结构化对比：

```json
{ "baseline": {"status":403,"body_bytes":9,"sha256":"...","duration_ms":35},
  "variant":  {"status":200,"body_bytes":16,"sha256":"...","duration_ms":41},
  "delta": {"status_changed":true,"body_bytes":7,"similarity":0.0,"duration_delta_ms":6},
  "verdict": "different",
  "hint": "auth_or_guard_bypassed：变体绕过了原本的拦截",
  "auth_only_change": true }
```

- 只换 Cookie/Authorization 就能 200 → `auth_or_guard_bypassed`（越权/未授权）。
- 状态相同但正文不同 → `same_status_different_body`（优先怀疑拿到了他人数据）。
- 完全一致 → `identical`（换凭证后仍一致 = 该接口根本没鉴权）。
- 顺带给出耗时差，作为延时盲注（`sleep 5`）的机械证据。

### 10.4 Agent 怎么用上它

0. **执行顺序由打法优先级决定**：一批工具请求入队前先按所属任务的 `playbook.priority` 排序（未授权 > 越权 > SQLi > 上传/RCE > 命令注入 > 反序列化 > SSRF > JWT > 云与供应链 > 逻辑 > GraphQL/WS > XSS），同优先级内保留模型原本顺序（`sortRequestsByPlaybook`）。模型会把低优先级的写在前面，执行层不会跟着跑偏。

1. 提示词里注入 `playbookIndex()`：每轮都能看到 12 条打法、步骤、确认条件和放弃条件。
2. `required_tasks[].playbook` 可声明绑定（`{id:"T3",playbook:"idor"}`），任务记录里持久化 `playbook` 字段。
3. 上下文里给 `playbook_hints`：对**尚未绑定**的未完成任务，按 target/purpose/reason 推荐 1–2 条打法（`recommendPlaybooks`）。
4. 报告口径写死在 playbook 的 `report` 里（泄露字段/条数、可操作角色、回显证据…），避免"信息泄露说不出泄露了什么"。
5. **覆盖账本** `checkpoint.playbook_runs`：每次工具调用按 `stepForTool()` 记到具体步骤，成功点亮该步骤，失败留 `last_error`。`playbookCoverage()` 汇总成"任务 x/y｜调用 n(ok/fail)｜步骤 k/m｜下一步 step_id｜最近失败原因"，既进上下文（`playbook_coverage`）也在每轮结束时落一条 `playbook-coverage` 事件与证据。这样"跑了几次、卡在哪一步"是查账，不是猜。

### 10.5 还没有的（外部流水线里有、我们缺）

| 缺的东西 | 影响 | 建议 |
|---|---|---|
| `http.race` 并发（Turbo Intruder 等价） | 逻辑漏洞里的并发领券/提现打不了 | 新增工具：N 个并发同请求，返回状态/条数差异 |
| `recon.takeover`（subjack） | 子域接管只能靠 nuclei takeover 模板 | 需要 subjack 二进制或用 nuclei 模板兜底 |
| `recon.cmdi`（commix 等价） | cmdi 目前靠手工 payload + OAST | playbook 已覆盖主要手法，可后补 |
| nuclei 模板分发 | 容器无 GitHub 出网，镜像里没有模板 → 扫描整体失败 | 模板放数据卷 `/opt/nianyun/data/nuclei-templates`，`recon.nuclei` 未指定时自动 `-t` 指向它（`NUCLEI_TEMPLATES_PATH` 可覆盖） |
| nuclei 单主机耗时 | 全量 15k 模板打一台主机在 300s 内跑不完 → 每轮都"超时且 0 条" | 默认只挂 `http/cves`、`http/vulnerabilities`、`http/exposures`、`http/cnvd`、`http/misconfiguration`、`http/takeovers`、`http/default-logins`、`http/exposed-panels`，并发 10 / 限速 30，模型可用 `params.templates`/`params.tags` 扩大 |
| 云 OSS 列举工具 | 目前用 `http.request` 直接打 REST | playbook 已给 URL 形态，够用 |
| 企业维度测绘（enscan） | ICP/APP/小程序/子公司拿不到 | 需要新 provider（有 API 才做） |
| 移动端（apktool/wxapkg） | App/小程序接口提取缺失 | 单独一条离线分析线，不进黑盒会话 |
| POC 脚本生成 | 报告只有步骤没有可跑脚本 | 报告阶段加 `poc.py` 模板生成 |

## 10.6 鉴权墙、执行器入参校验、完成语义（turn 47）

| 层 | 机制 | 落点 |
| --- | --- | --- |
| 识别 | `denialOf()` 只看 401、业务码（默认 `10403/10401/10402/401`）和鉴权短语；403/412 视为 WAF，不算墙 | `src/blackbox/authwall.ts` |
| 计数 | 以**请求自己的 URL** 为入口指纹（同路径不同参数算一个入口），同主机不同入口数达到 `auth_wall.streak_limit`（默认 3）即触墙 | authwall.ts + progress.ts `recordAuthDenial()` |
| 阻断 | 触墙后该前缀下的无凭证请求在 `begin()` 直接被拒（`auth_wall_requires_token`）；`/login`、`/sso`、`/token` 与带 `Authorization`/`Cookie`/`token` 的请求放行 | progress.ts |
| 换方向 | desk 注入 `auth_login_*`（jwt_auth）与 `auth_unauth_*`（unauth_exposure）两条任务 + 待处置建议，并把告警交给 Observer | desk.ts `injectAuthWallAdvice()` |
| 完成语义 | 任务结案证据全是被鉴权拒绝时，`completed` 被拒（`completion_on_denied_evidence`），任务转 `blocked` + `reason=blocked_by_auth` | progress.ts `merge()` + acceptance.ts 可自纠码表 |
| 入参校验 | `recon.secrets`/`recon.sast` 必须给 `input.path` 本地路径，URL 直接拒绝：`expected a local path, got URL` | tools.ts `localPathOf()` |

> 已知边界：墙的判定依赖响应体里出现鉴权码/短语；纯 403 WAF 页面不触发（这是刻意的，避免把 WAF 当鉴权）。`/api/*` 之外的路径仍可继续探测，这正是"找未授权入口"要用的空间。

## 11. 目前仍不理想的点（已知，未做）

1. ~~**建议积压**~~ **已修（turn 51）**：`supplement()` 落盘前按 `loop_control.advice_pending_limit`（默认 6）裁剪，最旧的 pending 归档为 `superseded`，不再把门禁卡在 `UNHANDLED_ADVICE`。
2. **引用纪律依赖提示词**：`evidence_ids` / `audit_ids` / `advice_id` 三类 id 混用仍会发生，只能靠提示词 + 拒绝明细纠正，没有自动纠错（自动纠错会掩盖证据问题，故意不做）。
3. **`assets` / `candidates` 两个既有测试基线**仍未修复（与本链路无关）。
4. **覆盖账本只有"步骤命中"，没有"步骤顺序"约束**：模型可以跳步（比如没跑 baseline 直接打 SQLi payload），账本会如实显示 `next_step` 但不会阻止它。要硬约束得在执行层拒绝乱序请求，会牺牲灵活性，暂不做。

## 12. 主 Agent 的自主性：它凭什么自己选工具（现状 + 实测）

### 12.1 自主的边界在哪里

没有任何规则引擎替它挑工具。每一轮的工具清单由模型自己写成 `tool_requests:[{tool,task_id,reason,input}]`，代码只做五件事：

| 层 | 代码 | 管什么 | 不管什么 |
|---|---|---|---|
| 协议 | `protocol.ts` `mainSchema` | 字段形状、枚举内工具名、`task_id` 必须存在 | 不评价选得对不对 |
| 排序 | `desk.ts` + `sortRequestsByPlaybook` | 一批请求按 `playbook.priority` 排队 | 只调顺序，不改它的选择 |
| 准入 | `progress.begin()` | 重试/重复/鉴权墙/任务终态才拦 | 空窗期不催、不代选工具 |
| 执行 | `tools.ts` | 参数校验（URL vs 本地路径、wordlist 根目录）、方法、超时 | 不替它补参数 |
| 监督 | `supervision.ts` + Observer | 语义事件、验收门禁、确认/驳回发现 | 只提建议，不改计划 |

所以它确实**有自主性**：96 个回合产生 86 次计划修订、192/193 个任务由它自己 `required_tasks` 声明、平均每回合 2.74 个工具（最多 9 个）。但自主不等于正确——下面这些数字是它的天花板。

### 12.2 它现在实际怎么挖（从 bdev.oppo.com 220 条 tool-result 还原）

```
① 入口面   burp.sitemap / katana.crawl / recon.js_endpoints / browser.open
            → 端点清单（本机 42 条 /api 路径）
② 匿名基线 http.request 无凭证逐条取 → status / body_bytes / body 指纹
            → 用 10200（有数据）vs 10403（TOKEN 错误）区分“可读面”与“鉴权面”
③ 指纹面   recon.nuclei（受限模板集）/ recon.cms / recon.tls / content_discovery
            → 命中 Spring Boot + Knife4j(doc.html) + Actuator（后者被 WAF 412 挡）
④ 参数面   recon.parameters → 对唯一可读接口做参数值矩阵
            → docType=0..10 / 数组注入 / 19 位溢出 / AND 1=1 vs 1=2（这一步现在会失控，见 12.3）
⑤ 认证面   POST /api/user/{login,register,getToken} + /api/user/captcha
            → 全 10403/10500：判定“要有 Token 才能过网关”
⑥ 确认面   http.diff（基线/变体结构化对比）+ recon.interactsh（OAST）+ burp.collab_*
⑦ 收口     task_outcomes 引自己的 tool-result → Observer 裁决 confirmed/needs_evidence/rejected
```

对应到打法库就是一条优先级队列：`unauth_exposure(1) → idor(2) → sqli(3) → upload_rce(4) → cmdi(5) → deserialization(6) → ssrf(7) → jwt_auth(8) → cloud_supply(9) → logic(10) → graphql_ws(11) → xss(12)`。实测走了 9 条（unauth 65 次、sqli 10、idor 6、deserialization 5、jwt_auth 4、xss 3、graphql 3、logic 2、cloud_supply 2），**upload_rce / cmdi / ssrf 一次没走**。

### 12.3 三个真实缺口：已修（turn 51）

原缺口（turn 48 的读数）与现在的机械保险一一对应：

| 缺口（原读数） | 现在怎么拦 | 阈值（可配置） | 落点 |
|---|---|---|---|
| **参数 fuzz 无熔断**：`/api/doc/folder/listAll` 31 次 / 19 种参数 / 只剩 7 种响应 | 按**路径**聚合调用次数、参数组合数、响应指纹数；产出速度掉到“每 3 次调用才 1 个新指纹”以下就熔断：任务直接 `blocked` + `reason=param_stall`，上下文出现 `param_stall` 块，时间线写 `param-stall` 事件 | `loop_control.param_stall_calls=5`、`param_stall_queries=3`、`param_stall_ratio=3` | `progress.ts` `recordParamWander()`、`context.ts`、`desk.ts` `reportParamStall()` |
| **POST 功能面从不枚举**：17 次 POST 全给 login/graphql，96 条 analysis 里“上传”出现 0 次 | 发现面够大（endpoints ≥ 10）却一条 POST 型打法（upload_rce/cmdi/ssrf/logic）都没跑过时，自动投递 `post_surface_*` 任务：比对 OPTIONS/405、从 JS/Swagger 找 `method:"post"` 与字段名 | endpoints ≥ 10 且四条 POST 打法 `calls=0` | `playbooks.ts` `postSurfaceTask()`、`desk.ts` `injectPostSurfaceTask()` |
| **建议积压**：18 条建议 15 条 pending，门禁卡在 `UNHANDLED_ADVICE` | `supplement()` 落盘前做上限裁剪：pending 超过上限就把最旧的归档成 `superseded`（保留最新的，不是删除；`superseded` 不计入门禁） | `loop_control.advice_pending_limit=6` | `progress.ts` `supplement()` |

**线上回放（部署后容器内用真实数据跑）**：

```
replayed: 37 条 listAll 结果（7 种响应体）
stalled at call#: 9        # 原流程跑了 31 次才停（靠预算耗尽），现在第 9 次就熔断
task: blocked param_stall
watch: {calls:35, queries:18, fingerprints:6, stalled_at:…}
post surface task: post_surface_20261024 :: 枚举 POST 功能面…   # endpoints=42、POST 打法全 0 时触发
```

#### 12.3.1 仍然存在的边界

- 熔断按**路径**聚合，参数在 path 里而不是 query 里（`/api/doc/86` vs `/api/doc/118`）时会被当成不同路径，不会熔断；这类“路径即 ID”的遍历靠 `repeat_limit` 也不管用，需要在 playbook 层用 `idor` 的 `swap_id` 步骤来约束。
- `post_surface_*` 只保证“任务被提出”，不保证模型一定去做：它仍是 pending 任务，靠优先级和上下文推着走。
- 建议上限会归档旧建议，Observer 若反复提同一条会再次出现（推进速度取决于模型是否按建议行动）。

### 12.4 给了它什么“意识”

| 输入 | 上下文里的样子 | 它据此做什么 |
|---|---|---|
| `playbook_hints` | 未绑定 playbook 的任务 → 推荐 1–2 条打法 | 给任务补 `playbook` 字段 |
| `playbook_coverage` | “unauth_exposure｜任务 61/102｜调用 65(ok 56)｜步骤 2/4｜下一步 diff_login” | 知道哪条打完了、卡在哪一步 |
| `auth_wall` | `blocked_prefixes` / `guidance` | 停遍历、转登录或未授权入口 |
| `retrieved_evidence` | 它自己点的 `evidence_queries` 结果 | 回看旧证据，不重跑 |
| `observer-review` / `advice` | 待处置建议 + 理由 | 用 `advice_decisions` 逐条回应 |
| `stopReason` / `budget_warning` | 剩余预算 | 收口还是继续 |

结论：**该调什么工具由它自己决定，而且确实在按“证据 → 下一步”推进**（86 次计划修订里绝大多数是“收口上一批 + 补三条新探测”）。它缺的不是“意识”，是三个机械保险：参数级熔断、POST 面兜底枚举、建议老化。

### 12.5 落地状态

| 优先级 | 改动 | 状态 |
|---|---|---|
| P0 | 参数级熔断 `param_stall` | **已落**：`param_stall_calls/queries/ratio` + `recordParamWander()` + 上下文块 + `param-stall` 事件 |
| P0 | POST 面兜底任务 | **已落**：`postSurfaceTask()` + `injectPostSurfaceTask()`，幂等（已有 `post_surface_*` 就不再投） |
| P0 | 建议上限 | **已落**：`supplement()` 裁剪到 `advice_pending_limit`，旧建议 `superseded` |
| P1 | 推荐信号升级（Swagger/JS 的 method+字段名、响应里的对象 id） | 待做：`recommendPlaybooks` 目前仍只看 URL/notes 字符串 |
| P1 | `unauth_exposure` 降权（pending > 8 时降优先级） | 待做 |
| P2 | 步骤顺序硬约束（乱序请求在执行层拒绝） | 待做，会牺牲灵活性 |

## 13. 四项升级：认证链、冒烟校验、评分倾斜、联动兜底（turn 52）

### 13.1 P0 跨工具认证链 `auth_token`

10403 死锁的根因不是"找不到登录接口"，而是**只用一种工具打**：`http.request` 拿不到 token，`browser.open` 拿到了也没人把它交给 HTTP。解法是把两件事写进同一本 playbook。

| 步骤 | 工具 | 干什么 |
|---|---|---|
| `login_page` | `browser.open` | 打开登录/SSO 页，`evaluate` 抓表单 action 与字段名 |
| `submit_login` | `browser.open` | `actions` 填账号密码 + 点提交；无表单时改用 `evaluate` 直接 fetch 登录接口 |
| `capture_token` | `browser.open` | `evaluate` 读 `localStorage`/`sessionStorage`/`document.cookie` |
| `replay` | `http.request` | 把 token 放进 `headers.Authorization` / `Cookie`，重打之前 10403 的接口 |
| `business` | `http.diff` | 匿名 vs 带 token 结构化对比，确认进了业务数据层 |

- 优先级 **2**（仅次于 `unauth_exposure`），全套 13 本：`unauth_exposure(1) → auth_token(2) → idor(3) → sqli(4) → upload_rce(5) → cmdi(6) → ssrf(7) → deserialization(8) → jwt_auth(9) → cloud_supply(10) → logic(11) → graphql_ws(12) → xss(13)`。
- `recommendPlaybooks` 新增触发词：`10403/10401/未登录/token 错误/token失效/unauthorized`、`/login`、`/sso`、`/oauth`、`gettoken` → 直接推荐 `auth_token`。
- 鉴权墙注入的任务（`auth_login_*`）从 `jwt_auth` 改绑 `auth_token`，完成条件是"拿到可用 Token 并让一个原本 10403 的接口返回业务数据"。
- 主 Agent 提示词加了一行硬要求：遇到 10403 不要换 URL 重试、不要只试一次 login 就收工，必须走完 浏览器取 Token → 带 Token 重放 → diff 确认。

**线上验证（新会话 `e12d3b4e80faeabb`，目标 bdev.oppo.com）**：

```
tasks: T1(unauth_exposure) T2 T3(auth_token) post_surface_… burp_scan_…
playbook_runs: auth_token:1[login_page]      # 模型自己选了这条链并点亮第一步
browser.open evaluate → {"href":"…/open/home","cookie":"username=…","ls":[],"ss":[]}
```

> 未完成的部分（如实记录）：跑到 `login_page` 之后模型又回到 `http.request` 刷匿名接口，`capture_token/replay/business` 没走完。原因是该站 `/open/*` 匿名就返回 200，没有墙推着它继续。链是通的，跟进意愿仍需靠鉴权墙/任务压力触发。

### 13.2 P1 冒烟校验（preflight）

`checkBlackboxEnvironment` 只证明"网络通、Burp 通"，不证明"工具能干活"。新增 `src/blackbox/preflight.ts`：

| 检查项 | 做法 | 硬拦？ |
|---|---|---|
| 12 个 CLI 二进制 | `NUCLEI_PATH/TRUFFLEHOG_PATH/…` 探活（8s 超时，`-version`/`--help`） | 否（缺失时执行器原本就会报 `${ENV}=…`） |
| nuclei 模板 | 目录存在且能在 3 层内找到至少 1 个 `.yaml` | **是**（装了但空 → 跑起来也是 0 命中） |
| Chromium | `chromium.executablePath()` 存在性 | 否（路径检查会误伤系统 Chrome / mock） |

- 触发点：`checkProjectBlackboxEnvironment` 之后写一份进 checkpoint；run 开始时若有就直接灌进执行器缓存；没有则在**第一批工具执行前**懒跑一次（没有工具调用的回合不花这 1-2 秒）。
- 同一套配置 60s 内只真跑一次（双 worker 并发抢同一 review 不会各探活一遍）。
- 执行器闸门：`executeBlackboxTool` 开头 `toolBlockedReason(tool)` → `rejected: <tool> unavailable (preflight): …`，且不计费。
- 上下文给 `preflight` 块：不可用工具 + guidance，模型不必再用回合撞墙。

**线上读数**：容器内 13 项全绿 —— `nuclei/trufflehog/semgrep/graphql-cop/wpscan/katana/ffuf/sqlmap/dalfox/testssl/naabu/subjs` 可执行、Chromium 就绪（`chromium-1187`）、nuclei 模板目录非空；新会话第一个工具批前落了一条 `preflight` 事件"冒烟校验通过：13 个工具可用"。

### 13.3 P2 评分权重倾斜（`asset-page-v2`）

`DEFAULT_ASSET_RULE` 从"识别页面"/`asset-page-v1` 换成按**可挖掘性**打分（`ASSET_RULE_VERSION = asset-page-v2`）：

| 加分项 | 分值 |
|---|---|
| `/api/`、`/graphql`、`/rest/`、`/v1~v3/`、swagger、api-docs、doc.html、actuator、druid、nacos | 80-100 |
| 登录/认证/SSO、注册、找回密码 | 85-100 |
| 管理后台、用户中心、订单/支付/退款、上传、导入导出 | 80-100 |
| 带 `?id=`、`?userId=`、`?orderId=`、`?file=` 等查询参数 | 75-95 |
| 纯静态页、Vue/React 空壳、CDN 资源、404、默认 nginx 页 | 0-25 |

理由：黑盒阶段的产出几乎全来自"有参数、有接口、要权限"的页面；静态营销页进去只能烧爬虫预算。

### 13.4 P3 OAST / Burp 联动兜底

两条"不投就永远漏"的动作改由代码兜底（`playbooks.ts` 纯函数 + `desk.ts` 每批注入）：

| 兜底 | 触发条件 | 任务 |
|---|---|---|
| `oastRequiredTask` | `cmdi/ssrf/deserialization` 的 `calls > 0` 但 `recon.interactsh` 从未成功执行 | `oast_required_*`：先 start 拿回调域名，回填进参数，再 poll 确认 |
| `burpScanTask` | 爬虫（`katana.crawl`/`burp.sitemap`）跑过、`endpoints ≥ 5`、`burp.scan` 从未执行 | `burp_scan_*`：对已发现入口跑扫描并逐条复核 issues |

判定依据是 `checkpoint.tool_calls`（每工具成功执行次数，`finish()` 维护），幂等（已有同名任务不再投）。

**线上验证**：新会话里两条都真实触发 —— `post-surface`（25 条入口、POST 打法全 0）、`linkage-burp`（爬虫已产出入口但没扫过）各投递一条任务。

### 13.5 测试与边界

| 项 | 结果 |
|---|---|
| 新增用例 | `test/auth-linkage.test.ts`（7 条：链顺序、推荐规则、OAST/Burp 幂等、preflight 空模板/有模板、评分规则） |
| 全量 | 313 条：311 通过，2 条失败仍是既有的 `assets` / `candidates` 基线 |
| 边界 | `auth_token` 只把"该走的路"写进上下文与优先级，模型仍可能停在第一步（见 13.1）；preflight 不拦"没装"只拦"装了用不了"，避免把测试/临时环境的链路提前掐死 |

### 13.6 `post_surface_*` 从建议变强制（turn 53）

13.4 的兜底只做到"任务被投递"，它仍然是 `pending`，模型可以一直不打它。这一节把它变成硬约束：**两轮不派活就上锁**。

| 层 | 机制 | 落点 |
|---|---|---|
| 记账 | 投递 `post_surface_*` 时写 `checkpoint.linkage.post_surface = {task_id, ignored_turns:0}` | `desk.ts` `injectPostSurfaceTask()` |
| 计数 | 每批 tool_requests 落队前检查：有没有 `task_id` 等于该任务 → 有则清零，没有则 `ignored_turns += 1` | `desk.ts` `watchPostSurface()` + `progress.ts` `tickPostSurface()` |
| 提权 | `ignored_turns >= 2` → `checkpoint.exclusive_task = <id>`，任务标 `reason=exclusive_until_done`，写 `post-surface-escalate` 事件 | `progress.ts` |
| 执行 | `begin()` 对非排他任务返回 `exclusive_task:<id>` 拒绝（不计费、不改任务状态）；`auth_token`/`jwt_auth` 与 `auth_` 前缀任务放行 | `progress.ts` `begin()` |
| 解锁 | 排他任务 `completed/blocked/failed` 时自动清锁，写 `exclusive-release` 事件 | `progress.ts` `finish()` + `desk.ts` |
| 提示词 | 运行时规则写死：存在 `post_surface_` 未完成任务时，下一批必须至少一条归属它，否则两轮后被上锁 | `agent.ts` |

**踩到的坑（已修）**：最初 `begin()` 的通用分支会把被拒任务写成 `blocked`，于是提权期间被拦的 `T1` 在解锁后永久停在 `task_blocked`。现在排他拒绝走 `transient` 分支——只拒绝、不改状态：

```
other T1 -> blocked:exclusive_task:post_surface_… | its status stays: pending   # 修复前是 blocked
after release: lock = undefined | other T1 -> allowed
```

**线上验证（部署后的真实 checkpoint，容器内）**：

```
miss 1: {"ignored_turns":1,"escalated":false}
miss 2: {"ignored_turns":2,"escalated":true}
lock: post_surface_20261024120457
other T1 -> blocked:"exclusive_task:post_surface_20261024120457"（status 仍是 pending，不计费）
post_surface 自身 -> 放行
after completion -> 锁清空，T1 恢复可执行
```

另有一条真实 run 的读数：会话 `e12d3b4e80faeabb` 被种入 `ignored_turns=1` 后重新开跑，模型的**第一批**就带上了该任务的请求（`linkage.post_surface.ignored_turns` 从 1 回到 0），说明提示词那条硬规则本身已经在阻止逃避；硬锁是它失效时的兜底。

> 边界：`tool-request` 事件里只记 `{evidence_id, tool}`，没有 `task_id`，所以"这一批服务了哪个任务"只能通过 `linkage` 计数与 `tool-result` 归属间接核对；要不要把 `task_id` 写进事件属于可观测性改动，暂未做。

### 13.7 RESTful 归一化：让"路径即 ID"的遍历也能被熔断（turn 54）

`param_stall` 按请求 URL 聚合时，`/api/doc/86` 和 `/api/doc/118` 是两个不同的请求身份，于是换成路径里的 id 遍历就绕过了熔断。修法是在算指纹之前先归一化。

| 步骤 | 规则 | 例 |
|---|---|---|
| 路径段 | 纯数字 → `{id}`；UUID → `{uuid}`；≥16 位 hex → `{hex}` | `/api/doc/86` → `/api/doc/{id}`；`/api/user/<uuid>` → `/api/user/{uuid}` |
| 聚合键 | `host + 归一化路径` | `bdev.oppo.com/api/doc/{id}` |
| 响应体 | 抹掉**本次路径里被替换的原始 id**、任意 UUID、ISO 时间、≥10 位长数字 | id 86 与 118 的两份正文落成同一指纹 |
| 变体计数 | 原始 pathname 进 `variants`（上限 20），路径 id 变化与 query 变化同等看待 | 5 个 id → `variants=5` |
| 熔断条件 | `calls ≥ 5` **且**（`queries ≥ 3` 或 `variants ≥ 3`）**且** `指纹数 × 3 ≤ calls` | 5 次 / 5 变体 / 1 种指纹 → 熔断 |

新增配置：`loop_control.param_stall_variants`（默认 3）。落点：[urlnorm.ts](src/blackbox/urlnorm.ts)（`normalizePath` / `normalizeBody`）+ [progress.ts](src/blackbox/progress.ts) `recordParamWander()`；上下文 `param_stall` 块与 `param-stall` 事件都带上变体数。

**线上验证（部署后的真实数据）**：

```
real requests: 237 | path-id shaped: 3
   GET /api/doc/content/86 -> /api/doc/content/{id}
   GET /api/doc/detail/86  -> /api/doc/detail/{id}
keys: bdev.oppo.com/api/doc/{id}          # 5 个不同 id 落到同一个 key
stalled at call#: 5 | calls: 5 variants: 5 fingerprints: 1
task: blocked param_stall
```

> 边界：占位符按**段**判断，`/api/doc/v2/86/detail` 能归一化；`/api/report-86.pdf` 这种"id 粘在文件名里"的段不归一化（刻意，避免把静态资源名当动态 id）。正文掩码是字面替换：若正文别处恰好出现同一个数字也会被抹掉，属可接受的误伤——结果只会更容易熔断，不会更松。

### 13.8 异常现象利用 / 重定向陷阱 / 战术参谋 / 跨域 JS / 工具 Fail-Fast（turn 56）

五项一起改，主线是同一件事：**目标给出的"异常"本身就是攻击面，不能当成"打不动了"。**

| # | 问题 | 落实 | 落点 |
|---|---|---|---|
| 1 | 只会按 playbook 顺序跑，不会因异常改战术 | 连续 3 条**不同路径**命中同一跳转目标或同一响应长度 → `anomaly_alert`，调度器立刻派 `host_header_injection_*` / `open_redirect_*` / `takeover_check_*` 三条任务（分别绑 `unauth_exposure` / `logic` / `cloud_supply`），写 `anomaly-exploit` 事件 | `blackbox/anomaly.ts` + `progress.recordAnomaly()` + `desk.observeToolResult()` |
| 2 | HTTP 客户端吞掉 301，POST 被降级成 GET | `http.request` **默认不跟随重定向**：返回原始 301/302 + `data.location` + `redirect_not_followed:true`；显式 `follow_redirects:true` 才跟，且只有 303 才降级方法，301/302 保留方法与 body | `blackbox/tools.ts` `httpTool()` |
| 3 | Observer 只会查账 | 新增 `TACTICAL_OBSERVER_RULES`（置于用户 Prompt 之前）：识别到全站 301 / 统一 10403 / WAF / OSS 直链 / catch-all / 跨域 SDK 时，禁止"统计性核验/补齐账本"类建议，必须给至少 1 条可执行 Bypass；机械侧再加 `observer-low-signal` 事件记录"有信号却零打法"的审查 | `blackbox/agent.ts` + `desk.ts` |
| 4 | JS 里的跨域 SDK 被当噪音 | `recon.js_endpoints` 结果里的非主域 host 进 `checkpoint.cross_domain`，身份类（id/auth/login/sso/passport/account/api）走 `auth_token`、其余走 `unauth_exposure`，写 `cross-domain-asset` 事件 | `playbooks.crossDomainTasks()` + `desk.observeToolResult()` |
| 5 | nuclei 反复 0 结果烧预算 | 连续两次 0 产出（`findings`/`items` 皆空）→ `tool_health[tool].disabled`，`begin()` 之后一律返回 `tool_disabled:<tool>`（不计费、不污名任务），写 `tool-disabled` 事件 | `progress.recordToolHealth()` + `begin()` |

**线上验证（部署后容器内真实请求 bdev.oppo.com）**：

```
PROBE /           status=301 location=https://bdev.oppo.com/            followed=no
PROBE /index.html status=301 location=https://bdev.oppo.com/index.html  followed=no
PROBE /open       status=301 location=https://bdev.oppo.com/open        followed=no
ANOMALY none            # 每条 301 的目标都带自己的路径 → 不是 catch-all，正确地不报警
PROBE /no-such-a/b/c 三条同样是 301 到各自路径 → ANOMALY none
FAILFAST disabled=true begin={"blocked":"tool_disabled:recon.nuclei"} T1=running
```

catch-all 命中路径由调度级用例覆盖（[anomaly-scheduler.test.ts](test/anomaly-scheduler.test.ts)）：本地起一个 302 到固定 `https://sso.example.test/login` 的服务，模型连打 `/a /b /c` → 会话里出现 `anomaly_alert.kind=catch_all_redirect`、`anomaly-exploit` 事件、以及三条利用任务（`takeover_check_*` 绑 `cloud_supply`）。

**踩到的两个坑（已修）**：

- 统一响应体阈值：最初只要 3 条同长度就报警，结果 `200 ok`（2 字节）这种空壳把正常扫描判成 catch-all，连带 19 个既有用例失败。现在要求 `body_bytes >= 256`。
- `reviewVersionOf` 把 `target_host` 算进状态版本，而它在运行开始时才补写 → 已排队的 Observer 审查被判"旧快照"，18 个用例回退到"先跑主 Agent"。现在 `target_host` 按非执行事实排除在版本之外。

> 边界：catch-all 只覆盖"同主机、3 条不同路径、同一 3xx 目标或同一 ≥256 字节正文"。跳转目标各自带路径（bdev 的 http→https 升级就是这种）不算 catch-all——那只是协议升级，不是路由收敛。

### 13.9 Playbook 调优六项（turn 59）

| 优先级 | 问题 | 落实 | 落点 |
|---|---|---|---|
| P0 | 有洞但推荐不出对应 playbook | 正则扩充：RESTful 路径 id（`/api/doc/86`、`/users/alice`、`{id}`、`:id`）、JSON Body 的 id 字段、更宽的鉴权失败语义（403/not logged in/signin/MFA/passport）、`next=`/`return_url=` 归 ssrf、`oss-cn-*` 归 cloud；同时把 endpoints 键与 findings 也喂进推荐器 | `recommendPlaybooks()` + `context.playbookHints()` |
| P0 | 单账号环境 IDOR 跑不通 | `idor` 步骤改为 `own_resource → baseline_self(自比对排除噪音) → shift_id(id±1 盲猜) → diff_auth → vertical`，confirm 只认 `diff_auth` 且要求差异在 baseline 里不出现 | `PLAYBOOKS` idor |
| P1 | sqli 上来就打 `' and 1=1`，WAF 秒封 | 改为 `arith_probe(2-1 无引号)→ diff_arith → quote_probe(单引号探错) → time_probe(SLEEP(2)) → sqlmap(level1/risk1/BEU) → blind_oast`；新增"同端点连续 2 次 WAF 拦截即停手" | `PLAYBOOKS` sqli |
| P1 | auth_token 撞验证码/MFA 死循环 | 新增 `gate_probe`（登录页里 evaluate 出 captcha/mfa/sso/slider 布尔量），命中即把认证任务判 `blocked`（`reason=auth_gate:<kind>`）并写 `auth-gate` 事件；stop 里写明"同一账号连续两次失败即停手" | `PLAYBOOKS` auth_token + `progress.recordAuthGate()` + `desk.observeToolResult()` |
| P2 | 缺 CORS 污染探测 | `unauth_exposure` 新增 `cors_probe`(带 `Origin: https://evil.example`) 与 `cors_verify`(http.diff 证明是反射不是固定值)，confirm.must_show 增加 ACAO 反射 + Allow-Credentials 分支 | `PLAYBOOKS` unauth_exposure |
| P2 | 异常利用任务只发一次包就结案 | `anomalyTasks` 三条的 completion_criteria 全部写明必须给 http.diff；执行层再加硬挡：`host_header_injection_*`/`open_redirect_*`/`takeover_check_*` 结案时若无 `http.diff` 证据 → 打回 `pending`，issue `ANOMALY_REQUIRES_DIFF` | `anomalyTasks()` + `progress.merge()` |

**线上验证（部署后容器内）**：

```
RESTful 数字 id -> idor          JSON body id -> idor
403 语义 -> auth_token           MFA -> auth_token          OSS 主机 -> cloud_supply
unauth_exposure: probe_sensitive > baseline_anon > diff_login > render > cors_probe > cors_verify
auth_token:      login_page > gate_probe > submit_login > capture_token > replay > business
idor:            own_resource > baseline_self > shift_id > diff_auth > vertical
sqli:            arith_probe > diff_arith > quote_probe > time_probe > sqlmap > blind_oast
```

> 边界：`gate_probe` 的识别依赖登录页里能 evaluate 到结构（有表单/DOM），纯跳转式 SSO 只会命中 `sso` 分支并直接判 blocked；`shift_id` 盲猜只在"相邻 id 同权限域"时有效，跨租户 id 段会返回 404，此时结论应是"不可越权"而不是继续枚举（枚举由 param_stall 与 tool 预算双重约束）。

### 13.10 四个方向升级（turn 60）

#### 方向 1：Playbook 从线性链进化为状态机图

`PlaybookStep` 新增三个可选字段：`next?: string[]`（后继节点）、`when?: string`（分支条件）、`concurrency?: number`（并发扇出）。**不设 `next` 的 playbook 行为完全不变**，所以 13 条老 playbook 不需要迁移；一旦某条 step 带 `next/when/concurrency`，`playbookIndex()` 会额外渲染一段「图模式打法」，把节点和箭头显式写进提示词，主 Agent 看到的是图而不是 1→2→3。

新增 playbook `race_condition`（优先级 12，插在 logic 与 graphql_ws 之间，总数为 14）：

```
baseline → lock_state → fanout(burp.send_batch)×20 → diff_effect → confirm_repeat
lock_state ［条件：前置失败就回 baseline 换目标］
```

关键约束写进了 prompt 与 playbook：竞态只能用 `burp.send_batch` 一次扇出，**串行 for 循环打 20 次不算竞态、不能当证据**；扇出后必须 `http.diff` 证明资源被消耗多次。

#### 方向 2：业务逻辑从「改价格」改成「画流程图 + 乱序/省略重放」

`logic` playbook 整体重写：

```
map_flow(burp.history) → replay_normal → skip_step → tamper_state → reorder → diff_effect
```

- `map_flow`：先把一条完整链路（领券→下单→支付→发货）的接口顺序和字段名抄出来；
- `skip_step`：省略中间步骤，**不付钱直接调发货/确认收货**——这是改 price 改不出来的洞；
- `tamper_state`：参数污染（多塞 `status=paid` / `step=4` / `paid=true`），服务端采信客户端状态才算；
- `reorder`：乱序重放（先确认收货再取消订单）；
- `diff_effect`：用 http.diff 证明服务器状态真的进入非法态。

文案层面也钉死了口径：`改前端 price/amount` 不再作为打法出现（后端会重算），`confirm.must_show` 明确写「只接受客户端改 price/status 的回显不算」。

#### 方向 3：路由模板提取（彻底解决 slug 型 RESTful 漏判）

`normalizePath()` 只认数字/UUID/hex，`/api/users/alice` 与 `/api/users/bob` 会各算一条路径。新增 `routeTemplate(pathname, memory)`：

| 规则 | 说明 |
|---|---|
| 动态学习 | 同一 parent 前缀下同一位置出现 **≥2 个不同取值** 才折叠成 `{pN}`；单次请求永远折叠不动 |
| 命名空间保护 | 第 0/1 段（`/api`、`/static`、`/v2`）永不折叠，否则 `/static` 与 `/api` 会被当成「同位置两个取值」而合并 |
| 路由词保护 | `list/detail/export/upload…` 与静态文件后缀不折叠 |
| 计数迁移 | 折叠发生时，把同 stem、同深度的旧原始路径记录（calls/queries/variants）迁到模板键下 |
| 指纹不迁移 | 折叠前的指纹天生带路径噪音，迁进来会把 1 种真实形状算成 2 种，直接顶掉熔断阈值 |
| 正文掩码 | 该位置见过的**所有**取值都进 `normalizeBody` 的掩码表，保证形状一致 |

#### 方向 4：攻击面降级（Plan B / 横向逃逸）

`progress.recordHostBlock()` 统计单 host 被拦次数（WAF 特征：403/406/429/503 + `waf|拦截|blocked by|cloudflare`；鉴权特征：401/403），**累计 3 次** → `state.lateral_escape`。`desk.observeToolResult()` 据此派 `lateral_escape_<stamp>` 任务并写 `lateral-escape` 事件，任务内容就是三条替代路径：

1. `recon.subdomains` 找同族子域；
2. 旧版本接口（从 `endpoints` 里扫出的 `/v1/` `/v0/` 直接带进任务，没有就试 `/v1/`、`/v0/`、`/internal/`）；
3. 移动端前缀 `/api/app/`、`/api/mobile/`、`/app/`；
4. 有跨域资产时顺带把 top-2 挂上 `crossDomainTasks`。

prompt 里同步加了「不要继续在原 host 上换参数或编码绕过」的硬口径，避免模型把 Plan B 当成换个 payload 继续撞。

**线上验证（部署后容器内实跑，镜像 部署时间 2026-10-24T22:3x）**：

```
TEMPLATE: /api/users/alice | /api/users/{p3} | /api/users/{p3}
STALL:    {"path":"h/api/users/{p3}","calls":5,"fingerprints":1,"variants":4} | task: blocked param_stall
ESCAPE:   {"host":"bdev.oppo.com","hits":3} | kinds: {"bdev.oppo.com":{"hits":3,"kinds":["waf"]}}
RACE:     baseline→lock_state lock_state→fanout fanoutx20→diff_effect diff_effect→confirm_repeat
LOGIC:    map_flow > replay_normal > skip_step > tamper_state > reorder > diff_effect
```

> 边界：路由模板是**运行时学习**的，一条路径如果只被访问一次，永远不会折叠（这是刻意的：单次访问既无法判断它是变量也无法判断它是路由名）。竞态 playbook 只允许一次扇出、成功一次即停手，不做批量放大；Plan B 只在同 host 被拦 ≥3 次后触发一次，不做无限扩散。

### 13.11 P0：http.diff 的"散光"修复（turn 62）

**问题**：`diffResponses` 只看 `status / body_bytes / similarity`，时间维度只输出不判定；相似度是单词级 5-token shingle 的 Jaccard，中文没有空格时整段退化成一个 token，相似度只有 0/1 两档。结果是 `sleep(5)` 与正常请求被判 `identical`，sqli/cmdi 两条线永远拿不到确认证据。

**改法**：判定核心整体搬到新文件 `src/blackbox/diff.ts`（`tools.ts` 只做再导出，旧 import 不变），四层判定：

| 层 | 规则 | 输出 |
|---|---|---|
| 时间 | `\|duration_delta_ms\| >= timing_threshold_ms`（默认 2000，可按调用覆盖）且正文无实质差异 → `timing_delta` | `timing: { suspect, threshold_ms, delta_ms, ratio }` |
| JSON | 解析成对象树，递归剔除 `timestamp/requestId/traceId/spanId/nonce/random/elapsed/_t…` 噪音键，再比键集合与取值 | `shape.json: { same_structure, changed[{path,baseline,variant}], added, removed, noise_removed }` |
| 文本 | 含中日韩 → 字符 3-gram Jaccard；纯西文 → 保留 5-token shingle；两者都不再是唯一判据 | `shape.metric: char3gram / token5shingle / json_structure` |
| 长度兜底 | `bytes_ratio > 0.2` 且不是"JSON 仅噪音差异" → 直接 `different`，跳过文本计算 | `delta.bytes_ratio` |

**verdict 词表**（新增 `timing_delta`，其余语义不变）：

```
identical     无实质差异（允许噪音键不同）
same_shape    结构/形状一致但取值不同 —— 越权、布尔等值、数据变化都在这里
different     状态、长度或结构显著不同
timing_delta  正文相同、耗时超阈值 —— 时间盲注 / 命令注入的唯一可用证据
```

**Playbook 同步**：`sqli.time_probe` 从 `http.request` 改成 `http.diff`（一次调用同时打正常与 `SLEEP(2)`，`timing_threshold_ms: 1800`），`sqli.confirm.evidence` 加入 `time_probe`；`cmdi.diff_time` 同理加阈值参数并进入 `confirm.evidence`。主 Prompt 增加 verdict 词表与「看到 timing_delta 就算确认成立」的口径。

**线上验证（部署后容器内，喂真实库里的 10403 body）**：

```
TIMING:    timing_delta | suspect: true | delta_ms: 5000 | similarity: 1
           timing_delta：正文无实质差异但耗时差 5000ms（阈值 2000ms）——时间盲注/命令注入的执行证据
JSON:      same_shape | metric: json_structure | noise_removed: 2
           changed: [{path:data.用户名, 张三→李四}, {path:data.手机号, 138…→139…}]
NOISE:     identical                （只有 timestamp/traceId 变化）
CJK:       token5shingle = 0.0000 | char3gram = 0.9231 | verdict = same_shape
LENGTH:    different | bytes_ratio: 0.3 | length_delta：长度差 30%（>20% 直接判不同）
REEXPORT:  tools.js 再导出可用，旧 import 不受影响
```

**用例**：新增 `test/diff-structured.test.ts`（11 条：时间维度 3、JSON 结构化 4、中文与长度兜底 3、状态语义 1）；`test/http-diff.test.ts` 里那条「sleep 5 秒仍判 identical」的旧断言按新语义改成 `timing_delta`；`test/http-diff-tool.test.ts` 增加端到端一条（本地 stub 服务 sleep 400ms，走真实工具链，断言 `verdict=timing_delta`、`summary` 含「时间维度异常」、证据落库）。

> 边界：`timing_threshold_ms` 有 200ms 下限，低于它的抖动一律不算；耗时包含 TCP/TLS 建连，跨地域代理下建议显式把阈值调到 3000 以上；`timing_delta` 要求正文无实质差异，若正文也变了则仍判 `different`（先解释数据变化，再看耗时）。

### 13.12 P0：Token 传递的"神经阻断"修复（turn 63）

**问题**：`http.request` 只认 `headers.Authorization`，模型把 `{"url":..., "token":"eyJ..."}` 写在顶层时被静默忽略——服务端继续 10403，日志里看不出任何线索，`auth_token` 链路永远走不通。这是 API 设计问题，不是 Prompt 问题。

**改法一：入口协议宽容层**（`src/blackbox/authinput.ts` → `normalizeAuthInput`，在 `httpTool` 入口原地改写 `input`）：

| 模型写法 | 执行器行为 |
|---|---|
| `token / jwt / access_token / accessToken / id_token / auth_token / bearer` | 转 `Authorization`；JWT 形态自动补 `Bearer `，已写 `Bearer xxx` 原样保留，裸串按原样发 |
| `headers.authorization` 已存在 | 不覆盖，`auth_applied` 里注明"被忽略" |
| `cookies` 对象 / 数组 / 串、`cookie_jar`、`cookieJar` | 合并进一个 `Cookie` 头（不覆盖显式 Cookie） |
| 被消费的字段 | 从 input 删除：满足严格校验，且 token 不进证据账本 |

转换结果写入 `data.auth_applied`（形如 `token → Authorization: Bearer eyJhbG…bHVl`），summary 里也带一段，**让"自动转换发生过"这件事在轨迹里可见**。

**改法二：全局凭据罐**（`project_tokens` 表 + `getTokenForHost` / `mergeProjectTokens`）：

- `browser.open` 执行后扫描 evaluate 结果（含 JSON 字符串形态）与页面链接/表单，捞出 JWT 形态的值，按 host 写入罐子，summary 显示「已捕获 N 个 Token 进全局罐」；
- 之后任何 `http.request` / `burp.request` 只要没显式写 Authorization，就按 host（含父域后缀匹配）自动挂上；`data.auth_applied` 显示「全局 Token 罐命中 <host>」；
- 等效于"Burp 里登录一次，后面所有发包自动带凭证"，不需要模型每轮手抄 token。

**必须存在的逃生口**：罐子装满后所有请求都会带凭证，未授权/绕过类证据就再也没法发匿名请求了。因此 `http.request` / `http.diff` 支持 `anonymous: true`（等价 `no_auth: true`、`use_jar: false`）：跳过全局 Cookie/Token 罐，只发显式传入的凭证。`unauth_exposure` 的 `baseline_anon`、`diff_login` 已按此改写，`http.diff` 会把匿名开关透传给基线（否则基线也会被罐子污染）。

**部署期副作用（已修）**：`Dockerfile.fast` 的 `npm ci` 依赖 registry；本机容器网络当前访问不到 `registry.npmjs.org` 与 `registry.npmmirror.com`（`ECONNRESET`），而 BuildKit npm cache mount 被清后无法重建，导致镜像构建直接卡死。处理：

1. 去掉 `Dockerfile.fast` 里的 `--mount=type=cache,target=/root/.npm`（该 mount 在 Docker Desktop/WSL2 上会报 `Exit handler never called` / `mount options is too long`）；
2. 新增 `deploy/control/Dockerfile.layer`：复用已有运行时层，只 `COPY` 本地 `npm run build` 产物（`.dockerignore` 排除了 `dist` 与 `console/spa`，所以用 `.layer-out` 作 staging context）。网络恢复后仍用 `Dockerfile.fast` 做完整构建。

**容器内实测（9 点，本地 stub 服务 + 真实工具链）**：

```
[1] normalizeAuthInput → {"Authorization":"Bearer eyJ…"}，token 字段已删除
[2] captureTokens(evaluate JSON 字符串) → ["access_token"]
[3] 顶层 token 实发 → {"code":0,"data":{"userId":86}} | auth_applied: token → Authorization: Bearer eyJhbG…bHVl
[4] 罐子自动挂（模型完全不传凭证） → {"code":0,…} | auth_applied: 全局 Token 罐命中 <host>
[5] anonymous:true 强制匿名 → {"code":10403,"msg":"TOKEN 错误"} | 跳过全局 Cookie/Token 罐
[6] http.diff 匿名基线 vs 带 token → different，相似度 0（状态 200→200）
[7] unauth_exposure 匿名步骤 → baseline_anon, diff_login
```

**用例**：`test/auth-input.test.ts`（9 条：别名/JWT 补 Bearer/不覆盖显式头/cookie 三种形态/JSON 字符串解析/噪声串过滤）、`test/auth-jar.test.ts`（5 条端到端：顶层 token、罐子命中、父域后缀匹配、`anonymous` 逃生口、罐子装满后的 diff 匿名基线）。全量 **378 通过 / 2 失败**（既有 assets、candidates 基线），`tsc` 0。

> 边界：罐子按 host 存，跨域（`id.oppo.com` 发的 token 打到 `bdev.oppo.com`）不会自动串用，需要显式传；token 在库中以明文存于 `project_tokens`，与 `project_cookies` 同等敏感度——备份/导出时按凭据处理。

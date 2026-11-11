# Nianyun 端到端验证报告（8700 Docker AI 环境）

> 目的：把焦点释放契约的修正真正编译进 `nianyun:control` 镜像、重启 8700 控制台、对一个真实 AI 会话实跑，验证「焦点只钉任务、只在该任务结案后释放、绝不靠轮数定时器松手、也不让 agent 散开」。

## 0. 焦点释放契约（用户最终意图，本次验证的准绳）

用户明确纠正了初版设计：

> 「我设置焦点的初衷是防止 agent 分散注意力，导致它东跑一下西跑一下。应该深入挖掘后，再对任务 T 判断是否存在漏洞和继续深挖的价值；没有这些就结案给出 finding，让 agent 继续下一个任务。」

据此，**正确的契约是**：

1. `forced_focus` 一旦锁定某任务 T，**持续钉住**——无论过了多少轮，只要 T 还没进入终态（completed/blocked/failed），焦点就一直锁在 T 上，其它任务的请求被拒收。
2. 只有当 agent 对 T 给出**结案 verdict**——有洞→写 finding 并标 completed；无洞/无价值→带证据引用的负面结案标 blocked/failed——焦点才释放，顺延到下一个任务。
3. **绝不能靠「轮数到了就 delete forced_focus」松手**：那会让任务还没结案就解锁，agent 立刻散开「东跑西跑」。
4. 收口保险：`focus_convergence` 在连续无增益（`stall_rounds=3`）或预算耗尽（`max_turns=8`/`max_tp=50`）时逼 agent 出 verdict；若 agent 无视，主循环代码兜底**强制标 blocked**，不会永久死锁，也不会散开。

## 1. 构建与部署过程（踩坑记录）

- **目标镜像**：`nianyun:control`（compose 项目 `nianyun-control`，服务 `nianyun`）。
- **官方构建失败**：`docker compose -f compose.control.yaml build nianyun` 在 `RUN npm ci` 步骤稳定失败（`npm error Exit handler never called!`）——本机 Docker overlayfs 上 npm 的已知 flake，与代码无关。
- **稳定绕过方案（宿主机编译 + 注入式构建）**：
  1. 宿主机 `npm run build` → 产出 `dist/` 与 `console/spa/`；
  2. 用 `deploy/control/Dockerfile.inject`（`FROM nianyun:control` + 仅 COPY `dist/` 与 `console/spa/`，**不动 `bin/` 避免 CRLF 复发**）打出新镜像覆盖 `nianyun:control` 标签；
  3. 构建上下文用 trimmed 目录（只含 `dist/` + `console/spa/` + `Dockerfile.inject`），绕过 `--ignorefile` 不被 buildx 支持的坑。
- **CRLF 二次坑**：注入构建若把 CRLF 版 `bin/nianyun` 拷进镜像，容器崩溃循环 `/usr/bin/env: 'bash\r': No such file or directory`。注入式构建不碰 `bin/`，从根本上规避。
- **保留运行配置**：`data` 是命名卷 `nianyun-control-data`，重建不丢数据；AI 变量来自数据卷内运行时 `tools.env.yaml`（compose env 里 `BLACKBOX_AGENT_*` 为空，属正常）。
- **结果**：新容器 `running/healthy`，8700 正常，项目 `p_06db586d65`「Ledger」资产 / 会话完整保留。

## 2. 代码改动（已编译进镜像，容器内 grep 确认）

- `src/blackbox/focus.ts`
  - **删除** `DEFAULT_FORCED_FOCUS_ROUNDS`（轮数定时器常量）；
  - 改写 `computeFocus` 的 `forced_focus` 分支：去掉 `if (forced.rounds >= cap) 释放` 的定时器释放逻辑，直接返回锁定；`forced` 类型去掉 `rounds?`/`max_rounds?`；
  - **新增** `forcedFocusReleased(state)`：任务缺失或已终态时返回 true，供主循环显式 `delete state.forced_focus`，清除残留、避免误导操作员。
- `src/blackbox/progress.ts`：`forced_focus` 类型精简为 `{ task_id, kind, at, note? }`（去掉 `rounds`/`max_rounds`）。
- `src/blackbox/focus-budget.ts`：`convergenceFor` 文案改为逼出 verdict 契约——① 有洞→写 finding + `task_outcomes` 标 completed；② 无洞/无价值→`task_outcomes` 标 blocked/failed 带证据引用负面结案；明确「焦点锁不靠轮数松手」。
- `src/control/console/desk.ts`
  - SPA 缴械设置点去掉 `rounds:0, max_rounds:4`，note 改为「焦点不会因轮数松手，你必须真的逆出结论才切下一个任务」；
  - **删除**主循环的定时器释放块，替换为：`forcedFocusReleased(state)` 为真时 `delete state.forced_focus`（数据卫生）。
- **单测**：
  - 新增 `test/focus-release-verdict.test.ts`（5/5）：非终态持有强制焦点、终态后顺延下一任务（FIFO）、SPA `spaHint` 含 `browser.open`、残留 `rounds` 字段不触发释放、`forcedFocusReleased` 三类判定。
  - 更新 `test/focus-value-budget.test.ts`：断言新文案 `结案 verdict` / `task_outcomes`（原脆弱的 `focus_stalled` 字面量断言已替换，`reason` 字段校验保留）。

## 3. 端到端验证（会话 `7a51d4458a5959c0`，m.ctrip.com，重建镜像后）

从事件流 + 数据库 `checkpoint_json` 双重取证：

- `[system/spa-disarm]` 判定 m.ctrip.com 为 SPA 外壳，生成任务 `T_SPA_REVERSE_86274664`；
- **4 次 `focus-lock`（`reason: forced`）** 把焦点钉在 `T_SPA_REVERSE_86274664`，期间多次 `focus-appeal` 被拒（「焦点契约不变，记账等下一轮计划自行切换」）；
- **`forced-focus-released` 事件 = 0**（轮数定时器释放已被彻底移除，全程无此事件）；
- `focus-convergence` 触发于 `reason: focus_stalled`（「连续 3 轮没有高价值证据」，即 `stall_rounds=3`，**不是**轮数定时器）；
  - 第一轮 `focus_stalled` 给 agent 收口机会 → agent 未自行 verdict；
  - 第二轮 `focus-convergence`「强制收口：模型未在下一轮结…已由控制面标 blocked」（`forced: true`）——代码兜底强制标 `blocked`；
- 焦点随后落到 `T1`（`reason: sticky`），再推进到 `H_idor_47aed713`——**agent 继续下一个任务，没有散开**。

**数据库硬证据（验证 `forcedFocusReleased` 清理）**：

| 会话 | 代码版本 | `state.forced_focus` 字段 |
|---|---|---|
| `d5ab7a0d67497fb6`（旧：轮数定时器） | 旧 | **存在且残留** `{"task_id":"T_SPA_REVERSE_85645493",...}`（任务已结案仍留着，误导操作员） |
| `7a51d4458a5959c0`（新：仅 verdict 释放） | 新 | **不存在**（`forced_focus present?: False`） |

> 这正是新增 `forcedFocusReleased` 的意义：任务终态后把 `state.forced_focus` 字段显式清掉，不再残留误导。

**结论**：焦点释放契约全部满足——钉住深挖、只靠 verdict 释放、无轮数定时器、无散开、字段干净。

## 4. 实测中发现并修复的副作用：Sandbox 崩溃导致「无法深挖」

本会话里 `T_SPA_REVERSE` 之所以「连续 3 轮没高价值证据」，除了收敛判定外，还有一个**环境病灶**：

- `nianyun-control-sandbox-1` 一直在 `Restarting`——日志报 `SANDBOX_TOKEN is not configured`；
- 于是 `browser.open`（走 sidecar sandbox 的 Playwright）被 `tool-rejected: dead_end` 拒绝，SPA 逆向这条最需要浏览器的路径**根本跑不起来**；
- agent 被迫退回 burp.history / recon.js_endpoints / evidence.read 等控制面工具，自然挖不深。

**修复**（本地 dev/test 盒子的官方逃生通道，错误日志本身即提示）：在 `compose.control.yaml` 的 `sandbox` 服务加

```yaml
SANDBOX_ALLOW_ANON: "true"   # 本地无 token 时免密连 sidecar；生产务必配真实 token 并删此行
```

`sandbox/server.ts:133` 的授权逻辑：`!cfg.token` 时直接返回 `cfg.allowAnon`，所以控制面空 token 也能连通。重建 sandbox 后 `Up (healthy)`、`listening on :8790`，控制面即可真正下发浏览器/执行类工具。

> 注意：本会话是在 sandbox 修复**之前**跑的，所以「收敛强制 blocked」在一定程度上是被环境逼的，而非 agent 主动判定无价值。sandbox 修好后**应重跑一次干净 e2e**，才能公正评估 agent 的真实深挖能力。

## 5. 干净 e2e（sandbox 已修）结论：契约稳，但 agent 仍是「观察者」而非「猎手」

会话 `bf18c0b103878839`（m.ctrip.com，sandbox.reachable=true，浏览器/exec 可用）回答两个问题：

**(a) 焦点契约在「agent 真能挖」时依旧只 verdict 释放 —— ✅ 确认**
- `spa-disarm` → `T_SPA_REVERSE_87140441` 被 **5 次 `focus-lock`（`reason: forced`）** 钉住（t=154→229），`focus-appeal` 全拒；
- **`forced-focus-released` 事件 = 0**（无轮数定时器释放）；
- `focus-convergence` 以 `focus_stalled`（4 轮 / 0 TP）触发，agent 未自行结案 → 控制面兜底强制 `blocked`；
- 焦点落到 `T1` → 再推进 `H_idor_47aed713` / `H_object_enum_0458205c`——无散开；
- DB 复核：`state.forced_focus` 字段 `present: False`（已被 `forcedFocusReleased` 清掉）。

**(b) agent 是否「猎手式」深入？—— ⚠️ 部分：散开已修，但「观察-复述」循环仍在，零 finding**

对比旧报告「每轮从零规划、零进展」：本次**有改善**——中后段分析开始**跨轮引用既有证据**（`ev-f74a96291fede194` 外壳 200、`ev-9a4dd2eae48af06f` 的 authwall/waf_suspected/static_response 信号链），说明 forced 焦点锁迫使它留下来积累了证据，不再原地重排计划。

但距「猎手」仍差三步，且正是卡点：
1. **观察信号却不升级**：burp.history 已给出 `waf_suspected`（`/swagger-resources` 6 条 403/406/429，响应体均为 30B 同一拦截页）、`authwall`（5 条连续 403）、`static_response`（`sw.js` 固定 30514B）——这些是 WAF 指纹 / 疑似 Swagger 暴露的强信号，agent 却只在每轮**复述**它们，未对任何一条做主动验证（如探 `/swagger-resources` 是否真暴露、试 WAF bypass）；
2. **零 finding**：全会话 DB 无 finding 落库（此前统计里的 "findings" 仅是分析文本里的「不写 findings」字样，属误报）；
3. **不结案**：`T1` 在 t=334 又触发 `focus_stalled`（5 轮 / 25 TP，这次是真用了工具），即将被强制 `blocked`——带着一堆观察、没有 verdict。

根因仍是旧报告点名的「假设—验证—链式深入」缺失：agent 当前是**证据收集型观察者**，不是**验证—利用型猎手**。焦点锁修好了「东跑西跑」，但没修好「挖不深」。

## 6. 结论与下一步

| 项 | 状态 |
|---|---|
| 焦点释放契约（删轮数定时器、仅 verdict 释放、字段清理） | ✅ 两次 e2e 稳定通过 |
| Sandbox 崩溃导致无法深挖 | ✅ 已修（`SANDBOX_ALLOW_ANON=true`） |
| 干净 e2e：契约在 sandbox 上行时依旧稳 | ✅ 通过（`bf18c0b103878839`） |
| agent「散开」问题 | ✅ 已解决（forced 焦点钉住 + 仅 verdict 释放） |
| agent「猎手式」深挖（验证 + 利用 + 结案 / 写 finding） | ❌ 仍缺失：观察者循环，零 finding |

**下一步最高优先级（超出焦点契约，是真正的能力缺口）**：
1. **逼出 verdict / finding**：收敛或每轮校验层加硬约束——若本轮引用了既有证据却既不产出新动作也不写 finding，则要求本轮回合必须 (a) 对一条信号做主动验证（exploit/bypass 探针），或 (b) 用 `task_outcomes` 带证据引用结案（completed 写 finding / blocked 写负面结案）；否则判 `stalled` 直接转操作员。
2. **信号→动作映射**：把已识别的强信号（waf_suspected、authwall、static_response、sw.js 固定长度）接成「下一步该打什么」的动作建议注入 prompt，避免只复述不行动。
3. **finding 落库门槛**：agent 声明任务 completed 时，必须同时写入至少一条 finding（含证据引用），否则不允许标 completed——防止「标完成但无产出」。

## 7. 强制变更 ①②③ 落地后的干净 e2e（会话 `20770876a584cbc1`，m.ctrip.com）

按上一节三条「下一步」实现了三项强制变更并编译进 `nianyun:control`：

- **① 建议强制处置**（`focus-budget.ts`）：`pendingIgnoredAdvice()` 读 `state.advice` 中 `status=pending && misses≥1` 的条目；当连续无进展轮达到 `stall_rounds-1` 且存在未处置建议时提前 1 轮收敛并把 advice id 点名进收敛理由。
- **② 信号→动作映射**（`signal-actions.ts` + `context.ts`）：把 `waf_suspected` / `authwall` / `soa2_exception_echo` 三类强信号映射成「下一步该打什么」的 `context.signal_actions`，`agent.ts` 规则要求每轮对信号动作「执行探针或显式放弃」。
- **③ finding 硬门槛**（`progress.ts`）：`VULN_PLAYBOOKS`（17 个漏洞确认打法）标 `completed` 时必须有一条 finding（本轮/历史）覆盖本任务证据，否则 `completion_without_verdict` 拒绝、任务退回 pending；交付/侦察/未知打法豁免。

**运行结果（891 事件，71 工具调用，36 agent turn，2.29M token，27 分钟，`stopReason=validation_failed_review_required`）**：

| 验证点 | 证据 | 结论 |
|---|---|---|
| ① 建议被处置而非忽略 | 3 条 `advice` 事件；`adviceDecisionResults` = 2 条 `status: applied`；关键建议（review-833ee5bf）指出「T2 其实已完成、sourcemap 探测是确定性重复、fs.read 路径两次被拒、必须先取 WAF wall_fp」 | ✅ 采纳并转化为新任务 |
| ② 信号→动作 | `waf-escalation`（marker=`waf-blockblocked by envoy waf` → 建 `waf_bypass_20261102034908`）、`lateral-escape`（hits 6）、`post-surface`（discovered 15 条 /api 路径）、`exec.python` 抽 bundle（chunks 15/15、soa2=6、appid=4） | ✅ 不再只复述，转为主动探针与建任务 |
| ③ 空标 completed 被拦 | `post_surface_20261102034912`（unauth_exposure）多轮被拒：`COMPLETION_WITHOUT_VERDICT` → 后续 `TASK_EVIDENCE_INVALID` + `CLOSURE_DELIVERABLES_UNMET`；任务始终退回 pending | ✅ 门槛真实生效 |
| 焦点契约 | 13 次 `focus-lock`（5 次 forced 于 `T_SPA_REVERSE`）、`forced-focus-released` 事件 = 0、6 次 convergence；forced 持续 5 轮后仅因 forced-block 释放，再 sticky 到 T1→H_idor | ✅ 无轮数定时器释放 |
| 安全收口 | 校验未过 → `supervisor-pause`（`state_validation_failed`，`unhandled_advice:1`，reason_codes 含 `VALIDATION_ERRORS_REMAIN`/`UNHANDLED_ADVICE`），转操作员而非伪造完成 | ✅ 宁可转人工也不假结案 |

**与基线 `bf18c0b103878839` 对比**：基线 537 事件、建议全被忽略（review-stale 8+、0 采纳）、仅观察复述、零 finding；本次 891 事件、**2 条建议 applied**、产生 `waf_bypass`/`post_surface`/`lateral_escape` 任务、抽到 15 条真实 /api 路径与 6 条带真实 appid 的 SOA2 路径、③ 拦下假结案。**行为确已从「观察者」向「猎手」迁移。**

**仍未闭合的缺口（诚实记录）**：本轮 findings 仍为 0。agent 已经挖到有价值的真实事实（`/restapi/soa2/{appid}/{action}` 匿名 POST 可达、`createclientid` 返回 200 且含 ClientID、`queryCookieBWList` 200），但未能把这些事实打包成通过 `validateFinding` + 验收的 finding，于是 ③ 拒绝把它判成 completed，运行以「转操作员」安全收尾。也就是说：**挖得动、也守得住底线了，但「把事实收口成可复核 finding 并给出正面 verdict」这最后一公里仍未打通。** 这正是下一步要解决的能力缺口（而非纪律问题）。

---

## 8. 谓词层上线后的干净 e2e（会话 `b9601629efd1f137`，2026-11-02）

目标仍是 `https://m.ctrip.com/`，用于验证「P0-1 图污染 / P0-2 环境摩擦 / 谓词 + vuln_gaps」三件事是否真的改变行为。

**运行结果：12 轮 / 12 次工具调用 / 7 分钟 / 512k token / 0 finding，`stopReason=required_review_pending`；完成 0、失败 0、受阻 1、未执行 7。**

### 8.1 三条验证项

| 验证点 | 实测证据 | 结论 |
|---|---|---|
| **http.diff 占比** | 6 次 `http.request` : 3 次 `http.diff` = **2:1**（基线 50:4 = 12.5:1）。且性质变了：`/` 的 302→200 匿名/渲染对照（`verdict=different`）、`/swagger-resources` 匿名 vs 带凭证（`verdict=identical`，正是 `unauth_exposure` 需要的形状） | ✅ 占比与质量双改善（基线是「同 URL 自比 + 两个不存在的 appid 互比」） |
| **vuln_gaps 注入** | 用线上真实会话数据跑 `boundedContext()`：`vuln_gaps` 键存在，内容为 `T3` 与 `T_SPA_REVERSE_97204841` 两条 `unauth_exposure`，`missing` = 「匿名请求返回<400」「响应正文里的真实敏感数据」 | ✅ 已注入且可执行 |
| **vuln_gaps 被消费** | T3 一条请求都没发 | ❌ 未消费（run 在 12 轮提前停止，见 8.3） |
| **finding 谓词门槛** | 本场无漏洞任务尝试 `completed`；实际触发的是 `CLOSURE_DELIVERABLES_UNMET`(T1) | ⚠️ 未被执行到（未验证，非通过） |

### 8.2 P0-1 图污染修复在本场失效（真缺口，已修）

`H_idor_47aed713`、`H_object_enum_0458205c` **仍从 `z9probe_notexist/{id}` 派生**。

根因链：`z9probe` 来自 **`burp.history`**（该结果摘要："模板 22 个"）。Burp history 跨会话共享，上一场自己造的探测路径本场被当作「发现的端点」重新入图——节点 `properties = {status_code:404, origin:"link", hits:2}`、`status=untested`、**无正文**。而 `route_missing` 只在「本次真打过、有正文」的路径上由 `routeMissingOf()` 计算，被动发现路径**从不计算**（`desk.ts:2934-2943` 只带 `status_code`）→ 门恒不命中。

**修复**：`graph/hypotheses.ts` 新增 `cannotLocateObject()`，判据 = `route_missing` **或**（`origin≠"request"` 且 `status_code ∈ {404,410}`）；`activeHypotheses()` 同步撤下。保守边界：`origin="request"` 时仍交给正文判据，不误杀「大正文软 404」。`builder.ts` 同时把 `requested:true` 规范化为 `origin:"request"`，否则两者无法区分。

### 8.3 本场暴露的两个结构性冲突（未修，待决策）

1. **`dead_end` 与谓词互斥**
   T1 的 `http.diff` 被 `tool-rejected: dead_end` 拒收，原文：「ep:m.ctrip.com/html5 已在历程图标为死胡同（同一请求已重复 5 次（响应未变化））」。谓词要求「对同一端点做对照」，`dead_end` 要求「永不再碰这个端点」——两条规则直接打架，且 `dead_end` 是硬拒收（不计费、不给证据）。
2. **纸面采纳建议 → 提前停（`required_review_pending`，仅 12 轮）**
   两次 `protocol-error`（`output_tokens` 顶格 8000、`validation_errors: ["summary: expected string, received undefined"]`）之后，主 Agent 的应对是**一轮发 0 个 `tool_requests`**，把 advice 标 `status: accepted`（`task_ids:["T1","T2"]`），理由原文：「本轮 tool_requests 压到 0 条以规避协议再次失败」。desk 门禁随即判定 `openAdvice=0` 且终审未过期 → `keepGoing=false` → 停止。
   → 「采纳建议」目前只需**指一个已存在的任务 id**，不需要真的执行它。

**同轮已顺带修掉的两个放大项**：`protocol.ts` 的 `summary` 改为 `.default("")`（摘要缺失只丢叙事，不连累本轮工具动作）；`agent.ts` 默认 `maxTokens` 8000 → 12000（上限仍 16000）。

### 8.4 本轮验证后的回归

`graph-route-missing`（13）、`graph-wall-repeat`(10)、`graph-rank-hypothesis`(11)、`vuln-predicates`(13)、`hunter-enforcement`(11)、`attack-graph`(25)、`graph-candidates`(6)、`graph-discovery`(11)、`blackbox-acceptance`(10)、`focus-release-verdict`(5)、`focus-value-budget`(20)、`advice-autoskip`(8) → **143 项全绿**；`tsc --noEmit` 干净；`nianyun:control` 重建重启，`/health=200`，容器内 `cannotLocateObject` / `origin` 规范化 / `summary` 默认值 / `maxTokens=12000` 全部在位。

### 8.5 结论

谓词层确实改变了**取证形态**（diff 从 12.5:1 到 2:1，且从自比变成真对照），`vuln_gaps` 也确实进了上下文。但**本场产出仍是 0**，原因不再是「不会验证」，而是三层叠加：`dead_end` 硬拦验证动作 → 协议截断吃掉回合 → 纸面采纳建议换取提前停止。**下一优先级应改 8.3 的两条，而不是继续加纪律。**

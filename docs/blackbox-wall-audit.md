# 黑盒（BlackBox）挖掘能力墙 · 拆除评审

> 结论先给：这套墙里**只有 5 条在控制真实风险**，其余 20 多条都在控制"成本"和"模型的判断失误"，而且实现方式选错了——它们把"一次误判"变成"永久失去能力"。拆的方向不是把阈值调大，而是**把不可撤销的硬门禁换成可撤销的提示，把按 run 计的预算换成按会话计的目标**。

---

## TL;DR

1. **最高优先级不是改阈值，是改 run 的存活方式**。`desk.ts:1745` 在 run 结束时把会话置 `paused`，等人工重启；`budgets.wall_clock_sec=1800` + `agent_turns=24` 意味着每 30 分钟/24 轮就断一次。SRC 深度挖掘的时间尺度是小时到天，这套循环方式决定了你永远只能做浅扫。
2. **`budgetMode` 有降级死锁**：判据拿"整条 playbook 的时间盒（600–1500s）"比"整次 run 的剩余墙钟（1800s）"。跑 sqli（时间盒 1500）时，**300 秒后永久 fast**，sqlmap 再也不会被放行。这是纯逻辑 bug。
3. **参数熔断会杀死盲注**：指纹只看 `status + body`，时间盲注的 body 100% 相同 → 1 种指纹 → 5 次调用后任务 `blocked`。而 playbook 自己写着"时间盲注要发几十上百次"。内置打法与内置熔断互相矛盾。
4. **鉴权墙的计数发生在放行判定之前**：打 `.env` / `/actuator` / `/swagger` 各一次 401，这三条本该放行的探测会把 streak 推到 3，于是**正在找未授权入口的任务被判 `blocked_by_auth`**。自己堵自己。
5. **`preflight` 之外还有一条更贵的墙没被列入**：`findings.ts` 要求证据 URL 与 `finding.target` 的 `href` **字符串完全相等**，重定向/尾斜杠/参数顺序任一不同就让整条 finding 被 rejected。

---

## 一、判断标准：哪些墙该保留

| 类别 | 特征 | 处置 |
|---|---|---|
| **R 类 · 真风险** | 不可撤销的外溢：打到 scope 外、破坏被测业务数据、给出一条挂着的 shell | 保留，只做可用性优化 |
| **C 类 · 成本** | 花钱/花时间，但不会造成外部损害 | 放大 + 改成"续跑"，不要设成能力上限 |
| **M 类 · 模型纠错** | 防止 LLM 重复、误判、自嗨 | **降级为提示**，保留证据，不设永久门禁 |

现在的问题是 M 类全部被实现成了硬门禁：`blocked` / `failed` / `disabled` 是**终态或会话级**的，一次误判就永久丢失一个能力。而 LLM 误判恰恰是常态——用终态去惩罚可撤销的错误，是把噪声控制写成了能力上限。

一条可用的判据：**如果这个动作的后果可以撤销（换参数重打一次），它就不该有硬门禁；如果后果不可撤销（写了数据库、打了别人资产），才值得硬拦。**

按这条判据：`-u/--host` 目标覆盖、7 方法白名单、请求/响应体积上限、写操作一次性、`--os-shell/--eval` 永久禁止 = 该保留。其余全部可以松。

---

## 二、四个结构性缺陷（改阈值治不好）

### 缺陷 1 · 降级死锁（`weights.ts:126-139` + `desk.ts:842,1314`）

```ts
// weights.ts:129
if (window.wallMsLeft > 0 && timeboxMs > 0 && window.wallMsLeft < timeboxMs) {
  reasons.push(`墙钟只剩 Xs，放不下 Ys 的完整时间盒`);
}
```

`timeboxSec` 取的是**待推进 playbook 的时间盒**（`desk.ts:842`，`Math.min(...)`，范围 600–1500s），`wallMsLeft` 是**整次 run 的剩余墙钟**。两者不是同一量纲：

- run 总墙钟 1800s，sqli 时间盒 1500s → 跑满 300s 后 `wallMsLeft < 1500` 恒成立 → `mode="fast"` 永久；
- `desk.ts:1314` 把 `allowHeavy` 绑在 `mode==="full"` 上 → **sqlmap / nuclei / katana 在本 run 余下 1500 秒里一次都跑不了**；
- `deserialization` 的第一步就是 `recon.nuclei`，600 秒后这条打法直接失效。

`Math.min` 让它更糟：只要有 `jwt_auth`（600s）这类短时间盒任务挂着，全局按 600 判，等于**最紧的那条打法绑架所有打法**。

**修法**：判据换成"剩余墙钟是否够一次重型步骤"，时间盒只做提示。

### 缺陷 2 · 参数熔断的盲注盲区（`progress.ts:682,717-727`）

```ts
const fingerprint = hash({ status: Number(data.status || 0), body });
const stalled = watch.calls >= calls && varied && watch.fingerprints.length * ratio <= watch.calls;
if (stalled) { ...; status: "blocked", reason: "param_stall" }
```

时间盲注：`?id=1` / `?id=1' AND SLEEP(5)-- -` 两次响应 **body 完全相同**，只有耗时不同 → 指纹恒为 1 种 → `1*3 <= 5` 成立 → 5 次调用后任务 `blocked`。

对照 `playbooks.ts:180`（sqli 的 `blind_script` 步）："时间盲注要发几十上百次带 sleep 的请求并逐字符二分"。**系统会在自己的打法跑到第 5 次时把它判死。**

同类误伤：越权遍历（换 id，响应结构相同）、状态机试探（改 status，响应同构）。

**修法**：① 指纹纳入耗时分桶（`<300 / <1000 / <2500 / ≥2500ms`）；② 熔断只发 interrupt，不置 `blocked`。

### 缺陷 3 · 鉴权墙自己堵自己（`authwall.ts:120-147` + `progress.ts:733-751`）

`recordAuthDenial` 先 `trackDenial(...)` 累加 streak，而放行通道（`safe_path` / `unauth_playbook` / `explicit`）**只在已经 tripped 之后的 `wallVerdict` 里才被检查**（`progress.ts:811`）。

于是：一次 `unauth_exposure` 任务打 `/.env`（401）、`/actuator/env`（401）、`/swagger-ui.html`（401）→ 三个不同入口 → `urls.length >= 3` → 触发墙 → 该任务被 `recordAuthDenial` 立刻置 `blocked_by_auth`。

**三条"放行通道"在墙触发的那一刻不生效，因为它们正是把墙推起来的燃料。**

**修法**：放行判定提前到计数之前，命中通道的请求不进 streak。

### 缺陷 4 · "鉴权拒绝"与"负向结论"不可区分（`progress.ts:243-251`）

```ts
const denial = completionDenial(evidence, task, references, ...);
if (denial.deniedOnly && denial.evidence > 0) { status: "blocked", reason: "blocked_by_auth" }
```

一条任务如果**一致地证明**了"该入口鉴权正确、无数据可越权"，它的全部证据必然都是 401/403——这在 `denialOf` 眼里与"发了个请求被拒"完全同形。结果是：**最有价值的负向结论（排除项）被判为受阻**，而 `acceptance` 里 `blocked` 与 `failed` 同样计入"未完成"，报告只能写"部分完成"。

这会反向激励 agent：为了拿到"completed"，它会倾向于把"疑似"写成 `finding`。**这是所有墙里唯一会主动降低报告质量的。**

**修法**：当一个任务的 playbook ∈ `{auth_token, unauth_exposure, jwt_auth, idor}` 且 evidence 一致为拒绝时，判 `completed` + `verified_negative`，不算阻塞。

### 附：缺陷 5 · 证据 URL 精确比较（`findings.ts:20-22`）

```ts
return new URL(url).href === new URL(finding.target).href;
```

`http.request` 拿到的往往是 `http://t/api/doc/86`，而 `finding.target` 可能写 `http://t/api/doc/86/`（尾斜杠）、`http://t/api/doc/118`（越权时 target 与被引用响应本来就不是同一个 id）、或被重定向后的规范化 URL。任一不同 → 整条 finding `rejected`，且报错信息只说"必须引用该目标成功的原始工具结果"，agent 无从自查。

**修法**：host 相等 + pathname 归一化（复用 `urlnorm.normalizePath`）后比较。

---

## 三、逐墙系数表

### A. 执行前置墙

| 墙 | 现值 | 建议 | 判断 |
|---|---|---|---|
| `execution.mode` 总开关（`execution.ts:19`） | 必须 `execute` | **保留** | 这是"进程能力"开关，不是 agent 能力开关；`inspect/serve` 有明确用途。 |
| preflight 硬拦（`preflight.ts:142`→`tools.ts:2622`） | 模板空/二进制不在即 `unavailable` | 保留，但**只对"配置错误"生效** | 现状已基本正确（二进制不存在不硬拦）。补一条：模板目录为空时给 tool-result 带一次性提示"`recon.nuclei` 模板缺失，改用 http.request 手工验证"。 |
| 工具名白名单（`tools.ts:2620`） | 73 项 | 保留 | 白名单本身没问题，问题是它与 `protocol.ts:94-107` 的 enum **是两份手写清单**。加工具漏改一处 = 工具存在但模型调不了。**改法**：`z.enum(BLACKBOX_TOOL_NAMES)`。 |
| 参数形状校验（`2625-2630`） | `params/args/actions` 按工具白名单 | 保留 | 这是在防止模型"以为设置了其实没设"，语义正确。 |
| CLI 永久禁止（`216-232`） | `--os-shell/--sql-shell/--os-pwn/--eval/--code` | **保留** | 给的是"挂着的交互 shell"，自动化无法记账；真要 RCE，`--os-cmd` 一次就够。 |
| CLI 交互参数（`235-239`） | `--os-cmd/--sql-query/--file-read/--file-write` 需 `BLACKBOX_ALLOW_INTERACTIVE_EXEC` | 改为**规则文档开关**（`tools["recon.sql"].allow_interactive`） | 现在是环境变量，改一次要重启进程；放进 rules 文档可以按会话开。 |
| 目标覆盖参数（`-u/-l/--host`） | 禁 | **保留** | 唯一真 R 类。 |
| `-w` 字典必须落在 `recon.wordlists` 根 | 强制 | 保留 | 防止读任意本地文件。 |
| `-t` 模板必须落在 template 根 | 强制 | **放宽**：允许目录内相对路径与纯 tag 表达式（不含 `/`） | 现在 `-t sqli` 这种 tag 会被当路径校验，nuclei 的 tag 过滤用不了。 |
| `--proxy/-x` 改写成内部 MITM | 强制 | 保留 | 留痕需要。 |
| `exec.*` 沙箱 `timeout_s` | **5–300s**（`workspace.ts:503`） | **5–900s** | 协议层 `protocol.ts:31-32` 已允许 900，`mcp.ts:61` 只允许 300，`workspace.ts` 又 clamp 到 300——三处不一致，模型看到 900，实际被静默砍成 300。深挖一条链（5000 次签名枚举）300 秒必然不够。 |
| `trivialPassthrough`（`routing.ts:73`） | 裸调 CLI / 单发 requests 被 reject | 保留，但 `barePythonHttp` 只拦"单发" | 现状已有 `force_sandbox` 逃生门，语义正确。 |

### B. 单条请求准入墙（`progress.ts:801-843` `begin()`）

| 墙 | 现值 | 建议 | 判断 |
|---|---|---|---|
| 鉴权墙 streak | 3 | **10** | 3 个不同入口被拒就判墙，对"API 全部要 token"的 SPA 是常态而非异常。配合缺陷 3 的修法。 |
| 鉴权墙计数通道 | 不辨通道 | **先判通道，命中不计数** | 见缺陷 3。 |
| 预算降级 | 时间盒判据 | **改判据**（见缺陷 1） | 逻辑错误。 |
| 权重降级阈值 | `weightLeft < 20` | **`< 5`** | 20 权重 = 4 次扫描就提前降级；权重真正耗尽会自然停，不需要提前 20 步刹车。 |
| 排他任务（POST 面） | 忽略 2 轮即提权为唯一任务 | **4 轮**，且豁免已 confirm 进度的任务 | 2 轮太急，认证链刚打通 Token 就被打断。 |
| 工具熔断 | 连续 2 次 0 产出 → **会话内禁用** | **不禁用**，只发 interrupt + 保留 detail | nuclei 默认模板打不到目标太常见。真正的刹车是权重。`begin():826` 的 `tool_disabled` 分支随之失效。 |
| 重复 `repeat_limit` | 2 | **3** | 报告需要复现两次；2 次就把"复测"判成重复。 |
| 重试耗尽 `task_retry_limit` | 2（+1） | **3**（+1） | 失败 3 次才 failed。注意：改 payload 会变 identity，不累加失败，所以这条主要影响"同请求连续失败"。 |
| 参数熔断 | 5/3/3/ratio 3 | **40/12/12/ratio 25** | 见缺陷 2；只靠调参只能缓解，必须改指纹。 |
| 死胡同 `dead_end` | 图标记后拒打 | 保留（有 `bypass_dead_end`） | 语义正确。建议把 `bypass_dead_end` 写进 runtime rules 让模型知道。 |
| 任务终态 | `completed/blocked/failed` 后同 task_id 不再执行 | 保留，但**在 text 规则里明说"补充验证要新建 task_id"** | 否则模型会反复撞同一个门。 |
| `max_redirects` | 5 | **10** | OIDC/SSO 链常见 6–8 跳。 |
| `max_timeout_ms` | 60000 | **180000** | 时间盲注 + 慢接口。 |
| `max_body_bytes` | 256KB | **2MB** | SPA 首屏 JSON 常超 256KB，截断后 `http.diff` 的 `same_shape` 判定会失真。 |
| `max_output_bytes` | 2MB | **8MB** | `fs.read` / 扫描输出。 |
| 方法白名单 | 7 个 | **保留** | R 类。 |

### C. 完成 / 结案墙

| 墙 | 现值 | 建议 | 判断 |
|---|---|---|---|
| `invalid_task_transition`（`progress.ts:272`） | 必须给 `outcome_reason` | 保留 | 合理。 |
| 完成必须有成功证据（`241`） | 强制 | 保留 | 这是报告可信度的地基，不能动。 |
| `completion_on_denied_evidence`（`245`） | 一律 `blocked_by_auth` | **区分 verified_negative** | 见缺陷 4。 |
| `anomaly_requires_diff`（`254-264`） | Host 注入/开放重定向/接管必须 `http.diff` | 放宽为"`http.diff` **或** OAST 回连" | 有些跳转类只需 Host 头对照，一份 diff 太重；而盲打类本来就只有 OAST 证据。 |
| `acceptance` 四道闸 | TASKS_NOT_TERMINAL / VALIDATION_ERRORS_REMAIN / EVIDENCE_INTEGRITY_FAILED / TERMINAL_REVIEW_PENDING | 保留 | 结案闸。但 `TERMINAL_REVIEW_PENDING` 因为 Observer 每 5 次调用就被唤醒，会反复把 `reviewPending` 置真 → 长 run 收不了尾。配合下面的 observer 频率一起改。 |
| `validateFinding` | 必须引用同目标成功 tool-result | 保留校验，**放宽 URL 比较** | 见缺陷 5。 |

### D. 监督墙

| 墙 | 现值 | 建议 | 判断 |
|---|---|---|---|
| 预算 ≥80% 告警 | 保留 | 保留 | 只是 warning。 |
| Observer 触发频率（`supervision.ts:86`） | `toolCalls % 5 === 0` | **`% 20 === 0`** | 600 权重下每 5 次 = 120 次 observer 调用，token 成本可能与主 agent 同量级。这条墙在偷预算。 |
| Observer 重试 | attempts ≤ 2 | 保留 | 合理。 |
| `stall_batch_limit` | 3 批无新信息即 `stalled` 停机 | **6** | 探索期"连续几批无新指纹"是正常的。 |

### E. 隐藏墙（你列的清单里没有，但更贵）

| 墙 | 位置 | 影响 | 建议 |
|---|---|---|---|
| **run 结束即 paused，需人工重启** | `desk.ts:1745` | run 预算用完 → `status=paused`、`phase=awaiting_operator`；没有自动续跑。这是"每 30 分钟人工点一次"的根因，比任何阈值都限制能力。 | 见下节"会话级预算 + 自动续跑" |
| **上下文证据窗口** | `context.ts:10,88` | 只给 32 条证据、body 截断 1200 字符 | 关键 JSON 常在长 body 深处。建议 tool-result 的 body 放宽到 4000，或对命中敏感词（`token`/`secret`/`password`/`AK`/`SK`）的记录优先保留 |
| **`agent_turns` 24** | `rules.ts:57` | 24 轮 LLM 调用 | 回合数不是成本，token/cost 才是。建议 `agent_turns: 0`（不限）或 120，由 `cost` 兜底 |
| **`budgetMode` 的 guidance 文本** | `desk.ts:857-859` | 直接告诉模型"跳过 sqlmap/nuclei/katana" | 这是 prompt 层的自我审查，比代码门禁更难察觉。改为"降级只影响本批重型步骤" |
| **`protocol.ts` strict + 整轮丢弃** | `protocol.ts` | 一条 `tool_requests` 不合规 → 该条丢弃；整轮不合规 → 连续 2 次才停 | 已改过（连 2 次才停），保持。但 enum 双份维护是真隐患 |

---

## 四、立即可用（不改代码）

`config/rules.srchunt.json` 已写入并**通过 `blackboxRulesDiagnostics` 校验**（`valid: true`、`fallback: false`、`issues: []`、50 条 safe_paths、14 条 text 生效）。

把它整体塞进 `BLACKBOX_RULES_DOCUMENT` 即可，无需重启进程：

| 维度 | 默认 | 本档 |
|---|---|---|
| 调度预算 | 900s | 5400s |
| 墙钟 | 1800s | 14400s |
| 权重 | 120 | 600 |
| 轮次 | 24 | 120 |
| 重试 | 5 | 12 |
| 成本上限 | 0（不限） | 25（新增刹车） |
| stage | 900s ×4 | 1800s ×12 |
| 鉴权墙 | 3 | 10 |
| 参数熔断 | 5/3/3/3 | 40/12/12/25 |
| 重复/失败/停滞 | 2/2/3 | 3/3/6 |
| 重定向/超时/body | 5/60s/256KB | 10/180s/2MB |

**它治好了什么**：预算类（B 表大半）、熔断频率、鉴权墙阈值、资源上限、以及 prompt 层的自我审查（text 段重写了"重复与停滞""完成判定""预算与降级""鉴权墙""漏洞检测与验证"五条）。

**它治不好什么**：缺陷 1（降级死锁）、缺陷 2（盲注指纹）、缺陷 3（计数顺序）、缺陷 4（verified-negative）、缺陷 5（URL 比较）——这五个要改代码。

---

## 五、代码改动（8 处，按优先级）

> 状态：**P0-1 … P1-8 已全部落到工作区**（`tsc --noEmit` 通过；全量 `vitest run` 595 passed / 2 failed，2 个失败经基线复验为既有问题，与本次改动无关）。完整 diff 在 `docs/patches/wall-removal.patch`，可 `git apply -R` 一键回滚。

> 所有位置行号基于当前 `main`（`d936884` + 本地改动）。每处给出"原文"与"替换为"，直接对拷即可。

### P0-1 · 修降级死锁 `src/blackbox/weights.ts`

原文（126-139）：

```ts
export function budgetMode(window: BudgetWindow): { mode: BudgetMode; reasons: string[] } {
  const reasons: string[] = [];
  const timeboxMs = Math.max(0, Number(window.timeboxSec) || 0) * 1000;
  if (window.wallMsLeft > 0 && timeboxMs > 0 && window.wallMsLeft < timeboxMs) {
    reasons.push(`墙钟只剩 ${Math.round(window.wallMsLeft / 1000)}s，放不下 ${Math.round(timeboxMs / 1000)}s 的完整时间盒`);
  }
  if (window.weightLeft > 0 && window.weightLeft < 20) {
    reasons.push(`工具权重只剩 ${window.weightLeft}（重型扫描一次要 3–5）`);
  }
```

替换为：

```ts
/**
 * 一个重型步骤（nuclei / sqlmap / katana）的墙钟期望。
 *
 * 降级只看"还剩不剩得下一次重型步骤"，不再拿整条 playbook 的时间盒当判据：
 * timebox 是"整场打法"的期望（600–1500s），wallMsLeft 是"本次 run 的剩余"（默认 1800s），
 * 两者不可比 —— 跑 sqli（timebox 1500）满 300s 后 wallMsLeft 恒小于 timebox，
 * 于是本 run 剩下的 1500 秒里 sqlmap 永远被判 budget_degraded。
 * 而且 budgetView 取的是 min(timebox)，最紧的那条打法会绑架所有打法。
 */
export const HEAVY_STEP_SEC = 300;

export function budgetMode(window: BudgetWindow): { mode: BudgetMode; reasons: string[] } {
  const reasons: string[] = [];
  if (window.wallMsLeft > 0 && window.wallMsLeft < HEAVY_STEP_SEC * 1000) {
    reasons.push(`墙钟只剩 ${Math.round(window.wallMsLeft / 1000)}s，不够一次重型步骤（约 ${HEAVY_STEP_SEC}s）`);
  }
  if (window.weightLeft > 0 && window.weightLeft < 5) {
    reasons.push(`工具权重只剩 ${window.weightLeft}（重型扫描一次要 3–5）`);
  }
```

`timeboxSec` 字段保留在类型里（其他调用方仍会传），只是不再参与判定。

### P0-2 · 参数熔断不置死 + 指纹纳入耗时 `src/blackbox/progress.ts`

原文（682）：

```ts
    const fingerprint = hash({ status: Number(data.status || 0), body });
```

替换为：

```ts
    // 耗时也是"形状"。时间盲注 / sleep 探测的响应体 100% 相同，唯一区别是耗时；
    // 不把耗时纳入指纹，等于把"最需要重复请求的打法"直接判成"参数面榨干"。
    const timingBucket = (ms: number): number => (ms < 300 ? 0 : ms < 1000 ? 1 : ms < 2500 ? 2 : 3);
    const fingerprint = hash({ status: Number(data.status || 0), t: timingBucket(Number(data.duration_ms || 0)), body });
```

原文（723-727）：

```ts
    const record = this.state.tasks[task];
    if (record && !["completed", "blocked", "failed"].includes(String(record.status))) {
      this.state.tasks[task] = { ...record, status: "blocked", reason: "param_stall",
        outcome_reason: `${key} 打了 ${watch.calls} 次、${watch.queries.length} 种参数，响应指纹只有 ${watch.fingerprints.length} 种：该参数面已榨干，换打法或换端点。` };
    }
```

替换为：

```ts
    // 熔断只发提示，不把任务判死。盲注与越权遍历本来就要"同一形状打很多次"，
    // 判 blocked 会把需要耐心的打法提前掐死；真正的浪费由权重预算兜住。
    this.addInterrupts([{
      id: `param-stall:${key}:${watch.stalled_at}`, kind: "param_stall", severity: "medium",
      text: `${key} 已打 ${watch.calls} 次、${watch.queries.length} 种参数，响应指纹只有 ${watch.fingerprints.length} 种：若是盲注/越权遍历，改看 time/status 维度继续；若是纯换参数穷举，换端点。`,
      data: { path: key, calls: watch.calls, queries: watch.queries.length, fingerprints: watch.fingerprints.length },
    }]);
```

### P0-3 · 鉴权墙先判通道再计数 `src/blackbox/authwall.ts` + `progress.ts`

在 `authwall.ts` 的 `wallVerdict` **之前**新增一个导出：

```ts
/**
 * 这条请求是否命中放行通道（不看墙是否已经触发）。
 *
 * 独立于 wallVerdict 的原因是计数顺序：streak 在 trackDenial 里累加，
 * 而 wallVerdict 只在 tripped 之后才被调用。于是"打 .env / actuator / swagger 各一次 401"
 * 这三条本该放行的未授权探测会把 streak 推过阈值，让正在找未授权入口的任务被判 blocked_by_auth。
 */
export function bypassChannelOf(url: string, input: Record<string, unknown> | undefined, options: WallOptions = {}): "safe_path" | "unauth_playbook" | "explicit" | undefined {
  if (AUTH_PATH.test(url)) return "safe_path";
  if (options.allowBypass !== false && input?.bypass_auth_wall === true) return "explicit";
  if (options.allowUnauthPlaybook !== false && options.playbook && WALL_BYPASS_PLAYBOOKS.has(options.playbook)) return "unauth_playbook";
  const safePaths = options.safePaths || [];
  if (safePaths.length && safePaths.some(item => url.toLowerCase().includes(item.toLowerCase()))) return "safe_path";
  return undefined;
}
```

`progress.ts:12` 的 import 加入 `bypassChannelOf`；`recordAuthDenial`（733 起）在 `const verdict = denialOf(...)` **之后、`trackDenial` 之前**插入：

```ts
    // 放行通道里的探测是"绕墙的正路"，不是撞墙：被拒也不进 streak，否则墙会被自己人推倒。
    // 只在 denied 时跳过 —— 正常响应仍然要经过 trackDenial，那里负责把 streak 清零。
    if (verdict.denied && bypassChannelOf(url, request.input, {
      playbook: this.playbookOf(task),
      safePaths: this.wallOptions.safePaths,
      allowUnauthPlaybook: this.wallOptions.allowUnauthPlaybook,
      allowBypass: this.wallOptions.allowBypass,
    })) return;
```

**注意这里必须是 `verdict.denied &&` 而不是无条件的 `if (channel) return;`**：`trackDenial` 在 `denied=false` 时会把 streak 清零，无条件 return 会让"成功带凭证打进去"这个清零动作也失效，墙就再也解不掉了。

### P0-4 · verified-negative 不算受阻 `src/blackbox/progress.ts`

原文（245-251）：

```ts
      const denial = completionDenial(evidence, task, references, { NIANYUN_AUTH_WALL_CODES: this.authWall.codes.join(",") });
      if (denial.deniedOnly && denial.evidence > 0) {
```

替换为：

```ts
      const denial = completionDenial(evidence, task, references, { NIANYUN_AUTH_WALL_CODES: this.authWall.codes.join(",") });
      // 一组探测"一致地证明该入口鉴权正确"是可交付的负向结论，不是受阻。
      // 不区分这两种，模型为了拿到 completed 会倾向于把"疑似"写成 finding —— 那是唯一会主动
      // 降低报告质量的惩罚。
      const negativeByDesign = ["auth_token", "unauth_exposure", "jwt_auth", "idor"].includes(String(record.playbook || ""));
      // 至少要两条证据才算"一组探测"：只有一条 401 是"发了个请求被拒"，不是负向结论。
      // 这个下限是防"打一个接口就宣布验证完成"的捷径。
      if (denial.deniedOnly && denial.evidence >= 2 && negativeByDesign) {
        Object.assign(record, { status: "completed", evidence_ids: [...references],
          outcome_reason: `verified_negative: ${denial.denied}/${denial.evidence} 条证据一致指向鉴权正确（401/10403，无数据泄漏），结论是无该问题。` });
        (this.state.taskOutcomeResults ||= {})[task] = { status: "applied", issues: [] };
        resolve(`completion_without_valid_task_evidence:${task}`);
        continue;
      }
      if (denial.deniedOnly && denial.evidence > 0) {
```

### P0-5 · 证据 URL 归一化比较 `src/blackbox/findings.ts`

原文（20-22）：

```ts
  if (!referenced.some(e => e?.kind === "tool-result" && (e.data as Record<string, unknown>)?.ok === true && evidenceUrls(e).some(url => {
    try { return new URL(url).href === new URL(finding.target).href; } catch { return false; }
  }))) return "候选发现必须引用该目标成功的原始工具结果";
```

替换为：

```ts
  // 用 href 全等比较会让重定向、尾斜杠、越权场景里的"另一个 id"全部引用失败，
  // 而报错只说"必须引用该目标成功的原始工具结果"，模型无从自查。
  const sameTarget = (a: string, b: string): boolean => {
    try {
      const left = new URL(a); const right = new URL(b);
      return left.host === right.host && normalizePath(left.pathname).path === normalizePath(right.pathname).path;
    } catch { return a === b; }
  };
  if (!referenced.some(e => e?.kind === "tool-result" && (e.data as Record<string, unknown>)?.ok === true && evidenceUrls(e).some(url => sameTarget(url, finding.target)))) {
    return "候选发现必须引用该目标成功的原始工具结果";
  }
```

并在文件头 `import { evidenceUrls } from "./facts.js";` 旁加 `import { normalizePath } from "./urlnorm.js";`。

### P1-6 · 工具 0 产出不再禁用 `src/blackbox/progress.ts`

原文（610-614）：

```ts
    health.zeros += 1;
    if (health.zeros < 2) return;
    health.disabled = true;
    health.detail = `${name} 连续 ${health.zeros} 次 0 产出（模板不匹配或目标无命中），已在本会话禁用`;
```

替换为：

```ts
    health.zeros += 1;
    if (health.zeros < 2) return;
    // 不用"会话内禁用"惩罚 0 产出：nuclei 默认模板打不到目标、dalfox 对 SPA 无命中、
    // sqlmap 参数不对，都能连续两次 0 产出，但换个模板 tag / 字典就有效。
    // 真正的刹车是权重预算；这里只留一次提示。
    health.detail = `${name} 已连续 ${health.zeros} 次 0 产出：换模板 tag / 换字典 / 换档位，不要用同一组参数重试。`;
    if (health.zeros === 2) this.addInterrupts([{
      id: `tool-health:${name}:${health.last_at}`, kind: "tool_health", severity: "medium",
      text: `${name} 连续 2 次 0 产出。同参数重试不划算：换 tags/字典/扫描档位，或改用 http.request 手工验证。`,
      data: { tool: name },
    }]);
```

（`begin():826` 的 `tool_disabled` 分支随之永不触发，不需要删。）

### P1-7 · Observer 频率 `src/blackbox/supervision.ts`

原文（86）：

```ts
    (event.madeProgress && usage.toolCalls > 0 && (usage.toolCalls === 1 || usage.toolCalls % 5 === 0)) || warningsChanged);
```

替换为：

```ts
    // 每 5 个权重就唤醒一次 Observer，等于把预算砍半：600 权重下是 120 次额外 LLM 调用。
    // 语义事件（新发现、失败、鉴权墙、预算告警）已经足够触发审阅。
    (event.madeProgress && usage.toolCalls > 0 && (usage.toolCalls === 1 || usage.toolCalls % 20 === 0)) || warningsChanged);
```

### P1-8 · 沙箱超时对齐 900s `src/blackbox/workspace.ts`

原文（503）：

```ts
  const timeoutS = clamp(options.timeout_s, 60, 5, 300);
```

替换为：

```ts
  // protocol.ts 已允许 900s，mcp.ts 只允许 300，这里又 clamp 到 300：
  // 三处不一致时模型看到的是最大值，实际被静默砍掉。深挖一条签名/加密链 300s 不够。
  const timeoutS = clamp(options.timeout_s, 60, 5, 900);
```

同时 `mcp.ts:61` 的 `timeout_s: z.number().int().min(5).max(300)` 改为 `.max(900)`。

---

## 六、会话级预算 + 自动续跑（最大的一处，单独说）

**问题**：`budgets` 是 **per-run**（`desk.ts:755` 的 `runBase` 记录起点），run 结束后 `status=paused` 等人工。所以"1800s"不是总时长，而是"每 30 分钟断一次、每次断都要人点一下、断一次上下文重建一次"。

**目标**：把"预算上限"从"能力天花板"改成"心跳"。

三层设计：

1. **会话预算（真上限）**：新增 `budgets.session_wall_clock_sec` / `session_tool_calls`，用 `usage` 的累计值（已持久化在 checkpoint）判定，跨 run 累积。
2. **run 心跳（防卡死）**：保留现有 `wall_clock_sec=1800`，但它的作用只是"单个 run 最多跑多久"，到点后**不置 paused，而是自动开下一个 run**。
3. **自动续跑**：`stopReason ∈ {time_budget_exhausted, wall_clock_exhausted, tool_budget_exhausted, agent_turn_budget_exhausted, stalled}` 且会话预算未尽、且 `auto_continue_runs < N` 时，`setTimeout(() => this.startProjectBlackboxAgents(pid, sessionId), 1000)`。

`desk.ts:1745` 附近改为：

```ts
const CONTINUABLE = new Set(["time_budget_exhausted", "wall_clock_exhausted", "tool_budget_exhausted",
  "agent_turn_budget_exhausted", "stalled"]);
const autoRuns = Number(this.cfg.tools_env.values.BLACKBOX_AUTO_CONTINUE_RUNS || 0);
const runsSoFar = Number(progress.state.supervision?.runs || 0) + 1;
progress.state.supervision = { ...progress.state.supervision, runs: runsSoFar } as typeof progress.state.supervision;
const willContinue = CONTINUABLE.has(stopReason) && autoRuns > 0 && runsSoFar < autoRuns;
this.db.updateBlackboxSession(pid, sessionId, {
  status: stopReason === "operator_cancelled" ? "cancelled"
    : stopReason === "tasks_completed" && !progress.state.supervision?.reviewPending ? "completed"
    : willContinue ? "running" : "paused",
  phase: willContinue ? "auto_continuing" : "awaiting_operator",
});
if (willContinue) setTimeout(() => { void this.startProjectBlackboxAgents(pid, sessionId).catch(() => {}); }, 1000);
```

**必须同时做**：`budgets.cost` / `tokens` 要设成真实上限（`config/rules.srchunt.json` 里给了 `cost: 25`）。否则自动续跑会变成无人值守烧钱——这是唯一会"拆墙拆出事故"的地方。建议再配 `BLACKBOX_AUTO_CONTINUE_RUNS=8`（≈4 小时）。

---

## 七、不建议拆的墙（诚实版）

这几条拆了不会让 agent 更强，只会让报告更不可信或让流量打到不该去的地方：

1. **目标覆盖参数禁止**（`-u/-l/--host/-d/-target`）。这是 scope 的唯一技术保障。你想换目标就新建会话。
2. **方法白名单 + 请求/响应体积上限**。防误伤被测业务（一次 500MB 上传就能把客户存储打满）。
3. **`--os-shell/--sql-shell/--eval/--code` 永久禁止**。它们给的是"挂着的交互会话"，机器人无法记账、无法复现、无法写进证据链。真要 RCE 用 `--os-cmd` 一次即可。
4. **`evidence` 的 kind + task_id 校验**。`tool-result` 才能当执行证据、`audit_ids` 不能混用——这是报告能被第三方复核的地基。可以放宽 URL 比较（P0-5），不能放宽 kind。
5. **写操作一次性 + `reason` 必填**。压着不做第二遍，是 SRC 不被告的底线。

另外两条**看似该拆、实际不该**：

- **`preflight` 硬拦 nuclei 无模板**：看似多余（反正 0 命中），但"跑成功、0 命中"会污染 `tool_health` 并烧权重，而 preflight 给的错误信息比 nuclei 自己的清楚。保留，只在文案上补一句替代方案。
- **`repeat_limit` 不要取消**：它是唯一能防止 agent 用 40 种编码变体刷同一个 403 的机制。3 次足够。

---

## 八、落地顺序

| 步骤 | 内容 | 风险 | 验证 |
|---|---|---|---|
| 1 | 把 `config/rules.srchunt.json` 塞进 `BLACKBOX_RULES_DOCUMENT` | 0（已验证 `issues: []`） | 控制台 `rule-warning` 事件应消失；`checkpoint.rule_hash` 变化 |
| 2 | P0-1 降级死锁 | 低（纯判据） | 新增单测：`wallMsLeft=1200, timeboxSec=1500 → mode==="full"` |
| 3 | P0-2 参数熔断 | 低 | 新增单测：同 body 不同 duration_ms 产生 2 个指纹；熔断后 task.status !== "blocked" |
| 4 | P0-3 鉴权墙计数 | 低 | 新增单测：`unauth_exposure` 打 5 个 401 入口后 `auth_wall.tripped_at === undefined` |
| 5 | P0-4 verified-negative | 中（改变完成语义） | 新增单测：playbook=idor + 全 401 证据 → completed 且 outcome_reason 含 `verified_negative` |
| 6 | P0-5 URL 归一化 | 低 | 单测：target 带尾斜杠 / 不同 id 段均可引用 |
| 7 | P1-6/7/8 | 低 | `npx vitest run` 全绿 |
| 8 | 自动续跑 | **高**（烧钱） | 先 `BLACKBOX_AUTO_CONTINUE_RUNS=2` + `cost: 5` 跑一场观察 |

跑测试：`npm test`（vitest）。这 5 处 P0 都会影响 `test/completion.test.ts` 与 `test/campaign.test.ts` 的断言，改完先看这两个文件。

---

## 九、一句话总账

这套墙的设计假设是"一次 run = 一次完整评估"，所以它把一切都压缩到 30 分钟、120 权重、24 轮里，再用一大批终态惩罚来保证"不浪费"。SRC 的真实形状是"一个资产、多天、多轮、多身份"——**墙的数量不是问题，墙的终态性才是问题**。把 M 类的终态换成提示、把 C 类的上限换成心跳、把 R 类原样留下，挖掘能力会立刻上一个量级，而唯一需要认真设的刹车是 `cost`。

---

## 十、本次实际落地与验证

### 改动清单

| 文件 | 改动 | 对应缺陷 |
|---|---|---|
| `src/blackbox/weights.ts` | `budgetMode` 判据改为"剩余墙钟是否够一次重型步骤"（`HEAVY_STEP_SEC=300`）；权重阈值 20→5 | 1 |
| `src/blackbox/progress.ts` | 指纹纳入耗时桶；参数熔断改发 interrupt 不置 blocked；`recordAuthDenial` 先判放行通道；负向结论判 `verified_negative`；工具 0 产出不再禁用 | 2/3/4 + 工具熔断 |
| `src/blackbox/authwall.ts` | 新增 `bypassChannelOf()`（与 `wallVerdict` 解耦，供计数前判定） | 3 |
| `src/blackbox/findings.ts` | 证据 URL 改为 host + `normalizePath` 归一化比较 | 5 |
| `src/blackbox/supervision.ts` | Observer 心跳 `%5`→`%20` | 成本 |
| `src/blackbox/workspace.ts` | 沙箱 `timeout_s` 上限 300→900 | 超时死锁 |
| `src/blackbox/mcp.ts` | `timeout_s` schema 上限 300→900（与协议/执行层对齐） | 同上 |
| `test/*.test.ts` | 8 个用例断言同步新行为，新增 2 个回归用例 | — |

### 验证

```text
npx tsc --noEmit -p tsconfig.json   →  无错误
npx vitest run                      →  595 passed / 3 failed / 2 skipped（74 files）
```

3 个失败全部与本次改动无关，已逐一复验：

- `test/assets.test.ts`（asset inventory）与 `test/candidates.test.ts`（候选池）：在**未打补丁的原始文件**上复跑同样失败，属基线既有问题；
- `test/sandbox-service.test.ts`（EBUSY 清理临时目录）：并发跑时偶发，单独复跑 13 passed。

### 新增回归用例

1. `budget-weights.test.ts` — "does not degrade just because the playbook timebox exceeds the remaining wall clock"：`wall=1200s < timebox=1500s` 必须仍是 `full`。这条用例锁死降级死锁不复发。
2. `authwall.test.ts` — "records a denied-only completion as verified_negative for negative-by-design playbooks"：`playbook=idor` + 两条拒绝证据 → `completed` 且 `outcome_reason` 含 `verified_negative`，且不产生 `auth_wall_alert`。
3. `authwall.test.ts` — "refuses verified_negative on a single denied probe"：**只有一条** 401 时仍然 `blocked_by_auth`。这条是防 `verified_negative` 变成"打一个接口就结案"的捷径——负向结论必须建立在至少两条互为对照的证据上（匿名与带凭证、或两个不同入口）。

### 回滚

```bash
git apply -R docs/patches/wall-removal.patch
```

patch 只覆盖 `src/blackbox/` 下 7 个文件。`test/` 在本仓库未纳入索引（`git status` 显示为 deleted-from-index），所以测试断言的新行为没有进 patch：回滚 src 之后，`anomaly / authwall / budget-weights / param-stall / urlnorm-stall` 这 5 个文件里的 10 个用例断言需要按第五节同步还原，否则会红。

### 还没做（需要你决定）

1. **会话级预算 + 自动续跑**（第六节）。这是收益最大也最危险的一处，必须同时设 `cost` 上限与 `BLACKBOX_AUTO_CONTINUE_RUNS`，否则会无人值守烧钱。
2. **`protocol.ts` 的 tool enum 改为从 `BLACKBOX_TOOL_NAMES` 生成**，消除双份工具清单。
3. **`anomaly_requires_diff` 允许 OAST 证据**（目前只认 `http.diff`）。
4. **`context.ts` 的 body 截断 1200 → 4000 字符**，并对命中敏感词的 tool-result 优先保留。
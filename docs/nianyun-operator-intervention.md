# Nianyun 控制台「操作员介入」流程实测报告

> 实测时间：2026-11-01 ｜ 模式：`execute` 无模型凭证 → 回落本地规划器
> 会话：`p_4acf93c7ec` / `784b64a1e0835449`（目标 `https://support.oppo.com/cn/`）
> 控制台：因 8700 被 Docker 后端占用，改起在 `http://127.0.0.1:8900/#/blackbox`

## 0. 一句话结论

控制台的「操作员介入」**入口能用、API 正常、会话可见、焦点仪表盘能渲染**；但当我真正下指令去救一个被阻断的任务时，**主 Agent 对操作员输入毫无反应**——自由文本指令是只写死胡同，`focus extend` 救不活被系统阻断的任务，resume 后零新行为。操作员介入当前是**装饰性**的，救不了任何一条卡住的线索。

---

## 1. 控制台本身能跑（已验证）

- 起因：用户给的 `127.0.0.1:8700` 实际被 `com.docker.backend.exe` 监听，不是 Nianyun。故改用 8900 起控制台。
- 起服：`nianyun console --listen 127.0.0.1:8900` → 健康正常，`project_count=12, session_count=10`。
- 会话在控制台可见：`GET /api/projects/p_4acf93c7ec/blackbox-sessions` → `784b64a1e0835449`，`status=paused / phase=awaiting_operator`。
- 焦点仪表盘 `GET .../focus` 正常返回（只是把 `blocked` 任务过滤掉了，所以 `tasks` 为空）。

## 2. 介入前的会话状态（闸门处）

```
T1-baseline      completed
T2-headers       completed
T3-robots        completed
T4-js-surface    completed
T5-cors          completed
T_SPA_REVERSE_38538276  blocked   ← 唯一未完成任务
stopReason=blocked；checkpoint.instructions=[]（无指令字段）
```

本地规划器把 `support.oppo.com` 判为 Vue SPA，spawn 了 SPA 逆向任务，但收口正则抠 `/api` 失败 → 判 `blocked`，整场转 `awaiting_operator` 等人工。

## 3. 我做的两次介入（真实 API）

**① 下发自由文本指令（最自然的操作员动作）**
```
POST .../blackbox-sessions/784b64a1e0835449/instruction
{"text":"不要只靠正则抠 /api… 直接抓 JS bundle，提取 axios baseURL / fetch / 网关前缀 / chunk 文件名…"}
→ 落库 event #1573, kind=instruction, actor=operator  ✅ 已记录
```

**② 对被阻断任务做 `focus extend`（结构化杠杆）**
```
POST .../blackbox-sessions/784b64a1e0835449/focus
{"action":"extend","task_id":"T_SPA_REVERSE_38538276"}
→ event #1574 system：「已退 1 轮预算并清除收口指令」
```

**③ resume 续跑**
```
POST .../blackbox-sessions/784b64a1e0835449/resume
→ ok:true，session 立即回到 ready/awaiting_operator
```

## 4. resume 后的真实结果（关键证据）

干预后新增事件**只有 2 条**，且都与 Agent 行为无关：

| # | kind | 内容 | 是否驱动 Agent |
|---|------|------|----------------|
| 1574 | focus-convergence:system | extend 的系统回执 | 否 |
| 1575 | lifecycle:operator | 「会话已恢复，等待 Agent 调度」 | 否 |

**主 Agent 在 resume 后：**
- 发出 **0** 条新工具请求；
- **0** 条事件提及 bundle / axios / gateway / SPA 提取；
- 新增证据 **0** 条；
- 被阻断任务 `T_SPA_REVERSE_38538276` resume 后**仍是 `blocked`**，`focus_task_id` 空、`focus_usage` 为 null。

也就是说：我下的那段详细指令，Agent 一个字都没看到；extend 也没把任务复活成 `pending`。resume 纯粹空转一轮，原样回到 `awaiting_operator`。

## 5. 根因（代码级）

1. **指令是只写通道。** `addProjectBlackboxInstruction`（desk.ts:1842）只做 `addBlackboxEvent(..., "operator","instruction", text)`，不写 checkpoint、不设 `macro_interrupt`、不注入提示词。全 src 没有任何地方把 `kind=operator/instruction` 事件读回 Agent（grep 唯一命中是 agent.ts:386 的审计 id 注释，与指令无关）。
2. **Agent 只读 checkpoint，不读 events 表。** `runBlackboxMainAgent` 入参是 `(values, latest=checkpoint, candidate, signal, runtime)`；checkpoint 从不含 `instructions` 字段。故即便 LLM 模式，操作员文本也进不了上下文——这是**架构性断链**，不是本地规划器独有。
3. **`macro_interrupt` 是系统→操作员信号，不是操作员→Agent 通道。** 它只在 `session_convergences` 超阈时由系统自动设置（desk.ts:1619），用来提示「转人工」，其内容不反哺 Agent。
4. **被系统阻断的任务无法被操作员救活。** 操作员对 blocked 任务仅有的杠杆：`converge`（放弃，标 blocked/operator_blocked）、`extend`（只减已清空的 `focus_usage.turns`，不把任务变 pending）、`restore`（只救 `operator_blocked`，救不了系统阻断）、`switch`（切到别的任务，但其它都已 completed）。**没有任何「换打法重试」的杠杆。**

## 6. 与专业 SRC 猎手的差距（控制维度）

专业猎手卡住一条线索时，会改手法再试（换参数、换入口、换协议、手测）。本系统的操作员介入：
- 不能把新思路传给 Agent（指令死通道）；
- 不能让 Agent 对卡住的线索换打法重试（无 unblock-and-retry）；
- 唯一能改变产出的结构化动作是 `review`（确认/驳回发现）和 `converge`（放弃）。

结果：控制台看起来「可介入」，实则操作员在卡住的线索上**束手无策**——这正是报告第 1 版指出的「控制」维度漏洞的放大版。

## 7. 修复建议（按性价比）

1. **把操作员指令真正接进 Agent（最高优先级）。** 在 `runBlackboxMainAgent` 入参里加 `operator_instructions`（从 events 表按 session 取 `kind=instruction` 且未消费的条目），render 进 system/user prompt 末尾作为「操作员定向要求」。断链点明确，改动小。
2. **新增 `focus` 动作 `retry`/`unblock`**：把系统阻断的任务重置为 `pending` 并清空 `outcome_reason`，允许下一轮换打法重试（可带 `note` 把操作员思路一并写入任务 `purpose`，让 LLM 看到）。
3. **`extend` 应顺带复活任务**：当目标任务是 `blocked` 且非 `operator_blocked` 时，`extend` 应同时置 `status=pending`，否则 extend 对阻断任务无意义。
4. **指令消费后留痕**：在 checkpoint 记 `last_instruction_id`，避免重复投喂；Agent 应在事件流里回显「已采纳操作员指令：…」，让操作员确认真的生效（否则操作员永远不知道指令被忽略）。
5. **UI 诚实化**：`instruction` 输入框若暂不接 Agent，应标注「当前版本指令仅留痕、不参与调度」，否则是误导性交互。

---

## 附：本次实测轨迹（可直接复现）

```bash
# 1) 起控制台（避开 Docker 占用的 8700）
./bin/nianyun console --listen 127.0.0.1:8900

# 2) 下操作员指令
curl -X POST http://127.0.0.1:8900/api/projects/p_4acf93c7ec/blackbox-sessions/784b64a1e0835449/instruction \
  -H 'Content-Type: application/json' -d '{"text":"直接抓 JS bundle 提取 axios baseURL / fetch / 网关前缀"}'

# 3) 对阻断任务 extend
curl -X POST http://127.0.0.1:8900/api/projects/p_4acf93c7ec/blackbox-sessions/784b64a1e0835449/focus \
  -H 'Content-Type: application/json' -d '{"action":"extend","task_id":"T_SPA_REVERSE_38538276"}'

# 4) resume
curl -X POST http://127.0.0.1:8900/api/projects/p_4acf93c7ec/blackbox-sessions/784b64a1e0835449/resume

# 5) 观察：新增事件仅 1574/1575，无新工具请求、无新证据，任务仍 blocked
```

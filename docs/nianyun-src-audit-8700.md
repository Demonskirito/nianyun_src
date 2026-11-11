# Nianyun 黑盒 SRC 挖掘审计（8700 Docker / 真实 AI 环境）

> 审计时间：2026-11-01
> 环境：**`http://127.0.0.1:8700`（Docker 容器 `nianyun-control-nianyun-1`，镜像 `nianyun:control`）**
> 模型：`BLACKBOX_AGENT_MODEL=deepseek-v4.1-flash-1017`，base `maas.qianwenaiapi.com/compatible-mode/v1`，API key 已配置
> 项目：`p_06db586d65`「Ledger」｜645 个资产候选 / 30 个已跑会话
> 抽样会话：`17e1b714fab57d6b`（business.oppo.com，198 事件/41 证据/17 任务）与 `277a31c5647c7864`（m.ctrip.com，96 事件）

> ⚠️ **方法论更正**：此前 `docs/nianyun-src-mining-audit.md` 与 `docs/nianyun-operator-intervention.md` 是在**错误环境**（本地裸进程 `127.0.0.1:8900`，无模型 key、读本地空库）下得出的，**结论作废**。那份报告里「Observer 是橡皮图章」「指令通道在 LLM 模式也读不到」等判断均不成立——它们来自无模型回落的本地规划器，不是真实 AI。本报告基于 8700 的真实 AI 会话，结论以本文件为准。

---

## 0. 一句话结论

真实 AI 跑起来后，**主 Agent 和 Observer 都在干活，但两者之间、以及 Agent 与控制系统之间断链**，导致 25/30 个会话卡在 `awaiting_operator`、零产出。核心问题有三个：
1. **主 Agent 陷入「重规划死循环」**：每轮都「从零规划/首轮初始化」，重复声明同一批侦察任务，几乎不执行、不收口。
2. **Observer→Agent 反馈回路断裂**：Observer 把 Agent 的矛盾看得一清二楚（"你说没结果，账本里已有 7 条"），但建议**从未被 Agent 采纳**，Agent 下一轮照旧重复同样的错误。
3. **SPA 缴械 + 焦点锁 = 死锁**：`spa-disarm` 禁用主机侦察工具并锁定 `T_SPA_REVERSE` 为焦点 → 该任务无工具可用、0 进度 → 焦点锁拒收所有其他请求 → 4 轮 0 TP → 强制收口 blocked。

---

## 1. 主 Agent 实际干了什么（business.oppo.com 会话）

13 次 `agent:analysis` 的原文开头：
- 「本轮从零规划」「会话刚初始化」「新一轮会话」「首轮规划」「会话首次规划」「会话环境已就绪…本轮按资产规划首轮铺面任务」……

**没有任何一轮越过"规划 + 派第一批侦察"**。实际真正执行的工具只有 9 次：
- `http.request`（基线 GET）×5
- `burp.history` ×3
- `burp.sitemap`（31 条入口）×1
- `recon.js_endpoints` ×1 → 结果：**「页面未引用可分析的 JavaScript 文件」**

**从未真正执行**的：nuclei、katana.crawl、content_discovery、api_routes、unauth_exposure、参数发现、越权探测——这些都被声明成任务，但要么被焦点锁拒收，要么被 SPA 缴械禁用。也就是说，对一个真实 SRC 目标，主 Agent 只做了**基线 GET + 读了一下 Burp 历史**，真正的攻击面探测一步没走。

## 2. Observer 实际干了什么（关键纠正！）

**Observer 在真实 AI 模式下非常活跃且专业**：71 次 checkpoint 保存、4 次 review、4 次 advice。它的建议直击要害：

> 「本轮核心问题不是'缺证据'，而是主 Agent 在重复劳动却没有闭合任务，同时对已有证据的判断有误。基线已经拿到了，不用再取。ev-d429c5a3 与 ev-bd1e6eb6 是两次独立匿名 GET…均 200…主 Agent 的 summary 仍写'尚未收到任何工具结果'——账本与叙述矛盾。」

> 「焦点任务其实已经出结论，但主 Agent 自己没读自己的结果。ev-c13e29 是 /static/favicon.ico 200、ev-0f9787 是同前缀随机 .js 404——两者已构成等效对照，架构判定完毕，本轮不需要再做任何基线或探针。」

> （ctrip 会话）「主 Agent 本轮计划与检查点状态错位：焦点锁 current_focus_task_id=T1，但 4 条 tool_requests 全部挂 task_id=T1_surface_map，会被 focus_lock 拒收。」

**结论：Observer 完全不是橡皮图章，它是整个系统里最清醒的角色。** 此前我在无模型环境说它是橡皮图章，是错的，特此收回。

## 3. 控制面实际干了什么（断链点）

- **`spa-disarm`（步兵缴械）**：`business.oppo.com 判定为 SPA 外壳（5159B）` → 生成 `T_SPA_REVERSE_22016752`，并**对该主机禁用 `content_discovery/nuclei/api_routes`**。
- **`focus-appeal` ×7**：全部是「本轮全部请求都挂…被焦点 `T_SPA_REVERSE_22016752` 拒收：焦点契约不变，记账等下一轮计划自行切换」。即：焦点锁死在 SPA 逆向任务上，**其他所有请求一律被拒**。
- **`focus-convergence` ×2**：`T_SPA_REVERSE 已消耗 4 轮 / 0 TP（连续 3 轮没有高价值证据）` → `强制收口：已由控制面标记 blocked`。
- **`supervisor-pause` ×2 + `validation-failed` ×2**：「审核后验收校验失败」「阶段结束门禁发现阻塞校验错误」——**验收门禁本身也失败了**，会话无法干净收尾。
- **`graph-rank` 仍给 `http.request` 打 0 分**（"未绑定打法"）——和本地环境一样的图加成失效。
- **Burp 首连异常**：`warning: Burp 代理不可用 connect ECONNREFUSED 192.168.65.254:8080`（Docker 网关 IP），随后才连上 `host.docker.internal:8080`。首连地址指向网关是配置异味（疑似容器内残留代理环境变量）。

---

## 4. 四维度诊断

### 打法（Playbook）
- **`spa_reverse` 打法自相矛盾**：`spa-disarm` 的逻辑是「判定 SPA → 禁用主机侦察工具 → 生成 T_SPA_REVERSE」。但被禁用的正是逆向 SPA 所需的工具（content_discovery/nuclei/api_routes/js 提取），于是 T_SPA_REVERSE **天生无工具可用 → 必然 0 进度 → 必然 blocked**。Observer 也点破：「SPA 的真实攻击面就在 burp.sitemap 已列出的那些 bundle 里」——可恰恰是 disarm 把提取 bundle 的路堵死了。
- **打法只声明不执行**：16 个 playbook 里真正落到工具调用的极少，Agent 停在「声明任务」这一步。

### 预算（Budget）
- 配置其实很慷慨：`time_sec=5400 / tool_calls=600 / agent_turns=120 / cost=$25`。但 **25/30 会话在预算几乎没动的情况下就卡死在 awaiting_operator**——预算不是被耗尽，是被**控制死锁提前耗尽可能性**。没有"卡住就换思路/换路径"的预算再分配机制。

### 路径（Path）
- **侦察路径几近为零**：两个抽样会话都只做到基线 GET + burp 历史读取，连 katana 爬取、nuclei、参数发现都没真正跑。真正的 SRC 挖掘路径（子域/端口/爆破/参数/越权）完全没展开。
- **`graph-rank` 把 `http.request` 评为 0**：基础请求是后续一切的前提，却因"未绑定打法"被打 0 分，排序加成起反作用。

### 控制（Control）
- **Observer→Agent 反馈断裂**：Observer 的建议没有回流进 Agent 的下一轮上下文，是最致命的断链。系统花了算力让 Observer 看得清，却不让 Agent 听见。
- **焦点锁 + SPA 缴械死锁**（见 §3）：一个设计缺陷把整场探测锁死。
- **验收门禁自败**：`validation-failed` 出现两次，说明收敛/结案逻辑本身有 bug。
- **主 Agent 重规划循环**：每轮"从零规划"是 prompt/状态管理的失败——Agent 不读自己的 checkpoint，把已初始化的会话当成新会话。

---

## 5. 与专业 SRC 猎手的差距

专业猎手在一个目标上的典型节奏：**建基线 → 摸清架构（SPA 就去找 bundle/API）→ 立假设 → 用对应工具验证 → 链式利用 → 出可提交报告**。本系统的 AI 卡在第一步和第二、三步之间的缝隙里：
- 猎手发现 SPA 会去扒 JS bundle 找真实 API；本系统发现 SPA 后**直接缴械、锁死、放弃**。
- 猎手看到"基线已拿"就推进；本系统 **Agent 反复重取基线、Observer 反复提醒、Agent 反复无视**。
- 猎手卡住会换手法；本系统卡住只会**焦点锁拒收一切 → 强制收口**。

差距不在"工具不够"，而在**闭环（感知→决策→执行→复核→再决策）断了三处**：Agent 不读状态、Observer 不被听、控制面会自锁。

---

## 6. 修复建议（按性价比排序）

1. **【最高优先级】把 Observer 的 advice 真正接回 Agent 循环。** 这是花最小改动、收益最大的一处：在主 Agent 下一轮的 prompt/上下文里注入"上一轮 Observer 的未解决建议（advice 里未 closed 的条目）"，并强制要求 Agent 在 analysis 里逐条回应（采纳/拒绝+理由）。否则 Observer 等于白干。
2. **修 `spa_reverse` 打法的自锁。** `spa-disarm` 不该禁用逆向所需的工具；应保留 `recon.js_endpoints / burp.sitemap bundle 提取 / http.request` 等只读手段，且 T_SPA_REVERSE 的"无工具可用"不应被判 0 TP 强制收口，而应标记为 `needs_different_tactic` 交操作员。
3. **解焦点锁死锁。** 当焦点任务连续 N 轮 0 进度且其所需工具被禁用时，自动放宽焦点锁或切换焦点，而不是无限拒收其他请求。
4. **修 `graph-rank` 对 `http.request` 打 0 分。** 基础请求应作为前置步骤给予正分或豁免排序惩罚。
5. **治主 Agent 重规划循环。** 在 analysis 前注入 checkpoint 摘要（已完成任务/已有证据/当前焦点），并禁止"从零规划"措辞——Agent 必须基于既有 checkpoint 续跑。
6. **修验收门禁 `validation-failed`。** 排查 supervisor-pause 的校验逻辑，避免会话无法干净收尾。
7. **清容器内代理环境变量。** 消除 Burp 首连指向 `192.168.65.254:8080` 网关 IP 的异味，统一走 `host.docker.internal:8080`。
8. **把 `NIANYUN_OBSERVE=0` 这个死变量从容器 env 里删掉**，避免误导后来人以为 Observer 被关了（实际它由 `BLACKBOX_OBSERVER_ASYNC` 控制，默认开启）。

---

## 附：可复现的核对路径

```bash
# 控制台即 Docker 容器内的 Nianyun（8700），不是本地进程
curl http://127.0.0.1:8700/api/health
curl http://127.0.0.1:8700/api/projects/p_06db586d65/blackbox-sessions
# 看某个会话的时间线（events 含 agent:analysis / observer:advice / focus-appeal / spa-disarm / focus-convergence）
curl http://127.0.0.1:8700/api/projects/p_06db586d65/blackbox-sessions/17e1b714fab57d6b
```

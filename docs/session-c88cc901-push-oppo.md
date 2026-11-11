# 会话全时间线：`http://push.oppo.com/`（session `c88cc9012d897f55`）

> 数据来源：容器内 `data/nianyun.db`（`blackbox_sessions` / `blackbox_events` / `blackbox_evidence`）导出后逐条核对，
> 时间轴为会话创建时刻起的相对秒；证据 ID 均为账本真实 ID，可 `evidence.read` 复查。
> 复现命令见文末。

## 1. 会话元信息

| 项 | 值 |
|---|---|
| project | `p_06db586d65`（bdev/push/hd 等 oppo 资产同项目） |
| session | `c88cc9012d897f55` |
| candidate | `6636b8a290453ebd` |
| target | `http://push.oppo.com/`（301 → `https://push.oppo.com/` → `https://open.oppomobile.com/`） |
| 创建 → 结束 | 1792915667.102 → 1792916731.701（墙钟 **1064s / 17m44s**，其中工具执行 188s、调度 875s） |
| 终态 | `status=paused` `phase=awaiting_operator` `stopReason=validation_failed_review_required` |
| 轮次 | 主 Agent 9 轮 / Observer 9 轮（全部 `decision=continue`） |
| 工具调用 | 权重计费 55 次（协议层 51 条 `tool-requests`、50 条结果、2 条 rejected） |
| Token | 496,763（9 轮，约 55k/轮） |
| 证据 | 127 条（`main-agent` 61 / `http.request` 46 / `observer` 9 / `nianyun` 3 / 扫描器 6 / `browser.open` 2 / `historical_urls` 2） |
| 发现 | 1 条：`F-INTERNAL-ROUTE-DISCLOSURE`（`信息泄露` / `severity=info` / **Observer 已确认**） |
| 预算对照 | 调度 900s（用 875s，97%）、墙钟 1800s（用 1064s，59%）、权重 120（用 55，46%）、轮次 24（用 9，38%） |

**结论先行**：这一轮不是被时间掐死的，是被**流程门禁**掐死的（`advice_decisions` 漏写 → 2 条 `ADVICE_DISPOSITION_INVALID` → 验收失败 → 暂停等人工）。
时间/权重都还有一半预算没用。

## 2. 环境与开场（+0s ~ +29s）

| 时间 | 事件 |
|---|---|
| +0s | 会话创建；Burp 代理探测通过：`http://host.docker.internal:8080`（`ready=true`） |
| +8s | 工具冒烟：**`recon.sast` 不可用**（其余 nuclei/secrets 等 OK）→ 该工具整场不可用 |
| +29s | 主循环启动，预算快照写入事件：`timeMs=900000 wallClockMs=1800000 toolCalls=120 agentTurns=24` |

## 3. 九轮推进（主 Agent 视角）

| 轮 | 时间 | 主 Agent 决策 | 派发的工具（→ 关键返回） | Observer |
|---|---|---|---|---|
| R1 | +59s | 只做环境检查，先建任务集再派低影响侦察；建 `T1/T2/T4/T5/post_surface_push` 5 个任务 | `http.request` GET push → **301** `Location=https://push.oppo.com/?qljuiojq7=1`；`recon.content_discovery` → 1718 行命中（工件 jsonl）；`recon.js_endpoints` open.oppomobile.com → 无 JS；`http.request` OPTIONS push → 200，`ACAO:*`+`ACAC:true` | — |
| R2 | +207s | 承接 R1 证据：判定 catch-all 疑云，派验证矩阵（https 基线 / 随机路径反证 / Host 头 / 敏感路径 / Origin / POST 面） | GET https push → 301→open.oppomobile.com；`/zz-…probe` → 301 同目标（**catch-all 成立**）；`/.env`、`/actuator/health` → **412 2681B WAF 页**；OPTIONS → 200；`recon.api_routes` → **rejected：缺 input.wordlist** | 审查#1 +261s |
| R3 | +299s | 采纳审查#1 三条补证，改判据为三态（真实 200 / WAF 412 / catch-all 301）；派 WAF 规范化绕过矩阵 | `browser.open` open.oppomobile.com → 200 截图（工件 png）；`/health` → 301（**非**关键词拦截）；`//actuator/health`、`/actuator/;/health`、`/%2e%65nv`、OPTIONS `/actuator/health` → 全部 **412**；`recon.historical_urls` → 0 行 | 审查#2 +423s（批评 4 条重复 + 3 条已自证伪） |
| R4 | +520s | 认领批评，停止 WAF 变形；转 open.oppomobile.com 取 JS 入口 | `/` → 200；`index-643dd1d6.js`、`bootstrap-1b0ca83d.js` → 200；OPTIONS `/` → 403；`baymax-go2/?list-type=2` → 302；`common-federation/index.json`、`remoteEntry_*.js` → 200 | 审查#3 +558s |
| R5 | +609s | 修正 CORS 判据（固定 `*` 不算反射），补 import 链 | push OPTIONS → 200；`remoteEntry_8576ede6.js`、`__federation_expose_SsiMount-*.js` → 200；POST/OPTIONS `baymax-go2/` → 302 通用跳转 | 审查#4 +662s |
| R6 | +745s | 判 T1 completed、T5 failed；继续扒 federation 模块找 API 前缀 | push 301；`base-389b461b.js` 系列、`Apis-*.js`、`UtilsHttp-*.js` → 200；`cloudmachine/device/list-plus`、`device/device-info` → 200（1884B 同模板） | 审查#5 +789s |
| R7 | +836s | 结案 T7（CORS 反射证伪）、T8（baymax-go2 非 OSS 可列举）；打内部路由 | 两条 cloudmachine 200 + `zz-…ctrl9` 302 + 3 条 OPTIONS 200 | 审查#6 +880s → **确认 `F-INTERNAL-ROUTE-DISCLOSURE`** |
| R8 | +925s | 结案 T2 failed（关键词 WAF 不可绕）；继续 import 链 | `base-389b461b.js`、`captcha-*.js`、`settlement/static/js/settleChange.js` → 200 | 审查#7 +956s |
| R9 | +1001s | 打 `/base/v1/*` 业务接口 + 自查 T9 | POST `/base/v1/dict/get_key` → 200 `code:300001`（Go validator 必填 `DictKey` 报错 = **已穿过鉴权层**）；GET `/base/v1/feature-flag/get?key=…` → `code:0, data.content=""`；POST `/quickapp/officialapi/v1/base/gensign` → 200；POST `/base/v1/captcha/verify-code` → 200；GET `bdev.oppo.com/` → 200；`baymax-go2/?acl` → 302；POST `/home/send-message/send-phone-code` → 200 | 审查#8 +1037s、审查#9 +1064s |

## 4. Observer 九次审查都做了什么

| 序 | 时间 | decision | 核心意见（原文摘） |
|---|---|---|---|
| 1 | +261s | continue | push 是「全站 301 + WAF」的组合，别把 412 当敏感文件泄露；最强面在 open.oppomobile.com |
| 2 | +423s | continue | 7 条请求里 4 条重复、3 条是已被自身结果证伪的 WAF 变形，「预算正在被无效消耗」；逐条点名重复的 evidence |
| 3 | +558s | continue | T1/T5/T2 证伪链自洽，要求把 CORS 定性（`*`+credentials 无利用性）、用真实报文验 Host 头 |
| 4 | +662s | continue | 方向合理，要求从 federation 模块抽 API 清单、补 `baymax` 的 OSS 语义 |
| 5 | +789s | continue | 架构判断到位；指出 T9 的 200 需要排除「SPA 壳回显」误报 |
| 6 | +880s | continue | **裁决发现**：`F-INTERNAL-ROUTE-DISCLOSURE` = `confirmed`（要求 severity=info，禁止表述成"未授权访问"）；同时指出 T9 两条 200 不是业务数据 |
| 7 | +956s | continue | 三条 import 链取回到位，判据成立；要求把 `dict/get_key` 的字段校验报错当作突破口 |
| 8 | +1037s | continue | T10 结果**推翻**了「`/base/v1/*` 整段是鉴权墙」的假设：validator 报错说明已进业务层，只差一个字段值；点名 4 项证据缺口 |
| 9 | +1064s | continue（validation_failed） | 硬性阻塞：`advice_decisions` 为空 → 三条实质意见一条都没被处置；两处漏记（T10 判据被自己的证据推翻仍写 pending） |

Observer 平均 **每次审查耗 32~50s**（+209→+261、+375→+423、+521→+558、+610→+662、+747→+789、+838→+880、+926→+956、+1003→+1037），共约 5.6 分钟模型时间，占调度预算的 38%。

## 5. 工具使用统计（本会话）

| 工具 | 证据数 | 说明 |
|---|---|---|
| `http.request` | 46 | 绝对主力：基线、变体、匿名对照、业务接口 |
| `recon.content_discovery` | 2 | 1718 行命中 → 判定字典回显 / catch-all |
| `recon.historical_urls` | 2 | 0 行（无历史 URL 数据源命中） |
| `recon.js_endpoints` | 1 | open.oppomobile.com 首页无 `<script src>`（SPA 动态注入） |
| `recon.api_routes` | 1 | **rejected**：`requires input.wordlist`（Agent 没给 wordlist 路径，直接被拒） |
| `browser.open` | 2 | 渲染 open.oppomobile.com + 截图工件 |
| 未使用 | — | nuclei / sqlmap / xss / katana / interactsh / burp.send_batch / burp.intruder / recon.subdomains 全部零调用 |

## 6. 协议摩擦与调度拦截（可直接改的坑）

| 时间 | 类型 | 内容 |
|---|---|---|
| +59s | protocol-warning | 3 条被丢：`input.url: Invalid URL` ×2、`required_tasks[2].target: Invalid URL`（Agent 把裸域名写进 url） |
| +209s | tool-rejected | `recon.api_routes` 缺 `input.wordlist` → 不计费但白跑一轮 |
| +299s | protocol-warning | `input: Unrecognized keys: "concurrency", "requests"`（想用 `burp.send_batch` 的并发语义，但塞错了工具/字段） |
| +520s | protocol-warning | `input: Unrecognized key: "target"`、`required_tasks.target: Invalid URL` |
| +925s | protocol-warning | `input.duration_seconds: Too big: expected number to be <=60` |
| +1003s | param-stall | `open.oppomobile.com/baymax-go2/` 打了 5 次、3 种参数、0 个路径 id、响应指纹只有 1 种 → 熔断该端点参数面 |
| +1003s | budget-warning | 覆盖率 0.545，预算接近阈值 |
| +1037s | supervisor-pause / validation-failed | `ADVICE_DISPOSITION_INVALID` ×2（`review-d9a3260b…`、`review-8f5650eb…`）+ `PARTIAL_TASK_OUTCOME` |

## 7. 任务账本（11 条，收尾时 1 completed / 5 failed / 5 pending）

| 任务 | playbook | 终态 | 结论 |
|---|---|---|---|
| T1 | unauth_exposure | completed | 匿名根路径与随机路径同 301 同 Location → catch-all，无独立业务面 |
| T2 | unauth_exposure | failed | 关键词型 WAF：`/.env` 与全部规范化/编码变体稳定 412 同一页，`/health` 走 301 → 拦截由关键字触发，放弃 |
| T4 | — | pending | 卡在 `recon.api_routes` 缺 wordlist（工具使用问题，不是目标问题） |
| T5 | — | failed | Host / X-Forwarded-Host 均未改写 Location → 无 Host 头注入 |
| post_surface_push | — | pending | 会话结束时仍未完成 POST 面枚举 |
| T7 | unauth_exposure | failed | CORS：无 Origin 基线 vs 外部 Origin 同码同头，`ACAO` 固定 `*` → 非反射，无利用性 |
| T8 | cloud_supply | failed | `baymax-go2` 是 catch-all 错误路由，非公共可列举 OSS；`recon.secrets` 只吃本地路径，无法对远端用 |
| T9 | unauth_exposure | failed | 错误页回显内部路由 → 转入发现（见 §8），任务本身按"同模板回显"结案 |
| T10 | unauth_exposure | pending | 已取到 `/base/v1/dict/get_key` 穿过鉴权层的证据，未补真实 `DictKey` |
| T11 | unauth_exposure | pending | `bdev.oppo.com`（cookie 里有 `username`/`callbackUrlLogin`）从未被真正打过 |
| T12 | cloud_supply | pending | `param_stall` 熔断，未收口 |

## 8. 唯一发现与裁决

```
F-INTERNAL-ROUTE-DISCLOSURE  信息泄露 / info / status=confirmed
target: https://open.oppomobile.com/baymax-go2/
evidence: ev-d285c1a162e0b5bd (OPTIONS) + ev-d06797237428af37 (POST)
```
- 现象：任意不存在路径（GET/POST/OPTIONS 一致）返回 500 页，正文内联 `<script>` 硬编码 `/cloudmachine/device/list-plus`、`/cloudmachine/device/device-info`、`/cloudmachineintl/device/list` 等内部路由，并按命中改写 Back 链接；错误码随机（2526557761 / 2526585228），证明是通用模板对任意输入回显。
- 影响：泄露内部管理路由命名与模块结构，无数据外泄。
- Observer 裁决原文要求：`severity=info`，**不得**表述为「管理入口暴露」或「未授权访问」。

## 9. 终止归因

| 层次 | 事实 |
|---|---|
| 直接原因 | `supervision.acceptance` 报 `ADVICE_DISPOSITION_INVALID`：主 Agent 连续多轮把 Observer 的 3 条建议（`/base/v1/*` 不是整段墙、bdev 当独立资产、baymax-go2 停止）搁置，`advice_decisions` 始终为空 → 6 条 advice 未处置 → 门禁 `validation_failed_review_required` |
| 预算 | 调度 875/900s（97%）、墙钟 1064/1800s（59%）、权重 55/120（46%）、轮次 9/24 → **时间不是瓶颈** |
| 目标侧 | push.oppo.com 是纯跳转 + 关键词 WAF，真实业务面在 open.oppomobile.com，后者未鉴权接口多（`/base/v1/*`、`/quickapp/officialapi/*`、`/home/send-message/send-phone-code`） |
| 未验证的高价值线索（被门禁截断） | ① `dict/get_key` 补真实 `DictKey`（字段名已从报错泄露）② `/base/v1/flow/staining` 零覆盖 ③ `feature-flag` 用真实 key 重放 ④ `bdev.oppo.com?callbackUrlLogin=//evil…` 开放重定向 ⑤ `id.heytap.com/packages/account_web_sdk/index.umd.js` 里的 appId/登录接口 ⑥ `/home/send-message/send-phone-code` 短信滥用（已 200，未判语义） |

## 10. 可复现查询

```bash
# 会话总览
docker exec -w /opt/nianyun nianyun-control-nianyun-1 node -e "
const {DatabaseSync}=require('node:sqlite');
const db=new DatabaseSync('/opt/nianyun/data/nianyun.db',{readOnly:true});
const s=db.prepare('select id,target,status,phase,created_at,updated_at from blackbox_sessions where id=?').get('c88cc9012d897f55');
const ck=JSON.parse(db.prepare('select checkpoint_json from blackbox_sessions where id=?').get('c88cc9012d897f55').checkpoint_json);
console.log(s); console.log(ck.stopReason, ck.usage);"

# 事件流（按时间）
docker exec -w /opt/nianyun nianyun-control-nianyun-1 node -e "
const {DatabaseSync}=require('node:sqlite');
const db=new DatabaseSync('/opt/nianyun/data/nianyun.db',{readOnly:true});
for(const e of db.prepare('select actor,kind,text,created_at from blackbox_events where session_id=? order by created_at,id').all('c88cc9012d897f55'))
  console.log(new Date(e.created_at*1000).toISOString().slice(11,19), e.actor, e.kind, String(e.text).slice(0,90));"
```
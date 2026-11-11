# 无模型跑完一场黑盒会话：`nianyun run <url>`

这份文档记录为了让 nianyun-agent「在没有模型凭证、没有 Burp 的机器上，也能把一个 URL 从头跑到出报告」所做的改动、每处改动的根因，以及两次真实跑分的结果。

## 1. 为什么原来跑不完

控制台里那套流程（建项目 → 导入候选 → 环境检查 → 跑会话 → 出报告）本身是通的，卡住的地方在两头：

| 现象 | 根因 |
|---|---|
| `环境检查未通过：Burp proxy is not configured` | `tools.env.yaml` 里 `tools:` 下嵌了一层 `arl:` 分组，摊平函数只摊一层，把整组压成 `"[object Object]"`。于是文件里明明写了 `BURP_PROXY_REQUIRED: "true"`，代码里读到的却是一个默认值——配了等于没配。 |
| 会话能起，但主 Agent 一条计划都给不出 | `tools.env.yaml` 里所有模型凭证为空（`BLACKBOX_AGENT_*` / `ANTHROPIC_*` / `OPENAI_*`），主 Agent 无从规划。 |
| 有任务在跑，但永远停在 `stalled` | ①`forced_focus` 指向的任务一旦已结案，焦点锁不放行，其它任务的请求被一律拒收；②系统自建的 `T_SPA_REVERSE_*` 永远 pending；③首页无同源脚本时 `T4` 既不发请求也不结案；④被拒收的请求不进账本，规划器以为「从没试过」而反复重发。 |

## 2. 改动清单

新增：

- `src/control/run.ts` — 一条命令跑完一个 URL；带收敛循环（`stalled` / `required_review_pending` 不算终态，继续推进直到验收门禁定下来），产物写 `report.md` / `summary.json` / `run.json`。
- `src/blackbox/local_plan.ts` — 确定性规划器（无 LLM）：声明 5 条只读任务、按证据推进、给出候选发现、以 Observer 身份复核。

修改：

- `src/control/cli.ts` — 增加 `run` 子命令。
- `src/shared/tools-env.ts` — 摊平改为递归（嵌套分组不再被吞）。
- `src/blackbox/focus.ts` — 强制焦点/粘性焦点指向已终态任务时释放，避免死锁。
- `src/control/console/desk.ts` — 本地规划模式下关闭焦点锁（焦点锁是为 LLM 的注意力漂移设计的），并在时间线留痕；引入 `useLocalPlanner`。
- `src/blackbox/agent.ts` — 在 `runBlackboxMainAgent` / `runBlackboxObserver` 的口子上接本地规划器。

**关键设计**：本地规划器插在与 LLM 完全相同的接缝上，不是另开一条执行路径。所以证据账本、闭包审计、Observer 复核、验收门禁、报告渲染全部照旧生效——这也是为什么它跑出来的报告和带模型时是同一套结构。

本地规划器的边界：只有 GET/HEAD/OPTIONS 加一个 `Origin` 探针；不写、不爆破、不猜路径；每任务 3 次不成即按 fallback 收口。

## 3. 两次实跑

| 目标 | 结果 | 发现 |
|---|---|---|
| `https://support.oppo.com/cn/`（宿主直连） | `acceptance_ready: true`，3 条发现 | CORS 回显任意来源 + 凭证（high）、缺失 6 项安全响应头（low）、`server: openresty`（info） |
| `https://www.opposhop.cn/`（宿主直连，全新目标） | `acceptance_ready: true`，3 条发现 | CORS 回显任意来源 + 凭证（high）、缺失 5 项安全响应头（info）、`server: nginx`（info） |
| `https://www.oppo.com/cn/`（**容器内 / 控制台项目 `Ledger`**） | `acceptance_ready: true`，会话 `7445c72d02948680` | 缺失 5 项安全响应头（low）、ACAO `*`（low）、`server: openresty`（info） |

第三条是在 8700 那个控制台里、落到已有项目 `Ledger` 上跑的，会话与报告在页面上直接可查。

两种 CORS 结论的差别要看清：`ACAO: *` 且不带凭证只是 low（任意站点能读匿名内容）；`ACAO: <回显来源> + ACAC: true` 才是 high（登录态可被跨域读取）。规划器按实际响应头分档，不是一律判高。

CORS 那条在 HTTP 层复核过：

```
access-control-allow-origin: https://nianyun-probe.example
access-control-allow-credentials: true
vary: Origin,Access-Control-Request-Method,Access-Control-Request-Headers
```

回显是真实的（不是工具臆造）。但**定级要人工过一遍**：同一套 CORS 回显作用在纯静态 HTML 上是中低危，作用在带用户态的接口（`mall-api` 那类）上才是高危——这正是之前 H-04 复核时的结论，报告里的 `high` 只代表规划器的初始判定。

## 4. 怎么用

```bash
# config.yaml: execution.mode: execute
# tools.env.yaml: BURP_PROXY_URL 置空、BURP_PROXY_REQUIRED 置 "false"
node dist/control/cli.js run https://example.com/ --project demo-run
```

产物在 `data/projects/<project_id>/`：

- `report.md` — 任务覆盖 + 候选发现与复核（给人看）
- `summary.json` — 同一份结论的结构化版本（给脚本看）
- `run.json` — 本次 run 的元信息（目标、会话、停止原因、验收是否通过、耗时）

### 落到控制台里正在看的那个项目

控制台默认跑在容器里（`nianyun-control-nianyun-1`，数据在 `nianyun-data` 卷），宿主上的 `data/` 与它无关。要在 8700 那个项目里落一次真实 run：

```bash
# 1) 把新代码放进容器（临时生效；容器被重建后需重做，长期生效要 docker compose build nianyun）
docker cp dist/. nianyun-control-nianyun-1:/opt/nianyun/dist/

# 2) 容器里的环境文件：容器没有公网直连能力，必须借宿主的 Burp/代理出网
docker cp tools.env.yaml nianyun-control-nianyun-1:/opt/nianyun/tools.env.yaml
#    BURP_PROXY_URL: "http://host.docker.internal:8080"   ← 宿主 8080 上的 Burp
#    BURP_PROXY_REQUIRED: "false"                        ← 缺代理时不阻塞，但不配就出不去

# 3) 指定项目 id 落会话；--fresh 强制新会话（默认复用同候选的旧会话）
docker exec -e NIANYUN_MODE=execute nianyun-control-nianyun-1 \
  node dist/control/cli.js run https://www.oppo.com/cn/ --project-id p_06db586d65 --fresh
```

验证就走控制台自己的接口（和页面读的是同一份数据）：

```bash
curl -s http://127.0.0.1:8700/api/projects/p_06db586d65/blackbox-sessions/7445c72d02948680
curl -s "http://127.0.0.1:8700/api/projects/p_06db586d65/blackbox-sessions/7445c72d02948680/report?format=markdown"
```

> 为什么容器必须走代理：容器内 DNS 正常、TCP 能连（Docker Desktop 的拦截器会立刻接受连接），但真正的 HTTPS 全部失败——`fetch failed` 几毫秒返回，Playwright 则卡到 20s 超时。实测只有 `host.docker.internal:8080`（宿主 Burp）能出网。

## 5. 测试

`npx vitest run`：93 个文件 / 772 条，767 通过，2 跳过，3 失败。三条失败与本次改动无关：

- `test/assets.test.ts`、`test/candidates.test.ts` — 把 `src` 改动 stash 掉后同样失败（既有问题）。
- `test/sandbox-service.test.ts` — Windows 上临时目录 `EBUSY`，并发跑复现、单跑通过（环境问题）。

改动本身的验证方式是两次实跑：验收门禁 `ready: true`，五个规划任务全部 `completed`，发现经 Observer 复核为 `confirmed`。
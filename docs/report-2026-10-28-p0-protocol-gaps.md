# P0/P1/P2 三个致命空洞的填补 + 镜像链路修复

**上一轮**：[四个协议的修复](report-2026-10-28-protocol-hardening.md) · **审计**：[§47](agent-constraints-audit.md)
**本轮实测全部跑在真实会话 `1cdf92d4816b72bf`（note.yun）与真实镜像 `nianyun:control` 上**，不是构造用例。

---

## 0. 结论先行

| 项 | 改之前 | 改之后（实测） |
|---|---|---|
| `required_tasks` 被丢的回执 | `(item): Invalid input` | `required_tasks[2]: 缺 deliverables；correct_shape_example` 可照抄 |
| `diff_score=0` 的处理 | 只把分数交回模型 | 连续 2 次 → 任务 `blocked(zero_entropy_diff)` + 焦点转移 |
| 历史会话复盘 | 241 个 untested 节点的尸检报告 | `POST …/replay-protocols` 一次算出 4 条结论（43 调 → 15 调） |
| SPA 缴械后的写法 | 只说"用 Playwright" | 上下文里直接给可执行骨架（`exec.python`，只填 URL） |
| 字典抽样之后 | 看到 200 也不知道下一步 | 200 展开同类 3 条 / 412 整类标灰 |
| 部署 | `docker cp` 进活容器（重启即回退） | `docker build` 真构建 → 不可变镜像 → `compose up` |
| `docker build` | `mount options is too long`（不可用） | 可用（根因：基础镜像 480 层，已压平成 1 层） |

---

## 1. P0-1 结构化校验回执

### 病根
`agent.ts` 的 `salvageItems` 把 zod issue 拼成字符串：`issue.path.join(".") || "(item)"`。
union 全灭时 path 为空 → 永远输出 `(item): Invalid input`。note.yun 那轮 `required_tasks` 被丢了 13 条，
模型只能整条重写，于是同一件事被声明 8 次（`merged_from: ["T1"×8]`），上下文被自己的复述撑爆。

### 改法
新模块 `src/blackbox/validation-envelope.ts`：

```ts
rejectEnvelope(snapshotIssues(issues), { field, index, example })
→ { status: "rejected", reason: "schema_validation_failed",
    target: "required_tasks[2]",
    missing_keys: ["deliverables", "success_criteria"],
    invalid_keys: { priority: "expected number, got string" },
    unknown_keys: ["priority_hint"],
    correct_shape_example: { id: "T_x", deliverables: ["js_content"], … },
    hint: "required_tasks[2]：缺字段 deliverables；只改这一条，其它条目不用重写。" }
```

三个判断是关键：

1. **`invalid_type` + `received === "undefined"` 归为"缺键"**，不是"值错"——两者修法不同（补键 vs 改值）；
2. **union 全灭时选"最接近成功"的一支**（缺键最少的 branch）来报告，而不是把三支的错误全倒出来；
3. `correct_shape_example` 取 `fieldGuide`/`toolGuide` 里的真实示例，模型照抄即可过。

`RejectEnvelope` 扩展了 `target / missing_keys / invalid_keys / unknown_keys / correct_shape_example`，
`message` 改为结构化摘要（`tool_requests[0]: 多 params`），事件里同时保留 `dropped_keys` 兼容既有读者。

**测试**：`test/protocol-p0-p1.test.ts` 前 5 条（缺键/值错/未知键/union 择优/条目级错误）。

---

## 2. P0-2 零熵熔断（diff_score=0 一票否决）

`desk.ts` 在 `recon.traffic_diff` 返回后维护 `state.zero_diff_streak`：

| 条件 | 行为 |
|---|---|
| `status === "identical"` | 计数 +1 |
| 计数 ≥ 2 | 当前任务 `status=blocked`、`reason=zero_entropy_diff`；焦点转给下一个未打的聚类探针；写 `zero-entropy-stop` 事件；计数归零 |
| 其它结果 | 计数归零 |

设计取舍：**不等到 8 轮微观预算**（那 8 轮在这类目标上全是重复包），两次相同就收口；
但也不判"整场结束"——只收这条任务，焦点交给下一个探针，避免一个死胡同拖垮整轮。

---

## 3. P0-3 协议回填（Offline Replay）

`src/blackbox/replay_protocols.ts` + `POST /api/projects/:pid/blackbox-sessions/:sid/replay-protocols`。

只读：拿账本里的 tool-result 事件，按时间顺序喂给 `redirectOf / applySovereignty`、`spaFingerprint`、
`planProbes / probeTask`，**不改历史状态**，结论写成 `historical_inference` 事件（`data.replay=true`，前端可画虚线）。

### 真实会话上的输出（第一次跑就抓到两个真缺陷）

```
tool_results=43  calls_actual=43  calls_with_protocols=15
[sovereignty_transfer] call#2:  note.yun.oppo.com 301 → cloud.oppo.com
[spa_disarm]          call#5:  cloud.oppo.com 是 5158B SPA 外壳（framework:vuei、inline:4、external:7）
[dict_collapse]       call#15: 一次吐出 224 个端点 → 折叠成 4 个探针（/.env~、/redoc、/admin、/db）
[traffic_waste]       重复请求：http://note.yun.oppo.com/ 共 18 次 → 新协议下 17 次会被拒收
```

### 回放抓出的两个真 bug（不跑真实数据永远发现不了）

| # | 缺陷 | 后果 | 修法 |
|---|---|---|---|
| 1 | `spaFingerprint` 只读顶层 `data.content_type` | 真实 tool-result 的 mime 在 `headers["content-type"]` → **线上永不触发缴械** | 读 `headers` 里的 content-type（`data.mime` 兜底） |
| 2 | SPA 判据要求 `external_scripts <= 1` | 真实外壳有 **7 个** `<script src>` → 判不出来 | 改为"可见正文占比 < 12% + ≥2 个打包产物"，或经典挂载点 |

第 2 条尤其说明问题：上一轮我写"5158B 外壳 0 个外部 script"，那是 `recon.js_endpoints` 的
`no_script_references` 报错文案，**不是事实**。真实响应有 7 个外链脚本、4916 字符正文里可见文字不足 5%。
新判据在真实响应上：`text_ratio:0.01 / bundles:7 / framework:vuei → is_spa=true`；
在一篇正常 SSR 文档页上 `text_ratio` 高 → `is_spa=false`（测试同时钉这两条）。

---

## 4. P1-1 特种兵骨架

`src/blackbox/specialist_kits.ts`，两份模板：

| id | 工具 | 用途 |
|---|---|---|
| `spa_xhr_capture` | `exec.python` | Playwright 抓 XHR/fetch，`wait_until=networkidle` + 3s 兜底等待，输出 `{title, html_bytes, apis[], total_requests}` |
| `spa_inline_constants` | `exec.python` | 零依赖正则抠 `apiBase/baseURL` 常量，比渲染快 |

注入位置：`context.spa_mode.kit`（**不是** system prompt 全文）——只在 SPA 命中时出现，附 `deliverable`
（"至少 1 条带 method 的真实接口路径"）与 3 条注意事项（容器里要先 `playwright install`、
networkidle 之后还要等、拿到 url 立刻用 `http.request` 复核）。

---

## 5. P1-2 聚类展开/收敛

`cluster.ts` 新增纯函数 `expandFromProbe(plan, outcome, { limit })`：

| 探针结果 | 判定 | 动作 |
|---|---|---|
| 200 / 30x（非同形） | `expand` | 同类剩余 3 条 → `forced_focus` 指向该任务，`dict_probe.buckets` 就地改写为下一批 |
| 401 / 403 | `expand` | 同上，但记为"鉴权墙" |
| 412 / 418 / 1020 / 命中 WAF 页 | `collapse` | 同类剩余**全部** `status=blocked` + `wall=cluster_collapsed` |
| 与 catch-all 基线同形 | `collapse` | 存在性不可判定，整类标灰 |
| 404 等 | `skip` | 换下一个类别代表 |

落地时有 `cluster-expand` / `cluster-collapse` 两类事件，标灰的节点数就是"省掉的调用数"。

---

## 6. P2 镜像链路：从 `docker cp` 到真构建

### 6.1 根因（不是"COPY 太多文件"）

```
$ docker image inspect nianyun:control → layers: 480, size 11.95 GB
$ docker build … → failed to solve: mount options is too long
$ docker run  (482 层镜像) → failed to mount /var/lib/docker/rootfs/overlayfs/…: mount options is too long
```

containerd/overlayfs 把每一层写成 `lowerdir=` 的一项。**480 层时这个字符串已经贴到上限**：
481 层还能跑，482 层连容器都起不来。所以：
- `COPY dist/` 能过、紧接着 `COPY console/spa/` 就炸（同一 build 里层数在增长）；
- 换成一个 `ADD tar` 之后，又在后面的单文件 `COPY` 上炸；
- `DOCKER_BUILDKIT=0` 走 legacy builder 也一样（报错从 `failed to solve` 变成 `failed to mount`）。

### 6.2 修法：压平基础镜像

`scripts/flatten-image.cjs`（node 直调 docker，避免 PowerShell 吃引号）：

```
export 根文件系统 → 8.21 GB tar（181.5 s）
docker import + 逐条 --change 重建 config（37 条指令，ENV×31 / WORKDIR / ENTRYPOINT / EXPOSE /
  HEALTHCHECK / LABEL）（629 s）
→ nianyun:control-flat：1 层 / 11.52 GB，ENTRYPOINT ["/usr/local/bin/nianyun-control"]，健康检查在
```

自检：起容器 → `/health=true`，`dist/control/console/http.js` 与 `console/spa/index.html` 在，
`httpx/nuclei/ffuf/subfinder/katana/naabu/gau/dnsx` 八个工具全在 PATH。

之后 `docker build -f deploy/control/Dockerfile.dist` **1 秒级通过**，产出 22 层镜像。

### 6.3 部署脚本（`scripts/deploy-image.ps1`）

| 基础镜像层数 | 路径 |
|---|---|
| ≤ 64 | `docker build -f deploy/control/Dockerfile.dist`（真构建、可复现、CI 同款） |
| > 64 | `docker create` → `docker cp` → `docker commit`（老机器的兜底，会打印警告让人去压平） |

两条路都以 `docker compose -p nianyun-control up -d --no-deps --force-recreate` 收尾，
再用 `/health` + 镜像 label（`nianyun.build.strategy` / `org.opencontainers.image.revision`）验证，
并打印回滚命令。回滚点用 `docker tag`（秒级，不复制层）。

**为什么必须走镜像而不是 cp+restart**：cp 进活容器后，镜像里还是旧代码，`docker restart` 就回退；
镜像方案里构建产物是镜像的一层，重启、recreate、别人拉这个 tag 都是同一份代码。

### 6.4 CI 守卫（`.github/workflows/image.yml`）

| job | 内容 |
|---|---|
| `typecheck-and-test` | `tsc --noEmit` + `npm run build` + 清单必须与 dist 对齐（`git diff --exit-code`）+ 全量 vitest |
| `build-fast` | `Dockerfile.fast` **`--no-cache`** 构建 + 起容器冒烟（`/health`、四个协议模块存在） |
| `build-full` | 手动/每周：`Dockerfile` 全量构建 + 八个扫描器 `command -v` 校验（防 PD 版本与 SHA 腐坏） |

CI 的意义在于：本机的层数上限是环境事故，CI 里没有这个包袱，所以"真构建"放 CI 兜底。

---

## 7. 测试

| 文件 | 用例 | 增量 |
|---|---|---|
| `test/protocol-p0-p1.test.ts` | 17 | 回执 5 + 展开 4 + 骨架 3 + 回填 5 |
| `test/protocol-hardening.test.ts` | 18 | +2（真实 5158B 外壳判 SPA、正文占比高的 SSR 页不判）、改写 1（旧期望写反的 bundle 用例） |
| `test/note-yun-replay.test.ts` | 5 | — |
| `test/blackbox-tool-access.test.ts` | 21 | 断言从"zod 原文含 unrecognized"改为"结构化字段含 params" |

全量：**90 文件通过 / 762 用例通过 / 2 skipped / 2 失败**（`assets`、`candidates`，本轮之前就红）。

---

## 8. 本轮自造缺陷（12 个，全部照实记）

| # | 缺陷 | 怎么发现 | 根因 |
|---|---|---|---|
| 1 | 回填路由写成 `parts.length === 5` | 真调用返回 `{"ok":false,"error":"not found"}` | `projects` 前缀在更早的 split 已被吃掉，实际是 4 段 |
| 2 | staging 把 dist 放在根上 | 容器起来报 `missing /opt/nianyun/dist/control/cli.js` | `ADD tar /` 是按归档内路径落地的，staging 必须镜像绝对路径 |
| 3 | `--change 'ENTRYPOINT ["/usr/local/bin/nianyun-control"]'` | 容器报 `[/usr/local/bin/nianyun-control]: not found` | PowerShell 吃掉内层双引号，写成字面量；且 `docker create … /bin/true` 把 Cmd/ENTRYPOINT 一起污染，还把坏镜像打成了 `nianyun:control` → 靠 `control-prev-*` 回滚标签恢复 |
| 4 | `HEALTHCHECK CMD-SHELL` 走 `docker import --change` | `Unknown type "CMD-SHELL"` | import 只认 `CMD` |
| 5 | 时长直接透传 | `missing unit in duration "20000000000"` | image config 里是纳秒，docker 要 `20s` |
| 6 | 压平后直接连叠两层（482 层） | 容器起不来，服务中断 ~2 分钟 | 481 层是硬上限，部署脚本没做层数预检 → 现在先读 `len(.RootFS.Layers)` 再选路径 |
| 7 | SPA 判据 `external_scripts <= 1` | 回放真实会话时判不出来 | 上一轮把 `js_endpoints` 的 `no_script_references` 当成"没有外链脚本"，事实是 7 个 |
| 8 | SPA 只读顶层 `content_type` | 回放判不出来 | 真实数据里 mime 在 `headers` |
| 9 | 回填只找 `endpoints/hits/paths` | 224 条的字典轮被漏掉 | 真实键名是 `items`（ffuf），`entries` 是 burp 流量（不该算字典） |
| 10 | `items` 当对象处理 | 路径全是空串 | ffuf 的命中是**字符串**数组 |
| 11 | 路径归一化 `//.env` | 探针名荒唐 | `host/path` 形态没有剥 host |
| 12 | 两次改测试用 `String.replace` 多行块，静默没生效 | 测试仍跑旧期望 | 中文全角/换行差异；改成按行号 splice |

规律：**12 个里 9 个是"改完没在真实数据上验"**（1、2、7、8、9、10、11 + 3 的两次），
2 个是环境本身（5、6），1 个是工具链怪癖（4）。
`5→6` 这一对尤其典型：压平是"修 bug"，但压平后的第一次部署又造出了新的上限问题。

---

## 9. 现在的状态

| 项 | 值 |
|---|---|
| 容器 | `nianyun-control-nianyun-1`，`Up (healthy)` |
| 镜像 | 22 层，label `nianyun.build.strategy=dist-overlay`，`revision=d936884` |
| 核算 | `/health=true`；`historical_inference=10`、`protocol-backfill=5` 已落账 |
| 数据 | 10 个会话 / 5148 事件 / note.yun 图仍 241 节点 239 边（未受影响） |
| 回滚 | `pwsh scripts/deploy-image.ps1 -Rollback nianyun:control-prev-20261028-175650` |

## 10. 仍未做

1. **`zero_entropy` 与 `plateau` 的联动**：现在零熵只收单任务，`convergeFocus` 的全局收口仍是独立判断，两者没有合并成一个"这轮没信息量"的统一信号。
2. **回填事件的渲染**：`historical_inference` 已进事件流，但 `visual.ts` 还没给它做虚线/半透明样式，图谱上看不出"这是推演不是事实"。
3. **展开规则的第二跳**：`expand` 只推一批 3 条，第二批回来是否继续展开仍靠下一轮抽样，没有做"按类别递归"。
4. **`required_tasks` 丢条目的上游**：结构化回执解决"看不懂"，但 note.yun 那 13 条为什么**一开始**不合法（缺 `deliverables` 还是 union 选错分支）还没逐条归因。
5. **CI 未真正跑过**：`image.yml` 是本轮新写的，本机无法执行 GitHub Actions，只能静态自检（YAML 结构、job 依赖、命令存在）。
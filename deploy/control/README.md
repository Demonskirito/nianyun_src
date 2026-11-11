# 控制面镜像：构建矩阵与纪律

本目录有三个 Dockerfile，它们不是"多个方案"，而是**一条约束链上的不同档位**。
选错档位的代价很具体：用错一次就可能把镜像层数堆到内核上限，之后**任何**容器都起不来。

## 一、先认清约束

| 依赖 | 现状（2026-11-06 实测） | 影响 |
|---|---|---|
| `mirrors.aliyun.com/debian` | ✅ 200 | apt 可用 |
| `registry.npmmirror.com` | ✅ 200 | npm 可用 |
| `github.com` | ❌ **000 不可达** | **8 个扫描器、go 工具、testssl/jwt_tool/graphql-cop 全部装不了** |
| `node:22.22.0-bookworm-slim` | ✅ 本地已有 329MB | `FROM` 不需要网络 |

**结论：全量构建（`Dockerfile`）现在跑不通，卡在 GitHub。** 这不是配置问题，
不要靠"再试一次"解决；要么修好出网，要么走 overlay 档位。

## 二、四个档位

| 文件 | 干什么 | 需要网络 | 层数增量 | 什么时候用 |
|---|---|---|---|---|
| `Dockerfile` | 三阶段全量：工具链 + `npm ci` + 编译 + 运行时 | **需要 GitHub** | 20~30 层 | 新增扫描器、apt 包、node 大版本；**且 GitHub 可达** |
| `Dockerfile.dist` | 在已有 base 上只换 `dist/` 与 SPA，带 LABEL 追溯 | 不需要 | 2 层 | 需要"这批 dist 是哪来的"时；需先打 `nianyun-dist.tar` |
| `Dockerfile.fast` | 复用 base 但重跑 `tsc` + console build | 需要 npm | 4~6 层 | 只想改 TS/前端、不想动工具链 |

> `Dockerfile.dist` 接受 `--build-arg BASE_IMAGE=...` 并写入 LABEL（commit / 构建时间），
> 能追溯"这层 dist 是哪来的"；日常部署走 `scripts/deploy-image.ps1`。

## 三、日常部署（99% 的场景）

**用脚本，不要手敲。** `scripts/deploy-image.ps1` 已经把"构建产物进镜像 + 带日期 tag +
重建容器 + 健康校验"串好了，并且能回滚：

```powershell
pwsh scripts/deploy-image.ps1              # tsc → 镜像 → 重建容器 → 健康校验
pwsh scripts/deploy-image.ps1 -SkipBuild   # dist 已是最新，只做镜像
pwsh scripts/deploy-image.ps1 -Rollback nianyun:control-prev-<stamp>
```

`Dockerfile.dist` 是这条路线的声明式等价物，需要 `--build-arg BASE_IMAGE` 并预先生成
`nianyun-dist.tar`（仓库里有 `.dockerignore` 的放行规则，但**没有打包脚本**，
现存的那份 tar 是 10-29 的陈旧归档）。想要 LABEL 追溯时再走它，日常用上面的脚本。

两条纪律，违反任何一条都会把层数推向事故线：

1. **镜像不可变**：`nianyun:control` 只是一个"当前指向"的别名。每次产出新镜像都带日期 tag，
   回滚就是把别名指回上一版；反复把新镜像打成同一个 tag，等于把所有历史层串成一条链。
2. **每部署一次就多一层，必须有回收动作**。`commit` 路线本身是可接受的（产物进镜像、可回滚），
   真正的问题是只增不减 —— 见第五节。

## 四、什么时候必须重建 base

只在这三种情况下才需要跑全量 `Dockerfile`：

- 新增/升级扫描器（`HTTPX_VERSION` 等 ARG）；
- 新增 apt / pip / gem 包；
- node 主版本变更。

前置条件是 **GitHub 可达**（`curl -o /dev/null -w '%{http_code}' https://github.com` 返回 200）。
恢复后：

```bash
docker build -f deploy/control/Dockerfile -t nianyun:control-base-$(date +%Y%m%d) .
# 跑通后把日常部署的 BASE_IMAGE 指向它
```

`Dockerfile` 里每个下载都带 sha256 校验（`sha256sum -c -`），版本号全部走 ARG，
不允许 `latest` —— 保证同一份 Dockerfile 在任何时候重建出同一个镜像。

## 五、层数：必须监控的硬指标

**实测边界：481 层能跑，482 层直接失败**（`scripts/flatten-image.cjs` 与
`scripts/deploy-image.ps1` 的注释里各记了一次，2026-10-29 那次踩的就是 482 层）。
不要用"每层多少字节 ÷ 4095"去推算 —— 实际告警点远高于此，照实测值管。

```bash
# 检查（超过 400 层就该安排扁平化，别等 482）
docker history nianyun:control --format '{{.ID}}' | grep -c .
```

超限后的症状是 `failed to mount ...: mount options is too long`，
**`docker build` 与 `docker run` 同时失效**，但已运行的容器仍健康（挂载已建立，不重新解析）。
重启 Docker Desktop、清 build cache 都试过，**无效**——它不是 daemon 状态问题。
（唯一还"有效"的副作用是清 cache 会给 import 腾出空间。）

### 应急扁平化（break-glass）

**用 `scripts/flatten-image.cjs`，不要手写 `docker export | import`。** 脚本已经处理了三个
会让人排查半天的坑：`--change` 要逐条重建 config、PowerShell 会吃掉
`ENTRYPOINT ["..."]` 里的双引号、`docker import` 只认 `HEALTHCHECK CMD`。

```bash
node scripts/flatten-image.cjs                          # 生成 nianyun:control-flat
node scripts/flatten-image.cjs --tag nianyun:control   # 压平并顶替当前 tag
```

它内部做的事：对运行中的容器 `docker export`（合并视图）→ 从 `Config` 逐条生成
`--change ENV/WORKDIR/ENTRYPOINT/HEALTHCHECK` → `docker import` 成单层 → 校验。
`docker export` 只需要停止写入，不需要停容器；但**稳妥起见先 `docker commit` 一份备份**：

```bash
docker commit <容器> nianyun:control-before-flatten-$(date +%Y%m%d)   # 只加可写层，几 MB
node scripts/flatten-image.cjs --tag nianyun:control-flat-$(date +%Y%m%d)
docker run --rm --entrypoint node nianyun:control-flat-$(date +%Y%m%d) -e "console.log('ok')"
```

**验证能起之后才切 tag**。`docker import` 不继承元数据，所以 `ENV`（30 项，含 `PATH`、
各扫描器路径、pip 镜像）必须逐项还原：漏 `PATH` 直接起不来，漏 `*_PATH` 会让工具全部
静默不可用。只还原**镜像自带**的变量，compose 注入的密钥类变量不要写进镜像。

切完 tag 后 `docker compose -f compose.control.yaml up -d --force-recreate --no-build nianyun`，
再确认一次 health 与数据卷（`/opt/nianyun/data` 是 named volume，扁平化不影响它）。


## 六、事故记录：这是第二次

| 时间 | 层数 | 结果 | 处置 |
|---|---|---|---|
| 2026-10-29 | 482 | `docker build` 失败 | 当天写了 `scripts/flatten-image.cjs`，压到 1 层 |
| 2026-11-06 | **548** | `docker build` **与 `docker run` 同时**失败 | 再压到 1 层（12.4GB），还原 30 个 ENV，切 tag + `--force-recreate` |

两次之间隔了 8 天，层数从 1 涨回 548。**工具已经有了，坏的是没有人定期看这个数**——
所以这份文档把阈值写成了明确动作（超过 400 层就安排扁平化），而不是"注意层数"。

第二次的症状比第一次更重：第一次只是 `build` 失败（`commit` 路线还能用），
第二次连 `docker run --rm` 都起不来，意味着**新建容器这条路径整体失效**——
现役容器一旦被删除或 `--force-recreate`，服务就再也起不来。当时是靠容器还活着撑住的。

第一次事故的处置脚本 `flatten-image.cjs` 里还留着一条实测结论：层数与"COPY 条目数"无关，
换 tar、换 legacy builder 都救不了，只能压平。这条省了第二次白折腾一轮。

## 七、日常检查清单

```bash
docker history nianyun:control --format '{{.ID}}' | grep -c .   # 层数 > 400 就该动手
docker images nianyun:control --format '{{.Size}}'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8700/health   # 期望 200
```

层数只在"部署"时增长。如果发现它无故上涨，去看 `deploy-image.ps1` 与 `inject` 构建
是不是被反复调用、且每次都覆盖同一个 tag。


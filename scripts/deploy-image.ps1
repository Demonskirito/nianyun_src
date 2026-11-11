# 部署 control plane：把 dist 做成**不可变镜像**再重建容器（不再 cp 进活容器）
#
#   pwsh scripts/deploy-image.ps1               # tsc → 镜像 → 重建容器 → 健康校验
#   pwsh scripts/deploy-image.ps1 -SkipBuild    # dist 已是最新，只做镜像
#   pwsh scripts/deploy-image.ps1 -Rollback nianyun:control-prev-<stamp>
#
# 为什么不是 docker build
# ----------------------
# 本机 nianyun:control 有 **480 层**（11.95 GB，工具链一点点叠出来的）。containerd
# overlayfs snapshotter 把它拼成 `lowerdir=` 时已经贴到 mount options 上限，于是**任何**
# 新增构建步骤都会失败：
#     failed to solve: mount options is too long
#     failed to mount /tmp/containerd-mount731127947: mount options is too long
# 换目录为单个 ADD tar、换 legacy builder（DOCKER_BUILDKIT=0）都试过，同样报错 ——
# 说明它与"COPY 的条目数"无关，就是层链长度。要彻底修得把基础镜像压成单层（见文末）。
#
# 在压缩之前，这里用 commit 路线：
#   起一个**不启动**的临时容器 → docker cp 构建产物进去 → docker commit 出一个新镜像
#   （只多 1 层，实测 481 层仍能正常启动）→ compose 用新镜像重建。
# 与旧做法的区别：构建产物进了镜像，`docker restart` 不会退回旧代码，镜像可回溯、可回滚、
# 可被 CI 用同一个 tar 复现。
#
# 彻底修复（一次性，之后 docker build 恢复正常）：
#   docker create --name flat nianyun:control
#   cmd /c "docker export flat > E:\tmp\flat.tar"
#   docker import --change 'WORKDIR /opt/nianyun' --change 'ENTRYPOINT ["/usr/local/bin/nianyun-control"]' `
#     E:\tmp\flat.tar nianyun:control-flat
#   docker tag nianyun:control-flat nianyun:control
# 压平后层数 480 → 1，overlay 的 lowerdir 不再超长，docker build 立刻恢复。

[CmdletBinding()]
param(
  [switch]$SkipBuild,
  [string]$Rollback,
  [string]$Project = "nianyun-control",
  [string]$Service = "nianyun",
  [string]$ComposeFile = "compose.control.yaml",
  [int]$HealthTimeoutSeconds = 120
)

# Windows PowerShell 5.1 会把 native 命令写 stderr 当成 NativeCommandError；
# docker build / docker cp 的进度日志本来就走 stderr，配合 "Stop" 会在成功时中断部署。
# 这里改成 Continue，失败判定统一交给 Step 的 $LASTEXITCODE 与脚本里的显式 throw。
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Get-NodeExe {
  $candidates = @(
    @(
      $env:DSH_NODE,
      "C:\Users\$env:USERNAME\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }
  )
  if ($candidates.Count -gt 0) { return [string]$candidates[0] }
  return "node"
}
$node = Get-NodeExe

function Step($label, $block) {
  Write-Host "==> $label" -ForegroundColor Cyan
  & $block
  if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw "$label 失败（exit $LASTEXITCODE）" }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$gitRev = "untracked"
try { $rev = git rev-parse --short HEAD 2>$null; if ($rev) { $gitRev = $rev.Trim() } } catch { }

if ($Rollback) {
  Step "回滚：把 $Rollback 重新打成 nianyun:control" { docker tag $Rollback nianyun:control | Out-Null }
  $prevTag = "（本次是回滚）"
} else {
  if (-not $SkipBuild) {
    Step "构建 TypeScript（tsc）" { & $node node_modules\typescript\bin\tsc -p tsconfig.json }
    Step "重建工具清单（读 dist，必须在 tsc 之后）" { & $node scripts\gen-tool-manifest.mjs | Out-Null }
  }
  if (-not (Test-Path dist\control\console\http.js)) { throw "dist 不完整：先跑 tsc（去掉 -SkipBuild）" }

  $prevTag = "nianyun:control-prev-$stamp"
  Step "记回滚点 $prevTag（秒级 tagging，不复制层）" { docker tag nianyun:control $prevTag | Out-Null }

  $nextTag = "nianyun:control-next-$stamp"

  # 基础镜像层数决定走哪条路：
  #   ≤16 层 → 直接 docker build（真构建、可复现、CI 同款）
  #   >16 层 → 这台机器的 overlay 会报 mount options is too long，退回 commit 路线
  $baseLayers = [int](docker image inspect nianyun:control --format '{{len .RootFS.Layers}}')
  Write-Host "    基础镜像 $baseLayers 层" -ForegroundColor DarkGray

  if ($baseLayers -le 64) {
    Step "打包 dist / console-spa / entrypoint 为单个归档" {
      # staging 必须**镜像容器里的绝对路径**：ADD tar 到 / 之后文件才会落在
      # /opt/nianyun/dist、/opt/nianyun/console/spa、/usr/local/bin/nianyun-control。
      # 第一版把 dist 放在 staging 根上，结果进了 /dist —— 容器起来报
      # "missing /opt/nianyun/dist/control/cli.js"（本轮实测踩过）。
      $stage = ".layer-out/image"
      if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
      New-Item -ItemType Directory "$stage\usr\local\bin" -Force | Out-Null
      New-Item -ItemType Directory "$stage\opt\nianyun\data\config" -Force | Out-Null
      New-Item -ItemType Directory "$stage\opt\nianyun\console" -Force | Out-Null
      Copy-Item dist "$stage\opt\nianyun\dist" -Recurse -Force
      if (Test-Path console\spa) { Copy-Item console\spa "$stage\opt\nianyun\console\spa" -Recurse -Force }
      Copy-Item deploy\control\entrypoint.sh "$stage\usr\local\bin\nianyun-control" -Force
      if (Test-Path nianyun-dist.tar) { Remove-Item nianyun-dist.tar -Force }
      & tar -cf nianyun-dist.tar -C $stage .
      if ($LASTEXITCODE -ne 0) { throw "tar 打包失败" }
    }
    Step "docker build -f deploy/control/Dockerfile.dist" {
      docker build -f deploy/control/Dockerfile.dist `
        --build-arg "BASE_IMAGE=nianyun:control" `
        --build-arg "GIT_REV=$gitRev" `
        --build-arg "BUILT_AT=$(Get-Date -Format o)" `
        -t $nextTag .
    }
  } else {
    Write-Host "!! 基础镜像 $baseLayers 层，走 commit 路线（先跑 node scripts/flatten-image.cjs --tag nianyun:control 压平）" -ForegroundColor Yellow
    Step "起临时容器并灌入构建产物" {
    docker rm -f nianyun-dist-stage 2>$null | Out-Null
    # 不要给 create 传命令：传了就会改 Cmd（甚至被踩成 ENTRYPOINT 字面量），
    # 而 commit 会把这个 config 一起继承下去。不传 = 完全继承基础镜像的 ENTRYPOINT/CMD。
    $cid = docker create --name nianyun-dist-stage nianyun:control
    if (-not $cid) { throw "docker create 失败" }
    docker cp "dist/." "nianyun-dist-stage:/opt/nianyun/dist/" | Out-Null
    if (Test-Path console\spa) { docker cp "console/spa/." "nianyun-dist-stage:/opt/nianyun/console/spa/" | Out-Null }
    docker cp "deploy/control/entrypoint.sh" "nianyun-dist-stage:/usr/local/bin/nianyun-control" | Out-Null
    }

    # 只改 LABEL：ENTRYPOINT/WORKDIR/EXPOSE 由 docker create 从基础镜像继承，
    # 不在这里重写 —— PowerShell 会把 --change 'ENTRYPOINT ["..."]' 里的双引号吃掉，
    # 结果写成字面量 [/usr/local/bin/nianyun-control]，容器起不来（本轮实测踩过）。
    Step "commit 成镜像 $nextTag" {
      docker commit `
        --change "LABEL org.opencontainers.image.revision=$gitRev" `
        --change "LABEL org.opencontainers.image.created=$(Get-Date -Format o)" `
        --change "LABEL nianyun.build.strategy=dist-commit" `
        nianyun-dist-stage $nextTag | Out-Null
    }

    Step "清理临时容器" { docker rm -f nianyun-dist-stage 2>$null | Out-Null }
  }

  Step "把新镜像切成 nianyun:control" { docker tag $nextTag nianyun:control }
}

Step "用新镜像重建容器（--force-recreate，不用 cp、不用 restart）" {
  docker compose -p $Project -f $ComposeFile up -d --no-deps --force-recreate $Service
}

Write-Host "==> 等 /health（最多 ${HealthTimeoutSeconds}s）" -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
$healthy = $false
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 3
  try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8700/health" -TimeoutSec 5
    if ($health.ok) { $healthy = $true; break }
  } catch { }
}
$container = "$Project-$Service-1"
if (-not $healthy) {
  Write-Host "!! /health 未通过，容器日志尾部：" -ForegroundColor Red
  docker logs --tail 40 $container
  Write-Host "回滚：pwsh scripts/deploy-image.ps1 -Rollback $prevTag" -ForegroundColor Yellow
  throw "部署失败"
}

$imageId = (docker inspect $container --format '{{.Image}}')
$labels = docker image inspect $imageId | ConvertFrom-Json
$layers = $labels[0].RootFS.Layers.Count
Write-Host ""
Write-Host "部署完成" -ForegroundColor Green
"  容器          $container"
"  镜像          $($imageId.Substring(7, 12))（$layers 层）"
"  构建策略      $($labels[0].Config.Labels.'nianyun.build.strategy')"
"  镜像内 commit $($labels[0].Config.Labels.'org.opencontainers.image.revision')"
"  回滚标签      $prevTag"
Write-Host ""
Write-Host "回滚：pwsh scripts/deploy-image.ps1 -Rollback $prevTag" -ForegroundColor DarkGray

#!/usr/bin/env node
/**
 * 把 480 层的 nianyun:control 压成单层镜像。
 *
 * 为什么必须做：containerd overlayfs 的 rootfs 挂载把每一层写成 lowerdir= 的一项，
 * 481 层时这个字符串已经贴到上限——再叠任何一层，连**容器都起不来**：
 *   failed to mount /var/lib/docker/rootfs/overlayfs/...: mount options is too long
 * 实测边界：481 层能跑，482 层直接失败（本轮部署踩到）。
 * 压平后层数 480 → 1，docker build / docker commit 全部恢复。
 *
 * 用的是 docker export（合并视图）+ docker import（单层）+ --change 逐条重建 config。
 * 注意：必须用 spawn 数组形式调 docker，PowerShell 会把 `ENTRYPOINT ["..."]` 里的
 * 双引号吃掉，写成字面量 [/usr/local/bin/nianyun-control]，容器就起不来。
 *
 * 用法：
 *   node scripts/flatten-image.cjs                 # 生成 nianyun:control-flat
 *   node scripts/flatten-image.cjs --tag nianyun:control   # 压平并顶替当前 tag
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const args = process.argv.slice(2);
const tagIndex = args.indexOf("--tag");
const targetTag = tagIndex >= 0 ? args[tagIndex + 1] : "nianyun:control-flat";
const source = process.env.FLATTEN_SOURCE || "nianyun:control";
const workDir = process.env.FLATTEN_DIR || path.join(os.tmpdir(), "nianyun-flatten");

function docker(argv, options = {}) {
  const result = spawnSync("docker", argv, { encoding: options.encoding || "utf8", stdio: options.stdio || "pipe" });
  if (result.status !== 0) {
    const stderr = String(result.stderr || "").slice(0, 800);
    throw new Error(`docker ${argv.slice(0, 3).join(" ")} 失败（${result.status}）：${stderr}`);
  }
  return result.stdout;
}

function step(label, fn) {
  const t0 = Date.now();
  process.stdout.write(`==> ${label}\n`);
  const value = fn();
  process.stdout.write(`    ${((Date.now() - t0) / 1000).toFixed(1)}s\n`);
  return value;
}

const layers = JSON.parse(docker(["image", "inspect", source]))[0];
const config = layers.Config;
process.stdout.write(`源镜像 ${source}：${layers.RootFS.Layers.length} 层 / ${(layers.Size / 1024 ** 3).toFixed(2)} GB\n`);
if (layers.RootFS.Layers.length <= 2) {
  process.stdout.write("已经是单层镜像，不需要压平\n");
  process.exit(0);
}

fs.mkdirSync(workDir, { recursive: true });
const tarPath = path.join(workDir, "rootfs.tar");
const containerName = "nianyun-flatten-src";

step("清理旧容器", () => {
  spawnSync("docker", ["rm", "-f", containerName], { stdio: "ignore" });
});

step("创建导出用容器", () => {
  docker(["create", "--name", containerName, source]);
});

step(`导出 rootfs → ${tarPath}`, () => {
  if (fs.existsSync(tarPath)) fs.unlinkSync(tarPath);
  const result = spawnSync("docker", ["export", "-o", tarPath, containerName], { stdio: "inherit" });
  if (result.status !== 0) throw new Error("docker export 失败");
  process.stdout.write(`    tar ${(fs.statSync(tarPath).size / 1024 ** 3).toFixed(2)} GB\n`);
});

step("组装 --change（逐条重建 config）", () => {
  const changes = [];
  for (const entry of config.Env || []) changes.push(`ENV ${entry}`);
  if (config.WorkingDir) changes.push(`WORKDIR ${config.WorkingDir}`);
  if (config.User) changes.push(`USER ${config.User}`);
  if (config.Entrypoint && config.Entrypoint.length) changes.push(`ENTRYPOINT ${JSON.stringify(config.Entrypoint)}`);
  if (config.Cmd && config.Cmd.length) changes.push(`CMD ${JSON.stringify(config.Cmd)}`);
  for (const port of Object.keys(config.ExposedPorts || {})) changes.push(`EXPOSE ${port}`);
  if (config.Healthcheck && config.Healthcheck.Test && config.Healthcheck.Test.length) {
    const test = config.Healthcheck.Test[0] === "CMD-SHELL"
      ? `CMD-SHELL ${config.Healthcheck.Test.slice(1).join(" ")}`
      : `CMD ${config.Healthcheck.Test.slice(1).join(" ")}`;
    const opts = [];
    if (config.Healthcheck.Interval) opts.push(`--interval=${config.Healthcheck.Interval}`);
    if (config.Healthcheck.Timeout) opts.push(`--timeout=${config.Healthcheck.Timeout}`);
    if (config.Healthcheck.StartPeriod) opts.push(`--start-period=${config.Healthcheck.StartPeriod}`);
    if (config.Healthcheck.Retries) opts.push(`--retries=${config.Healthcheck.Retries}`);
    changes.push(`HEALTHCHECK ${opts.join(" ")} ${test}`.replace(/\s+/g, " ").trim());
  }
  changes.push(`LABEL nianyun.build.strategy=flattened`);
  changes.push(`LABEL org.opencontainers.image.base.digest=${layers.Id}`);
  return changes;
});

const changes = step("读取 config", () => {
  const list = [];
  for (const entry of config.Env || []) list.push(`ENV ${entry}`);
  if (config.WorkingDir) list.push(`WORKDIR ${config.WorkingDir}`);
  if (config.User) list.push(`USER ${config.User}`);
  if (config.Entrypoint && config.Entrypoint.length) list.push(`ENTRYPOINT ${JSON.stringify(config.Entrypoint)}`);
  if (config.Cmd && config.Cmd.length) list.push(`CMD ${JSON.stringify(config.Cmd)}`);
  for (const port of Object.keys(config.ExposedPorts || {})) list.push(`EXPOSE ${port}`);
  if (config.Healthcheck && config.Healthcheck.Test && config.Healthcheck.Test.length) {
    // docker import --change 只认 `HEALTHCHECK CMD`（写 CMD-SHELL 会报 Unknown type），
    // 所以把原来 CMD-SHELL 的整条命令包成 sh -c。
    const [kind, ...rest] = config.Healthcheck.Test;
    // image config 里的时长是**纳秒**（20000000000），docker 要的是 "20s"，必须换算。
    const dur = (ns) => {
      if (!ns) return undefined;
      const seconds = Number(ns) / 1e9;
      return `${seconds % 1 === 0 ? seconds : seconds.toFixed(1)}s`;
    };
    const opts = [];
    if (config.Healthcheck.Interval) opts.push(`--interval=${dur(config.Healthcheck.Interval)}`);
    if (config.Healthcheck.Timeout) opts.push(`--timeout=${dur(config.Healthcheck.Timeout)}`);
    if (config.Healthcheck.StartPeriod) opts.push(`--start-period=${dur(config.Healthcheck.StartPeriod)}`);
    if (config.Healthcheck.Retries) opts.push(`--retries=${config.Healthcheck.Retries}`);
    const command = kind === "CMD-SHELL" ? rest.join(" ") : rest.map(part => JSON.stringify(part)).join(" ");
    list.push(`HEALTHCHECK ${opts.join(" ")} CMD ${command}`.replace(/\s+/g, " ").trim());
  }
  list.push("LABEL nianyun.build.strategy=flattened");
  list.push(`LABEL org.opencontainers.image.source=${source}`);
  return list;
});
process.stdout.write(`    ${changes.length} 条 config 指令\n`);

step(`import 成单层镜像 ${targetTag}`, () => {
  const importArgs = ["import"];
  for (const change of changes) importArgs.push("--change", change);
  importArgs.push(tarPath, targetTag);
  const result = spawnSync("docker", importArgs, { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
  if (result.status !== 0) throw new Error(`docker import 失败：${String(result.stderr || "").slice(0, 600)}`);
  process.stdout.write(`    ${String(result.stdout).trim().slice(0, 80)}\n`);
});

step("清理", () => {
  spawnSync("docker", ["rm", "-f", containerName], { stdio: "ignore" });
  if (process.env.FLATTEN_KEEP_TAR !== "1") fs.rmSync(tarPath, { force: true });
});

const flat = JSON.parse(docker(["image", "inspect", targetTag]))[0];
process.stdout.write(`\n压平完成：${targetTag} → ${flat.RootFS.Layers.length} 层 / ${(flat.Size / 1024 ** 3).toFixed(2)} GB\n`);
process.stdout.write(`ENTRYPOINT ${JSON.stringify(flat.Config.Entrypoint)}\n`);
process.stdout.write(`ENV ${flat.Config.Env.length} 条，健康检查 ${flat.Config.Healthcheck ? "有" : "无"}\n`);
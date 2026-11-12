/**
 * Build the three sandbox images in dependency order:
 *   nianyun:sandbox -> nianyun:sandbox-scanner -> nianyun:sandbox-service
 *
 * The base job image bakes in `requests`, but Docker build containers on some
 * hosts (notably behind a local HTTP proxy) cannot reach PyPI directly and the
 * Dockerfile degrades to a runtime install. Detect a local proxy and forward it
 * as predefined build args so the pre-install always happens. On hosts with
 * direct internet access nothing is injected and behaviour is unchanged.
 */
import { spawnSync } from "node:child_process";
import { createConnection } from "node:net";

const LOCAL_PORTS = [7897, 7890, 10809, 1080, 8080];
const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
const shell = process.platform === "win32";

/** Only localhost proxies need rewriting; other proxies are reachable from the build container as-is. */
function localProxyToContainer(raw) {
  if (!raw) return undefined;
  try {
    const url = new URL(raw.trim());
    if (!LOCAL_HOSTS.has(url.hostname)) return undefined;
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    return `${url.protocol}//host.docker.internal:${port}`;
  } catch {
    return undefined;
  }
}

function probe(port, timeoutMs = 500) {
  return new Promise((resolve) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

async function resolveBuildProxy() {
  const explicit = process.env.NIANYUN_BUILD_PROXY?.trim();
  if (explicit) return { value: localProxyToContainer(explicit) || explicit, source: "NIANYUN_BUILD_PROXY" };
  // Probe the known local proxy ports first. IDEs/sandboxes often inject an
  // HTTPS_PROXY on a random loopback-only port (e.g. 127.0.0.1:15684) that a
  // Docker build container cannot reach, so the env var is only a fallback.
  for (const port of LOCAL_PORTS) {
    if (await probe(port)) return { value: `http://host.docker.internal:${port}`, source: `local port ${port}` };
  }
  const fromEnvironment = localProxyToContainer(process.env.HTTPS_PROXY || process.env.HTTP_PROXY);
  if (fromEnvironment) return { value: fromEnvironment, source: "HTTPS_PROXY/HTTP_PROXY" };
  return undefined;
}

function docker(args, options = {}) {
  const result = spawnSync("docker", args, { stdio: "inherit", shell, ...options });
  if (result.error) {
    console.error(`[sandbox:images] cannot run docker: ${result.error.message}`);
    process.exit(1);
  }
  return result;
}

const proxy = await resolveBuildProxy();
if (proxy) console.log(`[sandbox:images] build proxy ${proxy.value} (detected via ${proxy.source})`);
else console.log("[sandbox:images] no local build proxy detected; assuming direct PyPI access");

const proxyArgs = proxy
  ? [`--build-arg=HTTP_PROXY=${proxy.value}`, `--build-arg=HTTPS_PROXY=${proxy.value}`]
  : [];

const builds = [
  ["job", ["build", "-f", "deploy/sandbox/Dockerfile.job", "-t", "nianyun:sandbox", "deploy/sandbox", ...proxyArgs]],
  ["scanner", ["build", "-f", "deploy/sandbox/Dockerfile.scanner", "-t", "nianyun:sandbox-scanner", "deploy/sandbox"]],
  ["service", ["build", "-f", "deploy/sandbox/Dockerfile", "-t", "nianyun:sandbox-service", "."]],
];

for (const [label, args] of builds) {
  console.log(`[sandbox:images] building ${label} image`);
  const outcome = docker(args);
  if (outcome.status !== 0) {
    console.error(`[sandbox:images] ${label} build failed (exit ${outcome.status})`);
    process.exit(outcome.status ?? 1);
  }
}

// Keep the -c body free of spaces: on Windows spawnSync passes args through
// cmd.exe when shell is enabled, and a quoted multi-word script would be split.
const check = docker(
  ["run", "--rm", "--entrypoint", "python3", "nianyun:sandbox", "-c", "print(__import__('requests').__version__)"],
  { stdio: "pipe", encoding: "utf8", shell: false },
);
if (check.status === 0) {
  console.log(`[sandbox:images] all three images ready; requests ${String(check.stdout).trim()} baked into the job image`);
} else {
  console.warn("[sandbox:images] WARNING: requests is NOT preinstalled; job code will need a runtime pip install.");
  console.warn("[sandbox:images] set NIANYUN_BUILD_PROXY to your proxy and rebuild to restore parity.");
}

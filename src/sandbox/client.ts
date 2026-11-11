/**
 * 控制面 → Sidecar Sandbox Service 的客户端。
 *
 * 控制面永远不碰 Docker；它只知道一个 HTTP 地址和一个 token。
 * 超时留 15s 余量：服务端已经按 timeout_s 杀进程，这里只防"服务本身卡死"。
 */
export type RemoteSandboxRequest = {
  lang: "python" | "bash";
  code: string;
  requirements?: string[];
  timeout_s?: number;
  memory_mb?: number;
  network?: boolean;
  /** 会话状态键：同一个 key 的多次调用共享 /state（跨调用记忆）。 */
  state_key?: string;
};

export type RemoteSandboxState = {
  key: string;
  mount: string;
  root: string;
  files: number;
  bytes: number;
  pruned: number;
  pruned_protected?: number;
  bands?: Record<string, { files: number; bytes: number }>;
  over_quota?: boolean;
  truncated: boolean;
  entries: Array<{ path: string; bytes: number; mtime_s: number }>;
};

export type RemoteSandboxFile = { path: string; bytes: number; content_base64: string; truncated: boolean };

export type RemoteSandboxResult = {
  ok: boolean;
  run_id: string;
  exit_code: number | null;
  timed_out: boolean;
  isolation: "microvm" | "container" | "process-jail";
  egress: string;
  stdout: string;
  stderr: string;
  duration_ms: number;
  truncated: boolean;
  files: RemoteSandboxFile[];
  state?: RemoteSandboxState;
};

export class SandboxServiceError extends Error {
  readonly status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = "SandboxServiceError";
    this.status = status;
  }
}

export async function execInSandboxService(options: {
  url: string;
  token?: string;
  signal?: AbortSignal;
  timeoutS?: number;
}, request: RemoteSandboxRequest): Promise<RemoteSandboxResult> {
  const base = options.url.replace(/\/+$/, "");
  if (!base) throw new SandboxServiceError("sandbox service url is not configured (SANDBOX_URL)");
  const budgetMs = Math.max(5, Number(request.timeout_s || 60)) * 1000 + 15_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budgetMs);
  const onAbort = () => controller.abort();
  options.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const response = await fetch(`${base}/sandbox/exec`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    const text = await response.text();
    let parsed: unknown = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
    if (!response.ok) {
      const detail = parsed && typeof parsed === "object" ? String((parsed as { error?: unknown }).error || text) : text;
      throw new SandboxServiceError(`sandbox service HTTP ${response.status}: ${(detail || "no detail").slice(0, 400)}`, response.status);
    }
    if (!parsed || typeof parsed !== "object") throw new SandboxServiceError("sandbox service returned a non-JSON body", response.status);
    const body = parsed as Record<string, unknown>;
    if (typeof body.stdout !== "string" || typeof body.stderr !== "string") {
      throw new SandboxServiceError("sandbox service response is missing stdout/stderr", response.status);
    }
    return {
      ok: body.ok === true,
      run_id: String(body.run_id || ""),
      exit_code: typeof body.exit_code === "number" ? body.exit_code : null,
      timed_out: body.timed_out === true,
      isolation: (body.isolation === "microvm" || body.isolation === "container" ? body.isolation : "process-jail"),
      egress: String(body.egress || ""),
      stdout: body.stdout,
      stderr: body.stderr,
      duration_ms: Number(body.duration_ms || 0),
      truncated: body.truncated === true,
      files: Array.isArray(body.files) ? (body.files as RemoteSandboxFile[]).filter(file => file && typeof file.path === "string" && typeof file.content_base64 === "string") : [],
      // /state 摘要是跨调用记忆的唯一凭据：漏传会让 agent 以为"没存住"。
      ...(body.state && typeof body.state === "object" ? { state: body.state as RemoteSandboxState } : {}),
    };
  } catch (error) {
    if (error instanceof SandboxServiceError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new SandboxServiceError(/abort/i.test(message) ? `sandbox service timed out after ${Math.round(budgetMs / 1000)}s` : `sandbox service unreachable: ${message}`);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

export async function sandboxServiceHealth(url: string, token?: string): Promise<Record<string, unknown>> {
  const base = url.replace(/\/+$/, "");
  const response = await fetch(`${base}/health`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  const body = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!response.ok) throw new SandboxServiceError(`sandbox health HTTP ${response.status}`, response.status);
  return body;
}
/** 列出会话 /state（不裁剪，只读）。 */
export async function sandboxStateList(options: { url: string; token?: string; signal?: AbortSignal }, key: string): Promise<RemoteSandboxState> {
  const base = options.url.replace(/\/+$/, "");
  if (!base) throw new SandboxServiceError("sandbox service url is not configured (SANDBOX_URL)");
  const response = await fetch(`${base}/sandbox/state?key=${encodeURIComponent(key)}`, {
    headers: options.token ? { authorization: `Bearer ${options.token}` } : undefined,
    signal: options.signal,
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) throw new SandboxServiceError(String(body.error || `sandbox state failed with ${response.status}`), response.status);
  return body as unknown as RemoteSandboxState;
}

/** 回读单个文件：文本直接给 content，二进制给 content_base64。 */
export async function sandboxStateFile(options: { url: string; token?: string; signal?: AbortSignal }, key: string, path: string): Promise<{ path: string; bytes: number; truncated: boolean; is_text: boolean; content?: string; content_base64?: string }> {
  const base = options.url.replace(/\/+$/, "");
  if (!base) throw new SandboxServiceError("sandbox service url is not configured (SANDBOX_URL)");
  const response = await fetch(`${base}/sandbox/state/file?key=${encodeURIComponent(key)}&path=${encodeURIComponent(path)}`, {
    headers: options.token ? { authorization: `Bearer ${options.token}` } : undefined,
    signal: options.signal,
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) throw new SandboxServiceError(String(body.error || `sandbox state file failed with ${response.status}`), response.status);
  return body as unknown as { path: string; bytes: number; truncated: boolean; is_text: boolean; content?: string; content_base64?: string };
}

/** 会话结束时清掉 /state。 */
export async function sandboxStateClear(options: { url: string; token?: string; signal?: AbortSignal }, key: string): Promise<{ removed: boolean }> {
  const base = options.url.replace(/\/+$/, "");
  if (!base) throw new SandboxServiceError("sandbox service url is not configured (SANDBOX_URL)");
  const response = await fetch(`${base}/sandbox/state?key=${encodeURIComponent(key)}`, {
    method: "DELETE",
    headers: options.token ? { authorization: `Bearer ${options.token}` } : undefined,
    signal: options.signal,
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) throw new SandboxServiceError(String(body.error || `sandbox state clear failed with ${response.status}`), response.status);
  return { removed: body.removed === true };
}
/** 写回 /state 的一个文件（RPC cursor、"工具结果回灌"用）。 */
export async function sandboxStateWriteFile(options: { url: string; token?: string; signal?: AbortSignal }, key: string, path: string, content: string): Promise<number> {
  const base = options.url.replace(/\/+$/, "");
  if (!base) throw new SandboxServiceError("sandbox service url is not configured (SANDBOX_URL)");
  const response = await fetch(`${base}/sandbox/state/file?key=${encodeURIComponent(key)}&path=${encodeURIComponent(path)}`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
    },
    body: JSON.stringify({ content }),
    signal: options.signal,
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) throw new SandboxServiceError(String(body.error || `sandbox state write failed with ${response.status}`), response.status);
  return Number(body.bytes || 0);
}
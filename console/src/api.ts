export async function api<T = Record<string, unknown>>(path: string, opt?: RequestInit): Promise<T> {
  const r = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opt,
  });
  const text = await r.text();
  let data: Record<string, unknown> = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: text };
  }
  if (!r.ok && !data.error) data.error = r.statusText;
  return data as T;
}

export async function listAuthSeeds() {
  return api<AuthSeedList>("/api/auth-seeds");
}

export async function saveAuthSeed(host: string, content: string) {
  return api<SaveSeedResult>("/api/auth-seeds", { method: "POST", body: JSON.stringify({ host, content }) });
}

export async function deleteAuthSeed(host: string) {
  return api<{ ok?: boolean; error?: string }>("/api/auth-seeds/" + encodeURIComponent(host), { method: "DELETE" });
}

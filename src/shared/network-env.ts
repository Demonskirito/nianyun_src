/** Outbound traffic uses direct connections, including inherited child environments. */
export const PROXY_ENV_KEYS = [
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
] as const;

export function clearProxyEnv(env: Record<string, string | undefined>): void {
  for (const key of PROXY_ENV_KEYS) env[key] = "";
  env.NO_PROXY = "*";
  env.no_proxy = "*";
}

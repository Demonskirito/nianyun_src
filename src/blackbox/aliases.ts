/** Canonical tool ids and the binary/short names the model may emit instead. */
export const BLACKBOX_TOOL_ALIASES: Record<string, string> = {
  browser: "browser.open",
  http: "http.request",
  burp: "burp.request",
  katana: "katana.crawl",
  subfinder: "recon.subdomains",
  dnsx: "recon.dns",
  httpx: "recon.http_probe",
  naabu: "recon.ports",
  gau: "recon.historical_urls",
  waybackurls: "recon.historical_urls",
  ffuf: "recon.content_discovery",
  nuclei: "recon.nuclei",
  interactsh: "recon.interactsh", arjun: "recon.parameters", subjs: "recon.js_endpoints", testssl: "recon.tls",
  kiterunner: "recon.api_routes", dalfox: "recon.xss", sqlmap: "recon.sql", jwt_tool: "recon.jwt",
  "graphql-cop": "recon.graphql", wpscan: "recon.cms", trufflehog: "recon.secrets", semgrep: "recon.sast",
};

export function canonicalTool(name: unknown): string {
  const raw = String(name ?? "").trim();
  return BLACKBOX_TOOL_ALIASES[raw] || raw;
}
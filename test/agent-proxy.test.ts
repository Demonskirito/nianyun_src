import { describe, expect, it } from "vitest";
import { noProxyMatches, resolveAgentProxy } from "../src/blackbox/agent-proxy.js";
import { GROUPS } from "../src/control/console/llm-io.js";

const BASE = "https://llm.example.com/v1";
const ENV = {} as NodeJS.ProcessEnv;

describe("LLM egress is decoupled from BURP_PROXY_URL", () => {
  it("never falls back to the Burp capture port", () => {
    const result = resolveAgentProxy({ BURP_PROXY_URL: "http://host.docker.internal:8080" }, BASE, ENV);
    expect(result).toMatchObject({ url: "", source: "direct" });
  });

  it("an explicit proxy wins and Burp is ignored", () => {
    const result = resolveAgentProxy({
      BLACKBOX_AGENT_PROXY_URL: "http://host.docker.internal:7897",
      BURP_PROXY_URL: "http://host.docker.internal:8080",
    }, BASE, ENV);
    expect(result).toMatchObject({ url: "http://host.docker.internal:7897", source: "explicit", host: "host.docker.internal:7897" });
  });

  it("an explicitly empty value means forced direct, even when env has a proxy", () => {
    const result = resolveAgentProxy({ BLACKBOX_AGENT_PROXY_URL: "" }, BASE,
      { HTTPS_PROXY: "http://env.proxy:3128" } as NodeJS.ProcessEnv);
    expect(result).toMatchObject({ url: "", source: "direct" });
  });

  it("uses standard env proxies when nothing is configured explicitly", () => {
    expect(resolveAgentProxy({}, BASE, { HTTPS_PROXY: "http://env.proxy:3128" } as NodeJS.ProcessEnv))
      .toMatchObject({ url: "http://env.proxy:3128", source: "environment" });
    expect(resolveAgentProxy({}, BASE, { http_proxy: "http://lower.proxy:8080" } as NodeJS.ProcessEnv))
      .toMatchObject({ url: "http://lower.proxy:8080", source: "environment" });
  });

  it("respects NO_PROXY for an internal model service", () => {
    const result = resolveAgentProxy({ NO_PROXY: ".internal,localhost,10.0.0.0/8" },
      "https://llm.internal/v1", { HTTPS_PROXY: "http://env.proxy:3128" } as NodeJS.ProcessEnv);
    expect(result).toMatchObject({ url: "", source: "no_proxy" });
  });

  it("BLACKBOX_AGENT_NO_PROXY can override the environment list from Desk", () => {
    const result = resolveAgentProxy({ BLACKBOX_AGENT_NO_PROXY: "llm.example.com" }, BASE,
      { HTTPS_PROXY: "http://env.proxy:3128", NO_PROXY: "localhost" } as NodeJS.ProcessEnv);
    expect(result).toMatchObject({ url: "", source: "no_proxy" });
  });

  it("explicit configuration deliberately ignores NO_PROXY (config = intent)", () => {
    const result = resolveAgentProxy({
      BLACKBOX_AGENT_PROXY_URL: "http://host.docker.internal:7897",
      NO_PROXY: "llm.example.com",
    }, BASE, ENV);
    expect(result.source).toBe("explicit");
  });

  it("proxy host labels are redacted (no credentials leak into logs)", () => {
    const result = resolveAgentProxy({ BLACKBOX_AGENT_PROXY_URL: "http://user:secret@proxy.test:8080" }, BASE, ENV);
    expect(result.host).toBe("proxy.test:8080");
    expect(result.host).not.toContain("secret");
  });
});

describe("NO_PROXY matching", () => {
  it("matches exact hosts, suffixes and leading-dot rules", () => {
    expect(noProxyMatches("localhost", "localhost")).toBe(true);
    expect(noProxyMatches("a.internal", ".internal")).toBe(true);
    expect(noProxyMatches("a.b.internal", "internal")).toBe(true);
    expect(noProxyMatches("notinternal", "internal")).toBe(false);
    expect(noProxyMatches("anything.test", "*")).toBe(true);
  });

  it("matches IPv4 CIDR ranges used by container NO_PROXY", () => {
    expect(noProxyMatches("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(noProxyMatches("192.168.1.5", "192.168.0.0/16")).toBe(true);
    expect(noProxyMatches("11.1.2.3", "10.0.0.0/8")).toBe(false);
    expect(noProxyMatches("a.test", "10.0.0.0/8")).toBe(false);
  });

  it("ignores host:port rules and empty lists", () => {
    expect(noProxyMatches("a.test", "a.test:8080")).toBe(true);
    expect(noProxyMatches("a.test", "")).toBe(false);
    expect(noProxyMatches("", "*")).toBe(false);
  });
});

describe("Desk settings can persist the decoupled keys", () => {
  it("the blackbox whitelist includes all three new keys", () => {
    for (const key of ["BLACKBOX_AGENT_PROXY_URL", "BLACKBOX_AGENT_NO_PROXY", "BLACKBOX_AGENT_IGNORE_HTTPS_ERRORS"]) {
      expect(GROUPS.blackbox).toContain(key);
    }
  });
});

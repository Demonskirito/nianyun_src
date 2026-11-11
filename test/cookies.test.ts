import { describe, expect, it } from "vitest";
import { cookieHeaderFor, cookiesForUrl, mergeCookies, parseCookieHeader, parseSetCookie } from "../src/blackbox/cookies.js";

const now = 1_800_000_000;

describe("blackbox cookie jar", () => {
  it("parses Set-Cookie attributes and defaults", () => {
    const cookie = parseSetCookie("sid=abc; Domain=.example.com; Path=/app; Max-Age=3600; Secure; HttpOnly; SameSite=Lax", "https://www.example.com/app/login", now)!;
    expect(cookie).toMatchObject({
      name: "sid", value: "abc", domain: "example.com", path: "/app", hostOnly: false,
      secure: true, httpOnly: true, sameSite: "lax", expires: now + 3600,
    });
    const hostOnly = parseSetCookie("theme=dark; Path=/", "https://www.example.com/", now)!;
    expect(hostOnly).toMatchObject({ domain: "www.example.com", hostOnly: true, path: "/", expires: null });
  });

  it("rejects domain cookies that do not cover the request host", () => {
    expect(parseSetCookie("sid=abc; Domain=other.example", "https://www.example.com/", now)).toBeNull();
  });

  it("matches host-only, domain, path, secure and expiry rules", () => {
    const jar = mergeCookies([], [
      parseSetCookie("sid=abc; Path=/", "https://app.example.com/", now)!,
      parseSetCookie("scoped=1; Domain=.example.com; Path=/api; Secure", "https://app.example.com/api/login", now)!,
      parseSetCookie("expired=1; Max-Age=0", "https://app.example.com/", now)!,
    ], now);
    expect(cookieHeaderFor(jar, "https://app.example.com/api/users", now)).toBe("scoped=1; sid=abc");
    expect(cookieHeaderFor(jar, "http://app.example.com/api/users", now)).toBe("sid=abc");
    expect(cookieHeaderFor(jar, "https://api.example.com/", now)).toBe("");
    expect(cookieHeaderFor(jar, "https://api.example.com/api/items", now)).toBe("scoped=1");
    expect(cookieHeaderFor(jar, "https://other.example.com/", now)).toBe("");
    expect(cookiesForUrl(jar, "https://app.example.com/other", now).map((cookie) => cookie.name)).toEqual(["sid"]);
  });

  it("lets an explicit Cookie header override stored values", () => {
    const stored = mergeCookies([], [parseSetCookie("sid=old; Path=/", "https://app.example.com/", now)!], now);
    const explicit = parseCookieHeader("sid=new; theme=dark", "https://app.example.com/");
    const merged = mergeCookies(stored, explicit, now);
    expect(cookieHeaderFor(merged, "https://app.example.com/", now)).toBe("sid=new; theme=dark");
  });

  it("removes cookies by expiry and caps the jar", () => {
    const jar = mergeCookies([], [parseSetCookie("sid=abc; Path=/", "https://app.example.com/", now)!], now);
    const removed = mergeCookies(jar, [parseSetCookie("sid=gone; Path=/; Max-Age=0", "https://app.example.com/", now)!], now);
    expect(removed).toHaveLength(0);
    const many = mergeCookies([], Array.from({ length: 350 }, (_, index) => parseSetCookie(`c${index}=v; Path=/`, "https://app.example.com/", now)!), now);
    expect(many).toHaveLength(300);
  });
});

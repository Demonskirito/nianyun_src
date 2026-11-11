import { describe, expect, it } from "vitest";
import { routeTemplate, normalizePath } from "../src/blackbox/urlnorm.js";

describe("route template folding", () => {
  it("keeps numeric ids on the static path", () => {
    expect(normalizePath("/api/doc/86").path).toBe("/api/doc/{id}");
  });

  it("folds slug-like ids once two values are seen at the same position", () => {
    const memory = {};
    const first = routeTemplate("/api/users/alice", memory);
    expect(first.path).toBe("/api/users/alice");
    const second = routeTemplate("/api/users/bob", memory);
    expect(second.path).toBe("/api/users/{p3}");
    const third = routeTemplate("/api/users/carol", memory);
    expect(third.path).toBe("/api/users/{p3}");
    expect(second.ids).toContain("bob");
  });

  it("never folds route words or static files", () => {
    const memory = {};
    expect(routeTemplate("/api/doc/list", memory).path).toBe("/api/doc/list");
    expect(routeTemplate("/api/doc/detail", memory).path).toBe("/api/doc/detail");
    expect(routeTemplate("/api/doc/list", memory).path).toBe("/api/doc/list");
    expect(routeTemplate("/static/app.js", memory).path).toBe("/static/app.js");
    expect(routeTemplate("/static/main.js", memory).path).toBe("/static/main.js");
  });
});

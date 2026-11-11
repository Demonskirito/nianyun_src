import { describe, expect, it } from "vitest";
import { normalizeAutomation } from "../src/asset/automation.js";

describe("asset automation", () => {
  it("requires seeds for enabled schedules and bounds the interval", () => {
    expect(() => normalizeAutomation({ enabled: true })).toThrow(/seed/);
    expect(() => normalizeAutomation({ interval_sec: 10 })).toThrow(/between/);
    expect(normalizeAutomation({ enabled: true, interval_sec: 600, seeds: ["https://example.com"] })).toMatchObject({
      enabled: true,
      interval_sec: 600,
      discover: true,
      validate: true,
      score: true,
    });
  });
});

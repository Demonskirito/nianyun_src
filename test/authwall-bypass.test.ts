import { describe, expect, it } from "vitest";
import { blockedByWall, recordWallBypass, wallVerdict, type AuthWallState } from "../src/blackbox/authwall.js";
import { BlackboxProgress, observerStateVersion } from "../src/blackbox/progress.js";

const wall = (urls = ["https://h/api/order/list", "https://h/api/order/detail"]): AuthWallState =>
  ({ host: "https://h", streak: 3, urls, tripped_at: Date.now(), code: "10403" });

describe("auth wall bypass channels", () => {
  it("keeps blocking the denied prefix when no channel applies", () => {
    const state = { auth_wall: wall() };
    expect(wallVerdict(state, "https://h/api/order/other", {}).blocked).toBe(true);
    expect(blockedByWall(state, "https://h/api/order/other", {})).toBe(true);
  });

  it("lets sensitive paths through — the wall must not forbid unauth verification", () => {
    const state = { auth_wall: wall() };
    const safePaths = [".env", ".git/", "/swagger", "/actuator"];
    for (const path of ["/api/.env", "/api/order/actuator/env"]) {
      const verdict = wallVerdict(state, `https://h${path}`, {}, { safePaths });
      expect(verdict.bypass).toBe("safe_path");
      expect(verdict.blocked).toBe(false);
    }
    // Same URL is still blocked when the safe list is empty: the channel is configurable.
    expect(wallVerdict(state, "https://h/api/order/actuator/env", {}, { safePaths: [] }).blocked).toBe(true);
  });

  it("lets unauth_exposure / jwt_auth tasks through and nothing else", () => {
    const state = { auth_wall: wall() };
    expect(wallVerdict(state, "https://h/api/order/other", {}, { playbook: "unauth_exposure" })).toEqual({ blocked: false, bypass: "unauth_playbook" });
    expect(wallVerdict(state, "https://h/api/order/other", {}, { playbook: "idor" }).blocked).toBe(true);
    expect(wallVerdict(state, "https://h/api/order/other", {}, { playbook: "unauth_exposure", allowUnauthPlaybook: false }).blocked).toBe(true);
  });

  it("honours an explicit bypass_auth_wall declaration only when allowed", () => {
    const state = { auth_wall: wall() };
    expect(wallVerdict(state, "https://h/api/order/other", { bypass_auth_wall: true })).toEqual({ blocked: false, bypass: "explicit" });
    expect(wallVerdict(state, "https://h/api/order/other", { bypass_auth_wall: true }, { allowBypass: false }).blocked).toBe(true);
    // Bypass is not a credential: an authentication header still wins over the wall.
    expect(wallVerdict(state, "https://h/api/order/other", { headers: { Authorization: "Bearer t" } }).blocked).toBe(false);
  });

  it("records every honoured bypass so the wall stays observable", () => {
    const state = { auth_wall: wall() };
    recordWallBypass(state, "https://h/api/.env", "safe_path");
    recordWallBypass(state, "https://h/api/order/x", "explicit");
    expect(state.auth_wall.bypasses).toBe(2);
    expect(state.auth_wall.last_bypass?.kind).toBe("explicit");
    // No wall, nothing to record.
    const clean: { auth_wall?: AuthWallState } = {};
    recordWallBypass(clean, "https://h/api/x", "safe_path");
    expect(clean.auth_wall).toBeUndefined();
  });

  it("does not invalidate a pending Observer review on every bypass", () => {
    const progress = new BlackboxProgress();
    progress.state.tasks.T1 = { status: "pending" };
    const before = observerStateVersion(progress.state);
    progress.wallOptions = { safePaths: [".env"], allowUnauthPlaybook: true, allowBypass: true };
    progress.state.auth_wall = { ...wall(), tripped_at: Date.now() };
    recordWallBypass(progress.state, "https://h/api/.env", "safe_path");
    recordWallBypass(progress.state, "https://h/api/.env", "safe_path");
    // 墙状态（含 last_bypass.at 时间戳）属于运行期元数据：放行再多次也不能让待审的 review 作废。
    // 墙触发本身仍通过 auth_wall_alert + supervision.authWallSeenAt 送到 Observer。
    expect(observerStateVersion(progress.state)).toBe(before);
  });
});

describe("auth wall bypass inside the progress guard", () => {
  const base = () => {
    const progress = new BlackboxProgress();
    progress.state.auth_wall = wall();
    progress.wallOptions = { safePaths: [".env", "/swagger"], allowUnauthPlaybook: true, allowBypass: true };
    return progress;
  };

  it("still blocks a plain repeat of the denied prefix", () => {
    const progress = base();
    const action = progress.begin({ tool: "http.request", task_id: "T1", reason: "retry", input: { url: "https://h/api/order/other" } }, "https://h", 2, 2);
    expect(action.blocked).toBe("auth_wall_requires_token");
  });

  it("allows the sensitive path and bills it as a bypass", () => {
    const progress = base();
    const action = progress.begin({ tool: "http.request", task_id: "T2", reason: "env probe", input: { url: "https://h/api/.env" } }, "https://h", 2, 2);
    expect(action.blocked).toBeUndefined();
    expect(progress.state.auth_wall?.bypasses).toBe(1);
  });

  it("allows the task whose playbook is unauth_exposure", () => {
    const progress = base();
    progress.state.tasks.T3 = { status: "pending", playbook: "unauth_exposure" };
    const action = progress.begin({ tool: "http.request", task_id: "T3", reason: "unauth probe", input: { url: "https://h/api/order/anon" } }, "https://h", 2, 2);
    expect(action.blocked).toBeUndefined();
  });

  it("allows an explicit bypass_auth_wall declaration", () => {
    const progress = base();
    const action = progress.begin({ tool: "http.request", task_id: "T4", reason: "unauth baseline", input: { url: "https://h/api/order/anon", bypass_auth_wall: true } }, "https://h", 2, 2);
    expect(action.blocked).toBeUndefined();
    expect(progress.state.auth_wall?.last_bypass?.kind).toBe("explicit");
  });
});
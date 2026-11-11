import { describe, expect, it } from "vitest";
import { PLAYBOOK_IDS } from "../src/blackbox/playbooks.js";
import {
  PLAYBOOK_REQUIREMENTS, evaluateRequirements, hasRequirements, isVulnPlaybook, vulnerabilityGaps,
} from "../src/blackbox/vuln-predicates.js";

/**
 * 谓词层把 playbook 的 `confirm.must_show`（中文散文）变成机器可判的条件。
 *
 * 背景（2026-11-02 m.ctrip.com）：`validateFinding` 当时只校验「证据存在 + 同 host 同 path」，
 * 于是「匿名 GET 返回 200」也能成为合法 finding；playbook 里写得很专业的确认标准
 * 没有任何代码消费。这里把三件事钉死：覆盖全部 16 个打法、谓词真的能判否、
 * 未满足时能说出缺哪一件。
 */

type Ev = Record<string, unknown>;
const diff = (verdict: string): Ev => ({ id: `ev-${verdict}`, kind: "tool-result", tool: "http.diff", data: { verdict } });
const anonOk = (body = ""): Ev => ({
  id: "ev-anon", kind: "tool-result", tool: "http.request",
  data: { anonymous: true, status: 200, ok: true, body },
});

describe("谓词覆盖：16 个打法一个都不能漏", () => {
  it("每个 PLAYBOOK_IDS 都有谓词定义（新增打法忘了写会在这里失败）", () => {
    const missing = PLAYBOOK_IDS.filter(id => !PLAYBOOK_REQUIREMENTS[id]);
    expect(missing).toEqual([]);
    expect(PLAYBOOK_IDS.length).toBe(16);
  });

  it("真实 id 全部登记为漏洞确认型，只有 spa_reverse 是交付型", () => {
    // 旧实现手抄的名单用了 command_injection / jwt_forgery / subdomain_takeover /
    // business_logic / graphql，和真实 id（cmdi / jwt_auth / cloud_supply / logic /
    // graphql_ws）对不上，导致这五类打法的门槛从未生效。这里逐个钉住。
    for (const id of ["cmdi", "jwt_auth", "cloud_supply", "logic", "graphql_ws", "idor", "sqli"]) {
      expect(hasRequirements(id)).toBe(true);
      expect(isVulnPlaybook(id)).toBe(true);
    }
    expect(isVulnPlaybook("spa_reverse")).toBe(false);
    expect(hasRequirements("spa_reverse")).toBe(true);
  });

  it("未登记的打法不拦结案（但也拿不到漏洞身份）", () => {
    expect(hasRequirements("not_a_playbook")).toBe(false);
    expect(isVulnPlaybook("not_a_playbook")).toBe(false);
    expect(evaluateRequirements("not_a_playbook", []).satisfied).toBe(true);
  });
});

describe("谓词判定：不够就是不够", () => {
  it("idor：没有任何对照 → 未满足，且缺少项点名 http.diff", () => {
    const verdict = evaluateRequirements("idor", [anonOk()]);
    expect(verdict.satisfied).toBe(false);
    expect(verdict.missing.join()).toContain("http.diff");
  });

  it("idor：一次 same_shape 对照即成立（越权看的是结构一致、取值不同）", () => {
    expect(evaluateRequirements("idor", [diff("same_shape")]).satisfied).toBe(true);
  });

  it("idor：identical 不能当越权（两边完全一样，说明没跨到别人的对象）", () => {
    expect(evaluateRequirements("idor", [diff("identical")]).satisfied).toBe(false);
  });

  it("unauth_exposure：光匿名 200 不够，body 里必须有真实敏感数据", () => {
    const bare = evaluateRequirements("unauth_exposure", [anonOk("{\"ok\":true}")]);
    expect(bare.satisfied).toBe(false);
    expect(bare.missing.join()).toContain("敏感");
    const leaky = evaluateRequirements("unauth_exposure", [anonOk("{\"db\":\"jdbc:mysql://10.0.0.2:3306/app\"}")]);
    expect(leaky.satisfied).toBe(true);
  });

  it("匿名标记缺失时不算未授权可达（不能靠猜）", () => {
    const withAuth = evaluateRequirements("unauth_exposure", [
      { id: "ev-x", kind: "tool-result", tool: "http.request", data: { status: 200, ok: true, body: "jdbc:mysql://a:b@h/db" } },
    ]);
    expect(withAuth.satisfied).toBe(false);
  });

  it("sqli 是 any：只要 timing_delta 成立就算", () => {
    expect(evaluateRequirements("sqli", [diff("timing_delta")]).satisfied).toBe(true);
    expect(evaluateRequirements("sqli", [diff("identical")]).satisfied).toBe(false);
  });

  it("spa_reverse 是交付型：exec.python 产出即可结案，但不是漏洞", () => {
    const verdict = evaluateRequirements("spa_reverse", [
      { id: "ev-py", kind: "tool-result", tool: "exec.python", data: { ok: true, output: "soa2=6" } },
    ]);
    expect(verdict.deliverable).toBe(true);
    expect(verdict.satisfied).toBe(true);
    expect(isVulnPlaybook("spa_reverse")).toBe(false);
  });

  it("敏感数据判据不收 token/email 这类常见键（否则等于永远为真）", () => {
    const generic = evaluateRequirements("cloud_supply", [
      { id: "ev-g", kind: "tool-result", tool: "http.request", data: { ok: true, body: '{"token":"x","email":"a@b.c","userId":1}' } },
    ]);
    expect(generic.satisfied).toBe(false);
  });
});

describe("谓词缺口：注入上下文的是「还差哪件」", () => {
  const state = {
    tasks: {
      T_idor: { status: "pending", playbook: "idor" },
      T_done: { status: "completed", playbook: "idor" },
      T_spa: { status: "pending", playbook: "spa_reverse" },
      T_unknown: { status: "pending", playbook: "whatever" },
    },
  };

  it("只报未结案的漏洞确认型任务，交付型与未知打法不出现", () => {
    const gaps = vulnerabilityGaps(state, []);
    expect(gaps.map(gap => gap.task_id)).toEqual(["T_idor"]);
  });

  it("缺口补上之后就不再出现在上下文里", () => {
    const gaps = vulnerabilityGaps(state, [diff("same_shape")]);
    expect(gaps).toEqual([]);
  });
});

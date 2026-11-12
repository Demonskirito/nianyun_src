<p align="center">
  <img src="console/public/mark.jpg" alt="Nianyun logo" width="80" height="80">
</p>

<h1 align="center">Nianyun</h1>

<p align="center">
  <strong>Authorized SRC asset discovery and blackbox session control plane</strong><br>
  Assets in · sessions out · evidence-backed findings</p>

> Authorized SRC / bug-bounty programs and labs only. Do not point this at systems you do not own or have written permission to test.

## What it does

Nianyun is a TypeScript control plane and operator desk for **authorized asset-based vulnerability discovery**:

1. Create a project and record the authorization you are working under.
2. Discover assets through ARL (local lighthouse) or FOFA (search engine), manual import, or HTTP seeds. Both providers accept a wildcard base such as `*.qwen.ai`: ARL runs the brute dictionary (default `small`, `big` is opt-in and can take an hour) plus DNS-dataset/certificate/DNS-plugin enumeration and collects domain, site and IP assets, while FOFA fans out into `domain=`, `host=` and `cert=` queries and merges the results inside the target namespace. ARL is asynchronous: an empty collect means the task is still in `domain_brute`/`site_identify`, so collect again later. FOFA talks to `fofa.info` over `node:https` with a 45s socket budget; set `FOFA_PROXY` (e.g. `http://host.docker.internal:7897`) when the container must egress through a proxy.
3. Probe candidates, screenshot and score the interesting ones.
4. Open a bounded **blackbox session** per candidate.
5. The main agent plans tasks, requests tools, and records every result in an evidence ledger.
6. A read-only Observer reviews task coverage and evidence consistency; an operator confirms or rejects findings.
7. Export the per-session summary or the project report.

There is no scope engine, target-origin confinement, CTF platform, flag submission, solver workspace, traffic tap, or VPN pipeline in this tree. Authorization is an operator responsibility.

## Layout

| Path | Role |
|---|---|
| `src/asset` | asset/candidate model, ARL and FOFA discovery, HTTP probing, vision review, automation |
| `src/blackbox` | JSON protocol, main agent, Observer, tool executor, evidence/approval/acceptance |
| `src/control/console` | operator desk HTTP API and project ledger |
| `src/control/cli.ts` | `nianyun console`, `status`, `inspect` |
| `src/report`, `src/risk` | project report and asset risk scoring |
| `src/validation` | low-impact HTTP header checks |
| `src/shared` | config, SQLite schema, execution gates, ledger |
| `console/` | React operator desk (`:8700`) |
| `deploy/control` | control-plane image with blackbox tools and Chromium |
| `deploy/arl` | optional ARL stack configuration (third-party image) |
| `compose.yaml` | control plane; ARL services behind `--profile arl` |
| `compose.control.yaml` | control plane + sandbox sidecar |
| `THIRD_PARTY_NOTICES.md` | provenance and license of `deploy/arl/` assets |
| `resources/wordlists` | approved wordlists for content/API discovery |

## Requirements

- Node.js **>= 22.19** (uses the built-in `node:sqlite`).
- For real tool execution: `tools.env.yaml` with model credentials, a Burp proxy/bridge when required, and the recon binaries (the `deploy/control` image bundles them).

## Run

```bash
npm ci
npm --prefix console ci
cp config.example.yaml config.yaml
cp tools.env.example.yaml tools.env.yaml     # fill keys, never commit
npm run build
bin/nianyun console                          # http://127.0.0.1:8700/
```

Execution modes:

- `serve` (default): console, project/candidate configuration; network actions are refused.
- `execute`: enables discovery, probing, review, and blackbox tool execution.

Set in `config.yaml`:

```yaml
execution:
  mode: execute
```

or `NIANYUN_MODE=execute`.

### Run a single URL end to end

```bash
bin/nianyun run https://example.com/ --project demo-run
```

One invocation goes through the whole pipeline — project (auto-created as `auto-<host>`)
→ candidate import → environment preflight → blackbox session → report — and writes
`report.md`, `summary.json` and `run.json` into `data/projects/<id>/`. It keeps
re-entering the run loop until the acceptance gate settles, so "waiting for a review"
or "stalled this round" never ends the command.

Without model credentials the main agent and the Observer fall back to the deterministic
local planner (`src/blackbox/local_plan.ts`, switch: `NIANYUN_LOCAL_PLANNER=off|auto|force`).
That planner is read-only by design: GET/HEAD/OPTIONS plus one `Origin` probe, no write
verbs, no path guessing, and it plugs in at the same seam as the LLM, so the evidence
ledger, closure audit, Observer review and acceptance gate all still apply.

## Deployment with Docker

Three compose entry points are provided:

| File | Starts | Use when |
|---|---|---|
| `compose.control.yaml` | control plane + sandbox sidecar | recommended, no ARL required |
| `compose.yaml` | control plane built from source | building the image yourself |
| `compose.yaml --profile arl` | plus the optional ARL discovery stack | ARL discovery is wanted |

```bash
cp .env.example .env          # fill in credentials; .env is git-ignored
docker compose -f compose.yaml up -d --build
```

That builds the control image from `deploy/control/Dockerfile` and starts only
the console. The sidecar stack (`compose.control.yaml`) additionally needs a
pre-built `nianyun:sandbox-service` image (see the build note in that file).
Once both `nianyun:control` and the sandbox image exist:

```bash
docker build -f deploy/control/Dockerfile -t nianyun:control .
docker compose -f compose.control.yaml up -d --no-build
```

`compose.control.yaml` defaults to `Dockerfile.fast` for fast local rebuilds from
a pre-built base; `--no-build` skips it and uses the image built above. Behind a
restrictive proxy the control image may need the mirror build args documented in
`deploy/control/README.md`.

The console listens on `http://127.0.0.1:8700/` (override with `NIANYUN_PORT`).
On Windows, 8700 can fall inside the Hyper-V excluded port range; if binding
fails with "forbidden by its access permissions", pick another `NIANYUN_PORT`.

### Optional: ARL discovery stack

ARL (Asset Reconnaissance Lighthouse) is an **external, optional** discovery
provider. `src/asset/arl.ts` calls it over HTTP with a `Token` header; the
control plane neither embeds nor builds ARL. Without `ARL_TOKEN`, the console
starts normally and FOFA, manual import and HTTP seeds still work.

The ARL stack is a third-party image. `compose.yaml` declares it and Docker
Compose pulls it on demand — **no Dockerfile is needed** to install it:

```bash
# 1. Put ARL_TOKEN, MONGO_ROOT_USER / MONGO_ROOT_PASSWORD and
#    RABBITMQ_DEFAULT_USER / RABBITMQ_DEFAULT_PASS in .env (see .env.example).
#    Generate a token with: openssl rand -hex 24
# 2. Start the ARL services (this also creates the shared `nianyun_default` network):
docker compose -f compose.yaml --profile arl up -d
# 3. If you use compose.control.yaml, attach the control plane to that network:
docker compose -f compose.control.yaml -f compose.control.arl.yaml up -d
```

Notes:

- ARL web UI is `https://127.0.0.1:5003/` (`ARL_PORT`); the control plane reaches
  it at `ARL_URL` (default `http://arl-web:5003`) with the same `ARL_TOKEN`.
- All five ARL services (web, worker, scheduler, mongodb, rabbitmq) sit behind
  `profiles: ["arl"]`. A plain `docker compose -f compose.yaml up -d` starts only
  the control plane and pulls none of those images.
- `ARL_IMAGE` defaults to a **pinned digest** of `honmashironeko/arl-docker-all`.
  It is a third-party image: verify its provenance before use and update the
  digest deliberately. `deploy/arl/` only holds configuration mounted into it.
- No default credentials ship with this repository. The ARL entrypoint refuses
  to start when the token or mongo/rabbitmq credentials are missing.
  `deploy/arl/mongo-init.js` still carries the upstream local-only web password —
  change it before exposing ARL beyond localhost.
- See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and
  licensing of the `deploy/arl/` assets.
- Only point ARL at domains you own or are explicitly authorized to test.

## Blackbox safety model

- Tool URLs are operator-supplied; methods and request bodies are limited by `BLACKBOX_RULES_DOCUMENT` (default GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE, JSON/form/raw/binary bodies).
- Each project keeps a shared cookie jar: `Set-Cookie` from HTTP/Burp and browser cookies are stored per domain/path and replayed automatically across the project's blackbox sessions; an explicit `Cookie` header overrides same-name entries.
- Every registered tool is callable directly by the main agent; there is no tool-navigation switch, no per-tool enable/disable flag and no per-action human approval. The rules document only carries risk switches such as `tools.<tool>.allow_credential_attack`.
- The rules document is JSON merged over built-in defaults. An unparsable document is reported at console startup and in the session timeline, then the whole document falls back to defaults (every tool callable, default budgets); invalid individual values are ignored with a listed reason, and the console refuses to save an unparsable document. Credential opt-ins are shown on the rules page and stored on the session checkpoint, and rejected calls are written to the evidence ledger.
- Findings must reference a successful tool result from the same session; Observer review is not exploit verification.
- Timeouts are not failures. A tool stopped by the batch deadline or its own per-tool cap keeps its partial output in the evidence ledger, is recorded as `tool-timeout`, does not consume the retry budget, and leaves its task pending. Work that no longer fits the stage budget is marked deferred with a reason instead of disappearing, and a batch never starts a slow tool (sqlmap, semgrep, testssl, kiterunner, dalfox) with less time than it needs.
- Tool identity includes the tool's parameters, so re-running nuclei with different templates or sqlmap with a different URL is new work; only an identical call counts as a repeat.
- Exit codes that mean "ran fine, found nothing" (for example ffuf and kiterunner exit 1) are accepted per tool instead of being reported as crashes.
- External tools are used the way an operator uses them: `input.args` passes any CLI flag through (up to 40), and each tool receives the project cookie jar and the configured Burp proxy automatically, so authenticated targets are scannable with `-H`/`--headers`/`--cookie` semantics per tool. `input.timeout_seconds` raises a single tool's clock up to 900s within the stage budget. The hard limits are the ones that would turn a scanner into something else: target overrides, file read/write, config/wordlist/template overrides, proxy overrides, OS/SQL shells, code templates and `--eval` are refused with a reason.
- The per-tool capability matrix, the denylist and the remaining gaps are documented in [docs/tool-capability.md](docs/tool-capability.md).
- `browser.open`/`browser.screenshot` accept `actions` (click, fill, press, select, check, hover, wait, scroll) and `evaluate`, so a login flow or a DOM check is one call that ends with the customary snapshot and screenshot.
- The browser is persistent per session: one Chromium per project/session is reused, so login state, `localStorage` and tabs survive between calls; `new_tab` opens a tab, `browser.close` releases it, and idle sessions close after 10 minutes.
- `input.source` turns a call into a pipeline stage: the full artifact of an earlier tool (by name or evidence id) becomes the target list for httpx, nuclei, naabu, dnsx or testssl, so `katana → httpx → nuclei` needs no copied URLs. Results stay bounded and report `items_truncated`; `evidence.read` pages the artifact past both limits.
- Credential attacks (`--passwords`/`--usernames`) are off unless the rules document sets `tools.<tool>.allow_credential_attack: true`, and the password list must live inside the approved wordlist directory.- `input.params` is an allowlisted knob bag, not a free-form CLI: nuclei (`severity`, `tags`, `templates`, `rate_limit`, `concurrency`), sqlmap (`level`, `risk`, `technique`, `dbms`, `data`, `param`), ffuf (`rate`, `extensions`, `method`), naabu (`ports`, `rate`), httpx (`ports`, `threads`) and testssl (`severity`) are bounded and validated before the command is built; any other key or tool is refused without charging the budget, and applied values are echoed into the evidence ledger.
- One malformed or unlinkable tool request no longer voids a round: list items are validated one by one, invalid entries are dropped with a stated reason (`protocol-warning`, `tool-requests-rejected`), and the remaining requests still run. Short tool names (`sqlmap`, `nuclei`, `burp`, ...) are accepted as aliases of the canonical ids.
- A refused request (tool disabled by rules, tool binary not configured, unusable input) is reported as `tool-rejected`, does not consume the tool-call budget or the retry budget, leaves its task pending, and stops repeating after the repeat limit.
- Budgets, repeat detection, stall detection, and a checkpoint CAS guard bound every run.

## Blackbox tool health

The console's **系统 → 工具健康度** page (`/#/health`) aggregates the evidence ledger per tool: attempts, successes, failures, timeouts, refusals, success rate, average and P95 duration, sessions covered, and the last error. It reads `/api/tool-health?window=24h|7d|30d|all&project=<id>`, so the numbers survive restarts and can be scoped to one project. Refused requests are excluded from the success-rate denominator because they never reached the tool.

## Tests

```bash
npm test        # Node 22.19+ required
```

`npm run build` builds `dist/` and `console/spa/`.

## License

MIT for the Nianyun source (`LICENSE`). The deployment assets under `deploy/arl/`
are adapted from a third-party Apache-2.0 project; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and `LICENSES/Apache-2.0.txt`.

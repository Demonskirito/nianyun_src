# Tool capability parity

The goal is that the main agent can do what an SRC researcher does at a shell prompt, not a
smaller curated subset. This page records how each tool is opened up and what is still out of
reach on purpose.

## Model

1. **`input.args`** passes any CLI flag through (≤ 40 entries, ≤ 512 chars each). A denylist
   removes the flags that turn a scanner into a different class of tool.
2. **Auth is automatic**: the project cookie jar is replayed and `input.headers` become the
   tool's native header flag, so authenticated targets are scannable without hand-building
   commands. Per tool: `-H` (nuclei, ffuf, httpx, dalfox, kiterunner), `--headers`/`--cookie`
   (sqlmap, wpscan), `--headers` (gau), `Cookie:` header for the `-H` family.
3. **The operator's Burp proxy is injected** (`-proxy`, `-x`, `--proxy`, `-http-proxy`), so
   external tool traffic shows up in the same place as browser and `http.request` traffic.
4. **`input.timeout_seconds`** raises a single tool's clock up to 900 s, still bounded by the
   stage budget; defaults are per tool (nuclei 300, sqlmap 600, scan tools 180–300).
5. **Structured output** for the JSONL tools: nuclei findings keep template id, name,
   severity, matcher, tags and extracted results; httpx keeps status, title, tech and length.
6. **Browser interaction**: `browser.open`/`browser.screenshot` accept `actions`
   (click, fill, press, select, check, uncheck, hover, wait, scroll) and `evaluate`, so a login
   flow or a DOM check is one call that still ends with the usual snapshot and screenshot.
7. **Persistent browser per session**: one Chromium per `project:session`, reused by every
   `browser.*` call, so login state, `localStorage` and tabs survive between calls. `new_tab`
   opens another tab, `browser.close` releases it, idle sessions close after 10 minutes, and an
   operator cancel closes it immediately.
8. **Pipelines**: `input.source` feeds the *full artifact* of an earlier tool (by name or
   evidence id) into the next tool as a target list, so `katana → httpx → nuclei` is three
   calls with no copied URLs: `{"source":{"tool":"katana.crawl","limit":2000}}`. Receivers are
   httpx, nuclei, naabu, dnsx and testssl; single-target tools are refused with the list of
   capable tools.
9. **Paging**: results stay bounded (2000 lines, 4096 chars each) and now report
   `items_truncated`; `evidence.read` reads the artifact by `tool`/`evidence_id` with
   `offset`/`limit`/`width`, so the full output stays reachable.
10. **Every tool is always available; risky capabilities are opted into per tool.** There is no
    per-tool enable/disable flag: the rules document's `tools.<tool>` entries only carry risk
    switches, and `allow_credential_attack: true` is what unlocks `--passwords`/`--usernames`
    (the password list must still live under `NIANYUN_WORDLIST_ROOT`). The rules page shows a
    warning tag when it is on, and a legacy `enabled` flag is ignored with a stated reason.

## Denylist (refused with a stated reason)

| Category | Flags | Why |
|---|---|---|
| Target override | `-u`, `--url`, `-host`, `-d`, `--domain`, `-target`, `-l`, `--list` | The scheduler owns the target; a call may not move it |
| File write | `-o`, `--output`, `-od`, `-oJ`, `--log`, `--logfile`, `--json-out`, `--sarif-export`, `--report`, `-of` | Keeps artifacts in the evidence ledger |
| Local file read | `-c`, `--config`, `-r`, `--request`, `--rawfile`, `--payload-file`, `--custom-payload` | Config/request files are outside the model's authority |
| Wordlist / template override | `-w`, `--wordlist`, `-t`, `--templates` | Use `wordlist`+`wordlist_root` (approved root) and `params.templates` (traversal-guarded) |
| Proxy override | `-proxy`, `--proxy`, `-x`, `--http-proxy`, `--socks5` | A model-chosen proxy is an exfiltration channel |
| Shell / code execution | `--os-shell`, `--os-pwn`, `--os-cmd`, `--os-smbrelay`, `--sql-shell`, `--sql-query`, `--eval`, `--input-cmd`, `-code`, `--enable-code`, `--autofix` | Turns a scanner into a shell or source rewriter |
| Credential attack | `--passwords`, `--usernames` | Account lockout risk; needs an explicit rule opt-in |

Everything else — severity/tag filters, `-etags`, `-dast`, `-headless`, `-mc`/`-fs`/`-recursion`
for ffuf, `--tamper`, `--crawl`, `--risk`, `-A`/`-X`, `--enumerate`, `--plugins-detection`,
`-jsc`, `-kf`, OAST flags — goes through untouched.

## Per-tool state

| Tool | Deprecated restriction | Now |
|---|---|---|
| nuclei | 5 knobs, no auth, 150 s | full flag surface minus code templates; jar + proxy; 300 s; structured findings |
| sqlmap | level/risk only, no cookies, 240 s | `--tamper`, `--crawl`, `--headers`, `--cookie`, `--dbms`, `--technique`, `-p`; 600 s; `--os-*`/`--sql-query`/`--file-*` denied |
| ffuf | 3 knobs, anonymous | `-mc`, `-fs`, `-H`, `-recursion`, `-X`, `-e`; jar + proxy; 180 s |
| httpx | ports only | full flags, jar, proxy, structured status/title/tech |
| naabu / dnsx / subfinder | fixed | full flags (target override still owned by the scheduler) |
| katana | fixed depth/rate | depth/duration knobs; proxy; crawler remains rate-limited at 1 rps |
| dalfox | fixed | headers, jar, proxy, `--blind`, custom payload from `params` |
| testssl | severity only | all flags except output files; proxy |
| wpscan | passive only | `--enumerate`, `--plugins-detection`, headers, cookie, proxy |
| kiterunner | fixed rate | headers, approved wordlist, own flags |
| trufflehog / semgrep | local path | unchanged: these are local-source tools, not remote scanners |
### Burp bridge (integrations/burp-bridge)

The bridge is a Burp extension (Montoya API 2024.7) that exposes Burp's own data and actions over a
host-scoped, bearer-token HTTP API on port 8765. Reads are always available; actions are explicit
tools so the ledger records them.

| Tool | Path | Gate |
|---|---|---|
| `burp.history` / `burp.sitemap` / `burp.issues` / `burp.entry` | `/proxy/history`, `/sitemap`, `/issues`, `/proxy/entry` | read; host must equal the session target |
| `burp.ws_history` | `/ws/history` | read; WebSocket payloads previewed, not replayed |
| `burp.scope` | `/scope` | read; `isInScope` check for the URL |
| `burp.intercept` | `GET/POST /intercept` | reads or toggles the proxy intercept switch |
| `burp.decoder` | `/decoder` | base64/url/html/hex, sha256, uuid |
| `burp.send` | `/http/send` | sends one request through Burp's HTTP stack; method allowlist, host match, redacted body preview |
| `burp.repeater` / `burp.organizer` | `/repeater`, `/organizer` | hands the request to the operator |
| `burp.collab_generate` / `burp.collab_poll` | `/collab/*` | OOB payloads and interactions (Burp Collaborator) |
| `burp.scan` / `burp.scan_status` / `burp.scan_stop` | `/scan/*` | passive audit by default; **active** requires `tools["burp.scan"].allow_active_scan=true` |

Redaction happens inside the extension: `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
secret-looking query parameters and body fields are replaced before the response leaves Burp.
### Full surface (bridge v3)

Bridge v3 exposes every programmable Montoya API area. Nothing is disabled: these are high-risk
capabilities and the operator is expected to run them only against authorised targets.

| Tool | What it drives |
|---|---|
| `burp.info` | Burp version, project, task-engine state, intercept state, capability list |
| `burp.control` | pause/resume Burp's task engine, import project/user options, raise log events, send to Decoder, shut Burp down, unload the bridge |
| `burp.options` | export project or user options as JSON |
| `burp.cookies` | list the cookie jar (values stay in Burp) and set cookies |
| `burp.storage` | extension key/value store, persisted across sessions |
| `burp.sitemap_issues` / `burp.sitemap_add` | read site-map issues; send a request and add the exchange to the site map |
| `burp.scope_edit` | include/exclude URLs or scope patterns |
| `burp.send_batch` | up to 50 requests through Burp's HTTP stack in one call |
| `burp.crawl` | Burp Scanner crawler (start + status). **Not usable on Burp 2024.7.3**: `Scanner.startCrawl` ships as an unimplemented stub (`UnsupportedOperationException`), so the tool explains that and points at `katana.crawl` / the Dashboard crawl |
| `burp.scan_issues` / `burp.scan_report` | per-audit issue detail; HTML/XML report written on the Burp host |
| `burp.intruder` | attack engine: sniper, battering ram, pitchfork, cluster bomb over `§markers§`, with concurrency, delay, stop-on-match, status filters, regex match and a 5000-request ceiling. `race: true` fires the burst from one gate (concurrent, **not** last-byte sync — Montoya owns the socket); `extract: [{name, regex, group}]` pulls columns out of every hit |
| `burp.intruder_send` | open a real Intruder tab with the request |
| `burp.compare` | line diff, response keyword analysis, response variation analysis, or send both payloads to Comparer |
| `burp.convert` | base64/URL/HTML/hex, any Burp digest algorithm, gzip/deflate compression (implemented with `java.util.zip` because Burp 2024.7.3's DEFLATE branch is a stub), random strings, radix conversion, JSON editing, JWT decode |
| `burp.proxy_rule` | Match and Replace as data: URL regex + method filter, request/response header and body rewrites, `block` for bridge sends; `test` dry-runs a rule without sending. Applies to Burp's own traffic through a registered HttpHandler and to bridge sends |
| `burp.websocket` | Open a ws/wss session through Burp, send text or binary frames, poll buffered inbound frames, close |
| `burp.bchecks` | Import a BCheck script (`.bcheck` JSON) so it joins active scans; returns load status and errors |

Active scans are on by default (`tools["burp.scan"].allow_active_scan: true`); set it to `false`
to force passive-only audits.

Rewrite rules persist in the extension data store (`nianyun.rules`) and survive a reload. `block`
is honoured on bridge-initiated sends; Burp's own handler API has no drop action, so proxied traffic
is rewritten but never dropped.

**Unimplemented in Burp 2024.7.3** (Burp's own API stubs, reported as clear errors rather than
silent failures): `Scanner.startCrawl` — use `katana.crawl` or start the crawl from Burp's Dashboard.

Bridge v3 also answers uncaught failures as a JSON `500` body (`{"ok":false,"error":"<Exception>: <message>"}`),
so a failing Burp call shows up in the transcript instead of a dropped connection.

Not exposed: Repeater/Comparer/Logger **tab state** (the UI widgets themselves), proxy listener
start/stop, and extension management beyond self-unload — Montoya has no API for those.


## Remaining gaps (known, not hidden)

- **No fan-out**: a pipeline stage scans a list serially inside one tool process. The agent can
  chain calls, but there is no parallel dispatch of N targets across streams.
- **Single-target tools can't consume a list**: ffuf/kiterunner still fuzz one URL per call
  (the executor refuses `input.source` there and lists the tools that accept it).
- **No browser tabs API beyond `new_tab`**: the oldest tab is closed automatically past five.
- **In-page `console`/network capture** is not returned per call; use Burp or `evaluate` for
  what you need.
- **Credential attacks** remain off until the operator opts in per tool; there is no global
  switch by design, and no way to switch a whole tool off.

## Verification

- `test/tool-capability.test.ts`: flag passthrough, denylist, header/cookie/proxy injection,
  timeout caps, structured parsing, argument redaction in the ledger, identity sensitivity.
- `test/tool-params.test.ts`: the typed knob bag and its bounds.
- `test/tool-pipeline.test.ts`: artifact→target-list resolution, list flags, evidence paging,
  credential gating and its wordlist-root check.
- `test/blackbox-tool-access.test.ts`: a recorded artifact feeds the next tool through the real
  database.
- Manual browser smoke: two calls sharing one session (DOM + `localStorage` survive), a
  screenshot with no navigation, `browser.close`, then a fresh session; plus fill → click →
  evaluate with a broken selector that must not lose the snapshot.
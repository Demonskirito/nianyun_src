# Nianyun

TypeScript control plane and operator desk for authorized SRC asset discovery and blackbox sessions.

This tree is for **authorized SRC / bug-bounty programs and labs only**. Do not point it at systems you do not own or have written permission to test.

## Layout

| Path | Role |
|---|---|
| `src/control` | console API, project ledger, CLI |
| `src/blackbox` | main agent, Observer, tool executor, evidence ledger, rules document |
| `src/asset` | asset/candidate import, ARL, discovery, probing, review, automation |
| `src/report`, `src/risk`, `src/validation` | project report, risk scoring, low-impact checks |
| `console/` | operator desk (`bin/nianyun console` → `:8700`) |
| `bin/` | `nianyun`, `nianyun-mcp` |
| `resources/` | wordlists |
| `deploy/` | control-plane image, optional ARL stack |
| `config.example.yaml` | copy to `config.yaml` (gitignored) |
| `tools.env.example.yaml` | copy to `tools.env.yaml` (gitignored) |

## How to run

```bash
npm ci
npm --prefix console ci
cp config.example.yaml config.yaml
cp tools.env.example.yaml tools.env.yaml
# fill model/tool keys in tools.env.yaml — never commit them
npm run build
bin/nianyun console
```

Execution is `serve` by default. Set `execution.mode: execute` (or `NIANYUN_MODE=execute`) to enable discovery, probing, review, and blackbox tool execution.

Desk: http://127.0.0.1:8700/
Quick start: [`README.md`](README.md#run)

## Do not

- Commit keys, `.env`, `tools.env.yaml`, `config.yaml`, tokens, or Burp connector exports
- Copy `data/`, `tools/c2/`, `deploy/hosted/`, or `deploy/inimage/` into a public tree
- Point the agent LLM URL at the desk (`:8700`) or `host.docker.internal`
- Use this against unauthorized targets

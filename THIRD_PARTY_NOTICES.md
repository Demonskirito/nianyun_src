# Third-party notices

Nianyun is MIT-licensed (see `LICENSE`). The deployment assets listed below are
**not** covered by that grant: they correspond to configuration from a
third-party Apache-2.0 project. They are reproduced here with attribution,
a description of the changes, and a copy of that license.

## ARL deployment assets

| Item | Detail |
|---|---|
| Original project | ARL (Asset Reconnaissance Lighthouse), `TophantTechnology/ARL` |
| Docker packaging | `honmashironeko/ARL-docker` — Apache-2.0, built from a community backup of ARL v2.6.2 |
| Runtime image | `honmashironeko/arl-docker-all` on Docker Hub, pinned by digest in `compose.yaml` |
| Upstream license | Apache License 2.0 — full text in `LICENSES/Apache-2.0.txt` |

Files in this repository that correspond to the upstream docker deployment
assets:

- `deploy/arl/config-docker.yaml`
- `deploy/arl/entrypoint.sh`
- `deploy/arl/mongo-init.js`

Changes made in this repository (Apache-2.0 section 4(b)):

- Replaced hard-coded MongoDB / RabbitMQ / API credentials with `__*__`
  placeholders, injected from environment variables by `entrypoint.sh` with
  URL encoding for connection strings.
- Added a startup check that refuses to run with missing credentials or a token
  containing unsafe characters, plus explanatory comments.
- Retained the upstream `ARL_ROLE` web / worker / scheduler startup commands.

`compose.yaml`, `compose.control.yaml`, `compose.control.arl.yaml`,
`.env.example`, and the control-plane integration in `src/asset/arl.ts` are
original to this repository.

This repository does **not** vendor ARL source code or ship the ARL image. The
image is pulled from Docker Hub at runtime only when the `arl` compose profile is
enabled. Verify its provenance and contents, and confirm you are authorized to
scan your targets, before use. `deploy/arl/mongo-init.js` retains the upstream
local-only default web credential; change it if ARL is reachable from anything
other than localhost.

Other third-party components (Node.js, MongoDB, RabbitMQ, and the recon tools
pinned in `generated/tool-manifest.json`) are distributed under their own
licenses and are not bundled in this repository.

References observed on 2026-11-12: `honmashironeko/ARL-docker` (Apache-2.0),
`TophantTechnology/ARL`, and the Apache License 2.0 at
<https://www.apache.org/licenses/LICENSE-2.0>.

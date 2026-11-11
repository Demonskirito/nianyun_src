#!/usr/bin/env bash
set -euo pipefail

root="${NIANYUN_REPO_ROOT:-/opt/nianyun}"
data="${NIANYUN_DATA_DIR:-$root/data}"
config_dir="$data/config"
config="${NIANYUN_CONFIG:-$config_dir/config.yaml}"

cd "$root"
# One-time migration from the pre-rename database filename. Keeps existing
# projects / sessions / evidence when an existing data volume is reused.
if [[ ! -e "$data/nianyun.db" && -e "$data/heimdall.db" ]]; then
  mv "$data/heimdall.db" "$data/nianyun.db"
  for suffix in -wal -shm -journal; do
    if [[ -e "$data/heimdall.db${suffix}" ]]; then
      mv "$data/heimdall.db${suffix}" "$data/nianyun.db${suffix}"
    fi
  done
fi
# First boot: seed data/config from env, then never overwrite operator edits.
node deploy/unified/init.mjs
# Mode is parsed by the application before opening a database or starting workers.
# Missing configuration uses the shipped example without writing to the data volume.
if [[ ! -e "$config" ]]; then config="$root/deploy/control/config.yaml"; fi
if [[ "${NIANYUN_MODE:-}" == "inspect" ]]; then
  exec bin/nianyun --config "$config" inspect
fi
exec bin/nianyun --config "$config" console --listen "${NIANYUN_LISTEN:-0.0.0.0:8700}"

#!/usr/bin/env bash
set -euo pipefail
export NIANYUN_REPO_ROOT="${NIANYUN_REPO_ROOT:-/opt/nianyun}"
export NIANYUN_DATA_DIR="${NIANYUN_DATA_DIR:-$NIANYUN_REPO_ROOT/data}"
cd "$NIANYUN_REPO_ROOT"
node deploy/unified/init.mjs
CFG="${NIANYUN_CONFIG:-$NIANYUN_DATA_DIR/config/config.yaml}"
exec bin/nianyun --config "$CFG" console --listen "${NIANYUN_LISTEN:-0.0.0.0:8700}"

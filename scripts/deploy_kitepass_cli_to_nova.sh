#!/usr/bin/env bash
#
# Purpose:
#   Sync, build, and install the kitepass CLI on the nova host.
# Usage:
#   bash scripts/deploy_kitepass_cli_to_nova.sh
# Key env:
#   NOVA_HOST, NOVA_REMOTE_CLI_DIR, NOVA_REMOTE_INSTALL_DIR

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NOVA_HOST="${NOVA_HOST:-nova}"
REMOTE_CLI_DIR="${NOVA_REMOTE_CLI_DIR:-/home/ubuntu/codex/agent-passport-cli}"
REMOTE_INSTALL_DIR="${NOVA_REMOTE_INSTALL_DIR:-/home/ubuntu/.local/bin}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd ssh
require_cmd rsync

rsync -az --delete \
  --exclude '.git' \
  --exclude 'target' \
  "${CLI_DIR}/" "${NOVA_HOST}:${REMOTE_CLI_DIR}/"

ssh "${NOVA_HOST}" "bash -lc '
  source ~/.cargo/env
  cd ${REMOTE_CLI_DIR}
  cargo build --workspace --bins
  mkdir -p ${REMOTE_INSTALL_DIR}
  install -m 0755 target/debug/kitepass ${REMOTE_INSTALL_DIR}/kitepass
'"

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SHARED_HPKE_DIR="$(cd "${CLI_DIR}/.." && pwd)/kap-hpke-shared"

NOVA_HOST="${NOVA_HOST:-nova}"
REMOTE_CLI_DIR="${NOVA_REMOTE_CLI_DIR:-/home/ubuntu/codex/kitepass-cli}"
REMOTE_SHARED_HPKE_DIR="${NOVA_REMOTE_SHARED_HPKE_DIR:-/home/ubuntu/codex/kap-hpke-shared}"
REMOTE_INSTALL_DIR="${NOVA_REMOTE_INSTALL_DIR:-/home/ubuntu/.local/bin}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd ssh
require_cmd rsync

if [[ ! -d "${SHARED_HPKE_DIR}" ]]; then
  echo "Missing shared HPKE crate at ${SHARED_HPKE_DIR}" >&2
  exit 1
fi

rsync -az --delete \
  --exclude '.git' \
  --exclude 'target' \
  "${CLI_DIR}/" "${NOVA_HOST}:${REMOTE_CLI_DIR}/"

rsync -az --delete \
  --exclude '.git' \
  --exclude 'target' \
  "${SHARED_HPKE_DIR}/" "${NOVA_HOST}:${REMOTE_SHARED_HPKE_DIR}/"

ssh "${NOVA_HOST}" "bash -lc '
  source ~/.cargo/env
  cd ${REMOTE_CLI_DIR}
  cargo build --workspace --bins
  mkdir -p ${REMOTE_INSTALL_DIR}
  install -m 0755 target/debug/kitepass ${REMOTE_INSTALL_DIR}/kitepass
'"

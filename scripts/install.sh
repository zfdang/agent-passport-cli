#!/bin/sh
#
# Purpose:
#   Download and install a released kitepass CLI binary from GitHub Releases.
# Usage:
#   sh scripts/install.sh
#   curl -fsSL .../scripts/install.sh | sh
# Key env:
#   KITEPASS_REPO, KITEPASS_VERSION, KITEPASS_INSTALL_DIR

set -eu

REPO="${KITEPASS_REPO:-zfdang/agent-passport-cli}"
BINARY_NAME="${KITEPASS_BINARY_NAME:-kitepass}"
INSTALL_DIR="${KITEPASS_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${KITEPASS_VERSION:-latest}"

log() {
  printf '%s\n' "$*" >&2
}

fail() {
  log "error: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

download() {
  url="$1"
  output="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$output" "$url"
    return
  fi

  fail "either curl or wget is required"
}

resolve_version() {
  if [ "$VERSION" != "latest" ]; then
    printf '%s' "$VERSION"
    return
  fi

  api_url="https://api.github.com/repos/$REPO/releases/latest"
  body_file="$TMP_DIR/latest-release.json"
  download "$api_url" "$body_file"

  version=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$body_file" | head -n 1)
  [ -n "$version" ] || fail "failed to resolve latest release tag from $api_url"
  printf '%s' "$version"
}

detect_target() {
  os=$(uname -s)
  arch=$(uname -m)

  case "$os" in
    Linux) platform_os="linux" ;;
    Darwin) platform_os="macos" ;;
    *) fail "unsupported operating system: $os" ;;
  esac

  case "$arch" in
    x86_64|amd64) platform_arch="x86_64" ;;
    arm64|aarch64) platform_arch="arm64" ;;
    *) fail "unsupported architecture: $arch" ;;
  esac

  printf '%s-%s' "$platform_os" "$platform_arch"
}

install_binary() {
  release_tag="$1"
  target="$2"
  archive_name="kitepass-cli-$target-$release_tag.tar.gz"
  download_url="https://github.com/$REPO/releases/download/$release_tag/$archive_name"
  archive_path="$TMP_DIR/$archive_name"
  unpack_dir="$TMP_DIR/unpack"

  log "Installing $BINARY_NAME $release_tag for $target"
  log "Downloading $download_url"

  mkdir -p "$unpack_dir" "$INSTALL_DIR"
  download "$download_url" "$archive_path"

  tar -xzf "$archive_path" -C "$unpack_dir"

  binary_path=$(find "$unpack_dir" -type f -name "$BINARY_NAME" | head -n 1)
  [ -n "$binary_path" ] || fail "failed to locate $BINARY_NAME in downloaded archive"

  cp "$binary_path" "$INSTALL_DIR/$BINARY_NAME"
  chmod 755 "$INSTALL_DIR/$BINARY_NAME"
}

print_success() {
  log ""
  log "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      log "Note: $INSTALL_DIR is not currently in PATH."
      log "Add this line to your shell profile if needed:"
      log "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
  esac
}

need_cmd uname
need_cmd tar
need_cmd mktemp

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM HUP

TARGET=$(detect_target)
RESOLVED_VERSION=$(resolve_version)

install_binary "$RESOLVED_VERSION" "$TARGET"
print_success

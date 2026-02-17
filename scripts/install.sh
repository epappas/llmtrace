#!/usr/bin/env bash
set -euo pipefail

# LLMTrace Proxy installer
# Usage: curl -sS https://raw.githubusercontent.com/epappas/llmtrace/main/scripts/install.sh | bash
#
# Environment variables:
#   LLMTRACE_VERSION   - specific version to install (default: latest)
#   LLMTRACE_INSTALL   - install directory (default: /usr/local/bin or ~/.local/bin)
#   LLMTRACE_NO_CONFIG - set to 1 to skip downloading config.example.yaml

REPO="epappas/llmtrace"
BINARY="llmtrace-proxy"

# --- Helpers ---------------------------------------------------------------

info()  { printf '  \033[1;34m->\033[0m %s\n' "$*"; }
ok()    { printf '  \033[1;32m->\033[0m %s\n' "$*"; }
err()   { printf '  \033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || err "'$1' is required but not found"
}

# --- Detect platform -------------------------------------------------------

detect_platform() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux*)  os="linux" ;;
    Darwin*) os="macos" ;;
    *)       err "Unsupported OS: $os. Use Docker instead: docker pull ghcr.io/$REPO:latest" ;;
  esac

  case "$arch" in
    x86_64|amd64)   arch="amd64" ;;
    aarch64|arm64)   arch="arm64" ;;
    *)               err "Unsupported architecture: $arch" ;;
  esac

  # Validate against available binaries
  if [ "$os" = "linux" ] && [ "$arch" != "amd64" ]; then
    err "Pre-built binaries are only available for linux-amd64. Use Docker for arm64: docker pull ghcr.io/$REPO:latest"
  fi
  if [ "$os" = "macos" ] && [ "$arch" != "arm64" ]; then
    err "Pre-built binaries are only available for macos-arm64. Install via cargo: cargo install llmtrace"
  fi

  ASSET="${BINARY}-${os}-${arch}"
}

# --- Resolve version -------------------------------------------------------

resolve_version() {
  if [ -n "${LLMTRACE_VERSION:-}" ]; then
    VERSION="$LLMTRACE_VERSION"
    TAG="v$VERSION"
  else
    info "Fetching latest release..."
    TAG=$(curl -sS "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [ -z "$TAG" ] && err "Could not determine latest version. Set LLMTRACE_VERSION manually."
    VERSION="${TAG#v}"
  fi
  info "Version: $VERSION"
}

# --- Determine install directory -------------------------------------------

resolve_install_dir() {
  if [ -n "${LLMTRACE_INSTALL:-}" ]; then
    INSTALL_DIR="$LLMTRACE_INSTALL"
  elif [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
}

# --- Download and install --------------------------------------------------

download_binary() {
  local url="https://github.com/$REPO/releases/download/$TAG/$ASSET"
  local tmp
  tmp="$(mktemp)"

  info "Downloading $ASSET..."
  if command -v curl >/dev/null 2>&1; then
    curl -fSL --progress-bar -o "$tmp" "$url" || err "Download failed. Check that release $TAG exists at https://github.com/$REPO/releases"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "$tmp" "$url" || err "Download failed. Check that release $TAG exists at https://github.com/$REPO/releases"
  else
    err "curl or wget is required"
  fi

  chmod +x "$tmp"

  if [ "$INSTALL_DIR" = "/usr/local/bin" ] && [ ! -w "$INSTALL_DIR" ]; then
    info "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv "$tmp" "$INSTALL_DIR/$BINARY"
  else
    mv "$tmp" "$INSTALL_DIR/$BINARY"
  fi

  ok "Installed $BINARY to $INSTALL_DIR/$BINARY"
}

download_config() {
  [ "${LLMTRACE_NO_CONFIG:-0}" = "1" ] && return

  if [ -f "config.yaml" ]; then
    info "config.yaml already exists, skipping"
    return
  fi

  local url="https://raw.githubusercontent.com/$REPO/$TAG/config.example.yaml"
  info "Downloading example config..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o config.yaml "$url" 2>/dev/null || info "Could not download config (non-fatal)"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O config.yaml "$url" 2>/dev/null || info "Could not download config (non-fatal)"
  fi

  [ -f "config.yaml" ] && ok "Downloaded config.yaml"
}

# --- Verify ----------------------------------------------------------------

verify() {
  if ! command -v "$BINARY" >/dev/null 2>&1; then
    case ":$PATH:" in
      *":$INSTALL_DIR:"*) ;;
      *)
        echo ""
        info "Add $INSTALL_DIR to your PATH:"
        echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
        echo ""
        return
        ;;
    esac
  fi

  ok "$($INSTALL_DIR/$BINARY --version 2>/dev/null || echo "$BINARY $VERSION")"
}

# --- Main ------------------------------------------------------------------

main() {
  echo ""
  echo "  LLMTrace Proxy Installer"
  echo "  ========================"
  echo ""

  detect_platform
  resolve_version
  resolve_install_dir
  download_binary
  download_config
  verify

  echo ""
  echo "  Get started:"
  echo "    export OPENAI_API_KEY=\"sk-...\""
  echo "    $BINARY --config config.yaml"
  echo ""
  echo "  Docs: https://github.com/$REPO"
  echo ""
}

main

#!/bin/sh
# Install zapsend from a GitHub Release: download, verify SHA-256, install.
#
#   curl -fsSL https://raw.githubusercontent.com/Urdemonlord/zapsend/master/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.1.0 --dir ~/.local/bin
#
# Env overrides (mainly for testing):
#   ZAPSEND_VERSION          tag to install, e.g. v0.1.0 (default: latest release)
#   ZAPSEND_INSTALL_DIR      where to put the binary (default: ~/.local/bin)
#   ZAPSEND_RELEASE_BASE_URL download root (default: GitHub releases/download)
set -eu

REPO="Urdemonlord/zapsend"
BASE_URL="${ZAPSEND_RELEASE_BASE_URL:-https://github.com/$REPO/releases/download}"
VERSION="${ZAPSEND_VERSION:-latest}"
INSTALL_DIR="${ZAPSEND_INSTALL_DIR:-$HOME/.local/bin}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "usage: install.sh [--version vX.Y.Z] [--dir DIR]"
      exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux) ;;
  *) echo "zapsend install: $os has no prebuilt binary yet; use: cargo install zapsend" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) target="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
  *) echo "zapsend install: architecture $arch is not supported" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\(v[^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || { echo "could not resolve the latest release" >&2; exit 1; }
fi

asset="zapsend-${VERSION}-${target}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
curl -fsSL -o "$tmp/$asset" "$BASE_URL/$VERSION/$asset"
curl -fsSL -o "$tmp/$asset.sha256" "$BASE_URL/$VERSION/$asset.sha256"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && sha256sum -c "$asset.sha256")
elif command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && shasum -a 256 -c "$asset.sha256")
else
  echo "need sha256sum or shasum to verify the download" >&2; exit 1
fi

mkdir -p "$INSTALL_DIR"
tar -xzf "$tmp/$asset" -C "$tmp"
cp "$tmp/zapsend-${VERSION}-${target}/zapsend" "$INSTALL_DIR/zapsend"
chmod +x "$INSTALL_DIR/zapsend"
"$INSTALL_DIR/zapsend" --version
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "installed to $INSTALL_DIR/zapsend; add $INSTALL_DIR to PATH if it is not there yet" ;;
esac
echo "installed zapsend $VERSION to $INSTALL_DIR/zapsend"

#!/bin/sh
# Install zapsend from a GitHub Release: download, verify SHA-256, install.
#
#   curl -fsSL https://raw.githubusercontent.com/Urdemonlord/zapsend/master/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.1.0 --dir ~/.local/bin
#
# Supported: Linux (x86_64, aarch64) and Windows x86_64 from Git Bash/MSYS.
# macOS has no prebuilt binary yet; use `cargo install zapsend` there.
# Linux binaries are linked against glibc; musl systems (e.g. Alpine Linux)
# are refused by this script, use `cargo install zapsend` there too.
#
# What the SHA-256 check proves: the checksum is published in the same
# GitHub Release as the binary, so it proves the download was not corrupted
# in transit, but it cannot prove the release itself was not replaced. If
# that matters to you, build from source, or compare against a checksum you
# obtained earlier through a channel you already trust. Either way you are
# trusting the release publisher. Signed assets (minisign/cosign) are not
# used: a signature would
# only move the trust problem to the signing key, which a first-time
# installer would still have to fetch from the same place, and it would add
# key management to every release for a project with one maintainer.
#
# Env overrides (mainly for testing):
#   ZAPSEND_VERSION          tag to install, e.g. v0.1.0 (default: latest release)
#   ZAPSEND_INSTALL_DIR      where to put the binary (default: ~/.local/bin)
#   ZAPSEND_RELEASE_BASE_URL download root (default: GitHub releases/download)
#   ZAPSEND_OS / ZAPSEND_ARCH
#                            override uname detection (tests only)
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
[ -n "${ZAPSEND_OS:-}" ] && os="$ZAPSEND_OS"
[ -n "${ZAPSEND_ARCH:-}" ] && arch="$ZAPSEND_ARCH"

case "$os" in
  Linux) kind=linux ;;
  MINGW*|MSYS*|CYGWIN*) kind=windows ;;
  *) echo "zapsend install: $os has no prebuilt binary; on macOS use: cargo install zapsend" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) gnu_arch=x86_64 ;;
  aarch64|arm64) gnu_arch=aarch64 ;;
  *) echo "zapsend install: architecture $arch is not supported" >&2; exit 1 ;;
esac

case "$kind" in
  linux) target="$gnu_arch-unknown-linux-gnu" ;;
  windows)
    if [ "$gnu_arch" != x86_64 ]; then
      echo "zapsend install: no Windows $gnu_arch binary yet; use the x86_64 zip from the releases page" >&2
      exit 1
    fi
    target="x86_64-pc-windows-gnu"
    ;;
esac

# Refuse musl (e.g. Alpine) before downloading: the Linux binaries are
# glibc-linked and there is no musl artifact to fall back to.
if [ "$kind" = linux ] && ldd --version 2>&1 | grep -qi musl; then
  echo "zapsend install: musl libc (e.g. Alpine Linux) is not supported by the prebuilt binaries; use: cargo install zapsend" >&2
  exit 1
fi

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\(v[^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || { echo "could not resolve the latest release" >&2; exit 1; }
fi

case "$kind" in
  linux) asset="zapsend-${VERSION}-${target}.tar.gz"; bin="zapsend" ;;
  windows) asset="zapsend-${VERSION}-${target}.zip"; bin="zapsend.exe" ;;
esac

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
case "$kind" in
  linux) tar -xzf "$tmp/$asset" -C "$tmp" ;;
  windows)
    if command -v unzip >/dev/null 2>&1; then
      unzip -o -q "$tmp/$asset" -d "$tmp"
    elif command -v bsdtar >/dev/null 2>&1; then
      bsdtar -xf "$tmp/$asset" -C "$tmp"
    elif command -v tar >/dev/null 2>&1 && tar --version 2>&1 | grep -qi bsdtar; then
      # Git Bash ships bsdtar as tar, which extracts zip archives. GNU tar
      # cannot extract zip archives, so only accept tar when it is bsdtar.
      tar -xf "$tmp/$asset" -C "$tmp"
    else
      echo "need unzip or bsdtar to extract the Windows archive" >&2; exit 1
    fi
    ;;
esac

# Stage the new binary inside $INSTALL_DIR (same filesystem, so the final
# rename is atomic), smoke-test it there, then move it into place. The staged
# name keeps the binary's suffix ($bin), so on Windows it is still a .exe the
# smoke test can run. A failed
# download, check, or test leaves the installed binary untouched, and an
# upgrade while `zapsend daemon` runs does not hit "Text file busy": rename
# replaces the directory entry while the running process keeps the old file.
# On Windows the rename fails if the binary is running; the error below
# says so instead of leaving a half-installed binary behind.
staged="$INSTALL_DIR/.zapsend.new.$$.$bin"
trap 'rm -f "$staged"; rm -rf "$tmp"' EXIT INT TERM
cp "$tmp/zapsend-${VERSION}-${target}/$bin" "$staged"
chmod +x "$staged"
"$staged" --version >/dev/null
mv "$staged" "$INSTALL_DIR/$bin" || { echo "could not replace $INSTALL_DIR/$bin (is zapsend running? stop it and retry)" >&2; exit 1; }
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "installed to $INSTALL_DIR/$bin; add $INSTALL_DIR to PATH if it is not there yet" ;;
esac
echo "installed zapsend $VERSION to $INSTALL_DIR/$bin"

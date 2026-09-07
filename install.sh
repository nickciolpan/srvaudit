#!/bin/sh
# Install srvaudit from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/nickciolpan/srvaudit/main/install.sh | sh
#
# Environment:
#   SRVAUDIT_VERSION   tag to install (default: the latest release)
#   PREFIX             install directory (default: /usr/local/bin, else ~/.local/bin)
set -eu

REPO="nickciolpan/srvaudit"
BIN="srvaudit"
VERSION="${SRVAUDIT_VERSION:-latest}"
PREFIX="${PREFIX:-}"

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'srvaudit install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || have wget || die "need curl or wget"
have tar || die "need tar"

fetch() { # fetch <url> <dest>
  if have curl; then
    curl -fsSL "$1" -o "$2"
  else
    wget -qO "$2" "$1"
  fi
}

# ---------------------------------------------------------------- platform --
os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported OS '$os'. Build from source: cargo install --git https://github.com/$REPO" ;;
esac
case "$arch" in
  x86_64 | amd64)  arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported architecture '$arch'. Build from source: cargo install --git https://github.com/$REPO" ;;
esac

# ----------------------------------------------------------------- version --
if [ "$VERSION" = latest ]; then
  VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" /dev/stdout 2>/dev/null \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1) \
    || die "could not reach the GitHub API"
  [ -n "$VERSION" ] || die "could not determine the latest release"
fi

asset="$BIN-$os-$arch"
url="https://github.com/$REPO/releases/download/$VERSION/$asset.tar.gz"

# -------------------------------------------------------------- destination --
if [ -z "$PREFIX" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    PREFIX=/usr/local/bin
  else
    PREFIX="$HOME/.local/bin"
  fi
fi
mkdir -p "$PREFIX" || die "cannot create $PREFIX"
[ -w "$PREFIX" ] || die "$PREFIX is not writable. Re-run with PREFIX=~/.local/bin, or use sudo."

say "srvaudit $VERSION  ($os/$arch)  ->  $PREFIX"

# ------------------------------------------------------------------ install --
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t srvaudit)
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch "$url" "$tmp/$asset.tar.gz" || die "download failed: $url"

# Verify against the checksum published beside the tarball. A missing checksum
# is a reason to stop, not a reason to shrug.
if fetch "$url.sha256" "$tmp/$asset.tar.gz.sha256" 2>/dev/null; then
  if have sha256sum; then
    (cd "$tmp" && sha256sum -c "$asset.tar.gz.sha256" >/dev/null) || die "checksum mismatch"
  elif have shasum; then
    (cd "$tmp" && shasum -a 256 -c "$asset.tar.gz.sha256" >/dev/null) || die "checksum mismatch"
  else
    warn "  ! no sha256sum or shasum available; skipping checksum verification"
  fi
  say "  · checksum ok"
else
  die "no published checksum for $asset.tar.gz — refusing to install"
fi

tar -xzf "$tmp/$asset.tar.gz" -C "$tmp"
[ -f "$tmp/$asset" ] || die "archive did not contain $asset"
chmod +x "$tmp/$asset"
mv -f "$tmp/$asset" "$PREFIX/$BIN"

say "  · installed $PREFIX/$BIN"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) warn "  ! $PREFIX is not on your PATH — add it with:"
     warn "      echo 'export PATH=\"$PREFIX:\$PATH\"' >> ~/.profile" ;;
esac

"$PREFIX/$BIN" --version
say "Try:  $BIN --help"

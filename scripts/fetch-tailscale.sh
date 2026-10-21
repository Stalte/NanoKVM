#!/bin/bash
#
# Fetch the pinned static riscv64 Tailscale build into kvmapp/tailscale/ for
# the hardened package. The device never downloads Tailscale itself.
#
# Usage: scripts/fetch-tailscale.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/scripts/tailscale.lock"

NAME="tailscale_${TAILSCALE_VERSION}_riscv64"
URL="https://pkgs.tailscale.com/stable/${NAME}.tgz"
DEST="$ROOT/kvmapp/tailscale"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[INFO] fetching $URL"
curl -fsSL --retry 3 -o "$WORK/$NAME.tgz" "$URL"
published="$(curl -fsSL --retry 3 "$URL.sha256" | tr -d '[:space:]')"
actual="$(sha256sum "$WORK/$NAME.tgz" | cut -d' ' -f1)"

if [ "$actual" != "$TAILSCALE_SHA256" ]; then
    echo "[ERROR] $NAME.tgz sha256 $actual does not match the pinned $TAILSCALE_SHA256" >&2
    exit 1
fi
if [ "$published" != "$TAILSCALE_SHA256" ]; then
    echo "[ERROR] pkgs.tailscale.com publishes $published for $NAME.tgz, pinned is $TAILSCALE_SHA256" >&2
    exit 1
fi

tar -xzf "$WORK/$NAME.tgz" -C "$WORK"
mkdir -p "$DEST"
for bin in tailscale tailscaled; do
    install -m 0755 "$WORK/$NAME/$bin" "$DEST/$bin"
    machine=$(od -An -tu1 -j18 -N1 "$DEST/$bin" | tr -d ' \n')
    if [ "$machine" != "243" ]; then
        echo "[ERROR] $bin is not a riscv64 binary" >&2
        exit 1
    fi
done
printf '%s\n' "$TAILSCALE_VERSION" > "$DEST/VERSION"
printf '%s  %s\n' "$TAILSCALE_SHA256" "$NAME.tgz" > "$DEST/SOURCE.sha256"

echo "[DONE] Tailscale $TAILSCALE_VERSION in kvmapp/tailscale/"

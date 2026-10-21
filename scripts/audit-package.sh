#!/bin/bash
#
# Audit a hardened NanoKVM package before it is published.
#
# Fails when the package is missing a piece of the lockdown or still carries
# something the hardened build removes. Then lists every network endpoint
# string found in the shipped files, so a reviewer can see at a glance what
# the binaries know about. Strings are not proof of behaviour: the firewall is
# what stops a binary from using them.
#
# Usage: scripts/audit-package.sh build/release/nanokvm_<version>.tar.gz
# Writes build/release/AUDIT.txt next to the tarball.

set -euo pipefail

TARBALL="${1:-}"
if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
    echo "Usage: $0 <nanokvm_X.Y.Z.tar.gz>" >&2
    exit 1
fi

NAME="$(basename "$TARBALL" .tar.gz)"
REPORT="$(dirname "$TARBALL")/AUDIT.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tar -xzf "$TARBALL" -C "$WORK"
PKG="$WORK/$NAME"

fail=0
check() {
    local what="$1"
    shift
    if "$@"; then
        echo "  ok    $what"
    else
        echo "  FAIL  $what"
        fail=1
    fi
}
absent() { [ ! -e "$PKG/$1" ]; }
present() { [ -f "$PKG/$1" ]; }
contains() { grep -q -- "$2" "$PKG/$1" 2>/dev/null; }

{
    echo "NanoKVM hardened package audit: $NAME"
    echo "sha256: $(sha256sum "$TARBALL" | cut -d' ' -f1)"
    echo
    echo "== Lockdown present"
    check "harden.sh"                          present hardening/harden.sh
    check "hardening.conf"                     present hardening/hardening.conf
    check "nanokvm-guard helper"               present hardening/nanokvm-guard
    check "S02hardening boot hook"             present system/init.d/S02hardening
    check "bundled tailscaled"                 present tailscale/tailscaled
    check "bundled tailscale CLI"              present tailscale/tailscale
    check "tailscaled runs unprivileged"       contains system/init.d/S98tailscaled "run-as"
    check "tailscaled in userspace mode"       contains system/init.d/S98tailscaled "userspace-networking"
    check "tailscaled log upload disabled"     contains system/init.d/S98tailscaled "no-logs-no-support"
    check "Wi-Fi init script is the stub"      contains system/init.d/S30wifi "Wi-Fi is disabled"
    check "S95nanokvm applies the lockdown"    contains system/init.d/S95nanokvm "harden.sh apply"
    check "default-deny OUTPUT policy"         contains hardening/harden.sh ":OUTPUT DROP"
    echo
    echo "== Removed features absent"
    check "no PicoClaw bundle"                 absent picoclaw
    check "no PicoClaw init script"            absent system/init.d/S96picoclaw
    check "no stock online updater script"     absent system/update-nanokvm.py
    echo
    if ls "$PKG/.signature/manifest" >/dev/null 2>&1; then
        echo "== Signed: yes (verify with nanokvm-sign verify)"
    else
        echo "== Signed: no (sign it with nanokvm-sign before uploading)"
    fi
    echo
    echo "== Bundled Tailscale"
    cat "$PKG/tailscale/VERSION" 2>/dev/null || echo "  (no VERSION file)"
    cat "$PKG/tailscale/SOURCE.sha256" 2>/dev/null || true
    echo
    echo "== ELF files shipped"
    find "$PKG" -type f -print0 | sort -z | while IFS= read -r -d '' f; do
        if [ "$(head -c4 "$f" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; then
            printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$PKG"/}"
        fi
    done
    echo
    echo "== Endpoint strings per file (informational)"
    echo "   Hostnames and URLs embedded in shipped files. Dead code still shows up"
    echo "   here; only tailscaled's user can open a connection to any of them."
    find "$PKG" -type f -print0 | sort -z | while IFS= read -r -d '' f; do
        hits=$(strings -n 6 "$f" 2>/dev/null \
            | grep -oE '(https?|wss?)://[A-Za-z0-9._-]+\.[A-Za-z]{2,}|[A-Za-z0-9-]+\.(sipeed\.com|maixhub\.com|aliyuncs\.com|qq\.com|baidu\.com|tailscale\.(com|io)|openai\.com|anthropic\.com)|\b(114\.114\.114\.114|119\.29\.29\.29|223\.5\.5\.5|8\.8\.8\.8|8\.8\.4\.4)\b' \
            | grep -vE 'example\.(invalid|com)|localhost|\.local\b|w3\.org|xmlsoap|schemas\.|purl\.org|apache\.org|golang\.org|github\.com/[A-Za-z]' \
            | LC_ALL=C sort -u | head -n 40 || true)
        if [ -n "$hits" ]; then
            echo "  ${f#"$PKG"/}"
            echo "$hits" | sed 's/^/      /'
        fi
    done
} > "$REPORT"
cat "$REPORT"

if [ "$fail" -ne 0 ]; then
    echo "[ERROR] hardened package audit failed; see $REPORT" >&2
    exit 1
fi

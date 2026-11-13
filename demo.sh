#!/usr/bin/env bash
#
# zapsend demo — a complete round trip on a single machine.
#
#   ./demo.sh
#   BIN=./target/release/zapsend ./demo.sh
#   SIZE_MB=64 ./demo.sh
#
# Why one machine can run both ends: the receiver takes its own API port
# (--port 53400) while multicast discovery stays on 53317, exactly as the
# protocol expects. The two processes therefore never fight over a socket.
#
# The script tries real multicast discovery first. If the network blocks it
# (guest wifi, corporate VLAN, many VMs) it falls back to --ip and says so,
# which is also the advice zapsend prints when a scan comes up empty.

set -euo pipefail

BIN="${BIN:-./target/debug/zapsend}"
PORT="${PORT:-53400}"
SIZE_MB="${SIZE_MB:-8}"

if [[ -t 1 ]]; then
    B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[0m'
else
    B=""; D=""; G=""; Y=""; R=""
fi

step() { printf '\n%s▸ %s%s\n' "$B" "$*" "$R"; }
note() { printf '%s  %s%s\n' "$D" "$*" "$R"; }
ok()   { printf '%s✓ %s%s\n' "$G" "$*" "$R"; }
warn() { printf '%s! %s%s\n' "$Y" "$*" "$R"; }

if [[ ! -x "$BIN" ]]; then
    note "binary not found, building…"
    cargo build
fi

WORK="$(mktemp -d)"
RECV_PID=""
cleanup() {
    if [[ -n "$RECV_PID" ]]; then
        kill "$RECV_PID" 2>/dev/null || true
        wait "$RECV_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

mkdir -p "$WORK/inbox"
dd if=/dev/urandom of="$WORK/payload.bin" bs=1048576 count="$SIZE_MB" 2>/dev/null

step "starting receiver on :$PORT"
"$BIN" receive --port "$PORT" --alias nas --dir "$WORK/inbox" >"$WORK/receiver.log" 2>&1 &
RECV_PID=$!
sleep 1.5
note "pid $RECV_PID, saving to $WORK/inbox"

step "discovering devices"
"$BIN" discover --wait 4 >"$WORK/discover.log" 2>/dev/null || true
cat "$WORK/discover.log"

if grep -q "nas" "$WORK/discover.log"; then
    step "sending ${SIZE_MB}MB over discovery"
    "$BIN" send "$WORK/payload.bin" --to nas --scan 3
else
    warn "multicast is blocked on this network — falling back to --ip"
    note "this is the same escape hatch zapsend suggests when a scan finds nothing"
    step "sending ${SIZE_MB}MB over --ip"
    "$BIN" send "$WORK/payload.bin" --ip "127.0.0.1:$PORT"
fi

step "verifying"
if [[ ! -f "$WORK/inbox/payload.bin" ]]; then
    warn "file never arrived"
    echo
    cat "$WORK/receiver.log"
    exit 1
fi

SRC_SHA="$(sha_of "$WORK/payload.bin")"
DST_SHA="$(sha_of "$WORK/inbox/payload.bin")"

note "source $SRC_SHA"
note "dest   $DST_SHA"

if [[ "$SRC_SHA" == "$DST_SHA" ]]; then
    ok "byte-identical (${SIZE_MB}MB)"
else
    warn "checksum mismatch"
    exit 1
fi

step "receiver log"
cat "$WORK/receiver.log"

printf '\n%sDone.%s\n\n' "$B" "$R"

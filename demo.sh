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
export ZAPSEND_CONFIG="$WORK/hosts.json"
RECV_PID=""
VAULT_PID=""
cleanup() {
    for pid in "$RECV_PID" "$VAULT_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
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

# Three files of different sizes, so the demo exercises a real multi-file
# transfer rather than one big blob.
mkdir -p "$WORK/inbox"
dd if=/dev/urandom of="$WORK/photo.jpg" bs=1048576 count="$SIZE_MB" 2>/dev/null
dd if=/dev/urandom of="$WORK/notes.pdf" bs=1024 count=340 2>/dev/null
dd if=/dev/urandom of="$WORK/clip.mp4" bs=1048576 count="$((SIZE_MB / 2 + 1))" 2>/dev/null
FILES=("$WORK/photo.jpg" "$WORK/notes.pdf" "$WORK/clip.mp4")

step "starting receiver on :$PORT"
"$BIN" receive --port "$PORT" --alias nas --dir "$WORK/inbox" >"$WORK/receiver.log" 2>&1 &
RECV_PID=$!
sleep 1.5
note "pid $RECV_PID, saving to $WORK/inbox"

FINGERPRINT="$(grep -o 'fingerprint [0-9a-f]*' "$WORK/receiver.log" | awk '{print $2}' | head -1)"
note "peer fingerprint ${FINGERPRINT:0:16}…"

step "discovering devices"
"$BIN" discover --wait 4 >"$WORK/discover.log" 2>/dev/null || true
cat "$WORK/discover.log"

if grep -q "nas" "$WORK/discover.log"; then
    step "sending 3 files over discovery (fingerprint pinned automatically)"
    "$BIN" send "${FILES[@]}" --to nas --scan 3
else
    warn "multicast is blocked on this network — falling back to --ip"
    note "the fingerprint still comes from the receiver, so TLS stays pinned"
    step "sending 3 files over --ip with an explicit fingerprint"
    "$BIN" send "${FILES[@]}" --ip "127.0.0.1:$PORT" --fingerprint "$FINGERPRINT"
fi

step "verifying"
FAILED=0
for src in "${FILES[@]}"; do
    name="$(basename "$src")"
    dst="$WORK/inbox/$name"
    if [[ ! -f "$dst" ]]; then
        warn "$name never arrived"
        FAILED=1
        continue
    fi
    a="$(sha_of "$src")"
    b="$(sha_of "$dst")"
    if [[ "$a" == "$b" ]]; then
        ok "$name  ${a:0:16}…"
    else
        warn "$name  checksum mismatch"
        FAILED=1
    fi
done

if [[ "$FAILED" -ne 0 ]]; then
    echo
    cat "$WORK/receiver.log"
    exit 1
fi

step "refusing an unverified --ip send"
# Capture first, then grep: see the wrong-fingerprint step for why.
"$BIN" send "$WORK/notes.pdf" --ip "127.0.0.1:$PORT" >"$WORK/no_fp.log" 2>&1 || true
if grep -q "without a verified certificate fingerprint" "$WORK/no_fp.log"; then
    ok "bare --ip was refused, with the fix in the message"
else
    warn "bare --ip was NOT refused"
    cat "$WORK/no_fp.log"
    exit 1
fi

step "trust on first use saves the fingerprint"
"$BIN" send "$WORK/notes.pdf" --ip "127.0.0.1:$PORT" --tofu >"$WORK/tofu.log" 2>&1
if grep -q "127.0.0.1:$PORT" "$WORK/hosts.json" 2>/dev/null; then
    ok "fingerprint saved under 127.0.0.1:$PORT"
else
    warn "--tofu did not save the fingerprint"
    cat "$WORK/tofu.log" "$WORK/hosts.json" 2>/dev/null
    exit 1
fi
"$BIN" send "$WORK/notes.pdf" --ip "127.0.0.1:$PORT" >"$WORK/tofu2.log" 2>&1
if grep -q "pinned to" "$WORK/tofu2.log"; then
    ok "second send verified against the saved fingerprint"
else
    warn "second send was not pinned"
    cat "$WORK/tofu2.log"
    exit 1
fi

step "rejecting a wrong fingerprint"
# Capture first, then grep: `| grep -q` closes the pipe early, the sender dies
# of SIGPIPE, and `set -o pipefail` would report failure even on a match.
"$BIN" send "$WORK/notes.pdf" \
    --ip "127.0.0.1:$PORT" \
    --fingerprint "0000000000000000000000000000000000000000000000000000000000000000" \
    >"$WORK/pin.log" 2>&1 || true

if grep -q "pinning failed" "$WORK/pin.log"; then
    ok "wrong fingerprint was refused"
else
    warn "wrong fingerprint was NOT refused"
    cat "$WORK/pin.log"
    exit 1
fi

step "PIN protection"
VAULT_PORT=$((PORT + 1))
mkdir -p "$WORK/vault"
"$BIN" receive --port "$VAULT_PORT" --alias vault --pin 424242 --dir "$WORK/vault" >"$WORK/vault.log" 2>&1 &
VAULT_PID=$!
sleep 1.5
VAULT_FP="$(grep -o 'fingerprint [0-9a-f]*' "$WORK/vault.log" | awk '{print $2}' | head -1)"

"$BIN" send "$WORK/notes.pdf" --ip "127.0.0.1:$VAULT_PORT" --fingerprint "$VAULT_FP" --pin 000000 >"$WORK/pin_bad.log" 2>&1 || true
if grep -q "rejected the PIN" "$WORK/pin_bad.log"; then
    ok "wrong PIN refused"
else
    warn "wrong PIN was NOT refused"
    cat "$WORK/pin_bad.log"
    exit 1
fi

"$BIN" send "$WORK/notes.pdf" --ip "127.0.0.1:$VAULT_PORT" --fingerprint "$VAULT_FP" --pin 424242 >"$WORK/pin_ok.log" 2>&1 || true
if [[ -f "$WORK/vault/notes.pdf" ]]; then
    ok "correct PIN accepted"
else
    warn "correct PIN did not get through"
    cat "$WORK/pin_ok.log"
    exit 1
fi

step "receiver log"
cat "$WORK/receiver.log"

printf '\n%sDone.%s\n\n' "$B" "$R"

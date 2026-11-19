#!/bin/bash
# Interop against an independent LocalSend implementation: lsq.
#
#   https://github.com/AlexDevFlow/lsq — a Rust CLI by someone who is not us.
#
# Both ends being zapsend proves nothing about the protocol; it proves the code
# agrees with itself. This script puts someone else's code on the other side,
# in all three directions, and compares SHA-256. It found two real bugs the day
# it was first run:
#
#   * `send --ip host:53320` connected to 53317, because the port the peer
#     *announced* overwrote the port we had just reached.
#   * `pull` could not talk to a peer that serves the Download API over plain
#     HTTP, because it never tried the other scheme.
#
# Usage: ./tests/interop-lsq.sh [path-to-zapsend]
set -u
Z=${1:-$(dirname "$0")/../target/release/zapsend}
LSQ_VERSION=v0.1.0
WANTV=$(sed -n 's/^version = "\(.*\)"/\1/p' "$(dirname "$0")/../Cargo.toml" | head -1)
HAVEV=$("$Z" --version 2>/dev/null | awk '{print $2}')
if [ "$WANTV" != "$HAVEV" ]; then
  echo "refusing to run: $Z reports '$HAVEV', Cargo.toml says '$WANTV'" >&2
  exit 1
fi

T=$(mktemp -d)
export ZAPSEND_CONFIG="$T/hosts.json"
PIDS=()
pass=0
fail=0
check() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "  ✓ $1"; else fail=$((fail+1)); echo "  ✗ $1 — want [$3] got [$2]"; fi; }
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

echo "▸ fetching lsq $LSQ_VERSION"
curl -sL -o "$T/lsq.tgz" \
  "https://github.com/AlexDevFlow/lsq/releases/download/$LSQ_VERSION/lsq-x86_64-unknown-linux-gnu.tar.gz" \
  || { echo "cannot download lsq; skipping" >&2; exit 0; }
tar xzf "$T/lsq.tgz" -C "$T"
LSQ="$T/lsq"

mkdir -p "$T/in" "$T/a" "$T/b" "$T/c"
head -c 3000000 /dev/urandom > "$T/in/payload.bin"
echo hello-from-zapsend > "$T/in/note.txt"
sha_in_bin=$(sha256sum "$T/in/payload.bin" | cut -d' ' -f1)
sha_in_txt=$(sha256sum "$T/in/note.txt" | cut -d' ' -f1)

echo "▸ A. zapsend send → lsq receive (they are the receiver)"
"$LSQ" --ephemeral --alias lsq-recv --port 53320 receive --dest "$T/a" --yes > "$T/a.log" 2>&1 &
PIDS+=($!)
sleep 3
"$Z" send "$T/in/payload.bin" "$T/in/note.txt" --ip 127.0.0.1:53320 --tofu --json > "$T/a.json" 2>/dev/null
check 'exit code' "$?" '0'
check 'the peer took both files' "$(jq -r '.ok' "$T/a.json")" 'true'
check 'payload arrived intact' "$(sha256sum "$T/a/payload.bin" 2>/dev/null | cut -d' ' -f1)" "$sha_in_bin"
check 'note arrived intact' "$(sha256sum "$T/a/note.txt" 2>/dev/null | cut -d' ' -f1)" "$sha_in_txt"

echo "▸ B. lsq send → zapsend receive (we are the receiver)"
"$Z" receive --dir "$T/b" --port 53321 > "$T/b.log" 2>&1 &
PIDS+=($!)
sleep 3
"$LSQ" --ephemeral --alias lsq-send --port 53322 send "$T/in/payload.bin" "$T/in/note.txt" \
  --to 127.0.0.1:53321 > "$T/b-send.log" 2>&1
check 'their sender reported success' "$?" '0'
check 'payload arrived intact' "$(sha256sum "$T/b/payload.bin" 2>/dev/null | cut -d' ' -f1)" "$sha_in_bin"
check 'note arrived intact' "$(sha256sum "$T/b/note.txt" 2>/dev/null | cut -d' ' -f1)" "$sha_in_txt"

echo "▸ C. zapsend pull ← lsq share (their Download API, over plain HTTP)"
"$LSQ" --ephemeral --alias lsq-share --port 53330 share "$T/in/payload.bin" "$T/in/note.txt" > "$T/c.log" 2>&1 &
PIDS+=($!)
sleep 3
"$Z" pull --ip 127.0.0.1:53330 --tofu --dir "$T/c" --json > "$T/c.json" 2>/dev/null
check 'exit code' "$?" '0'
check 'both files pulled' "$(jq -r '.count' "$T/c.json")" '2'
check 'payload arrived intact' "$(sha256sum "$T/c/payload.bin" 2>/dev/null | cut -d' ' -f1)" "$sha_in_bin"
check 'note arrived intact' "$(sha256sum "$T/c/note.txt" 2>/dev/null | cut -d' ' -f1)" "$sha_in_txt"

echo
[ $fail -eq 0 ] && echo "INTEROP TESTS: $pass checks, all passed" || echo "INTEROP TESTS: $pass checks, $fail failed"
[ $fail -eq 0 ]

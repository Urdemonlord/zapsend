#!/bin/bash
# Security + sync verification for the security/sync-hardening front.
#
#   ./tests/security-ip-sync.sh [path-to-zapsend]
#
# Covers, against one local receiver:
#   1. bare `--ip` (no fingerprint) is refused, with the fix in the message
#   2. `--ip --fingerprint` sends, verified
#   3. `--tofu` saves the fingerprint; a later bare `--ip` verifies against it
#   4. `sync` without --replace reports a changed file as a conflict and
#      leaves the receiver's copy alone
#   5. `sync --replace` overwrites it, hash-verified, with no `name (1)` copy
#   6. plain `send` still never clobbers: a second send lands as `name (1)`
set -u
Z=${1:-$(dirname "$0")/../target/release/zapsend}
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

sha_of() { sha256sum "$1" | cut -d' ' -f1; }
PORT=53440
mkdir -p "$T/recv" "$T/src" "$T/sync-src"
echo "hello-security" > "$T/src/note.txt"
echo "v1,aaa" > "$T/sync-src/report.csv"

"$Z" receive --port "$PORT" --alias sec-recv --dir "$T/recv" > "$T/receiver.log" 2>&1 &
PIDS+=($!)
sleep 2
FP=$(grep -o 'fingerprint [0-9a-f]*' "$T/receiver.log" | awk '{print $2}' | head -1)
check 'receiver printed a fingerprint' "${#FP}" '64'

echo "▸ 1. bare --ip is refused"
"$Z" send "$T/src/note.txt" --ip "127.0.0.1:$PORT" > "$T/no_fp.log" 2>&1
check 'exit code non-zero' "$?" '1'
check 'message names the fix' "$(grep -c 'without a verified certificate fingerprint' "$T/no_fp.log")" '1'
check 'message offers --tofu' "$(grep -c -- '--tofu' "$T/no_fp.log")" '1'
check 'nothing arrived' "$(ls "$T/recv" 2>/dev/null | wc -l)" '0'

echo "▸ 2. --ip --fingerprint sends"
"$Z" send "$T/src/note.txt" --ip "127.0.0.1:$PORT" --fingerprint "$FP" > "$T/fp.log" 2>&1
check 'exit code' "$?" '0'
check 'file arrived intact' "$(sha_of "$T/recv/note.txt")" "$(sha_of "$T/src/note.txt")"

echo "▸ 3. --tofu saves, later bare --ip verifies"
"$Z" send "$T/src/note.txt" --ip "127.0.0.1:$PORT" --tofu > "$T/tofu.log" 2>&1
check 'exit code' "$?" '0'
check 'fingerprint saved under the address' "$(grep -c "127.0.0.1:$PORT" "$T/hosts.json")" '1'
"$Z" send "$T/src/note.txt" --ip "127.0.0.1:$PORT" > "$T/tofu2.log" 2>&1
check 'exit code' "$?" '0'
check 'second send pinned' "$(grep -c 'pinned to' "$T/tofu2.log")" '1'

echo "▸ 4. sync without --replace: conflict, receiver untouched"
"$Z" sync "$T/sync-src" --ip "127.0.0.1:$PORT" --fingerprint "$FP" > "$T/sync1.log" 2>&1
check 'first sync exit code' "$?" '0'
check 'report.csv arrived (v1)' "$(sha_of "$T/recv/report.csv")" "$(sha_of "$T/sync-src/report.csv")"
SHA_V1=$(sha_of "$T/recv/report.csv")
echo "v2,bbb,more" > "$T/sync-src/report.csv"
"$Z" sync "$T/sync-src" --ip "127.0.0.1:$PORT" --fingerprint "$FP" > "$T/sync2.log" 2>&1
check 'conflicting sync exits non-zero' "$?" '1'
check 'conflict named' "$(grep -c 'report.csv' "$T/sync2.log")" '1'
check 'receiver still holds v1' "$(sha_of "$T/recv/report.csv")" "$SHA_V1"

echo "▸ 5. sync --replace overwrites, hash-verified"
"$Z" sync "$T/sync-src" --ip "127.0.0.1:$PORT" --fingerprint "$FP" --replace > "$T/sync3.log" 2>&1
check 'replace sync exit code' "$?" '0'
check 'receiver now holds v2' "$(sha_of "$T/recv/report.csv")" "$(sha_of "$T/sync-src/report.csv")"
check 'no duplicate copy' "$(ls "$T/recv" | grep -c 'report (1)' || true)" '0'
"$Z" sync "$T/sync-src" --ip "127.0.0.1:$PORT" --fingerprint "$FP" > "$T/sync4.log" 2>&1
check 'second sync is a no-op' "$?" '0'

echo "▸ 6. plain send still never clobbers"
"$Z" send "$T/src/note.txt" --ip "127.0.0.1:$PORT" --fingerprint "$FP" > "$T/dup.log" 2>&1
check 'exit code' "$?" '0'
check 'second copy landed as note (1).txt' "$(test -f "$T/recv/note (1).txt" && echo yes || echo no)" 'yes'
check 'original untouched' "$(sha_of "$T/recv/note.txt")" "$(sha_of "$T/src/note.txt")"

echo
[ $fail -eq 0 ] && echo "SECURITY+SYNC TESTS: $pass checks, all passed" || echo "SECURITY+SYNC TESTS: $pass checks, $fail failed"
[ $fail -eq 0 ]

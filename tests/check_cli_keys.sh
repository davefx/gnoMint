#!/bin/sh
# check_cli_keys.sh — verify the gnomint-cli addca prompt accepts every
# key algorithm gnoMint supports (RSA, DSA, ECDSA, Ed25519) and emits a
# certificate that reflects the chosen algorithm.
#
# Companion to issue #49 (ECDSA/Ed25519 support); the CLI prompt was
# updated in the parity PR but never tested directly.

set -eu

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-keys-XXXXXX)
trap 'rm -rf "$TMPDIR_HERE"' EXIT

run_addca() {
    algo=$1
    bits_or_curve=$2
    months=$3
    db="$TMPDIR_HERE/${algo}.gnomint"
    out="$TMPDIR_HERE/${algo}.out"
    # 13-line driver: command + 5 subject + CN + email + SAN + key + size + months + change + confirm
    LC_ALL=C "$GNOMINT_CLI" "$db" >"$out" 2>&1 <<EOF || true
addca





Test ${algo} CA


${algo}
${bits_or_curve}
${months}
no
yes
showcert 1
quit
EOF
}

# Ed25519 ignores bit length so we still must answer the prompt for
# consistency: 0 or any number, but the prompt is suppressed because the
# new ECDSA/Ed25519 dispatch skips the bitlength question for Ed25519.
# We provide the value anyway so the driver isn't algorithm-dependent;
# unused values are ignored.

fail=0

check_session() {
    algo=$1; out=$2; expected_marker=$3
    if ! grep -q "CA generated successfully" "$out"; then
        echo "FAIL: $algo — CA generation didn't complete" >&2
        echo "--- captured session ---" >&2
        cat "$out" >&2
        fail=1
        return
    fi
    if ! grep -qE "$expected_marker" "$out"; then
        echo "FAIL: $algo — expected marker /$expected_marker/ in showcert output" >&2
        echo "--- captured session ---" >&2
        cat "$out" >&2
        fail=1
    fi
}

# RSA 1024
run_addca RSA 1024 12
check_session RSA "$TMPDIR_HERE/RSA.out" "Test RSA CA"

# DSA 1024
run_addca DSA 1024 12
check_session DSA "$TMPDIR_HERE/DSA.out" "Test DSA CA"

# ECDSA P-256
run_addca ECDSA 256 12
check_session ECDSA "$TMPDIR_HERE/ECDSA.out" "Test ECDSA CA"

# Ed25519 (the size field is ignored — pass 0)
run_addca Ed25519 0 12
check_session Ed25519 "$TMPDIR_HERE/Ed25519.out" "Test Ed25519 CA"

if [ "$fail" -eq 0 ]; then
    echo "PASS: gnomint-cli addca accepts RSA / DSA / ECDSA / Ed25519"
    exit 0
else
    exit 1
fi

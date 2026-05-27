#!/bin/bash
# tests/check_cli_algorithms.sh — verify CA creation and certificate signing
# with every supported key algorithm: RSA, ECDSA (P-256/384/521), Ed25519.
set -euo pipefail

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}

CLI="$GNOMINT_CLI"
if [ ! -x "$CLI" ]; then
    echo "SKIP: $CLI not built or not executable" >&2
    exit 77
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

run_algo_test() {
    local algo="$1"
    local extra_prompts="$2"
    local db="$TMPDIR/algo-${algo}.gnomint"

    # Create CA with the given algorithm, then sign a server cert under it
    # addca prompts: C, ST, L, O, OU, CN, email, SAN, keytype, [bitlen/curve], months, change?[No], sure?[Yes]
    LC_ALL=C "$CLI" "$db" >"$TMPDIR/${algo}-setup.txt" 2>&1 <<EOF
addca
US


Test Org

${algo} Test CA


${algo}
${extra_prompts}
240
No
Yes
addservercert 1 web ${algo}-test.example.com
listcert
quit
EOF

    if ! grep -q "CA generated successfully" "$TMPDIR/${algo}-setup.txt"; then
        echo "FAIL [${algo}]: CA creation failed"
        cat "$TMPDIR/${algo}-setup.txt" >&2
        return 1
    fi

    if ! grep -q "Certificate generated successfully" "$TMPDIR/${algo}-setup.txt"; then
        echo "FAIL [${algo}]: server cert signing failed"
        cat "$TMPDIR/${algo}-setup.txt" >&2
        return 1
    fi

    # Verify both certs are listed
    local cert_count
    cert_count=$(grep -c "Test CA\|test.example" "$TMPDIR/${algo}-setup.txt" || true)
    if [ "$cert_count" -lt 2 ]; then
        echo "FAIL [${algo}]: expected 2 certs in listcert, found $cert_count"
        cat "$TMPDIR/${algo}-setup.txt" >&2
        return 1
    fi

    echo "  ${algo}: CA created + server cert signed OK"
    return 0
}

failures=0

# RSA 2048
run_algo_test "RSA" "2048" || ((failures++))

# ECDSA P-256
run_algo_test "ECDSA" "256" || ((failures++))

# ECDSA P-384
db="$TMPDIR/algo-ECDSA-384.gnomint"
LC_ALL=C "$CLI" "$db" >"$TMPDIR/ECDSA-384-setup.txt" 2>&1 <<EOF
addca
US


Test Org

ECDSA-384 Test CA


ECDSA
384
240
No
Yes
addservercert 1 web ecdsa384-test.example.com
quit
EOF
if grep -q "Certificate generated successfully" "$TMPDIR/ECDSA-384-setup.txt"; then
    echo "  ECDSA P-384: CA created + server cert signed OK"
else
    echo "FAIL [ECDSA P-384]: server cert signing failed"
    cat "$TMPDIR/ECDSA-384-setup.txt" >&2
    ((failures++))
fi

# ECDSA P-521
db="$TMPDIR/algo-ECDSA-521.gnomint"
LC_ALL=C "$CLI" "$db" >"$TMPDIR/ECDSA-521-setup.txt" 2>&1 <<EOF
addca
US


Test Org

ECDSA-521 Test CA


ECDSA
521
240
No
Yes
addservercert 1 web ecdsa521-test.example.com
quit
EOF
if grep -q "Certificate generated successfully" "$TMPDIR/ECDSA-521-setup.txt"; then
    echo "  ECDSA P-521: CA created + server cert signed OK"
else
    echo "FAIL [ECDSA P-521]: server cert signing failed"
    cat "$TMPDIR/ECDSA-521-setup.txt" >&2
    ((failures++))
fi

# Ed25519
run_algo_test "Ed25519" "" || ((failures++))

if [ "$failures" -gt 0 ]; then
    echo "FAIL: $failures algorithm(s) failed"
    exit 1
fi

echo "PASS: all algorithms create CAs and sign server certs"

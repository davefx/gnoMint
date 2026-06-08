#!/bin/bash
# tests/check_cli_parity.sh — exercises the CLI commands added in the
# GUI/CLI parity pass: renewcert, exportchain, revokemany, deletemany.
# Pinned to LC_ALL=C so prompts accept the literal "Yes" string.
set -euo pipefail

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
SRCDIR="${srcdir:-.}"
FIXTURE="${FIXTURE:-${SRCDIR}/../certs/example-ca.gnomint}"

CLI="$GNOMINT_CLI"
if [ ! -x "$CLI" ]; then
    echo "SKIP: $CLI not built or not executable" >&2
    exit 77
fi
if [ ! -r "$FIXTURE" ]; then
    echo "SKIP: fixture $FIXTURE not readable" >&2
    exit 77
fi
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

DB="$TMPDIR/cli-parity.gnomint"
CHAIN="$TMPDIR/chain.pem"
RENEWDB="$TMPDIR/renew-test.gnomint"

cp "$FIXTURE" "$DB"
chmod 644 "$DB"

# --- Test 1: CA renewal must be rejected ---
LC_ALL=C "$CLI" "$DB" >"$TMPDIR/ca_renew.txt" 2>&1 <<EOF
renewcert 2
quit
EOF
grep -q "CA certificates cannot be renewed" "$TMPDIR/ca_renew.txt"
echo "  CA renewal rejection: OK"

# --- Test 2: exportchain, revokemany, deletemany, search, diff ---
LC_ALL=C "$CLI" "$DB" >"$TMPDIR/out.txt" 2>&1 <<EOF
exportchain 5 $CHAIN
revokemany 6 7
deletemany 1
search gnomint
search xx-no-such-cert-xx
diff 1 5
diff 1 1
quit
EOF

grep -q "Full chain.*written to $CHAIN" "$TMPDIR/out.txt"
grep -q "2 certificates revoked" "$TMPDIR/out.txt"
grep -q "CSR deleted" "$TMPDIR/out.txt"
grep -q "gnomint-program" "$TMPDIR/out.txt"
grep -q "0 matches\." "$TMPDIR/out.txt"
grep -qE "^[1-9][0-9]* fields? differ\." "$TMPDIR/out.txt"
grep -qE "^0 fields? differ\." "$TMPDIR/out.txt"

BEGIN=$(grep -c "BEGIN CERTIFICATE" "$CHAIN")
if [ "$BEGIN" -lt 2 ]; then
    echo "FAIL: chain has only $BEGIN BEGIN markers (expected >= 2)"
    exit 1
fi
echo "  exportchain / revokemany / deletemany / search / diff: OK"

# --- Test 3: successful non-CA renewal ---
# Create a fresh DB with an RSA root CA (gets SKI from GnuTLS) and a
# server cert under it, then renew the server cert.
# addca prompts: C, ST, L, O, OU, CN, email, SAN, keytype, bitlen,
#                months, "change anything?"[No], "are you sure?"[Yes]
LC_ALL=C "$CLI" "$RENEWDB" >"$TMPDIR/renew_setup.txt" 2>&1 <<EOF
addca
US


Test Org

Renewal Test CA


RSA
2048
240
No
Yes
addservercert 1 web renewal-test.example.com
quit
EOF

grep -q "Certificate generated successfully" "$TMPDIR/renew_setup.txt" || {
    echo "FAIL: could not create test CA + server cert for renewal test:"
    cat "$TMPDIR/renew_setup.txt" >&2
    exit 1
}

# CA is id 1, server cert is id 2. Renew the server cert.
LC_ALL=C "$CLI" "$RENEWDB" >"$TMPDIR/renew_result.txt" 2>&1 <<EOF
renewcert 2
Yes
quit
EOF

if grep -q "Certificate renewed" "$TMPDIR/renew_result.txt"; then
    echo "  renewcert (non-CA): OK"
else
    echo "FAIL: renewcert did not succeed:"
    cat "$TMPDIR/renew_result.txt" >&2
    exit 1
fi

echo "PASS: renewcert / exportchain / revokemany / deletemany all work end-to-end"

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

cp "$FIXTURE" "$DB"

LC_ALL=C "$CLI" "$DB" >"$TMPDIR/out.txt" 2>&1 <<EOF
renewcert 2
Yes
exportchain 2 $CHAIN
revokemany 5 6
deletemany 1
search gnoMint
search xx-no-such-cert-xx
diff 1 3
diff 1 1
quit
EOF

grep -q "Certificate renewed" "$TMPDIR/out.txt"
grep -q "Full chain.*written to $CHAIN" "$TMPDIR/out.txt"
grep -q "2 certificates revoked" "$TMPDIR/out.txt"
grep -q "CSR deleted" "$TMPDIR/out.txt"
# search command must surface the matching cert and report 0 for a bogus pattern
grep -q "gnoMint program" "$TMPDIR/out.txt"
grep -q "0 matches\." "$TMPDIR/out.txt"
# diff command: comparing distinct certs reports >= 1 differences,
# comparing a cert against itself reports 0.
grep -qE "^[1-9][0-9]* fields? differ\." "$TMPDIR/out.txt"
grep -qE "^0 fields? differ\." "$TMPDIR/out.txt"

# Confirm chain has at least 2 BEGIN markers (leaf + root for a level-1 cert)
BEGIN=$(grep -c "BEGIN CERTIFICATE" "$CHAIN")
if [ "$BEGIN" -lt 2 ]; then
    echo "FAIL: chain has only $BEGIN BEGIN markers (expected >= 2)"
    exit 1
fi

echo "PASS: renewcert / exportchain / revokemany / deletemany all work end-to-end"

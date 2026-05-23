#!/bin/sh
# check_cli_dhgen.sh - exercise gnomint-cli `dhgen`. Generation is slow
# because GnuTLS has to find a safe prime; we use the minimum acceptable
# size and gate behind GNOMINT_TEST_DHGEN=1 so `make check` stays fast
# by default. To run: GNOMINT_TEST_DHGEN=1 make -C tests check.

set -eu

if [ "${GNOMINT_TEST_DHGEN:-0}" != "1" ]; then
    echo "SKIP: set GNOMINT_TEST_DHGEN=1 to run this test (it takes 30s+)" >&2
    exit 77
fi

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-dhgen-XXXXXX)
trap 'rm -rf "$TMPDIR_HERE"' EXIT

DB="$TMPDIR_HERE/dh.gnomint"
PFILE="$TMPDIR_HERE/dh.pem"
OUT="$TMPDIR_HERE/out.txt"

LC_ALL=C "$GNOMINT_CLI" "$DB" >"$OUT" 2>&1 <<INNER || true
dhgen 1024 $PFILE
quit
INNER

if [ ! -s "$PFILE" ]; then
    echo "FAIL: dhgen didn't create $PFILE" >&2
    cat "$OUT" >&2
    exit 1
fi
if ! grep -q "DH PARAMETERS" "$PFILE"; then
    echo "FAIL: $PFILE doesn't contain DH PARAMETERS marker" >&2
    head -5 "$PFILE" >&2
    exit 1
fi

echo "PASS: gnomint-cli dhgen wrote a valid PKCS#3 DH parameter file"

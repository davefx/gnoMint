#!/bin/sh
# check_cli_import.sh - verify gnomint-cli `importfile` ingests a PEM
# certificate. We generate a small self-signed cert with OpenSSL, then
# import it and check that listcert sees the new entry.

set -eu

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "SKIP: openssl not available to generate fixture PEM" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-import-XXXXXX)
if command -v cygpath >/dev/null 2>&1; then TMPDIR_HERE=$(cygpath -m "$TMPDIR_HERE"); fi
trap 'rm -rf "$TMPDIR_HERE"' EXIT

PEM="$TMPDIR_HERE/imported.pem"
DB="$TMPDIR_HERE/import.gnomint"
OUT="$TMPDIR_HERE/out.txt"

# Generate a small self-signed cert. -nodes => key is unencrypted, so
# importfile won't need a passphrase.
MSYS2_ARG_CONV_EXCL='*' openssl req -x509 -newkey rsa:2048 -nodes \
    -days 30 \
    -subj "/CN=Imported External Cert" \
    -keyout "$TMPDIR_HERE/key.pem" \
    -out "$PEM" 2>/dev/null

LC_ALL=C "$GNOMINT_CLI" "$DB" >"$OUT" 2>&1 <<INNER || true
importfile $PEM
listcert
quit
INNER

if ! grep -q "File imported successfully" "$OUT"; then
    echo "FAIL: import didn't report success" >&2
    cat "$OUT" >&2
    exit 1
fi
# listcert truncates the subject to ~14 chars in the table view; look for
# the prefix that survives the truncation.
if ! grep -q "Imported Extern" "$OUT"; then
    echo "FAIL: imported cert not visible in listcert output" >&2
    echo "--- captured ---" >&2
    cat "$OUT" >&2
    echo "--- end ---" >&2
    exit 1
fi

echo "PASS: gnomint-cli importfile absorbs an external PEM certificate"

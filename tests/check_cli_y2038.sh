#!/bin/bash
# tests/check_cli_y2038.sh — verifies that a certificate expiring well past the
# Year-2038 boundary is managed correctly REGARDLESS OF THE HOST ARCHITECTURE.
#
# The fixture certs/example-ca.gnomint contains "Y2038 Future Test CA", a CA
# whose notAfter is in 2076. gnoMint stores dates as 64-bit integers in the
# database, so this date must display correctly even on a 32-bit-time_t build
# (i386), where GnuTLS's time_t API would otherwise cap it at 2038-01-19.
#
# This test fails on a build that truncates dates to 32-bit time_t for display
# (the pre-fix i386 behaviour: listcert showed 2038, or list and detail
# disagreed). It passes identically on amd64 and i386.
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
if command -v cygpath >/dev/null 2>&1; then TMPDIR=$(cygpath -m "$TMPDIR"); fi
trap 'rm -rf "$TMPDIR"' EXIT
DB="$TMPDIR/y2038.gnomint"
cp "$FIXTURE" "$DB"
chmod 644 "$DB"

# listcert truncates the subject column to 16 chars, so match on a prefix.
CANAME="Y2038 Future Test CA"
CANAME_PREFIX="Y2038 Future Tes"

# --- locate the far-future CA and capture its list row -----------------------
LC_ALL=C "$CLI" "$DB" >"$TMPDIR/list.txt" 2>&1 <<EOF
listcert
quit
EOF

ROW=$(grep -F "$CANAME_PREFIX" "$TMPDIR/list.txt" || true)
if [ -z "$ROW" ]; then
    echo "FAIL: fixture is missing '$CANAME'" >&2
    cat "$TMPDIR/list.txt" >&2
    exit 1
fi

CERT_ID=$(printf '%s' "$ROW" | awk '{print $1}')
echo "  found '$CANAME' as cert id $CERT_ID"

# --- 1) listcert must show 2076, never the 2038 overflow ---------------------
if ! printf '%s' "$ROW" | grep -q "2076"; then
    echo "FAIL: listcert does not show year 2076 for '$CANAME'" >&2
    echo "  row: $ROW" >&2
    exit 1
fi
if printf '%s' "$ROW" | grep -qE "01/19/2038|/2038 03:14"; then
    echo "FAIL: listcert shows the 2038 overflow date for '$CANAME'" >&2
    echo "  row: $ROW" >&2
    exit 1
fi
echo "  listcert shows 2076: OK"

# --- 2) showcert must agree with listcert (both 2076, same exact date) -------
# This is the cross-view consistency guarantee: the detail view sources its
# dates from the same 64-bit database columns as the list, so the two never
# disagree (the pre-fix i386 behaviour was list=2076, detail=2038).
LC_ALL=C "$CLI" "$DB" >"$TMPDIR/show.txt" 2>&1 <<EOF
showcert $CERT_ID
quit
EOF

EXPLINE=$(grep -E "Expires on:" "$TMPDIR/show.txt" || true)
if ! printf '%s' "$EXPLINE" | grep -q "2076"; then
    echo "FAIL: showcert does not show year 2076 for '$CANAME'" >&2
    echo "  '$EXPLINE'" >&2
    echo "  (list and detail must agree; detail must not cap at 2038)" >&2
    exit 1
fi

# Extract the MM/DD/YYYY date from the list row and from the detail line; they
# must be identical.
LIST_DATE=$(printf '%s' "$ROW"     | grep -oE '[0-9]{2}/[0-9]{2}/2076' | tail -1)
SHOW_DATE=$(printf '%s' "$EXPLINE" | grep -oE '[0-9]{2}/[0-9]{2}/2076' | tail -1)
if [ -z "$LIST_DATE" ] || [ "$LIST_DATE" != "$SHOW_DATE" ]; then
    echo "FAIL: list ('$LIST_DATE') and detail ('$SHOW_DATE') disagree on the expiration" >&2
    exit 1
fi
echo "  showcert agrees with listcert ($SHOW_DATE): OK"

echo "PASS: 2076 certificate managed correctly on $(uname -m)"
exit 0

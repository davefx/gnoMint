#!/bin/bash
# tests/check_cli_y2038_import.sh — importing a post-2038 certificate must
# either show the correct dates (where time_t is 64-bit) or warn the user that
# the date cannot be represented (where time_t is 32-bit). It must NEVER store
# a wrong date silently. Architecture-independent.
#
# Fixture certs/y2038-cert.pem is a CA certificate whose notAfter is in 2076.
set -euo pipefail

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
SRCDIR="${srcdir:-.}"
PEM="${SRCDIR}/../certs/y2038-cert.pem"

CLI="$GNOMINT_CLI"
if [ ! -x "$CLI" ]; then
    echo "SKIP: $CLI not built or not executable" >&2
    exit 77
fi
if [ ! -r "$PEM" ]; then
    echo "SKIP: fixture $PEM not readable" >&2
    exit 77
fi

TMPDIR=$(mktemp -d)
if command -v cygpath >/dev/null 2>&1; then TMPDIR=$(cygpath -m "$TMPDIR"); fi
trap 'rm -rf "$TMPDIR"' EXIT
DB="$TMPDIR/import.gnomint"

# --- import the 2076 certificate -------------------------------------------
IMPORT_OUT=$(LC_ALL=C "$CLI" "$DB" <<EOF 2>&1
importfile $PEM
quit
EOF
)

if ! printf '%s' "$IMPORT_OUT" | grep -q "File imported successfully"; then
    echo "FAIL: import did not report success" >&2
    printf '%s\n' "$IMPORT_OUT" >&2
    exit 1
fi

# --- list the imported certificate -----------------------------------------
LIST_OUT=$(printf 'listcert\nquit\n' | LC_ALL=C "$CLI" "$DB" 2>&1)
ROW=$(printf '%s' "$LIST_OUT" | grep -F "Y2038 Future Tes" || true)
if [ -z "$ROW" ]; then
    echo "FAIL: imported certificate not visible in listcert" >&2
    printf '%s\n' "$LIST_OUT" >&2
    exit 1
fi

# --- the guarantee: correct date OR an explicit warning --------------------
DATE_OK=false
WARNED=false
printf '%s' "$ROW" | grep -q "2076" && DATE_OK=true
# A capping warning at import, or the inline "(after 2038?)" list marker.
printf '%s' "$IMPORT_OUT" | grep -qiE "after 2038|cannot represent" && WARNED=true
printf '%s' "$ROW"        | grep -qiE "after 2038"                  && WARNED=true

if $DATE_OK; then
    echo "PASS: imported certificate shows the correct 2076 date ($(uname -m))"
elif $WARNED; then
    echo "PASS: imported certificate's uncapped date warned, not silently wrong ($(uname -m))"
else
    echo "FAIL: imported post-2038 date neither correct nor warned" >&2
    echo "--- import output ---" >&2; printf '%s\n' "$IMPORT_OUT" >&2
    echo "--- list row ---" >&2;     printf '%s\n' "$ROW" >&2
    exit 1
fi

# --- and never a silently-wrong cached date in the database ----------------
# (We can only assert this cheaply via the CLI: the row must not claim a
#  pre-2038 expiration year for a certificate that really expires in 2076.)
if printf '%s' "$ROW" | grep -qE "/(2037|2036|2035) "; then
    if ! printf '%s' "$ROW" | grep -qiE "after 2038"; then
        echo "FAIL: row shows a pre-2038 year with no warning for a 2076 cert" >&2
        printf '%s\n' "$ROW" >&2
        exit 1
    fi
fi

exit 0

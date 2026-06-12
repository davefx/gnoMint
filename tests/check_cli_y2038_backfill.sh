#!/bin/bash
# tests/check_cli_y2038_backfill.sh — NULL-date handling and self-healing.
#
# Simulates a database written by a host that could not represent a post-2038
# date: we MANUALLY NULL the activation/expiration of the 2076 CA in a copy of
# the test database, then open it with gnomint-cli and check the architecture-
# appropriate behaviour:
#
#   * 64-bit time_t: ca_file_open() backfills the NULL columns from the PEM, so
#     the database now holds the real 2076 date and the list shows it.
#   * 32-bit time_t: the columns stay NULL (the host still cannot represent the
#     date and must not write a wrong one); the list re-derives from the PEM and
#     flags the value with an "(after 2038?)" marker.
#
# Requires the sqlite3 CLI to nullify the columns; SKIPs if unavailable.
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
if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "SKIP: sqlite3 CLI not available (needed to nullify the test dates)" >&2
    exit 77
fi

TMPDIR=$(mktemp -d)
if command -v cygpath >/dev/null 2>&1; then TMPDIR=$(cygpath -m "$TMPDIR"); fi
trap 'rm -rf "$TMPDIR"' EXIT
DB="$TMPDIR/backfill.gnomint"
cp "$FIXTURE" "$DB"
chmod 644 "$DB"

# --- locate the 2076 CA ----------------------------------------------------
ID=$(printf 'listcert\nquit\n' | LC_ALL=C "$CLI" "$DB" 2>&1 \
        | grep -F "Y2038 Future Tes" | awk '{print $1}')
if [ -z "$ID" ]; then
    echo "FAIL: fixture is missing the 2076 CA" >&2
    exit 1
fi
echo "  2076 CA is cert id $ID"

# --- manually nullify its dates --------------------------------------------
sqlite3 "$DB" "UPDATE certificates SET activation=NULL, expiration=NULL WHERE id=$ID;"
BEFORE=$(sqlite3 "$DB" "SELECT count(*) FROM certificates WHERE id=$ID AND expiration IS NULL;")
if [ "$BEFORE" != "1" ]; then
    echo "FAIL: could not nullify the dates (got count=$BEFORE)" >&2
    exit 1
fi
echo "  dates nullified in the database"

# --- open with gnomint-cli (this triggers the backfill on a capable host) ---
ROW=$(printf 'listcert\nquit\n' | LC_ALL=C "$CLI" "$DB" 2>&1 \
        | grep -F "Y2038 Future Tes" || true)
if [ -z "$ROW" ]; then
    echo "FAIL: 2076 CA vanished from listcert after nullifying" >&2
    exit 1
fi

# --- inspect the database AFTER opening ------------------------------------
AFTER=$(sqlite3 "$DB" "SELECT expiration FROM certificates WHERE id=$ID;")

if [ -n "$AFTER" ]; then
    # Backfilled (64-bit time_t host): column is now populated — must be 2076.
    YEAR=$(sqlite3 "$DB" "SELECT strftime('%Y', expiration, 'unixepoch') FROM certificates WHERE id=$ID;")
    if [ "$YEAR" != "2076" ]; then
        echo "FAIL: backfilled the wrong year ($YEAR, expected 2076)" >&2
        exit 1
    fi
    if ! printf '%s' "$ROW" | grep -q "2076"; then
        echo "FAIL: backfilled column but list does not show 2076" >&2
        printf '%s\n' "$ROW" >&2
        exit 1
    fi
    echo "PASS: NULL dates self-healed (backfilled to 2076) on $(uname -m)"
else
    # Not backfilled (32-bit time_t host): column stays NULL; list re-derives
    # and must flag the value rather than show a silently-capped date.
    if ! printf '%s' "$ROW" | grep -qiE "after 2038"; then
        echo "FAIL: NULL date on a 32-bit host shown without the '(after 2038?)' marker" >&2
        printf '%s\n' "$ROW" >&2
        exit 1
    fi
    echo "PASS: NULL dates kept NULL and flagged (no wrong value written) on $(uname -m)"
fi

exit 0

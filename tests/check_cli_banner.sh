#!/bin/sh
# check_cli_banner.sh - verify that gnomint-cli prints the "Notice: N
# certificates expire within..." line (issue #56) when opening a
# database that contains soon-to-expire certs.

set -eu

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-banner-XXXXXX)
PREV_WARN=$(gsettings get org.gnome.gnomint expire-warning-days 2>/dev/null || echo 30)
gsettings set org.gnome.gnomint expire-warning-days 90 || true
cleanup() {
    rm -rf "$TMPDIR_HERE"
    gsettings set org.gnome.gnomint expire-warning-days "$PREV_WARN" 2>/dev/null || true
}
trap cleanup EXIT

DB="$TMPDIR_HERE/banner.gnomint"
CREATE_OUT="$TMPDIR_HERE/create.out"
REOPEN_OUT="$TMPDIR_HERE/reopen.out"

LC_ALL=C "$GNOMINT_CLI" "$DB" >"$CREATE_OUT" 2>&1 <<'INNER' || true
addca





Soon To Expire CA


RSA
1024
1
no
yes
quit
INNER

if ! grep -q "CA generated successfully" "$CREATE_OUT"; then
    echo "FAIL: setup - CA creation did not complete" >&2
    cat "$CREATE_OUT" >&2
    exit 1
fi

LC_ALL=C "$GNOMINT_CLI" "$DB" >"$REOPEN_OUT" 2>&1 <<'INNER' || true
quit
INNER

if ! grep -qE "Notice: [0-9]+ certificates? expires? within" "$REOPEN_OUT"; then
    echo "FAIL: expected expiry notice missing from reopen output" >&2
    echo "--- captured ---" >&2
    cat "$REOPEN_OUT" >&2
    echo "--- end ---" >&2
    exit 1
fi

echo "PASS: gnomint-cli prints the expiry notice (#56) on database open"

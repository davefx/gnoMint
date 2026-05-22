#!/bin/sh
# check_cli_info.sh — exercise the read-only / informational gnomint-cli
# commands. These don't change state, so we run them all in a single
# session and grep the captured output for each command's signature
# text.
#
# Commands covered:
#   - version
#   - about
#   - warranty
#   - distribution
#   - help
#   - status                  (after opening a DB)
#   - showpreferences         (after opening a DB)
#   - listcert / listcsr      (on the empty fresh DB, just runs cleanly)

set -eu

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-info-XXXXXX)
trap 'rm -rf "$TMPDIR_HERE"' EXIT

DB="$TMPDIR_HERE/info-test.gnomint"
OUT="$TMPDIR_HERE/out.txt"

# Pipe a sequence of informational commands. The first run creates an
# empty DB at $DB (newdb), then runs the read-only commands.
LC_ALL=C "$GNOMINT_CLI" "$DB" >"$OUT" 2>&1 <<EOF
version
about
warranty
distribution
help
status
showpreferences
listcert
listcsr
quit
EOF

# Each assertion captures a unique substring known to be in the
# output of the corresponding command. Order doesn't matter — grep
# only checks presence.

fail=0
check() {
    if ! grep -q "$1" "$OUT"; then
        echo "FAIL: expected pattern '$1' missing from output" >&2
        fail=1
    fi
}

check "gnoMint version"                            # version
check "ABSOLUTELY NO WARRANTY"                     # about / warranty
check "redistribute"                               # distribution / about
check "warranty"                                   # help lists 'warranty' as a command
check "Current opened file"                        # status
check "current preferences"                        # showpreferences
check "Certificates in Database"                   # listcert
check "Certificate Requests in Database"           # listcsr

if [ $fail -eq 0 ]; then
    echo "PASS: 8 informational gnomint-cli commands produced expected output"
    exit 0
else
    echo "FAIL: see $OUT for full session output" >&2
    cat "$OUT" >&2 || true
    exit 1
fi

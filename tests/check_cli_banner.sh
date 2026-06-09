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
cleanup() {
    rm -rf "$TMPDIR_HERE"
}
trap cleanup EXIT

# Use the keyfile backend so the test works everywhere (Linux containers,
# macOS, Windows/MSYS2) without needing dconf or a D-Bus session.
export GSETTINGS_BACKEND=keyfile
export XDG_CONFIG_HOME="$TMPDIR_HERE/config"
mkdir -p "$XDG_CONFIG_HOME/glib-2.0/settings"
printf '[org/gnome/gnomint]\nexpire-warning-days=90\n' \
    > "$XDG_CONFIG_HOME/glib-2.0/settings/keyfile"

# Compile the GSettings schema into a local directory so g_settings_new()
# can find it regardless of whether `make install` ran.
SCHEMA_SRC="${abs_top_srcdir:-..}/gconf/org.gnome.gnomint.gschema.xml"
if [ ! -f "$SCHEMA_SRC" ]; then
    for d in /usr/local/share/glib-2.0/schemas /usr/share/glib-2.0/schemas; do
        if [ -f "$d/gschemas.compiled" ]; then
            export GSETTINGS_SCHEMA_DIR="$d"
            break
        fi
    done
else
    SCHEMA_DIR="$TMPDIR_HERE/schemas"
    mkdir -p "$SCHEMA_DIR"
    cp "$SCHEMA_SRC" "$SCHEMA_DIR/"
    glib-compile-schemas "$SCHEMA_DIR"
    export GSETTINGS_SCHEMA_DIR="$SCHEMA_DIR"
fi

DB="$TMPDIR_HERE/banner.gnomint"
CREATE_OUT="$TMPDIR_HERE/create.out"
REOPEN_OUT="$TMPDIR_HERE/reopen.out"

# addca prompts: C, ST, L, O, OU, CN, Email, SAN, Key type, Key size,
# Months, Change?, Confirm.  We create a CA expiring in 1 month so the
# 90-day warning fires.
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

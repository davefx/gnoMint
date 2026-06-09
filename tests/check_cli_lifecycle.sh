#!/bin/sh
# check_cli_lifecycle.sh — exercise the gnomint-cli commands that still
# had no test coverage as of the comprehensive sweep.
#
# Strategy: use the wizard `addservercert` to create signed certs in one
# shot (avoids the addcsr/sign two-step), then exercise everything that
# operates on the resulting state. addcsr / delete / revoke / setpolicy /
# setpreference all ask for a Yes/No confirmation, so every confirmation
# answer below is right after the command that triggers it.
#
# Skipped — see task #93 follow-ups: extractcertpkey, extractcsrpkey
# (interactive passphrase entry that's awkward to feed from stdin),
# changepassword (same), importfile, importdir, dhgen (slow and needs
# fixtures).

set -eu

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}
if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-life-XXXXXX)
# On MSYS2, convert POSIX /tmp to Windows path for the native MinGW binary
if command -v cygpath >/dev/null 2>&1; then TMPDIR_HERE=$(cygpath -m "$TMPDIR_HERE"); fi
trap 'rm -rf "$TMPDIR_HERE"' EXIT

DB="$TMPDIR_HERE/life.gnomint"
SAVED="$TMPDIR_HERE/life-copy.gnomint"
CRL="$TMPDIR_HERE/ca1.crl.pem"
OUT="$TMPDIR_HERE/out.txt"

# Each Yes/yes/no below answers a specific confirmation prompt right
# after the command that triggers it. Comments mark prompt boundaries.
LC_ALL=C "$GNOMINT_CLI" "$DB" >"$OUT" 2>&1 <<EOF || true
addca
ES
Madrid
Madrid
gnoMint CLI Test
QA
Test Lifecycle Root CA


RSA
1024
12
no
yes
status
listcert
showcert 1
addservercert 1 web example.com
listcert
showcert 2
showpolicy 1
setpolicy 1 12 60
Yes
showpolicy 1
setpreference 0 0
Yes
showpreferences
addcsr





Throwaway CSR


RSA
1024
no
yes
listcsr
showcsr 1
delete 1
Yes
revoke 2
Yes
listcert --see-revoked
crlgen 1 $CRL
savedbas $SAVED
status
quit
EOF

fail=0
check() {
    label=$1; pattern=$2
    if ! grep -qE "$pattern" "$OUT"; then
        echo "FAIL: $label — expected /$pattern/ in output" >&2
        fail=1
    fi
}

# State-creation
check "addca created cert"      "CA generated successfully"
check "status sees DB path"     "Current opened file"
check "listcert shows CA"       "Test Lifecycle Root CA"
check "showcert 1 CA"           "Test Lifecycle Root CA"

# addservercert produced cert id 2
check "addservercert OK"        "Certificate generated successfully"
check "listcert sees signed"    "example.com"
check "showcert 2 CN"           "example.com"

# Policy commands
check "showpolicy table"        "months before expiration"
check "setpolicy ran"           "Policy set correctly"

# Preferences
check "setpreference ran"       "Gnome keyring support"
check "showpreferences output"  "current preferences"

# CSR lifecycle
check "addcsr OK"               "CSR generated successfully"
check "addcsr leaf"             "Throwaway CSR"
check "listcsr sees CSR"        "Throwaway CSR"
check "showcsr CN"              "Throwaway CSR"
check "delete OK"               "Request deleted|CSR deleted"

# Revocation + CRL
check "revoke OK"               "Certificate revoked"
check "crlgen wrote CRL"        "CRL generated successfully"

# savedbas wrote the second DB
if [ ! -s "$SAVED" ]; then
    echo "FAIL: savedbas didn't create $SAVED" >&2
    fail=1
fi

# CRL file content sanity
if [ -s "$CRL" ]; then
    if ! grep -q "BEGIN X509 CRL\|BEGIN CRL" "$CRL"; then
        echo "FAIL: $CRL exists but lacks BEGIN marker" >&2
        fail=1
    fi
else
    echo "FAIL: $CRL not created or empty" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: 13 untested gnomint-cli commands exercised end-to-end"
    exit 0
else
    echo "--- captured session ---" >&2
    cat "$OUT" >&2
    echo "--- end captured session ---" >&2
    exit 1
fi

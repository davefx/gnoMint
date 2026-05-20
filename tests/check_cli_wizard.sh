#!/bin/sh
# check_cli_wizard.sh — verify gnomint-cli's `addservercert` command
# generates a working server certificate signed by the chosen CA.
#
# Companion to scenario_wizard_window in tests/check_workflows.c (which
# covers the GTK side). Together they exercise the wizard feature added
# in response to issue #15 / PR #16 on both interfaces gnoMint ships.
#
# Strategy:
#   - Spawn gnomint-cli against a fresh tempfile DB.
#   - Run addca to create a 1024-bit RSA CA (small for speed).
#   - Run addservercert <ca-id> web <server-name> to drive the wizard
#     non-interactively.
#   - Run showcert on the issued cert and grep for the server name.
#
# Failure modes the test catches:
#   - addservercert rejects a valid CA id (would be the case under the
#     pre-review-feedback ca_file_check_if_is_cert_id check, since a
#     just-created self-signed CA is technically also a cert).
#   - addservercert silently fails to generate a CSR or to sign it.
#   - The signed certificate doesn't carry the server name as its CN.

set -eu

# Force a known locale so the confirmation prompts accept "yes"/"no"
# verbatim regardless of the test environment's LANG setting.
LC_ALL=C
LANG=C
export LC_ALL LANG

GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}

if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-wizard-XXXXXX)
trap 'rm -rf "$TMPDIR_HERE"' EXIT INT TERM
TEST_DB="$TMPDIR_HERE/test.gnomint"
SERVER_NAME="web.example.test"

OUTPUT=$(
    "$GNOMINT_CLI" "$TEST_DB" <<EOF 2>&1 || true
addca





Wizard Test CA


RSA
1024
12
no
yes
addservercert 1 web $SERVER_NAME
showcert 2
exit
EOF
)

# The signed cert is id=2 (id=1 is the CA). showcert prints the subject
# Distinguished Name; the wizard sets CN to the server name.
if ! printf '%s\n' "$OUTPUT" | grep -q "CN=$SERVER_NAME"; then
    echo "FAIL: CN=$SERVER_NAME not found in showcert 2 output" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$OUTPUT" >&2
    echo "--- end captured output ---" >&2
    exit 1
fi

# Sanity: the user-facing "Certificate generated successfully" line is
# what addservercert prints on success. Make sure we hit it.
if ! printf '%s\n' "$OUTPUT" | grep -q "Certificate generated successfully"; then
    echo "FAIL: 'Certificate generated successfully' message not seen" >&2
    printf '%s\n' "$OUTPUT" >&2
    exit 1
fi

echo "PASS: addservercert produced a cert with CN=$SERVER_NAME"

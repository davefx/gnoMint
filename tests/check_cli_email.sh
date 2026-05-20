#!/bin/sh
# check_cli_email.sh — verify the gnomint-cli accepts an emailAddress when
# adding a CA and surfaces it in the certificate's Distinguished Name.
#
# Companion test to the email-address round-trip in tests/check_workflows.c
# (which covers the GTK side). Together they exercise the feature added in
# response to issue #19 on both interfaces gnoMint ships.
#
# Strategy:
#   - Spawn gnomint-cli pointing at a fresh tempfile DB.
#   - Pipe an addca conversation (RSA, 1024-bit, 12 months — small so the
#     test stays fast) including a known email address.
#   - Follow up with `showcert 1` in the same session.
#   - Grep the captured output for the email.
#
# Failure modes the test catches:
#   - addca skips or misorders the new email prompt.
#   - tls_generate_self_signed_certificate doesn't actually embed
#     GNUTLS_OID_PKCS9_EMAIL in the subject DN.
#   - tls_parse_cert_pem doesn't read the email back into the DN string
#     surfaced by `showcert`.

set -eu

# Allow override for distcheck etc.; default to in-tree build location.
GNOMINT_CLI=${GNOMINT_CLI:-../src/gnomint-cli}

if [ ! -x "$GNOMINT_CLI" ]; then
    echo "SKIP: $GNOMINT_CLI not built or not executable" >&2
    exit 77         # GNU autotest convention for SKIP.
fi

TMPDIR_HERE=$(mktemp -d /tmp/gnomint-cli-test-XXXXXX)
trap 'rm -rf "$TMPDIR_HERE"' EXIT INT TERM
TEST_DB="$TMPDIR_HERE/test.gnomint"
EMAIL="ca-cli-test@example.com"
CN="Test CLI CA"

# Pipe the addca conversation. Empty lines accept the (NULL) default for
# Country/State/Locality/Organization/OU. The email prompt is the new one
# this test exercises. SAN is left empty. RSA 1024-bit, 12-month validity.
OUTPUT=$(
    "$GNOMINT_CLI" "$TEST_DB" <<EOF 2>&1 || true
addca





$CN
$EMAIL

RSA
1024
12
no
yes
showcert 1
exit
EOF
)

if ! printf '%s\n' "$OUTPUT" | grep -q "$EMAIL"; then
    echo "FAIL: email '$EMAIL' not found in gnomint-cli output" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$OUTPUT" >&2
    echo "--- end captured output ---" >&2
    exit 1
fi

echo "PASS: gnomint-cli addca embedded '$EMAIL' visible via showcert"

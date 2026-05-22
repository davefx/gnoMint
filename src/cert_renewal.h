/*  gnoMint: certificate renewal entry point.
 *
 *  Takes an existing certificate (by database id), generates a fresh
 *  keypair, and signs a new certificate with the same subject + SAN as
 *  the original, using the parent CA's current policy for everything
 *  else (validity, key usage, extended key usage).
 *
 *  The old certificate is left untouched in the database — common
 *  practice is "issue new, deploy, revoke old". The caller can revoke
 *  the old cert explicitly via the existing menu.
 *
 *  Returns NULL on success and writes the new cert's database id into
 *  *new_cert_id_out (if non-NULL). On failure returns a freshly
 *  allocated error string the caller must g_free.
 */

#ifndef _CERT_RENEWAL_H_
#define _CERT_RENEWAL_H_

#include <glib.h>

gchar * cert_renewal_renew (guint64 cert_id, guint64 *new_cert_id_out);

#endif

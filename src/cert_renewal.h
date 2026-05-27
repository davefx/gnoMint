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
 *  CLI: Returns NULL on success and writes the new cert's database id
 *  into *new_cert_id_out (if non-NULL). On failure returns a freshly
 *  allocated error string the caller must g_free.
 *
 *  GUI: Asynchronous — the callback receives the error string (or NULL
 *  on success).  The caller must g_free the error.
 */

#ifndef _CERT_RENEWAL_H_
#define _CERT_RENEWAL_H_

#include <glib.h>

#ifdef GNOMINTCLI

gchar * cert_renewal_renew (guint64 cert_id, guint64 *new_cert_id_out);

#else

typedef void (*CertRenewalCallback)(gchar *error, gpointer user_data);

void cert_renewal_renew (guint64 cert_id, guint64 *new_cert_id_out,
                         CertRenewalCallback cb, gpointer user_data);

#endif

#endif

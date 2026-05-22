/* Bulk certificate / CSR operations.
 * Pure DB-layer helpers shared by the GUI (ca.c) and the CLI
 * (ca-cli-callbacks.c). No GTK / readline dependencies. */

#ifndef _CA_BULK_H_
#define _CA_BULK_H_

#include <glib.h>

/* Revoke every certificate whose id is in `cert_ids`. Skips entries
 * that aren't certs or are already revoked. Returns the count of
 * actually-revoked entries. If `error_out` is non-NULL, the first
 * underlying error is stored there (caller frees with g_free). */
gint ca_bulk_revoke_ids (GSList *cert_ids, gchar **error_out);

/* Delete every CSR whose id is in `csr_ids`. Skips entries that aren't
 * CSRs. Returns the count of actually-deleted entries. */
gint ca_bulk_delete_csr_ids (GSList *csr_ids, gchar **error_out);

#endif

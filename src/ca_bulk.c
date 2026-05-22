/* Bulk certificate / CSR operations. See ca_bulk.h. */

#include "ca_bulk.h"
#include "ca_file.h"

gint
ca_bulk_revoke_ids (GSList *cert_ids, gchar **error_out)
{
	gint count = 0;
	if (error_out)
		*error_out = NULL;
	for (GSList *l = cert_ids; l; l = l->next) {
		guint64 id = GPOINTER_TO_UINT (l->data);
		if (id == 0)
			continue;
		if (! ca_file_check_if_is_cert_id (id))
			continue;
		gchar *err = ca_file_revoke_crt (id);
		if (err) {
			if (error_out && ! *error_out)
				*error_out = err;
			else
				g_free (err);
			continue;
		}
		count++;
	}
	return count;
}

gint
ca_bulk_delete_csr_ids (GSList *csr_ids, gchar **error_out)
{
	gint count = 0;
	if (error_out)
		*error_out = NULL;
	for (GSList *l = csr_ids; l; l = l->next) {
		guint64 id = GPOINTER_TO_UINT (l->data);
		if (id == 0)
			continue;
		if (! ca_file_check_if_is_csr_id (id))
			continue;
		gchar *err = ca_file_remove_csr (id);
		if (err) {
			if (error_out && ! *error_out)
				*error_out = err;
			else
				g_free (err);
			continue;
		}
		count++;
	}
	return count;
}

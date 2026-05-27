//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006-2009 David Marín Carreño <davefx@gmail.com>
//
//  This file is part of gnoMint.
//
//  gnoMint is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 3 of the License, or   
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of 
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#ifndef GNOMINTCLI


#include <glib-object.h>
#include <gtk/gtk.h>
#include "gtk4-compat.h"
#include <gdk/gdk.h>
#include <glib/gi18n.h>

#endif

#include <stdlib.h>
#include <string.h>


#include "ca.h"
#include "ca_bulk.h"
#include "ca_file.h"
#ifndef GNOMINTCLI
#include "cert_row.h"
#endif
#include "certificate_properties.h"
#include "crl.h"
#include "csr_properties.h"
#include "dialog.h"
#include "export.h"
#include "new_ca_window.h"
#include "new_req_window.h"
#include "new_cert.h"
#include "cert_renewal.h"
#include "cert_diff.h"
#include "preferences-gui.h"
#include "preferences-window.h"
#include "import.h"
#include "wizard_window.h"

#ifndef GNOMINTCLI

#define GNOMINT_MIME_TYPE "application/x-gnomint"


enum {CA_MODEL_COLUMN_ID=0,
      CA_MODEL_COLUMN_IS_CA=1,
      CA_MODEL_COLUMN_SERIAL=2,
      CA_MODEL_COLUMN_SUBJECT=3,
      CA_MODEL_COLUMN_ACTIVATION=4,
      CA_MODEL_COLUMN_EXPIRATION=5,
      CA_MODEL_COLUMN_REVOCATION=6,
      CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB=7,
      CA_MODEL_COLUMN_PEM=8,
      CA_MODEL_COLUMN_DN=9,
      CA_MODEL_COLUMN_PARENT_DN=10,
      CA_MODEL_COLUMN_PARENT_ROUTE=11,
      CA_MODEL_COLUMN_ITEM_TYPE=12,
      CA_MODEL_COLUMN_PARENT_ID=13, /* Only for CSRs */
      CA_MODEL_COLUMN_FOREGROUND=14, /* GdkRGBA-style color name, or NULL
                                      * for default. "gray" for certs
                                      * with effective_expiration past
                                      * the current time. */
      CA_MODEL_COLUMN_NUMBER=15}
        CaModelColumns;

enum {CSR_MODEL_COLUMN_ID=0,
      CSR_MODEL_COLUMN_SUBJECT=1,
      CSR_MODEL_COLUMN_PRIVATE_KEY_IN_DB=2,
      CSR_MODEL_COLUMN_PEM=3,
      CSR_MODEL_COLUMN_PARENT_ID=4,
      CSR_MODEL_COLUMN_NUMBER=5}
        CsrModelColumns;




extern GtkBuilder * main_window_gtkb;
extern GtkBuilder * cert_popup_menu_gtkb;
extern GtkBuilder * csr_popup_menu_gtkb;


/* --- New GtkColumnView-based model (GTK 4 modernization) --- */
static GListStore        *ca_root_model      = NULL;  /* top-level GnomintCertRow items */
static GtkTreeListModel  *ca_tree_list_model  = NULL;
GtkMultiSelection *ca_selection_model  = NULL;
static GtkColumnView     *ca_columnview       = NULL;

/* Hash table used during model-rebuild: maps parent_route strings to
 * the GnomintCertRow that owns those children.  Only valid during a
 * single ca_refresh_model_callback invocation. */
static GHashTable *ca_route_to_row = NULL;
/* Parallel hash: "CSR" parent CA rows keyed by parent_id (string). */
static GHashTable *ca_id_to_row = NULL;

/* Pure helper exposed for unit tests: classify a row's foreground color
 * given its effective expiration timestamp, a "now" reference, and the
 * warning-window in days. Returns a static string literal (so callers
 * don't free it) or NULL for the default color.
 *
 *   effective_expiration  | now / warn_days     | result
 *   ---------------------+--------------------+-----------
 *   0  (no expiration)    | (any)              | NULL
 *   < now                 | (any)              | "gray"
 *   < now + warn_days*day | warn_days > 0      | "#cc7700"
 *   anything else                              | NULL
 */
const gchar *
ca_compute_row_foreground (time_t effective_expiration, time_t now,
                           gint warn_days)
{
    if (effective_expiration <= 0)
        return NULL;
    if (effective_expiration < now)
        return "gray";
    if (warn_days > 0) {
        time_t threshold = now + (time_t) warn_days * 86400;
        if (effective_expiration < threshold)
            return "#cc7700";
    }
    return NULL;
}

/* Simple "response" signal handler: destroy the dialog on any response.
 * Used for fire-and-forget informational dialogs presented with
 * gtk_window_present instead of the deprecated compat_dialog_run. */
static void
__ca_dialog_response_destroy (GtkDialog *dialog,
                              gint       response_id G_GNUC_UNUSED,
                              gpointer   user_data   G_GNUC_UNUSED)
{
    gtk_window_destroy (GTK_WINDOW (dialog));
}

/* Variant that also frees user_data with g_free after destroying the
 * dialog.  Used for the cert-diff viewer where a CertDiff* must be
 * released when the user closes the dialog. */
static void
__ca_dialog_response_destroy_and_free (GtkDialog *dialog,
                                       gint       response_id G_GNUC_UNUSED,
                                       gpointer   user_data)
{
    gtk_window_destroy (GTK_WINDOW (dialog));
    cert_diff_free ((CertDiff *) user_data);
}

/* ---- Async confirmation-dialog response callbacks (Step 2.1) ---- */

/* Helper: free a GSList stored as "ids" data on the dialog. */
static void
__ca_gslist_free_notify (gpointer data)
{
    g_slist_free ((GSList *) data);
}

/* Response callback for the bulk-revoke confirmation dialog.
 * cert_ids GSList is attached to the dialog as "ids". */
static void
__ca_bulk_revoke_response (GtkDialog *dialog,
                           gint       response_id,
                           gpointer   user_data G_GNUC_UNUSED)
{
    GSList *cert_ids = (GSList *) g_object_get_data (G_OBJECT (dialog), "ids");
    gtk_window_destroy (GTK_WINDOW (dialog));

    if (response_id != GTK_RESPONSE_YES)
        return;

    gchar *err = NULL;
    gint done = ca_bulk_revoke_ids (cert_ids, &err);

    if (err) {
        dialog_error (g_strdup_printf (
            _("Bulk revoke completed with errors. First error: %s"), err));
        g_free (err);
    }

    GObject *parent = gtk_builder_get_object (main_window_gtkb, "main_window1");
    gchar *summary = g_strdup_printf (
        ngettext ("%d certificate revoked.",
                  "%d certificates revoked.", done), done);
    GtkWidget *info = gtk_message_dialog_new (
        GTK_WINDOW (parent), GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE, "%s", summary);
    g_free (summary);
    g_signal_connect (info, "response",
                      G_CALLBACK (__ca_dialog_response_destroy), NULL);
    gtk_window_present (GTK_WINDOW (info));

    dialog_refresh_list ();
}

/* Response callback for the bulk-delete-CSRs confirmation dialog.
 * csr_ids GSList is attached to the dialog as "ids". */
static void
__ca_bulk_delete_csrs_response (GtkDialog *dialog,
                                gint       response_id,
                                gpointer   user_data G_GNUC_UNUSED)
{
    GSList *csr_ids = (GSList *) g_object_get_data (G_OBJECT (dialog), "ids");
    gtk_window_destroy (GTK_WINDOW (dialog));

    if (response_id != GTK_RESPONSE_YES)
        return;

    gchar *err = NULL;
    ca_bulk_delete_csr_ids (csr_ids, &err);

    if (err) {
        dialog_error (g_strdup_printf (
            _("Bulk delete completed with errors. First error: %s"), err));
        g_free (err);
    }
    dialog_refresh_list ();
}

static void
__ca_renew_done_cb (gchar *error, gpointer user_data)
{
    (void) user_data;
    if (error) {
        dialog_error (error);
        g_free (error);
        return;
    }
    dialog_info (_("Certificate renewed. A new certificate with a fresh "
                   "keypair has been added to the database alongside the "
                   "original."));
    ca_refresh_model_callback ();
}

/* Response callback for the certificate-renewal confirmation dialog.
 * cert_id is stored as a heap-allocated guint64 in user_data. */
static void
__ca_renew_response (GtkDialog *dialog,
                     gint       response_id,
                     gpointer   user_data)
{
    guint64 cert_id = *(guint64 *) user_data;
    gtk_window_destroy (GTK_WINDOW (dialog));
    g_free (user_data);

    if (response_id != GTK_RESPONSE_YES)
        return;

    cert_renewal_renew (cert_id, NULL,
                        __ca_renew_done_cb, NULL);
}

/* Response callback for the single-certificate-revoke confirmation dialog.
 * cert id is stored as a heap-allocated guint64 in user_data. */
static void
__ca_revoke_response (GtkDialog *dialog,
                      gint       response_id,
                      gpointer   user_data)
{
    guint64 id = *(guint64 *) user_data;
    gtk_window_destroy (GTK_WINDOW (dialog));
    g_free (user_data);

    if (response_id != GTK_RESPONSE_YES)
        return;

    gchar *errmsg = ca_file_revoke_crt (id);
    if (errmsg) {
        dialog_error (_(errmsg));
    }

    dialog_refresh_list ();
}

/* Response callback for the single-CSR-delete confirmation dialog.
 * csr id is stored as a heap-allocated guint64 in user_data. */
static void
__ca_delete_csr_response (GtkDialog *dialog,
                          gint       response_id,
                          gpointer   user_data)
{
    guint64 id = *(guint64 *) user_data;
    gtk_window_destroy (GTK_WINDOW (dialog));
    g_free (user_data);

    if (response_id != GTK_RESPONSE_YES)
        return;

    ca_file_remove_csr (id);
    dialog_refresh_list ();
}

static gboolean view_csr = TRUE;
static gboolean view_rcrt = TRUE;
static gboolean view_expired = TRUE;

/* Map ca_id (guint64 boxed as a pointer) → effective_expiration (time_t
 * boxed as a pointer). Used by the hide-expired filter to enforce the
 * RFC 5280 rule that a certificate's effective validity ends with its
 * issuing CA. Populated as ca_file_foreach_crt iterates: CAs come before
 * their descendants in hierarchical order, so by the time a descendant
 * is processed its CA's effective_expiration is already cached. Reset
 * each ca_refresh_model_callback. */
static GHashTable *ca_effective_expiration = NULL;

/* Count of certificates whose effective_expiration falls inside the
 * configured warning window. Reset to 0 at the start of every
 * ca_refresh_model_callback, incremented from __ca_refresh_model_add_certificate
 * each time ca_compute_row_foreground returns the amber colour. Used
 * to drive the expiry-banner shown above the tree view (issue #56). */
static gint ca_expiring_soon_count = 0;

/* The user may dismiss the banner; once dismissed for a given file
 * we don't show it again until the user re-opens the file. */
static gboolean ca_expiry_infobar_dismissed = FALSE;

/* "Show only expiring" filter mode (#56): when TRUE, the row-add
 * function skips any non-amber leaf row. CAs are always shown so the
 * tree hierarchy stays intact. Activated by the banner's "Show them"
 * action button; reset when the banner is dismissed or a new file is
 * opened. Non-static so the test scenario can flip it directly. */
gboolean ca_view_only_expiring = FALSE;

/* Custom GtkInfoBar response id for the banner's "Show them" button.
 * Chosen well outside the GtkResponseType range so it can't collide. */
#define CA_BANNER_RESPONSE_SHOW_THEM 100

/* Active search text for the filter box (#53). When non-empty, leaf
 * certificates whose subject/serial doesn't contain this substring
 * (case-insensitive) are hidden from the tree. Owned by ca.c; freed
 * on next change. */
static gchar *ca_search_text = NULL;

/* Does the haystack (UTF-8) contain the needle (UTF-8) ignoring case?
 * Both are assumed non-NULL; an empty needle matches anything. */
gboolean
__ca_search_match (const gchar *haystack, const gchar *needle)
{
	if (!needle || !*needle) return TRUE;
	if (!haystack) return FALSE;
	gchar *h = g_utf8_strdown (haystack, -1);
	gchar *n = g_utf8_strdown (needle, -1);
	gboolean m = (strstr (h, n) != NULL);
	g_free (h);
	g_free (n);
	return m;
}


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames);
int __ca_refresh_model_add_csr (void *pArg, int argc, char **argv, char **columnNames);

/* Helper: get the currently selected GnomintCertRow from the selection
 * model.  Returns NULL if nothing is selected or the selection is
 * empty.  The caller does NOT own the returned pointer (it's borrowed
 * from the model). */
static GnomintCertRow *__ca_get_selected_row (void);

/* Determine whether the selected row is a cert, CSR, or neither.
 * Returns CA_FILE_ELEMENT_TYPE_CERT, CA_FILE_ELEMENT_TYPE_CSR, or -1.
 * If row_out is non-NULL, stores the GnomintCertRow* there (borrowed). */
static gint __ca_selection_type_cv (GnomintCertRow **row_out);

void __ca_activate_certificate_selection_cv (GnomintCertRow *row);
void __ca_activate_csr_selection_cv (GnomintCertRow *row);
void __ca_deactivate_actions (void);
void __ca_export_public_pem_cv (GnomintCertRow *row, gint type);
void __ca_export_private_pkcs8_cv (GnomintCertRow *row, gint type);
void __ca_export_private_pem_cv (GnomintCertRow *row, gint type);
void __ca_export_pkcs12_cv (GnomintCertRow *row, gint type);

/* Date formatting helper: convert epoch string to locale date string.
 * Returns a newly allocated string, or NULL if the epoch is 0/empty. */
static gchar *__ca_format_epoch_to_date (const gchar *epoch_str);

void __disable_widget (gchar *widget_name);
void __enable_widget (gchar *widget_name);


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames)
{
	/* Search filter (#53): skip leaf certs whose subject/serial
	 * doesn't contain the active search text. CAs are always shown
	 * so the tree hierarchy stays intact and the search reveals
	 * which CA issued the matched leaves. Run before any allocation
	 * so the early-return is leak-free. */
	if (ca_search_text && *ca_search_text &&
	    argv[CA_FILE_CERT_COLUMN_IS_CA] &&
	    atoi (argv[CA_FILE_CERT_COLUMN_IS_CA]) == 0) {
		gboolean matched =
		    __ca_search_match (argv[CA_FILE_CERT_COLUMN_SUBJECT], ca_search_text) ||
		    __ca_search_match (argv[CA_FILE_CERT_COLUMN_SERIAL],  ca_search_text);
		if (! matched)
			return 0;
	}

	GListStore *root_store = G_LIST_STORE (pArg);

	/* Compute this cert's *effective* expiration: the earliest of its
	 * own notAfter and every ancestor CA's notAfter, per RFC 5280.
	 *
	 * Parent lookup uses parent_route, which is colon-delimited like
	 * ":3:5:" (this cert's parent is id 5, grandparent is id 3). For
	 * top-level certs parent_route is ":" — no parent, so effective
	 * expiration is just self_expiration.
	 *
	 * Because ca_file_foreach_crt yields certs in hierarchical order,
	 * by the time we see a leaf cert the entire CA chain is already
	 * cached in ca_effective_expiration. We also cache CAs we process
	 * so that any cert further down can look us up. */
	time_t self_expiration = (argv[CA_FILE_CERT_COLUMN_EXPIRATION] &&
				  argv[CA_FILE_CERT_COLUMN_EXPIRATION][0])
		? (time_t) g_ascii_strtoll (
		    argv[CA_FILE_CERT_COLUMN_EXPIRATION], NULL, 10)
		: 0;
	time_t effective_expiration = self_expiration;

	if (argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE]) {
		const gchar *route = argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE];
		const gchar *trailing = strrchr (route, ':');
		/* route looks like ":3:5:" — the immediate parent id sits
		 * between the second-to-last and the last ':'. */
		if (trailing && trailing != route) {
			const gchar *p = trailing - 1;
			while (p > route && *p != ':')
				p--;
			if (*p == ':' && p + 1 < trailing) {
				guint64 parent_id = g_ascii_strtoull (p + 1, NULL, 10);
				gpointer key = GUINT_TO_POINTER ((guint) parent_id);
				if (ca_effective_expiration &&
				    g_hash_table_contains (ca_effective_expiration, key)) {
					time_t parent_eff = (time_t) GPOINTER_TO_INT (
					    g_hash_table_lookup (ca_effective_expiration, key));
					if (parent_eff > 0 &&
					    (effective_expiration == 0 ||
					     parent_eff < effective_expiration))
						effective_expiration = parent_eff;
				}
			}
		}
	}

	/* Cache this CA's effective expiration so descendants pick it up. */
	if (argv[CA_FILE_CERT_COLUMN_IS_CA] &&
	    atoi (argv[CA_FILE_CERT_COLUMN_IS_CA]) == 1 &&
	    argv[CA_FILE_CERT_COLUMN_ID] && ca_effective_expiration) {
		guint64 self_id = g_ascii_strtoull (
		    argv[CA_FILE_CERT_COLUMN_ID], NULL, 10);
		g_hash_table_insert (ca_effective_expiration,
		                     GUINT_TO_POINTER ((guint) self_id),
		                     GINT_TO_POINTER ((gint) effective_expiration));
	}

	/* Skip if hiding expired and this cert (or its CA chain) is past. */
	if (! view_expired && effective_expiration > 0 &&
	    effective_expiration < time (NULL))
		return 0;

	const gchar *row_foreground = ca_compute_row_foreground (
	    effective_expiration, time (NULL),
	    preferences_get_expire_warning_days ());

	/* Count amber rows so we can drive the expiry banner (#56). */
	gboolean is_amber = (row_foreground &&
	                     g_strcmp0 (row_foreground, "#cc7700") == 0);
	if (is_amber)
		ca_expiring_soon_count++;

	/* "Show only expiring" mode (#56 "Show them"): hide non-amber
	 * leaves. CAs are always shown so the tree path to an amber
	 * leaf stays visible. */
	if (ca_view_only_expiring &&
	    argv[CA_FILE_CERT_COLUMN_IS_CA] &&
	    atoi (argv[CA_FILE_CERT_COLUMN_IS_CA]) == 0 &&
	    !is_amber)
		return 0;

	/* Build the GnomintCertRow for this certificate. */
	GnomintCertRow *row = gnomint_cert_row_new ();
	gnomint_cert_row_set_id (row, (guint64) atoll (argv[CA_FILE_CERT_COLUMN_ID]));
	gnomint_cert_row_set_is_ca (row, atoi (argv[CA_FILE_CERT_COLUMN_IS_CA]) != 0);
	gnomint_cert_row_set_serial (row, argv[CA_FILE_CERT_COLUMN_SERIAL]);

	if (argv[CA_FILE_CERT_COLUMN_REVOCATION]) {
		gchar *revoked_subject = g_markup_printf_escaped (
		    "<s>%s</s>", argv[CA_FILE_CERT_COLUMN_SUBJECT]);
		gnomint_cert_row_set_subject (row, revoked_subject);
		g_free (revoked_subject);
		gnomint_cert_row_set_revocation (row, TRUE);
	} else {
		gnomint_cert_row_set_subject (row, argv[CA_FILE_CERT_COLUMN_SUBJECT]);
		gnomint_cert_row_set_revocation (row, FALSE);
	}

	gnomint_cert_row_set_activation (row, argv[CA_FILE_CERT_COLUMN_ACTIVATION]);
	gnomint_cert_row_set_expiration (row, argv[CA_FILE_CERT_COLUMN_EXPIRATION]);
	gnomint_cert_row_set_pkey_in_db (row, atoi (argv[CA_FILE_CERT_COLUMN_PRIVATE_KEY_IN_DB]) != 0);
	gnomint_cert_row_set_pem (row, argv[CA_FILE_CERT_COLUMN_PEM]);
	gnomint_cert_row_set_dn (row, argv[CA_FILE_CERT_COLUMN_DN]);
	gnomint_cert_row_set_parent_dn (row, argv[CA_FILE_CERT_COLUMN_PARENT_DN]);
	gnomint_cert_row_set_parent_route (row, argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE]);
	gnomint_cert_row_set_item_type (row,
	    gnomint_cert_row_get_is_ca (row) ? GNOMINT_ROW_TYPE_CA : GNOMINT_ROW_TYPE_CERT);
	gnomint_cert_row_set_foreground (row, row_foreground);
	gnomint_cert_row_set_effective_expiration (row, effective_expiration);

	/* Find the parent: look up parent_route in the hash table.
	 * Top-level certs have parent_route ":" and go into root_store. */
	const gchar *parent_route = argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE];
	GListStore *target_store = root_store;

	if (parent_route && g_strcmp0 (parent_route, ":") != 0 && ca_route_to_row) {
		GnomintCertRow *parent_row = g_hash_table_lookup (
		    ca_route_to_row, parent_route);
		if (parent_row)
			target_store = gnomint_cert_row_get_children (parent_row);
	}

	g_list_store_append (target_store, row);

	/* Register this row so children can find it.  The key is
	 * parent_route + id + ":" — the route that a child of this
	 * row would carry. */
	if (ca_route_to_row) {
		gchar *my_route = g_strdup_printf (
		    "%s%" G_GUINT64_FORMAT ":",
		    parent_route ? parent_route : ":",
		    gnomint_cert_row_get_id (row));
		/* The hash table owns the key string. */
		g_hash_table_insert (ca_route_to_row, my_route, row);
	}

	/* Also register by ID so CSRs can find their parent CA. */
	if (ca_id_to_row) {
		gchar *id_str = g_strdup (argv[CA_FILE_CERT_COLUMN_ID]);
		g_hash_table_insert (ca_id_to_row, id_str, row);
	}

	g_object_unref (row);

	return 0;
}



int __ca_refresh_model_add_csr (void *pArg, int argc, char **argv, char **columnNames)
{
	/* Search filter (#53): skip CSRs whose subject doesn't match. */
	if (ca_search_text && *ca_search_text) {
		if (! __ca_search_match (argv[CA_FILE_CSR_COLUMN_SUBJECT],
		                          ca_search_text))
			return 0;
	}

	GListStore *root_store = G_LIST_STORE (pArg);

	GnomintCertRow *row = gnomint_cert_row_new ();
	gnomint_cert_row_set_id (row, (guint64) atoll (argv[CA_FILE_CSR_COLUMN_ID]));
	gnomint_cert_row_set_subject (row, argv[CA_FILE_CSR_COLUMN_SUBJECT]);
	gnomint_cert_row_set_pkey_in_db (row, atoi (argv[CA_FILE_CSR_COLUMN_PRIVATE_KEY_IN_DB]) != 0);
	gnomint_cert_row_set_pem (row, argv[CA_FILE_CSR_COLUMN_PEM]);
	gnomint_cert_row_set_item_type (row, GNOMINT_ROW_TYPE_CSR);
	if (argv[CA_FILE_CSR_COLUMN_PARENT_ID]) {
		gnomint_cert_row_set_parent_id (row,
		    (guint64) atoll (argv[CA_FILE_CSR_COLUMN_PARENT_ID]));
	}

	/* CSRs are shown as children of their parent CA in the tree.
	 * Look up the parent CA by its id string. If not found (or no
	 * parent), append to root. */
	GListStore *target_store = root_store;
	if (argv[CA_FILE_CSR_COLUMN_PARENT_ID] && ca_id_to_row) {
		GnomintCertRow *parent_row = g_hash_table_lookup (
		    ca_id_to_row, argv[CA_FILE_CSR_COLUMN_PARENT_ID]);
		if (parent_row)
			target_store = gnomint_cert_row_get_children (parent_row);
	}

	g_list_store_append (target_store, row);
	g_object_unref (row);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Date formatting helper (extracted from old tree-view data func)    */
/* ------------------------------------------------------------------ */

static gchar *
__ca_format_epoch_to_date (const gchar *epoch_str)
{
	if (!epoch_str || !epoch_str[0])
		return NULL;

	time_t model_time = (time_t) g_ascii_strtoll (epoch_str, NULL, 10);
	if (model_time == 0)
		return NULL;

	gchar buf[100];
#ifndef WIN32
	struct tm model_time_tm;
	gmtime_r (&model_time, &model_time_tm);
	strftime (buf, sizeof (buf), _("%m/%d/%Y %R GMT"), &model_time_tm);
#else
	struct tm *model_time_tm = gmtime (&model_time);
	strftime (buf, sizeof (buf), _("%m/%d/%Y %H:%M GMT"), model_time_tm);
#endif
	return g_strdup (buf);
}

/* ------------------------------------------------------------------ */
/*  GtkColumnView factory callbacks                                    */
/* ------------------------------------------------------------------ */

/* Helper: extract the GnomintCertRow from a GtkListItem.  The item in
 * a GtkTreeListModel-backed column view is a GtkTreeListRow; the
 * actual data object is obtained via gtk_tree_list_row_get_item(). */
static GnomintCertRow *
__ca_row_from_list_item (GtkListItem *list_item)
{
	GtkTreeListRow *tree_row = GTK_TREE_LIST_ROW (
	    gtk_list_item_get_item (list_item));
	if (!tree_row)
		return NULL;
	return GNOMINT_CERT_ROW (gtk_tree_list_row_get_item (tree_row));
}

/* --- Subject column (GtkTreeExpander + GtkLabel with markup) --- */

static void
__ca_subject_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                    GtkListItem *list_item,
                    gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *expander = gtk_tree_expander_new ();
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_label_set_use_markup (GTK_LABEL (label), TRUE);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_tree_expander_set_child (GTK_TREE_EXPANDER (expander), label);
	gtk_list_item_set_child (list_item, expander);
}

static void
__ca_subject_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                   GtkListItem *list_item,
                   gpointer user_data G_GNUC_UNUSED)
{
	GtkTreeListRow *tree_row = GTK_TREE_LIST_ROW (
	    gtk_list_item_get_item (list_item));
	GtkWidget *expander = gtk_list_item_get_child (list_item);
	gtk_tree_expander_set_list_row (GTK_TREE_EXPANDER (expander), tree_row);

	GnomintCertRow *row = GNOMINT_CERT_ROW (
	    gtk_tree_list_row_get_item (tree_row));
	GtkWidget *label = gtk_tree_expander_get_child (
	    GTK_TREE_EXPANDER (expander));

	const gchar *subject = gnomint_cert_row_get_subject (row);
	gtk_label_set_markup (GTK_LABEL (label), subject ? subject : "");

	const gchar *fg = gnomint_cert_row_get_foreground (row);
	if (fg) {
		/* Apply foreground colour via CSS. */
		GtkStyleContext *ctx = gtk_widget_get_style_context (label);
		GtkCssProvider *prov = gtk_css_provider_new ();
		gchar *css = g_strdup_printf ("label { color: %s; }", fg);
		gtk_css_provider_load_from_data (prov, css, -1);
		gtk_style_context_add_provider (ctx, GTK_STYLE_PROVIDER (prov),
		                                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		g_free (css);
		g_object_unref (prov);
	}
	g_object_unref (row);
}

/* --- Is-CA column (GtkImage) --- */

static void
__ca_is_ca_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                  GtkListItem *list_item,
                  gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *image = gtk_image_new ();
	gtk_list_item_set_child (list_item, image);
}

static void
__ca_is_ca_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                 GtkListItem *list_item,
                 gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = __ca_row_from_list_item (list_item);
	GtkWidget *image = gtk_list_item_get_child (list_item);

	if (row && gnomint_cert_row_get_is_ca (row)) {
		gchar *path = g_build_filename (
		    PACKAGE_DATA_DIR, "gnomint", "ca-stamp-16.png", NULL);
		gtk_image_set_from_file (GTK_IMAGE (image), path);
		g_free (path);
	} else {
		gtk_image_clear (GTK_IMAGE (image));
	}
	if (row) g_object_unref (row);
}

/* --- Private-key column (GtkImage) --- */

static void
__ca_pkey_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                 GtkListItem *list_item,
                 gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *image = gtk_image_new ();
	gtk_list_item_set_child (list_item, image);
}

static void
__ca_pkey_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                GtkListItem *list_item,
                gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = __ca_row_from_list_item (list_item);
	GtkWidget *image = gtk_list_item_get_child (list_item);

	if (row && gnomint_cert_row_get_pkey_in_db (row)) {
		gchar *path = g_build_filename (
		    PACKAGE_DATA_DIR, "gnomint", "key-16.png", NULL);
		gtk_image_set_from_file (GTK_IMAGE (image), path);
		g_free (path);
	} else {
		gtk_image_clear (GTK_IMAGE (image));
	}
	if (row) g_object_unref (row);
}

/* --- Serial column (GtkLabel) --- */

static void
__ca_serial_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                   GtkListItem *list_item,
                   gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_list_item_set_child (list_item, label);
}

static void
__ca_serial_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                  GtkListItem *list_item,
                  gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = __ca_row_from_list_item (list_item);
	GtkWidget *label = gtk_list_item_get_child (list_item);
	const gchar *serial = row ? gnomint_cert_row_get_serial (row) : NULL;
	gtk_label_set_text (GTK_LABEL (label), serial ? serial : "");

	const gchar *fg = row ? gnomint_cert_row_get_foreground (row) : NULL;
	if (fg) {
		GtkStyleContext *ctx = gtk_widget_get_style_context (label);
		GtkCssProvider *prov = gtk_css_provider_new ();
		gchar *css = g_strdup_printf ("label { color: %s; }", fg);
		gtk_css_provider_load_from_data (prov, css, -1);
		gtk_style_context_add_provider (ctx, GTK_STYLE_PROVIDER (prov),
		                                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		g_free (css);
		g_object_unref (prov);
	}
	if (row) g_object_unref (row);
}

/* --- Generic date column (Activation / Expiration / Revocation) --- */

/* The user_data for the date bind callback indicates which field:
 * 0 = activation, 1 = expiration, 2 = revocation. */
#define CA_DATE_ACTIVATION  0
#define CA_DATE_EXPIRATION  1
#define CA_DATE_REVOCATION  2

static void
__ca_date_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                 GtkListItem *list_item,
                 gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_list_item_set_child (list_item, label);
}

static void
__ca_date_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                GtkListItem *list_item,
                gpointer user_data)
{
	gint which = GPOINTER_TO_INT (user_data);
	GnomintCertRow *row = __ca_row_from_list_item (list_item);
	GtkWidget *label = gtk_list_item_get_child (list_item);

	const gchar *epoch_str = NULL;
	if (row) {
		switch (which) {
		case CA_DATE_ACTIVATION:
			epoch_str = gnomint_cert_row_get_activation (row);
			break;
		case CA_DATE_EXPIRATION:
			epoch_str = gnomint_cert_row_get_expiration (row);
			break;
		case CA_DATE_REVOCATION:
			/* Revocation is stored as a boolean; the epoch
			 * string is not stored separately. Show empty
			 * for non-revoked, or just "(revoked)" for revoked. */
			if (gnomint_cert_row_get_revocation (row))
				epoch_str = NULL; /* fall through to special handling */
			else
				epoch_str = NULL;
			break;
		default:
			epoch_str = NULL;
			break;
		}
	}

	/* For the revocation column, we don't have epoch data in the new
	 * model (revocation is a boolean). Show "Yes" / empty. */
	if (which == CA_DATE_REVOCATION) {
		if (row && gnomint_cert_row_get_revocation (row))
			gtk_label_set_text (GTK_LABEL (label), _("Yes"));
		else
			gtk_label_set_text (GTK_LABEL (label), "");
	} else {
		gchar *formatted = __ca_format_epoch_to_date (epoch_str);
		gtk_label_set_text (GTK_LABEL (label), formatted ? formatted : "");
		g_free (formatted);
	}

	const gchar *fg = row ? gnomint_cert_row_get_foreground (row) : NULL;
	if (fg) {
		GtkStyleContext *ctx = gtk_widget_get_style_context (label);
		GtkCssProvider *prov = gtk_css_provider_new ();
		gchar *css = g_strdup_printf ("label { color: %s; }", fg);
		gtk_css_provider_load_from_data (prov, css, -1);
		gtk_style_context_add_provider (ctx, GTK_STYLE_PROVIDER (prov),
		                                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		g_free (css);
		g_object_unref (prov);
	}
	if (row) g_object_unref (row);
}



/* GtkTreeListModel child-model callback: given a GnomintCertRow,
 * return its children GListStore (or NULL if empty/leaf). */
static GListModel *
__ca_tree_list_create_model (gpointer item, gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = GNOMINT_CERT_ROW (item);
	GListStore *children = gnomint_cert_row_get_children (row);
	if (g_list_model_get_n_items (G_LIST_MODEL (children)) == 0)
		return NULL;
	return G_LIST_MODEL (g_object_ref (children));
}

/* Helper: recursively expand all rows in the tree list model. */
static void
__ca_expand_all (GtkTreeListModel *tree_model)
{
	guint n = g_list_model_get_n_items (G_LIST_MODEL (tree_model));
	for (guint i = 0; i < n; i++) {
		GtkTreeListRow *tlr = gtk_tree_list_model_get_row (tree_model, i);
		if (tlr) {
			gtk_tree_list_row_set_expanded (tlr, TRUE);
			g_object_unref (tlr);
		}
		/* After expanding, new items may have been inserted, so
		 * update n to cover them. */
		n = g_list_model_get_n_items (G_LIST_MODEL (tree_model));
	}
}

/* Column view revocation column reference, used to toggle visibility. */
static GtkColumnViewColumn *ca_revocation_column = NULL;

gboolean ca_refresh_model_callback ()
{
	/* Build a fresh root GListStore. */
	GListStore *new_root = g_list_store_new (GNOMINT_TYPE_CERT_ROW);

	if (ca_effective_expiration)
		g_hash_table_destroy (ca_effective_expiration);
	ca_effective_expiration = g_hash_table_new (g_direct_hash, g_direct_equal);
	ca_expiring_soon_count = 0;

	/* Build temporary hash tables for parent lookup during population. */
	if (ca_route_to_row)
		g_hash_table_destroy (ca_route_to_row);
	ca_route_to_row = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	if (ca_id_to_row)
		g_hash_table_destroy (ca_id_to_row);
	ca_id_to_row = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	ca_file_foreach_crt (__ca_refresh_model_add_certificate, view_rcrt, new_root);

	if (view_csr)
		ca_file_foreach_csr (__ca_refresh_model_add_csr, new_root);

	/* Clean up the temporary hash tables. */
	g_hash_table_destroy (ca_route_to_row);
	ca_route_to_row = NULL;
	g_hash_table_destroy (ca_id_to_row);
	ca_id_to_row = NULL;

	/* Replace the root model. */
	if (ca_root_model)
		g_object_unref (ca_root_model);
	ca_root_model = new_root;

	/* Create a GtkTreeListModel wrapping the flat root store. */
	GtkTreeListModel *tree_model = gtk_tree_list_model_new (
	    G_LIST_MODEL (g_object_ref (ca_root_model)),
	    FALSE,  /* passthrough = FALSE so items are GtkTreeListRow */
	    TRUE,   /* autoexpand — we'll also expand manually */
	    __ca_tree_list_create_model,
	    NULL, NULL);

	/* Get or create the column view. */
	if (!ca_columnview) {
		GObject *obj = gtk_builder_get_object (main_window_gtkb, "ca_treeview");
		ca_columnview = GTK_COLUMN_VIEW (obj);
	}

	gboolean first_time = (ca_tree_list_model == NULL);

	/* Replace old tree list model. */
	if (ca_tree_list_model)
		g_object_unref (ca_tree_list_model);
	ca_tree_list_model = tree_model;

	/* Create a selection model. */
	GtkMultiSelection *sel = gtk_multi_selection_new (
	    G_LIST_MODEL (g_object_ref (ca_tree_list_model)));
	if (ca_selection_model)
		g_object_unref (ca_selection_model);
	ca_selection_model = sel;

	if (first_time) {
		/* ---- Set up columns (done once) ---- */

		/* Subject */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_subject_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_subject_bind),  NULL);
			GtkColumnViewColumn *col = gtk_column_view_column_new (
			    _("Subject"), f);
			gtk_column_view_column_set_expand (col, TRUE);
			gtk_column_view_column_set_resizable (col, TRUE);
			gtk_column_view_append_column (ca_columnview, col);
			g_object_unref (col);
		}

		/* Is CA */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_is_ca_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_is_ca_bind),  NULL);
			GtkColumnViewColumn *col = gtk_column_view_column_new ("", f);
			gtk_column_view_column_set_fixed_width (col, 32);
			gtk_column_view_append_column (ca_columnview, col);
			g_object_unref (col);
		}

		/* Private Key */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_pkey_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_pkey_bind),  NULL);
			GtkColumnViewColumn *col = gtk_column_view_column_new ("", f);
			gtk_column_view_column_set_fixed_width (col, 32);
			gtk_column_view_append_column (ca_columnview, col);
			g_object_unref (col);
		}

		/* Serial */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_serial_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_serial_bind),  NULL);
			GtkColumnViewColumn *col = gtk_column_view_column_new (
			    _("Serial"), f);
			gtk_column_view_column_set_resizable (col, TRUE);
			gtk_column_view_append_column (ca_columnview, col);
			g_object_unref (col);
		}

		/* Activation */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_date_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_date_bind),
			                  GINT_TO_POINTER (CA_DATE_ACTIVATION));
			GtkColumnViewColumn *col = gtk_column_view_column_new (
			    _("Activation"), f);
			gtk_column_view_column_set_resizable (col, TRUE);
			gtk_column_view_append_column (ca_columnview, col);
			g_object_unref (col);
		}

		/* Expiration */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_date_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_date_bind),
			                  GINT_TO_POINTER (CA_DATE_EXPIRATION));
			GtkColumnViewColumn *col = gtk_column_view_column_new (
			    _("Expiration"), f);
			gtk_column_view_column_set_resizable (col, TRUE);
			gtk_column_view_append_column (ca_columnview, col);
			g_object_unref (col);
		}

		/* Revocation */
		{
			GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
			g_signal_connect (f, "setup", G_CALLBACK (__ca_date_setup), NULL);
			g_signal_connect (f, "bind",  G_CALLBACK (__ca_date_bind),
			                  GINT_TO_POINTER (CA_DATE_REVOCATION));
			ca_revocation_column = gtk_column_view_column_new (
			    _("Revocation"), f);
			gtk_column_view_column_set_resizable (ca_revocation_column, TRUE);
			gtk_column_view_append_column (ca_columnview, ca_revocation_column);
			/* Don't unref — we keep the pointer to toggle visibility. */
		}

		/* Connect selection-changed. */
		g_signal_connect (ca_selection_model, "selection-changed",
		                  G_CALLBACK (ca_treeview_selection_change), NULL);

		/* Connect row activation. */
		g_signal_connect (ca_columnview, "activate",
		                  G_CALLBACK (ca_treeview_row_activated), NULL);
	}

	/* Toggle revocation column visibility. */
	if (ca_revocation_column)
		gtk_column_view_column_set_visible (ca_revocation_column, view_rcrt);

	/* Set the model on the column view. */
	gtk_column_view_set_model (ca_columnview,
	                           GTK_SELECTION_MODEL (ca_selection_model));

	/* Expand all rows. */
	__ca_expand_all (ca_tree_list_model);

	/* Update the expiry banner (#56). Shown only when at least one
	 * cert is in the amber window AND the user hasn't dismissed it
	 * for the currently-open file. */
	{
		GtkWidget *bar  = GTK_WIDGET (
		    gtk_builder_get_object (main_window_gtkb, "expiry_infobar"));
		GtkLabel  *lbl  = GTK_LABEL (
		    gtk_builder_get_object (main_window_gtkb, "expiry_infobar_label"));
		gint days = preferences_get_expire_warning_days ();

		if (bar && lbl && ca_expiring_soon_count > 0 &&
		    !ca_expiry_infobar_dismissed && days > 0) {
			gchar *msg;
			if (ca_view_only_expiring) {
				msg = g_strdup_printf (
				    ngettext (
				        "Showing only the <b>%d certificate</b> expiring "
				        "in the next %d days. Close this banner to show "
				        "everything again.",
				        "Showing only the <b>%d certificates</b> expiring "
				        "in the next %d days. Close this banner to show "
				        "everything again.",
				        ca_expiring_soon_count),
				    ca_expiring_soon_count, days);
			} else {
				msg = g_strdup_printf (
				    ngettext (
				        "<b>%d certificate</b> expires in the next %d days. "
				        "Right-click it to renew with a fresh key.",
				        "<b>%d certificates</b> expire in the next %d days. "
				        "Right-click each one to renew with a fresh key.",
				        ca_expiring_soon_count),
				    ca_expiring_soon_count, days);
			}
			gtk_label_set_markup (lbl, msg);
			g_free (msg);

			/* Add the "Show them" action button on first show. The
			 * GtkInfoBar widget itself owns the button once added; we
			 * don't want to add it again on every refresh, so we
			 * stash a flag on the widget. */
			if (!g_object_get_data (G_OBJECT (bar), "show-them-added")) {
				gtk_info_bar_add_button (GTK_INFO_BAR (bar),
				                         _("_Show them"),
				                         CA_BANNER_RESPONSE_SHOW_THEM);
				g_object_set_data (G_OBJECT (bar), "show-them-added",
				                   GINT_TO_POINTER (1));
			}
			/* Don't offer "Show them" if we're already in that mode. */
			gtk_widget_set_visible (bar, TRUE);
		} else if (bar) {
			gtk_widget_set_visible(bar, FALSE);
		}
	}

	return TRUE;
}

/* Ctrl+F focuses the search entry (#53). GTK 4 uses
 * GtkEventControllerKey instead of the old key-press-event signal. */
gboolean
ca_on_key_pressed (GtkEventControllerKey *controller,
                   guint keyval, guint keycode,
                   GdkModifierType state,
                   gpointer user_data G_GNUC_UNUSED)
{
	if ((state & GDK_CONTROL_MASK) &&
	    (keyval == GDK_KEY_f || keyval == GDK_KEY_F)) {
		GObject *entry = gtk_builder_get_object (main_window_gtkb,
		                                          "search_entry");
		if (entry && GTK_IS_WIDGET (entry)) {
			gtk_widget_grab_focus (GTK_WIDGET (entry));
			return TRUE;
		}
	}
	return FALSE;
}

/* Search-entry handler (#53). Triggers on every keystroke; just stash
 * the new search text and refresh the tree. The actual filter is
 * applied in __ca_refresh_model_add_certificate. */
G_MODULE_EXPORT void
ca_on_search_changed (GtkSearchEntry *entry, gpointer user_data G_GNUC_UNUSED)
{
	const gchar *text = gtk_editable_get_text(GTK_EDITABLE(entry));
	g_free (ca_search_text);
	ca_search_text = (text && *text) ? g_strdup (text) : NULL;
	ca_refresh_model_callback ();
}

/* GtkInfoBar response handler: dismiss / close => hide and remember
 * that we've dismissed for this open file. Re-opening the file resets
 * the dismissed flag. */
G_MODULE_EXPORT void
ca_expiry_infobar_response (GtkInfoBar *bar,
                            gint        response,
                            gpointer    user_data G_GNUC_UNUSED)
{
	if (response == CA_BANNER_RESPONSE_SHOW_THEM) {
		/* Enter "show only expiring" filter mode and refresh. The
		 * banner stays visible (text changes to reflect the mode);
		 * closing it both clears the filter and dismisses the banner. */
		ca_view_only_expiring = TRUE;
		ca_refresh_model_callback ();
		return;
	}
	if (response == GTK_RESPONSE_CLOSE || response == -7 /* close button */) {
		ca_expiry_infobar_dismissed = TRUE;
		if (ca_view_only_expiring) {
			/* Restore the full view too. */
			ca_view_only_expiring = FALSE;
			ca_refresh_model_callback ();
		}
		gtk_widget_set_visible(GTK_WIDGET(bar), FALSE);
	}
}

/* ------------------------------------------------------------------ */
/*  Selection helpers for GtkColumnView                                */
/* ------------------------------------------------------------------ */

static GnomintCertRow *
__ca_get_selected_row (void)
{
	if (!ca_selection_model)
		return NULL;

	GtkBitset *sel = gtk_selection_model_get_selection (
	    GTK_SELECTION_MODEL (ca_selection_model));
	if (gtk_bitset_get_size (sel) != 1)
		return NULL;

	guint pos = gtk_bitset_get_nth (sel, 0);
	GtkTreeListRow *tlr = GTK_TREE_LIST_ROW (
	    g_list_model_get_item (
	        G_LIST_MODEL (ca_selection_model), pos));
	if (!tlr)
		return NULL;

	GnomintCertRow *row = GNOMINT_CERT_ROW (
	    gtk_tree_list_row_get_item (tlr));
	g_object_unref (tlr);
	return row;   /* caller must g_object_unref */
}

static gint
__ca_selection_type_cv (GnomintCertRow **row_out)
{
	GnomintCertRow *row = __ca_get_selected_row ();
	if (!row) {
		if (row_out) *row_out = NULL;
		return -1;
	}
	gint item_type = gnomint_cert_row_get_item_type (row);
	if (row_out)
		*row_out = row;  /* transfer ownership to caller */
	else
		g_object_unref (row);

	switch (item_type) {
	case GNOMINT_ROW_TYPE_CERT:
	case GNOMINT_ROW_TYPE_CA:
		return CA_FILE_ELEMENT_TYPE_CERT;
	case GNOMINT_ROW_TYPE_CSR:
		return CA_FILE_ELEMENT_TYPE_CSR;
	default:
		return -1;
	}
}

/* ------------------------------------------------------------------ */
/*  Activation handlers for GtkColumnView                              */
/* ------------------------------------------------------------------ */

static void
__ca_certificate_activated_cv (GnomintCertRow *row)
{
	certificate_properties_display (
	    gnomint_cert_row_get_id (row),
	    gnomint_cert_row_get_pem (row),
	    gnomint_cert_row_get_pkey_in_db (row),
	    gnomint_cert_row_get_is_ca (row));
}

static void
__ca_csr_activated_cv (GnomintCertRow *row)
{
	csr_properties_display (
	    gnomint_cert_row_get_pem (row),
	    gnomint_cert_row_get_pkey_in_db (row));
}

/* GtkColumnView "activate" signal or menu "Properties" action.
 * The old signature took GtkTreeView args; the new one takes
 * GtkColumnView + position.  We also support being called with
 * NULL arguments (from the Properties menu item). */
G_MODULE_EXPORT gboolean
ca_treeview_row_activated (GtkColumnView *colview G_GNUC_UNUSED,
                           guint position,
                           gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);

	if (type == CA_FILE_ELEMENT_TYPE_CERT && row) {
		__ca_certificate_activated_cv (row);
	} else if (type == CA_FILE_ELEMENT_TYPE_CSR && row) {
		__ca_csr_activated_cv (row);
	}

	if (row) g_object_unref (row);
	return FALSE;
}


static void
__ca_set_action_enabled (const gchar *action_name, gboolean enabled)
{
	GtkWidget *win = GTK_WIDGET (gtk_builder_get_object (main_window_gtkb, "main_window1"));
	if (!win) return;
	GAction *a = g_action_map_lookup_action (G_ACTION_MAP (win), action_name);
	if (a) g_simple_action_set_enabled (G_SIMPLE_ACTION (a), enabled);
}

static void
__ca_set_toolbutton_sensitive (const gchar *id, gboolean sensitive)
{
	GObject *w = gtk_builder_get_object (main_window_gtkb, id);
	if (w) gtk_widget_set_sensitive (GTK_WIDGET (w), sensitive);
}

void __ca_activate_certificate_selection_cv (GnomintCertRow *row)
{
	gboolean pk_indb = gnomint_cert_row_get_pkey_in_db (row);
	gboolean is_revoked = gnomint_cert_row_get_revocation (row);
	gboolean is_ca = gnomint_cert_row_get_is_ca (row);

	__ca_set_action_enabled ("export", TRUE);
	__ca_set_action_enabled ("export-chain", TRUE);
	__ca_set_action_enabled ("extract-pkey", pk_indb);
	__ca_set_toolbutton_sensitive ("extractpkey_toolbutton", pk_indb);
	__ca_set_action_enabled ("revoke", !is_revoked);
	__ca_set_toolbutton_sensitive ("revoke_toolbutton", !is_revoked);
	/* Renewal is not offered for CA certificates: the new cert would
	 * have a different key, so all certificates previously signed by
	 * the old CA would no longer chain to it. */
	__ca_set_action_enabled ("renew", !is_revoked && !is_ca);
	__ca_set_action_enabled ("sign", FALSE);
	__ca_set_toolbutton_sensitive ("sign_toolbutton", FALSE);
	__ca_set_action_enabled ("delete", FALSE);
	__ca_set_toolbutton_sensitive ("delete_toolbutton", FALSE);
	__ca_set_action_enabled ("properties", TRUE);
}

void __ca_activate_csr_selection_cv (GnomintCertRow *row)
{
	gboolean pk_indb = gnomint_cert_row_get_pkey_in_db (row);

	__ca_set_action_enabled ("export", TRUE);
	__ca_set_action_enabled ("extract-pkey", pk_indb);
	__ca_set_toolbutton_sensitive ("extractpkey_toolbutton", pk_indb);
	__ca_set_action_enabled ("revoke", FALSE);
	__ca_set_toolbutton_sensitive ("revoke_toolbutton", FALSE);
	__ca_set_action_enabled ("renew", FALSE);
	__ca_set_action_enabled ("sign", TRUE);
	__ca_set_toolbutton_sensitive ("sign_toolbutton", TRUE);
	__ca_set_action_enabled ("delete", TRUE);
	__ca_set_toolbutton_sensitive ("delete_toolbutton", TRUE);
	__ca_set_action_enabled ("properties", TRUE);
}

void __ca_deactivate_actions ()
{
	__ca_set_action_enabled ("export", FALSE);
	__ca_set_action_enabled ("export-chain", FALSE);
	__ca_set_action_enabled ("extract-pkey", FALSE);
	__ca_set_toolbutton_sensitive ("extractpkey_toolbutton", FALSE);
	__ca_set_action_enabled ("revoke", FALSE);
	__ca_set_toolbutton_sensitive ("revoke_toolbutton", FALSE);
	__ca_set_action_enabled ("renew", FALSE);
	__ca_set_action_enabled ("sign", FALSE);
	__ca_set_toolbutton_sensitive ("sign_toolbutton", FALSE);
	__ca_set_action_enabled ("delete", FALSE);
	__ca_set_toolbutton_sensitive ("delete_toolbutton", FALSE);
	__ca_set_action_enabled ("properties", FALSE);
}

/* GtkMultiSelection "selection-changed" handler.  Signature differs
 * from the old GtkTreeView "cursor-changed"; we ignore the position/
 * n_items args and just re-query the selection. */
G_MODULE_EXPORT void
ca_treeview_selection_change (GtkSelectionModel *model G_GNUC_UNUSED,
                              guint position G_GNUC_UNUSED,
                              guint n_items G_GNUC_UNUSED,
                              gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);

	switch (type) {
	case CA_FILE_ELEMENT_TYPE_CERT:
		__ca_activate_certificate_selection_cv (row);
		g_object_unref (row);
		break;
	case CA_FILE_ELEMENT_TYPE_CSR:
		__ca_activate_csr_selection_cv (row);
		g_object_unref (row);
		break;
	case -1:
	default:
		if (row) g_object_unref (row);
		__ca_deactivate_actions ();
		break;
	}
}


void __ca_export_public_pem_cv (GnomintCertRow *row, gint type)
{
	GObject *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	const gchar * pem = NULL;
	const gchar * parent_route = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");

	if (type == CA_FILE_ELEMENT_TYPE_CERT)
		dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export certificate"),
								  GTK_WINDOW(widget),
								  GTK_FILE_CHOOSER_ACTION_SAVE,
								  _("_Cancel"), GTK_RESPONSE_CANCEL,
								  _("_Save"), GTK_RESPONSE_ACCEPT,
								  NULL));
	else
		dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export certificate signing request"),
								  GTK_WINDOW(widget),
								  GTK_FILE_CHOOSER_ACTION_SAVE,
								  _("_Cancel"), GTK_RESPONSE_CANCEL,
								  _("_Save"), GTK_RESPONSE_ACCEPT,
								  NULL));


	if (compat_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		filename = g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog)));
		file = g_io_channel_new_file (filename, "w", &error);
		if (error) {
			gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
			if (type == CA_FILE_ELEMENT_TYPE_CERT)
				dialog_error (_("There was an error while exporting certificate."));
			else
				dialog_error (_("There was an error while exporting CSR."));
			return;
		}

                pem = gnomint_cert_row_get_pem (row);
                if (type == CA_FILE_ELEMENT_TYPE_CERT)
			parent_route = gnomint_cert_row_get_parent_route (row);

                if (pem)
                        g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);

		if (parent_route && strcmp (parent_route, ":")) {
			gchar ** tokens = g_strsplit (parent_route, ":", -1);
			guint num_tokens = g_strv_length (tokens) - 2;
			gint i;

			for (i=num_tokens; i>=1; i--) {
				gchar * parent_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, atoll(tokens[i]));
				if (parent_pem) {
					g_io_channel_write_chars (file, parent_pem, strlen(parent_pem), NULL, &error);
					g_free (parent_pem);
				}
			}

			g_strfreev (tokens);
		}

                if (error) {
                        gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
                        if (type == CA_FILE_ELEMENT_TYPE_CERT)
                                dialog_error (_("There was an error while exporting certificate."));
                        else
                                dialog_error (_("There was an error while exporting CSR."));
                        return;
                }

                g_io_channel_shutdown (file, TRUE, &error);
                if (error) {
                        gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
                        if (type == CA_FILE_ELEMENT_TYPE_CERT)
                                dialog_error (_("There was an error while exporting certificate."));
                        else
                                dialog_error (_("There was an error while exporting CSR."));
                        return;
                }

                g_io_channel_unref (file);

                gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
                if (type == CA_FILE_ELEMENT_TYPE_CERT)
                        dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
                                                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                    GTK_MESSAGE_INFO,
                                                                    GTK_BUTTONS_CLOSE,
                                                                    "%s",
                                                                    _("Certificate exported successfully")));
                else
                        dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
                                                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                                                    GTK_MESSAGE_INFO,
                                                                    GTK_BUTTONS_CLOSE,
                                                                    "%s",
                                                                    _("Certificate signing request exported successfully")));
                g_signal_connect (dialog, "response",
                                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
                gtk_window_present (GTK_WINDOW (dialog));

        }
}


static void
__ca_export_pkcs8_done (const gchar *error_msg, gpointer user_data)
{
	gchar *filename = (gchar *) user_data;

	if (! error_msg) {
		GObject *widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
		GtkDialog *dlg = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
								    GTK_DIALOG_DESTROY_WITH_PARENT,
								    GTK_MESSAGE_INFO,
								    GTK_BUTTONS_CLOSE,
								    "%s",
								    _("Private key exported successfully")));
		g_signal_connect (dlg, "response",
		                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
		gtk_window_present (GTK_WINDOW (dlg));
	} else {
		dialog_error ((gchar *) error_msg);
	}

	g_free (filename);
}

void __ca_export_private_pkcs8_cv (GnomintCertRow *row, gint type)
{
	GObject *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	guint64 id;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");

	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export crypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));


	if (compat_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
		return;
	}

	filename = g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog)));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));

	id = gnomint_cert_row_get_id (row);

	export_private_pkcs8 (id, type, filename,
	                      __ca_export_pkcs8_done, filename);
}


static void
__ca_export_private_pem_done_cb (const gchar *error_msg, gpointer user_data)
{
	(void) user_data;
	if (error_msg) {
		dialog_error ((gchar *) error_msg);
	} else {
		GObject *widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
		GtkDialog *info = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
		                                                      GTK_DIALOG_DESTROY_WITH_PARENT,
		                                                      GTK_MESSAGE_INFO,
		                                                      GTK_BUTTONS_CLOSE,
		                                                      "%s",
		                                                      _("Private key exported successfully")));
		g_signal_connect (info, "response",
		                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
		gtk_window_present (GTK_WINDOW (info));
	}
}

void __ca_export_private_pem_cv (GnomintCertRow *row, gint type)
{
	GObject *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	guint64 id;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");

	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export unencrypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));


	if (compat_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
		return;
	}

	filename = g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog)));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));

	id = gnomint_cert_row_get_id (row);

	export_private_pem (id, type, filename,
	                    __ca_export_private_pem_done_cb, NULL);
	g_free (filename);
}


static void
__ca_export_pkcs12_done (const gchar *error_msg, gpointer user_data)
{
	g_free (user_data); /* filename */

	if (error_msg && strlen(error_msg)) {
		dialog_error ((gchar *) error_msg);
		return;
	}

	if (error_msg) {
		/* Export cancelled by user (empty string) */
		return;
	}

	GObject *widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	GtkDialog *dlg = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_INFO,
						    GTK_BUTTONS_CLOSE,
						    "%s",
						    _("Certificate exported successfully")));
	g_signal_connect (dlg, "response",
	                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
	gtk_window_present (GTK_WINDOW (dlg));
}

void __ca_export_pkcs12_cv (GnomintCertRow *row, gint type)
{
	GObject *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	guint64 id;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");

	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new
			       (_("Export whole certificate in PKCS#12 package"),
				GTK_WINDOW(widget),
				GTK_FILE_CHOOSER_ACTION_SAVE,
				_("_Cancel"), GTK_RESPONSE_CANCEL,
				_("_Save"), GTK_RESPONSE_ACCEPT,
				NULL));


	if (compat_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
		return;
	}

	filename = g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog)));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
	id = gnomint_cert_row_get_id (row);

	export_pkcs12 (id, type, filename,
	               __ca_export_pkcs12_done, filename);
}


/* ---- Async export-certificate dialog (Step 2.2) ---- */

/* Context passed through the export-certificate dialog response. */
typedef struct {
    GnomintCertRow *row;
    gint            type;
    GtkBuilder     *dialog_gtkb;
} ExportCertCtx;

static void
__ca_export_cert_response (GtkDialog *dialog,
                           gint       response_id,
                           gpointer   user_data)
{
    ExportCertCtx *ctx = (ExportCertCtx *) user_data;

    if (!response_id || response_id == GTK_RESPONSE_CANCEL) {
        gtk_window_destroy (GTK_WINDOW (dialog));
        g_object_unref (G_OBJECT (ctx->dialog_gtkb));
        g_object_unref (ctx->row);
        g_free (ctx);
        return;
    }

    if (gtk_check_button_get_active (GTK_CHECK_BUTTON (
            gtk_builder_get_object (ctx->dialog_gtkb, "publicpart_radiobutton1")))) {
        __ca_export_public_pem_cv (ctx->row, ctx->type);
    } else if (gtk_check_button_get_active (GTK_CHECK_BUTTON (
            gtk_builder_get_object (ctx->dialog_gtkb, "privatepart_radiobutton2")))) {
        __ca_export_private_pkcs8_cv (ctx->row, ctx->type);
    } else if (gtk_check_button_get_active (GTK_CHECK_BUTTON (
            gtk_builder_get_object (ctx->dialog_gtkb, "privatepart_uncrypted_radiobutton2")))) {
        __ca_export_private_pem_cv (ctx->row, ctx->type);
    } else if (gtk_check_button_get_active (GTK_CHECK_BUTTON (
            gtk_builder_get_object (ctx->dialog_gtkb, "bothparts_radiobutton3")))) {
        __ca_export_pkcs12_cv (ctx->row, ctx->type);
    } else {
        dialog_error (_("Unexpected error"));
    }

    gtk_window_destroy (GTK_WINDOW (dialog));
    g_object_unref (G_OBJECT (ctx->dialog_gtkb));
    g_object_unref (ctx->row);
    g_free (ctx);
}

G_MODULE_EXPORT void ca_on_export1_activate (gpointer sender, gpointer user_data)
{
	GObject * widget = NULL;
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);
	GtkBuilder * dialog_gtkb = NULL;
	gboolean has_pk_in_db = FALSE;
	ExportCertCtx *ctx = NULL;

	if (type == -1) {
		if (row) g_object_unref (row);
		return;
	}

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "export_certificate_dialog.ui", NULL ),
				   NULL);

	has_pk_in_db = gnomint_cert_row_get_pkey_in_db (row);
	widget = gtk_builder_get_object (dialog_gtkb, "privatepart_radiobutton2");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), has_pk_in_db);
	widget = gtk_builder_get_object (dialog_gtkb, "bothparts_radiobutton3");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), has_pk_in_db);

	if (type == CA_FILE_ELEMENT_TYPE_CSR) {
 	        widget = gtk_builder_get_object (dialog_gtkb, "export_certificate_dialog");
		gtk_window_set_title (GTK_WINDOW(widget), _("Export CSR - gnoMint"));

		widget = gtk_builder_get_object (dialog_gtkb, "label2");
		gtk_label_set_text
                        (GTK_LABEL(widget),
                         _("Please, choose which part of the saved Certificate Signing Request you want to export:"));

		widget = gtk_builder_get_object (dialog_gtkb, "label5");
		gtk_label_set_markup
                        (GTK_LABEL(widget),
                         _("<i>Export the Certificate Signing Request to a public file, in PEM format.</i>"));

		widget = gtk_builder_get_object (dialog_gtkb, "label15");
		gtk_label_set_markup
                        (GTK_LABEL(widget),
                         _("<i>Export the saved private key to a PKCS#8 password-protected file. This file should only be accessed by the subject of the Certificate Signing Request.</i>"));

	        widget = gtk_builder_get_object (dialog_gtkb, "bothparts_radiobutton3");
		g_object_set (G_OBJECT (widget), "visible", FALSE, NULL);
	        widget = gtk_builder_get_object (dialog_gtkb, "label19");
		g_object_set (G_OBJECT (widget), "visible", FALSE, NULL);

	}

	ctx = g_new0 (ExportCertCtx, 1);
	ctx->row = row;            /* transfer ownership */
	ctx->type = type;
	ctx->dialog_gtkb = dialog_gtkb; /* transfer ownership */

	widget = gtk_builder_get_object (dialog_gtkb, "export_certificate_dialog");

	g_signal_connect (widget, "response",
	                  G_CALLBACK (__ca_export_cert_response), ctx);
	gtk_window_present (GTK_WINDOW (widget));
}

/* Export the full certificate chain (leaf + intermediates + root) as a
 * single PEM bundle. Intended use: deploy the bundle as a web server's
 * SSLCertificateChainFile / ssl_certificate. See #52. */
G_MODULE_EXPORT void ca_on_export_chain_activate (gpointer sender G_GNUC_UNUSED,
                                                  gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);

	if (type != CA_FILE_ELEMENT_TYPE_CERT) {
		if (row) g_object_unref (row);
		dialog_error (_("Please select a certificate to export its chain."));
		return;
	}

	guint64 cert_id = gnomint_cert_row_get_id (row);
	g_object_unref (row);

	gchar *cn = NULL;
	{
		gchar *dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, cert_id);
		if (dn) {
			/* Best-effort CN extraction for the default filename. */
			const gchar *p = strstr (dn, "CN=");
			if (p) {
				p += 3;
				const gchar *end = strchr (p, ',');
				cn = end ? g_strndup (p, end - p) : g_strdup (p);
			}
			g_free (dn);
		}
	}

	GObject *parent = gtk_builder_get_object (main_window_gtkb, "main_window1");
	GtkWidget *dialog = gtk_file_chooser_dialog_new (
	    _("Export certificate chain"), GTK_WINDOW (parent),
	    GTK_FILE_CHOOSER_ACTION_SAVE,
	    _("_Cancel"), GTK_RESPONSE_CANCEL,
	    _("_Save"),   GTK_RESPONSE_ACCEPT, NULL);
	if (cn && cn[0]) {
		gchar *fname = g_strdup_printf ("%s.chain.pem", cn);
		gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (dialog), fname);
		g_free (fname);
	}

	gint resp = compat_dialog_run (GTK_DIALOG (dialog));
	if (resp != GTK_RESPONSE_ACCEPT) {
		gtk_window_destroy(GTK_WINDOW(dialog));
		g_free (cn);
		return;
	}

	gchar *filename = g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog)));
	gtk_window_destroy(GTK_WINDOW(dialog));

	gchar *chain_pem = ca_file_get_chain_pem_from_id (cert_id);
	if (! chain_pem) {
		dialog_error (_("Could not build certificate chain."));
		g_free (filename);
		g_free (cn);
		return;
	}

	GError *err = NULL;
	if (! g_file_set_contents (filename, chain_pem, -1, &err)) {
		dialog_error (g_strdup_printf (_("Failed to write chain: %s"),
		                               err ? err->message : "?"));
		g_clear_error (&err);
	} else {
		GtkWidget *info = gtk_message_dialog_new (
		    GTK_WINDOW (parent),
		    GTK_DIALOG_DESTROY_WITH_PARENT,
		    GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE,
		    "%s", _("Certificate chain exported successfully."));
		g_signal_connect (info, "response",
		                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
		gtk_window_present (GTK_WINDOW (info));
	}

	g_free (chain_pem);
	g_free (filename);
	g_free (cn);
}

/* ------------------------------------------------------------------ */
/*  Bulk operations (issue #54)                                       */
/* ------------------------------------------------------------------ */

/* The actual ca_bulk_revoke_ids / ca_bulk_delete_csr_ids implementations
 * live in ca_bulk.c so the CLI can link them too. */

/* Helper: walk the tree selection, partitioning selected rows into a
 * list of cert ids and a list of CSR ids. The returned GSLists are
 * caller-owned (free with g_slist_free; no per-element free needed
 * since each element is a GUINT-boxed pointer). */
void
__ca_collect_selected_ids (GSList **cert_ids_out, GSList **csr_ids_out)
{
	*cert_ids_out = NULL;
	*csr_ids_out = NULL;

	if (!ca_selection_model)
		return;

	GtkBitset *sel = gtk_selection_model_get_selection (
	    GTK_SELECTION_MODEL (ca_selection_model));
	guint64 n = gtk_bitset_get_size (sel);

	for (guint64 i = 0; i < n; i++) {
		guint pos = gtk_bitset_get_nth (sel, i);
		GtkTreeListRow *tlr = GTK_TREE_LIST_ROW (
		    g_list_model_get_item (
		        G_LIST_MODEL (ca_selection_model), pos));
		if (!tlr)
			continue;
		GnomintCertRow *row = GNOMINT_CERT_ROW (
		    gtk_tree_list_row_get_item (tlr));
		g_object_unref (tlr);
		if (!row)
			continue;

		guint64 id = gnomint_cert_row_get_id (row);
		gint item_type = gnomint_cert_row_get_item_type (row);
		g_object_unref (row);

		if (id == 0)
			continue;
		gpointer boxed = GUINT_TO_POINTER ((guint) id);
		if (item_type == GNOMINT_ROW_TYPE_CSR)
			*csr_ids_out = g_slist_prepend (*csr_ids_out, boxed);
		else
			*cert_ids_out = g_slist_prepend (*cert_ids_out, boxed);
	}
}

/* GUI handler: ask for confirmation, then bulk-revoke every selected
 * cert (and skip CSRs / non-certs in the selection). Visible from the
 * Certificates menu and the right-click popup. */
G_MODULE_EXPORT void
ca_on_bulk_revoke_activate (gpointer sender G_GNUC_UNUSED,
                            gpointer user_data G_GNUC_UNUSED)
{
	GSList *cert_ids = NULL, *csr_ids = NULL;
	__ca_collect_selected_ids (&cert_ids, &csr_ids);
	g_slist_free (csr_ids);

	gint n = (gint) g_slist_length (cert_ids);
	if (n == 0) {
		g_slist_free (cert_ids);
		dialog_error (_("Please select one or more certificates to revoke."));
		return;
	}

	GObject *parent = gtk_builder_get_object (main_window_gtkb, "main_window1");
	gchar *msg = g_strdup_printf (
	    ngettext ("Are you sure you want to revoke %d certificate?",
	              "Are you sure you want to revoke %d certificates?", n),
	    n);
	GtkWidget *dialog = gtk_message_dialog_new_with_markup (
	    GTK_WINDOW (parent), GTK_DIALOG_DESTROY_WITH_PARENT,
	    GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
	    "<b>%s</b>\n\n<span font_size='small'>%s</span>", msg,
	    _("Revoking a certificate will include it in the next CRL, marking "
	      "it as invalid. CSRs in the selection (if any) are not affected; "
	      "use \"Delete selected CSRs\" for those."));
	g_free (msg);
	g_object_set_data_full (G_OBJECT (dialog), "ids", cert_ids,
	                        __ca_gslist_free_notify);
	g_signal_connect (dialog, "response",
	                  G_CALLBACK (__ca_bulk_revoke_response), NULL);
	gtk_window_present (GTK_WINDOW (dialog));
}

/* GUI handler: bulk-delete CSRs from the current selection. */
G_MODULE_EXPORT void
ca_on_bulk_delete_csrs_activate (gpointer sender G_GNUC_UNUSED,
                                 gpointer user_data G_GNUC_UNUSED)
{
	GSList *cert_ids = NULL, *csr_ids = NULL;
	__ca_collect_selected_ids (&cert_ids, &csr_ids);
	g_slist_free (cert_ids);

	gint n = (gint) g_slist_length (csr_ids);
	if (n == 0) {
		g_slist_free (csr_ids);
		dialog_error (_("Please select one or more CSRs to delete."));
		return;
	}

	GObject *parent = gtk_builder_get_object (main_window_gtkb, "main_window1");
	gchar *msg = g_strdup_printf (
	    ngettext ("Are you sure you want to delete %d Certificate Signing Request?",
	              "Are you sure you want to delete %d Certificate Signing Requests?", n),
	    n);
	GtkWidget *dialog = gtk_message_dialog_new_with_markup (
	    GTK_WINDOW (parent), GTK_DIALOG_DESTROY_WITH_PARENT,
	    GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "<b>%s</b>", msg);
	g_free (msg);
	g_object_set_data_full (G_OBJECT (dialog), "ids", csr_ids,
	                        __ca_gslist_free_notify);
	g_signal_connect (dialog, "response",
	                  G_CALLBACK (__ca_bulk_delete_csrs_response), NULL);
	gtk_window_present (GTK_WINDOW (dialog));
}

typedef struct {
	gchar          *filename;
	guint64         id;
	gint            type;
	GnomintCertRow *row;
} _ExtractPkeyCtx;

static void
__ca_extract_pkey_done (const gchar *error_msg, gpointer user_data)
{
	_ExtractPkeyCtx *ctx = (_ExtractPkeyCtx *) user_data;

	if (! error_msg) {
		GObject *widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
		GtkDialog *dlg = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
								    GTK_DIALOG_DESTROY_WITH_PARENT,
								    GTK_MESSAGE_INFO,
								    GTK_BUTTONS_CLOSE,
								    "%s",
								    _("Private key exported successfully")));
		g_signal_connect (dlg, "response",
		                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
		gtk_window_present (GTK_WINDOW (dlg));

		if (ctx->type == CA_FILE_ELEMENT_TYPE_CERT)
			ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CERT, ctx->filename, ctx->id);
		else
			ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CSR, ctx->filename, ctx->id);

		dialog_refresh_list();
	} else {
		dialog_error ((gchar *) error_msg);
	}

	g_free (ctx->filename);
	g_object_unref (ctx->row);
	g_free (ctx);
}

G_MODULE_EXPORT void ca_on_extractprivatekey1_activate (gpointer sender, gpointer user_data)
{
	GnomintCertRow *row = NULL;
	gint type;
	gchar *filename = NULL;
	guint64 id;
	GObject *widget = NULL;
	GtkDialog *dialog = NULL;
	_ExtractPkeyCtx *ctx;

	type = __ca_selection_type_cv (&row);
	if (type == -1 || !row) {
		if (row) g_object_unref (row);
		return;
	}

	id = gnomint_cert_row_get_id (row);

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");

	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export crypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));

	if (compat_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));
		g_object_unref (row);
		return;
	}

	filename = g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog)));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(dialog)));

	ctx = g_new0 (_ExtractPkeyCtx, 1);
	ctx->filename = filename;
	ctx->id = id;
	ctx->type = type;
	ctx->row = row;

	export_private_pkcs8 (id, type, filename,
	                      __ca_extract_pkey_done, ctx);
}


G_MODULE_EXPORT void ca_on_renew_activate (gpointer sender, gpointer user_data)
{
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);
	guint64 cert_id = 0;
	GObject *parent_win = NULL;
	GtkDialog *confirm = NULL;

	if (type != CA_FILE_ELEMENT_TYPE_CERT) {
		if (row) g_object_unref (row);
		return;
	}

	if (gnomint_cert_row_get_is_ca (row)) {
		g_object_unref (row);
		dialog_error (_("CA certificates cannot be renewed. A renewed CA "
		                "would have a different key, so certificates "
		                "previously signed by the old CA would no longer "
		                "chain to it."));
		return;
	}

	cert_id = gnomint_cert_row_get_id (row);
	g_object_unref (row);

	parent_win = gtk_builder_get_object (main_window_gtkb, "main_window1");
	confirm = GTK_DIALOG (gtk_message_dialog_new_with_markup (
	    GTK_WINDOW (parent_win),
	    GTK_DIALOG_DESTROY_WITH_PARENT,
	    GTK_MESSAGE_QUESTION,
	    GTK_BUTTONS_YES_NO,
	    _("<b>Renew this certificate?</b>\n\n"
	      "gnoMint will issue a new certificate with the same subject "
	      "and SAN as the selected one, signed by the same CA, with a "
	      "freshly-generated keypair. The old certificate will remain in "
	      "the database — revoke it manually after you have deployed the "
	      "new one.")));
	guint64 *cert_id_heap = g_new (guint64, 1);
	*cert_id_heap = cert_id;
	g_signal_connect (confirm, "response",
	                  G_CALLBACK (__ca_renew_response), cert_id_heap);
	gtk_window_present (GTK_WINDOW (GTK_WIDGET (confirm)));
}


/* Build and show the diff dialog from two PEM strings. Both must be
 * non-NULL; ownership stays with the caller. */
void
__ca_show_diff_dialog (const gchar *pem_left, const gchar *pem_right,
                       const gchar *left_label, const gchar *right_label)
{
	CertDiff *diff = cert_diff_new (pem_left, pem_right);

	GObject *parent_obj = gtk_builder_get_object (main_window_gtkb, "main_window1");
	GtkWidget *parent = (parent_obj && GTK_IS_WINDOW (parent_obj))
	                    ? GTK_WIDGET (parent_obj) : NULL;
	gint n_diffs = cert_diff_count_differences (diff);
	gchar *title = g_strdup_printf (
	    ngettext ("Certificate diff — %d difference",
	              "Certificate diff — %d differences", n_diffs),
	    n_diffs);

	GtkWidget *dlg = gtk_dialog_new_with_buttons (
	    title, parent ? GTK_WINDOW (parent) : NULL,
	    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
	    _("_Close"), GTK_RESPONSE_CLOSE, NULL);
	g_free (title);
	gtk_window_set_default_size (GTK_WINDOW (dlg), 900, 600);

	GtkWidget *content = gtk_dialog_get_content_area (GTK_DIALOG (dlg));

	GtkWidget *scroll = gtk_scrolled_window_new ();
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_widget_set_hexpand (scroll, TRUE);
	gtk_box_append (GTK_BOX (content), scroll);

	GtkWidget *grid = gtk_grid_new ();
	gtk_grid_set_column_spacing (GTK_GRID (grid), 12);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 4);
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scroll), grid);

	/* Column headers. */
	GtkWidget *l_hdr_left  = gtk_label_new (NULL);
	gchar *m;
	m = g_markup_printf_escaped ("<b>%s</b>", left_label  ? left_label  : _("Left"));
	gtk_label_set_markup (GTK_LABEL (l_hdr_left), m); g_free (m);
	gtk_label_set_xalign (GTK_LABEL (l_hdr_left), 0);
	GtkWidget *l_hdr_right = gtk_label_new (NULL);
	m = g_markup_printf_escaped ("<b>%s</b>", right_label ? right_label : _("Right"));
	gtk_label_set_markup (GTK_LABEL (l_hdr_right), m); g_free (m);
	gtk_label_set_xalign (GTK_LABEL (l_hdr_right), 0);

	gtk_grid_attach (GTK_GRID (grid), gtk_label_new (""),  0, 0, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), l_hdr_left,          1, 0, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), l_hdr_right,         2, 0, 1, 1);

	gint row = 1;
	for (GList *l = diff->fields; l; l = l->next) {
		CertDiffField *f = (CertDiffField *) l->data;
		GtkWidget *name  = gtk_label_new (f->field_name);
		gtk_label_set_xalign (GTK_LABEL (name), 0);
		gtk_widget_set_valign (name, GTK_ALIGN_START);

		const gchar *lval = f->left  ? f->left  : "—";
		const gchar *rval = f->right ? f->right : "—";

		GtkWidget *left  = gtk_label_new (NULL);
		GtkWidget *right = gtk_label_new (NULL);

		if (f->differs) {
			gchar *lm = g_markup_printf_escaped (
			    "<span foreground=\"#cc7700\">%s</span>", lval);
			gchar *rm = g_markup_printf_escaped (
			    "<span foreground=\"#cc7700\">%s</span>", rval);
			gtk_label_set_markup (GTK_LABEL (left),  lm);
			gtk_label_set_markup (GTK_LABEL (right), rm);
			g_free (lm); g_free (rm);
		} else {
			gtk_label_set_text (GTK_LABEL (left),  lval);
			gtk_label_set_text (GTK_LABEL (right), rval);
		}
		gtk_label_set_xalign (GTK_LABEL (left),  0);
		gtk_label_set_xalign (GTK_LABEL (right), 0);
		gtk_label_set_selectable (GTK_LABEL (left),  TRUE);
		gtk_label_set_selectable (GTK_LABEL (right), TRUE);
		gtk_label_set_wrap (GTK_LABEL (left),  TRUE);
		gtk_label_set_wrap (GTK_LABEL (right), TRUE);
		gtk_widget_set_hexpand (left,  TRUE);
		gtk_widget_set_hexpand (right, TRUE);

		gtk_grid_attach (GTK_GRID (grid), name,  0, row, 1, 1);
		gtk_grid_attach (GTK_GRID (grid), left,  1, row, 1, 1);
		gtk_grid_attach (GTK_GRID (grid), right, 2, row, 1, 1);
		row++;
	}

	gtk_widget_set_visible(dlg, TRUE);
	g_signal_connect (dlg, "response",
	                  G_CALLBACK (__ca_dialog_response_destroy_and_free), diff);
	gtk_window_present (GTK_WINDOW (dlg));
}

/* Menu callback: prompt for a PEM file via GtkFileChooser, then diff
 * against the currently-selected cert. */
G_MODULE_EXPORT void
ca_on_compare_with_activate (gpointer sender G_GNUC_UNUSED,
                             gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);
	if (type != CA_FILE_ELEMENT_TYPE_CERT) {
		if (row) g_object_unref (row);
		return;
	}
	gchar *left_pem = g_strdup (gnomint_cert_row_get_pem (row));
	gchar *left_subject = g_strdup (gnomint_cert_row_get_subject (row));
	g_object_unref (row);
	if (!left_pem) {
		dialog_error (_("Cannot read PEM of the selected certificate."));
		g_free (left_subject);
		return;
	}

	GObject *parent = gtk_builder_get_object (main_window_gtkb, "main_window1");
	GtkWidget *chooser = gtk_file_chooser_dialog_new (
	    _("Compare with PEM file…"),
	    (parent && GTK_IS_WINDOW (parent)) ? GTK_WINDOW (parent) : NULL,
	    GTK_FILE_CHOOSER_ACTION_OPEN,
	    _("_Cancel"), GTK_RESPONSE_CANCEL,
	    _("_Open"),   GTK_RESPONSE_ACCEPT, NULL);
	gint resp = compat_dialog_run (GTK_DIALOG (chooser));
	gchar *path = (resp == GTK_RESPONSE_ACCEPT)
	              ? g_file_get_path(gtk_file_chooser_get_file(GTK_FILE_CHOOSER(chooser)))
	              : NULL;
	gtk_window_destroy(GTK_WINDOW(chooser));
	if (!path) {
		g_free (left_pem); g_free (left_subject);
		return;
	}

	gchar *right_pem = NULL;
	GError *err = NULL;
	if (!g_file_get_contents (path, &right_pem, NULL, &err)) {
		dialog_error (err ? err->message : _("Cannot read file."));
		g_clear_error (&err);
		g_free (path); g_free (left_pem); g_free (left_subject);
		return;
	}
	gchar *right_label = g_path_get_basename (path);
	__ca_show_diff_dialog (left_pem, right_pem,
	                       left_subject ? left_subject : _("Selected"),
	                       right_label);
	g_free (right_label);
	g_free (right_pem);
	g_free (left_pem);
	g_free (left_subject);
	g_free (path);
}

G_MODULE_EXPORT void ca_on_revoke_activate (gpointer sender, gpointer user_data)
{
	GObject * widget = NULL;
	GtkDialog * dialog = NULL;
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);
	guint64 id = 0;

	if (type == CA_FILE_ELEMENT_TYPE_CSR || type == -1) {
		if (row) g_object_unref (row);
		return;
	}

	id = gnomint_cert_row_get_id (row);
	g_object_unref (row);

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	if (! ca_file_check_if_is_ca_id (id)) {

		dialog = GTK_DIALOG(gtk_message_dialog_new_with_markup (GTK_WINDOW(widget),
							    GTK_DIALOG_DESTROY_WITH_PARENT,
							    GTK_MESSAGE_QUESTION,
							    GTK_BUTTONS_YES_NO,
							    "<b>%s</b>\n\n<span font_size='small'>%s</span>",
							    _("Are you sure you want to revoke this certificate?"),
							    _("Revoking a certificate will include it in the next CRL, marking it as invalid. This way, any future use of the certificate will be denied (as long as the CRL is checked).")));
	} else {

		dialog = GTK_DIALOG(gtk_message_dialog_new_with_markup (GTK_WINDOW(widget),
							    GTK_DIALOG_DESTROY_WITH_PARENT,
							    GTK_MESSAGE_QUESTION,
							    GTK_BUTTONS_YES_NO,
							    "<b>%s</b>\n\n<span font_size='small'>%s</span>",		
							    _("Are you sure you want to revoke this CA certificate?"),
							    _("Revoking a certificate will include it in the next CRL, marking it as invalid. This way, any future use of the certificate will be denied (as long as the CRL is checked). \n\nMoreover, revoking a CA certificate can invalidate all the certificates generated with it, so all them should be regenerated with a new CA certificate.")));
	}

	guint64 *id_heap = g_new (guint64, 1);
	*id_heap = id;
	g_signal_connect (dialog, "response",
	                  G_CALLBACK (__ca_revoke_response), id_heap);
	gtk_window_present (GTK_WINDOW (GTK_WIDGET (dialog)));
}


G_MODULE_EXPORT void ca_on_delete2_activate (gpointer sender, gpointer user_data)
{
	GObject * widget = NULL;
	GtkDialog * dialog = NULL;
	GnomintCertRow *row = NULL;
	gint type = __ca_selection_type_cv (&row);
	guint64 id = 0;

	if (type != CA_FILE_ELEMENT_TYPE_CSR) {
		if (row) g_object_unref (row);
		return;
	}

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_QUESTION,
						    GTK_BUTTONS_YES_NO,
						    "%s",
						    _("Are you sure you want to delete this Certificate Signing Request?")));

	id = gnomint_cert_row_get_id (row);
	g_object_unref (row);

	guint64 *id_heap = g_new (guint64, 1);
	*id_heap = id;
	g_signal_connect (dialog, "response",
	                  G_CALLBACK (__ca_delete_csr_response), id_heap);
	gtk_window_present (GTK_WINDOW (GTK_WIDGET (dialog)));
}

G_MODULE_EXPORT void ca_on_sign1_activate (gpointer sender, gpointer user_data)
{
	GnomintCertRow *row = NULL;

	gint type = __ca_selection_type_cv (&row);
	const gchar * csr_pem;
	guint64 csr_id;
	guint64 csr_parent_id_num;
	gchar * csr_parent_id_str;

	if (type != CA_FILE_ELEMENT_TYPE_CSR) {
		if (row) g_object_unref (row);
		return;
	}

	csr_id = gnomint_cert_row_get_id (row);
	csr_pem = gnomint_cert_row_get_pem (row);
	csr_parent_id_num = gnomint_cert_row_get_parent_id (row);
	csr_parent_id_str = g_strdup_printf ("%" G_GUINT64_FORMAT, csr_parent_id_num);

	new_cert_window_display (csr_id, csr_pem, csr_parent_id_str);

	g_free (csr_parent_id_str);
	g_object_unref (row);
}



gboolean ca_open (gchar *filename, gboolean create)
{
	if (! ca_file_open (filename, create))
		return FALSE;


	/* Re-arm the expiry banner for the freshly-opened file. */
	ca_expiry_infobar_dismissed = FALSE;
	ca_view_only_expiring = FALSE;

	/* Reset the search filter so the new DB starts with everything
	 * visible — both internally and in the entry widget. */
	g_clear_pointer (&ca_search_text, g_free);
	{
		GObject *e = gtk_builder_get_object (main_window_gtkb, "search_entry");
		if (e && GTK_IS_ENTRY (e))
			gtk_editable_set_text(GTK_EDITABLE(e), "");
	}

	dialog_refresh_list();


	return TRUE;
}

guint64 ca_get_selected_row_id ()
{
	GnomintCertRow *row = NULL;
	guint64 result = 0;

	if (__ca_selection_type_cv (&row) != -1 && row) {
		result = gnomint_cert_row_get_id (row);
		g_object_unref (row);
	}

	return result;
}

gchar * ca_get_selected_row_pem ()
{
	GnomintCertRow *row = NULL;
	gchar * result = NULL;

	if (__ca_selection_type_cv (&row) != -1 && row) {
		result = g_strdup (gnomint_cert_row_get_pem (row));
		g_object_unref (row);
	}

	return result;
}


void ca_update_csr_view (gboolean new_value, gboolean refresh)
{
        view_csr = new_value;
        if (refresh)
                dialog_refresh_list();
}

G_MODULE_EXPORT gboolean ca_csr_view_toggled (gpointer sender, gpointer user_data)
{
        view_csr = !view_csr;
        ca_update_csr_view (view_csr, TRUE);
        if (view_csr != preferences_get_crq_visible())
                preferences_set_crq_visible (view_csr);

        return TRUE;
}

void ca_update_revoked_view (gboolean new_value, gboolean refresh)
{
        view_rcrt = new_value;
        if (refresh)
                dialog_refresh_list();
}

G_MODULE_EXPORT gboolean ca_rcrt_view_toggled (gpointer sender, gpointer user_data)
{
        view_rcrt = !view_rcrt;
        ca_update_revoked_view (view_rcrt, TRUE);
        if (view_rcrt != preferences_get_revoked_visible())
                preferences_set_revoked_visible (view_rcrt);

        return TRUE;
}

void ca_update_expired_view (gboolean new_value, gboolean refresh)
{
        view_expired = new_value;
        if (refresh)
                dialog_refresh_list();
}

G_MODULE_EXPORT gboolean ca_expired_view_toggled (gpointer sender, gpointer user_data)
{
        view_expired = !view_expired;
        ca_update_expired_view (view_expired, TRUE);
        if (view_expired != preferences_get_expired_visible())
                preferences_set_expired_visible (view_expired);

        return TRUE;
}

G_MODULE_EXPORT void ca_generate_crl (gpointer sender, gpointer user_data)
{
        crl_window_display ();
}





void
ca_treeview_popup_handler (GtkGestureClick *gesture,
                           int n_press, double x, double y,
                           gpointer user_data)
{
	GtkWidget *colview_widget = GTK_WIDGET (user_data);
	GMenuModel *menu_model = NULL;
	GnomintCertRow *row = NULL;
	gint selection_type;

	/* The row under the click is already selected by the default
	 * GtkColumnView click handling, so just query the selection. */
	selection_type = __ca_selection_type_cv (&row);

	switch (selection_type) {
	case CA_FILE_ELEMENT_TYPE_CERT:
		if (!cert_popup_menu_gtkb) goto cleanup;
		menu_model = G_MENU_MODEL (gtk_builder_get_object (
		                 cert_popup_menu_gtkb, "certificate_popup_menu"));
		break;
	case CA_FILE_ELEMENT_TYPE_CSR:
		if (!csr_popup_menu_gtkb) goto cleanup;
		menu_model = G_MENU_MODEL (gtk_builder_get_object (
		                 csr_popup_menu_gtkb, "csr_popup_menu"));
		break;
	default:
		goto cleanup;
	}

	if (!menu_model) goto cleanup;

	{
		GtkWidget *popover = gtk_popover_menu_new_from_model (menu_model);
		GdkRectangle rect = { (int)x, (int)y, 1, 1 };
		gtk_popover_set_pointing_to (GTK_POPOVER (popover), &rect);
		gtk_widget_set_parent (popover, colview_widget);
		gtk_popover_popup (GTK_POPOVER (popover));
	}

cleanup:
	if (row) g_object_unref (row);
}

/* ---- Async change-password dialog (Step 2.5b) ---- */

/* Response callback for the change-password dialog.  Replaces the old
 * do { ... } while (repeat) loop that used compat_dialog_run. */
static void
__ca_change_pwd_response (GtkDialog *dialog,
                          gint       response_id,
                          gpointer   user_data)
{
    GtkBuilder *dialog_gtkb = (GtkBuilder *) user_data;
    GObject *widget = NULL;
    GtkDialog *info_dialog = NULL;

    if (!response_id || response_id == GTK_RESPONSE_CANCEL ||
        response_id == GTK_RESPONSE_DELETE_EVENT) {
        gtk_window_destroy (GTK_WINDOW (dialog));
        g_object_unref (G_OBJECT (dialog_gtkb));
        return;
    }

    /* Read entries. */
    widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
    const gchar *newpwd = gtk_editable_get_text (GTK_EDITABLE (widget));

    widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
    const gchar *currpwd = gtk_editable_get_text (GTK_EDITABLE (widget));

    /* Validate current password. */
    if (ca_file_is_password_protected () && !ca_file_check_password (currpwd)) {
        dialog_error (_("The current password you have entered  "
                        "doesn't match with the actual current database password."));
        widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
        gtk_widget_grab_focus (GTK_WIDGET (widget));
        /* Re-present the same dialog so the user can try again. */
        gtk_window_present (GTK_WINDOW (dialog));
        return;
    }

    /* Password validated — apply the change. */
    widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
    if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {

        if (ca_file_is_password_protected ()) {
            /* It's a password change. */
            if (!ca_file_password_change (currpwd, newpwd)) {
                dialog_error (_("Error while changing database password. "
                                "The operation was cancelled."));
            } else {
                info_dialog = GTK_DIALOG (gtk_message_dialog_new (
                    GTK_WINDOW (dialog),
                    GTK_DIALOG_DESTROY_WITH_PARENT,
                    GTK_MESSAGE_INFO,
                    GTK_BUTTONS_CLOSE,
                    "%s",
                    _("Password changed successfully")));
                g_signal_connect (info_dialog, "response",
                                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
                gtk_window_present (GTK_WINDOW (info_dialog));
            }
        } else {
            /* It's a new password. */
            if (!ca_file_password_protect (newpwd)) {
                dialog_error (_("Error while establishing database password. "
                                "The operation was cancelled."));
            } else {
                info_dialog = GTK_DIALOG (gtk_message_dialog_new (
                    GTK_WINDOW (dialog),
                    GTK_DIALOG_DESTROY_WITH_PARENT,
                    GTK_MESSAGE_INFO,
                    GTK_BUTTONS_CLOSE,
                    "%s",
                    _("Password established successfully")));
                g_signal_connect (info_dialog, "response",
                                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
                gtk_window_present (GTK_WINDOW (info_dialog));
            }
        }
    } else {
        if (ca_file_is_password_protected ()) {
            /* Remove password protection. */
            if (!ca_file_password_unprotect (currpwd)) {
                dialog_error (_("Error while removing database password. "
                                "The operation was cancelled."));
            } else {
                info_dialog = GTK_DIALOG (gtk_message_dialog_new (
                    GTK_WINDOW (dialog),
                    GTK_DIALOG_DESTROY_WITH_PARENT,
                    GTK_MESSAGE_INFO,
                    GTK_BUTTONS_CLOSE,
                    "%s",
                    _("Password removed successfully")));
                g_signal_connect (info_dialog, "response",
                                  G_CALLBACK (__ca_dialog_response_destroy), NULL);
                gtk_window_present (GTK_WINDOW (info_dialog));
            }
        } else {
            /* No password and not requesting one — nothing to do. */
        }
    }

    gtk_window_destroy (GTK_WINDOW (dialog));
    g_object_unref (G_OBJECT (dialog_gtkb));
}

G_MODULE_EXPORT void ca_on_change_pwd_menuitem_activate (gpointer sender, gpointer user_data)
{
	GObject * widget = NULL;
	GtkBuilder * dialog_gtkb = NULL;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "change_password_dialog.ui", NULL),
				   NULL);

	if (ca_file_is_password_protected()) {
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
		gtk_check_button_set_active (GTK_CHECK_BUTTON(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label1");
		g_object_set (G_OBJECT(widget), "visible", TRUE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
		g_object_set (G_OBJECT(widget), "visible", TRUE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_commit_button");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	} else {
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_no_radiobutton");
		gtk_check_button_set_active (GTK_CHECK_BUTTON(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label1");
		g_object_set (G_OBJECT(widget), "visible", FALSE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
		g_object_set (G_OBJECT(widget), "visible", FALSE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	}

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	/* Present the dialog asynchronously with a response callback. */
	widget = gtk_builder_get_object (dialog_gtkb, "change_password_dialog");
	gtk_window_set_title (GTK_WINDOW(widget), _("Change CA password - gnoMint"));

	g_signal_connect (widget, "response",
	                  G_CALLBACK (__ca_change_pwd_response), dialog_gtkb);
	gtk_window_present (GTK_WINDOW (widget));
}


G_MODULE_EXPORT gboolean ca_changepwd_newpwd_entry_changed (GtkWidget *entry, gpointer user_data)
{
	GtkBuilder * dialog_gtkb = g_object_get_data (G_OBJECT(entry), "dialog_gtkb");
	GObject *widget;

	const gchar *pwd1;
	const gchar *pwd2;
	const gchar *currpwd;
	gboolean pwd_protect;

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	pwd_protect = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
	pwd1 = gtk_editable_get_text(GTK_EDITABLE(widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
	pwd2 = gtk_editable_get_text(GTK_EDITABLE(widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
	currpwd = gtk_editable_get_text(GTK_EDITABLE(widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_commit_button");
	if (pwd_protect) {
		if (strlen(pwd1) && strlen(pwd2) && ! strcmp(pwd1, pwd2)) {
			if (!ca_file_is_password_protected() || (ca_file_is_password_protected() && strlen(currpwd)))
				gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
			else
				gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);			
		} else {
			gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);		
		}
	} else {
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
	}

	return FALSE;
}

G_MODULE_EXPORT gboolean ca_changepwd_pwd_protect_radiobutton_toggled (GtkWidget *button, gpointer user_data)
{
	GtkBuilder * dialog_gtkb;
	GObject * widget = NULL;


	if (! G_IS_OBJECT(button))
		return TRUE;

	dialog_gtkb = g_object_get_data (G_OBJECT(button), "dialog_gtkb");
	if (! dialog_gtkb)
		return TRUE;

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		/* We want to password-protect the database */
		
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		ca_changepwd_newpwd_entry_changed (button, NULL);
	
	} else {

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	}

	return FALSE;
}


/* ---- Async DH-parameters dialog (Step 2.3) ---- */

static void
__ca_dh_param_response (GtkDialog *dialog,
                        gint       response_id,
                        gpointer   user_data)
{
    GtkBuilder *dialog_gtkb = (GtkBuilder *) user_data;

    if (!response_id) {
        gtk_window_destroy (GTK_WINDOW (dialog));
        g_object_unref (G_OBJECT (dialog_gtkb));
        return;
    }

    GObject *spin = gtk_builder_get_object (dialog_gtkb, "dh_prime_size_spinbutton");
    guint dh_size = gtk_spin_button_get_value (GTK_SPIN_BUTTON (spin));

    /* Inner file-save dialog stays compat_dialog_run for now (Phase 3). */
    GtkDialog *dialog2 = GTK_DIALOG (gtk_file_chooser_dialog_new (
        _("Save Diffie-Hellman parameters"),
        GTK_WINDOW (dialog),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        _("_Cancel"), GTK_RESPONSE_CANCEL,
        _("_Save"), GTK_RESPONSE_ACCEPT,
        NULL));

    if (compat_dialog_run (GTK_DIALOG (dialog2)) == GTK_RESPONSE_ACCEPT) {
        gchar *filename = g_file_get_path (
            gtk_file_chooser_get_file (GTK_FILE_CHOOSER (dialog2)));

        gchar *strerror = export_dh_param (dh_size, filename);

        gtk_window_destroy (GTK_WINDOW (dialog2));
        gtk_window_destroy (GTK_WINDOW (dialog));

        if (strerror) {
            dialog_error (strerror);
        } else {
            GObject *parent = gtk_builder_get_object (main_window_gtkb, "main_window1");
            GtkDialog *info = GTK_DIALOG (gtk_message_dialog_new (
                GTK_WINDOW (parent),
                GTK_DIALOG_DESTROY_WITH_PARENT,
                GTK_MESSAGE_INFO,
                GTK_BUTTONS_CLOSE,
                "%s",
                _("Diffie-Hellman parameters saved successfully")));
            g_signal_connect (info, "response",
                              G_CALLBACK (__ca_dialog_response_destroy), NULL);
            gtk_window_present (GTK_WINDOW (info));
        }

        g_free (filename);
    } else {
        gtk_window_destroy (GTK_WINDOW (dialog2));
        gtk_window_destroy (GTK_WINDOW (dialog));
    }

    g_object_unref (G_OBJECT (dialog_gtkb));
}

G_MODULE_EXPORT void ca_generate_dh_param_show (GtkWidget *menuitem, gpointer user_data)
{
	GtkDialog * dialog = NULL;
	GtkBuilder * dialog_gtkb = NULL;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "dh_parameters_dialog.ui", NULL),
				   NULL);


	dialog = GTK_DIALOG(gtk_builder_get_object (dialog_gtkb, "dh_parameters_dialog"));

	g_signal_connect (dialog, "response",
	                  G_CALLBACK (__ca_dh_param_response), dialog_gtkb);
	gtk_window_present (GTK_WINDOW (dialog));
}


/*
 *
 *   FILE MENU CALLBACKS
 *
 */ 


G_MODULE_EXPORT void on_add_self_signed_ca_activate  (gpointer sender, gpointer     user_data)
{
	new_ca_window_display();
	
}

G_MODULE_EXPORT void on_add_csr_activate  (gpointer sender, gpointer     user_data)
{
	new_req_window_display();
	
}

G_MODULE_EXPORT void on_wizard_web_activate  (gpointer sender, gpointer user_data)
{
	wizard_window_display(WIZARD_CERT_TYPE_WEB_SERVER);
}

G_MODULE_EXPORT void on_wizard_email_activate  (gpointer sender, gpointer user_data)
{
	wizard_window_display(WIZARD_CERT_TYPE_EMAIL_SERVER);
}


/* ---- Async import file-or-directory dialog (Step 2.4) ---- */

static void
__ca_import_file_or_dir_response (GtkDialog *dialog,
                                  gint       response_id,
                                  gpointer   user_data)
{
    GtkBuilder *dialog_gtkb = (GtkBuilder *) user_data;

    if (response_id < 0) {
        gtk_window_destroy (GTK_WINDOW (dialog));
        g_object_unref (G_OBJECT (dialog_gtkb));
        return;
    }

    GtkCheckButton *radiobutton = GTK_CHECK_BUTTON (
        gtk_builder_get_object (dialog_gtkb, "importfile_radiobutton"));
    gboolean import_file = gtk_check_button_get_active (radiobutton);

    gtk_window_destroy (GTK_WINDOW (dialog));

    GObject *main_window_widget = gtk_builder_get_object (main_window_gtkb, "main_window");

    if (import_file) {
        /* Import single file — inner file chooser stays compat_dialog_run (Phase 3). */
        gchar *filename;
        GtkWidget *fc = gtk_file_chooser_dialog_new (
            _("Select PEM file to import"),
            GTK_WINDOW (main_window_widget),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            _("_Cancel"), GTK_RESPONSE_CANCEL,
            _("_Open"), GTK_RESPONSE_ACCEPT,
            NULL);

        if (compat_dialog_run (GTK_DIALOG (fc)) == GTK_RESPONSE_ACCEPT) {
            filename = g_file_get_path (
                gtk_file_chooser_get_file (GTK_FILE_CHOOSER (fc)));
            gtk_window_destroy (GTK_WINDOW (fc));
        } else {
            gtk_window_destroy (GTK_WINDOW (fc));
            g_object_unref (G_OBJECT (dialog_gtkb));
            return;
        }

        if (!import_single_file (filename, NULL, NULL)) {
            GtkWidget *err = gtk_message_dialog_new (
                GTK_WINDOW (main_window_widget),
                GTK_DIALOG_DESTROY_WITH_PARENT,
                GTK_MESSAGE_ERROR,
                GTK_BUTTONS_CLOSE,
                _("Problem when importing '%s' file"),
                filename);
            g_signal_connect (err, "response",
                              G_CALLBACK (__ca_dialog_response_destroy), NULL);
            gtk_window_present (GTK_WINDOW (err));
        }
        g_free (filename);
    } else {
        /* Import directory — inner file chooser stays compat_dialog_run (Phase 3). */
        gchar *filename;
        GtkWidget *fc = gtk_file_chooser_dialog_new (
            _("Select directory to import"),
            GTK_WINDOW (main_window_widget),
            GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
            _("_Cancel"), GTK_RESPONSE_CANCEL,
            _("_Open"), GTK_RESPONSE_ACCEPT,
            NULL);

        if (compat_dialog_run (GTK_DIALOG (fc)) == GTK_RESPONSE_ACCEPT) {
            filename = g_file_get_path (
                gtk_file_chooser_get_file (GTK_FILE_CHOOSER (fc)));
            gtk_window_destroy (GTK_WINDOW (fc));
        } else {
            gtk_window_destroy (GTK_WINDOW (fc));
            g_object_unref (G_OBJECT (dialog_gtkb));
            return;
        }

        gchar *result = import_whole_dir (filename);

        if (result) {
            GtkWidget *err = gtk_message_dialog_new (
                GTK_WINDOW (main_window_widget),
                GTK_DIALOG_DESTROY_WITH_PARENT,
                GTK_MESSAGE_ERROR,
                GTK_BUTTONS_CLOSE,
                "%s", result);
            g_signal_connect (err, "response",
                              G_CALLBACK (__ca_dialog_response_destroy), NULL);
            gtk_window_present (GTK_WINDOW (err));
        }
        g_free (filename);
    }

    g_object_unref (G_OBJECT (dialog_gtkb));
}

G_MODULE_EXPORT void on_import1_activate  (gpointer sender, gpointer     user_data)
{
	GObject *widget;
	GtkBuilder * dialog_gtkb = NULL;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "import_file_or_directory_dialog.ui", NULL),
				   NULL);

        widget = gtk_builder_get_object (dialog_gtkb, "import_file_or_directory_dialog");

        g_signal_connect (widget, "response",
                          G_CALLBACK (__ca_import_file_or_dir_response), dialog_gtkb);
        gtk_window_present (GTK_WINDOW (widget));
}


/*
 *
 *   EDIT MENU CALLBACKS
 *
 */ 



G_MODULE_EXPORT void on_preferences1_activate  (gpointer sender, gpointer     user_data)
{
        preferences_window_display ();
}

G_MODULE_EXPORT void on_properties1_activate  (gpointer sender, gpointer     user_data)
{
	ca_treeview_row_activated (NULL, 0, NULL);
}




#endif


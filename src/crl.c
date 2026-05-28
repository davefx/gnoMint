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

#include <glib/gi18n.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef GNOMINTCLI
#include <glib-object.h>

#include <gtk/gtk.h>
#endif

#include "crl.h"
#include "ca_file.h"
#include "pkey_manage.h"
#include "dialog.h"
#include "tls.h"
#ifndef GNOMINTCLI
#include "ca_selector.h"
#endif

void __crl_gfree_gfunc (gpointer data, gpointer user_data);

#ifndef GNOMINTCLI
GtkBuilder *crl_window_gtkb = NULL;
static GtkSingleSelection *crl_ca_selection = NULL;
static GListStore *crl_ca_root_store = NULL;

static void
__crl_selection_changed (GObject *sel, GParamSpec *pspec G_GNUC_UNUSED,
                         gpointer user_data G_GNUC_UNUSED)
{
	guint pos = gtk_single_selection_get_selected (GTK_SINGLE_SELECTION (sel));
	gboolean has_sel = (pos != GTK_INVALID_LIST_POSITION);
	gtk_widget_set_sensitive (
	    GTK_WIDGET (gtk_builder_get_object (crl_window_gtkb, "crl_ok_button")),
	    has_sel);
}



void crl_window_display (void)
{
        GtkWidget * widget = NULL;

	crl_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (crl_window_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "new_crl_dialog.ui", NULL),
				   NULL);

        widget = GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
        gtk_window_set_transient_for (GTK_WINDOW (widget), dialog_get_main_window ());
        gtk_widget_set_visible(widget, TRUE);

	/* Populate and set up CA selector (GtkColumnView). */
	crl_ca_root_store = ca_selector_populate ();
	crl_ca_selection = ca_selector_setup (
	    GTK_COLUMN_VIEW (gtk_builder_get_object (crl_window_gtkb, "crl_ca_treeview")),
	    crl_ca_root_store, NULL);

	g_signal_connect (crl_ca_selection, "notify::selected",
	                  G_CALLBACK (__crl_selection_changed), NULL);
}


G_MODULE_EXPORT void crl_cancel_clicked_cb (GtkButton *button, gpointer userdata)
{
	GtkWidget * window = GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
        gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));	

}

static void
__crl_generate_done_cb (gchar *error, gpointer user_data)
{
	(void) user_data;
	if (error) {
		dialog_error (error);
		g_free (error);
	} else {
		dialog_info (_("CRL generated successfully"));
	}
}

typedef struct {
    guint64 ca_id;
} _CrlOkCtx;

static void
__crl_ok_save_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	_CrlOkCtx *ctx = (_CrlOkCtx *) user_data;
	GtkFileDialog *fd = GTK_FILE_DIALOG (source);
	GError *err = NULL;
	GFile *gfile = gtk_file_dialog_save_finish (fd, result, &err);

	if (!gfile) {
		g_clear_error (&err);
		g_free (ctx);
		return;
	}

	gchar *filename = g_file_get_path (gfile);
	g_object_unref (gfile);

	crl_generate (ctx->ca_id, filename, __crl_generate_done_cb, NULL);

	GtkDialog *crl_dlg = GTK_DIALOG(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(crl_dlg)));

	g_free (ctx);
}

G_MODULE_EXPORT void crl_ok_clicked_cb (GtkButton *button, gpointer userdata)
{
	guint64 ca_id = ca_selector_get_selected_id (crl_ca_selection);
	if (ca_id == 0)
		return;

	GtkWindow *parent = GTK_WINDOW(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));

	_CrlOkCtx *ctx = g_new0 (_CrlOkCtx, 1);
	ctx->ca_id = ca_id;

	GtkFileDialog *fd = gtk_file_dialog_new ();
	gtk_file_dialog_set_title (fd, _("Export Certificate Revocation List"));
	gtk_file_dialog_save (fd, parent, NULL, __crl_ok_save_cb, ctx);
	g_object_unref (fd);
}

#endif /*GNOMINTCLI*/

/* Shared helper: given a decrypted private key, generate the CRL and write it. */
static gchar *
__crl_generate_with_pkey (guint64 ca_id, GIOChannel *file,
                          gchar *ca_pem, gchar *dn,
                          PkeyManageData *crypted_pkey,
                          gchar *private_key,
                          GList *revoked_certs,
                          gint crl_version, time_t timestamp)
{
	gchar *pem = NULL;
	GError *error = NULL;

	pem = tls_generate_crl (revoked_certs,
	                        (guchar *) ca_pem,
	                        (guchar *) private_key,
	                        crl_version,
	                        timestamp,
	                        timestamp + (3600 * ca_file_policy_get_int (ca_id, "HOURS_BETWEEN_CRL_UPDATES")));

	g_free (ca_pem);
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	if (!pem) {
		g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
		g_list_free (revoked_certs);
		ca_file_rollback_new_crl_transaction ();
		return g_strdup (_("There was an error while generating CRL."));
	}
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);

	if (error) {
		g_free (pem);
		g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
		g_list_free (revoked_certs);
		ca_file_rollback_new_crl_transaction ();
		return g_strdup (_("There was an error while writing CRL."));
	}
	g_free (pem);

	ca_file_commit_new_crl_transaction (ca_id, revoked_certs);

	g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
	g_list_free (revoked_certs);

	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_io_channel_unref (file);
		return g_strdup (_("There was an error while exporting CRL."));
	}

	g_io_channel_unref (file);

	return NULL;
}

#ifdef GNOMINTCLI

gchar * crl_generate (guint64 ca_id, gchar *filename)
{
	time_t timestamp;
	gint crl_version = 0;
	gchar * dn = NULL;
	gchar * ca_pem = NULL;
	gchar * private_key = NULL;
	PkeyManageData * crypted_pkey = NULL;
	GList * revoked_certs = NULL;
	GIOChannel * file = NULL;
	GError * error = NULL;
	gchar *strerror = NULL;

	file = g_io_channel_new_file (filename, "w", &error);
	g_free (filename);
	if (error) {
		return (_("There was an error while exporting CRL."));
	}

	ca_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	crypted_pkey = pkey_manage_get_certificate_pkey (ca_id);
	dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	timestamp = time (NULL);

	revoked_certs = ca_file_get_revoked_certs (ca_id, &strerror);

	if (strerror) {
		return (_("There was an error while getting revoked certificates."));
	}

	crl_version = ca_file_begin_new_crl_transaction (1, timestamp);

	if (ca_id && ca_pem && crypted_pkey && dn) {

		private_key = pkey_manage_uncrypt (crypted_pkey, dn);
		if (!private_key) {
			g_free (ca_pem);
			pkey_manage_data_free (crypted_pkey);
			g_free (dn);
			g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
			g_list_free (revoked_certs);
			ca_file_rollback_new_crl_transaction ();
			return (_("There was an error while generating CRL."));
		}

		{
			gchar *result = __crl_generate_with_pkey (
				ca_id, file, ca_pem, dn, crypted_pkey,
				private_key, revoked_certs, crl_version, timestamp);
			g_free (private_key);
			return result;
		}

	} else {
		g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
		g_list_free (revoked_certs);
		ca_file_rollback_new_crl_transaction ();
		return (_("There was an error while exporting CRL."));
	}
}

#else /* GUI async crl_generate */

typedef struct {
	guint64              ca_id;
	GIOChannel          *file;
	gchar               *ca_pem;
	gchar               *dn;
	PkeyManageData      *crypted_pkey;
	GList               *revoked_certs;
	gint                 crl_version;
	time_t               timestamp;
	CrlGenerateCallback  cb;
	gpointer             cb_user_data;
} _CrlGenerateCtx;

static void
_crl_generate_uncrypt_cb (gchar *private_key, gpointer data)
{
	_CrlGenerateCtx *ctx = (_CrlGenerateCtx *) data;

	if (!private_key) {
		g_free (ctx->ca_pem);
		pkey_manage_data_free (ctx->crypted_pkey);
		g_free (ctx->dn);
		g_list_foreach (ctx->revoked_certs, __crl_gfree_gfunc, NULL);
		g_list_free (ctx->revoked_certs);
		ca_file_rollback_new_crl_transaction ();
		ctx->cb (g_strdup (_("There was an error while generating CRL.")),
		         ctx->cb_user_data);
		g_free (ctx);
		return;
	}

	{
		gchar *result = __crl_generate_with_pkey (
			ctx->ca_id, ctx->file, ctx->ca_pem, ctx->dn,
			ctx->crypted_pkey, private_key,
			ctx->revoked_certs, ctx->crl_version, ctx->timestamp);
		g_free (private_key);
		ctx->cb (result, ctx->cb_user_data);
		g_free (ctx);
	}
}

static void
_crl_generate_got_pkey_cb (PkeyManageData *crypted_pkey, gpointer data)
{
	_CrlGenerateCtx *ctx = (_CrlGenerateCtx *) data;

	ctx->crypted_pkey = crypted_pkey;

	if (!ctx->ca_pem || !crypted_pkey || !ctx->dn) {
		g_free (ctx->ca_pem);
		pkey_manage_data_free (crypted_pkey);
		g_free (ctx->dn);
		g_list_foreach (ctx->revoked_certs, __crl_gfree_gfunc, NULL);
		g_list_free (ctx->revoked_certs);
		ca_file_rollback_new_crl_transaction ();
		ctx->cb (g_strdup (_("There was an error while exporting CRL.")),
		         ctx->cb_user_data);
		g_free (ctx);
		return;
	}

	pkey_manage_uncrypt (crypted_pkey, ctx->dn,
	                     _crl_generate_uncrypt_cb, ctx);
}

void crl_generate (guint64 ca_id, gchar *filename,
                   CrlGenerateCallback cb, gpointer user_data)
{
	GIOChannel * file = NULL;
	GError * error = NULL;
	gchar *strerror = NULL;
	_CrlGenerateCtx *ctx;

	file = g_io_channel_new_file (filename, "w", &error);
	g_free (filename);
	if (error) {
		cb (g_strdup (_("There was an error while exporting CRL.")), user_data);
		return;
	}

	ctx = g_new0 (_CrlGenerateCtx, 1);
	ctx->ca_id = ca_id;
	ctx->file = file;
	ctx->ca_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	ctx->dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	ctx->timestamp = time (NULL);
	ctx->revoked_certs = ca_file_get_revoked_certs (ca_id, &strerror);
	ctx->cb = cb;
	ctx->cb_user_data = user_data;

	if (strerror) {
		g_free (ctx->ca_pem);
		g_free (ctx->dn);
		g_free (ctx);
		cb (g_strdup (_("There was an error while getting revoked certificates.")), user_data);
		return;
	}

	ctx->crl_version = ca_file_begin_new_crl_transaction (1, ctx->timestamp);

	pkey_manage_get_certificate_pkey (ca_id, _crl_generate_got_pkey_cb, ctx);
}

#endif /* GNOMINTCLI */

void __crl_gfree_gfunc (gpointer data, gpointer user_data)
{
        g_free (data);
}

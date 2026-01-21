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

void __crl_gfree_gfunc (gpointer data, gpointer user_data);

#ifndef GNOMINTCLI
GtkBuilder *crl_window_gtkb = NULL;
GtkTreeStore * crl_ca_list_model = NULL;


enum {CRL_CA_MODEL_COLUMN_ID=0,
      CRL_CA_MODEL_COLUMN_SERIAL=1,
      CRL_CA_MODEL_COLUMN_SUBJECT=2,
      CRL_CA_MODEL_COLUMN_DN=3,
      CRL_CA_MODEL_COLUMN_PARENT_DN=4,
      CRL_CA_MODEL_COLUMN_PEM=5,
      CRL_CA_MODEL_COLUMN_EXPIRATION=6,
      CRL_CA_MODEL_COLUMN_NUMBER=7}
        CrlCaListModelColumns;

typedef struct {
        GtkTreeStore * new_model;
        GtkTreeIter * last_parent_iter;
        GtkTreeIter * last_ca_iter;
} __CrlRefreshModelAddCaUserData;

int __crl_refresh_model_add_ca (void *pArg, int argc, char **argv, char **columnNames);
void __crl_populate_ca_treeview (GtkTreeView *treeview);



int __crl_refresh_model_add_ca (void *pArg, int argc, char **argv, char **columnNames)
{
	GValue *last_dn_value = g_new0 (GValue, 1);
	GValue *last_parent_dn_value = g_new0 (GValue, 1);
	GtkTreeIter iter;
        __CrlRefreshModelAddCaUserData *pdata = (__CrlRefreshModelAddCaUserData *) pArg;
	GtkTreeStore * new_model = pdata->new_model;

        const gchar * string_value;
	gchar *subject_with_expiration = NULL;

	// Format subject with expiration year
	subject_with_expiration = ca_file_format_subject_with_expiration(
		argv[CRL_CA_MODEL_COLUMN_SUBJECT], 
		argv[CRL_CA_MODEL_COLUMN_EXPIRATION]);

	// First we check if this is the first CA, or is a self-signed certificate
	if (! pdata->last_ca_iter || (! strcmp (argv[CRL_CA_MODEL_COLUMN_DN],argv[CRL_CA_MODEL_COLUMN_PARENT_DN])) ) {

		if (pdata->last_parent_iter)
			gtk_tree_iter_free (pdata->last_parent_iter);

		pdata->last_parent_iter = NULL;
		
	} else {
		// If not, then we must find the parent of the current nod
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), pdata->last_ca_iter, CRL_CA_MODEL_COLUMN_DN, last_dn_value);
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), pdata->last_ca_iter, CRL_CA_MODEL_COLUMN_PARENT_DN, 
					  last_parent_dn_value);
		
                string_value = g_value_get_string (last_dn_value);
                g_assert (string_value);

		if (! strcmp (argv[CRL_CA_MODEL_COLUMN_PARENT_DN], string_value)) {
			// Last node is parent of the current node
			if (pdata->last_parent_iter)
				gtk_tree_iter_free (pdata->last_parent_iter);
			pdata->last_parent_iter = gtk_tree_iter_copy (pdata->last_ca_iter);
		} else {
			// We go back in the hierarchical tree, starting in the current parent, until we find the parent of the
			// current certificate.
			
			while (pdata->last_parent_iter && 
			       strcmp (argv[CRL_CA_MODEL_COLUMN_PARENT_DN], g_value_get_string(last_parent_dn_value))) {

				if (! gtk_tree_model_iter_parent(GTK_TREE_MODEL(new_model), &iter, pdata->last_parent_iter)) {
					// Last ca iter is a top_level
					if (pdata->last_parent_iter)
						gtk_tree_iter_free (pdata->last_parent_iter);
					pdata->last_parent_iter = NULL;
				} else {
					if (pdata->last_parent_iter)
						gtk_tree_iter_free (pdata->last_parent_iter);
					pdata->last_parent_iter = gtk_tree_iter_copy (&iter);
				}

				g_value_unset (last_parent_dn_value);

				gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), pdata->last_parent_iter,
							  CRL_CA_MODEL_COLUMN_DN, 
							  last_parent_dn_value);

			}
		}

		
	}

	gtk_tree_store_append (new_model, &iter, pdata->last_parent_iter);
	
	gtk_tree_store_set (new_model, &iter,
			    CRL_CA_MODEL_COLUMN_ID, atoi(argv[CRL_CA_MODEL_COLUMN_ID]), 
			    CRL_CA_MODEL_COLUMN_SERIAL, atoll(argv[CRL_CA_MODEL_COLUMN_SERIAL]),
			    CRL_CA_MODEL_COLUMN_SUBJECT, subject_with_expiration,
			    CRL_CA_MODEL_COLUMN_DN, argv[CRL_CA_MODEL_COLUMN_DN],
			    CRL_CA_MODEL_COLUMN_PARENT_DN, argv[CRL_CA_MODEL_COLUMN_PARENT_DN],
                            CRL_CA_MODEL_COLUMN_PEM, argv[CRL_CA_MODEL_COLUMN_PEM],
			    CRL_CA_MODEL_COLUMN_EXPIRATION, argv[CRL_CA_MODEL_COLUMN_EXPIRATION],
			    -1);
	if (pdata->last_ca_iter)
		gtk_tree_iter_free (pdata->last_ca_iter);
	pdata->last_ca_iter = gtk_tree_iter_copy (&iter);

	g_free (last_dn_value);
	g_free (last_parent_dn_value);
	g_free (subject_with_expiration);

	return 0;
}


void __crl_populate_ca_treeview (GtkTreeView *treeview)
{
	GtkCellRenderer * renderer = NULL;
        __CrlRefreshModelAddCaUserData pdata;

	crl_ca_list_model = gtk_tree_store_new (CRL_CA_MODEL_COLUMN_NUMBER, G_TYPE_UINT, G_TYPE_UINT64, G_TYPE_STRING,
                                                G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

        pdata.new_model = crl_ca_list_model;
        pdata.last_parent_iter = NULL;
        pdata.last_ca_iter = NULL;

	ca_file_foreach_ca (__crl_refresh_model_add_ca, &pdata);

        if (pdata.last_parent_iter)
                gtk_tree_iter_free (pdata.last_parent_iter);

        if (pdata.last_ca_iter)
                gtk_tree_iter_free (pdata.last_ca_iter);

	g_dataset_destroy (crl_ca_list_model);

	renderer = GTK_CELL_RENDERER (gtk_cell_renderer_text_new());

	gtk_tree_view_insert_column_with_attributes (treeview,
						     -1, _("Subject"), renderer,
						     "markup", CRL_CA_MODEL_COLUMN_SUBJECT,
						     NULL);

	
	gtk_tree_view_set_model (treeview, GTK_TREE_MODEL(crl_ca_list_model));

	gtk_tree_view_expand_all (treeview);

	return;

}

G_MODULE_EXPORT void crl_treeview_cursor_changed_cb (GtkTreeView *treeview, gpointer userdata)
{
        GtkTreeSelection *selection = gtk_tree_view_get_selection (treeview);
        if (gtk_tree_selection_count_selected_rows(selection) == 0)
                gtk_widget_set_sensitive (GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "crl_ok_button")), FALSE);
        else
                gtk_widget_set_sensitive (GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "crl_ok_button")), TRUE);
}



void crl_window_display (void)
{
        GtkWidget * widget = NULL;

	crl_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (crl_window_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "new_crl_dialog.ui", NULL),
				   NULL);
	gtk_builder_connect_signals (crl_window_gtkb, NULL);
	
        widget = GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
        gtk_widget_show (widget);

        __crl_populate_ca_treeview (GTK_TREE_VIEW(gtk_builder_get_object (crl_window_gtkb, "crl_ca_treeview")));

}


G_MODULE_EXPORT void crl_cancel_clicked_cb (GtkButton *button, gpointer userdata)
{
	GtkWidget * window = GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
        gtk_widget_destroy(GTK_WIDGET(window));	

}

G_MODULE_EXPORT void crl_ok_clicked_cb (GtkButton *button, gpointer userdata)
{
	GtkWidget *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	guint64 ca_id = 0;
        gchar * strerror = NULL;

	GtkTreeView *treeview = GTK_TREE_VIEW(gtk_builder_get_object(crl_window_gtkb, "crl_ca_treeview"));
	GtkTreeSelection *selection = gtk_tree_view_get_selection (treeview);
        GValue *value = g_new0(GValue, 1);
        GtkTreeModel *model;
	GtkTreeIter iter;

        gtk_tree_selection_get_selected (selection, &model, &iter);
        gtk_tree_model_get_value (model, &iter, CRL_CA_MODEL_COLUMN_ID, value);
        ca_id = g_value_get_uint(value);


	widget = GTK_WIDGET(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export Certificate Revocation List"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));
		
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		return;
	}

	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	strerror = crl_generate (ca_id, filename);
	if (strerror) {
		dialog_error (strerror);
	} else {
		
	}

	gtk_widget_destroy (GTK_WIDGET(dialog));
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_INFO,
						    GTK_BUTTONS_CLOSE,
						    "%s",
						    _("CRL generated successfully")));
	gtk_dialog_run (GTK_DIALOG(dialog));
	
	gtk_widget_destroy (GTK_WIDGET(dialog));

        dialog = GTK_DIALOG(gtk_builder_get_object (crl_window_gtkb, "new_crl_dialog"));
        gtk_widget_destroy(GTK_WIDGET(dialog));	
			
}

#endif /*GNOMINTCLI*/

gchar * crl_generate (guint64 ca_id, gchar *filename)
{
        time_t timestamp;
        gint crl_version = 0;
	gchar * dn = NULL;
	gchar * ca_pem = NULL;
	gchar * private_key = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * pem = NULL;
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
                        return (_("There was an error while generating CRL."));
                }
                g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);

                if (error) {
                        g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
                        g_list_free (revoked_certs);
                        ca_file_rollback_new_crl_transaction ();
                        return (_("There was an error while writing CRL."));
                }
                g_free (pem);

	} else {
                        g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
                        g_list_free (revoked_certs);
                        ca_file_rollback_new_crl_transaction ();
                        return (_("There was an error while exporting CRL."));
        }
        
        ca_file_commit_new_crl_transaction (ca_id, revoked_certs);
		
        g_list_foreach (revoked_certs, __crl_gfree_gfunc, NULL);
        g_list_free (revoked_certs);
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_io_channel_unref (file);
		return (_("There was an error while exporting CRL."));
	}
	
	g_io_channel_unref (file);
	
	return NULL;
}

void __crl_gfree_gfunc (gpointer data, gpointer user_data)
{
        g_free (data);
}

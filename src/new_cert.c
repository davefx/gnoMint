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
#endif

#include <stdlib.h>
#include <string.h>
#include <glib/gi18n.h>

#include "ca_file.h"
#include "tls.h"
#include "dialog.h"
#include "pkey_manage.h"
#include "preferences-gui.h"
#include "new_cert.h"

#ifndef GNOMINTCLI
GtkBuilder * new_cert_window_gtkb = NULL;
GtkTreeStore * new_cert_ca_list_model = NULL;


enum {NEW_CERT_CA_MODEL_COLUMN_ID=0,
      NEW_CERT_CA_MODEL_COLUMN_SERIAL=1,
      NEW_CERT_CA_MODEL_COLUMN_SUBJECT=2,
      NEW_CERT_CA_MODEL_COLUMN_DN=3,
      NEW_CERT_CA_MODEL_COLUMN_PARENT_DN=4,
      NEW_CERT_CA_MODEL_COLUMN_PEM=5,
      NEW_CERT_CA_MODEL_COLUMN_NUMBER=6}
        NewCertCaListModelColumns;

typedef struct {
        GtkTreeStore * new_model;
        GtkTreeIter * last_parent_iter;
        GtkTreeIter * last_ca_iter;
} __NewCertWindowRefreshModelAddCaUserData;

typedef struct {
        gboolean found;
        GtkTreeIter * iter;
        const gchar *ca_id;        
} __NewCertWindowFindCaUserData;

int __new_cert_window_refresh_model_add_ca (void *pArg, int argc, char **argv, char **columnNames);
void __new_cert_populate_ca_treeview (GtkTreeView *treeview);
gboolean __new_cert_window_find_ca (GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data);



int __new_cert_window_refresh_model_add_ca (void *pArg, int argc, char **argv, char **columnNames)
{
	GValue *last_dn_value = g_new0 (GValue, 1);
	GValue *last_parent_dn_value = g_new0 (GValue, 1);
	GtkTreeIter iter;
        __NewCertWindowRefreshModelAddCaUserData *pdata = (__NewCertWindowRefreshModelAddCaUserData *) pArg;
	GtkTreeStore * new_model = pdata->new_model;

        const gchar * string_value;

	// First we check if this is the first CA, or is a self-signed certificate
	if (! pdata->last_ca_iter || (! strcmp (argv[NEW_CERT_CA_MODEL_COLUMN_DN],argv[NEW_CERT_CA_MODEL_COLUMN_PARENT_DN])) ) {

		if (pdata->last_parent_iter)
			gtk_tree_iter_free (pdata->last_parent_iter);

		pdata->last_parent_iter = NULL;
		
	} else {
		// If not, then we must find the parent of the current nod
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), pdata->last_ca_iter, NEW_CERT_CA_MODEL_COLUMN_DN, last_dn_value);
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), pdata->last_ca_iter, NEW_CERT_CA_MODEL_COLUMN_PARENT_DN, 
					  last_parent_dn_value);
		
                string_value = g_value_get_string (last_dn_value);
                g_assert (string_value);

		if (! strcmp (argv[NEW_CERT_CA_MODEL_COLUMN_PARENT_DN], string_value)) {
			// Last node is parent of the current node
			if (pdata->last_parent_iter)
				gtk_tree_iter_free (pdata->last_parent_iter);
			pdata->last_parent_iter = gtk_tree_iter_copy (pdata->last_ca_iter);
		} else {
			// We go back in the hierarchical tree, starting in the current parent, until we find the parent of the
			// current certificate.
			
			while (pdata->last_parent_iter && 
			       strcmp (argv[NEW_CERT_CA_MODEL_COLUMN_PARENT_DN], g_value_get_string(last_parent_dn_value))) {

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
							  NEW_CERT_CA_MODEL_COLUMN_DN, 
							  last_parent_dn_value);

			}
		}

		
	}

	gtk_tree_store_append (new_model, &iter, pdata->last_parent_iter);
	
	gtk_tree_store_set (new_model, &iter,
			    0, atoll(argv[NEW_CERT_CA_MODEL_COLUMN_ID]), 
			    1, atoll(argv[NEW_CERT_CA_MODEL_COLUMN_SERIAL]),
			    2, argv[NEW_CERT_CA_MODEL_COLUMN_SUBJECT],
			    3, argv[NEW_CERT_CA_MODEL_COLUMN_DN],
			    4, argv[NEW_CERT_CA_MODEL_COLUMN_PARENT_DN],
                            5, argv[NEW_CERT_CA_MODEL_COLUMN_PEM],
			    -1);
	if (pdata->last_ca_iter)
		gtk_tree_iter_free (pdata->last_ca_iter);
	pdata->last_ca_iter = gtk_tree_iter_copy (&iter);

	g_free (last_dn_value);
	g_free (last_parent_dn_value);

	return 0;
}




void __new_cert_populate_ca_treeview (GtkTreeView *treeview)
{
	GtkCellRenderer * renderer = NULL;
        __NewCertWindowRefreshModelAddCaUserData pdata;

	new_cert_ca_list_model = gtk_tree_store_new (NEW_CERT_CA_MODEL_COLUMN_NUMBER, G_TYPE_UINT64, G_TYPE_UINT64, G_TYPE_STRING,
						    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

        pdata.new_model = new_cert_ca_list_model;
        pdata.last_parent_iter = NULL;
        pdata.last_ca_iter = NULL;

	ca_file_foreach_ca (__new_cert_window_refresh_model_add_ca, &pdata);

        if (pdata.last_parent_iter)
                gtk_tree_iter_free (pdata.last_parent_iter);

        if (pdata.last_ca_iter)
                gtk_tree_iter_free (pdata.last_ca_iter);

	g_dataset_destroy (new_cert_ca_list_model);

	renderer = GTK_CELL_RENDERER (gtk_cell_renderer_text_new());

	gtk_tree_view_insert_column_with_attributes (treeview,
						     -1, _("Subject"), renderer,
						     "markup", NEW_CERT_CA_MODEL_COLUMN_SUBJECT,
						     NULL);

	
	gtk_tree_view_set_model (treeview, GTK_TREE_MODEL(new_cert_ca_list_model));

	gtk_tree_view_expand_all (treeview);

	return;

}

G_MODULE_EXPORT void new_cert_signing_ca_treeview_cursor_changed (GtkTreeView *treeview, gpointer userdata)
{
        GtkTreeSelection *selection = gtk_tree_view_get_selection (treeview);
        if (gtk_tree_selection_count_selected_rows(selection) == 0)
                gtk_widget_set_sensitive (GTK_WIDGET(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_next2")), FALSE);
        else
                gtk_widget_set_sensitive (GTK_WIDGET(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_next2")), TRUE);
}

gboolean __new_cert_window_find_ca (GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
        __NewCertWindowFindCaUserData *userdata = (__NewCertWindowFindCaUserData *) data;
        
        guint64 ca_id;

        gtk_tree_model_get (model, iter, NEW_CERT_CA_MODEL_COLUMN_ID, &ca_id, -1);

        if (ca_id == atoll(userdata->ca_id)) {
                userdata->found = TRUE;
                *(userdata->iter) = (*iter);
                return TRUE;
        }
        
        return FALSE;
}


void new_cert_window_display(const guint64 csr_id, const gchar *csr_pem, const gchar *csr_parent_id)
{
	GObject * object;
        TlsCsr * csr_info = NULL;

	csr_info = tls_parse_csr_pem (csr_pem);

	new_cert_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (new_cert_window_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "new_cert_window.ui", NULL ),
				   NULL);
	

	gtk_builder_connect_signals (new_cert_window_gtkb, NULL); 	
	
        object = gtk_builder_get_object (new_cert_window_gtkb, "new_cert_window");
        g_object_set_data_full (G_OBJECT(object), "csr_info", csr_info, (GDestroyNotify) tls_csr_free);
	g_object_set_data (G_OBJECT(object), "csr_id", g_strdup_printf ("%" G_GUINT64_FORMAT, csr_id));

	object = gtk_builder_get_object (new_cert_window_gtkb, "c_label");
	gtk_label_set_text (GTK_LABEL(object), csr_info->c);

	object = gtk_builder_get_object (new_cert_window_gtkb, "st_label");
	gtk_label_set_text (GTK_LABEL(object), csr_info->st);

	object = gtk_builder_get_object (new_cert_window_gtkb, "l_label");
	gtk_label_set_text (GTK_LABEL(object), csr_info->l);

	object = gtk_builder_get_object (new_cert_window_gtkb, "o_label");
	gtk_label_set_text (GTK_LABEL(object), csr_info->o);

	object = gtk_builder_get_object (new_cert_window_gtkb, "ou_label");
	gtk_label_set_text (GTK_LABEL(object), csr_info->ou);

	object = gtk_builder_get_object (new_cert_window_gtkb, "cn_label");
	gtk_label_set_text (GTK_LABEL(object), csr_info->cn);
	
        object = gtk_builder_get_object (new_cert_window_gtkb, "signing_ca_treeview");
        __new_cert_populate_ca_treeview (GTK_TREE_VIEW(object));

        if (csr_parent_id) {
                GtkTreeIter iter; 
                GtkTreeModel *model = gtk_tree_view_get_model (GTK_TREE_VIEW(object)); 
                __NewCertWindowFindCaUserData *userdata = g_new0 (__NewCertWindowFindCaUserData, 1);

                userdata->iter = &iter;
                userdata->ca_id = csr_parent_id;

                gtk_tree_model_foreach (model, __new_cert_window_find_ca, userdata);
                
                if (userdata->found) {
                        GtkTreeSelection *selection = gtk_tree_view_get_selection (GTK_TREE_VIEW(object));
                        gtk_tree_selection_set_mode (selection, GTK_SELECTION_SINGLE);
                        gtk_tree_selection_select_iter (selection, &iter);
                }

                g_free (userdata);
        }

}


void new_cert_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

G_MODULE_EXPORT void on_new_cert_next2_clicked (GtkButton *button,
			      gpointer user_data) 
{
	// Whenever gnoMint support more than one CA, here we will
	// have to select the CA for signing the CSR.

	// Meanwhile, we choose the unique CA, and determine its policy.
	GtkTreeView *treeview = GTK_TREE_VIEW(gtk_builder_get_object(new_cert_window_gtkb, "signing_ca_treeview"));
	GtkTreeSelection *selection = gtk_tree_view_get_selection (treeview);
        GValue *value = g_new0(GValue, 1);
        GtkTreeModel *model;
	GtkTreeIter iter;
	GObject * object;
	guint i_value;
	guint64 ca_id;
        const gchar *ca_pem;
        TlsCert *tls_ca_cert = NULL;
        TlsCsr * tls_csr = g_object_get_data (G_OBJECT(gtk_builder_get_object(new_cert_window_gtkb, "new_cert_window")), "csr_info");

        gtk_tree_selection_get_selected (selection, &model, &iter);
        gtk_tree_model_get_value (model, &iter, NEW_CERT_CA_MODEL_COLUMN_ID, value);
        ca_id = g_value_get_uint64(value);
        
        g_value_unset (value);

        gtk_tree_model_get_value (model, &iter, NEW_CERT_CA_MODEL_COLUMN_PEM, value);
        ca_pem = g_value_get_string(value);
        tls_ca_cert = tls_parse_cert_pem (ca_pem);
        g_free (value);
	
        /* Check for differences in fields that must be equal according to the CA policy */
        if (ca_file_policy_get_int (ca_id, "C_FORCE_SAME") && 
            (tls_ca_cert->c != tls_csr->c) && // If they are the same, they both are NULL, so it is OK
            (tls_ca_cert->c == NULL || tls_csr->c == NULL || strcmp(tls_ca_cert->c, tls_csr->c))) {
                dialog_error (_("The policy of this CA obligue the country field of the certificates to be the same as the one in the CA cert."));
                return;
        }
        if (ca_file_policy_get_int (ca_id, "ST_FORCE_SAME") && 
            (tls_ca_cert->st != tls_csr->st) && // If they are the same, they both are NULL, so it is OK
            (tls_ca_cert->st == NULL || tls_csr->st == NULL || strcmp(tls_ca_cert->st, tls_csr->st))) {
                dialog_error (_("The policy of this CA obligue the state/province field of the certificates to be the same as the one in the CA cert."));
                return;
        }
        if (ca_file_policy_get_int (ca_id, "L_FORCE_SAME") && 
            (tls_ca_cert->l != tls_csr->l) && // If they are the same, they both are NULL, so it is OK
            (tls_ca_cert->l == NULL || tls_csr->st == NULL || strcmp(tls_ca_cert->l, tls_csr->l))) {
                dialog_error (_("The policy of this CA obligue the locality/city field of the certificates to be the same as the one in the CA cert."));
                return;
        }
        if (ca_file_policy_get_int (ca_id, "O_FORCE_SAME") && 
            (tls_ca_cert->o != tls_csr->o) && // If they are the same, they both are NULL, so it is OK
            (tls_ca_cert->o == NULL || tls_csr->o == NULL || strcmp(tls_ca_cert->o, tls_csr->o))) {
                dialog_error (_("The policy of this CA obligue the organization field of the certificates to be the same as the one in the CA cert."));
                return;
        }
        if (ca_file_policy_get_int (ca_id, "OU_FORCE_SAME") && 
            (tls_ca_cert->ou != tls_csr->ou) && // If they are the same, they both are NULL, so it is OK
            (tls_ca_cert->ou == NULL || tls_csr->ou == NULL || strcmp(tls_ca_cert->ou, tls_csr->ou))) {
                dialog_error (_("The policy of this CA obligue the organizational unit field of the certificates to be the same as the one in the CA cert."));
                return;
        }
        


        tls_cert_free (tls_ca_cert);

	i_value = ca_file_policy_get_int (ca_id, "MONTHS_TO_EXPIRE");
	object = gtk_builder_get_object (new_cert_window_gtkb, "months_before_expiration_spinbutton1");
	gtk_spin_button_set_range (GTK_SPIN_BUTTON(object), 1, i_value);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "CA");
	object = gtk_builder_get_object (new_cert_window_gtkb, "ca_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);

/* 	i_value = ca_file_policy_get_int (ca_id, "CERT_SIGN")); */
/* 	object = gtk_builder_get_object (new_cert_window_gtkb, "cert_signing_check2"); */
/* 	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value); */

	i_value = ca_file_policy_get_int (ca_id, "CRL_SIGN");
	object = gtk_builder_get_object (new_cert_window_gtkb, "crl_signing_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "NON_REPUDIATION");
	object = gtk_builder_get_object (new_cert_window_gtkb, "non_repudiation_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "DIGITAL_SIGNATURE");
	object = gtk_builder_get_object (new_cert_window_gtkb, "digital_signature_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "KEY_ENCIPHERMENT");
	object = gtk_builder_get_object (new_cert_window_gtkb, "key_encipherment_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "KEY_AGREEMENT");
	object = gtk_builder_get_object (new_cert_window_gtkb, "key_agreement_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "DATA_ENCIPHERMENT");
	object = gtk_builder_get_object (new_cert_window_gtkb, "data_encipherment_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "TLS_WEB_SERVER");
	object = gtk_builder_get_object (new_cert_window_gtkb, "webserver_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "TLS_WEB_CLIENT");
	object = gtk_builder_get_object (new_cert_window_gtkb, "webclient_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "TIME_STAMPING");
	object = gtk_builder_get_object (new_cert_window_gtkb, "time_stamping_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "CODE_SIGNING");
	object = gtk_builder_get_object (new_cert_window_gtkb, "code_signing_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "EMAIL_PROTECTION");
	object = gtk_builder_get_object (new_cert_window_gtkb, "email_protection_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);
	
	i_value = ca_file_policy_get_int (ca_id, "OCSP_SIGNING");
	object = gtk_builder_get_object (new_cert_window_gtkb, "ocsp_signing_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	i_value = ca_file_policy_get_int (ca_id, "ANY_PURPOSE");
	object = gtk_builder_get_object (new_cert_window_gtkb, "any_purpose_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(object), i_value);
	gtk_widget_set_sensitive (GTK_WIDGET(object), i_value);

	
	new_cert_tab_activate (2);
}

G_MODULE_EXPORT void on_new_cert_previous2_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_cert_tab_activate (0);
}

G_MODULE_EXPORT void on_new_cert_next1_clicked (GtkButton *button,
			      gpointer user_data) 
{

	new_cert_tab_activate (1);
}

G_MODULE_EXPORT void on_new_cert_previous3_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_cert_tab_activate (1);
}

G_MODULE_EXPORT void on_new_cert_cancel_clicked (GtkButton *widget,
			       gpointer user_data) 
{
	GtkWidget * window = GTK_WIDGET(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_window"));
        gtk_object_destroy(GTK_OBJECT(window));	
	
}

G_MODULE_EXPORT void on_new_cert_property_toggled (GtkWidget *button, gpointer user_data)
{
        gboolean is_active;
	
	if (! button)
		return;

        is_active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));

	if (! strcmp(gtk_widget_get_name (button), "non_repudiation_check")) {
                if (! is_active) {
                        // TIME_STAMPING cannot be inactive
                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                              "time_stamping_check")), FALSE);
                        // We must check if EMAIL_PROTECTION can be active
                        if (! gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) &&
                            ! gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check"))) &&
                            ! gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check")))) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb,
                                                                                                      "email_protection_check")), FALSE);
                        }
                        
                        // We must check if OCSP_SIGNING can be active
                        if (! gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check")))) {
                                // If is not active, we must deactivate OCSP_SIGNING
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb,
                                                                                                      "ocsp_signing_check")), FALSE);
                        }
                        
                }
        }
        
	if (! strcmp(gtk_widget_get_name (button), "digital_signature_check")) {
                if (! is_active) {
                        // We must check if TLS_WEB_SERVER can be active
                        if (! gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check"))) &&
                            ! gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check")))) {
                                // If none is active, we must deactivate TLS_WEB_SERVER
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "webserver_check")), FALSE);
                        }

                        // We must check if TLS_WEB_CLIENT can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check")))) {
                                // If none is active, we must deactivate TLS_WEB_CLIENT
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "webclient_check")), FALSE);
                        }

                        // TIME_STAMPING and CODE_SIGNING cannot be active if digital signature is deactivated
                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,
                                                                                             "time_stamping_check")), FALSE);

                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,
                                                                                             "code_signing_check")), FALSE);

                        // We must check if EMAIL_PROTECTION can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check")))) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "email_protection_check")), FALSE);
                        }

                        // We must check if OCSP_SIGNING can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation_check")))) {
                                // If none is active, we must deactivate OCSP_SIGNING
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "ocsp_signing_check")), FALSE);
                        }
                        
                        
                }
        }
        
	if (! strcmp(gtk_widget_get_name (button), "key_encipherment_check")) {
                if (! is_active) {
                        // We must check if TLS_WEB_SERVER can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb, "digital_signature_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check")))) {
                                // If none is active, we must deactivate TLS_WEB_SERVER
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "webserver_check")), FALSE);
                        }

                        // We must check if EMAIL_PROTECTION can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check")))) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "email_protection_check")), FALSE);
                        }


                }
        }

	if (! strcmp(gtk_widget_get_name (button), "key_agreement_check")) {
                if (! is_active) {
                        // We must check if TLS_WEB_SERVER can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check")))) {
                                // If none is active, we must deactivate TLS_WEB_SERVER
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "webserver_check")), FALSE);
                        }
                        // We must check if TLS_WEB_CLIENT can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check")))) {
                                // If none is active, we must deactivate TLS_WEB_CLIENT
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "webclient_check")), FALSE);
                        }

                        // We must check if EMAIL_PROTECTION can be active
                        if (! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation_check"))) &&
                            ! gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check")))) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "email_protection_check")), FALSE);
                        }
                }

        }

		

        // Purposes


	if (! strcmp(gtk_widget_get_name (button), "webserver_check")) {
                if (is_active) {
                        // We must check digitalSignature || keyEncipherment || keyAgreement
                        if (!( gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check"))))) {
                                // If none is active, we activate key encipherment
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "key_encipherment_check")), TRUE);
                        }
                        
                }
        }
        
	if (! strcmp(gtk_widget_get_name (button), "webclient_check")) {
                if (is_active) {
                        // We must check digitalSignature || keyEncipherment || keyAgreement
                        if (!( gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check"))))) {
                                // If none is active, we activate digital signature
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "digital_signature_check")), TRUE);
                        }
                        
                }
        }

	if (! strcmp(gtk_widget_get_name (button), "time_stamping_check")){
                if (is_active) {
                        // We must check digitalSignature && nonRepudiation
                        if (!( gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) &&
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation_check"))))) {
                                // If none is active, we activate them both
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "digital_signature_check")), TRUE);
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "non_repudiation_check")), TRUE);
                        }
                               
                }
        }

	if (! strcmp(gtk_widget_get_name (button), "code_signing_check")) {
                if (is_active) {
                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                              "digital_signature_check")), TRUE);
                }
        }

	if (! strcmp(gtk_widget_get_name (button), "email_protection_check")) {
                if (is_active) {
                        // We must check digitalSignature || nonRepudiation || (keyEncipherment || keyAgreement)
                        if (!( gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_encipherment_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"key_agreement_check"))))) {
                                // If none is active, we activate key encipherment
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "digital_signature_check")), TRUE);
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "key_encipherment_check")), TRUE);
                        }
                               
                }
        }

	if (! strcmp(gtk_widget_get_name (button), "ocsp_signing_check")) {
                if (is_active) {
                        // We must check digitalSignature || nonRepudiation
                        if (!( gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"digital_signature_check"))) ||
                               gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gtk_builder_get_object(new_cert_window_gtkb,"non_repudiation"))))) {
                                // If none is active, we activate digital signature
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object (new_cert_window_gtkb, 
                                                                                                      "digital_signature_check")), TRUE);
                        }
                               
                }
        }

        
}

G_MODULE_EXPORT void on_new_cert_commit_clicked (GtkButton *widg,
				 gpointer user_data) 
{
	GtkTreeView *treeview = GTK_TREE_VIEW(gtk_builder_get_object(new_cert_window_gtkb, "signing_ca_treeview"));
	GtkTreeSelection *selection = gtk_tree_view_get_selection (treeview);
        GValue *value = g_new0(GValue, 1);
        GtkTreeModel *model;
	GtkTreeIter iter;

	TlsCertCreationData *cert_creation_data = NULL;

	GObject *widget = NULL;
	gint active = -1;
	guint64 ca_id;
	gchar * csr_id_str = g_object_get_data (G_OBJECT(gtk_builder_get_object(new_cert_window_gtkb, "new_cert_window")), "csr_id");
	guint64 csr_id = atoll(csr_id_str);

	const gchar *strerror = NULL;

        gtk_tree_selection_get_selected (selection, &model, &iter);
        gtk_tree_model_get_value (model, &iter, NEW_CERT_CA_MODEL_COLUMN_ID, value);
        ca_id = g_value_get_uint64(value);

	cert_creation_data = g_new0 (TlsCertCreationData, 1);
		
	widget = gtk_builder_get_object (new_cert_window_gtkb, "months_before_expiration_spinbutton1");
	active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(widget));
	cert_creation_data->key_months_before_expiration = active;

	widget = gtk_builder_get_object (new_cert_window_gtkb, "ca_check");
	cert_creation_data->ca = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "crl_signing_check");
	cert_creation_data->crl_signing = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "digital_signature_check");
	cert_creation_data->digital_signature = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "data_encipherment_check");
	cert_creation_data->data_encipherment = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "key_encipherment_check");
	cert_creation_data->key_encipherment = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "non_repudiation_check");
	cert_creation_data->non_repudiation = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "key_agreement_check");
	cert_creation_data->key_agreement = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));

	widget = gtk_builder_get_object (new_cert_window_gtkb, "email_protection_check");
	cert_creation_data->email_protection = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "code_signing_check");
	cert_creation_data->code_signing = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "webclient_check");
	cert_creation_data->web_client = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "webserver_check");
	cert_creation_data->web_server = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "time_stamping_check");
	cert_creation_data->time_stamping = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "ocsp_signing_check");
	cert_creation_data->ocsp_signing = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = gtk_builder_get_object (new_cert_window_gtkb, "any_purpose_check");
	cert_creation_data->any_purpose = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));

	cert_creation_data->crl_distribution_point = ca_file_policy_get (ca_id, "CRL_DISTRIBUTION_POINT");

	strerror = new_cert_sign_csr (csr_id, ca_id, cert_creation_data);

	if (strerror) {
		dialog_error ((gchar *) strerror);
	}

	widget = G_OBJECT(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_window"));
        gtk_object_destroy(GTK_OBJECT(widget));	

	dialog_refresh_list();

}
#endif

const gchar *new_cert_sign_csr (guint64 csr_id, guint64 ca_id, TlsCertCreationData *cert_creation_data)
{
	gchar *csr_pem = NULL;
	
	gchar *certificate;
        gchar *error = NULL;

	gchar *pem;
	gchar *dn;
	gchar *pkey_pem;
	PkeyManageData *crypted_pkey;

	time_t tmp;
	struct tm * expiration_time;

	tmp = time (NULL);	
	cert_creation_data->activation = tmp;
	
#ifndef WIN32
	expiration_time = g_new (struct tm,1);
	localtime_r (&tmp, expiration_time);
#else
	expiration_time = localtime(&tmp);
#endif
	expiration_time->tm_mon = expiration_time->tm_mon + cert_creation_data->key_months_before_expiration;
	expiration_time->tm_year = expiration_time->tm_year + (expiration_time->tm_mon / 12);
	expiration_time->tm_mon = expiration_time->tm_mon % 12;		
	cert_creation_data->expiration = mktime(expiration_time);
#ifndef WIN32
	g_free (expiration_time);
#endif

        ca_file_get_next_serial (&cert_creation_data->serial, ca_id);

	csr_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CSR, csr_id);
	pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	crypted_pkey = pkey_manage_get_certificate_pkey (ca_id);
	dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
					      
	if (pem && crypted_pkey && dn) {

		TlsCert * ca_cert = tls_parse_cert_pem (pem);
		
		/* Check if expiration of the new cert is due after the expiration of the CA certificate.
		   In that case, we reset the expiration date to the CA certificate expiration date, and
		   show a info message.
		*/
		if (cert_creation_data->expiration > ca_cert->expiration_time) {
			dialog_info (_("The expiration date of the new certificate is after the expiration date of the CA certificate.\n\n"
				       "According to the current standards, this is not allowed. The new certificate will be created with the same "
				       "expiration date as the CA certificate."));
			cert_creation_data->expiration = ca_cert->expiration_time;
		}
		
		tls_cert_free (ca_cert);
		
		PkeyManageData *csr_pkey = NULL;

		pkey_pem = pkey_manage_uncrypt (crypted_pkey, dn);

		if (! pkey_pem) {
			g_free (pem);
			pkey_manage_data_free (crypted_pkey);
			g_free (dn);
			return (_("Error while signing CSR."));
		}

		error = tls_generate_certificate (cert_creation_data, csr_pem, pem, pkey_pem, &certificate);

		g_free (pkey_pem);
                if (! error) {
		
                        csr_pkey = pkey_manage_get_csr_pkey (csr_id);
                        
                        if (csr_pkey)
                                if (csr_pkey->is_in_db)
                                        error = ca_file_insert_cert (cert_creation_data->ca, 1, csr_pkey->pkey_data, certificate);
                                else
                                        error = ca_file_insert_cert (cert_creation_data->ca, 0, csr_pkey->external_file, certificate);			
                        else
                                error = ca_file_insert_cert (cert_creation_data->ca, 0, NULL, certificate);
                        
                        if (!error)
                                ca_file_remove_csr (csr_id);
                        else 
                                dialog_error (error);
                        
                        pkey_manage_data_free (csr_pkey);
		}
	}
		
        if (!error && preferences_get_gnome_keyring_export()) {
                TlsCert * cert = NULL;
                gchar *filename = NULL;
                gchar *directory = NULL;
                gchar *aux = NULL;
                cert = tls_parse_cert_pem (certificate);

                // We must calculate the name of the file. 
                // Basically, it will be the subject DN + issuer DN + sha1 fingerprint
                // with substitution of non-valid filename characters

                aux = g_strdup_printf ("%s_%s_%s.pem", cert->dn, cert->i_dn, cert->sha1);
                
                aux = g_strcanon (aux,
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.",
                                  '_');
                
                directory = g_build_filename (g_get_home_dir(), ".gnome2", "keystore", NULL);
                filename = g_build_filename (g_get_home_dir(), ".gnome2", "keystore", aux, NULL);

                if (! g_mkdir_with_parents (directory, 0700)) {
                        g_file_set_contents (filename, certificate, strlen(certificate), NULL);
                }

        }


	g_free (pem);
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	return error;
}


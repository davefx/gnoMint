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


#include <glib-object.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "creation_process_window.h"
#include "ca_file.h"
#include "country_table.h"
#include "tls.h"
#include "pkey_manage.h"
#include "new_req_window.h"
#include "san_manager.h"
#include "ca_selector.h"

#include <glib/gi18n.h>
#include "dialog.h"

GtkBuilder * new_req_window_gtkb = NULL;
static GtkSingleSelection *new_req_ca_selection = NULL;
static GListStore *new_req_ca_root_store = NULL;
gboolean new_req_ca_id_valid = FALSE;
guint64 new_req_ca_id;
GtkWidget *san_manager_widget1 = NULL;


/* (CA tree population and GtkColumnView setup is handled by
 * ca_selector_populate() and ca_selector_setup() in ca_selector.c.) */

G_MODULE_EXPORT void new_req_inherit_fields_toggled (GtkCheckButton *button, gpointer user_data)
{
	GtkWidget *colview = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "new_req_ca_treeview"));

	if (gtk_check_button_get_active (GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "inherit_radiobutton")))) {
		/* Inherit -- enable the column view and select the first row. */
		gtk_widget_set_sensitive (colview, TRUE);
		gtk_single_selection_set_can_unselect (new_req_ca_selection, FALSE);
		gtk_single_selection_set_selected (new_req_ca_selection, 0);
	} else {
		/* Don't inherit -- disable the column view and clear selection. */
		gtk_widget_set_sensitive (colview, FALSE);
		gtk_single_selection_set_can_unselect (new_req_ca_selection, TRUE);
		gtk_single_selection_set_selected (new_req_ca_selection, GTK_INVALID_LIST_POSITION);
	}
}



G_MODULE_EXPORT void on_new_req_privkey_type_toggle (GtkCheckButton *button,
                                                     gpointer        user_data);

void new_req_window_display()
{
	GtkBuilder *san_builder;
	GtkWidget *alignment;
	gchar *ui_file;

	new_req_window_gtkb = gtk_builder_new();

	ui_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "new_req_window.ui", NULL);
	gtk_builder_add_from_file (new_req_window_gtkb, ui_file, NULL);
	g_free(ui_file);
	
	
	country_table_populate_dropdown(GTK_DROP_DOWN(gtk_builder_get_object(new_req_window_gtkb, "country_combobox1")));

	/* Populate and set up CA selector (GtkColumnView). */
	new_req_ca_root_store = ca_selector_populate ();
	new_req_ca_selection = ca_selector_setup (
	    GTK_COLUMN_VIEW (gtk_builder_get_object (new_req_window_gtkb, "new_req_ca_treeview")),
	    new_req_ca_root_store, NULL);

	new_req_inherit_fields_toggled (GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "inherit_radiobutton")), NULL);

	gtk_check_button_set_active (GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "rsa_radiobutton1")), TRUE);

	gtk_spin_button_set_value (GTK_SPIN_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "keylength_spinbutton1")), 2048);

	// Initialize SAN manager widget
	san_builder = gtk_builder_new();
	ui_file = g_build_filename(PACKAGE_DATA_DIR, "gnomint", "san_manager_widget.ui", NULL);
	gtk_builder_add_from_file(san_builder, ui_file, NULL);
	g_free(ui_file);
	san_manager_widget1 = san_manager_create(san_builder, "san_manager_vbox");
	
	if (san_manager_widget1) {
		alignment = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "san_alignment1"));
		gtk_box_append(GTK_BOX(alignment), san_manager_widget1);
		gtk_widget_set_visible(san_manager_widget1, TRUE);
	}

	/* Connect signals explicitly (gtk_builder_connect_signals removed in GTK 4) */
	GtkWidget *w;
	w = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "rsa_radiobutton1"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_req_privkey_type_toggle), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "dsa_radiobutton1"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_req_privkey_type_toggle), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "ecdsa_radiobutton1"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_req_privkey_type_toggle), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "eddsa_radiobutton1"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_req_privkey_type_toggle), NULL);

	w = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "inherit_radiobutton"));
	if (w) g_signal_connect(w, "toggled", G_CALLBACK(new_req_inherit_fields_toggled), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb, "manual_radiobutton"));
	if (w) g_signal_connect(w, "toggled", G_CALLBACK(new_req_inherit_fields_toggled), NULL);

	on_new_req_privkey_type_toggle (NULL, NULL);
}

void new_req_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(gtk_builder_get_object (new_req_window_gtkb, "new_req_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

G_MODULE_EXPORT void on_new_req_privkey_type_toggle (GtkCheckButton *button,
						     gpointer        user_data)
{
	GtkCheckButton *rsatoggle   = GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "rsa_radiobutton1"));
	GtkCheckButton *dsatoggle   = GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "dsa_radiobutton1"));
	GtkCheckButton *ecdsatoggle = GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "ecdsa_radiobutton1"));
	GtkCheckButton *eddsatoggle = GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "eddsa_radiobutton1"));

	GtkAdjustment *adj = GTK_ADJUSTMENT (gtk_builder_get_object (new_req_window_gtkb, "AdjustmentKeyLengthSpinButton1"));
	GtkWidget *spin    = GTK_WIDGET (gtk_builder_get_object (new_req_window_gtkb, "keylength_spinbutton1"));
	GtkWidget *combo   = GTK_WIDGET (gtk_builder_get_object (new_req_window_gtkb, "ecdsa_curve_combo1"));
	GtkLabel  *label   = GTK_LABEL  (gtk_builder_get_object (new_req_window_gtkb, "label99"));
	gdouble    value   = gtk_spin_button_get_value (GTK_SPIN_BUTTON (spin));

	if (rsatoggle && gtk_check_button_get_active(rsatoggle)) {
		gtk_adjustment_set_upper (adj, 10240);
		gtk_widget_set_visible(spin, TRUE);
		if (combo) gtk_widget_set_visible(combo, FALSE);
		if (label) {
			gtk_label_set_text (label, _("Private key bit length:"));
			gtk_widget_set_visible(GTK_WIDGET(label), TRUE);
		}
	} else if (dsatoggle && gtk_check_button_get_active(dsatoggle)) {
		gtk_adjustment_set_upper (adj, 3072);
		if (value > 3072)
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (spin), 3072);
		gtk_widget_set_visible(spin, TRUE);
		if (combo) gtk_widget_set_visible(combo, FALSE);
		if (label) {
			gtk_label_set_text (label, _("Private key bit length:"));
			gtk_widget_set_visible(GTK_WIDGET(label), TRUE);
		}
	} else if (ecdsatoggle && gtk_check_button_get_active(ecdsatoggle)) {
		gtk_widget_set_visible(spin, FALSE);
		if (combo) {
			gtk_widget_set_visible(combo, TRUE);
			if (gtk_drop_down_get_selected (GTK_DROP_DOWN (combo)) == GTK_INVALID_LIST_POSITION)
				gtk_drop_down_set_selected (GTK_DROP_DOWN (combo), 0);
		}
		if (label) {
			gtk_label_set_text (label, _("ECDSA curve:"));
			gtk_widget_set_visible(GTK_WIDGET(label), TRUE);
		}
	} else if (eddsatoggle && gtk_check_button_get_active(eddsatoggle)) {
		gtk_widget_set_visible(spin, FALSE);
		if (combo) gtk_widget_set_visible(combo, FALSE);
		if (label) gtk_widget_set_visible(GTK_WIDGET(label), FALSE);
	}
}

G_MODULE_EXPORT void on_new_req_cn_entry_changed (GtkEditable *editable,
			 gpointer user_data) 
{
	GtkButton *button = GTK_BUTTON(gtk_builder_get_object (new_req_window_gtkb, "new_req_next2"));

	if (strlen (gtk_editable_get_text(GTK_EDITABLE(editable)))) 
		gtk_widget_set_sensitive (GTK_WIDGET(button), TRUE);
	else
		gtk_widget_set_sensitive (GTK_WIDGET(button), FALSE);
		
}



G_MODULE_EXPORT void on_new_req_next1_clicked (GtkButton *button,
			      gpointer user_data)
{
        TlsCert * tlscert;
        GtkWidget * widget;
	const gchar *pem;
	gboolean inherit_fields;

	inherit_fields = gtk_check_button_get_active (GTK_CHECK_BUTTON(gtk_builder_get_object(new_req_window_gtkb, "inherit_radiobutton")));

	GnomintCertRow *sel_row = ca_selector_get_selected_row (new_req_ca_selection);

        if (inherit_fields && sel_row) {

		pem = gnomint_cert_row_get_pem (sel_row);
		g_assert (pem);
                tlscert = tls_parse_cert_pem (pem);

                new_req_ca_id_valid = TRUE;
                new_req_ca_id = gnomint_cert_row_get_id (sel_row);
		g_object_unref (sel_row);

		widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"country_combobox1"));
                if (ca_file_policy_get_int (new_req_ca_id, "C_INHERIT")) {
                        gtk_widget_set_sensitive (widget, ! ca_file_policy_get_int (new_req_ca_id, "C_FORCE_SAME"));
                        {
                                GtkDropDown *dd = GTK_DROP_DOWN (widget);
                                guint idx = country_table_find_code (dd, tlscert->c);
                                gtk_drop_down_set_selected (dd, idx);
                        }
                } else {
                        gtk_widget_set_sensitive (widget, TRUE);
			gtk_drop_down_set_selected (GTK_DROP_DOWN(widget), GTK_INVALID_LIST_POSITION);
                }
                
		widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"st_entry1"));
                if (ca_file_policy_get_int (new_req_ca_id, "ST_INHERIT")) {
                        gtk_widget_set_sensitive (widget, ! ca_file_policy_get_int (new_req_ca_id, "ST_FORCE_SAME"));
                        gtk_editable_set_text(GTK_EDITABLE(widget), tlscert->st);
                } else {
                        gtk_widget_set_sensitive (widget, TRUE);
                        gtk_editable_set_text(GTK_EDITABLE(widget), "");
                }
                
		widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"city_entry1"));
                if (ca_file_policy_get_int (new_req_ca_id, "L_INHERIT")) {
                        gtk_widget_set_sensitive (widget, ! ca_file_policy_get_int (new_req_ca_id, "L_FORCE_SAME"));
                        gtk_editable_set_text(GTK_EDITABLE(widget), tlscert->l);
                } else {
                        gtk_widget_set_sensitive (widget, TRUE);
                        gtk_editable_set_text(GTK_EDITABLE(widget), "");
                }
                
		widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"o_entry1"));
                if (ca_file_policy_get_int (new_req_ca_id, "O_INHERIT")) {
                        gtk_widget_set_sensitive (widget, ! ca_file_policy_get_int (new_req_ca_id, "O_FORCE_SAME"));
                        gtk_editable_set_text(GTK_EDITABLE(widget), tlscert->o);
                } else {
                        gtk_widget_set_sensitive (widget, TRUE);
                        gtk_editable_set_text(GTK_EDITABLE(widget), "");
                }
                
                widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"ou_entry1"));
                if (ca_file_policy_get_int (new_req_ca_id, "OU_INHERIT")) {
                        gtk_widget_set_sensitive (widget, ! ca_file_policy_get_int (new_req_ca_id, "OU_FORCE_SAME"));
                        gtk_editable_set_text(GTK_EDITABLE(widget), tlscert->ou);
                } else {
                        gtk_widget_set_sensitive (widget, TRUE);
			gtk_editable_set_text(GTK_EDITABLE(widget), "");
		}
                
                tls_cert_free (tlscert);
        } else {
		if (sel_row)
			g_object_unref (sel_row);
                new_req_ca_id_valid = FALSE;

                widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"country_combobox1"));
                gtk_widget_set_sensitive (widget, TRUE);
		gtk_drop_down_set_selected (GTK_DROP_DOWN(widget), GTK_INVALID_LIST_POSITION);
                widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"st_entry1"));
                gtk_widget_set_sensitive (widget, TRUE);
		gtk_editable_set_text(GTK_EDITABLE(widget), "");
                widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"city_entry1"));
                gtk_widget_set_sensitive (widget, TRUE);
		gtk_editable_set_text(GTK_EDITABLE(widget), "");
                widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"o_entry1"));
                gtk_widget_set_sensitive (widget, TRUE);
		gtk_editable_set_text(GTK_EDITABLE(widget), "");
                widget = GTK_WIDGET(gtk_builder_get_object(new_req_window_gtkb,"ou_entry1"));
                gtk_widget_set_sensitive (widget, TRUE);
		gtk_editable_set_text(GTK_EDITABLE(widget), "");
        }

	new_req_tab_activate (1);
}

G_MODULE_EXPORT void on_new_req_previous2_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_req_tab_activate (0);
}

G_MODULE_EXPORT void on_new_req_next2_clicked (GtkButton *widget,
			      gpointer user_data)
{
	GtkEditable *cn = GTK_EDITABLE(gtk_builder_get_object (new_req_window_gtkb, "new_req_cn_entry"));
	if (!strlen (gtk_editable_get_text (cn))) {
		dialog_error (_("Please enter a Common Name (CN) for the certificate request."));
		return;
	}
	new_req_tab_activate (2);
}

G_MODULE_EXPORT void on_new_req_previous3_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_req_tab_activate (1);
}

G_MODULE_EXPORT void on_new_req_cancel_clicked (GtkButton *widget,
			       gpointer user_data) 
{
	
	GtkWindow *window = GTK_WINDOW(gtk_builder_get_object (new_req_window_gtkb, "new_req_window"));

	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));
	
}

static void
__new_req_commit_password_cb (gchar *password, gpointer user_data)
{
	TlsCreationData *csr_creation_data = (TlsCreationData *) user_data;
	GtkWindow *window;

	if (!password) {
		/* The user hasn't provided a valid password */
		tls_creation_data_free (csr_creation_data);
		return;
	}

	csr_creation_data->password = password;

	window = GTK_WINDOW(gtk_builder_get_object (new_req_window_gtkb, "new_req_window"));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));

	creation_process_window_csr_display (csr_creation_data);
}

G_MODULE_EXPORT void on_new_req_commit_clicked (GtkButton *widg,
			       gpointer user_data)
{
	TlsCreationData *csr_creation_data = NULL;

	GtkWidget *widget = NULL;
	GtkWindow *window = NULL;
	gint active = -1;
	gchar *text = NULL;

	csr_creation_data = g_new0 (TlsCreationData, 1);

        if (new_req_ca_id_valid)
                csr_creation_data->parent_ca_id_str = g_strdup_printf ("'%"G_GUINT64_FORMAT"'", new_req_ca_id);

	{
		GtkDropDown *country_dd = GTK_DROP_DOWN(gtk_builder_get_object (new_req_window_gtkb, "country_combobox1"));
		const gchar *code = country_table_get_code (country_dd);
		if (code)
			csr_creation_data->country = g_strndup (code, 2);
		else
			csr_creation_data->country = NULL;
	}
		
	widget = GTK_WIDGET(gtk_builder_get_object (new_req_window_gtkb, "st_entry1"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		csr_creation_data->state = g_strdup (text);
	else
		csr_creation_data->state = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_req_window_gtkb, "city_entry1"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		csr_creation_data->city = g_strdup (text);
	else
		csr_creation_data->city = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_req_window_gtkb, "o_entry1"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		csr_creation_data->org = g_strdup (text);
	else
		csr_creation_data->org = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_req_window_gtkb, "ou_entry1"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		csr_creation_data->ou = g_strdup (text);
	else
		csr_creation_data->ou = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_req_window_gtkb, "cn_entry1"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		csr_creation_data->cn = g_strdup (text);
	else
		csr_creation_data->cn = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_req_window_gtkb, "email_entry1"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		csr_creation_data->emailAddress = g_strdup (text);
	else
		csr_creation_data->emailAddress = NULL;

	// Get SANs from SAN manager widget
	if (san_manager_widget1) {
		gchar *san_string = san_manager_get_string(san_manager_widget1);
		if (san_string && san_string[0])
			csr_creation_data->subject_alt_name = san_string;
		else {
			g_free(san_string);
			csr_creation_data->subject_alt_name = NULL;
		}
	} else {
		csr_creation_data->subject_alt_name = NULL;
	}

	{
		GtkWidget *eddsa = GTK_WIDGET (
		    gtk_builder_get_object (new_req_window_gtkb, "eddsa_radiobutton1"));
		GtkWidget *ecdsa = GTK_WIDGET (
		    gtk_builder_get_object (new_req_window_gtkb, "ecdsa_radiobutton1"));
		GtkWidget *dsa   = GTK_WIDGET (
		    gtk_builder_get_object (new_req_window_gtkb, "dsa_radiobutton1"));
		if (eddsa && gtk_check_button_get_active (GTK_CHECK_BUTTON (eddsa)))
			csr_creation_data->key_type = 3; /* EdDSA */
		else if (ecdsa && gtk_check_button_get_active (GTK_CHECK_BUTTON (ecdsa)))
			csr_creation_data->key_type = 2; /* ECDSA */
		else if (dsa && gtk_check_button_get_active (GTK_CHECK_BUTTON (dsa)))
			csr_creation_data->key_type = 1; /* DSA */
		else
			csr_creation_data->key_type = 0; /* RSA */
	}

	if (csr_creation_data->key_type == 2 /* ECDSA */) {
		static const int ecdsa_bitlengths[] = { 256, 384, 521 };
		GtkDropDown *curve_dd = GTK_DROP_DOWN (
			gtk_builder_get_object (new_req_window_gtkb, "ecdsa_curve_combo1"));
		guint sel = curve_dd ? gtk_drop_down_get_selected (curve_dd) : GTK_INVALID_LIST_POSITION;
		csr_creation_data->key_bitlength = (sel < G_N_ELEMENTS (ecdsa_bitlengths)) ? ecdsa_bitlengths[sel] : 256;
	} else if (csr_creation_data->key_type == 3 /* EdDSA */) {
		csr_creation_data->key_bitlength = 0;
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (new_req_window_gtkb, "keylength_spinbutton1"));
		active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		csr_creation_data->key_bitlength = active;
	}

	if (ca_file_is_password_protected()) {
		pkey_manage_ask_password (__new_req_commit_password_cb, csr_creation_data);
		return;
        }

	window = GTK_WINDOW(gtk_builder_get_object (new_req_window_gtkb, "new_req_window"));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));

	creation_process_window_csr_display (csr_creation_data);

}





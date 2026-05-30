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

#include "new_ca_window.h"
#include "creation_process_window.h"
#include "ca_file.h"
#include "tls.h"
#include "pkey_manage.h"
#include "country_table.h"
#include "san_manager.h"

#include <glib/gi18n.h>
#include "dialog.h"

GtkBuilder * new_ca_window_gtkb = NULL;
GtkWidget *san_manager_widget = NULL;

G_MODULE_EXPORT void on_new_ca_privkey_type_toggle (GtkCheckButton *button,
                                                    gpointer        user_data);

void new_ca_window_display()
{
	// Workaround for libglade
	GtkBuilder *san_builder;
	GtkWidget *alignment;
	gchar *ui_file;

	new_ca_window_gtkb = gtk_builder_new();
	ui_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "new_ca_window.ui", NULL);
	gtk_builder_add_from_file(new_ca_window_gtkb, ui_file, NULL);
	g_free(ui_file);
	
	
	country_table_populate_dropdown(GTK_DROP_DOWN(gtk_builder_get_object(new_ca_window_gtkb, "country_combobox")));

	gtk_check_button_set_active(GTK_CHECK_BUTTON(gtk_builder_get_object (new_ca_window_gtkb, "rsa_radiobutton")), TRUE);

	gtk_spin_button_set_value (GTK_SPIN_BUTTON(gtk_builder_get_object(new_ca_window_gtkb, "keylength_spinbutton")), 2048);

	// Initialize SAN manager widget
	san_builder = gtk_builder_new();
	ui_file = g_build_filename(PACKAGE_DATA_DIR, "gnomint", "san_manager_widget.ui", NULL);
	gtk_builder_add_from_file(san_builder, ui_file, NULL);
	g_free(ui_file);
	san_manager_widget = san_manager_create(san_builder, "san_manager_vbox");
	
	if (san_manager_widget) {
		alignment = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "san_alignment"));
		gtk_box_append(GTK_BOX(alignment), san_manager_widget);
		gtk_widget_set_visible(san_manager_widget, TRUE);
	}

	/* Connect signals explicitly (gtk_builder_connect_signals removed in GTK 4) */
	GtkWidget *w;
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "rsa_radiobutton"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_ca_privkey_type_toggle), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "dsa_radiobutton"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_ca_privkey_type_toggle), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "ecdsa_radiobutton"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_ca_privkey_type_toggle), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "eddsa_radiobutton"));
	if (w) g_signal_connect(w, "notify::active", G_CALLBACK(on_new_ca_privkey_type_toggle), NULL);

	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_pwd_protect_yes_radiobutton"));
	if (w) g_signal_connect(w, "toggled", G_CALLBACK(on_new_ca_pwd_protect_radiobutton_toggled), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_pwd_protect_no_radiobutton"));
	if (w) g_signal_connect(w, "toggled", G_CALLBACK(on_new_ca_pwd_protect_radiobutton_toggled), NULL);

	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_pwd_entry_1"));
	if (w) g_signal_connect(w, "changed", G_CALLBACK(on_new_ca_pwd_entry_changed), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_pwd_entry_2"));
	if (w) g_signal_connect(w, "changed", G_CALLBACK(on_new_ca_pwd_entry_changed), NULL);

	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "cn_entry"));
	if (w) g_signal_connect(w, "changed", G_CALLBACK(on_cn_entry_changed), NULL);

	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_next1"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_next1_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_previous2"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_previous2_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_next2"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_next2_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_previous3"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_previous3_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_commit"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_commit_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_cancel1"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_cancel_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_cancel2"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_cancel_clicked), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(new_ca_window_gtkb, "new_ca_cancel3"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new_ca_cancel_clicked), NULL);

	on_new_ca_privkey_type_toggle (NULL, NULL);

}



// TAB Manage

void new_ca_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

G_MODULE_EXPORT void on_new_ca_privkey_type_toggle (GtkCheckButton *button,
						     gpointer        user_data)
{
	GtkCheckButton *rsatoggle   = GTK_CHECK_BUTTON (gtk_builder_get_object (new_ca_window_gtkb, "rsa_radiobutton"));
	GtkCheckButton *dsatoggle   = GTK_CHECK_BUTTON (gtk_builder_get_object (new_ca_window_gtkb, "dsa_radiobutton"));
	GtkCheckButton *ecdsatoggle = GTK_CHECK_BUTTON (gtk_builder_get_object (new_ca_window_gtkb, "ecdsa_radiobutton"));
	GtkCheckButton *eddsatoggle = GTK_CHECK_BUTTON (gtk_builder_get_object (new_ca_window_gtkb, "eddsa_radiobutton"));

	GtkAdjustment *adj = GTK_ADJUSTMENT (gtk_builder_get_object (new_ca_window_gtkb, "adjustmentCAKeyLength"));
	GtkWidget *spin    = GTK_WIDGET (gtk_builder_get_object (new_ca_window_gtkb, "keylength_spinbutton"));
	GtkWidget *combo   = GTK_WIDGET (gtk_builder_get_object (new_ca_window_gtkb, "ecdsa_curve_combo"));
	GtkLabel  *label   = GTK_LABEL  (gtk_builder_get_object (new_ca_window_gtkb, "label21"));
	gdouble    value   = gtk_spin_button_get_value (GTK_SPIN_BUTTON (spin));

	if (rsatoggle && gtk_check_button_get_active (rsatoggle)) {
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


G_MODULE_EXPORT void on_cn_entry_changed (GtkEditable *editable,
			 gpointer user_data) 
{
	GtkButton *button = GTK_BUTTON(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_next1"));

	if (strlen (gtk_editable_get_text(GTK_EDITABLE(editable)))) 
		gtk_widget_set_sensitive (GTK_WIDGET(button), TRUE);
	else
		gtk_widget_set_sensitive (GTK_WIDGET(button), FALSE);
		
}

G_MODULE_EXPORT void on_new_ca_next1_clicked (GtkButton *widget,
			      gpointer user_data)
{
	GtkEditable *cn = GTK_EDITABLE(gtk_builder_get_object (new_ca_window_gtkb, "cn_entry"));
	if (!strlen (gtk_editable_get_text (cn))) {
		dialog_error (_("Please enter a Common Name (CN) for the CA."));
		return;
	}
	new_ca_tab_activate (1);
}

G_MODULE_EXPORT void on_new_ca_previous2_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_ca_tab_activate (0);
}

G_MODULE_EXPORT void on_new_ca_next2_clicked (GtkButton *widget,
			      gpointer user_data) 
{
	new_ca_tab_activate (2);
}

G_MODULE_EXPORT void on_new_ca_previous3_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_ca_tab_activate (1);
}

G_MODULE_EXPORT void on_new_ca_cancel_clicked (GtkButton *widget,
			       gpointer user_data) 
{
	
	GtkWindow *window = GTK_WINDOW(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_window"));

	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));
	
}


G_MODULE_EXPORT void on_new_ca_pwd_entry_changed (GtkEntry *entry,
				       gpointer user_data)
{
	const gchar *text1;
	const gchar *text2;
	
	GtkEntry *pwd_entry_1 = GTK_ENTRY(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_pwd_entry_1"));
	GtkEntry *pwd_entry_2 = GTK_ENTRY(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_pwd_entry_2"));
	GtkButton *commit_button = GTK_BUTTON(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_commit"));

	text1 = gtk_editable_get_text(GTK_EDITABLE(pwd_entry_1));
	text2 = gtk_editable_get_text(GTK_EDITABLE(pwd_entry_2));

	if (strlen(text1) && strlen(text2) && ! strcmp(text1, text2)) {
		gtk_widget_set_sensitive (GTK_WIDGET(commit_button), TRUE);		
	} else {
		gtk_widget_set_sensitive (GTK_WIDGET(commit_button), FALSE);		
	}

}


G_MODULE_EXPORT void on_new_ca_pwd_protect_radiobutton_toggled (GtkCheckButton *radiobutton, 
						     gpointer user_data)
{
	GtkCheckButton *yes = GTK_CHECK_BUTTON(gtk_builder_get_object (new_ca_window_gtkb, 
								     "new_ca_pwd_protect_yes_radiobutton"));
	GtkLabel *pwd_label_1 = GTK_LABEL(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_pwd_label_1"));
	GtkLabel *pwd_label_2 = GTK_LABEL(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_pwd_label_2"));
	GtkEntry *pwd_entry_1 = GTK_ENTRY(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_pwd_entry_1"));
	GtkEntry *pwd_entry_2 = GTK_ENTRY(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_pwd_entry_2"));
	GtkButton *commit_button = GTK_BUTTON(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_commit"));

	if (gtk_check_button_get_active (GTK_CHECK_BUTTON(yes))) {
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_label_1), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_label_2), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_entry_1), TRUE);
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_entry_2), TRUE);
		on_new_ca_pwd_entry_changed (pwd_entry_1, NULL);
	} else {
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_label_1), FALSE);
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_label_2), FALSE);
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_entry_1), FALSE);
		gtk_widget_set_sensitive (GTK_WIDGET(pwd_entry_2), FALSE);
		gtk_widget_set_sensitive (GTK_WIDGET(commit_button), TRUE);		
	}

}


static void
__new_ca_commit_password_cb (gchar *password, gpointer user_data)
{
	TlsCreationData *ca_creation_data = (TlsCreationData *) user_data;
	GtkWindow *window;

	if (!password) {
		/* The user hasn't provided a valid password */
		tls_creation_data_free (ca_creation_data);
		return;
	}

	ca_creation_data->password = password;

	window = GTK_WINDOW(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_window"));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));

	creation_process_window_ca_display (ca_creation_data);
}

G_MODULE_EXPORT void on_new_ca_commit_clicked (GtkButton *widg,
			       gpointer user_data)
{
	TlsCreationData *ca_creation_data = NULL;

	GtkWidget *widget = NULL;
	GtkWindow *window = NULL;
	gint active = -1;
	gchar *text = NULL;

	time_t tmp;
	struct tm * expiration_time;

	ca_creation_data = g_new0 (TlsCreationData, 1);
	{
		GtkDropDown *country_dd = GTK_DROP_DOWN(gtk_builder_get_object (new_ca_window_gtkb, "country_combobox"));
		const gchar *code = country_table_get_code (country_dd);
		if (code)
			ca_creation_data->country = g_strndup (code, 2);
		else
			ca_creation_data->country = NULL;
	}
		
	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "st_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->state = g_strdup (text);
	else
		ca_creation_data->state = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "city_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->city = g_strdup (text);
	else
		ca_creation_data->city = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "o_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->org = g_strdup (text);
	else
		ca_creation_data->org = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "ou_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->ou = g_strdup (text);
	else
		ca_creation_data->ou = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "cn_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->cn = g_strdup (text);
	else
		ca_creation_data->cn = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "email_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->emailAddress = g_strdup (text);
	else
		ca_creation_data->emailAddress = NULL;

	// Get SANs from SAN manager widget
	if (san_manager_widget) {
		gchar *san_string = san_manager_get_string(san_manager_widget);
		if (san_string && san_string[0])
			ca_creation_data->subject_alt_name = san_string;
		else {
			g_free(san_string);
			ca_creation_data->subject_alt_name = NULL;
		}
	} else {
		ca_creation_data->subject_alt_name = NULL;
	}

	{
		/* Walk the radio group in priority order so the most
		 * specific selection wins (eddsa > ecdsa > dsa > rsa). */
		GtkWidget *eddsa = GTK_WIDGET (
		    gtk_builder_get_object (new_ca_window_gtkb, "eddsa_radiobutton"));
		GtkWidget *ecdsa = GTK_WIDGET (
		    gtk_builder_get_object (new_ca_window_gtkb, "ecdsa_radiobutton"));
		GtkWidget *dsa   = GTK_WIDGET (
		    gtk_builder_get_object (new_ca_window_gtkb, "dsa_radiobutton"));
		if (eddsa && gtk_check_button_get_active (GTK_CHECK_BUTTON (eddsa)))
			ca_creation_data->key_type = 3; /* EdDSA */
		else if (ecdsa && gtk_check_button_get_active (GTK_CHECK_BUTTON (ecdsa)))
			ca_creation_data->key_type = 2; /* ECDSA */
		else if (dsa && gtk_check_button_get_active (GTK_CHECK_BUTTON (dsa)))
			ca_creation_data->key_type = 1; /* DSA */
		else
			ca_creation_data->key_type = 0; /* RSA */
	}

	if (ca_creation_data->key_type == 2 /* ECDSA */) {
		/* Read the curve from the ECDSA dropdown.
		 * Index 0=P-256, 1=P-384, 2=P-521. */
		static const int ecdsa_bitlengths[] = { 256, 384, 521 };
		GtkDropDown *curve_dd = GTK_DROP_DOWN (
			gtk_builder_get_object (new_ca_window_gtkb, "ecdsa_curve_combo"));
		guint sel = curve_dd ? gtk_drop_down_get_selected (curve_dd) : GTK_INVALID_LIST_POSITION;
		ca_creation_data->key_bitlength = (sel < G_N_ELEMENTS (ecdsa_bitlengths)) ? ecdsa_bitlengths[sel] : 256;
	} else if (ca_creation_data->key_type == 3 /* EdDSA */) {
		ca_creation_data->key_bitlength = 0;  /* fixed by the curve */
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (new_ca_window_gtkb, "keylength_spinbutton"));
		active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		ca_creation_data->key_bitlength = active;
	}

	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "months_before_expiration_spinbutton"));
	active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(widget));
	ca_creation_data->key_months_before_expiration = active;

	tmp = time (NULL);	
	ca_creation_data->activation = tmp;
	
	expiration_time = g_new (struct tm,1);
#ifndef WIN32
	localtime_r (&tmp, expiration_time);
#else
	expiration_time = localtime(&tmp);
#endif
	expiration_time->tm_mon = expiration_time->tm_mon + ca_creation_data->key_months_before_expiration;
	expiration_time->tm_year = expiration_time->tm_year + (expiration_time->tm_mon / 12);
	expiration_time->tm_mon = expiration_time->tm_mon % 12;	
	ca_creation_data->expiration = mktime(expiration_time);
#ifndef WIN32
	g_free (expiration_time);
#endif


	widget = GTK_WIDGET(gtk_builder_get_object (new_ca_window_gtkb, "crl_distribution_point_entry"));
	text = (gchar *) gtk_editable_get_text(GTK_EDITABLE(widget));
	if (strlen (text))
		ca_creation_data->crl_distribution_point = g_strdup (text);
	else
		ca_creation_data->crl_distribution_point = NULL;


	if (ca_file_is_password_protected()) {
		pkey_manage_ask_password (__new_ca_commit_password_cb, ca_creation_data);
		return;
        }

	window = GTK_WINDOW(gtk_builder_get_object (new_ca_window_gtkb, "new_ca_window"));
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));

	creation_process_window_ca_display (ca_creation_data);
	




}





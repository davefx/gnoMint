//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007 David Marín Carreño <davefx@gmail.com>
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

#include <glade/glade.h>
#include <glib-object.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>

#include "ca_creation.h"
#include "ca_policy.h"
#include "new_cert_creation_process.h"
#include "ca_file.h"
#include "tls.h"
#include "ca.h"
#include "pkey_manage.h"

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)
#define D_(x) dgettext ("iso_3166", x)

GladeXML * new_cert_window_xml = NULL;




// NEW CERTIFICATE WINDOW CALLBACKS

void new_cert_window_display(gchar *csr_pem)
{
	gchar     * xml_file = NULL;
	TlsCsr * csr_info = tls_parse_csr_pem (csr_pem);
	GtkWidget * widget;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	// Workaround for libglade
	volatile GType foo = GTK_TYPE_FILE_CHOOSER_WIDGET, tst;
	tst = foo;
	new_cert_window_xml = glade_xml_new (xml_file, "new_cert_window", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (new_cert_window_xml); 	
	
	widget = glade_xml_get_widget (new_cert_window_xml, "c_label");
	gtk_label_set_text (GTK_LABEL(widget), csr_info->c);

	widget = glade_xml_get_widget (new_cert_window_xml, "st_label");
	gtk_label_set_text (GTK_LABEL(widget), csr_info->st);

	widget = glade_xml_get_widget (new_cert_window_xml, "l_label");
	gtk_label_set_text (GTK_LABEL(widget), csr_info->l);

	widget = glade_xml_get_widget (new_cert_window_xml, "o_label");
	gtk_label_set_text (GTK_LABEL(widget), csr_info->o);

	widget = glade_xml_get_widget (new_cert_window_xml, "ou_label");
	gtk_label_set_text (GTK_LABEL(widget), csr_info->ou);

	widget = glade_xml_get_widget (new_cert_window_xml, "cn_label");
	gtk_label_set_text (GTK_LABEL(widget), csr_info->cn);
	
	tls_csr_free (csr_info);

}

void new_cert_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(glade_xml_get_widget (new_cert_window_xml, "new_cert_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

void on_new_cert_next2_clicked (GtkButton *button,
			      gpointer user_data) 
{
	// Whenever gnoMint support more than one CA, here we will
	// have to select the CA for signing the CSR.

	// Meanwhile, we choose the unique CA, and determine its policy.

	guint64 ca_id = atoll("1");

	GtkWidget * widget;
	guint value;
	
	value = ca_policy_get (ca_id, "MONTHS_TO_EXPIRE");
	widget = glade_xml_get_widget (new_cert_window_xml, "months_before_expiration_spinbutton1");
	gtk_spin_button_set_range (GTK_SPIN_BUTTON(widget), 1, value);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON(widget), value);

	value = ca_policy_get (ca_id, "CA");
	widget = glade_xml_get_widget (new_cert_window_xml, "ca_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

/* 	value = ca_policy_get (ca_id, "CERT_SIGN")); */
/* 	widget = glade_xml_get_widget (new_cert_window_xml, "cert_signing_check2"); */
/* 	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value); */

	value = ca_policy_get (ca_id, "CRL_SIGN");
	widget = glade_xml_get_widget (new_cert_window_xml, "crl_signing_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = ca_policy_get (ca_id, "NON_REPUDIATION");
	widget = glade_xml_get_widget (new_cert_window_xml, "non_repudiation_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "DIGITAL_SIGNATURE");
	widget = glade_xml_get_widget (new_cert_window_xml, "digital_signature_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "KEY_ENCIPHERMENT");
	widget = glade_xml_get_widget (new_cert_window_xml, "key_encipherment_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "KEY_AGREEMENT");
	widget = glade_xml_get_widget (new_cert_window_xml, "key_agreement_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "DATA_ENCIPHERMENT");
	widget = glade_xml_get_widget (new_cert_window_xml, "data_encipherment_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "TLS_WEB_SERVER");
	widget = glade_xml_get_widget (new_cert_window_xml, "webserver_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "TLS_WEB_CLIENT");
	widget = glade_xml_get_widget (new_cert_window_xml, "webclient_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "TIME_STAMPING");
	widget = glade_xml_get_widget (new_cert_window_xml, "time_stamping_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "CODE_SIGNING");
	widget = glade_xml_get_widget (new_cert_window_xml, "code_signing_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "EMAIL_PROTECTION");
	widget = glade_xml_get_widget (new_cert_window_xml, "email_protection_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);
	
	value = ca_policy_get (ca_id, "OCSP_SIGNING");
	widget = glade_xml_get_widget (new_cert_window_xml, "ocsp_signing_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	value = ca_policy_get (ca_id, "ANY_PURPOSE");
	widget = glade_xml_get_widget (new_cert_window_xml, "any_purpose_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	gtk_widget_set_sensitive (widget, value);

	
	new_cert_tab_activate (2);
}

void on_new_cert_previous2_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_cert_tab_activate (0);
}

void on_new_cert_next1_clicked (GtkButton *button,
			      gpointer user_data) 
{

	new_cert_tab_activate (1);
}

void on_new_cert_previous3_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_cert_tab_activate (1);
}

void on_new_cert_cancel_clicked (GtkButton *widget,
			       gpointer user_data) 
{
	
	GtkWindow *window = GTK_WINDOW(glade_xml_get_widget (new_cert_window_xml, "new_cert_window"));

	gtk_object_destroy(GTK_OBJECT(window));
	
}

void on_new_cert_commit_clicked (GtkButton *widg,
				 gpointer user_data) 
{
	CertCreationData *cert_creation_data = NULL;
	gchar *csr_pem = NULL;
	
	gchar *certificate;
        gchar *error = NULL;

	GtkWidget *widget = NULL;
	GtkWindow *window = NULL;
	gint active = -1;
	gchar *pem;
	gchar *dn;
	gchar *pkey_pem;
	guint64 ca_id;
	PkeyManageData *crypted_pkey;
	
	time_t tmp;
	struct tm * expiration_time;

	cert_creation_data = g_new0 (CertCreationData, 1);
		
	widget = glade_xml_get_widget (new_cert_window_xml, "months_before_expiration_spinbutton1");
	active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(widget));
	cert_creation_data->key_months_before_expiration = active;

	tmp = time (NULL);	
	cert_creation_data->activation = tmp;
	
	expiration_time = g_new (struct tm,1);
	gmtime_r (&tmp, expiration_time);      
	expiration_time->tm_mon = expiration_time->tm_mon + cert_creation_data->key_months_before_expiration;
	expiration_time->tm_year = expiration_time->tm_year + (expiration_time->tm_mon / 12);
	expiration_time->tm_mon = expiration_time->tm_mon % 12;	
	cert_creation_data->expiration = mktime(expiration_time);
	g_free (expiration_time);

	widget = glade_xml_get_widget (new_cert_window_xml, "ca_check");
	cert_creation_data->ca = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "crl_signing_check");
	cert_creation_data->crl_signing = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "digital_signature_check");
	cert_creation_data->digital_signature = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "data_encipherment_check");
	cert_creation_data->data_encipherment = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "key_encipherment_check");
	cert_creation_data->key_encipherment = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "non_repudiation_check");
	cert_creation_data->non_repudiation = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "key_agreement_check");
	cert_creation_data->key_agreement = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));

	widget = glade_xml_get_widget (new_cert_window_xml, "email_protection_check");
	cert_creation_data->email_protection = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "code_signing_check");
	cert_creation_data->code_signing = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "webclient_check");
	cert_creation_data->web_client = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "webserver_check");
	cert_creation_data->web_server = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "time_stamping_check");
	cert_creation_data->time_stamping = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "ocsp_signing_check");
	cert_creation_data->ocsp_signing = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	widget = glade_xml_get_widget (new_cert_window_xml, "any_purpose_check");
	cert_creation_data->any_purpose = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));



	// Here I am supossing that there's only one CA cert, and its serial is 1.
	// We'll have to remake this when it is possible to hold more than one CA cert in DB.
	ca_id = 1;
	cert_creation_data->serial = ca_file_get_last_serial (ca_id) + 1;
	csr_pem = ca_get_selected_row_pem ();
	pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	crypted_pkey = pkey_manage_get_certificate_pkey (ca_id);
	dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, 1);
					      
	if (pem && crypted_pkey && dn) {
		
		PkeyManageData *csr_pkey = NULL;

		pkey_pem = pkey_manage_uncrypt (crypted_pkey, dn);

		if (! pkey_pem) {
			g_free (pem);
			pkey_manage_data_free (crypted_pkey);
			g_free (dn);
			return;
		}

		error = tls_generate_certificate (cert_creation_data, csr_pem, pem, pkey_pem, &certificate);

		g_free (pkey_pem);
                if (! error) {
		
                        csr_pkey = pkey_manage_get_csr_pkey (ca_get_selected_row_id());
                        
                        if (csr_pkey)
                                if (csr_pkey->is_in_db)
                                        error = ca_file_insert_cert (cert_creation_data, cert_creation_data->ca, csr_pkey->pkey_data, certificate);
                                else
                                        error = ca_file_insert_cert (cert_creation_data, cert_creation_data->ca, csr_pkey->external_file, certificate);			
                        else
                                error = ca_file_insert_cert (cert_creation_data, cert_creation_data->ca, NULL, certificate);
                        
                        if (!error)
                                ca_file_remove_csr (ca_get_selected_row_id());
                        else 
                                ca_error_dialog (error);
                        
                        pkey_manage_data_free (csr_pkey);
		}
	}
		
	g_free (pem);
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	window = GTK_WINDOW(glade_xml_get_widget (new_cert_window_xml, "new_cert_window"));
	gtk_object_destroy(GTK_OBJECT(window));	
	
	ca_refresh_model();
}


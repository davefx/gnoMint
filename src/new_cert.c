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
#include <time.h>
#include <glib/gi18n.h>

#include "ca_file.h"
#include "tls.h"
#include "dialog.h"
#include "pkey_manage.h"
#include "preferences-gui.h"
#include "new_cert.h"
#ifndef GNOMINTCLI
#  include "san_manager.h"
#  include "ca_selector.h"
#endif

#ifndef GNOMINTCLI
GtkBuilder * new_cert_window_gtkb = NULL;
static GtkSingleSelection *new_cert_ca_selection = NULL;
static GListStore *new_cert_ca_root_store = NULL;
#ifndef GNOMINTCLI
GtkWidget *new_cert_san_manager = NULL;  /* SAN editor for issue #40 */
#endif

static void
__new_cert_selection_changed (GObject *sel, GParamSpec *pspec G_GNUC_UNUSED,
                              gpointer user_data G_GNUC_UNUSED)
{
	guint pos = gtk_single_selection_get_selected (GTK_SINGLE_SELECTION (sel));
	gboolean has_sel = (pos != GTK_INVALID_LIST_POSITION);
	gtk_widget_set_sensitive (
	    GTK_WIDGET (gtk_builder_get_object (new_cert_window_gtkb, "new_cert_next2")),
	    has_sel);
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

	object = gtk_builder_get_object (new_cert_window_gtkb, "email_label");
	if (csr_info->emailAddress && csr_info->emailAddress[0]) {
		gtk_label_set_text (GTK_LABEL(object), csr_info->emailAddress);
	} else {
		gtk_label_set_text (GTK_LABEL(object), _("None"));
	}

#ifndef GNOMINTCLI
	/* SAN editor (issue #40): replace the read-only san_label with a
	 * live san_manager_widget pre-populated from the CSR. The
	 * commit handler (on_new_cert_next2_clicked) reads
	 * san_manager_get_string back into cert_creation_data so the
	 * issued certificate carries whatever the CA operator chose,
	 * not just the CSR's request. CLI doesn't have a SAN editor —
	 * the CLI signing path keeps the CSR's SAN verbatim. */
	{
		GtkBuilder *san_builder = gtk_builder_new ();
		gchar *san_ui = g_build_filename (PACKAGE_DATA_DIR, "gnomint",
		                                   "san_manager_widget.ui", NULL);
		gtk_builder_add_from_file (san_builder, san_ui, NULL);
		g_free (san_ui);
		new_cert_san_manager = san_manager_create (san_builder,
		                                            "san_manager_vbox");
		if (new_cert_san_manager) {
			GtkWidget *box = GTK_WIDGET (gtk_builder_get_object (
			    new_cert_window_gtkb, "san_alignment"));
			gtk_box_append(GTK_BOX(box), new_cert_san_manager);
			gtk_widget_set_visible(new_cert_san_manager, TRUE);
			if (csr_info->subject_alt_name && csr_info->subject_alt_name[0])
				san_manager_set_string (new_cert_san_manager,
				                        csr_info->subject_alt_name);
		}
	}
#endif
	
        /* Populate and set up CA selector (GtkColumnView). */
        new_cert_ca_root_store = ca_selector_populate ();
        new_cert_ca_selection = ca_selector_setup (
            GTK_COLUMN_VIEW (gtk_builder_get_object (new_cert_window_gtkb, "signing_ca_treeview")),
            new_cert_ca_root_store, NULL);

        g_signal_connect (new_cert_ca_selection, "notify::selected",
                          G_CALLBACK (__new_cert_selection_changed), NULL);

        if (csr_parent_id) {
                ca_selector_select_by_id (new_cert_ca_selection, atoll (csr_parent_id));
        }

	{
		static const char *bbox_ids[] = {
			"hbuttonbox14", "hbuttonbox3", "hbuttonbox15", NULL
		};
		dialog_notebook_fix_tab_focus (
		    GTK_NOTEBOOK (gtk_builder_get_object (new_cert_window_gtkb, "new_cert_notebook")),
		    bbox_ids, new_cert_window_gtkb);
	}

	gtk_widget_set_visible (
	    GTK_WIDGET (gtk_builder_get_object (new_cert_window_gtkb, "new_cert_window")), TRUE);

	gtk_window_present (GTK_WINDOW (gtk_builder_get_object (new_cert_window_gtkb, "new_cert_window")));
}


void new_cert_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

G_MODULE_EXPORT void on_new_cert_next2_clicked (GtkButton *button,
			      gpointer user_data)
{
	GObject * object;
	guint i_value;
	guint64 ca_id;
        const gchar *ca_pem;
        TlsCert *tls_ca_cert = NULL;
        TlsCsr * tls_csr = g_object_get_data (G_OBJECT(gtk_builder_get_object(new_cert_window_gtkb, "new_cert_window")), "csr_info");

	GnomintCertRow *sel_row = ca_selector_get_selected_row (new_cert_ca_selection);
	if (!sel_row)
		return;
	ca_id = gnomint_cert_row_get_id (sel_row);
	ca_pem = gnomint_cert_row_get_pem (sel_row);
	tls_ca_cert = tls_parse_cert_pem (ca_pem);
	g_object_unref (sel_row);
	
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
        gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(window)));	
	
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

static void
__new_cert_commit_done_cb (const gchar *error, gpointer user_data)
{
	(void) user_data;
	if (error) {
		dialog_error ((gchar *) error);
	}
	dialog_refresh_list ();
}

G_MODULE_EXPORT void on_new_cert_commit_clicked (GtkButton *widg,
				 gpointer user_data)
{
	TlsCertCreationData *cert_creation_data = NULL;

	GObject *widget = NULL;
	gint active = -1;
	guint64 ca_id;
	gchar * csr_id_str = g_object_get_data (G_OBJECT(gtk_builder_get_object(new_cert_window_gtkb, "new_cert_window")), "csr_id");
	guint64 csr_id = atoll(csr_id_str);

	ca_id = ca_selector_get_selected_id (new_cert_ca_selection);
	if (ca_id == 0)
		return;

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

	// SANs will be copied from the CSR by default
#ifndef GNOMINTCLI
	/* SAN editor (issue #40): read the (possibly-edited) SAN list back
	 * from the manager widget. The empty string also means none, and
	 * we normalise to NULL so the downstream tls_generate_certificate
	 * path takes the no-SAN branch. */
	if (new_cert_san_manager) {
		gchar *edited_san = san_manager_get_string (new_cert_san_manager);
		if (edited_san && *edited_san) {
			cert_creation_data->subject_alt_name = edited_san;
		} else {
			g_free (edited_san);
			cert_creation_data->subject_alt_name = NULL;
		}
	} else {
		cert_creation_data->subject_alt_name = NULL;
	}
#else
	cert_creation_data->subject_alt_name = NULL;
#endif

	widget = G_OBJECT(gtk_builder_get_object (new_cert_window_gtkb, "new_cert_window"));
        gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(widget)));

	new_cert_sign_csr (csr_id, ca_id, cert_creation_data,
	                   __new_cert_commit_done_cb, NULL);

}
#endif

/* Shared helper: given the decrypted CA private key, generate and insert the cert. */
static const gchar *
__new_cert_sign_with_pkey (guint64 csr_id, guint64 ca_id,
                           TlsCertCreationData *cert_creation_data,
                           gchar *csr_pem, gchar *pem,
                           gchar *pkey_pem)
{
	gchar *certificate = NULL;
	gchar *error = NULL;
	PkeyManageData *csr_pkey = NULL;

	TlsCert *ca_cert = tls_parse_cert_pem (pem);

	if (cert_creation_data->expiration > ca_cert->expiration_time) {
		dialog_info (_("The expiration date of the new certificate is after the expiration date of the CA certificate.\n\n"
			       "According to the current standards, this is not allowed. The new certificate will be created with the same "
			       "expiration date as the CA certificate."));
		cert_creation_data->expiration = ca_cert->expiration_time;
	}

	tls_cert_free (ca_cert);

	error = tls_generate_certificate (cert_creation_data, csr_pem, pem, pkey_pem, &certificate);

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

	if (!error && preferences_get_gnome_keyring_export()) {
		TlsCert * cert = NULL;
		gchar *filename = NULL;
		gchar *directory = NULL;
		gchar *aux = NULL;
		cert = tls_parse_cert_pem (certificate);

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

	return error;
}

static void
__new_cert_prepare_expiration (TlsCertCreationData *cert_creation_data)
{
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
}

#ifdef GNOMINTCLI

const gchar *new_cert_sign_csr (guint64 csr_id, guint64 ca_id, TlsCertCreationData *cert_creation_data)
{
	gchar *csr_pem = NULL;
	gchar *pem = NULL;
	gchar *dn = NULL;
	gchar *pkey_pem = NULL;
	PkeyManageData *crypted_pkey = NULL;
	const gchar *error = NULL;

	__new_cert_prepare_expiration (cert_creation_data);
	ca_file_get_next_serial (&cert_creation_data->serial, ca_id);

	csr_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CSR, csr_id);
	pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	crypted_pkey = pkey_manage_get_certificate_pkey (ca_id);
	dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);

	if (pem && crypted_pkey && dn) {
		pkey_pem = pkey_manage_uncrypt (crypted_pkey, dn);

		if (! pkey_pem) {
			g_free (pem);
			pkey_manage_data_free (crypted_pkey);
			g_free (dn);
			return (_("Error while signing CSR."));
		}

		error = __new_cert_sign_with_pkey (csr_id, ca_id, cert_creation_data,
		                                    csr_pem, pem, pkey_pem);
		g_free (pkey_pem);
	}

	g_free (pem);
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	return error;
}

#else /* GUI async new_cert_sign_csr */

typedef struct {
	guint64                 csr_id;
	guint64                 ca_id;
	TlsCertCreationData    *cert_creation_data;
	gchar                  *csr_pem;
	gchar                  *pem;
	gchar                  *dn;
	PkeyManageData         *crypted_pkey;
	NewCertSignCsrCallback  cb;
	gpointer                cb_user_data;
} _NewCertSignCtx;

static void
_new_cert_sign_uncrypt_cb (gchar *pkey_pem, gpointer data)
{
	_NewCertSignCtx *ctx = (_NewCertSignCtx *) data;
	const gchar *error = NULL;

	if (! pkey_pem) {
		g_free (ctx->pem);
		pkey_manage_data_free (ctx->crypted_pkey);
		g_free (ctx->dn);
		ctx->cb (_("Error while signing CSR."), ctx->cb_user_data);
		g_free (ctx);
		return;
	}

	error = __new_cert_sign_with_pkey (ctx->csr_id, ctx->ca_id,
	                                    ctx->cert_creation_data,
	                                    ctx->csr_pem, ctx->pem, pkey_pem);
	g_free (pkey_pem);

	g_free (ctx->pem);
	pkey_manage_data_free (ctx->crypted_pkey);
	g_free (ctx->dn);

	ctx->cb (error, ctx->cb_user_data);
	g_free (ctx);
}

static void
_new_cert_sign_got_pkey_cb (PkeyManageData *crypted_pkey, gpointer data)
{
	_NewCertSignCtx *ctx = (_NewCertSignCtx *) data;

	ctx->crypted_pkey = crypted_pkey;

	if (!ctx->pem || !crypted_pkey || !ctx->dn) {
		g_free (ctx->pem);
		pkey_manage_data_free (crypted_pkey);
		g_free (ctx->dn);
		ctx->cb (_("Error while signing CSR."), ctx->cb_user_data);
		g_free (ctx);
		return;
	}

	pkey_manage_uncrypt (crypted_pkey, ctx->dn,
	                     _new_cert_sign_uncrypt_cb, ctx);
}

void new_cert_sign_csr (guint64 csr_id, guint64 ca_id,
                        TlsCertCreationData *cert_creation_data,
                        NewCertSignCsrCallback cb, gpointer user_data)
{
	_NewCertSignCtx *ctx;

	__new_cert_prepare_expiration (cert_creation_data);
	ca_file_get_next_serial (&cert_creation_data->serial, ca_id);

	ctx = g_new0 (_NewCertSignCtx, 1);
	ctx->csr_id = csr_id;
	ctx->ca_id = ca_id;
	ctx->cert_creation_data = cert_creation_data;
	ctx->csr_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CSR, csr_id);
	ctx->pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	ctx->dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
	ctx->cb = cb;
	ctx->cb_user_data = user_data;

	pkey_manage_get_certificate_pkey (ca_id, _new_cert_sign_got_pkey_cb, ctx);
}

#endif /* GNOMINTCLI */


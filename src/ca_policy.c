//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007,2008 David Marín Carreño <davefx@gmail.com>
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

#include <glade/glade.h>
#include <glib-object.h>
#include <gtk/gtk.h>

#else

#include <glib.h>

#endif

#include <glib/gi18n.h>
#include <stdlib.h>
#include <string.h>
#include <ca_file.h> 

#include "tls.h"
#include "ca_policy.h"


#ifndef GNOMINTCLI

extern GladeXML * certificate_properties_window_xml;

gint __ca_policy_populate_step (void *pArg, int argc, char **argv, char **columnNames);

gint __ca_policy_populate_step (void *pArg, int argc, char **argv, char **columnNames)
{
	GHashTable * policy_table = (GHashTable *) pArg;

	g_hash_table_insert (policy_table, g_strdup (argv[1]), GINT_TO_POINTER(atoi(argv[2])));

	return 0;
}

void ca_policy_populate (guint64 ca_id) 
{
	GtkWidget * widget;
	gint value;
	GHashTable *policy_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);	

	ca_file_foreach_policy (__ca_policy_populate_step, ca_id, policy_table);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "C_INHERIT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "country_inherited_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "country_same_radiobutton"), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "country_differ_radiobutton"), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "ST_INHERIT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "state_inherited_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "state_same_radiobutton"), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "state_differ_radiobutton"), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "L_INHERIT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "city_inherited_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "city_same_radiobutton"), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "city_differ_radiobutton"), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "O_INHERIT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "organization_inherited_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "organization_same_radiobutton"), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "organization_differ_radiobutton"), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "OU_INHERIT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "ou_inherited_check");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "ou_same_radiobutton"), value);
        gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "ou_differ_radiobutton"), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "C_FORCE_SAME"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "country_same_radiobutton");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "ST_FORCE_SAME"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "state_same_radiobutton");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "L_FORCE_SAME"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "city_same_radiobutton");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "O_FORCE_SAME"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "organization_same_radiobutton");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

        value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "OU_FORCE_SAME"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "ou_same_radiobutton");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "HOURS_BETWEEN_CRL_UPDATES"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "hours_between_crl_updates_spinbutton");
	gtk_spin_button_set_value (GTK_SPIN_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "MONTHS_TO_EXPIRE"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "months_before_expiration_spinbutton2");
	gtk_spin_button_set_value (GTK_SPIN_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "CA"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "ca_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "CRL_SIGN"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "crl_signing_check1");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "NON_REPUDIATION"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "non_repudiation_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "DIGITAL_SIGNATURE"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "digital_signature_check4");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "KEY_ENCIPHERMENT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "key_encipherment_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "KEY_AGREEMENT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "key_agreement_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "DATA_ENCIPHERMENT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "data_encipherment_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "TLS_WEB_SERVER"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "webserver_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "TLS_WEB_CLIENT"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "webclient_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "TIME_STAMPING"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "time_stamping_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "CODE_SIGNING"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "code_signing_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "EMAIL_PROTECTION"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "email_protection_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	
	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "OCSP_SIGNING"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "ocsp_signing_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "ANY_PURPOSE"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "any_purpose_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);
	
        g_hash_table_destroy (policy_table);
}

#endif

guint ca_policy_get (guint64 ca_id, gchar *property_name)
{
	return ca_file_policy_get (ca_id, property_name);
}


void ca_policy_set (guint64 ca_id, gchar *property_name, guint value)
{
	ca_file_policy_set (ca_id, property_name, value);

}

#ifndef GNOMINTCLI

void ca_policy_expiration_spin_button_change (gpointer spin_button, gpointer userdata)
{
	GtkWidget * widget = glade_xml_get_widget (certificate_properties_window_xml, "certificate_properties_dialog");
	gchar * cert_id_str = (gchar *) g_object_get_data (G_OBJECT(widget), "cert_id");
	guint64 cert_id;
 
	if (! cert_id_str)
		return;

	if (! spin_button)
		return;

	cert_id = atoll(cert_id_str);

	ca_policy_set (cert_id, "MONTHS_TO_EXPIRE", gtk_spin_button_get_value(spin_button));

}

void ca_policy_crl_update_spin_button_change (gpointer spin_button, gpointer userdata)
{
	GtkWidget * widget = glade_xml_get_widget (certificate_properties_window_xml, "certificate_properties_dialog");
	gchar * cert_id_str = (gchar *) g_object_get_data (G_OBJECT(widget), "cert_id");
	guint64 cert_id;

	if (! cert_id_str)
		return;

	if (! spin_button)
		return;

	cert_id = atoll(cert_id_str);

	ca_policy_set (cert_id, "HOURS_BETWEEN_CRL_UPDATES", gtk_spin_button_get_value(spin_button));

}


void ca_policy_toggle_button_toggled (gpointer button, gpointer userdata)
{
	GtkWidget * widget = glade_xml_get_widget (certificate_properties_window_xml, "certificate_properties_dialog");
	gchar * cert_id_str = (gchar *) g_object_get_data (G_OBJECT(widget), "cert_id");
	guint64 cert_id;

	gchar *property_name = NULL;
        gboolean is_active;
	
	if (! cert_id_str)
		return;

	if (! button)
		return;

	cert_id = atoll(cert_id_str);
	
        is_active = gtk_toggle_button_get_active(button);

	if (! strcmp(glade_get_widget_name (button), "country_inherited_check")) {
		property_name = "C_INHERIT";
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "country_same_radiobutton"), is_active);
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "country_differ_radiobutton"), is_active);
        }
        
	if (! strcmp(glade_get_widget_name (button), "state_inherited_check")) {
		property_name = "ST_INHERIT";        
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "state_same_radiobutton"), is_active);
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "state_differ_radiobutton"), is_active);
        } 

	if (! strcmp(glade_get_widget_name (button), "city_inherited_check")) {
		property_name = "L_INHERIT";        
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "city_same_radiobutton"), is_active);
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "city_differ_radiobutton"), is_active);
        }

	if (! strcmp(glade_get_widget_name (button), "organization_inherited_check")) {
		property_name = "O_INHERIT";   
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "organization_same_radiobutton"), is_active);
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "organization_differ_radiobutton"), is_active);
        }

	if (! strcmp(glade_get_widget_name (button), "ou_inherited_check")) {
		property_name = "OU_INHERIT";        
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "ou_same_radiobutton"), is_active);
                gtk_widget_set_sensitive (glade_xml_get_widget (certificate_properties_window_xml, "ou_differ_radiobutton"), is_active);
        }

	if (! strcmp(glade_get_widget_name (button), "country_same_radiobutton"))
		property_name = "C_FORCE_SAME";        
        

	if (! strcmp(glade_get_widget_name (button), "state_same_radiobutton"))
		property_name = "ST_FORCE_SAME";        

	if (! strcmp(glade_get_widget_name (button), "city_same_radiobutton"))
		property_name = "L_FORCE_SAME";        

	if (! strcmp(glade_get_widget_name (button), "organization_same_radiobutton"))
		property_name = "O_FORCE_SAME";        

	if (! strcmp(glade_get_widget_name (button), "ou_same_radiobutton"))
		property_name = "OU_FORCE_SAME";        

	



	if (! strcmp(glade_get_widget_name (button), "ca_check2"))
		property_name = "CA";

	if (! strcmp(glade_get_widget_name (button), "crl_signing_check1"))
		property_name = "CRL_SIGN";
		
	if (! strcmp(glade_get_widget_name (button), "non_repudiation_check2")) {
                if (! is_active) {
                        // TIME_STAMPING cannot be inactive
                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                              "time_stamping_check2")), FALSE);
                        // We must check if EMAIL_PROTECTION can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE") &&
                            ! ca_policy_get (cert_id, "KEY_ENCIPHERMENT") &&
                            ! ca_policy_get (cert_id, "KEY_AGREEMENT")) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml,
                                                                                                      "email_protection_check2")), FALSE);
                        }

                        // We must check if OCSP_SIGNING can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE")) {
                                // If is not active, we must deactivate OCSP_SIGNING
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml,
                                                                                                      "ocsp_signing_check2")), FALSE);
                        }
                        
                }
		property_name = "NON_REPUDIATION";
        }
		
	if (! strcmp(glade_get_widget_name (button), "digital_signature_check4")) {
                if (! is_active) {
                        // We must check if TLS_WEB_SERVER can be active
                        if (! ca_policy_get (cert_id, "KEY_ENCIPHERMENT") &&
                            ! ca_policy_get (cert_id, "KEY_AGREEMENT")) {
                                // If none is active, we must deactivate TLS_WEB_SERVER
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "webserver_check2")), FALSE);
                        }

                        // We must check if TLS_WEB_CLIENT can be active
                        if (! ca_policy_get (cert_id, "KEY_AGREEMENT")) {
                                // If none is active, we must deactivate TLS_WEB_CLIENT
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "webclient_check2")), FALSE);
                        }

                        // TIME_STAMPING and CODE_SIGNING cannot be active if digital signature is deactivated
                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget(certificate_properties_window_xml,
                                                                                             "time_stamping_check2")), FALSE);

                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget(certificate_properties_window_xml,
                                                                                             "code_signing_check2")), FALSE);

                        // We must check if EMAIL_PROTECTION can be active
                        if (! ca_policy_get (cert_id, "NON_REPUDIATION") &&
                            ! ca_policy_get (cert_id, "KEY_ENCIPHERMENT") &&
                            ! ca_policy_get (cert_id, "KEY_AGREEMENT")) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "email_protection_check2")), FALSE);
                        }

                        // We must check if OCSP_SIGNING can be active
                        if (! ca_policy_get (cert_id, "NON_REPUDIATION")) {
                                // If none is active, we must deactivate OCSP_SIGNING
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "ocsp_signing_check2")), FALSE);
                        }


                }
		property_name = "DIGITAL_SIGNATURE";
        }
		
	if (! strcmp(glade_get_widget_name (button), "key_encipherment_check2")) {
                if (! is_active) {
                        // We must check if TLS_WEB_SERVER can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE") &&
                            ! ca_policy_get (cert_id, "KEY_AGREEMENT")) {
                                // If none is active, we must deactivate TLS_WEB_SERVER
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "webserver_check2")), FALSE);
                        }

                        // We must check if EMAIL_PROTECTION can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE") &&
                            ! ca_policy_get (cert_id, "NON_REPUDIATION") &&
                            ! ca_policy_get (cert_id, "KEY_AGREEMENT")) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "email_protection_check2")), FALSE);
                        }


                }
		property_name = "KEY_ENCIPHERMENT";		
        }

	if (! strcmp(glade_get_widget_name (button), "key_agreement_check2")) {
                if (! is_active) {
                        // We must check if TLS_WEB_SERVER can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE") &&
                            ! ca_policy_get (cert_id, "KEY_ENCIPHERMENT")) {
                                // If none is active, we must deactivate TLS_WEB_SERVER
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "webserver_check2")), FALSE);
                        }
                        // We must check if TLS_WEB_CLIENT can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE")) {
                                // If none is active, we must deactivate TLS_WEB_CLIENT
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "webclient_check2")), FALSE);
                        }

                        // We must check if EMAIL_PROTECTION can be active
                        if (! ca_policy_get (cert_id, "DIGITAL_SIGNATURE") &&
                            ! ca_policy_get (cert_id, "NON_REPUDIATION") &&
                            ! ca_policy_get (cert_id, "KEY_ENCIPHERMENT")) {
                                // If none is active, we must deactivate EMAIL_PROTECTION
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "email_protection_check2")), FALSE);
                        }
                }

		property_name = "KEY_AGREEMENT";
        }

		
	if (! strcmp(glade_get_widget_name (button), "data_encipherment_check2"))
		property_name = "DATA_ENCIPHERMENT";





        // Purposes


	if (! strcmp(glade_get_widget_name (button), "webserver_check2")) {
                if (is_active) {
                        // We must check digitalSignature || keyEncipherment || keyAgreement
                        if (!( ca_policy_get (cert_id, "DIGITAL_SIGNATURE") ||
                               ca_policy_get (cert_id, "KEY_ENCIPHERMENT") ||
                               ca_policy_get (cert_id, "KEY_AGREEMENT"))) {
                                // If none is active, we activate key encipherment
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "key_encipherment_check2")), TRUE);
                        }
                               
                }
                property_name = "TLS_WEB_SERVER";
        }

	if (! strcmp(glade_get_widget_name (button), "webclient_check2")) {
                if (is_active) {
                        // We must check digitalSignature || keyEncipherment || keyAgreement
                        if (!( ca_policy_get (cert_id, "DIGITAL_SIGNATURE") ||
                               ca_policy_get (cert_id, "KEY_AGREEMENT"))) {
                                // If none is active, we activate digital signature
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "digital_signature_check4")), TRUE);
                        }
                        
                }
                property_name = "TLS_WEB_CLIENT";
        }

	if (! strcmp(glade_get_widget_name (button), "time_stamping_check2")){
                if (is_active) {
                        // We must check digitalSignature && nonRepudiation
                        if (!( ca_policy_get (cert_id, "DIGITAL_SIGNATURE") &&
                               ca_policy_get (cert_id, "NON_REPUDIATION"))) {
                                // If none is active, we activate them both
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "digital_signature_check4")), TRUE);
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "non_repudiation_check2")), TRUE);
                        }
                               
                }
		property_name = "TIME_STAMPING";
        }

	if (! strcmp(glade_get_widget_name (button), "code_signing_check2")) {
                if (is_active) {
                        // We must check digitalSignature
                        if (!( ca_policy_get (cert_id, "DIGITAL_SIGNATURE"))) {
                                // If it is not active, we activate it
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "digital_signature_check4")), TRUE);
                        }
                        
                }
		property_name = "CODE_SIGNING";
        }

	if (! strcmp(glade_get_widget_name (button), "email_protection_check2")) {
                if (is_active) {
                        // We must check digitalSignature || nonRepudiation || (keyEncipherment || keyAgreement)
                        if (!( ca_policy_get (cert_id, "DIGITAL_SIGNATURE") ||
                               ca_policy_get (cert_id, "NON_REPUDIATION") ||
                               ca_policy_get (cert_id, "KEY_ENCIPHERMENT") ||
                               ca_policy_get (cert_id, "KEY_AGREEMENT"))) {
                                // If none is active, we activate key encipherment
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "digital_signature_check4")), TRUE);
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "key_encipherment_check2")), TRUE);
                        }
                               
                }
  		property_name = "EMAIL_PROTECTION";
        }

	if (! strcmp(glade_get_widget_name (button), "ocsp_signing_check2")) {
                if (is_active) {
                        // We must check digitalSignature || nonRepudiation
                        if (!( ca_policy_get (cert_id, "DIGITAL_SIGNATURE") ||
                               ca_policy_get (cert_id, "NON_REPUDIATION"))) {
                                // If none is active, we activate digital signature
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget (certificate_properties_window_xml, 
                                                                                                      "digital_signature_check4")), TRUE);
                        }
                               
                }
		property_name = "OCSP_SIGNING";
        }

	if (! strcmp(glade_get_widget_name (button), "any_purpose_check2"))
		property_name = "ANY_PURPOSE";

	if (property_name)
		ca_policy_set (cert_id, property_name, is_active);

}

#endif


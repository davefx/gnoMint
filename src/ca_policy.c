//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007 David Marín Carreño <davefx@gmail.com>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or   
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
#include <sqlite3.h>
#include <ca_file.h> 

#include "tls.h"


#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

extern sqlite3 * ca_db;
extern GladeXML * certificate_properties_window_xml;

gint __ca_policy_populate_step (void *pArg, int argc, char **argv, char **columnNames)
{
	GHashTable * policy_table = (GHashTable *) pArg;

	g_hash_table_insert (policy_table, g_strdup (argv[1]), GINT_TO_POINTER(atoi(argv[2])));

	return 0;
}

void ca_policy_populate (guint64 ca_id) 
{
	gchar * error_str;
	GtkWidget * widget;
	gint value;
	GHashTable *policy_table = g_hash_table_new (g_str_hash, g_str_equal);	

	gchar * query = g_strdup_printf ("SELECT ca_id, name, value FROM ca_policies WHERE ca_id=%"
					 G_GUINT64_FORMAT ";", ca_id);

	sqlite3_exec (ca_db, query,
		      __ca_policy_populate_step, policy_table, &error_str);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "MONTHS_TO_EXPIRE"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "months_before_expiration_spinbutton2");
	gtk_spin_button_set_value (GTK_SPIN_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "CA"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "ca_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "CERT_SIGN"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "cert_signing_check2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), value);

	value = GPOINTER_TO_INT (g_hash_table_lookup (policy_table, "CRL_SIGN"));
	widget = glade_xml_get_widget (certificate_properties_window_xml, "crl_signing_check5");
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
	

}


guint ca_policy_get (guint64 ca_id, gchar *property_name)
{
	gchar **row = ca_file_get_single_row ("SELECT value FROM ca_policies WHERE name='%s' AND ca_id=%llu ;", 
					      property_name, ca_id);

	if (!row)
		return 0;

	return atoi(row[0]);
}


void ca_policy_set (guint64 ca_id, gchar *property_name, guint value)
{

	if (! ca_file_get_single_row ("SELECT id, ca_id, name, value FROM ca_policies WHERE name='%s' AND ca_id=%llu ;", 
				      property_name, ca_id))
		ca_file_get_single_row ("INSERT INTO ca_policies(ca_id, name, value) VALUES (%llu, '%s', %d);",
					ca_id, property_name, value);
	else
		ca_file_get_single_row ("UPDATE ca_policies SET value=%d WHERE ca_id=%llu AND name='%s';",
					value, ca_id, property_name);
		
}


void ca_policy_spin_button_change (gpointer spin_button, gpointer userdata)
{
	guint64 serial_number;
	GtkWidget * widget = glade_xml_get_widget (certificate_properties_window_xml, "certificate_properties_dialog");
	gchar * cert_serial_number = (gchar *) g_object_get_data (G_OBJECT(widget), "cert_serial_number");

	if (! cert_serial_number)
		return;

	if (! spin_button)
		return;


	serial_number = atoll (cert_serial_number);

	
	ca_policy_set (serial_number, "MONTHS_TO_EXPIRE", gtk_spin_button_get_value(spin_button));

}


void ca_policy_toggle_button_toggled (gpointer button, gpointer userdata)
{
	guint64 serial_number;
	GtkWidget * widget = glade_xml_get_widget (certificate_properties_window_xml, "certificate_properties_dialog");
	gchar * cert_serial_number = (gchar *) g_object_get_data (G_OBJECT(widget), "cert_serial_number");

	gchar *property_name = NULL;
	
	if (! cert_serial_number)
		return;

	if (! button)
		return;
	
	serial_number = atoll (cert_serial_number);
	
	if (! strcmp(glade_get_widget_name (button), "ca_check2"))
		property_name = "CA";
		
	if (! strcmp(glade_get_widget_name (button), "cert_signing_check2"))
		property_name = "CERT_SIGN";
		
	if (! strcmp(glade_get_widget_name (button), "crl_signing_check5"))
		property_name = "CRL_SIGN";
		
	if (! strcmp(glade_get_widget_name (button), "non_repudiation_check2"))
		property_name = "NON_REPUDIATION";
		
	if (! strcmp(glade_get_widget_name (button), "digital_signature_check4"))
		property_name = "DIGITAL_SIGNATURE";
		
	if (! strcmp(glade_get_widget_name (button), "key_encipherment_check2"))
		property_name = "KEY_ENCIPHERMENT";
		
	if (! strcmp(glade_get_widget_name (button), "key_agreement_check2"))
		property_name = "KEY_AGREEMENT";
		
	if (! strcmp(glade_get_widget_name (button), "data_encipherment_check2"))
		property_name = "DATA_ENCIPHERMENT";

	if (! strcmp(glade_get_widget_name (button), "webserver_check2"))
		property_name = "TLS_WEB_SERVER";

	if (! strcmp(glade_get_widget_name (button), "webclient_check2"))
		property_name = "TLS_WEB_CLIENT";

	if (! strcmp(glade_get_widget_name (button), "time_stamping_check2"))
		property_name = "TIME_STAMPING";

	if (! strcmp(glade_get_widget_name (button), "code_signing_check2"))
		property_name = "CODE_SIGNING";

	if (! strcmp(glade_get_widget_name (button), "email_protection_check2"))
		property_name = "EMAIL_PROTECTION";

	if (! strcmp(glade_get_widget_name (button), "ocsp_signing_check2"))
		property_name = "OCSP_SIGNING";

	if (! strcmp(glade_get_widget_name (button), "any_purpose_check2"))
		property_name = "ANY_PURPOSE";

	if (property_name)
		ca_policy_set (serial_number, property_name, gtk_toggle_button_get_active(button));

}




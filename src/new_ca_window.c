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

#include <glade/glade.h>
#include <glib-object.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>

#include "ca_policy.h"
#include "new_ca_window.h"
#include "creation_process_window.h"
#include "ca_file.h"
#include "tls.h"
#include "pkey_manage.h"

#include <glib/gi18n.h>
#define D_(x) dgettext ("iso_3166", x)

typedef struct {
	char * name;
	char * code;
} CountryItem;

#define NUMBER_OF_COUNTRIES 244
CountryItem country_table[NUMBER_OF_COUNTRIES];


GladeXML * new_ca_window_xml = NULL;


void new_ca_window_display()
{
	gchar     * xml_file = NULL;
	// Workaround for libglade
	volatile GType foo = GTK_TYPE_FILE_CHOOSER_WIDGET, tst;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	tst = foo;
	new_ca_window_xml = glade_xml_new (xml_file, "new_ca_window", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (new_ca_window_xml); 	
	
	new_ca_populate_country_combobox(GTK_COMBO_BOX(glade_xml_get_widget(new_ca_window_xml, "country_combobox")));

}

static int comp_countries(const void *m1, const void *m2) {
	CountryItem *mi1 = (CountryItem *) m1;
	CountryItem *mi2 = (CountryItem *) m2;
	return g_ascii_strcasecmp (mi1->name, mi2->name);
}


// TAB Manage

void new_ca_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(glade_xml_get_widget (new_ca_window_xml, "new_ca_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

void on_cn_entry_changed (GtkEditable *editable,
			 gpointer user_data) 
{
	GtkButton *button = GTK_BUTTON(glade_xml_get_widget (new_ca_window_xml, "new_ca_next1"));

	if (strlen (gtk_entry_get_text (GTK_ENTRY(editable)))) 
		gtk_widget_set_sensitive (GTK_WIDGET(button), TRUE);
	else
		gtk_widget_set_sensitive (GTK_WIDGET(button), FALSE);
		
}

void on_new_ca_next1_clicked (GtkButton *widget,
			      gpointer user_data) 
{
	new_ca_tab_activate (1);
}

void on_new_ca_previous2_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_ca_tab_activate (0);
}

void on_new_ca_next2_clicked (GtkButton *widget,
			      gpointer user_data) 
{
	new_ca_tab_activate (2);
}

void on_new_ca_previous3_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_ca_tab_activate (1);
}

void on_new_ca_cancel_clicked (GtkButton *widget,
			       gpointer user_data) 
{
	
	GtkWindow *window = GTK_WINDOW(glade_xml_get_widget (new_ca_window_xml, "new_ca_window"));

	gtk_object_destroy(GTK_OBJECT(window));
	
}


void on_new_ca_pwd_entry_changed (GtkEntry *entry,
				       gpointer user_data)
{
	const gchar *text1;
	const gchar *text2;
	
	GtkEntry *pwd_entry_1 = GTK_ENTRY(glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_entry_1"));
	GtkEntry *pwd_entry_2 = GTK_ENTRY(glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_entry_2"));
	GtkButton *commit_button = GTK_BUTTON(glade_xml_get_widget (new_ca_window_xml, "new_ca_commit"));

	text1 = gtk_entry_get_text (pwd_entry_1);
	text2 = gtk_entry_get_text (pwd_entry_2);

	if (strlen(text1) && strlen(text2) && ! strcmp(text1, text2)) {
		gtk_widget_set_sensitive (GTK_WIDGET(commit_button), TRUE);		
	} else {
		gtk_widget_set_sensitive (GTK_WIDGET(commit_button), FALSE);		
	}

}


void on_new_ca_pwd_protect_radiobutton_toggled (GtkRadioButton *radiobutton, 
						     gpointer user_data)
{
	GtkRadioButton *yes = GTK_RADIO_BUTTON(glade_xml_get_widget (new_ca_window_xml, 
								     "new_ca_pwd_protect_yes_radiobutton"));
	GtkLabel *pwd_label_1 = GTK_LABEL(glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_label_1"));
	GtkLabel *pwd_label_2 = GTK_LABEL(glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_label_2"));
	GtkEntry *pwd_entry_1 = GTK_ENTRY(glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_entry_1"));
	GtkEntry *pwd_entry_2 = GTK_ENTRY(glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_entry_2"));
	GtkButton *commit_button = GTK_BUTTON(glade_xml_get_widget (new_ca_window_xml, "new_ca_commit"));

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(yes))) {
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


void on_new_ca_commit_clicked (GtkButton *widg,
			       gpointer user_data) 
{
	TlsCreationData *ca_creation_data = NULL;

	GtkWidget *widget = NULL;
	GtkWindow *window = NULL;
	gint active = -1;
	gchar *text = NULL;
	GtkTreeModel *tree_model = NULL;
	GtkTreeIter tree_iter;
	
	time_t tmp;
	struct tm * expiration_time;

	ca_creation_data = g_new0 (TlsCreationData, 1);
	widget = glade_xml_get_widget (new_ca_window_xml, "country_combobox");
	active = gtk_combo_box_get_active (GTK_COMBO_BOX(widget));

	if (active < 0) {
			ca_creation_data->country = NULL;
	} else {
		tree_model = gtk_combo_box_get_model (GTK_COMBO_BOX(widget));
		gtk_combo_box_get_active_iter (GTK_COMBO_BOX(widget), &tree_iter);
		gtk_tree_model_get (tree_model, &tree_iter, 1, &text, -1);

		ca_creation_data->country = g_strdup (text);
		g_free (text);
	}
		
	widget = glade_xml_get_widget (new_ca_window_xml, "st_entry");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		ca_creation_data->state = g_strdup (text);
	else
		ca_creation_data->state = NULL;

	widget = glade_xml_get_widget (new_ca_window_xml, "city_entry");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		ca_creation_data->city = g_strdup (text);
	else
		ca_creation_data->city = NULL;

	widget = glade_xml_get_widget (new_ca_window_xml, "o_entry");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		ca_creation_data->org = g_strdup (text);
	else
		ca_creation_data->org = NULL;

	widget = glade_xml_get_widget (new_ca_window_xml, "ou_entry");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		ca_creation_data->ou = g_strdup (text);
	else
		ca_creation_data->ou = NULL;

	widget = glade_xml_get_widget (new_ca_window_xml, "cn_entry");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		ca_creation_data->cn = g_strdup (text);
	else
		ca_creation_data->cn = NULL;

	widget = glade_xml_get_widget (new_ca_window_xml, "dsa_radiobutton");
	active = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	ca_creation_data->key_type = active;

	widget = glade_xml_get_widget (new_ca_window_xml, "keylength_spinbutton");
	active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(widget));
	ca_creation_data->key_bitlength = active;

	widget = glade_xml_get_widget (new_ca_window_xml, "months_before_expiration_spinbutton");
	active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(widget));
	ca_creation_data->key_months_before_expiration = active;

	tmp = time (NULL);	
	ca_creation_data->activation = tmp;
	
	expiration_time = g_new (struct tm,1);
	localtime_r (&tmp, expiration_time);      
	expiration_time->tm_mon = expiration_time->tm_mon + ca_creation_data->key_months_before_expiration;
	expiration_time->tm_year = expiration_time->tm_year + (expiration_time->tm_mon / 12);
	expiration_time->tm_mon = expiration_time->tm_mon % 12;	
	ca_creation_data->expiration = mktime(expiration_time);
	g_free (expiration_time);


	/* widget = glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_protect_yes_radiobutton"); */
	/* active = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget)); */
	/* ca_creation_data->is_pwd_protected = active; */

	/* if (active) { */
	/* 	widget = glade_xml_get_widget (new_ca_window_xml, "new_ca_pwd_entry_1"); */
	/* 	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget)); */
	/* 	if (strlen (text)) */
	/* 		ca_creation_data->password = g_strdup (text); */
	/* 	else */
	/* 		ca_creation_data->password = NULL; */
	/* } */


	if (ca_file_is_password_protected()) {
		ca_creation_data->password = pkey_manage_ask_password();

                if (! ca_creation_data->password) {
                        /* The user hasn't provided a valid password */
                        return;
                }

        }

	window = GTK_WINDOW(glade_xml_get_widget (new_ca_window_xml, "new_ca_window"));
	gtk_object_destroy(GTK_OBJECT(window));

	creation_process_window_ca_display (ca_creation_data);
	




}



void populate_country_table()
{
	int i = 0;

	country_table[i].name = D_("Afghanistan");
	country_table[i++].code = "AF";
	country_table[i].name = D_("Åland Islands");
	country_table[i++].code = "AX";
	country_table[i].name = D_("Albania");
	country_table[i++].code = "AL";
	country_table[i].name = D_("Algeria");
	country_table[i++].code = "DZ";
	country_table[i].name = D_("American Samoa");
	country_table[i++].code = "AS";
	country_table[i].name = D_("Andorra");
	country_table[i++].code = "AD";
	country_table[i].name = D_("Angola");
	country_table[i++].code = "AO";
	country_table[i].name = D_("Anguilla");
	country_table[i++].code = "AI";
	country_table[i].name = D_("Antarctica");
	country_table[i++].code = "AQ";
	country_table[i].name = D_("Antigua and Barbuda");
	country_table[i++].code = "AG";
	country_table[i].name = D_("Argentina");
	country_table[i++].code = "AR";
	country_table[i].name = D_("Armenia");
	country_table[i++].code = "AM";
	country_table[i].name = D_("Aruba");
	country_table[i++].code = "AW";
	country_table[i].name = D_("Australia");
	country_table[i++].code = "AU";
	country_table[i].name = D_("Austria");
	country_table[i++].code = "AT";
	country_table[i].name = D_("Azerbaijan");
	country_table[i++].code = "AZ";
	country_table[i].name = D_("Bahamas");
	country_table[i++].code = "BS";
	country_table[i].name = D_("Bahrain");
	country_table[i++].code = "BH";
	country_table[i].name = D_("Bangladesh");
	country_table[i++].code = "BD";
	country_table[i].name = D_("Barbados");
	country_table[i++].code = "BB";
	country_table[i].name = D_("Belarus");
	country_table[i++].code = "BY";
	country_table[i].name = D_("Belgium");
	country_table[i++].code = "BE";
	country_table[i].name = D_("Belize");
	country_table[i++].code = "BZ";
	country_table[i].name = D_("Benin");
	country_table[i++].code = "BJ";
	country_table[i].name = D_("Bermuda");
	country_table[i++].code = "BM";
	country_table[i].name = D_("Bhutan");
	country_table[i++].code = "BT";
	country_table[i].name = D_("Bolivia");
	country_table[i++].code = "BO";
	country_table[i].name = D_("Bosnia and Herzegovina");
	country_table[i++].code = "BA";
	country_table[i].name = D_("Botswana");
	country_table[i++].code = "BW";
	country_table[i].name = D_("Bouvet Island");
	country_table[i++].code = "BV";
	country_table[i].name = D_("Brazil");
	country_table[i++].code = "BR";
	country_table[i].name = D_("British Indian Ocean Territory");
	country_table[i++].code = "IO";
	country_table[i].name = D_("Brunei Darussalam");
	country_table[i++].code = "BN";
	country_table[i].name = D_("Bulgaria");
	country_table[i++].code = "BG";
	country_table[i].name = D_("Burkina Faso");
	country_table[i++].code = "BF";
	country_table[i].name = D_("Burundi");
	country_table[i++].code = "BI";
	country_table[i].name = D_("Cambodia");
	country_table[i++].code = "KH";
	country_table[i].name = D_("Cameroon");
	country_table[i++].code = "CM";
	country_table[i].name = D_("Canada");
	country_table[i++].code = "CA";
	country_table[i].name = D_("Cape Verde");
	country_table[i++].code = "CV";
	country_table[i].name = D_("Cayman Islands");
	country_table[i++].code = "KY";
	country_table[i].name = D_("Central African Republic");
	country_table[i++].code = "CF";
	country_table[i].name = D_("Chad");
	country_table[i++].code = "TD";
	country_table[i].name = D_("Chile");
	country_table[i++].code = "CL";
	country_table[i].name = D_("China");
	country_table[i++].code = "CN";
	country_table[i].name = D_("Christmas Island");
	country_table[i++].code = "CX";
	country_table[i].name = D_("Cocos (Keeling) Islands");
	country_table[i++].code = "CC";
	country_table[i].name = D_("Colombia");
	country_table[i++].code = "CO";
	country_table[i].name = D_("Comoros");
	country_table[i++].code = "KM";
	country_table[i].name = D_("Congo");
	country_table[i++].code = "CG";
	country_table[i].name = D_("Congo, The Democratic Republic of the");
	country_table[i++].code = "CD";
	country_table[i].name = D_("Cook Islands");
	country_table[i++].code = "CK";
	country_table[i].name = D_("Costa Rica");
	country_table[i++].code = "CR";
	country_table[i].name = D_("Côte d\'Ivoire");
	country_table[i++].code = "CI";
	country_table[i].name = D_("Croatia");
	country_table[i++].code = "HR";
	country_table[i].name = D_("Cuba");
	country_table[i++].code = "CU";
	country_table[i].name = D_("Cyprus");
	country_table[i++].code = "CY";
	country_table[i].name = D_("Czech Republic");
	country_table[i++].code = "CZ";
	country_table[i].name = D_("Denmark");
	country_table[i++].code = "DK";
	country_table[i].name = D_("Djibouti");
	country_table[i++].code = "DJ";
	country_table[i].name = D_("Dominica");
	country_table[i++].code = "DM";
	country_table[i].name = D_("Dominican Republic");
	country_table[i++].code = "DO";
	country_table[i].name = D_("Ecuador");
	country_table[i++].code = "EC";
	country_table[i].name = D_("Egypt");
	country_table[i++].code = "EG";
	country_table[i].name = D_("El Salvador");
	country_table[i++].code = "SV";
	country_table[i].name = D_("Equatorial Guinea");
	country_table[i++].code = "GQ";
	country_table[i].name = D_("Eritrea");
	country_table[i++].code = "ER";
	country_table[i].name = D_("Estonia");
	country_table[i++].code = "EE";
	country_table[i].name = D_("Ethiopia");
	country_table[i++].code = "ET";
	country_table[i].name = D_("Falkland Islands (Malvinas)");
	country_table[i++].code = "FK";
	country_table[i].name = D_("Faroe Islands");
	country_table[i++].code = "FO";
	country_table[i].name = D_("Fiji");
	country_table[i++].code = "FJ";
	country_table[i].name = D_("Finland");
	country_table[i++].code = "FI";
	country_table[i].name = D_("France");
	country_table[i++].code = "FR";
	country_table[i].name = D_("French Guiana");
	country_table[i++].code = "GF";
	country_table[i].name = D_("French Polynesia");
	country_table[i++].code = "PF";
	country_table[i].name = D_("French Southern Territories");
	country_table[i++].code = "TF";
	country_table[i].name = D_("Gabon");
	country_table[i++].code = "GA";
	country_table[i].name = D_("Gambia");
	country_table[i++].code = "GM";
	country_table[i].name = D_("Georgia");
	country_table[i++].code = "GE";
	country_table[i].name = D_("Germany");
	country_table[i++].code = "DE";
	country_table[i].name = D_("Ghana");
	country_table[i++].code = "GH";
	country_table[i].name = D_("Gibraltar");
	country_table[i++].code = "GI";
	country_table[i].name = D_("Greece");
	country_table[i++].code = "GR";
	country_table[i].name = D_("Greenland");
	country_table[i++].code = "GL";
	country_table[i].name = D_("Grenada");
	country_table[i++].code = "GD";
	country_table[i].name = D_("Guadeloupe");
	country_table[i++].code = "GP";
	country_table[i].name = D_("Guam");
	country_table[i++].code = "GU";
	country_table[i].name = D_("Guatemala");
	country_table[i++].code = "GT";
	country_table[i].name = D_("Guernsey");
	country_table[i++].code = "GG";
	country_table[i].name = D_("Guinea");
	country_table[i++].code = "GN";
	country_table[i].name = D_("Guinea-Bissau");
	country_table[i++].code = "GW";
	country_table[i].name = D_("Guyana");
	country_table[i++].code = "GY";
	country_table[i].name = D_("Haiti");
	country_table[i++].code = "HT";
	country_table[i].name = D_("Heard Island and Mcdonald Islands");
	country_table[i++].code = "HM";
	country_table[i].name = D_("Holy See (Vatican City State)");
	country_table[i++].code = "VA";
	country_table[i].name = D_("Honduras");
	country_table[i++].code = "HN";
	country_table[i].name = D_("Hong Kong");
	country_table[i++].code = "HK";
	country_table[i].name = D_("Hungary");
	country_table[i++].code = "HU";
	country_table[i].name = D_("Iceland");
	country_table[i++].code = "IS";
	country_table[i].name = D_("India");
	country_table[i++].code = "IN";
	country_table[i].name = D_("Indonesia");
	country_table[i++].code = "ID";
	country_table[i].name = D_("Iran, Islamic Republic of");
	country_table[i++].code = "IR";
	country_table[i].name = D_("Iraq");
	country_table[i++].code = "IQ";
	country_table[i].name = D_("Ireland");
	country_table[i++].code = "IE";
	country_table[i].name = D_("Isle of Man");
	country_table[i++].code = "IM";
	country_table[i].name = D_("Israel");
	country_table[i++].code = "IL";
	country_table[i].name = D_("Italy");
	country_table[i++].code = "IT";
	country_table[i].name = D_("Jamaica");
	country_table[i++].code = "JM";
	country_table[i].name = D_("Japan");
	country_table[i++].code = "JP";
	country_table[i].name = D_("Jersey");
	country_table[i++].code = "JE";
	country_table[i].name = D_("Jordan");
	country_table[i++].code = "JO";
	country_table[i].name = D_("Kazakhstan");
	country_table[i++].code = "KZ";
	country_table[i].name = D_("Kenya");
	country_table[i++].code = "KE";
	country_table[i].name = D_("Kiribati");
	country_table[i++].code = "KI";
	country_table[i].name = D_("Korea, Democratic People\'s Republic of");
	country_table[i++].code = "KP";
	country_table[i].name = D_("Korea, Republic of");
	country_table[i++].code = "KR";
	country_table[i].name = D_("Kuwait");
	country_table[i++].code = "KW";
	country_table[i].name = D_("Kyrgyzstan");
	country_table[i++].code = "KG";
	country_table[i].name = D_("Lao People\'s Democratic Republic");
	country_table[i++].code = "LA";
	country_table[i].name = D_("Latvia");
	country_table[i++].code = "LV";
	country_table[i].name = D_("Lebanon");
	country_table[i++].code = "LB";
	country_table[i].name = D_("Lesotho");
	country_table[i++].code = "LS";
	country_table[i].name = D_("Liberia");
	country_table[i++].code = "LR";
	country_table[i].name = D_("Libyan Arab Jamahiriya");
	country_table[i++].code = "LY";
	country_table[i].name = D_("Liechtenstein");
	country_table[i++].code = "LI";
	country_table[i].name = D_("Lithuania");
	country_table[i++].code = "LT";
	country_table[i].name = D_("Luxembourg");
	country_table[i++].code = "LU";
	country_table[i].name = D_("Macao");
	country_table[i++].code = "MO";
	country_table[i].name = D_("Macedonia, Republic of");
	country_table[i++].code = "MK";
	country_table[i].name = D_("Madagascar");
	country_table[i++].code = "MG";
	country_table[i].name = D_("Malawi");
	country_table[i++].code = "MW";
	country_table[i].name = D_("Malaysia");
	country_table[i++].code = "MY";
	country_table[i].name = D_("Maldives");
	country_table[i++].code = "MV";
	country_table[i].name = D_("Mali");
	country_table[i++].code = "ML";
	country_table[i].name = D_("Malta");
	country_table[i++].code = "MT";
	country_table[i].name = D_("Marshall Islands");
	country_table[i++].code = "MH";
	country_table[i].name = D_("Martinique");
	country_table[i++].code = "MQ";
	country_table[i].name = D_("Mauritania");
	country_table[i++].code = "MR";
	country_table[i].name = D_("Mauritius");
	country_table[i++].code = "MU";
	country_table[i].name = D_("Mayotte");
	country_table[i++].code = "YT";
	country_table[i].name = D_("Mexico");
	country_table[i++].code = "MX";
	country_table[i].name = D_("Micronesia, Federated States of");
	country_table[i++].code = "FM";
	country_table[i].name = D_("Moldova, Republic of");
	country_table[i++].code = "MD";
	country_table[i].name = D_("Monaco");
	country_table[i++].code = "MC";
	country_table[i].name = D_("Mongolia");
	country_table[i++].code = "MN";
	country_table[i].name = D_("Montenegro");
	country_table[i++].code = "ME";
	country_table[i].name = D_("Montserrat");
	country_table[i++].code = "MS";
	country_table[i].name = D_("Morocco");
	country_table[i++].code = "MA";
	country_table[i].name = D_("Mozambique");
	country_table[i++].code = "MZ";
	country_table[i].name = D_("Myanmar");
	country_table[i++].code = "MM";
	country_table[i].name = D_("Namibia");
	country_table[i++].code = "NA";
	country_table[i].name = D_("Nauru");
	country_table[i++].code = "NR";
	country_table[i].name = D_("Nepal");
	country_table[i++].code = "NP";
	country_table[i].name = D_("Netherlands");
	country_table[i++].code = "NL";
	country_table[i].name = D_("Netherlands Antilles");
	country_table[i++].code = "AN";
	country_table[i].name = D_("New Caledonia");
	country_table[i++].code = "NC";
	country_table[i].name = D_("New Zealand");
	country_table[i++].code = "NZ";
	country_table[i].name = D_("Nicaragua");
	country_table[i++].code = "NI";
	country_table[i].name = D_("Niger");
	country_table[i++].code = "NE";
	country_table[i].name = D_("Nigeria");
	country_table[i++].code = "NG";
	country_table[i].name = D_("Niue");
	country_table[i++].code = "NU";
	country_table[i].name = D_("Norfolk Island");
	country_table[i++].code = "NF";
	country_table[i].name = D_("Northern Mariana Islands");
	country_table[i++].code = "MP";
	country_table[i].name = D_("Norway");
	country_table[i++].code = "NO";
	country_table[i].name = D_("Oman");
	country_table[i++].code = "OM";
	country_table[i].name = D_("Pakistan");
	country_table[i++].code = "PK";
	country_table[i].name = D_("Palau");
	country_table[i++].code = "PW";
	country_table[i].name = D_("Palestinian Territory, Occupied");
	country_table[i++].code = "PS";
	country_table[i].name = D_("Panama");
	country_table[i++].code = "PA";
	country_table[i].name = D_("Papua New Guinea");
	country_table[i++].code = "PG";
	country_table[i].name = D_("Paraguay");
	country_table[i++].code = "PY";
	country_table[i].name = D_("Peru");
	country_table[i++].code = "PE";
	country_table[i].name = D_("Philippines");
	country_table[i++].code = "PH";
	country_table[i].name = D_("Pitcairn");
	country_table[i++].code = "PN";
	country_table[i].name = D_("Poland");
	country_table[i++].code = "PL";
	country_table[i].name = D_("Portugal");
	country_table[i++].code = "PT";
	country_table[i].name = D_("Puerto Rico");
	country_table[i++].code = "PR";
	country_table[i].name = D_("Qatar");
	country_table[i++].code = "QA";
	country_table[i].name = D_("Reunion");
	country_table[i++].code = "RE";
	country_table[i].name = D_("Romania");
	country_table[i++].code = "RO";
	country_table[i].name = D_("Russian Federation");
	country_table[i++].code = "RU";
	country_table[i].name = D_("Rwanda");
	country_table[i++].code = "RW";
	country_table[i].name = D_("Saint Helena");
	country_table[i++].code = "SH";
	country_table[i].name = D_("Saint Kitts and Nevis");
	country_table[i++].code = "KN";
	country_table[i].name = D_("Saint Lucia");
	country_table[i++].code = "LC";
	country_table[i].name = D_("Saint Pierre and Miquelon");
	country_table[i++].code = "PM";
	country_table[i].name = D_("Saint Vincent and the Grenadines");
	country_table[i++].code = "VC";
	country_table[i].name = D_("Samoa");
	country_table[i++].code = "WS";
	country_table[i].name = D_("San Marino");
	country_table[i++].code = "SM";
	country_table[i].name = D_("Sao Tome and Principe");
	country_table[i++].code = "ST";
	country_table[i].name = D_("Saudi Arabia");
	country_table[i++].code = "SA";
	country_table[i].name = D_("Senegal");
	country_table[i++].code = "SN";
	country_table[i].name = D_("Serbia");
	country_table[i++].code = "RS";
	country_table[i].name = D_("Seychelles");
	country_table[i++].code = "SC";
	country_table[i].name = D_("Sierra Leone");
	country_table[i++].code = "SL";
	country_table[i].name = D_("Singapore");
	country_table[i++].code = "SG";
	country_table[i].name = D_("Slovakia");
	country_table[i++].code = "SK";
	country_table[i].name = D_("Slovenia");
	country_table[i++].code = "SI";
	country_table[i].name = D_("Solomon Islands");
	country_table[i++].code = "SB";
	country_table[i].name = D_("Somalia");
	country_table[i++].code = "SO";
	country_table[i].name = D_("South Africa");
	country_table[i++].code = "ZA";
	country_table[i].name = D_("South Georgia and the South Sandwich Islands");
	country_table[i++].code = "GS";
	country_table[i].name = D_("Spain");
	country_table[i++].code = "ES";
	country_table[i].name = D_("Sri Lanka");
	country_table[i++].code = "LK";
	country_table[i].name = D_("Sudan");
	country_table[i++].code = "SD";
	country_table[i].name = D_("Suriname");
	country_table[i++].code = "SR";
	country_table[i].name = D_("Svalbard and Jan Mayen");
	country_table[i++].code = "SJ";
	country_table[i].name = D_("Swaziland");
	country_table[i++].code = "SZ";
	country_table[i].name = D_("Sweden");
	country_table[i++].code = "SE";
	country_table[i].name = D_("Switzerland");
	country_table[i++].code = "CH";
	country_table[i].name = D_("Syrian Arab Republic");
	country_table[i++].code = "SY";
	country_table[i].name = D_("Taiwan");
	country_table[i++].code = "TW";
	country_table[i].name = D_("Tajikistan");
	country_table[i++].code = "TJ";
	country_table[i].name = D_("Tanzania, United Republic of");
	country_table[i++].code = "TZ";
	country_table[i].name = D_("Thailand");
	country_table[i++].code = "TH";
	country_table[i].name = D_("Timor-Leste");
	country_table[i++].code = "TL";
	country_table[i].name = D_("Togo");
	country_table[i++].code = "TG";
	country_table[i].name = D_("Tokelau");
	country_table[i++].code = "TK";
	country_table[i].name = D_("Tonga");
	country_table[i++].code = "TO";
	country_table[i].name = D_("Trinidad and Tobago");
	country_table[i++].code = "TT";
	country_table[i].name = D_("Tunisia");
	country_table[i++].code = "TN";
	country_table[i].name = D_("Turkey");
	country_table[i++].code = "TR";
	country_table[i].name = D_("Turkmenistan");
	country_table[i++].code = "TM";
	country_table[i].name = D_("Turks and Caicos Islands");
	country_table[i++].code = "TC";
	country_table[i].name = D_("Tuvalu");
	country_table[i++].code = "TV";
	country_table[i].name = D_("Uganda");
	country_table[i++].code = "UG";
	country_table[i].name = D_("Ukraine");
	country_table[i++].code = "UA";
	country_table[i].name = D_("United Arab Emirates");
	country_table[i++].code = "AE";
	country_table[i].name = D_("United Kingdom");
	country_table[i++].code = "GB";
	country_table[i].name = D_("United States");
	country_table[i++].code = "US";
	country_table[i].name = D_("United States Minor Outlying Islands");
	country_table[i++].code = "UM";
	country_table[i].name = D_("Uruguay");
	country_table[i++].code = "UY";
	country_table[i].name = D_("Uzbekistan");
	country_table[i++].code = "UZ";
	country_table[i].name = D_("Vanuatu");
	country_table[i++].code = "VU";
	country_table[i].name = D_("Venezuela");
	country_table[i++].code = "VE";
	country_table[i].name = D_("Viet Nam");
	country_table[i++].code = "VN";
	country_table[i].name = D_("Virgin Islands, British");
	country_table[i++].code = "VG";
	country_table[i].name = D_("Virgin Islands, U.S.");
	country_table[i++].code = "VI";
	country_table[i].name = D_("Wallis and Futuna");
	country_table[i++].code = "WF";
	country_table[i].name = D_("Western Sahara");
	country_table[i++].code = "EH";
	country_table[i].name = D_("Yemen");
	country_table[i++].code = "YE";
	country_table[i].name = D_("Zambia");
	country_table[i++].code = "ZM";
	country_table[i].name = D_("Zimbabwe");
	country_table[i++].code = "ZW";

	qsort (country_table, NUMBER_OF_COUNTRIES, sizeof(CountryItem), comp_countries);
}

void new_ca_populate_country_combobox(GtkComboBox *country_combobox)
{
	int i = 0;
	GtkTreeStore * new_store = NULL;
	GtkTreeIter iter;
	GtkCellRenderer *renderer = NULL;

	populate_country_table();
	new_store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_STRING);

	for (i=0; i<NUMBER_OF_COUNTRIES; i++) {
		gtk_tree_store_append (new_store, &iter, NULL);
		gtk_tree_store_set (new_store, &iter, 0, country_table[i].name, 1, country_table[i].code, -1);
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX(country_combobox), GTK_TREE_MODEL (new_store));

	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (country_combobox), renderer, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (country_combobox), renderer, "text", 0);
	
}


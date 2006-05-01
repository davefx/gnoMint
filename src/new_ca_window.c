//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006 David Marín Carreño <davefx@gmail.com>
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

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

typedef struct {
	char * name;
	char * code;
} CountryItem;

#define NUMBER_OF_COUNTRIES 243
CountryItem country_table[NUMBER_OF_COUNTRIES];


GladeXML * new_ca_window_xml = NULL;


void populate_country_combobox();


void new_ca_window_display()
{
	gchar     * xml_file = NULL;
	GtkWidget * widget = NULL;
	
	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	new_ca_window_xml = glade_xml_new (xml_file, "new_ca_window", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (new_ca_window_xml); 	
	
	populate_country_combobox();
	
}

static int comp_countries(const void *m1, const void *m2) {
	CountryItem *mi1 = (CountryItem *) m1;
	CountryItem *mi2 = (CountryItem *) m2;
	return g_ascii_strcasecmp (mi1->name, mi2->name);
}



void populate_country_table()
{
	int i = 0;

	country_table[i].name = _("Afghanistan");
	country_table[i++].code = "AF";
	country_table[i].name = _("Aland Islands");
	country_table[i++].code = "AX";
	country_table[i].name = _("Albania");
	country_table[i++].code = "AL";
	country_table[i].name = _("Algeria");
	country_table[i++].code = "DZ";
	country_table[i].name = _("American Samoa");
	country_table[i++].code = "AS";
	country_table[i].name = _("Andorra");
	country_table[i++].code = "AD";
	country_table[i].name = _("Angola");
	country_table[i++].code = "AO";
	country_table[i].name = _("Anguilla");
	country_table[i++].code = "AI";
	country_table[i].name = _("Antarctica");
	country_table[i++].code = "AQ";
	country_table[i].name = _("Antigua and Barbuda");
	country_table[i++].code = "AG";
	country_table[i].name = _("Argentina");
	country_table[i++].code = "AR";
	country_table[i].name = _("Armenia");
	country_table[i++].code = "AM";
	country_table[i].name = _("Aruba");
	country_table[i++].code = "AW";
	country_table[i].name = _("Australia");
	country_table[i++].code = "AU";
	country_table[i].name = _("Austria");
	country_table[i++].code = "AT";
	country_table[i].name = _("Azerbaijan");
	country_table[i++].code = "AZ";
	country_table[i].name = _("Bahamas");
	country_table[i++].code = "BS";
	country_table[i].name = _("Bahrain");
	country_table[i++].code = "BH";
	country_table[i].name = _("Bangladesh");
	country_table[i++].code = "BD";
	country_table[i].name = _("Barbados");
	country_table[i++].code = "BB";
	country_table[i].name = _("Belarus");
	country_table[i++].code = "BY";
	country_table[i].name = _("Belgium");
	country_table[i++].code = "BE";
	country_table[i].name = _("Belize");
	country_table[i++].code = "BZ";
	country_table[i].name = _("Benin");
	country_table[i++].code = "BJ";
	country_table[i].name = _("Bermuda");
	country_table[i++].code = "BM";
	country_table[i].name = _("Bhutan");
	country_table[i++].code = "BT";
	country_table[i].name = _("Bolivia");
	country_table[i++].code = "BO";
	country_table[i].name = _("Bosnia and Herzegovina");
	country_table[i++].code = "BA";
	country_table[i].name = _("Botswana");
	country_table[i++].code = "BW";
	country_table[i].name = _("Bouvet Island");
	country_table[i++].code = "BV";
	country_table[i].name = _("Brazil");
	country_table[i++].code = "BR";
	country_table[i].name = _("British Indian Ocean Territory");
	country_table[i++].code = "IO";
	country_table[i].name = _("Brunei Darussalam");
	country_table[i++].code = "BN";
	country_table[i].name = _("Bulgaria");
	country_table[i++].code = "BG";
	country_table[i].name = _("Burkina Faso");
	country_table[i++].code = "BF";
	country_table[i].name = _("Burundi");
	country_table[i++].code = "BI";
	country_table[i].name = _("Cambodia");
	country_table[i++].code = "KH";
	country_table[i].name = _("Cameroon");
	country_table[i++].code = "CM";
	country_table[i].name = _("Canada");
	country_table[i++].code = "CA";
	country_table[i].name = _("Cape Verde");
	country_table[i++].code = "CV";
	country_table[i].name = _("Cayman Islands");
	country_table[i++].code = "KY";
	country_table[i].name = _("Central African Republic");
	country_table[i++].code = "CF";
	country_table[i].name = _("Chad");
	country_table[i++].code = "TD";
	country_table[i].name = _("Chile");
	country_table[i++].code = "CL";
	country_table[i].name = _("China");
	country_table[i++].code = "CN";
	country_table[i].name = _("Christmas Island");
	country_table[i++].code = "CX";
	country_table[i].name = _("Cocos (Keeling) Islands");
	country_table[i++].code = "CC";
	country_table[i].name = _("Colombia");
	country_table[i++].code = "CO";
	country_table[i].name = _("Comoros");
	country_table[i++].code = "KM";
	country_table[i].name = _("Congo");
	country_table[i++].code = "CG";
	country_table[i].name = _("Congo, the Democratic Republic of the");
	country_table[i++].code = "CD";
	country_table[i].name = _("Cook Islands");
	country_table[i++].code = "CK";
	country_table[i].name = _("Costa Rica");
	country_table[i++].code = "CR";
	country_table[i].name = _("Cote d\'Ivoire");
	country_table[i++].code = "CI";
	country_table[i].name = _("Croatia");
	country_table[i++].code = "HR";
	country_table[i].name = _("Cuba");
	country_table[i++].code = "CU";
	country_table[i].name = _("Cyprus");
	country_table[i++].code = "CY";
	country_table[i].name = _("Czech Republic");
	country_table[i++].code = "CZ";
	country_table[i].name = _("Denmark");
	country_table[i++].code = "DK";
	country_table[i].name = _("Djibouti");
	country_table[i++].code = "DJ";
	country_table[i].name = _("Dominica");
	country_table[i++].code = "DM";
	country_table[i].name = _("Dominican Republic");
	country_table[i++].code = "DO";
	country_table[i].name = _("Ecuador");
	country_table[i++].code = "EC";
	country_table[i].name = _("Egypt");
	country_table[i++].code = "EG";
	country_table[i].name = _("El Salvador");
	country_table[i++].code = "SV";
	country_table[i].name = _("Equatorial Guinea");
	country_table[i++].code = "GQ";
	country_table[i].name = _("Eritrea");
	country_table[i++].code = "ER";
	country_table[i].name = _("Estonia");
	country_table[i++].code = "EE";
	country_table[i].name = _("Ethiopia");
	country_table[i++].code = "ET";
	country_table[i].name = _("Falkland Islands (Malvinas)");
	country_table[i++].code = "FK";
	country_table[i].name = _("Faroe Islands");
	country_table[i++].code = "FO";
	country_table[i].name = _("Fiji");
	country_table[i++].code = "FJ";
	country_table[i].name = _("Finland");
	country_table[i++].code = "FI";
	country_table[i].name = _("France");
	country_table[i++].code = "FR";
	country_table[i].name = _("French Guiana");
	country_table[i++].code = "GF";
	country_table[i].name = _("French Polynesia");
	country_table[i++].code = "PF";
	country_table[i].name = _("French Southern Territories");
	country_table[i++].code = "TF";
	country_table[i].name = _("Gabon");
	country_table[i++].code = "GA";
	country_table[i].name = _("Gambia");
	country_table[i++].code = "GM";
	country_table[i].name = _("Georgia");
	country_table[i++].code = "GE";
	country_table[i].name = _("Germany");
	country_table[i++].code = "DE";
	country_table[i].name = _("Ghana");
	country_table[i++].code = "GH";
	country_table[i].name = _("Gibraltar");
	country_table[i++].code = "GI";
	country_table[i].name = _("Greece");
	country_table[i++].code = "GR";
	country_table[i].name = _("Greenland");
	country_table[i++].code = "GL";
	country_table[i].name = _("Grenada");
	country_table[i++].code = "GD";
	country_table[i].name = _("Guadeloupe");
	country_table[i++].code = "GP";
	country_table[i].name = _("Guam");
	country_table[i++].code = "GU";
	country_table[i].name = _("Guatemala");
	country_table[i++].code = "GT";
	country_table[i].name = _("Guernsey");
	country_table[i++].code = "GG";
	country_table[i].name = _("Guinea");
	country_table[i++].code = "GN";
	country_table[i].name = _("Guinea-Bissau");
	country_table[i++].code = "GW";
	country_table[i].name = _("Guyana");
	country_table[i++].code = "GY";
	country_table[i].name = _("Haiti");
	country_table[i++].code = "HT";
	country_table[i].name = _("Heard Island and Mcdonald Islands");
	country_table[i++].code = "HM";
	country_table[i].name = _("Holy See (Vatican City State)");
	country_table[i++].code = "VA";
	country_table[i].name = _("Honduras");
	country_table[i++].code = "HN";
	country_table[i].name = _("Hong Kong");
	country_table[i++].code = "HK";
	country_table[i].name = _("Hungary");
	country_table[i++].code = "HU";
	country_table[i].name = _("Iceland");
	country_table[i++].code = "IS";
	country_table[i].name = _("India");
	country_table[i++].code = "IN";
	country_table[i].name = _("Indonesia");
	country_table[i++].code = "ID";
	country_table[i].name = _("Iran, Islamic Republic of");
	country_table[i++].code = "IR";
	country_table[i].name = _("Iraq");
	country_table[i++].code = "IQ";
	country_table[i].name = _("Ireland");
	country_table[i++].code = "IE";
	country_table[i].name = _("Isle of Man");
	country_table[i++].code = "IM";
	country_table[i].name = _("Israel");
	country_table[i++].code = "IL";
	country_table[i].name = _("Italy");
	country_table[i++].code = "IT";
	country_table[i].name = _("Jamaica");
	country_table[i++].code = "JM";
	country_table[i].name = _("Japan");
	country_table[i++].code = "JP";
	country_table[i].name = _("Jersey");
	country_table[i++].code = "JE";
	country_table[i].name = _("Jordan");
	country_table[i++].code = "JO";
	country_table[i].name = _("Kazakhstan");
	country_table[i++].code = "KZ";
	country_table[i].name = _("Kenya");
	country_table[i++].code = "KE";
	country_table[i].name = _("Kiribati");
	country_table[i++].code = "KI";
	country_table[i].name = _("Korea, Democratic People\'s Republic of");
	country_table[i++].code = "KP";
	country_table[i].name = _("Korea, Republic of");
	country_table[i++].code = "KR";
	country_table[i].name = _("Kuwait");
	country_table[i++].code = "KW";
	country_table[i].name = _("Kyrgyzstan");
	country_table[i++].code = "KG";
	country_table[i].name = _("Lao People\'s Democratic Republic");
	country_table[i++].code = "LA";
	country_table[i].name = _("Latvia");
	country_table[i++].code = "LV";
	country_table[i].name = _("Lebanon");
	country_table[i++].code = "LB";
	country_table[i].name = _("Lesotho");
	country_table[i++].code = "LS";
	country_table[i].name = _("Liberia");
	country_table[i++].code = "LR";
	country_table[i].name = _("Libyan Arab Jamahiriya");
	country_table[i++].code = "LY";
	country_table[i].name = _("Liechtenstein");
	country_table[i++].code = "LI";
	country_table[i].name = _("Lithuania");
	country_table[i++].code = "LT";
	country_table[i].name = _("Luxembourg");
	country_table[i++].code = "LU";
	country_table[i].name = _("Macao");
	country_table[i++].code = "MO";
	country_table[i].name = _("Macedonia, The Former Yugoslav Republic of");
	country_table[i++].code = "MK";
	country_table[i].name = _("Madagascar");
	country_table[i++].code = "MG";
	country_table[i].name = _("Malawi");
	country_table[i++].code = "MW";
	country_table[i].name = _("Malaysia");
	country_table[i++].code = "MY";
	country_table[i].name = _("Maldives");
	country_table[i++].code = "MV";
	country_table[i].name = _("Mali");
	country_table[i++].code = "ML";
	country_table[i].name = _("Malta");
	country_table[i++].code = "MT";
	country_table[i].name = _("Marshall Islands");
	country_table[i++].code = "MH";
	country_table[i].name = _("Martinique");
	country_table[i++].code = "MQ";
	country_table[i].name = _("Mauritania");
	country_table[i++].code = "MR";
	country_table[i].name = _("Mauritius");
	country_table[i++].code = "MU";
	country_table[i].name = _("Mayotte");
	country_table[i++].code = "YT";
	country_table[i].name = _("Mexico");
	country_table[i++].code = "MX";
	country_table[i].name = _("Micronesia, Federated States of");
	country_table[i++].code = "FM";
	country_table[i].name = _("Moldova, Republic of");
	country_table[i++].code = "MD";
	country_table[i].name = _("Monaco");
	country_table[i++].code = "MC";
	country_table[i].name = _("Mongolia");
	country_table[i++].code = "MN";
	country_table[i].name = _("Montserrat");
	country_table[i++].code = "MS";
	country_table[i].name = _("Morocco");
	country_table[i++].code = "MA";
	country_table[i].name = _("Mozambique");
	country_table[i++].code = "MZ";
	country_table[i].name = _("Myanmar");
	country_table[i++].code = "MM";
	country_table[i].name = _("Namibia");
	country_table[i++].code = "NA";
	country_table[i].name = _("Nauru");
	country_table[i++].code = "NR";
	country_table[i].name = _("Nepal");
	country_table[i++].code = "NP";
	country_table[i].name = _("Netherlands");
	country_table[i++].code = "NL";
	country_table[i].name = _("Netherlands Antilles");
	country_table[i++].code = "AN";
	country_table[i].name = _("New Caledonia");
	country_table[i++].code = "NC";
	country_table[i].name = _("New Zealand");
	country_table[i++].code = "NZ";
	country_table[i].name = _("Nicaragua");
	country_table[i++].code = "NI";
	country_table[i].name = _("Niger");
	country_table[i++].code = "NE";
	country_table[i].name = _("Nigeria");
	country_table[i++].code = "NG";
	country_table[i].name = _("Niue");
	country_table[i++].code = "NU";
	country_table[i].name = _("Norfolk Island");
	country_table[i++].code = "NF";
	country_table[i].name = _("Northern Mariana Islands");
	country_table[i++].code = "MP";
	country_table[i].name = _("Norway");
	country_table[i++].code = "NO";
	country_table[i].name = _("Oman");
	country_table[i++].code = "OM";
	country_table[i].name = _("Pakistan");
	country_table[i++].code = "PK";
	country_table[i].name = _("Palau");
	country_table[i++].code = "PW";
	country_table[i].name = _("Palestinian Territory, Occupied");
	country_table[i++].code = "PS";
	country_table[i].name = _("Panama");
	country_table[i++].code = "PA";
	country_table[i].name = _("Papua New Guinea");
	country_table[i++].code = "PG";
	country_table[i].name = _("Paraguay");
	country_table[i++].code = "PY";
	country_table[i].name = _("Peru");
	country_table[i++].code = "PE";
	country_table[i].name = _("Philippines");
	country_table[i++].code = "PH";
	country_table[i].name = _("Pitcairn");
	country_table[i++].code = "PN";
	country_table[i].name = _("Poland");
	country_table[i++].code = "PL";
	country_table[i].name = _("Portugal");
	country_table[i++].code = "PT";
	country_table[i].name = _("Puerto Rico");
	country_table[i++].code = "PR";
	country_table[i].name = _("Qatar");
	country_table[i++].code = "QA";
	country_table[i].name = _("Reunion");
	country_table[i++].code = "RE";
	country_table[i].name = _("Romania");
	country_table[i++].code = "RO";
	country_table[i].name = _("Russian Federation");
	country_table[i++].code = "RU";
	country_table[i].name = _("Rwanda");
	country_table[i++].code = "RW";
	country_table[i].name = _("Saint Helena");
	country_table[i++].code = "SH";
	country_table[i].name = _("Saint Kitts and Nevis");
	country_table[i++].code = "KN";
	country_table[i].name = _("Saint Lucia");
	country_table[i++].code = "LC";
	country_table[i].name = _("Saint Pierre and Miquelon");
	country_table[i++].code = "PM";
	country_table[i].name = _("Saint Vincent and the Grenadines");
	country_table[i++].code = "VC";
	country_table[i].name = _("Samoa");
	country_table[i++].code = "WS";
	country_table[i].name = _("San Marino");
	country_table[i++].code = "SM";
	country_table[i].name = _("Sao Tome and Principe");
	country_table[i++].code = "ST";
	country_table[i].name = _("Saudi Arabia");
	country_table[i++].code = "SA";
	country_table[i].name = _("Senegal");
	country_table[i++].code = "SN";
	country_table[i].name = _("Serbia and Montenegro");
	country_table[i++].code = "CS";
	country_table[i].name = _("Seychelles");
	country_table[i++].code = "SC";
	country_table[i].name = _("Sierra Leone");
	country_table[i++].code = "SL";
	country_table[i].name = _("Singapore");
	country_table[i++].code = "SG";
	country_table[i].name = _("Slovakia");
	country_table[i++].code = "SK";
	country_table[i].name = _("Slovenia");
	country_table[i++].code = "SI";
	country_table[i].name = _("Solomon Islands");
	country_table[i++].code = "SB";
	country_table[i].name = _("Somalia");
	country_table[i++].code = "SO";
	country_table[i].name = _("South Africa");
	country_table[i++].code = "ZA";
	country_table[i].name = _("South Georgia and the South Sandwich Islands");
	country_table[i++].code = "GS";
	country_table[i].name = _("Spain");
	country_table[i++].code = "ES";
	country_table[i].name = _("Sri Lanka");
	country_table[i++].code = "LK";
	country_table[i].name = _("Sudan");
	country_table[i++].code = "SD";
	country_table[i].name = _("Suriname");
	country_table[i++].code = "SR";
	country_table[i].name = _("Svalbard and Jan Mayen");
	country_table[i++].code = "SJ";
	country_table[i].name = _("Swaziland");
	country_table[i++].code = "SZ";
	country_table[i].name = _("Sweden");
	country_table[i++].code = "SE";
	country_table[i].name = _("Switzerland");
	country_table[i++].code = "CH";
	country_table[i].name = _("Syrian Arab Republic");
	country_table[i++].code = "SY";
	country_table[i].name = _("Taiwan, Province of China");
	country_table[i++].code = "TW";
	country_table[i].name = _("Tajikistan");
	country_table[i++].code = "TJ";
	country_table[i].name = _("Tanzania, United Republic of");
	country_table[i++].code = "TZ";
	country_table[i].name = _("Thailand");
	country_table[i++].code = "TH";
	country_table[i].name = _("Timor-Leste");
	country_table[i++].code = "TL";
	country_table[i].name = _("Togo");
	country_table[i++].code = "TG";
	country_table[i].name = _("Tokelau");
	country_table[i++].code = "TK";
	country_table[i].name = _("Tonga");
	country_table[i++].code = "TO";
	country_table[i].name = _("Trinidad and Tobago");
	country_table[i++].code = "TT";
	country_table[i].name = _("Tunisia");
	country_table[i++].code = "TN";
	country_table[i].name = _("Turkey");
	country_table[i++].code = "TR";
	country_table[i].name = _("Turkmenistan");
	country_table[i++].code = "TM";
	country_table[i].name = _("Turks and Caicos Islands");
	country_table[i++].code = "TC";
	country_table[i].name = _("Tuvalu");
	country_table[i++].code = "TV";
	country_table[i].name = _("Uganda");
	country_table[i++].code = "UG";
	country_table[i].name = _("Ukraine");
	country_table[i++].code = "UA";
	country_table[i].name = _("United Arab Emirates");
	country_table[i++].code = "AE";
	country_table[i].name = _("United Kingdom");
	country_table[i++].code = "GB";
	country_table[i].name = _("United States");
	country_table[i++].code = "US";
	country_table[i].name = _("United States Minor Outlying Islands");
	country_table[i++].code = "UM";
	country_table[i].name = _("Uruguay");
	country_table[i++].code = "UY";
	country_table[i].name = _("Uzbekistan");
	country_table[i++].code = "UZ";
	country_table[i].name = _("Vanuatu");
	country_table[i++].code = "VU";
	country_table[i].name = _("Venezuela");
	country_table[i++].code = "VE";
	country_table[i].name = _("Viet Nam");
	country_table[i++].code = "VN";
	country_table[i].name = _("Virgin Islands, British");
	country_table[i++].code = "VG";
	country_table[i].name = _("Virgin Islands, U.S.");
	country_table[i++].code = "VI";
	country_table[i].name = _("Wallis and Futuna");
	country_table[i++].code = "WF";
	country_table[i].name = _("Western Sahara");
	country_table[i++].code = "EH";
	country_table[i].name = _("Yemen");
	country_table[i++].code = "YE";
	country_table[i].name = _("Zambia");
	country_table[i++].code = "ZM";
	country_table[i].name = _("Zimbabwe");
	country_table[i++].code = "ZW";

	qsort (country_table, NUMBER_OF_COUNTRIES, sizeof(CountryItem), comp_countries);
}

void populate_country_combobox()
{
	int i = 0;
	GtkComboBox *country_combobox = NULL;
	GtkTreeStore * new_store = NULL;
	GtkTreeIter iter;
	GtkCellRenderer *renderer = NULL;
	GValue *value = NULL;

	populate_country_table();
	new_store = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_STRING);

	country_combobox = GTK_COMBO_BOX(glade_xml_get_widget (new_ca_window_xml, "country_combobox"));
	for (i=0; i<NUMBER_OF_COUNTRIES; i++) {
		gtk_tree_store_append (new_store, &iter, NULL);
		gtk_tree_store_set (new_store, &iter, 0, country_table[i].name, 1, country_table[i].code, -1);
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX(country_combobox), new_store);
	gtk_combo_box_entry_set_text_column (GTK_COMBO_BOX_ENTRY (country_combobox), 0);

	renderer = gtk_cell_renderer_text_new ();
	value = g_new0 (GValue, 1);
	value = g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, " - ");
	g_object_set_property (G_OBJECT(renderer), "text", value);
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (country_combobox), renderer, FALSE);

	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (country_combobox), renderer, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (country_combobox), renderer, "text", 1);
	

		
                                             
}


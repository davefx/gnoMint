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

#include "new_ca_window.h"
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

typedef struct {
	char * name;
	char * code;
} CountryItem;

#define NUMBER_OF_COUNTRIES 244
CountryItem country_table[NUMBER_OF_COUNTRIES];


GladeXML * new_req_window_xml = NULL;
GtkTreeStore * new_req_ca_list_model = NULL;

GtkTreeIter * new_req_cert_parent_iter = NULL;
GtkTreeIter * new_req_last_ca_iter = NULL;



enum {NEW_REQ_CA_MODEL_COLUMN_ID=0,
      NEW_REQ_CA_MODEL_COLUMN_SERIAL=1,
      NEW_REQ_CA_MODEL_COLUMN_SUBJECT=2,
      NEW_REQ_CA_MODEL_COLUMN_DN=3,
      NEW_REQ_CA_MODEL_COLUMN_PARENT_DN=4,
      NEW_REQ_CA_MODEL_COLUMN_NUMBER=5}
        NewReqCaListModelColumns;


int __new_req_window_refresh_model_add_ca (void *pArg, int argc, char **argv, char **columnNames)
{
	GtkTreeIter iter;
	GtkTreeIter iter_previous;

	GtkTreeStore * new_model = GTK_TREE_STORE (pArg);

	// First we must check if the current CA is at the same level than the last one
	if (new_req_last_ca_iter) {
		gtk_tree_

	}
	
	gtk_tree_store_append (new_model, &iter, new_req_last_ca_iter);
	
	gtk_tree_store_set (new_model, &iter,
			    0, atoi(argv[CA_MODEL_COLUMN_ID]),
			    1, atoll(argv[CA_MODEL_COLUMN_SERIAL]),
			    2, argv[CA_MODEL_COLUMN_SUBJECT],
			    3, argv[CA_MODEL_COLUMN_DN],
			    -1);
	
	// For now, we only support one only CA
	if (atoi(argv[CA_MODEL_COLUMN_IS_CA]) != 0) {
		new_req_last_ca_iter = gtk_tree_iter_copy (&iter);
	}
	
	return 0;
}




// NEW CSR WINDOW CALLBACKS

void __new_req_populate_ca_treeview (GtkTreeView *treeview)
{
	new_req_ca_list_model = gtk_tree_store_new (NEW_REQ_CA_MODEL_COLUMN_NUMBER, G_TYPE_UINT64, G_TYPE_UINT64, G_TYPE_STRING,
						    G_TYPE_STRING, G_TYPE_STRING);
}

void new_req_window_display()
{
	gchar     * xml_file = NULL;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	// Workaround for libglade
	volatile GType foo = GTK_TYPE_FILE_CHOOSER_WIDGET, tst;
	tst = foo;
	new_req_window_xml = glade_xml_new (xml_file, "new_req_window", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (new_req_window_xml); 	
	
	new_ca_populate_country_combobox(GTK_COMBO_BOX(glade_xml_get_widget(new_req_window_xml, "country_combobox1")));

	__new_req_populate_ca_treeview (GTK_TREE_VIEW(glade_xml_get_widget(new_req_window_xml, "")));

}

void new_req_tab_activate (int tab_number)
{
	GtkNotebook *notebook = GTK_NOTEBOOK(glade_xml_get_widget (new_req_window_xml, "new_req_notebook"));
	
	gtk_notebook_set_current_page (notebook, tab_number);

}

void on_new_req_cn_entry_changed (GtkEditable *editable,
			 gpointer user_data) 
{
	GtkButton *button = GTK_BUTTON(glade_xml_get_widget (new_req_window_xml, "new_req_next2"));

	if (strlen (gtk_entry_get_text (GTK_ENTRY(editable)))) 
		gtk_widget_set_sensitive (GTK_WIDGET(button), TRUE);
	else
		gtk_widget_set_sensitive (GTK_WIDGET(button), FALSE);
		
}

void on_new_req_next1_clicked (GtkButton *widget,
			      gpointer user_data) 
{
	new_req_tab_activate (1);
}

void on_new_req_previous2_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_req_tab_activate (0);
}

void on_new_req_next2_clicked (GtkButton *widget,
			      gpointer user_data) 
{
	new_req_tab_activate (2);
}

void on_new_req_previous3_clicked (GtkButton *widget,
				  gpointer user_data) 
{
	new_req_tab_activate (1);
}

void on_new_req_cancel_clicked (GtkButton *widget,
			       gpointer user_data) 
{
	
	GtkWindow *window = GTK_WINDOW(glade_xml_get_widget (new_req_window_xml, "new_req_window"));

	gtk_object_destroy(GTK_OBJECT(window));
	
}

void on_new_req_commit_clicked (GtkButton *widg,
			       gpointer user_data) 
{
	CaCreationData *csr_creation_data = NULL;

	GtkWidget *widget = NULL;
	GtkWindow *window = NULL;
	gint active = -1;
	gchar *text = NULL;
	GtkTreeModel *tree_model = NULL;
	GtkTreeIter tree_iter;
	
	csr_creation_data = g_new0 (CaCreationData, 1);
	widget = glade_xml_get_widget (new_req_window_xml, "country_combobox1");
	active = gtk_combo_box_get_active (GTK_COMBO_BOX(widget));

	if (active < 0) {
			csr_creation_data->country = NULL;
	} else {
		tree_model = gtk_combo_box_get_model (GTK_COMBO_BOX(widget));
		gtk_combo_box_get_active_iter (GTK_COMBO_BOX(widget), &tree_iter);
		gtk_tree_model_get (tree_model, &tree_iter, 1, &text, -1);

		csr_creation_data->country = g_strdup (text);
		
	}
		
	widget = glade_xml_get_widget (new_req_window_xml, "st_entry1");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		csr_creation_data->state = g_strdup (text);
	else
		csr_creation_data->state = NULL;

	widget = glade_xml_get_widget (new_req_window_xml, "city_entry1");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		csr_creation_data->city = g_strdup (text);
	else
		csr_creation_data->city = NULL;

	widget = glade_xml_get_widget (new_req_window_xml, "o_entry1");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		csr_creation_data->org = g_strdup (text);
	else
		csr_creation_data->org = NULL;

	widget = glade_xml_get_widget (new_req_window_xml, "ou_entry1");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		csr_creation_data->ou = g_strdup (text);
	else
		csr_creation_data->ou = NULL;

	widget = glade_xml_get_widget (new_req_window_xml, "cn_entry1");
	text = (gchar *) gtk_entry_get_text (GTK_ENTRY(widget));
	if (strlen (text))
		csr_creation_data->cn = g_strdup (text);
	else
		csr_creation_data->cn = NULL;

	widget = glade_xml_get_widget (new_req_window_xml, "dsa_radiobutton1");
	active = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget));
	csr_creation_data->key_type = active;

	widget = glade_xml_get_widget (new_req_window_xml, "keylength_spinbutton1");
	active = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(widget));
	csr_creation_data->key_bitlength = active;

	window = GTK_WINDOW(glade_xml_get_widget (new_req_window_xml, "new_req_window"));
	gtk_object_destroy(GTK_OBJECT(window));

	if (ca_file_is_password_protected())
		csr_creation_data->password = pkey_manage_ask_password();

	new_csr_creation_process_window_display (csr_creation_data);	

}





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

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

#include "ca.h"
#include "ca_file.h"
#include "certificate_properties.h"
#include "csr_properties.h"
#include "tls.h"
#include "new_cert_window.h"

extern GladeXML * main_window_xml;
extern sqlite3 * ca_db;

GtkTreeStore * ca_model = NULL;
gboolean cert_title_inserted = FALSE;
GtkTreeIter * cert_parent_iter = NULL;
GtkTreeIter * last_ca_iter = NULL;
gboolean csr_title_inserted=FALSE;
GtkTreeIter * csr_parent_iter = NULL;



enum {CA_MODEL_COLUMN_ID=0,
      CA_MODEL_COLUMN_IS_CA=1,
      CA_MODEL_COLUMN_SERIAL=2,
      CA_MODEL_COLUMN_SUBJECT=3,
      CA_MODEL_COLUMN_ACTIVATION=4,
      CA_MODEL_COLUMN_EXPIRATION=5,
      CA_MODEL_COLUMN_IS_REVOKED=6,
      CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB=7,
      CA_MODEL_COLUMN_PEM=8,
      CA_MODEL_COLUMN_ITEM_TYPE=9,
      CA_MODEL_COLUMN_NUMBER=10}
CaModelColumns;

enum {CSR_MODEL_COLUMN_ID=0,
      CSR_MODEL_COLUMN_SUBJECT=1,
      CSR_MODEL_COLUMN_PRIVATE_KEY_IN_DB=2,
      CSR_MODEL_COLUMN_PEM=3,
      CSR_MODEL_COLUMN_NUMBER=4}
CsrModelColumns;

void __disable_widget (gchar *widget_name);
void __enable_widget (gchar *widget_name);


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames)
{
	GtkTreeIter iter;
	GtkTreeStore * new_model = GTK_TREE_STORE (pArg);
	
	if (cert_title_inserted == FALSE) {
		gtk_tree_store_insert (new_model, &iter, NULL, 0);
		gtk_tree_store_set (new_model, &iter,
				    3, _("<b>Certificates</b>"),
				    -1);
		last_ca_iter = gtk_tree_iter_copy (&iter);
		cert_parent_iter = gtk_tree_iter_copy (&iter);
		cert_title_inserted = TRUE;
	}

	gtk_tree_store_append (new_model, &iter, last_ca_iter);

	gtk_tree_store_set (new_model, &iter,
			    0, atoi(argv[CA_MODEL_COLUMN_ID]),
			    1, atoi(argv[CA_MODEL_COLUMN_IS_CA]),
			    2, atoll(argv[CA_MODEL_COLUMN_SERIAL]),
			    3, argv[CA_MODEL_COLUMN_SUBJECT],
			    4, atoi(argv[CA_MODEL_COLUMN_ACTIVATION]),
			    5, atoi(argv[CA_MODEL_COLUMN_EXPIRATION]),
			    6, atoi(argv[CA_MODEL_COLUMN_IS_REVOKED]),
			    7, atoi(argv[CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB]),
			    8, argv[CA_MODEL_COLUMN_PEM],
			    9, 0,
			    -1);


	// For now, we only support one only CA
	if (atoi(argv[CA_MODEL_COLUMN_IS_CA]) != 0) {
		last_ca_iter = gtk_tree_iter_copy (&iter);
	}
	
	

	return 0;
}


int __ca_refresh_model_add_csr (void *pArg, int argc, char **argv, char **columnNames)
{
	GtkTreeIter iter;
	GtkTreeStore * new_model = GTK_TREE_STORE(pArg);

	if (csr_title_inserted == 0) {
		gtk_tree_store_insert (new_model, &iter, NULL, 1);
		gtk_tree_store_set (new_model, &iter,
				    3, _("<b>Certificate Signing Requests</b>"),
				    -1);		
		csr_parent_iter = gtk_tree_iter_copy (&iter);
		csr_title_inserted = TRUE;
	}

	
	gtk_tree_store_append (new_model, &iter, csr_parent_iter);

	gtk_tree_store_set (new_model, &iter,
			    0, atoi(argv[CSR_MODEL_COLUMN_ID]),
			    3, argv[CSR_MODEL_COLUMN_SUBJECT],
			    7, atoi(argv[CSR_MODEL_COLUMN_PRIVATE_KEY_IN_DB]),
			    8, argv[CSR_MODEL_COLUMN_PEM],
			    9, 1,
			    -1);

	return 0;
}

void __ca_tree_view_date_datafunc (GtkTreeViewColumn *tree_column,
				   GtkCellRenderer *cell,
				   GtkTreeModel *tree_model,
				   GtkTreeIter *iter,
				   gpointer data)
{
	time_t model_time;
	struct tm model_time_tm;
	gchar model_time_str[100];
	gchar *result = NULL;
	size_t size = 0;       	

	gtk_tree_model_get(tree_model, iter, GPOINTER_TO_INT(data), &model_time, -1);

	if (model_time == 0) {
		g_object_set (G_OBJECT(cell), "text", "", NULL);
		return;
	}
		
	gmtime_r (&model_time, &model_time_tm);
	
	size = strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &model_time_tm);
	result = strdup (model_time_str);

	g_object_set(G_OBJECT(cell), "text", result, NULL);
	
	g_free (result);
}


void __ca_tree_view_serial_datafunc (GtkTreeViewColumn *tree_column,
				     GtkCellRenderer *cell,
				     GtkTreeModel *tree_model,
				     GtkTreeIter *iter,
				     gpointer data)
{
	guint64 serial;
	gchar *result = NULL;
	gchar * aux = NULL;

	gtk_tree_model_get(tree_model, iter, CA_MODEL_COLUMN_SERIAL, &serial, -1);

	if (serial == 0) {
		g_object_set (G_OBJECT(cell), "text", "", NULL);
		return;
	}

	while (serial > 0) {
		if (result) {
			aux = result;
			result = g_strdup_printf ("%02llX:%s", (long long unsigned int) serial%256, aux);
			g_free (aux);
		} else {
			result = g_strdup_printf ("%02llX", (long long unsigned int) serial%256);
		}

		serial = serial >> 8;
	}
	g_object_set(G_OBJECT(cell), "text", result, NULL);
	g_free (result);
}

void __ca_tree_view_is_ca_datafunc (GtkTreeViewColumn *tree_column,
			       GtkCellRenderer *cell,
			       GtkTreeModel *tree_model,
			       GtkTreeIter *iter,
			       gpointer data)
{
	gboolean is_ca;
	gchar *file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "ca-stamp-16.png", NULL);

	static GdkPixbuf * is_ca_pixbuf = NULL;
	static GdkPixbuf * null_pixbuf = NULL;
	GError *gerror = NULL;

	if (is_ca_pixbuf == NULL) {
		is_ca_pixbuf = gdk_pixbuf_new_from_file (file, &gerror);

		if (gerror)
			g_print ("%s\n", gerror->message);
	}

	g_free (file);

	if (null_pixbuf == NULL) {
		null_pixbuf = gdk_pixbuf_new (GDK_COLORSPACE_RGB, TRUE, 8, 1, 1);
	}

	gtk_tree_model_get(tree_model, iter, CA_MODEL_COLUMN_IS_CA, &is_ca, -1);

	if (is_ca) {
		g_object_set (G_OBJECT(cell), "pixbuf", is_ca_pixbuf, NULL);
	} else {
		g_object_set (G_OBJECT(cell), "pixbuf", null_pixbuf, NULL);
	}
}

void __ca_tree_view_private_key_in_db_datafunc (GtkTreeViewColumn *tree_column,
						GtkCellRenderer *cell,
						GtkTreeModel *tree_model,
						GtkTreeIter *iter,
						gpointer data)
{
	gboolean pk_indb;
	gchar *file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "key-16.png", NULL);

	static GdkPixbuf * pk_in_db_pixbuf = NULL;
	static GdkPixbuf * null_pixbuf = NULL;
	GError *gerror = NULL;

	if (pk_in_db_pixbuf == NULL) {
		pk_in_db_pixbuf = gdk_pixbuf_new_from_file (file, &gerror);

		if (gerror)
			g_print ("%s\n", gerror->message);
	}

	g_free (file);

	if (null_pixbuf == NULL) {
		null_pixbuf = gdk_pixbuf_new (GDK_COLORSPACE_RGB, TRUE, 8, 1, 1);
	}

	gtk_tree_model_get(tree_model, iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, -1);

	if (pk_indb) {
		g_object_set (G_OBJECT(cell), "pixbuf", pk_in_db_pixbuf, NULL);
	} else {
		g_object_set (G_OBJECT(cell), "pixbuf", null_pixbuf, NULL);
	}
}



gboolean ca_refresh_model () 
{
	gchar * error_str = NULL;
//	GtkTreeIter iter;
	GtkTreeStore * new_model = NULL;
	GtkTreeView * treeview = NULL;
	GtkCellRenderer * renderer = NULL;


	g_assert (ca_db != NULL);

	/* Models have these columns: 
	     - Id
	     - Is CA
	     - Serial
	     - Subject
	     - Activation
	     - Expiration
	     - Is revoked
	     - Private key is in DB
	     - PEM data
	     - Item type
	*/

	new_model = gtk_tree_store_new (10, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_UINT64, G_TYPE_STRING, 
					G_TYPE_INT, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN, G_TYPE_STRING, G_TYPE_INT);

	cert_title_inserted = FALSE;
	cert_parent_iter = NULL;
	last_ca_iter = NULL;
	csr_title_inserted=FALSE;
	csr_parent_iter = NULL;

	sqlite3_exec (ca_db, "SELECT id, is_ca, serial, subject, activation, expiration, is_revoked, private_key_in_db, pem FROM certificates ORDER BY id",
		     __ca_refresh_model_add_certificate, new_model, &error_str);

	sqlite3_exec (ca_db, "SELECT id, subject, private_key_in_db, pem FROM cert_requests ORDER BY id",
		     __ca_refresh_model_add_csr, new_model, &error_str);

	treeview = GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview"));

	if (ca_model) {
		g_object_unref (ca_model);		
	} else {
		/* There's no model assigned to the treeview yet, so we add its columns */
		
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
							     -1, _("Subject"), renderer,
							     "markup", CA_MODEL_COLUMN_SUBJECT,
							     NULL);
		
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_pixbuf_new ());
		
		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, "", renderer,
							    __ca_tree_view_is_ca_datafunc, NULL, NULL);

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_pixbuf_new ());

		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, "", renderer,
							    __ca_tree_view_private_key_in_db_datafunc, NULL, NULL);

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, _("Serial"), renderer,
							    __ca_tree_view_serial_datafunc, NULL, g_free);
		
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, _("Activation"), renderer,
							    __ca_tree_view_date_datafunc,
							    GINT_TO_POINTER(CA_MODEL_COLUMN_ACTIVATION), g_free);

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, _("Expiration"), renderer,
							    __ca_tree_view_date_datafunc,
							    GINT_TO_POINTER(CA_MODEL_COLUMN_EXPIRATION), g_free);


	}



	gtk_tree_view_set_model (treeview, GTK_TREE_MODEL(new_model));
	ca_model = new_model;

	gtk_tree_view_expand_all (treeview);

	return TRUE;
}

void __ca_certificate_activated (GtkTreeView *tree_view,
			       GtkTreePath *path,
			       GtkTreeViewColumn *column,
			       gpointer user_data)
{	
	GValue * valuestr = g_new0 (GValue, 1);
	GValue * valuebool = g_new0 (GValue, 1);
	GtkTreeIter iter;
	GtkTreeModel * tree_model = gtk_tree_view_get_model (tree_view);
	
	gtk_tree_model_get_iter (tree_model, &iter, path);
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_PEM, valuestr);	
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, valuebool);	

	certificate_properties_display (g_value_get_string(valuestr), g_value_get_boolean(valuebool));

	free (valuestr);
	free (valuebool);
}

void __ca_csr_activated (GtkTreeView *tree_view,
			       GtkTreePath *path,
			       GtkTreeViewColumn *column,
			       gpointer user_data)
{	
	GValue * value = g_new0 (GValue, 1);
	GValue * valuebool = g_new0 (GValue, 1);
	GtkTreeIter iter;
	GtkTreeModel * tree_model = gtk_tree_view_get_model (tree_view);
	
	gtk_tree_model_get_iter (tree_model, &iter, path);
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_PEM, value);	
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, valuebool);	

	csr_properties_display (g_value_get_string(value), g_value_get_boolean (valuebool));

	free (value);
	free (valuebool);
}

void ca_treeview_row_activated (GtkTreeView *tree_view,
				GtkTreePath *path,
				GtkTreeViewColumn *column,
				gpointer user_data)
{
	if (tree_view == NULL) {
			GtkTreeSelection *selection;
			GtkTreeIter selection_iter;
		
			tree_view = GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview"));
			selection = gtk_tree_view_get_selection (tree_view);
		
			if (gtk_tree_selection_count_selected_rows (selection) != 1)
				return;
		
			gtk_tree_selection_get_selected (selection, NULL, &selection_iter); 
			path = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), &selection_iter);

			
	}
	
	GtkTreePath *parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), cert_parent_iter);
	if (gtk_tree_path_is_ancestor (parent, path) && gtk_tree_path_compare (parent, path)) {
		__ca_certificate_activated (tree_view, path, column, user_data);
	} else {
		gtk_tree_path_free (parent);
		
		parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), csr_parent_iter);
		if (gtk_tree_path_is_ancestor (parent, path) && gtk_tree_path_compare (parent, path)) {
			__ca_csr_activated (tree_view, path, column, user_data);
		}
	}
	gtk_tree_path_free (parent);
	
}


void __ca_activate_certificate_selection (GtkTreeIter *iter)
{
	GtkWidget *widget;
	gboolean is_ca = FALSE;
	gboolean pk_indb = FALSE;
	gboolean is_revoked = FALSE;
	
	widget = glade_xml_get_widget (main_window_xml, "actions1");
	gtk_widget_set_sensitive (widget, TRUE);
	widget = glade_xml_get_widget (main_window_xml, "export1");
	gtk_widget_set_sensitive (widget, TRUE);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
			   CA_MODEL_COLUMN_IS_CA, &is_ca, 
			   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
			   CA_MODEL_COLUMN_IS_REVOKED, &is_revoked, -1);
	if (pk_indb) {
		widget = glade_xml_get_widget (main_window_xml, "extractprivatekey1");
		gtk_widget_set_sensitive (widget, TRUE);
	}

	if (! is_revoked) {
		widget = glade_xml_get_widget (main_window_xml, "revoke1");
		gtk_widget_set_sensitive (widget, TRUE);
	}

	widget = glade_xml_get_widget (main_window_xml, "sign1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "delete2");
	gtk_widget_set_sensitive (widget, FALSE);

}

void __ca_activate_csr_selection (GtkTreeIter *iter)
{
	GtkWidget *widget;
	gboolean pk_indb = FALSE;
	
	widget = glade_xml_get_widget (main_window_xml, "actions1");
	gtk_widget_set_sensitive (widget, TRUE);
	widget = glade_xml_get_widget (main_window_xml, "export1");
	gtk_widget_set_sensitive (widget, TRUE);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, -1);
	if (pk_indb) {
		widget = glade_xml_get_widget (main_window_xml, "extractprivatekey1");
		gtk_widget_set_sensitive (widget, TRUE);
	}

	widget = glade_xml_get_widget (main_window_xml, "revoke1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "sign1");
	gtk_widget_set_sensitive (widget, TRUE);

	widget = glade_xml_get_widget (main_window_xml, "delete2");
	gtk_widget_set_sensitive (widget, TRUE);
}

void __ca_deactivate_actions ()
{
	GtkWidget *widget;
	
	widget = glade_xml_get_widget (main_window_xml, "actions1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "export1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "extractprivatekey1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "revoke1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "sign1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "delete2");
	gtk_widget_set_sensitive (widget, FALSE);
}

gint __ca_selection_type (GtkTreeView *tree_view, GtkTreeIter **iter) {

	GtkTreeSelection *selection = gtk_tree_view_get_selection (tree_view);
	GtkTreeIter selection_iter;
	GtkTreePath *parent = NULL;
	GtkTreePath *selection_path = NULL;

	if (gtk_tree_selection_count_selected_rows (selection) != 1)
		return 0;

	gtk_tree_selection_get_selected (selection, NULL, &selection_iter); 
	if (iter)
		(*iter) = gtk_tree_iter_copy (&selection_iter);

	selection_path = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), &selection_iter);
	
	parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), cert_parent_iter);
	if (gtk_tree_path_is_ancestor (parent, selection_path) && gtk_tree_path_compare (parent, selection_path)) {
		gtk_tree_path_free (parent);
		return 1;
	}

	gtk_tree_path_free (parent);
	parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), csr_parent_iter);
	if (gtk_tree_path_is_ancestor (parent, selection_path) && gtk_tree_path_compare (parent, selection_path)) {
		gtk_tree_path_free (parent);
		return 2;
	}

	gtk_tree_path_free (parent);
	return 0;
}

void ca_treeview_selection_change (GtkTreeView *tree_view,
				   gpointer user_data)
{
	GtkTreeIter *selection_iter;
	switch (__ca_selection_type (tree_view, &selection_iter)) {
	case 1:
		__ca_activate_certificate_selection (selection_iter);
		break;
	case 2:
		__ca_activate_csr_selection (selection_iter);
		break;
	case 0:
	default:
		__ca_deactivate_actions();
		break;
	}
}

void __ca_error_dialog (gchar *message) {
   GtkWidget *dialog, *widget;
   
   widget = glade_xml_get_widget (main_window_xml, "main_window1");
   
   /* Create the widgets */
   
   dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
				    GTK_DIALOG_DESTROY_WITH_PARENT,
				    GTK_MESSAGE_ERROR,
				    GTK_BUTTONS_CLOSE,
				    "%s",
				    message);
   
   gtk_dialog_run (GTK_DIALOG(dialog));
   
   gtk_widget_destroy (dialog);

}

void __ca_export_public_pem (GtkTreeIter *iter, gint type)
{
	GtkWidget *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	gchar * pem = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;

	widget = glade_xml_get_widget (main_window_xml, "main_window1");
	
	if (type == 1)
		dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export certificate"),
								  GTK_WINDOW(widget),
								  GTK_FILE_CHOOSER_ACTION_SAVE,
								  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								  GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
								  NULL));
	else
		dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export certificate signing request"),
								  GTK_WINDOW(widget),
								  GTK_FILE_CHOOSER_ACTION_SAVE,
								  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								  GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
								  NULL));
		
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		file = g_io_channel_new_file (filename, "w", &error);
		if (error) {
			gtk_widget_destroy (GTK_WIDGET(dialog));
			if (type == 1)
				__ca_error_dialog (_("There was an error while exporting certificate."));
			else
				__ca_error_dialog (_("There was an error while exporting CSR."));
			return;
		} 

			gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PEM, &pem, -1);			
			g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
			if (error) {
				gtk_widget_destroy (GTK_WIDGET(dialog));
				if (type == 1)
					__ca_error_dialog (_("There was an error while exporting certificate."));
				else
					__ca_error_dialog (_("There was an error while exporting CSR."));
				return;
			} 

			g_io_channel_shutdown (file, TRUE, &error);
			if (error) {
				gtk_widget_destroy (GTK_WIDGET(dialog));
				if (type == 1)
					__ca_error_dialog (_("There was an error while exporting certificate."));
				else
					__ca_error_dialog (_("There was an error while exporting CSR."));
				return;
			} 

			g_io_channel_unref (file);

			gtk_widget_destroy (GTK_WIDGET(dialog));
			if (type == 1)
				dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
									    GTK_DIALOG_DESTROY_WITH_PARENT,
									    GTK_MESSAGE_INFO,
									    GTK_BUTTONS_CLOSE,
									    "%s",
									    _("Certificate exported successfully")));
			else
				dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
									    GTK_DIALOG_DESTROY_WITH_PARENT,
									    GTK_MESSAGE_INFO,
									    GTK_BUTTONS_CLOSE,
									    "%s",
									    _("Certificate signing request exported successfully")));
			gtk_dialog_run (GTK_DIALOG(dialog));
			
			gtk_widget_destroy (GTK_WIDGET(dialog));

		}
}


gchar * ca_dialog_get_password (gchar *info_message, gchar *password_message, gchar *confirm_message, gchar *distinct_error_message, guint minimum_length)
{
	GtkWidget * widget = NULL, * password_widget = NULL;
	//GtkDialog * dialog = NULL;
	GladeXML * dialog_xml = NULL;
	gchar     * xml_file = NULL;
	gint response = 0;
	gchar *password = NULL;
	const gchar *passwordagain = NULL;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "get_password_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	
	
	widget = glade_xml_get_widget (dialog_xml, "info_message");
	gtk_label_set_text (GTK_LABEL(widget), info_message);
	widget = glade_xml_get_widget (dialog_xml, "password_message");
	gtk_label_set_text (GTK_LABEL(widget), password_message);
	widget = glade_xml_get_widget (dialog_xml, "confirm_message");
	gtk_label_set_text (GTK_LABEL(widget), confirm_message);

	password_widget = glade_xml_get_widget (dialog_xml, "password_entry");
	widget = glade_xml_get_widget (dialog_xml, "password_dialog_ok_button");
	g_object_set_data (G_OBJECT(password_widget), "minimum_length", GINT_TO_POINTER(minimum_length));
	g_object_set_data (G_OBJECT(password_widget), "ok_button", widget);

	do {
		gtk_widget_grab_focus (password_widget);

		if (password)
			g_free (password);

		widget = glade_xml_get_widget (dialog_xml, "get_password_dialog");
		response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
		if (!response) {
			gtk_widget_destroy (widget);
			g_object_unref (G_OBJECT(dialog_xml));
			return NULL;
		} else {
			widget = glade_xml_get_widget (dialog_xml, "password_entry");
			password = g_strdup(gtk_entry_get_text (GTK_ENTRY(widget)));
			widget = glade_xml_get_widget (dialog_xml, "confirm_entry");
			passwordagain = gtk_entry_get_text (GTK_ENTRY(widget));
		}
		
		if (strcmp (password, passwordagain)) {
			__ca_error_dialog (distinct_error_message);
		}

	} while (strcmp (password, passwordagain));

	widget = glade_xml_get_widget (dialog_xml, "get_password_dialog");
	gtk_widget_destroy (widget);
	g_object_unref (G_OBJECT(dialog_xml));
	
	return password;
}

void ca_password_entry_changed_cb (GtkEditable *password_entry, gpointer user_data)
{
	GtkWidget * button = GTK_WIDGET(g_object_get_data (G_OBJECT(password_entry), "ok_button"));
	guint minimum_length = GPOINTER_TO_INT (g_object_get_data (G_OBJECT(password_entry), "minimum_length"));

	if (strlen (gtk_entry_get_text (GTK_ENTRY(password_entry))) >= minimum_length)
		gtk_widget_set_sensitive (button, TRUE);
	else
		gtk_widget_set_sensitive (button, FALSE);
	
}


void __ca_export_private_pkcs8 (GtkTreeIter *iter, gint type)
{
	GtkWidget *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	gchar * password = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;
	gint id;
	gchar ** privatekey = NULL;
	gchar * pem = NULL;

	widget = glade_xml_get_widget (main_window_xml, "main_window1");
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export crypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
							  GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
							  NULL));
		
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		return;
	}

	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	password = ca_dialog_get_password (_("You need to supply a passphrase for protecting the exported private key, "
					     "so nobody else but authorized people can use it. This passphrase will be asked "
					     "by any application that will make use of the private key."),
					   _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"), 
					   _("The introduced passphrases are distinct."), 8);
	if (! password) {
		g_free (filename);
		return;
	}
	
	file = g_io_channel_new_file (filename, "w", &error);
	g_free (filename);
	if (error) {
		__ca_error_dialog (_("There was an error while exporting private key."));
		g_free (password);
		return;
	} 
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		
	if (type == 1)
		privatekey = ca_file_get_single_row ("SELECT private_key FROM certificates WHERE id=%d", id);
	else
		privatekey = ca_file_get_single_row ("SELECT private_key FROM cert_requests WHERE id=%d", id);
		
	
	if (!privatekey) {
		__ca_error_dialog (_("There was an error while getting private key."));
		g_free (password);
		return;
	}
	
	pem = tls_generate_pkcs8_encrypted_private_key (privatekey[0], password); 
	g_free (password);
	g_strfreev (privatekey);
	
	if (!pem) {
		__ca_error_dialog (_("There was an error while password-protecting private key."));
		return;
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		__ca_error_dialog (_("There was an error while exporting private key."));
		return;
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		__ca_error_dialog (_("There was an error while exporting private key."));
		g_io_channel_unref (file);
		return;
	} 
	
	g_io_channel_unref (file);
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_INFO,
						    GTK_BUTTONS_CLOSE,
						    "%s",
						    _("Private key exported successfully")));
	gtk_dialog_run (GTK_DIALOG(dialog));
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	
}


void __ca_export_private_pem (GtkTreeIter *iter, gint type)
{
	GtkWidget *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;
	gint id;
	gchar ** privatekey = NULL;
	gchar * pem = NULL;

	widget = glade_xml_get_widget (main_window_xml, "main_window1");
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export uncrypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
							  GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
							  NULL));
		
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		return;
	}

	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	file = g_io_channel_new_file (filename, "w", &error);
	g_free (filename);
	if (error) {
		__ca_error_dialog (_("There was an error while exporting private key."));
		return;
	} 
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		
	if (type == 1)
		privatekey = ca_file_get_single_row ("SELECT private_key FROM certificates WHERE id=%d", id);
	else
		privatekey = ca_file_get_single_row ("SELECT private_key FROM cert_requests WHERE id=%d", id);
		
	
	if (!privatekey) {
		__ca_error_dialog (_("There was an error while getting private key."));
		return;
	}
	
	pem = g_strdup (privatekey[0]);
	g_strfreev (privatekey);
	
	if (!pem) {
		__ca_error_dialog (_("There was an error while password-protecting private key."));
		return;
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		__ca_error_dialog (_("There was an error while exporting private key."));
		return;
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		__ca_error_dialog (_("There was an error while exporting private key."));
		g_io_channel_unref (file);
		return;
	} 
	
	g_io_channel_unref (file);
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_INFO,
						    GTK_BUTTONS_CLOSE,
						    "%s",
						    _("Private key exported successfully")));
	gtk_dialog_run (GTK_DIALOG(dialog));
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	
}


void ca_on_export1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget * widget = NULL;
	//GtkDialog * dialog = NULL;
	GtkTreeIter *iter;	
	gint type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);
	GladeXML * dialog_xml = NULL;
	gchar     * xml_file = NULL;
	gboolean has_pk_in_db = FALSE;
	gint response = 0;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "export_certificate_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &has_pk_in_db, -1);			
	if (has_pk_in_db) {
		widget = glade_xml_get_widget (dialog_xml, "privatepart_radiobutton2");
		gtk_widget_set_sensitive (widget, TRUE);
	}

	widget = glade_xml_get_widget (dialog_xml, "export_certificate_dialog");

	response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
	if (!response || response == GTK_RESPONSE_CANCEL) {
		gtk_widget_destroy (widget);
		g_object_unref (G_OBJECT(dialog_xml));
		return;
	} 
	
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (glade_xml_get_widget (dialog_xml, "publicpart_radiobutton1")))) {
		/* Export public part */
		__ca_export_public_pem (iter, type);
		gtk_widget_destroy (widget);
		g_object_unref (G_OBJECT(dialog_xml));
		
		return;
	}
	
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (glade_xml_get_widget (dialog_xml, "privatepart_radiobutton2")))) {
		/* Export private part (crypted) */
		__ca_export_private_pkcs8 (iter, type);
		gtk_widget_destroy (widget);
		g_object_unref (G_OBJECT(dialog_xml));
		
		return;
	}

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (glade_xml_get_widget (dialog_xml, "privatepart_uncrypted_radiobutton2")))) {
		/* Export private part (uncrypted) */
		__ca_export_private_pem (iter, type);
		gtk_widget_destroy (widget);
		g_object_unref (G_OBJECT(dialog_xml));
		
		return;
	}
	
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (glade_xml_get_widget (dialog_xml, "bothparts_radiobutton3")))) {
		/* Export PKCS#12 structure */
		ca_todo_callback ();
/* 			gtk_widget_destroy (widget); */
/* 			g_object_unref (G_OBJECT(dialog_xml)); */
		
		return;
	}
	
	gtk_widget_destroy (widget);
	g_object_unref (G_OBJECT(dialog_xml));
	__ca_error_dialog (_("Unexpected error"));
}

void ca_todo_callback ()
{
	__ca_error_dialog (_("To do. Feature not implemented yet."));
}

void ca_on_delete2_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget * widget = NULL;
	GtkDialog * dialog = NULL;
	GtkTreeIter *iter;	
	gint type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);
	gint response = 0;
	gint id = 0;

	if (type != 2)
		return;
	
	widget = glade_xml_get_widget (main_window_xml, "main_window1");
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_QUESTION,
						    GTK_BUTTONS_YES_NO,
						    "%s",
						    _("Are you sure you want to delete this Certificate Signing Request?")));

	response = gtk_dialog_run(dialog);
	gtk_widget_destroy (GTK_WIDGET(dialog));

	if (response == GTK_RESPONSE_NO) {
		return;
	}

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);			
	ca_file_remove_csr (id);

	ca_refresh_model ();
}

void ca_on_sign1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTreeIter *iter;

	gint type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);
	gchar * csr_pem;

	if (type != 2)
		return;
		
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PEM, &csr_pem, -1);

	new_cert_window_display (csr_pem);
	
	g_free (csr_pem);
}



gboolean ca_open (gchar *filename) 
{
	if (! ca_file_open (filename))
		return FALSE;

	__enable_widget ("new_certificate1");
	__enable_widget ("save_as1");
	__enable_widget ("properties1");
	__enable_widget ("preferences1");


	ca_refresh_model ();
	
	
	return TRUE;
}

gint ca_get_selected_row_id ()
{
	GtkTreeIter *iter;
	gint result;

	gint type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &result, -1);

	type = 0;
	return result;
}

gchar * ca_get_selected_row_pem ()
{
	GtkTreeIter *iter;
	gchar * result;

	gint type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PEM, &result, -1);
	
	type = 0;
	return result;
}

gboolean ca_import (gchar *filename) 
{	
	// We start to check each type of file, in PEM and DER
	// formats, for see if some of them matches with the actual file

	// Certificate request


	// Certificate list

	// Single certificate

	// Private key without password

	// Certificate revocation list
	
	// PKCS7 structure
	
	ca_todo_callback ();
	
	return TRUE;

}


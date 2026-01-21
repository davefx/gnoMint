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
#include <gdk/gdk.h>
#include <glib/gi18n.h>

#endif

#include <stdlib.h>
#include <string.h>


#include "ca.h"
#include "ca_file.h"
#include "certificate_properties.h"
#include "crl.h"
#include "csr_properties.h"
#include "dialog.h"
#include "export.h"
#include "new_ca_window.h"
#include "new_req_window.h"
#include "new_cert.h"
#include "preferences-gui.h"
#include "preferences-window.h"
#include "import.h"

#ifndef GNOMINTCLI

#define GNOMINT_MIME_TYPE "application/x-gnomint"


enum {CA_MODEL_COLUMN_ID=0,
      CA_MODEL_COLUMN_IS_CA=1,
      CA_MODEL_COLUMN_SERIAL=2,
      CA_MODEL_COLUMN_SUBJECT=3,
      CA_MODEL_COLUMN_ACTIVATION=4,
      CA_MODEL_COLUMN_EXPIRATION=5,
      CA_MODEL_COLUMN_REVOCATION=6,
      CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB=7,
      CA_MODEL_COLUMN_PEM=8,
      CA_MODEL_COLUMN_DN=9,
      CA_MODEL_COLUMN_PARENT_DN=10,
      CA_MODEL_COLUMN_PARENT_ROUTE=11,
      CA_MODEL_COLUMN_ITEM_TYPE=12,
      CA_MODEL_COLUMN_PARENT_ID=13, /* Only for CSRs */
      CA_MODEL_COLUMN_NUMBER=14}
        CaModelColumns;

enum {CSR_MODEL_COLUMN_ID=0,
      CSR_MODEL_COLUMN_SUBJECT=1,
      CSR_MODEL_COLUMN_PRIVATE_KEY_IN_DB=2,
      CSR_MODEL_COLUMN_PEM=3,
      CSR_MODEL_COLUMN_PARENT_ID=4,
      CSR_MODEL_COLUMN_NUMBER=5}
        CsrModelColumns;




extern GtkBuilder * main_window_gtkb;
extern GtkBuilder * cert_popup_menu_gtkb;
extern GtkBuilder * csr_popup_menu_gtkb;


static GtkTreeStore * ca_model = NULL;
static gboolean cert_title_inserted = FALSE;
static GtkTreeIter * cert_parent_iter = NULL;
static GtkTreeIter * last_parent_iter = NULL;
static GtkTreeIter * last_cert_iter = NULL;
static gboolean csr_title_inserted=FALSE;
static GtkTreeIter * csr_parent_iter = NULL;

static gboolean view_csr = TRUE;
static gboolean view_rcrt = TRUE;


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames);
int __ca_refresh_model_add_csr (void *pArg, int argc, char **argv, char **columnNames);
void __ca_tree_view_date_datafunc (GtkTreeViewColumn *tree_column,
				   GtkCellRenderer *cell,
				   GtkTreeModel *tree_model,
				   GtkTreeIter *iter,
				   gpointer data);
void __ca_tree_view_is_ca_datafunc (GtkTreeViewColumn *tree_column,
                                    GtkCellRenderer *cell,
                                    GtkTreeModel *tree_model,
                                    GtkTreeIter *iter,
                                    gpointer data);
void __ca_tree_view_private_key_in_db_datafunc (GtkTreeViewColumn *tree_column,
						GtkCellRenderer *cell,
						GtkTreeModel *tree_model,
						GtkTreeIter *iter,
						gpointer data);
void __ca_certificate_activated (GtkTreeView *tree_view,
                                 GtkTreePath *path,
                                 GtkTreeViewColumn *column,
                                 gpointer user_data);
void __ca_csr_activated (GtkTreeView *tree_view,
                         GtkTreePath *path,
                         GtkTreeViewColumn *column,
                         gpointer user_data);
void __ca_activate_certificate_selection (GtkTreeIter *iter);
void __ca_activate_csr_selection (GtkTreeIter *iter);
void __ca_deactivate_actions (void);
gint __ca_selection_type (GtkTreeView *tree_view, GtkTreeIter **iter);
void __ca_export_public_pem (GtkTreeIter *iter, gint type);
gchar * __ca_export_private_pkcs8 (GtkTreeIter *iter, gint type);
void __ca_export_private_pem (GtkTreeIter *iter, gint type);
void __ca_export_pkcs12 (GtkTreeIter *iter, gint type);

void __disable_widget (gchar *widget_name);
void __enable_widget (gchar *widget_name);


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames)
{
	GtkTreeIter iter;
	GtkTreeStore * new_model = GTK_TREE_STORE (pArg);
	GValue *last_id_value = g_new0 (GValue, 1);
	GValue *last_parent_route_value = g_new0 (GValue, 1);
        guint64 uint64_value;
	const gchar * string_value;
	gchar * last_node_route = NULL;
	
	if (cert_title_inserted == FALSE) {
		gtk_tree_store_append (new_model, &iter, NULL);
		gtk_tree_store_set (new_model, &iter,
				    3, _("<b>Certificates</b>"),
				    -1);
		cert_parent_iter = gtk_tree_iter_copy (&iter);
		cert_title_inserted = TRUE;
	}

	if (! last_cert_iter || (! strcmp (argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE],":"))) {
		if (last_parent_iter)
			gtk_tree_iter_free (last_parent_iter);
		last_parent_iter = NULL;
	} else {
		// If not, then we must find the parent of the current node
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_cert_iter, CA_MODEL_COLUMN_ID, last_id_value);
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_cert_iter, CA_MODEL_COLUMN_PARENT_ROUTE, 
					  last_parent_route_value);
		
		uint64_value = g_value_get_uint64 (last_id_value);
		string_value = g_value_get_string (last_parent_route_value);
                g_assert (string_value);

		last_node_route = g_strdup_printf ("%s%"G_GUINT64_FORMAT":", string_value, uint64_value);

		if (! strcmp (argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE], last_node_route)) {
			// Last node is parent of the current node
			if (last_parent_iter)
				gtk_tree_iter_free (last_parent_iter);
			last_parent_iter = gtk_tree_iter_copy (last_cert_iter);
			g_free (last_node_route);
			last_node_route = NULL;
		} else {
			// We go back in the hierarchical tree, starting in the current parent, until we find the parent of the
			// current certificate.
			
			if (last_parent_iter)
                                gtk_tree_iter_free (last_parent_iter);
                        last_parent_iter = gtk_tree_iter_copy (last_cert_iter);

			while (last_node_route && 
			       strcmp (argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE], last_node_route)) {
				
				g_free (last_node_route);
				last_node_route = NULL;

				if (! gtk_tree_model_iter_parent(GTK_TREE_MODEL(new_model), &iter, last_parent_iter)) {
					// Last ca iter is a top_level
					if (last_parent_iter)
						gtk_tree_iter_free (last_parent_iter);
					last_parent_iter = NULL;
				} else {
					if (last_parent_iter)
						gtk_tree_iter_free (last_parent_iter);
					last_parent_iter = gtk_tree_iter_copy (&iter);

					g_value_unset (last_parent_route_value);
					g_value_unset (last_id_value);
					
					gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_parent_iter, CA_MODEL_COLUMN_ID, last_id_value);
					gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_parent_iter, CA_MODEL_COLUMN_PARENT_ROUTE, 
								  last_parent_route_value);
					
					uint64_value = g_value_get_uint64 (last_id_value);
					string_value = g_value_get_string (last_parent_route_value);
					if (string_value != NULL)
						last_node_route = g_strdup_printf ("%s%"G_GUINT64_FORMAT":", string_value, uint64_value);
					else 
						last_node_route = NULL;
				}

			}

			if (last_node_route)
				g_free (last_node_route);
		}
	
	}
	
	gtk_tree_store_append (new_model, &iter, (last_parent_iter ? last_parent_iter: cert_parent_iter));

        if (! argv[CA_FILE_CERT_COLUMN_REVOCATION])        
                gtk_tree_store_set (new_model, &iter,
                                    CA_MODEL_COLUMN_ID, atoll(argv[CA_FILE_CERT_COLUMN_ID]),
                                    CA_MODEL_COLUMN_IS_CA, atoi(argv[CA_FILE_CERT_COLUMN_IS_CA]),
                                    CA_MODEL_COLUMN_SERIAL, argv[CA_FILE_CERT_COLUMN_SERIAL],
                                    CA_MODEL_COLUMN_SUBJECT, argv[CA_FILE_CERT_COLUMN_SUBJECT],
                                    CA_MODEL_COLUMN_ACTIVATION, atoi(argv[CA_FILE_CERT_COLUMN_ACTIVATION]),
                                    CA_MODEL_COLUMN_EXPIRATION, atoi(argv[CA_FILE_CERT_COLUMN_EXPIRATION]),
                                    CA_MODEL_COLUMN_REVOCATION, 0,
                                    CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, atoi(argv[CA_FILE_CERT_COLUMN_PRIVATE_KEY_IN_DB]),
                                    CA_MODEL_COLUMN_PEM, argv[CA_FILE_CERT_COLUMN_PEM],
				    CA_MODEL_COLUMN_DN, argv[CA_FILE_CERT_COLUMN_DN],
				    CA_MODEL_COLUMN_PARENT_DN, argv[CA_FILE_CERT_COLUMN_PARENT_DN],
				    CA_MODEL_COLUMN_PARENT_ROUTE, argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE],
                                    CA_MODEL_COLUMN_ITEM_TYPE, 0,
                                    -1);
        else {
                gchar * revoked_subject = g_markup_printf_escaped ("<s>%s</s>", 
                                                                   argv[CA_FILE_CERT_COLUMN_SUBJECT]);

                gtk_tree_store_set (new_model, &iter,
                                    CA_MODEL_COLUMN_ID, atoll(argv[CA_FILE_CERT_COLUMN_ID]),
                                    CA_MODEL_COLUMN_IS_CA, atoi(argv[CA_FILE_CERT_COLUMN_IS_CA]),
                                    CA_MODEL_COLUMN_SERIAL, argv[CA_FILE_CERT_COLUMN_SERIAL],
                                    CA_MODEL_COLUMN_SUBJECT, revoked_subject,
                                    CA_MODEL_COLUMN_ACTIVATION, atoi(argv[CA_FILE_CERT_COLUMN_ACTIVATION]),
                                    CA_MODEL_COLUMN_EXPIRATION, atoi(argv[CA_FILE_CERT_COLUMN_EXPIRATION]),
                                    CA_MODEL_COLUMN_REVOCATION, atoi(argv[CA_FILE_CERT_COLUMN_REVOCATION]),
                                    CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, atoi(argv[CA_FILE_CERT_COLUMN_PRIVATE_KEY_IN_DB]),
                                    CA_MODEL_COLUMN_PEM, argv[CA_FILE_CERT_COLUMN_PEM],
				    CA_MODEL_COLUMN_DN, argv[CA_FILE_CERT_COLUMN_DN],
				    CA_MODEL_COLUMN_PARENT_DN, argv[CA_FILE_CERT_COLUMN_PARENT_DN],
				    CA_MODEL_COLUMN_PARENT_ROUTE, argv[CA_FILE_CERT_COLUMN_PARENT_ROUTE],
                                    CA_MODEL_COLUMN_ITEM_TYPE, 0,
                                    -1);

                g_free (revoked_subject);
        }


	if (last_cert_iter)
		gtk_tree_iter_free (last_cert_iter);
	last_cert_iter = gtk_tree_iter_copy (&iter);
 
	g_free (last_id_value);
	g_free (last_parent_route_value);      	

	return 0;
}



int __ca_refresh_model_add_csr (void *pArg, int argc, char **argv, char **columnNames)
{
	GtkTreeIter iter;
	GtkTreeStore * new_model = GTK_TREE_STORE(pArg);

	if (csr_title_inserted == 0) {
		gtk_tree_store_append (new_model, &iter, NULL);
		gtk_tree_store_set (new_model, &iter,
				    3, _("<b>Certificate Signing Requests</b>"),
				    -1);		
		csr_parent_iter = gtk_tree_iter_copy (&iter);
		csr_title_inserted = TRUE;
	}

	
	gtk_tree_store_append (new_model, &iter, csr_parent_iter);

        gtk_tree_store_set (new_model, &iter,
                            CA_MODEL_COLUMN_ID, atoll(argv[CA_FILE_CSR_COLUMN_ID]),
                            CA_MODEL_COLUMN_SUBJECT, argv[CA_FILE_CSR_COLUMN_SUBJECT],
                            CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, atoi(argv[CA_FILE_CSR_COLUMN_PRIVATE_KEY_IN_DB]),
                            CA_MODEL_COLUMN_PEM, argv[CA_FILE_CSR_COLUMN_PEM],
                            CA_MODEL_COLUMN_PARENT_ID, argv[CA_FILE_CSR_COLUMN_PARENT_ID],
                            CA_MODEL_COLUMN_ITEM_TYPE, 1,
                            -1);
	return 0;
}

void __ca_tree_view_date_datafunc (GtkTreeViewColumn *tree_column,
				   GtkCellRenderer *cell,
				   GtkTreeModel *tree_model,
				   GtkTreeIter *iter,
				   gpointer data)
{
	time_t model_time = 0;
#ifndef WIN32
	struct tm model_time_tm;
#else
	struct tm *model_time_tm = NULL;
#endif
	gchar model_time_str[100];
	gchar *result = NULL;

	gtk_tree_model_get(tree_model, iter, GPOINTER_TO_INT(data), &model_time, -1);

	if (model_time == 0) {
		g_object_set (G_OBJECT(cell), "text", "", NULL);
		return;
	}
#ifndef WIN32	
	gmtime_r (&model_time, &model_time_tm);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &model_time_tm);
#else
	model_time_tm = gmtime(&model_time);
	strftime(model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), model_time_tm);
#endif

	result = g_strdup (model_time_str);

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



gboolean ca_refresh_model_callback () 
{
	GtkTreeStore * new_model = NULL;
	GtkTreeView * treeview = NULL;
	GtkCellRenderer * renderer = NULL;
        GtkTreeViewColumn * column = NULL;
                 
        guint columns_number;

	/* Models have these columns: 
           - Id
           - Is CA
           - Serial
           - Subject
           - Activation
           - Expiration
           - Revocation
           - Private key is in DB
           - PEM data
           - DN
           - Parent DN
           - Parent route
           - Item type
           - Parent ID (only for CSR)
	*/

	new_model = gtk_tree_store_new (CA_MODEL_COLUMN_NUMBER, G_TYPE_UINT64, G_TYPE_BOOLEAN, G_TYPE_STRING, G_TYPE_STRING, 
					G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_STRING, 
					G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	cert_title_inserted = FALSE;
	cert_parent_iter = NULL;
	last_parent_iter = NULL;
	last_cert_iter = NULL;
	csr_title_inserted=FALSE;
	csr_parent_iter = NULL;

	ca_file_foreach_crt (__ca_refresh_model_add_certificate, view_rcrt, new_model);
          
        if (view_csr)
		ca_file_foreach_csr (__ca_refresh_model_add_csr, new_model);

	treeview = GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview"));

	if (ca_model) {
                GList * column_list;
		g_object_unref (ca_model);		

                // Remove revocation column
                column_list = gtk_tree_view_get_columns (treeview);
                columns_number = g_list_length (column_list);
                g_list_free (column_list);
        
                
	} else {
/*                 GtkTooltips * table_tooltips = gtk_tooltips_new(); */
          
		/* There's no model assigned to the treeview yet, so we add its columns */
		
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
							     -1, _("Subject"), renderer,
							     "markup", CA_MODEL_COLUMN_SUBJECT,
							     NULL);
		
/*                 gtk_tooltips_set_tip (table_tooltips, GTK_WIDGET(gtk_tree_view_get_column(treeview, column_number - 1)),  */
/*                                       _("Subject of the certificate or request"),  */
/*                                       _("This is the distinguished name (DN) of the certificate or request")); */

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_pixbuf_new ());
		
		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, "", renderer,
							    __ca_tree_view_is_ca_datafunc, 
							    NULL, NULL);

/*                 gtk_tooltips_set_tip (table_tooltips, GTK_WIDGET(gtk_tree_view_get_column(treeview, column_number - 1)),  */
/*                                       _("It's a CA certificate"),  */
/*                                       _("An icon in this column shows that the certificate is able to generate and sign " */
/*                                         "new certificates.")); */

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_pixbuf_new ());

		gtk_tree_view_insert_column_with_data_func (treeview,
							    -1, "", renderer,
							    __ca_tree_view_private_key_in_db_datafunc, 
							    NULL, NULL);

/*                 gtk_tooltips_set_tip (table_tooltips, GTK_WIDGET(gtk_tree_view_get_column(treeview, column_number - 1)),  */
/*                                       _("Private key kept in internal database"),  */
/*                                       _("An icon in this column shows that the private key related to the certificate " */
/*                                         "is kept in the gnoMint database.")); */

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
                                                             -1, _("Serial"), renderer,
                                                             "markup", CA_MODEL_COLUMN_SERIAL, 
                                                             NULL);
		
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

                renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());
                
                columns_number = gtk_tree_view_insert_column_with_data_func (treeview,
                                                                             -1, _("Revocation"), renderer,
                                                                             __ca_tree_view_date_datafunc,
                                                                             GINT_TO_POINTER(CA_MODEL_COLUMN_REVOCATION), 
                                                                             g_free);
                

	}

        column = gtk_tree_view_get_column(treeview, columns_number - 1);

        gtk_tree_view_column_set_visible (column, view_rcrt);        

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
        GValue * valueid = g_new0 (GValue, 1);
	GValue * valuestr = g_new0 (GValue, 1);
	GValue * value_pkey_in_db = g_new0 (GValue, 1);
	GValue * value_is_ca = g_new0 (GValue, 1);
	GtkTreeIter iter;
	GtkTreeModel * tree_model = gtk_tree_view_get_model (tree_view);
	
	gtk_tree_model_get_iter (tree_model, &iter, path);
        gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_ID, valueid);
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_PEM, valuestr);	
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, value_pkey_in_db);	
	gtk_tree_model_get_value (tree_model, &iter, CA_MODEL_COLUMN_IS_CA, value_is_ca);	

	certificate_properties_display (g_value_get_uint64 (valueid),
                                        g_value_get_string(valuestr), g_value_get_boolean(value_pkey_in_db),
					g_value_get_boolean (value_is_ca));

	g_free (valuestr);
	g_free (value_pkey_in_db);
	g_free (value_is_ca);
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



G_MODULE_EXPORT gboolean ca_treeview_row_activated (GtkTreeView *tree_view,
				    GtkTreePath *path,
				    GtkTreeViewColumn *column,
				    gpointer user_data)
{

        GtkTreePath *parent = NULL;
	
        if (tree_view == NULL) {
                GtkTreeSelection *selection;
                GtkTreeIter selection_iter;
		
                tree_view = GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview"));
                selection = gtk_tree_view_get_selection (tree_view);
		
                if (gtk_tree_selection_count_selected_rows (selection) != 1)
                        return FALSE;
		
                gtk_tree_selection_get_selected (selection, NULL, &selection_iter); 
                path = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), &selection_iter);

			
	}
	
	parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), cert_parent_iter);
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
	
	return FALSE;
	
}


void __ca_activate_certificate_selection (GtkTreeIter *iter)
{
	GObject *widget;
	gboolean is_ca = FALSE;
	gboolean pk_indb = FALSE;
	gint is_revoked = FALSE;
	
	widget = gtk_builder_get_object (main_window_gtkb, "export1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
			   CA_MODEL_COLUMN_IS_CA, &is_ca, 
			   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
			   CA_MODEL_COLUMN_REVOCATION, &is_revoked, -1);

	widget = gtk_builder_get_object (main_window_gtkb, "extractprivatekey1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), pk_indb);
	widget = gtk_builder_get_object (main_window_gtkb, "extractpkey_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), pk_indb);

        widget = gtk_builder_get_object (main_window_gtkb, "revoke1");
        gtk_widget_set_sensitive (GTK_WIDGET(widget), (! is_revoked));
        widget = gtk_builder_get_object (main_window_gtkb, "revoke_toolbutton");
        gtk_widget_set_sensitive (GTK_WIDGET(widget), (! is_revoked));


	widget = gtk_builder_get_object (main_window_gtkb, "sign1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "sign_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "delete2");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "delete_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "properties1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);


}

void __ca_activate_csr_selection (GtkTreeIter *iter)
{
	GObject *widget;
	gboolean pk_indb = FALSE;
	
	widget = gtk_builder_get_object (main_window_gtkb, "export1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, -1);

	widget = gtk_builder_get_object (main_window_gtkb, "extractprivatekey1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), pk_indb);
	widget = gtk_builder_get_object (main_window_gtkb, "extractpkey_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), pk_indb);

	widget = gtk_builder_get_object (main_window_gtkb, "revoke1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "revoke_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "sign1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
	widget = gtk_builder_get_object (main_window_gtkb, "sign_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

	widget = gtk_builder_get_object (main_window_gtkb, "delete2");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
	widget = gtk_builder_get_object (main_window_gtkb, "delete_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

	widget = gtk_builder_get_object (main_window_gtkb, "properties1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
}

void __ca_deactivate_actions ()
{
	GObject *widget;
	
	widget = gtk_builder_get_object (main_window_gtkb, "export1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "extractprivatekey1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "extractpkey_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "revoke1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "revoke_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "sign1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "sign_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "delete2");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	widget = gtk_builder_get_object (main_window_gtkb, "delete_toolbutton");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	widget = gtk_builder_get_object (main_window_gtkb, "properties1");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
}

gint __ca_selection_type (GtkTreeView *tree_view, GtkTreeIter **iter) {

	GtkTreeSelection *selection = gtk_tree_view_get_selection (tree_view);
	GtkTreeIter selection_iter;
	GtkTreePath *parent = NULL;
	GtkTreePath *selection_path = NULL;

	if (gtk_tree_selection_count_selected_rows (selection) != 1)
		return -1;

	gtk_tree_selection_get_selected (selection, NULL, &selection_iter); 
	if (iter)
		(*iter) = gtk_tree_iter_copy (&selection_iter);

	selection_path = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), &selection_iter);
	
	if (cert_parent_iter) {
		parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), cert_parent_iter);
		if (gtk_tree_path_is_ancestor (parent, selection_path) && gtk_tree_path_compare (parent, selection_path)) {
			gtk_tree_path_free (parent);
			gtk_tree_path_free (selection_path);
			/* It's a certificate */
			return CA_FILE_ELEMENT_TYPE_CERT;
		}
		gtk_tree_path_free (parent);
	}

	if (csr_parent_iter) {
		parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), csr_parent_iter);
		if (gtk_tree_path_is_ancestor (parent, selection_path) && gtk_tree_path_compare (parent, selection_path)) {
			gtk_tree_path_free (parent);
			gtk_tree_path_free (selection_path);
			/* It's a CSR */
			return CA_FILE_ELEMENT_TYPE_CSR;
		}
		gtk_tree_path_free (parent);
	}

	gtk_tree_path_free (selection_path);
	return -1;
}

G_MODULE_EXPORT gboolean ca_treeview_selection_change (GtkTreeView *tree_view,
				       gpointer user_data)
{
	GtkTreeIter *selection_iter = NULL;
	switch (__ca_selection_type (tree_view, &selection_iter)) {
	case CA_FILE_ELEMENT_TYPE_CERT:
		__ca_activate_certificate_selection (selection_iter);
		gtk_tree_iter_free (selection_iter);
		break;
	case CA_FILE_ELEMENT_TYPE_CSR:
		__ca_activate_csr_selection (selection_iter);
		gtk_tree_iter_free (selection_iter);
		break;
	case -1:
	default:
		if (selection_iter)
			gtk_tree_iter_free (selection_iter);
		__ca_deactivate_actions();
		break;
	}

	return FALSE;
}


void __ca_export_public_pem (GtkTreeIter *iter, gint type)
{
	GObject *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	gchar * pem = NULL;
	gchar * parent_route = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	
	if (type == 1)
		dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export certificate"),
								  GTK_WINDOW(widget),
								  GTK_FILE_CHOOSER_ACTION_SAVE,
								  _("_Cancel"), GTK_RESPONSE_CANCEL,
								  _("_Save"), GTK_RESPONSE_ACCEPT,
								  NULL));
	else
		dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export certificate signing request"),
								  GTK_WINDOW(widget),
								  GTK_FILE_CHOOSER_ACTION_SAVE,
								  _("_Cancel"), GTK_RESPONSE_CANCEL,
								  _("_Save"), GTK_RESPONSE_ACCEPT,
								  NULL));
		
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		file = g_io_channel_new_file (filename, "w", &error);
		if (error) {
			gtk_widget_destroy (GTK_WIDGET(dialog));
			if (type == 1)
				dialog_error (_("There was an error while exporting certificate."));
			else
				dialog_error (_("There was an error while exporting CSR."));
			return;
		} 

                gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PEM, &pem, -1);
                if (type == 1)
			gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PARENT_ROUTE, &parent_route, -1);
			
                g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);

		if (parent_route && strcmp (parent_route, ":")) {
			// The parent of the certificate is in the data base.
			// We then export all the certificates up to the root, after the given certificate
			// so it can be validated

			gchar ** tokens = g_strsplit (parent_route, ":", -1);
			// First and last tokens are always empty, as all parent ids start and end by ':'
			guint num_tokens = g_strv_length (tokens) - 2;
			gint i;

			for (i=num_tokens; i>=1; i--) {
				gchar * parent_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, atoll(tokens[i]));
				if (parent_pem) {
					g_io_channel_write_chars (file, parent_pem, strlen(parent_pem), NULL, &error);
					g_free (parent_pem);		
				}		
			}

			g_strfreev (tokens);
		}

                if (error) {
                        gtk_widget_destroy (GTK_WIDGET(dialog));
                        if (type == CA_FILE_ELEMENT_TYPE_CERT)
                                dialog_error (_("There was an error while exporting certificate."));
                        else
                                dialog_error (_("There was an error while exporting CSR."));
                        return;
                } 

                g_io_channel_shutdown (file, TRUE, &error);
                if (error) {
                        gtk_widget_destroy (GTK_WIDGET(dialog));
                        if (type == CA_FILE_ELEMENT_TYPE_CERT)
                                dialog_error (_("There was an error while exporting certificate."));
                        else
                                dialog_error (_("There was an error while exporting CSR."));
                        return;
                } 

                g_io_channel_unref (file);

                gtk_widget_destroy (GTK_WIDGET(dialog));
                if (type == CA_FILE_ELEMENT_TYPE_CERT)
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


gchar * __ca_export_private_pkcs8 (GtkTreeIter *iter, gint type)
{
	GObject *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	gint id;
	gchar * strerror = NULL;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export crypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));
		
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		return NULL;
	}

	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		
	
	strerror = export_private_pkcs8 (id, type, filename);

	if (! strerror) {
	
		dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
							    GTK_DIALOG_DESTROY_WITH_PARENT,
							    GTK_MESSAGE_INFO,
							    GTK_BUTTONS_CLOSE,
							    "%s",
							    _("Private key exported successfully")));
		gtk_dialog_run (GTK_DIALOG(dialog));
		
		gtk_widget_destroy (GTK_WIDGET(dialog));
	} else {
		dialog_error (strerror);
	}

	return filename;
}


void __ca_export_private_pem (GtkTreeIter *iter, gint type)
{
	GObject *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	gint id;
        gchar * error_msg = NULL;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Export uncrypted private key"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));
        
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		return;
	}
        
	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		
	
        error_msg = export_private_pem (id, type, filename);
        g_free (filename);

        if (error_msg) {
                dialog_error (error_msg);
        } else {
                dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
                                                            GTK_DIALOG_DESTROY_WITH_PARENT,
                                                            GTK_MESSAGE_INFO,
                                                            GTK_BUTTONS_CLOSE,
                                                            "%s",
                                                            _("Private key exported successfully")));
                gtk_dialog_run (GTK_DIALOG(dialog));
                
                gtk_widget_destroy (GTK_WIDGET(dialog));
        }
	
}


void __ca_export_pkcs12 (GtkTreeIter *iter, gint type)
{
	GObject *widget = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	gint id;

        gchar *error_msg = NULL;

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new 
			       (_("Export whole certificate in PKCS#12 package"),
				GTK_WINDOW(widget),
				GTK_FILE_CHOOSER_ACTION_SAVE,
				_("_Cancel"), GTK_RESPONSE_CANCEL,
				_("_Save"), GTK_RESPONSE_ACCEPT,
				NULL));
	
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		return;
	}

	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		

        error_msg = export_pkcs12 (id, type, filename);

        g_free (filename);

        if (error_msg && strlen(error_msg)) {
                dialog_error (error_msg);
                return;
        } 
        
        if (error_msg) {
                // Export cancelled by user
                return;
        }


        dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_INFO,
						    GTK_BUTTONS_CLOSE,
						    "%s",
						    _("Certificate exported successfully")));
	gtk_dialog_run (GTK_DIALOG(dialog));
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	
}


G_MODULE_EXPORT void ca_on_export1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GObject * widget = NULL;
	//GtkDialog * dialog = NULL;
	GtkTreeIter *iter = NULL;	
	gint type = __ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter);
	GtkBuilder * dialog_gtkb = NULL;
	gboolean has_pk_in_db = FALSE;
	gint response = 0;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "export_certificate_dialog.ui", NULL ),
				   NULL);
	gtk_builder_connect_signals (dialog_gtkb, NULL); 	
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &has_pk_in_db, -1);			
	widget = gtk_builder_get_object (dialog_gtkb, "privatepart_radiobutton2");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), has_pk_in_db);
	widget = gtk_builder_get_object (dialog_gtkb, "bothparts_radiobutton3");
	gtk_widget_set_sensitive (GTK_WIDGET(widget), has_pk_in_db);

	if (type == CA_FILE_ELEMENT_TYPE_CSR) {
 	        widget = gtk_builder_get_object (dialog_gtkb, "export_certificate_dialog");
		gtk_window_set_title (GTK_WINDOW(widget), _("Export CSR - gnoMint"));

		widget = gtk_builder_get_object (dialog_gtkb, "label2");
		gtk_label_set_text 
                        (GTK_LABEL(widget), 
                         _("Please, choose which part of the saved Certificate Signing Request you want to export:"));

		widget = gtk_builder_get_object (dialog_gtkb, "label5");
		gtk_label_set_markup 
                        (GTK_LABEL(widget), 
                         _("<i>Export the Certificate Signing Request to a public file, in PEM format.</i>"));

		widget = gtk_builder_get_object (dialog_gtkb, "label15");
		gtk_label_set_markup 
                        (GTK_LABEL(widget), 
                         _("<i>Export the saved private key to a PKCS#8 password-protected file. This file should only be accessed by the subject of the Certificate Signing Request.</i>"));

	        widget = gtk_builder_get_object (dialog_gtkb, "bothparts_radiobutton3");
		g_object_set (G_OBJECT (widget), "visible", FALSE, NULL);
	        widget = gtk_builder_get_object (dialog_gtkb, "label19");
		g_object_set (G_OBJECT (widget), "visible", FALSE, NULL);

	}
	

	widget = gtk_builder_get_object (dialog_gtkb, "export_certificate_dialog");

	response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
	if (!response || response == GTK_RESPONSE_CANCEL) {
		gtk_widget_destroy (GTK_WIDGET(widget));
		g_object_unref (G_OBJECT(dialog_gtkb));
		gtk_tree_iter_free (iter);
		return;
	} 
	
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (gtk_builder_get_object (dialog_gtkb, "publicpart_radiobutton1")))) {
		/* Export public part */
		__ca_export_public_pem (iter, type);
		gtk_widget_destroy (GTK_WIDGET(widget));
		g_object_unref (G_OBJECT(dialog_gtkb));
		gtk_tree_iter_free (iter);
		
		return;
	}
	
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (gtk_builder_get_object (dialog_gtkb, "privatepart_radiobutton2")))) {
		/* Export private part (crypted) */
		g_free (__ca_export_private_pkcs8 (iter, type));
		gtk_widget_destroy (GTK_WIDGET(widget));
		g_object_unref (G_OBJECT(dialog_gtkb));
		gtk_tree_iter_free (iter);
		
		return;
	}

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (gtk_builder_get_object (dialog_gtkb, "privatepart_uncrypted_radiobutton2")))) {
		/* Export private part (uncrypted) */
		__ca_export_private_pem (iter, type);
		gtk_widget_destroy (GTK_WIDGET(widget));
		g_object_unref (G_OBJECT(dialog_gtkb));
		gtk_tree_iter_free (iter);
		
		return;
	}
	
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (gtk_builder_get_object (dialog_gtkb, "bothparts_radiobutton3")))) {
		/* Export PKCS#12 structure */
		__ca_export_pkcs12 (iter, type);
		gtk_widget_destroy (GTK_WIDGET(widget));
		g_object_unref (G_OBJECT(dialog_gtkb));
		gtk_tree_iter_free (iter);
		
		return;
	}
	
	gtk_widget_destroy (GTK_WIDGET(widget));
	g_object_unref (G_OBJECT(dialog_gtkb));
	gtk_tree_iter_free (iter);
	dialog_error (_("Unexpected error"));
}

G_MODULE_EXPORT void ca_on_extractprivatekey1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTreeIter *iter = NULL;	
	gint type;
	gchar *filename = NULL;
	gint id;

	type = __ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		

	filename = __ca_export_private_pkcs8 (iter, type);

	if (! filename) {
		gtk_tree_iter_free (iter);
		return;
	}
	
	if (type == CA_FILE_ELEMENT_TYPE_CERT)
		ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CERT, filename, id);
	else
		ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CSR, filename, id);

	g_free (filename);
	gtk_tree_iter_free (iter);

	dialog_refresh_list();
}


G_MODULE_EXPORT void ca_on_revoke_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GObject * widget = NULL;
	GtkDialog * dialog = NULL;
        gchar * errmsg = NULL;
	GtkTreeIter *iter = NULL;	
	gint type = __ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter);
	gint response = 0;
	gint id = 0;

	if (type == CA_FILE_ELEMENT_TYPE_CSR) {
		gtk_tree_iter_free (iter);
		return;
	}
	


	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);			

	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	if (! ca_file_check_if_is_ca_id (id)) {

		dialog = GTK_DIALOG(gtk_message_dialog_new_with_markup (GTK_WINDOW(widget),
							    GTK_DIALOG_DESTROY_WITH_PARENT,
							    GTK_MESSAGE_QUESTION,
							    GTK_BUTTONS_YES_NO,
							    "<b>%s</b>\n\n<span font_size='small'>%s</span>",
							    _("Are you sure you want to revoke this certificate?"),
							    _("Revoking a certificate will include it in the next CRL, marking it as invalid. This way, any future use of the certificate will be denied (as long as the CRL is checked).")));
	} else {

		dialog = GTK_DIALOG(gtk_message_dialog_new_with_markup (GTK_WINDOW(widget),
							    GTK_DIALOG_DESTROY_WITH_PARENT,
							    GTK_MESSAGE_QUESTION,
							    GTK_BUTTONS_YES_NO,
							    "<b>%s</b>\n\n<span font_size='small'>%s</span>",		
							    _("Are you sure you want to revoke this CA certificate?"),
							    _("Revoking a certificate will include it in the next CRL, marking it as invalid. This way, any future use of the certificate will be denied (as long as the CRL is checked). \n\nMoreover, revoking a CA certificate can invalidate all the certificates generated with it, so all them should be regenerated with a new CA certificate.")));
	}

	response = gtk_dialog_run(dialog);
	gtk_widget_destroy (GTK_WIDGET(dialog));

	if (response == GTK_RESPONSE_NO) {
		gtk_tree_iter_free (iter);
		return;
	}

        errmsg = ca_file_revoke_crt (id);
	if (errmsg) {
                dialog_error (_(errmsg));

        }

	gtk_tree_iter_free (iter);
	dialog_refresh_list();
  
}


G_MODULE_EXPORT void ca_on_delete2_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GObject * widget = NULL;
	GtkDialog * dialog = NULL;
	GtkTreeIter *iter = NULL;	
	gint type = __ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter);
	gint response = 0;
	gint id = 0;

	if (type != CA_FILE_ELEMENT_TYPE_CSR) {
		gtk_tree_iter_free (iter);
		return;
	}
	
	widget = gtk_builder_get_object (main_window_gtkb, "main_window1");
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_QUESTION,
						    GTK_BUTTONS_YES_NO,
						    "%s",
						    _("Are you sure you want to delete this Certificate Signing Request?")));

	response = gtk_dialog_run(dialog);
	gtk_widget_destroy (GTK_WIDGET(dialog));

	if (response == GTK_RESPONSE_NO) {
		gtk_tree_iter_free (iter);
		return;
	}

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);			
	ca_file_remove_csr (id);

	gtk_tree_iter_free (iter);
	dialog_refresh_list();
}

G_MODULE_EXPORT void ca_on_sign1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTreeIter *iter = NULL;

	gint type = __ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter);
	gchar * csr_pem;
	gchar * csr_parent_id;
	guint64 csr_id;

	if (type != CA_FILE_ELEMENT_TYPE_CSR) {
		gtk_tree_iter_free (iter);
		return;
	}
		
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &csr_id, CA_MODEL_COLUMN_PEM, &csr_pem, CA_MODEL_COLUMN_PARENT_ID, &csr_parent_id, -1);

	new_cert_window_display (csr_id, csr_pem, csr_parent_id);
	
	g_free (csr_pem);
        g_free (csr_parent_id);
	gtk_tree_iter_free (iter);
}



gboolean ca_open (gchar *filename, gboolean create) 
{
	if (! ca_file_open (filename, create))
		return FALSE;

	__enable_widget ("new_certificate1");
	__enable_widget ("save_as1");
	__enable_widget ("preferences1");


	dialog_refresh_list();
	
	
	return TRUE;
}

guint64 ca_get_selected_row_id ()
{
	GtkTreeIter *iter = NULL;
	guint64 result = 0;

	if (__ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter) != -1) {
		gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &result, -1);
		gtk_tree_iter_free (iter);
	}

	return result;
}

gchar * ca_get_selected_row_pem ()
{
	GtkTreeIter *iter = NULL;
	gchar * result = NULL;

	if (__ca_selection_type (GTK_TREE_VIEW(gtk_builder_get_object (main_window_gtkb, "ca_treeview")), &iter) != -1) {
		gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PEM, &result, -1);
		gtk_tree_iter_free (iter);
	}
	
	return result;
}


void ca_update_csr_view (gboolean new_value, gboolean refresh)
{
        view_csr = new_value;
        gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(gtk_builder_get_object(main_window_gtkb, "csr_view_menuitem")), new_value);
        if (refresh)
                dialog_refresh_list();
}

G_MODULE_EXPORT gboolean ca_csr_view_toggled (GtkCheckMenuItem *button, gpointer user_data)
{
        ca_update_csr_view (gtk_check_menu_item_get_active (button), TRUE);
        if (view_csr != preferences_get_crq_visible())
                preferences_set_crq_visible (view_csr);

        return TRUE;
}

void ca_update_revoked_view (gboolean new_value, gboolean refresh)
{
        view_rcrt = new_value;
        gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(gtk_builder_get_object(main_window_gtkb, "revoked_view_menuitem")), new_value);
        if (refresh)
                dialog_refresh_list();
}

G_MODULE_EXPORT gboolean ca_rcrt_view_toggled (GtkCheckMenuItem *button, gpointer user_data)
{
        ca_update_revoked_view (gtk_check_menu_item_get_active (button), TRUE);
        if (view_rcrt != preferences_get_revoked_visible())
                preferences_set_revoked_visible (view_rcrt);

        return TRUE;
}

G_MODULE_EXPORT void ca_generate_crl (GtkCheckMenuItem *item, gpointer user_data)
{
        crl_window_display ();
}





G_MODULE_EXPORT gboolean ca_treeview_popup_handler (GtkTreeView *tree_view,
				    GdkEvent *event, gpointer user_data)
{
	GdkEventButton *event_button;
	GObject *menu, *widget;
	GtkTreeIter *iter = NULL;
	gboolean pk_indb, is_revoked;
	gint selection_type;
	GdkWindow *window;
	gint x, y;
	GdkRectangle rect;
	GtkTreePath *path = NULL;
	GtkTreeSelection *selection;
	
	g_return_val_if_fail (event != NULL, FALSE);
	
	if (event->type == GDK_BUTTON_PRESS) {

		event_button = (GdkEventButton *) event;
		if (event_button->button == 3) {
			/* Select the row under cursor before showing menu */
			if (gtk_tree_view_get_path_at_pos(tree_view, 
							  (gint)event_button->x, 
							  (gint)event_button->y,
							  &path, NULL, NULL, NULL)) {
				selection = gtk_tree_view_get_selection(tree_view);
				gtk_tree_selection_select_path(selection, path);
				gtk_tree_path_free(path);
			}
			
			/* Handle right-click popup menu directly */
			selection_type  = __ca_selection_type (tree_view, &iter);
			
			switch (selection_type) {
				
			case CA_FILE_ELEMENT_TYPE_CERT:
				if (!cert_popup_menu_gtkb) {
					if (iter)
						gtk_tree_iter_free (iter);
					return FALSE;
				}
				
				menu = gtk_builder_get_object (cert_popup_menu_gtkb,
							     "certificate_popup_menu");
				
				if (!menu) {
					if (iter)
						gtk_tree_iter_free (iter);
					return FALSE;
				}
				
				gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
						   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
						   CA_MODEL_COLUMN_REVOCATION, &is_revoked, -1);
				
				widget = gtk_builder_get_object (cert_popup_menu_gtkb, "extract_pkey_menuitem");
				if (widget)
					gtk_widget_set_sensitive (GTK_WIDGET(widget), pk_indb);
				
				widget = gtk_builder_get_object (cert_popup_menu_gtkb, "revoke_menuitem");
				if (widget)
					gtk_widget_set_sensitive (GTK_WIDGET(widget), (! is_revoked));

				/* Get click position and show menu there */
				window = gtk_widget_get_window (GTK_WIDGET(tree_view));
				if (window) {
					gdk_window_get_device_position (window, event_button->device, &x, &y, NULL);
					
					rect.x = x;
					rect.y = y;
					rect.width = 1;
					rect.height = 1;
					
					/* Detach if already attached to avoid warning, then attach and show */
					gtk_menu_detach (GTK_MENU(menu));
					gtk_menu_attach_to_widget (GTK_MENU(menu), GTK_WIDGET(tree_view), NULL);
					gtk_menu_popup_at_rect (GTK_MENU(menu), window, &rect,
								GDK_GRAVITY_SOUTH_EAST, GDK_GRAVITY_NORTH_WEST, 
								(GdkEvent *)event_button);
				}
				gtk_tree_iter_free (iter);
				return TRUE;  /* Event handled */
			case CA_FILE_ELEMENT_TYPE_CSR:
				if (!csr_popup_menu_gtkb) {
					if (iter)
						gtk_tree_iter_free (iter);
					return FALSE;
				}
				
				menu = gtk_builder_get_object (csr_popup_menu_gtkb,
							     "csr_popup_menu");

				if (!menu) {
					if (iter)
						gtk_tree_iter_free (iter);
					return FALSE;
				}

				gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
						   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
						   -1);
				
				widget = gtk_builder_get_object (csr_popup_menu_gtkb, "extract_pkey_menuitem3");
				if (widget)
					gtk_widget_set_sensitive (GTK_WIDGET(widget), pk_indb);
				
				/* Get click position and show menu there */
				window = gtk_widget_get_window (GTK_WIDGET(tree_view));
				if (window) {
					gdk_window_get_device_position (window, event_button->device, &x, &y, NULL);
					
					rect.x = x;
					rect.y = y;
					rect.width = 1;
					rect.height = 1;
					
					/* Detach if already attached to avoid warning, then attach and show */
					gtk_menu_detach (GTK_MENU(menu));
					gtk_menu_attach_to_widget (GTK_MENU(menu), GTK_WIDGET(tree_view), NULL);
					gtk_menu_popup_at_rect (GTK_MENU(menu), window, &rect,
								GDK_GRAVITY_SOUTH_EAST, GDK_GRAVITY_NORTH_WEST,
								(GdkEvent *)event_button);
				}
				gtk_tree_iter_free (iter);
				return TRUE;  /* Event handled */
			default:
			case -1:
				if (iter)
					gtk_tree_iter_free (iter);
				return FALSE;
			}
		}
	}
	
	return FALSE;
}

G_MODULE_EXPORT void ca_on_change_pwd_menuitem_activate (GtkMenuItem *menuitem, gpointer user_data) 
{
	GObject * widget = NULL;
	GtkDialog * dialog = NULL;
	GtkBuilder * dialog_gtkb = NULL;
	const gchar *newpwd;
	const gchar *currpwd;

	gint response = 0;
	gboolean repeat;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "change_password_dialog.ui", NULL),
				   NULL);
	gtk_builder_connect_signals (dialog_gtkb, NULL); 	

	if (ca_file_is_password_protected()) {
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label1");
		g_object_set (G_OBJECT(widget), "visible", TRUE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
		g_object_set (G_OBJECT(widget), "visible", TRUE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_commit_button");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	} else {
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_no_radiobutton");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label1");
		g_object_set (G_OBJECT(widget), "visible", FALSE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
		g_object_set (G_OBJECT(widget), "visible", FALSE, NULL);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

	}

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
	g_object_set_data (G_OBJECT(widget), "dialog_gtkb", dialog_gtkb);

	
	do {

		widget = gtk_builder_get_object (dialog_gtkb, "change_password_dialog");
		gtk_window_set_title (GTK_WINDOW(widget), _("Change CA password - gnoMint"));
		response = gtk_dialog_run(GTK_DIALOG(widget)); 
		
		if (!response || response == GTK_RESPONSE_CANCEL) {
			gtk_widget_destroy (GTK_WIDGET(widget));
			g_object_unref (G_OBJECT(dialog_gtkb));
			return;
		} 
		
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		newpwd = gtk_entry_get_text (GTK_ENTRY(widget));
		
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
		currpwd = gtk_entry_get_text (GTK_ENTRY(widget));

		repeat = (ca_file_is_password_protected() && ! ca_file_check_password (currpwd));
		
		if (repeat) {
			dialog_error (_("The current password you have entered  "
					   "doesn't match with the actual current database password."));
			widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
			gtk_widget_grab_focus (GTK_WIDGET(widget));
		} 

	} while (repeat);
	
	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {

		if (ca_file_is_password_protected()) {
			// It's a password change

			if (! ca_file_password_change (currpwd, newpwd)) {
				dialog_error (_("Error while changing database password. "
						   "The operation was cancelled."));
			} else {
				widget = gtk_builder_get_object (dialog_gtkb, "change_password_dialog");
				dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
									    GTK_DIALOG_DESTROY_WITH_PARENT,
									    GTK_MESSAGE_INFO,
									    GTK_BUTTONS_CLOSE,
									    "%s",
									    _("Password changed successfully")));
				gtk_dialog_run (GTK_DIALOG(dialog));
				
				gtk_widget_destroy (GTK_WIDGET(dialog));
			}

		} else {
			// It's a new password

			if (! ca_file_password_protect (newpwd)) {
				dialog_error (_("Error while establishing database password. "
						   "The operation was cancelled."));

			} else {
				widget = gtk_builder_get_object (dialog_gtkb, "change_password_dialog");
				dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
									    GTK_DIALOG_DESTROY_WITH_PARENT,
									    GTK_MESSAGE_INFO,
									    GTK_BUTTONS_CLOSE,
									    "%s",
									    _("Password established successfully")));
				gtk_dialog_run (GTK_DIALOG(dialog));
				
				gtk_widget_destroy (GTK_WIDGET(dialog));
			}
		}
	} else {
		if (ca_file_is_password_protected()) {
			// Remove password protection
			if (! ca_file_password_unprotect (currpwd)) {
				dialog_error (_("Error while removing database password. "
						   "The operation was cancelled."));
			} else {
				widget = gtk_builder_get_object (dialog_gtkb, "change_password_dialog");
				dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
									    GTK_DIALOG_DESTROY_WITH_PARENT,
									    GTK_MESSAGE_INFO,
									    GTK_BUTTONS_CLOSE,
									    "%s",
									    _("Password removed successfully")));
				gtk_dialog_run (GTK_DIALOG(dialog));
				
				gtk_widget_destroy (GTK_WIDGET(dialog));

			}

		} else {
			// Don't do anything
			
		}

	}

	widget = gtk_builder_get_object (dialog_gtkb, "change_password_dialog");
	gtk_widget_destroy (GTK_WIDGET(widget));

}


G_MODULE_EXPORT gboolean ca_changepwd_newpwd_entry_changed (GtkWidget *entry, gpointer user_data)
{
	GtkBuilder * dialog_gtkb = g_object_get_data (G_OBJECT(entry), "dialog_gtkb");
	GObject *widget;

	const gchar *pwd1;
	const gchar *pwd2;
	const gchar *currpwd;
	gboolean pwd_protect;

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	pwd_protect = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
	pwd1 = gtk_entry_get_text (GTK_ENTRY(widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
	pwd2 = gtk_entry_get_text (GTK_ENTRY(widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_current_pwd_entry");
	currpwd = gtk_entry_get_text (GTK_ENTRY(widget));

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_commit_button");
	if (pwd_protect) {
		if (strlen(pwd1) && strlen(pwd2) && ! strcmp(pwd1, pwd2)) {
			if (!ca_file_is_password_protected() || (ca_file_is_password_protected() && strlen(currpwd)))
				gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
			else
				gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);			
		} else {
			gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);		
		}
	} else {
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);
	}

	return FALSE;
}

G_MODULE_EXPORT gboolean ca_changepwd_pwd_protect_radiobutton_toggled (GtkWidget *button, gpointer user_data)
{
	GtkBuilder * dialog_gtkb;
	GObject * widget = NULL;


	if (! G_IS_OBJECT(button))
		return TRUE;

	dialog_gtkb = g_object_get_data (G_OBJECT(button), "dialog_gtkb");
	if (! dialog_gtkb)
		return TRUE;

	widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_pwd_protect_yes_radiobutton");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		/* We want to password-protect the database */
		
		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), TRUE);

		ca_changepwd_newpwd_entry_changed (button, NULL);
	
	} else {

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_label3");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);

		widget = gtk_builder_get_object (dialog_gtkb, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (GTK_WIDGET(widget), FALSE);
	}

	return FALSE;
}


G_MODULE_EXPORT void ca_generate_dh_param_show (GtkWidget *menuitem, gpointer user_data)
{
	GObject * widget = NULL;
	GtkDialog * dialog = NULL, * dialog2 = NULL;
	GtkBuilder * dialog_gtkb = NULL;
	gchar *filename;
	gint response = 0;
	guint dh_size;
	gchar *strerror;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "dh_parameters_dialog.ui", NULL),
				   NULL);
	gtk_builder_connect_signals (dialog_gtkb, NULL); 	
	

	dialog = GTK_DIALOG(gtk_builder_get_object (dialog_gtkb, "dh_parameters_dialog"));
	response = gtk_dialog_run(dialog); 
	
	if (!response) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		g_object_unref (G_OBJECT(dialog_gtkb));
		return;
	} 

	widget = gtk_builder_get_object (dialog_gtkb, "dh_prime_size_spinbutton");
	dh_size = gtk_spin_button_get_value (GTK_SPIN_BUTTON(widget));

	dialog2 = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Save Diffie-Hellman parameters"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  _("_Cancel"), GTK_RESPONSE_CANCEL,
							  _("_Save"), GTK_RESPONSE_ACCEPT,
							  NULL));
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog2), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog2)) == GTK_RESPONSE_ACCEPT) {

		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog2));

		strerror = export_dh_param (dh_size, filename);

		if (strerror) {
			gtk_widget_destroy (GTK_WIDGET(dialog2));
			gtk_widget_destroy (GTK_WIDGET(dialog));
			dialog_error (strerror);
		} else {
			gtk_widget_destroy (GTK_WIDGET(dialog2));
			gtk_widget_destroy (GTK_WIDGET(dialog));
			dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
								    GTK_DIALOG_DESTROY_WITH_PARENT,
								    GTK_MESSAGE_INFO,
								    GTK_BUTTONS_CLOSE,
								    "%s",
								    _("Diffie-Hellman parameters saved successfully")));
			gtk_dialog_run (GTK_DIALOG(dialog));
			
			gtk_widget_destroy (GTK_WIDGET(dialog));
		}


        }
	
	
	return;
}


/*
 *
 *   FILE MENU CALLBACKS
 *
 */ 


G_MODULE_EXPORT void on_add_self_signed_ca_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	new_ca_window_display();
	
}

G_MODULE_EXPORT void on_add_csr_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	new_req_window_display();
	
}


G_MODULE_EXPORT void on_import1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{

	gchar *filename;

	GObject *main_window_widget, *widget;
	GtkWidget *dialog;
	GtkBuilder * dialog_gtkb = NULL;
        GtkToggleButton *radiobutton = NULL;
	gint response = 0;
        gboolean import_file = TRUE;
	
	main_window_widget = gtk_builder_get_object (main_window_gtkb, "main_window");

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "import_file_or_directory_dialog.ui", NULL),
				   NULL);
	gtk_builder_connect_signals (dialog_gtkb, NULL);

        widget = gtk_builder_get_object (dialog_gtkb, "import_file_or_directory_dialog");
        response = gtk_dialog_run (GTK_DIALOG(widget));

        if (response < 0) {
                gtk_widget_destroy (GTK_WIDGET(widget));
                g_object_unref (G_OBJECT(dialog_gtkb));
                return;
        }

        radiobutton = GTK_TOGGLE_BUTTON(gtk_builder_get_object (dialog_gtkb, "importfile_radiobutton"));
        import_file = gtk_toggle_button_get_active(radiobutton);

        gtk_widget_destroy (GTK_WIDGET(widget));

        if (import_file) {
                // Import single file
                dialog = gtk_file_chooser_dialog_new (_("Select PEM file to import"),
                                                      GTK_WINDOW(main_window_widget),
                                                      GTK_FILE_CHOOSER_ACTION_OPEN,
                                                      _("_Cancel"), GTK_RESPONSE_CANCEL,
                                                      _("_Open"), GTK_RESPONSE_ACCEPT,
                                                      NULL);
                
                if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
                {
                        filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
                        gtk_widget_destroy (dialog);
                } else {
                        gtk_widget_destroy (dialog);
                        return;
                }		
                
                if (! import_single_file (filename, NULL, NULL)) {
                        dialog = gtk_message_dialog_new (GTK_WINDOW(main_window_widget),
                                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                                         GTK_MESSAGE_ERROR,
                                                         GTK_BUTTONS_CLOSE,
                                                         _("Problem when importing '%s' file"),
                                                         filename);
                        
                        gtk_dialog_run (GTK_DIALOG(dialog));
                        
                        gtk_widget_destroy (dialog);
                }
                return;
        } else {
                // Import directory

                gchar * result = NULL;

                dialog = gtk_file_chooser_dialog_new (_("Select directory to import"),
                                                      GTK_WINDOW(main_window_widget),
                                                      GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                                      _("_Cancel"), GTK_RESPONSE_CANCEL,
                                                      _("_Open"), GTK_RESPONSE_ACCEPT,
                                                      NULL);
                
                if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
                {
                        filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
                        gtk_widget_destroy (dialog);
                } else {
                        gtk_widget_destroy (dialog);
                        return;
                }		

                result = import_whole_dir (filename);

                if (result) {
                        dialog = gtk_message_dialog_new (GTK_WINDOW(main_window_widget),
                                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                                         GTK_MESSAGE_ERROR,
                                                         GTK_BUTTONS_CLOSE,
                                                         "%s", result);
                        
                        gtk_dialog_run (GTK_DIALOG(dialog));
                        
                        gtk_widget_destroy (dialog);
                }
                return;

        }
}


/*
 *
 *   EDIT MENU CALLBACKS
 *
 */ 



G_MODULE_EXPORT void on_preferences1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
        preferences_window_display ();
}

G_MODULE_EXPORT void on_properties1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	ca_treeview_row_activated (NULL, NULL, NULL, NULL);
}




#endif


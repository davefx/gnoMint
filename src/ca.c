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


#include <glade/glade.h>
#include <glib-object.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <glib/gi18n.h>
#include <stdlib.h>
#include <string.h>


#include "ca.h"
#include "ca_policy.h"
#include "ca_file.h"
#include "certificate_properties.h"
#include "crl.h"
#include "csr_properties.h"
#include "tls.h"
#include "new_ca_window.h"
#include "new_req_window.h"
#include "new_cert_window.h"
#include "pkey_manage.h"
#include "preferences-gui.h"
#include "import.h"

extern GladeXML * main_window_xml;
extern GladeXML * cert_popup_menu_xml;
extern GladeXML * csr_popup_menu_xml;

static GtkTreeStore * ca_model = NULL;
static gboolean cert_title_inserted = FALSE;
static GtkTreeIter * cert_parent_iter = NULL;
static GtkTreeIter * last_parent_iter = NULL;
static GtkTreeIter * last_cert_iter = NULL;
static gboolean csr_title_inserted=FALSE;
static GtkTreeIter * csr_parent_iter = NULL;

static gboolean view_csr = TRUE;
static gboolean view_rcrt = TRUE;

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
	GValue *last_dn_value = g_new0 (GValue, 1);
	GValue *last_parent_dn_value = g_new0 (GValue, 1);
        const gchar * string_value;
	
	if (cert_title_inserted == FALSE) {
		gtk_tree_store_append (new_model, &iter, NULL);
		gtk_tree_store_set (new_model, &iter,
				    3, _("<b>Certificates</b>"),
				    -1);
		cert_parent_iter = gtk_tree_iter_copy (&iter);
		cert_title_inserted = TRUE;
	}

	if (! last_cert_iter || (! strcmp (argv[CA_MODEL_COLUMN_DN], argv[CA_MODEL_COLUMN_PARENT_DN]))) {
		if (last_parent_iter)
			gtk_tree_iter_free (last_parent_iter);
		last_parent_iter = NULL;
	} else {
		// If not, then we must find the parent of the current nod
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_cert_iter, CA_MODEL_COLUMN_DN, last_dn_value);
		gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_cert_iter, CA_MODEL_COLUMN_PARENT_DN, 
					  last_parent_dn_value);
		
		string_value = g_value_get_string (last_dn_value);
                g_assert (string_value);
		

		if (! strcmp (argv[CA_MODEL_COLUMN_PARENT_DN], string_value)) {
			// Last node is parent of the current node
			if (last_parent_iter)
				gtk_tree_iter_free (last_parent_iter);
			last_parent_iter = gtk_tree_iter_copy (last_cert_iter);
		} else {
			// We go back in the hierarchical tree, starting in the current parent, until we find the parent of the
			// current certificate.
			
			while (last_parent_iter && 
                               g_value_get_string(last_parent_dn_value) && argv[CA_MODEL_COLUMN_PARENT_DN] &&
			       strcmp (argv[CA_MODEL_COLUMN_PARENT_DN], g_value_get_string(last_parent_dn_value))) {
				
				if (! gtk_tree_model_iter_parent(GTK_TREE_MODEL(new_model), &iter, last_parent_iter)) {
					// Last ca iter is a top_level
					if (last_parent_iter)
						gtk_tree_iter_free (last_parent_iter);
					last_parent_iter = NULL;
				} else {
					if (last_parent_iter)
						gtk_tree_iter_free (last_parent_iter);
					last_parent_iter = gtk_tree_iter_copy (&iter);
				}

				g_value_unset (last_parent_dn_value);
				gtk_tree_model_get_value (GTK_TREE_MODEL(new_model), last_parent_iter,
							  CA_MODEL_COLUMN_DN, 
							  last_parent_dn_value);
				
			}
		}
	
	}
	
	gtk_tree_store_append (new_model, &iter, (last_parent_iter ? last_parent_iter: cert_parent_iter));

        if (! argv[CA_MODEL_COLUMN_REVOCATION])        
                gtk_tree_store_set (new_model, &iter,
                                    CA_MODEL_COLUMN_ID, atoll(argv[CA_MODEL_COLUMN_ID]),
                                    CA_MODEL_COLUMN_IS_CA, atoi(argv[CA_MODEL_COLUMN_IS_CA]),
                                    CA_MODEL_COLUMN_SERIAL, argv[CA_MODEL_COLUMN_SERIAL],
                                    CA_MODEL_COLUMN_SUBJECT, argv[CA_MODEL_COLUMN_SUBJECT],
                                    CA_MODEL_COLUMN_ACTIVATION, atoi(argv[CA_MODEL_COLUMN_ACTIVATION]),
                                    CA_MODEL_COLUMN_EXPIRATION, atoi(argv[CA_MODEL_COLUMN_EXPIRATION]),
                                    CA_MODEL_COLUMN_REVOCATION, 0,
                                    CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, atoi(argv[CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB]),
                                    CA_MODEL_COLUMN_PEM, argv[CA_MODEL_COLUMN_PEM],
				    CA_MODEL_COLUMN_DN, argv[CA_MODEL_COLUMN_DN],
				    CA_MODEL_COLUMN_PARENT_DN, argv[CA_MODEL_COLUMN_PARENT_DN],
				    CA_MODEL_COLUMN_PARENT_ROUTE, argv[CA_MODEL_COLUMN_PARENT_ROUTE],
                                    CA_MODEL_COLUMN_ITEM_TYPE, 0,
                                    -1);
        else {
                gchar * revoked_subject = g_markup_printf_escaped ("<s>%s</s>", 
                                                                   argv[CA_MODEL_COLUMN_SUBJECT]);

                gtk_tree_store_set (new_model, &iter,
                                    CA_MODEL_COLUMN_ID, atoll(argv[CA_MODEL_COLUMN_ID]),
                                    CA_MODEL_COLUMN_IS_CA, atoi(argv[CA_MODEL_COLUMN_IS_CA]),
                                    CA_MODEL_COLUMN_SERIAL, argv[CA_MODEL_COLUMN_SERIAL],
                                    CA_MODEL_COLUMN_SUBJECT, revoked_subject,
                                    CA_MODEL_COLUMN_ACTIVATION, atoi(argv[CA_MODEL_COLUMN_ACTIVATION]),
                                    CA_MODEL_COLUMN_EXPIRATION, atoi(argv[CA_MODEL_COLUMN_EXPIRATION]),
                                    CA_MODEL_COLUMN_REVOCATION, atoi(argv[CA_MODEL_COLUMN_REVOCATION]),
                                    CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, atoi(argv[CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB]),
                                    CA_MODEL_COLUMN_PEM, argv[CA_MODEL_COLUMN_PEM],
				    CA_MODEL_COLUMN_DN, argv[CA_MODEL_COLUMN_DN],
				    CA_MODEL_COLUMN_PARENT_DN, argv[CA_MODEL_COLUMN_PARENT_DN],
				    CA_MODEL_COLUMN_PARENT_ROUTE, argv[CA_MODEL_COLUMN_PARENT_ROUTE],
                                    CA_MODEL_COLUMN_ITEM_TYPE, 0,
                                    -1);

                g_free (revoked_subject);
        }


	if (last_cert_iter)
		gtk_tree_iter_free (last_cert_iter);
	last_cert_iter = gtk_tree_iter_copy (&iter);
 
	g_free (last_dn_value);
	g_free (last_parent_dn_value);      	

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
                            CA_MODEL_COLUMN_ID, atoll(argv[CSR_MODEL_COLUMN_ID]),
                            CA_MODEL_COLUMN_SUBJECT, argv[CSR_MODEL_COLUMN_SUBJECT],
                            CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, atoi(argv[CSR_MODEL_COLUMN_PRIVATE_KEY_IN_DB]),
                            CA_MODEL_COLUMN_PEM, argv[CSR_MODEL_COLUMN_PEM],
                            CA_MODEL_COLUMN_PARENT_ID, argv[CSR_MODEL_COLUMN_PARENT_ID],
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



gboolean ca_refresh_model () 
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

	treeview = GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview"));

	if (ca_model) {
                GList * column_list;
		g_object_unref (ca_model);		

                // Remove revocation column
                column_list = gtk_tree_view_get_columns (treeview);
                columns_number = g_list_length (column_list);
                g_list_free (column_list);
        
                
	} else {
/*                 GtkTooltips * table_tooltips = gtk_tooltips_new(); */
                guint column_number;
          
		/* There's no model assigned to the treeview yet, so we add its columns */
		
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		column_number = gtk_tree_view_insert_column_with_attributes (treeview,
                                                                             -1, _("Subject"), renderer,
                                                                             "markup", CA_MODEL_COLUMN_SUBJECT,
                                                                             NULL);
		
/*                 gtk_tooltips_set_tip (table_tooltips, GTK_WIDGET(gtk_tree_view_get_column(treeview, column_number - 1)),  */
/*                                       _("Subject of the certificate or request"),  */
/*                                       _("This is the distinguished name (DN) of the certificate or request")); */

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_pixbuf_new ());
		
		column_number = gtk_tree_view_insert_column_with_data_func (treeview,
                                                                            -1, "", renderer,
                                                                            __ca_tree_view_is_ca_datafunc, 
                                                                            NULL, NULL);

/*                 gtk_tooltips_set_tip (table_tooltips, GTK_WIDGET(gtk_tree_view_get_column(treeview, column_number - 1)),  */
/*                                       _("It's a CA certificate"),  */
/*                                       _("An icon in this column shows that the certificate is able to generate and sign " */
/*                                         "new certificates.")); */

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_pixbuf_new ());

		column_number = gtk_tree_view_insert_column_with_data_func (treeview,
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



gboolean ca_treeview_row_activated (GtkTreeView *tree_view,
				    GtkTreePath *path,
				    GtkTreeViewColumn *column,
				    gpointer user_data)
{

        GtkTreePath *parent = NULL;
	
        if (tree_view == NULL) {
                GtkTreeSelection *selection;
                GtkTreeIter selection_iter;
		
                tree_view = GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview"));
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
	GtkWidget *widget;
	gboolean is_ca = FALSE;
	gboolean pk_indb = FALSE;
	gint is_revoked = FALSE;
	
	widget = glade_xml_get_widget (main_window_xml, "export1");
	gtk_widget_set_sensitive (widget, TRUE);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
			   CA_MODEL_COLUMN_IS_CA, &is_ca, 
			   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
			   CA_MODEL_COLUMN_REVOCATION, &is_revoked, -1);
	if (pk_indb) {
		widget = glade_xml_get_widget (main_window_xml, "extractprivatekey1");
		gtk_widget_set_sensitive (widget, TRUE);
	}

        widget = glade_xml_get_widget (main_window_xml, "revoke1");
        gtk_widget_set_sensitive (widget, (! is_revoked));

	widget = glade_xml_get_widget (main_window_xml, "sign1");
	gtk_widget_set_sensitive (widget, FALSE);

	widget = glade_xml_get_widget (main_window_xml, "delete2");
	gtk_widget_set_sensitive (widget, FALSE);

}

void __ca_activate_csr_selection (GtkTreeIter *iter)
{
	GtkWidget *widget;
	gboolean pk_indb = FALSE;
	
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
		/* It's a certificate */
		return 1;
	}

	gtk_tree_path_free (parent);
	parent = gtk_tree_model_get_path (gtk_tree_view_get_model(tree_view), csr_parent_iter);
	if (gtk_tree_path_is_ancestor (parent, selection_path) && gtk_tree_path_compare (parent, selection_path)) {
		gtk_tree_path_free (parent);
		/* It's a CSR */
		return 2;
	}

	gtk_tree_path_free (parent);
	return 0;
}

gboolean ca_treeview_selection_change (GtkTreeView *tree_view,
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

	return FALSE;
}

void ca_error_dialog (gchar *message) {
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
	gchar * parent_route = NULL;
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
				ca_error_dialog (_("There was an error while exporting certificate."));
			else
				ca_error_dialog (_("There was an error while exporting CSR."));
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
                        if (type == 1)
                                ca_error_dialog (_("There was an error while exporting certificate."));
                        else
                                ca_error_dialog (_("There was an error while exporting CSR."));
                        return;
                } 

                g_io_channel_shutdown (file, TRUE, &error);
                if (error) {
                        gtk_widget_destroy (GTK_WIDGET(dialog));
                        if (type == 1)
                                ca_error_dialog (_("There was an error while exporting certificate."));
                        else
                                ca_error_dialog (_("There was an error while exporting CSR."));
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


gchar * ca_dialog_get_password (gchar *info_message, 
                                gchar *password_message, gchar *confirm_message, 
                                gchar *distinct_error_message, guint minimum_length)
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
	g_object_set_data (G_OBJECT(password_widget), "minimum_length", 
                           GINT_TO_POINTER(minimum_length));
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
			ca_error_dialog (distinct_error_message);
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
	guint minimum_length = GPOINTER_TO_INT (g_object_get_data (G_OBJECT(password_entry), 
                                                                   "minimum_length"));

	if (strlen (gtk_entry_get_text (GTK_ENTRY(password_entry))) >= minimum_length)
		gtk_widget_set_sensitive (button, TRUE);
	else
		gtk_widget_set_sensitive (button, FALSE);
	
}


gchar * __ca_export_private_pkcs8 (GtkTreeIter *iter, gint type)
{
	GtkWidget *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	gchar * password = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;
	gint id;
	gchar * dn = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * privatekey = NULL;
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
		return NULL;
	}

	filename = g_strdup(gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog)));
	gtk_widget_destroy (GTK_WIDGET(dialog));
	
	
	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
		g_free (filename);
		g_free (password);
		return NULL;
	} 
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		
	if (type == 1) {
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
	} else {
		crypted_pkey = pkey_manage_get_csr_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CSR, id);
	}
		
	
	if (!crypted_pkey || !dn) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (filename);
		ca_error_dialog (_("There was an error while getting private key."));
		return NULL;
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);
	
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	if (! privatekey) {
		g_free (filename);
		return NULL;
	}
	
	password = ca_dialog_get_password (_("You need to supply a passphrase for protecting the exported private key, "
					     "so nobody else but authorized people can use it. This passphrase will be asked "
					     "by any application that will make use of the private key."),
					   _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"), 
					   _("The introduced passphrases are distinct."), 8);
	if (! password) {
		g_free (filename);
		g_free (privatekey);
		return NULL;
	}

	pem = tls_generate_pkcs8_encrypted_private_key (privatekey, password); 
	g_free (password);
	g_free (privatekey);
	
	if (!pem) {
		g_free (filename);
		ca_error_dialog (_("There was an error while password-protecting private key."));
		return NULL;
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		g_free (pem);
		g_free (filename);
		ca_error_dialog (_("There was an error while exporting private key."));
		return NULL;
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_free (filename);
		ca_error_dialog (_("There was an error while exporting private key."));
		g_io_channel_unref (file);
		return NULL;
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
	
	return filename;
}


void __ca_export_private_pem (GtkTreeIter *iter, gint type)
{
	GtkWidget *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;
	gint id;
	gchar * pem = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * dn = NULL;

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
		ca_error_dialog (_("There was an error while exporting private key."));
		return;
	} 
	
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		
	if (type == 1) {
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
	} else {
		crypted_pkey = pkey_manage_get_csr_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CSR, id);
	}
	
	if (!crypted_pkey || !dn) {
		pkey_manage_data_free(crypted_pkey);
		g_free (dn);
		ca_error_dialog (_("There was an error while getting private key."));
		return;
	}
	
	pem =  pkey_manage_uncrypt (crypted_pkey, dn);

	pkey_manage_data_free (crypted_pkey);
	g_free (dn);
	
	if (!pem) {
		ca_error_dialog (_("There was an error while decrypting private key."));
		return;
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
		return;
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
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


void __ca_export_pkcs12 (GtkTreeIter *iter, gint type)
{
	GtkWidget *widget = NULL;
	GIOChannel * file = NULL;
	gchar * filename = NULL;
	gchar * password = NULL;
	GtkDialog * dialog = NULL;
	GError * error = NULL;
	gint id;
	gchar * crt_pem = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * dn = NULL;
	gchar * privatekey = NULL;
        gnutls_datum_t * pkcs12_datum = NULL;

	widget = glade_xml_get_widget (main_window_xml, "main_window1");
	
	dialog = GTK_DIALOG (gtk_file_chooser_dialog_new 
			       (_("Export whole certificate in PKCS#12 package"),
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


	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		

	if (type == 1) {
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
		crt_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
	}
		
	
	if (! crypted_pkey || ! dn || ! crt_pem) {
		ca_error_dialog (_("There was an error while getting the certificate and private key from the internal database."));
		g_free (filename);
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		return;
	}
	
	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);

	if (! privatekey) {
		ca_error_dialog (_("There was an error while getting the certificate and private key from the internal database."));
		g_free (filename);
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		return;
	}

	password = ca_dialog_get_password (_("You need to supply a passphrase for protecting the exported certificate, "
					     "so nobody else but authorized people can use it. This passphrase will be asked "
					     "by any application that will import the certificate."),
					   _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"), 
					   _("The introduced passphrases are distinct."), 8);
	if (! password) {
		g_free (filename);
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		g_free (privatekey);
		return;
	}
			
	pkcs12_datum = tls_generate_pkcs12 (crt_pem, privatekey, password); 
	g_free (password);
	g_free (privatekey);
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);
	g_free (crt_pem);
	
	
	if (!pkcs12_datum) {
		ca_error_dialog (_("There was an error while generating the PKCS#12 package."));
		return;
	}
	
	file = g_io_channel_new_file (filename, "w", &error);
	g_free (filename);
	if (error) {
		ca_error_dialog (_("There was an error while exporting certificate."));
		return;
	} 

        g_io_channel_set_encoding (file, NULL, NULL);

	g_io_channel_write_chars (file, (gchar *) pkcs12_datum->data, pkcs12_datum->size, NULL, &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting the certificate."));
                g_free (pkcs12_datum->data);
                g_free (pkcs12_datum);
		return;
	} 
        g_free (pkcs12_datum->data);
	g_free (pkcs12_datum);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting the certificate."));
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
						    _("Certificate exported successfully")));
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
	widget = glade_xml_get_widget (dialog_xml, "privatepart_radiobutton2");
	gtk_widget_set_sensitive (widget, has_pk_in_db);

	if (type == 2) {
 	        widget = glade_xml_get_widget (dialog_xml, "export_certificate_dialog");
		gtk_window_set_title (GTK_WINDOW(widget), _("Export CSR - gnoMint"));

		widget = glade_xml_get_widget (dialog_xml, "label2");
		gtk_label_set_text 
                        (GTK_LABEL(widget), 
                         _("Please, choose which part of the saved Certificate Signing Request you want to export:"));

		widget = glade_xml_get_widget (dialog_xml, "label5");
		gtk_label_set_markup 
                        (GTK_LABEL(widget), 
                         _("<i>Export the Certificate Signing Request to a public file, in PEM format.</i>"));

		widget = glade_xml_get_widget (dialog_xml, "label15");
		gtk_label_set_markup 
                        (GTK_LABEL(widget), 
                         _("<i>Export the saved private key to a PKCS#8 password-protected file. This file should only be accessed by the subject of the Certificate Signing Request.</i>"));

	        widget = glade_xml_get_widget (dialog_xml, "bothparts_radiobutton3");
		g_object_set (G_OBJECT (widget), "visible", FALSE, NULL);
	        widget = glade_xml_get_widget (dialog_xml, "label19");
		g_object_set (G_OBJECT (widget), "visible", FALSE, NULL);

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
		g_free (__ca_export_private_pkcs8 (iter, type));
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
		__ca_export_pkcs12 (iter, type);
		gtk_widget_destroy (widget);
		g_object_unref (G_OBJECT(dialog_xml));
		
		return;
	}
	
	gtk_widget_destroy (widget);
	g_object_unref (G_OBJECT(dialog_xml));
	ca_error_dialog (_("Unexpected error"));
}

void ca_on_extractprivatekey1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTreeIter *iter;	
	gint type;
	gchar *filename = NULL;
	gint id;

	type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);		

	filename = __ca_export_private_pkcs8 (iter, type);

	if (! filename) {
		return;
	}
	
	if (type == 1)
		ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CERT, filename, id);
	else
		ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CSR, filename, id);

	g_free (filename);

	ca_refresh_model ();
}

void ca_todo_callback ()
{
	ca_error_dialog (_("To do. Feature not implemented yet."));
}


void ca_on_revoke_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget * widget = NULL;
	GtkDialog * dialog = NULL;
        gchar * errmsg = NULL;
	GtkTreeIter *iter;	
	gint type = __ca_selection_type (GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview")), &iter);
	gint response = 0;
	gint id = 0;

	if (type == 2)
		return;
	
	widget = glade_xml_get_widget (main_window_xml, "main_window1");
	dialog = GTK_DIALOG(gtk_message_dialog_new (GTK_WINDOW(widget),
						    GTK_DIALOG_DESTROY_WITH_PARENT,
						    GTK_MESSAGE_QUESTION,
						    GTK_BUTTONS_YES_NO,
						    "%s",
						    _("Are you sure you want to revoke this certificate?")));

	response = gtk_dialog_run(dialog);
	gtk_widget_destroy (GTK_WIDGET(dialog));

	if (response == GTK_RESPONSE_NO) {
		return;
	}

	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_ID, &id, -1);			
        errmsg = ca_file_revoke_crt (id);
	if (errmsg) {
                ca_error_dialog (_(errmsg));

        }

	ca_refresh_model ();
  
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
	gchar * csr_parent_id;

	if (type != 2)
		return;
		
	gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, CA_MODEL_COLUMN_PEM, &csr_pem, CA_MODEL_COLUMN_PARENT_ID, &csr_parent_id, -1);

	new_cert_window_display (csr_pem, csr_parent_id);
	
	g_free (csr_pem);
        g_free (csr_parent_id);
}



gboolean ca_open (gchar *filename, gboolean create) 
{
	if (! ca_file_open (filename, create))
		return FALSE;

	__enable_widget ("new_certificate1");
	__enable_widget ("save_as1");
	__enable_widget ("properties1");
	__enable_widget ("preferences1");


	ca_refresh_model ();
	
	
	return TRUE;
}

guint64 ca_get_selected_row_id ()
{
	GtkTreeIter *iter;
	guint64 result;

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
        gboolean successful_import = FALSE;
	GError *error = NULL;
	guchar *file_contents = NULL;
        gsize   file_contents_size = 0;
	
	GMappedFile * mapped_file = g_mapped_file_new (filename, FALSE, &error);

	if (error) {
		ca_error_dialog (_(error->message));
		return FALSE;
	}

	file_contents_size = g_mapped_file_get_length (mapped_file);
	file_contents = g_new0 (guchar, file_contents_size);
	memcpy (file_contents, g_mapped_file_get_contents (mapped_file), file_contents_size);
	
	g_mapped_file_free (mapped_file);


	// We start to check each type of file, in PEM and DER
	// formats, for see if some of them matches with the actual file


	// Certificate request
        successful_import = import_csr (file_contents, file_contents_size);

	// Certificate list (or single certificate)
        if (! successful_import)
                successful_import = import_certlist (file_contents, file_contents_size);

	// Private key without password
        if (! successful_import)
                successful_import = import_pkey_wo_passwd (file_contents, file_contents_size);

	// Certificate revocation list
        if (! successful_import)
                successful_import = import_crl (file_contents, file_contents_size);
	
	// PKCS7 structure
        if (! successful_import)
                successful_import = import_pkcs7 (file_contents, file_contents_size);

	// PKCS12 structure
        if (! successful_import)
                successful_import = import_pkcs12 (file_contents, file_contents_size);

        g_free (file_contents);

	if (successful_import) {
		ca_refresh_model();
	} else {
		ca_error_dialog (_("Couldn't find any supported format in the given file"));
	}

	return TRUE;

}

void ca_update_csr_view (gboolean new_value, gboolean refresh)
{
        view_csr = new_value;
        gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(glade_xml_get_widget(main_window_xml, "csr_view_menuitem")), new_value);
        if (refresh)
                ca_refresh_model ();
}

gboolean ca_csr_view_toggled (GtkCheckMenuItem *button, gpointer user_data)
{
        ca_update_csr_view (gtk_check_menu_item_get_active (button), TRUE);
        if (view_csr != preferences_get_crq_visible())
                preferences_set_crq_visible (view_csr);

        return TRUE;
}

void ca_update_revoked_view (gboolean new_value, gboolean refresh)
{
        view_rcrt = new_value;
        gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(glade_xml_get_widget(main_window_xml, "revoked_view_menuitem")), new_value);
        if (refresh)
                ca_refresh_model ();
}

gboolean ca_rcrt_view_toggled (GtkCheckMenuItem *button, gpointer user_data)
{
        ca_update_revoked_view (gtk_check_menu_item_get_active (button), TRUE);
        if (view_rcrt != preferences_get_revoked_visible())
                preferences_set_revoked_visible (view_rcrt);

        return TRUE;
}

void ca_generate_crl (GtkCheckMenuItem *item, gpointer user_data)
{
        crl_window_display ();
}




gboolean ca_treeview_popup_timeout_program_cb (gpointer data)
{
	GtkWidget *menu, *widget;
	GtkTreeView * tree_view =  GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview"));
	GdkEventButton *event_button = (GdkEventButton *) data;
	GtkTreeIter *iter;
	gboolean pk_indb, is_revoked;
	gint selection_type;

	selection_type  = __ca_selection_type (tree_view, &iter);
	switch (selection_type) {
		
	case 1:
		menu = glade_xml_get_widget (cert_popup_menu_xml,
					     "certificate_popup_menu");
		
		gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
				   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
				   CA_MODEL_COLUMN_REVOCATION, &is_revoked, -1);
		
		widget = glade_xml_get_widget (cert_popup_menu_xml, "extract_pkey_menuitem");
		gtk_widget_set_sensitive (widget, pk_indb);
		
		widget = glade_xml_get_widget (cert_popup_menu_xml, "revoke_menuitem");
		gtk_widget_set_sensitive (widget, (! is_revoked));

		gtk_menu_popup (GTK_MENU(menu), NULL, NULL, NULL, NULL, 
				event_button->button, event_button->time);
		return FALSE;
	case 2:
		menu = glade_xml_get_widget (csr_popup_menu_xml,
					     "csr_popup_menu");

		gtk_tree_model_get(GTK_TREE_MODEL(ca_model), iter, 
				   CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB, &pk_indb, 
				   -1);
		
		widget = glade_xml_get_widget (csr_popup_menu_xml, "extract_pkey_menuitem3");
		gtk_widget_set_sensitive (widget, pk_indb);
		
		gtk_menu_popup (GTK_MENU(menu), NULL, NULL, NULL, NULL, 
				event_button->button, event_button->time);
		return FALSE;
	default:
	case 0:
		return FALSE;
	}

}

void ca_treeview_popup_timeout_program (GdkEventButton *event)
{
	g_timeout_add (1, ca_treeview_popup_timeout_program_cb, event); 

}
					

gboolean ca_treeview_popup_handler (GtkTreeView *tree_view,
				    GdkEvent *event, gpointer user_data)
{
	GdkEventButton *event_button;
	
	g_return_val_if_fail (event != NULL, FALSE);
	
	if (event->type == GDK_BUTTON_PRESS) {

		event_button = (GdkEventButton *) event;
		if (event_button->button == 3) {
			ca_treeview_popup_timeout_program (event_button);
		}
	}
	
	return FALSE;
}

void ca_on_change_pwd_menuitem_activate (GtkMenuItem *menuitem, gpointer user_data) 
{
	GtkWidget * widget = NULL;
	GtkDialog * dialog = NULL;
	GladeXML * dialog_xml = NULL;
	gchar     * xml_file = NULL;
	const gchar *newpwd;
	const gchar *currpwd;

	gint response = 0;
	gboolean repeat;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "change_password_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	

	if (ca_file_is_password_protected()) {
		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_pwd_protect_yes_radiobutton");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label1");
		g_object_set (G_OBJECT(widget), "visible", TRUE, NULL);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_current_pwd_entry");
		g_object_set (G_OBJECT(widget), "visible", TRUE, NULL);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label2");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label3");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_commit_button");
		gtk_widget_set_sensitive (widget, FALSE);

	} else {
		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_pwd_protect_no_radiobutton");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(widget), TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label1");
		g_object_set (G_OBJECT(widget), "visible", FALSE, NULL);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_current_pwd_entry");
		g_object_set (G_OBJECT(widget), "visible", FALSE, NULL);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label2");
		gtk_widget_set_sensitive (widget, FALSE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label3");
		gtk_widget_set_sensitive (widget, FALSE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (widget, FALSE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (widget, FALSE);

	}

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_pwd_protect_yes_radiobutton");
	g_object_set_data (G_OBJECT(widget), "dialog_xml", dialog_xml);

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
	g_object_set_data (G_OBJECT(widget), "dialog_xml", dialog_xml);

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry2");
	g_object_set_data (G_OBJECT(widget), "dialog_xml", dialog_xml);

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_current_pwd_entry");
	g_object_set_data (G_OBJECT(widget), "dialog_xml", dialog_xml);

	
	do {

		widget = glade_xml_get_widget (dialog_xml, "change_password_dialog");
		gtk_window_set_title (GTK_WINDOW(widget), _("Change CA password - gnoMint"));
		response = gtk_dialog_run(GTK_DIALOG(widget)); 
		
		if (!response || response == GTK_RESPONSE_CANCEL) {
			gtk_widget_destroy (widget);
			g_object_unref (G_OBJECT(dialog_xml));
			return;
		} 
		
		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
		newpwd = gtk_entry_get_text (GTK_ENTRY(widget));
		
		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_current_pwd_entry");
		currpwd = gtk_entry_get_text (GTK_ENTRY(widget));

		repeat = (ca_file_is_password_protected() && ! ca_file_check_password (currpwd));
		
		if (repeat) {
			ca_error_dialog (_("The current password you have entered  "
					   "doesn't match with the actual current database password."));
			widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_current_pwd_entry");
			gtk_widget_grab_focus (widget);
		} 

	} while (repeat);
	
	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_pwd_protect_yes_radiobutton");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {

		if (ca_file_is_password_protected()) {
			// It's a password change

			if (! ca_file_password_change (currpwd, newpwd)) {
				ca_error_dialog (_("Error while changing database password. "
						   "The operation was cancelled."));
			} else {
				widget = glade_xml_get_widget (dialog_xml, "change_password_dialog");
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
				ca_error_dialog (_("Error while establishing database password. "
						   "The operation was cancelled."));

			} else {
				widget = glade_xml_get_widget (dialog_xml, "change_password_dialog");
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
				ca_error_dialog (_("Error while removing database password. "
						   "The operation was cancelled."));
			} else {
				widget = glade_xml_get_widget (dialog_xml, "change_password_dialog");
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

	widget = glade_xml_get_widget (dialog_xml, "change_password_dialog");
	gtk_widget_destroy (widget);

}


gboolean ca_changepwd_newpwd_entry_changed (GtkWidget *entry, gpointer user_data)
{
	GladeXML * dialog_xml = g_object_get_data (G_OBJECT(entry), "dialog_xml");
	GtkWidget *widget;

	const gchar *pwd1;
	const gchar *pwd2;
	const gchar *currpwd;
	gboolean pwd_protect;

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_pwd_protect_yes_radiobutton");
	pwd_protect = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
	pwd1 = gtk_entry_get_text (GTK_ENTRY(widget));

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry2");
	pwd2 = gtk_entry_get_text (GTK_ENTRY(widget));

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_current_pwd_entry");
	currpwd = gtk_entry_get_text (GTK_ENTRY(widget));

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_commit_button");
	if (pwd_protect) {
		if (strlen(pwd1) && strlen(pwd2) && ! strcmp(pwd1, pwd2)) {
			if (!ca_file_is_password_protected() || (ca_file_is_password_protected() && strlen(currpwd)))
				gtk_widget_set_sensitive (widget, TRUE);
			else
				gtk_widget_set_sensitive (widget, FALSE);			
		} else {
			gtk_widget_set_sensitive (widget, FALSE);		
		}
	} else {
		gtk_widget_set_sensitive (widget, TRUE);
	}

	return FALSE;
}

gboolean ca_changepwd_pwd_protect_radiobutton_toggled (GtkWidget *button, gpointer user_data)
{
	GladeXML * dialog_xml;
	GtkWidget * widget = NULL;


	if (! G_IS_OBJECT(button))
		return TRUE;

	dialog_xml = g_object_get_data (G_OBJECT(button), "dialog_xml");
	if (! dialog_xml)
		return TRUE;

	widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_pwd_protect_yes_radiobutton");
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		/* We want to password-protect the database */
		
		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label2");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label3");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (widget, TRUE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (widget, TRUE);

		ca_changepwd_newpwd_entry_changed (button, NULL);
	
	} else {

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label2");
		gtk_widget_set_sensitive (widget, FALSE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_label3");
		gtk_widget_set_sensitive (widget, FALSE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry1");
		gtk_widget_set_sensitive (widget, FALSE);

		widget = glade_xml_get_widget (dialog_xml, "ca_changepwd_newpwd_entry2");
		gtk_widget_set_sensitive (widget, FALSE);
	}

	return FALSE;
}


void ca_generate_dh_param (GtkWidget *menuitem, gpointer user_data)
{
	GtkWidget * widget = NULL;
	GtkDialog * dialog = NULL, * dialog2 = NULL;
	GladeXML * dialog_xml = NULL;
	GIOChannel * file = NULL;
	gchar     * xml_file = NULL;
	gchar *filename, * pem = NULL;
	GError * error = NULL;
	gint response = 0;
	guint dh_size;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "dh_parameters_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	
	

	dialog = GTK_DIALOG(glade_xml_get_widget (dialog_xml, "dh_parameters_dialog"));
	response = gtk_dialog_run(dialog); 
	
	if (!response) {
		gtk_widget_destroy (GTK_WIDGET(dialog));
		g_object_unref (G_OBJECT(dialog_xml));
		return;
	} 

	widget = glade_xml_get_widget (dialog_xml, "dh_prime_size_spinbutton");
	dh_size = gtk_spin_button_get_value (GTK_SPIN_BUTTON(widget));

	pem = tls_generate_dh_params (dh_size);

	dialog2 = GTK_DIALOG (gtk_file_chooser_dialog_new (_("Save Diffie-Hellman parameters"),
							  GTK_WINDOW(widget),
							  GTK_FILE_CHOOSER_ACTION_SAVE,
							  GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
							  GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
							  NULL));
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog2), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog2)) == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog2));
		file = g_io_channel_new_file (filename, "w", &error);
		if (error) {
			gtk_widget_destroy (GTK_WIDGET(dialog2));
			gtk_widget_destroy (GTK_WIDGET(dialog));
			ca_error_dialog (_("There was an error while saving Diffie-Hellman parameters."));
			return;
		} 

                g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
                if (error) {
                        gtk_widget_destroy (GTK_WIDGET(dialog2));
			gtk_widget_destroy (GTK_WIDGET(dialog));
			ca_error_dialog (_("There was an error while saving Diffie-Hellman parameters."));
			return;
                } 

                g_io_channel_shutdown (file, TRUE, &error);
                if (error) {
                        gtk_widget_destroy (GTK_WIDGET(dialog2));
			gtk_widget_destroy (GTK_WIDGET(dialog));
			ca_error_dialog (_("There was an error while saving Diffie-Hellman parameters."));
                        return;
                } 

                g_io_channel_unref (file);

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
	
	
	return;
}


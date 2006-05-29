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
#include <sqlite.h>

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

#include "ca_file.h"

extern GladeXML * main_window_xml;
extern sqlite * ca_db;

GtkTreeStore * ca_model = NULL;

enum {CA_MODEL_COLUMN_ID=0,
      CA_MODEL_COLUMN_IS_CA=1,
      CA_MODEL_COLUMN_SERIAL=2,
      CA_MODEL_COLUMN_SUBJECT=3,
      CA_MODEL_COLUMN_ACTIVATION=4,
      CA_MODEL_COLUMN_EXPIRATION=5,
      CA_MODEL_COLUMN_IS_REVOKED=6,
      CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB=7,
      CA_MODEL_COLUMN_NUMBER=8}
CaModelColumns;

void __disable_widget (gchar *widget_name);
void __enable_widget (gchar *widget_name);


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames)
{
	static gboolean ca_inserted=FALSE;
	static GtkTreeIter * last_ca_iter = NULL;
	GtkTreeIter iter;
	GtkTreeStore * new_model = GTK_TREE_STORE(pArg);
	
	gtk_tree_store_append (new_model, &iter, last_ca_iter);

	gtk_tree_store_set (new_model, &iter,
			    0, atoi(argv[CA_MODEL_COLUMN_ID]),
			    1, atoi(argv[CA_MODEL_COLUMN_IS_CA]),
			    2, atoi(argv[CA_MODEL_COLUMN_SERIAL]),
			    3, argv[CA_MODEL_COLUMN_SUBJECT],
			    4, atoi(argv[CA_MODEL_COLUMN_ACTIVATION]),
			    5, atoi(argv[CA_MODEL_COLUMN_EXPIRATION]),
			    6, atoi(argv[CA_MODEL_COLUMN_IS_REVOKED]),
			    7, atoi(argv[CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB]),
			    -1);

	if (atoi(argv[CA_MODEL_COLUMN_IS_CA]) != 0) {
		ca_inserted = 1;
		last_ca_iter = gtk_tree_iter_copy (&iter);
	}
	
	

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
	gmtime_r (&model_time, &model_time_tm);
	
	size = strftime (model_time_str, 200, "%c", &model_time_tm);
	result = strdup (model_time_str);

	g_object_set(G_OBJECT(cell), "text", result, NULL);
}

gboolean ca_refresh_model () 
{
	gchar * error_str = NULL;
	GtkTreeIter iter;
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
	*/

	new_model = gtk_tree_store_new (8, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_INT, G_TYPE_STRING, 
					G_TYPE_INT, G_TYPE_INT, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);

	sqlite_exec (ca_db, "SELECT id, is_ca, serial, subject, activation, expiration, is_revoked, private_key_in_db FROM certificates ORDER BY id",
		     __ca_refresh_model_add_certificate, new_model, &error_str);

	treeview = GTK_TREE_VIEW(glade_xml_get_widget (main_window_xml, "ca_treeview"));

	if (ca_model) {
		g_object_unref (ca_model);		
	} else {
		/* There's no model assigned to the treeview yet, so we add its columns */
		
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
							     -1, _("Serial"), renderer,
							     "text", CA_MODEL_COLUMN_SERIAL,
							     NULL);

		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
							     -1, _("Subject"), renderer,
							     "text", CA_MODEL_COLUMN_SUBJECT,
							     NULL);


		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
							     -1, _("CA"), renderer,
							     "text", CA_MODEL_COLUMN_IS_CA,
							     NULL);
		renderer = GTK_CELL_RENDERER(gtk_cell_renderer_text_new ());

		gtk_tree_view_insert_column_with_attributes (treeview,
							     -1, _("Private key in DB"), renderer,
							     "text", CA_MODEL_COLUMN_PRIVATE_KEY_IN_DB,
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


	}



	gtk_tree_view_set_model (treeview, new_model);
	ca_model = new_model;

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


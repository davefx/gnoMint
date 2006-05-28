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


int __ca_refresh_model_add_certificate (void *pArg, int argc, char **argv, char **columnNames)
{
	static GtkTreeIter last_ca_iter;
	GtkTreeStore * new_model = GTK_TREE_STORE(pArg);
	int i;
	
	for (i = 0; i < argc; i++)
		printf("[%s]=%s\n", columnNames[i], argv[i]);
	
	printf("\n\n\n");
	
	return 0;
}

gboolean ca_refresh_model () 
{
	gchar * error_str = NULL;
	GtkTreeIter iter;
	GtkTreeStore * new_model = NULL;
	
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


}


gboolean ca_open (gchar *filename) 
{
	if (! ca_file_open (filename))
		return FALSE;

	ca_refresh_model ();
	
	
	return TRUE;
}


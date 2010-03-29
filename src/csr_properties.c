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


#include <glib-object.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>

#include "tls.h"
#include "csr_properties.h"

#include <glib/gi18n.h>


GtkBuilder * csr_properties_window_gtkb = NULL;

void __csr_properties_populate (const char *csr_pem, gboolean);

void csr_properties_display(const char *csr_pem, gboolean privkey_in_db)
{
	GObject * widget = NULL;

	csr_properties_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (csr_properties_window_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "csr_properties_dialog.ui", NULL),
				   NULL);
	gtk_builder_connect_signals (csr_properties_window_gtkb, NULL);
	
	__csr_properties_populate (csr_pem, privkey_in_db);
       
	widget = gtk_builder_get_object (csr_properties_window_gtkb, "csr_properties_dialog");
	gtk_widget_show (GTK_WIDGET(widget));
}


void __csr_properties_populate (const char *csr_pem, gboolean privkey_in_db)
{
	GObject *widget = NULL;
	TlsCsr * csr = NULL;

	csr = tls_parse_csr_pem (csr_pem);

	widget = gtk_builder_get_object (csr_properties_window_gtkb, "certSubjectCNLabel1");	
	gtk_label_set_text (GTK_LABEL(widget), csr->cn);

	widget = gtk_builder_get_object (csr_properties_window_gtkb, "certSubjectOLabel1");	
	gtk_label_set_text (GTK_LABEL(widget), csr->o);

	widget = gtk_builder_get_object (csr_properties_window_gtkb, "certSubjectOULabel1");	
	gtk_label_set_text (GTK_LABEL(widget), csr->ou);

	if (! privkey_in_db) {
		widget = gtk_builder_get_object (csr_properties_window_gtkb, "privatekey_in_db_label");
		gtk_label_set_markup (GTK_LABEL(widget), _("<b>This Certificate Signing Request has its corresponding private key saved in a external file.</b>"));

	}

	tls_csr_free (csr);
}

G_MODULE_EXPORT void csr_properties_close_clicked (const char *csr_pem)
{
        GObject *widget = NULL;
	widget = gtk_builder_get_object (csr_properties_window_gtkb, "csr_properties_dialog");
	g_assert (widget);
	gtk_widget_destroy (GTK_WIDGET(widget));
}


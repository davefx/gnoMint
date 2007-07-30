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

#include "tls.h"


#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)




GladeXML * csr_properties_window_xml = NULL;

void __csr_properties_populate (const char *csr_pem, gboolean);

void csr_properties_display(const char *csr_pem, gboolean privkey_in_db)
{
	gchar     * xml_file = NULL;
	GtkWidget * widget = NULL;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	// Workaround for libglade
	volatile GType foo = GTK_TYPE_FILE_CHOOSER_WIDGET, tst;
	tst = foo;
	csr_properties_window_xml = glade_xml_new (xml_file, "csr_properties_dialog", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (csr_properties_window_xml); 	
	
	__csr_properties_populate (csr_pem, privkey_in_db);
       
	widget = glade_xml_get_widget (csr_properties_window_xml, "csr_properties_dialog");
	gtk_widget_show (widget);
}


void __csr_properties_populate (const char *csr_pem, gboolean privkey_in_db)
{
	GtkWidget *widget = NULL;
	TlsCsr * csr = NULL;

	csr = tls_parse_csr_pem (csr_pem);

	widget = glade_xml_get_widget (csr_properties_window_xml, "certSubjectCNLabel");	
	gtk_label_set_text (GTK_LABEL(widget), csr->cn);

	widget = glade_xml_get_widget (csr_properties_window_xml, "certSubjectOLabel");	
	gtk_label_set_text (GTK_LABEL(widget), csr->o);

	widget = glade_xml_get_widget (csr_properties_window_xml, "certSubjectOULabel");	
	gtk_label_set_text (GTK_LABEL(widget), csr->ou);

	if (! privkey_in_db) {
		widget = glade_xml_get_widget (csr_properties_window_xml, "privatekey_in_db_label");
		gtk_label_set_markup (GTK_LABEL(widget), "<b>This Certificate Signing Request has its corresponding private key saved in a external file.</b>");

	}

	tls_csr_free (csr);
}

void csr_properties_close_clicked (const char *csr_pem)
{
        GtkWidget *widget = NULL;
	widget = glade_xml_get_widget (csr_properties_window_xml, "csr_properties_dialog");
	g_assert (widget);
	gtk_widget_destroy (widget);
}


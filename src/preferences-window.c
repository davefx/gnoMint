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

#include "preferences-gui.h"
#include "preferences-window.h"

#include <glib/gi18n.h>

GladeXML *preferences_window_xml = NULL;

void preferences_window_display()
{
	gchar     * xml_file = NULL;
        GtkWidget * widget = NULL;
	volatile GType foo = GTK_TYPE_FILE_CHOOSER_WIDGET, tst;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	// Workaround for libglade
	tst = foo;
	preferences_window_xml = glade_xml_new (xml_file, "preferences_dialog", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (preferences_window_xml); 	
	
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(glade_xml_get_widget(preferences_window_xml, "gnomekeyring_export_check")),
                                      preferences_get_gnome_keyring_export());
	widget = glade_xml_get_widget (preferences_window_xml, "preferences_dialog");

        gtk_widget_show (widget);

}


void preferences_window_gnomekeyring_export_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
        gboolean new_status = gtk_toggle_button_get_active (togglebutton);
        gboolean current_status = preferences_get_gnome_keyring_export();

        if (new_status != current_status)
                preferences_set_gnome_keyring_export (new_status);
}

void preferences_window_ok_button_clicked_cb (GtkButton *button, gpointer user_data)
{
       	GtkWidget *widget = glade_xml_get_widget (preferences_window_xml, "preferences_dialog");
	gtk_widget_destroy (widget); 

}

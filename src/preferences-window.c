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

#include "preferences-gui.h"
#include "preferences-window.h"

#include <glib/gi18n.h>

GtkBuilder *preferences_window_gtkb = NULL;

void preferences_window_display()
{
        GtkWidget * widget = NULL;

	preferences_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (preferences_window_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "preferences_dialog.ui", NULL),
				   NULL);
	gtk_builder_connect_signals (preferences_window_gtkb, NULL);
	
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_builder_get_object(preferences_window_gtkb, "gnomekeyring_export_check")),
                                      preferences_get_gnome_keyring_export());
	widget = GTK_WIDGET(gtk_builder_get_object (preferences_window_gtkb, "preferences_dialog"));

        gtk_widget_show (widget);

}


G_MODULE_EXPORT void preferences_window_gnomekeyring_export_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
        gboolean new_status = gtk_toggle_button_get_active (togglebutton);
        gboolean current_status = preferences_get_gnome_keyring_export();

        if (new_status != current_status)
                preferences_set_gnome_keyring_export (new_status);
}

G_MODULE_EXPORT void preferences_window_ok_button_clicked_cb (GtkButton *button, gpointer user_data)
{
       	GtkWidget *widget = GTK_WIDGET(gtk_builder_get_object (preferences_window_gtkb, "preferences_dialog"));
	gtk_widget_destroy (widget); 

}

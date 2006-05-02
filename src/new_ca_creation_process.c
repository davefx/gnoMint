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

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

#include "ca_creation.h"

GladeXML * new_ca_window_process_xml = NULL;

gint timer=0;
GThread * new_ca_creation_process_thread = NULL;

gint new_ca_creation_pulse (gpointer data)
{
	GtkWidget * widget = NULL;

	widget = glade_xml_get_widget (new_ca_window_process_xml, "new_ca_creation_process_progressbar");

	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(widget));

	ca_creation_lock_status_mutex();
	
	if (strcmp(ca_creation_get_thread_message(), gtk_progress_bar_get_text(GTK_PROGRESS_BAR(widget)))) {
		gtk_progress_bar_set_text (GTK_PROGRESS_BAR(widget), ca_creation_get_thread_message());
		printf ("%s\n", ca_creation_get_thread_message());
	}

	if (ca_creation_get_thread_status() != 0) {
		g_thread_join (new_ca_creation_process_thread);
		printf ("Finalizado proceso de creacion\n");
		gtk_timeout_remove (timer);	       
	}

	ca_creation_unlock_status_mutex();

	return 1;
}


void new_ca_creation_process_window_display (CaCreationData * ca_creation_data)
{
	gchar     * xml_file = NULL;
	GtkWidget * widget = NULL;
	
	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	// Workaround for libglade
	volatile GType foo = GTK_TYPE_FILE_CHOOSER_WIDGET;

	new_ca_window_process_xml = glade_xml_new (xml_file, "new_ca_creation_process", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (new_ca_window_process_xml); 	
	
	new_ca_creation_process_thread = ca_creation_launch_thread (ca_creation_data);

	widget = glade_xml_get_widget (new_ca_window_process_xml, "new_ca_creation_process_progressbar");

	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(widget));

	gtk_progress_bar_set_text (GTK_PROGRESS_BAR(widget), ca_creation_get_thread_message());

	timer = gtk_timeout_add (100, new_ca_creation_pulse, NULL);


}




/* to remove a timer */
//gtk_timeout_remove (timer);


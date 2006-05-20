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


void new_ca_creation_process_error_dialog (gchar *message) {

   GtkWidget *dialog, *label, *widget;
   
   widget = glade_xml_get_widget (new_ca_window_process_xml, "new_ca_creation_process");

   /* Create the widgets */
   
   dialog = gtk_dialog_new_with_buttons (NULL,
                                         GTK_WINDOW(widget),
                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_STOCK_CLOSE,
                                         GTK_RESPONSE_NONE,
                                         NULL);
   label = gtk_label_new (message);
   
   /* Ensure that the dialog box is destroyed when the user responds. */
   
   g_signal_connect_swapped (dialog,
                             "response", 
                             G_CALLBACK (gtk_widget_destroy),
                             dialog);

   /* Add the label, and show everything we've added to the dialog. */

   gtk_container_add (GTK_CONTAINER (GTK_DIALOG(dialog)->vbox),
                      label);
   gtk_dialog_run (GTK_DIALOG(dialog));

   //g_free (message);
}

gint new_ca_creation_pulse (gpointer data)
{
	GtkWidget * widget = NULL;
	gchar *error_message = NULL;
	gint status = 0;

	widget = glade_xml_get_widget (new_ca_window_process_xml, "new_ca_creation_process_progressbar");

	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(widget));

	widget = glade_xml_get_widget (new_ca_window_process_xml, "status_message_label");

	ca_creation_lock_status_mutex();

	if (strcmp(ca_creation_get_thread_message(), gtk_label_get_text(GTK_LABEL(widget)))) {
		gtk_label_set_text (GTK_LABEL(widget), ca_creation_get_thread_message());
		printf ("%s\n", ca_creation_get_thread_message());
	}
	
	status = ca_creation_get_thread_status(); 

	ca_creation_unlock_status_mutex();


	if (status > 0) {
		g_thread_join (new_ca_creation_process_thread);
		printf ("Finalizado proceso de creacion correctamente\n");
		gtk_timeout_remove (timer);	       
	} else if (status < 0) {
		error_message = (gchar *) g_thread_join (new_ca_creation_process_thread);
		if (error_message) {
			new_ca_creation_process_error_dialog (error_message);
			printf ("%s\n\n", error_message);
		}
		gtk_timeout_remove (timer);	       
	}



	return 1;
}




void new_ca_creation_process_window_display (CaCreationData * ca_creation_data)
{
	gchar     * xml_file = NULL;
	GtkWidget * widget = NULL;
	
	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	new_ca_window_process_xml = glade_xml_new (xml_file, "new_ca_creation_process", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (new_ca_window_process_xml); 	
	
	new_ca_creation_process_thread = ca_creation_launch_thread (ca_creation_data);

	widget = glade_xml_get_widget (new_ca_window_process_xml, "new_ca_creation_process_progressbar");

	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(widget));

	gtk_progress_bar_set_text (GTK_PROGRESS_BAR(widget), ca_creation_get_thread_message());

	timer = gtk_timeout_add (100, new_ca_creation_pulse, NULL);


}




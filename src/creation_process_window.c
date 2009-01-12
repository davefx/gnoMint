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
#include <libintl.h>
#include <stdlib.h>
#include <string.h>

#include <glib/gi18n.h>


#include "ca_creation.h"
#include "csr_creation.h"
#include "ca_file.h"
#include "ca_policy.h"
#include "ca.h"
#include "creation_process_window.h"

GladeXML * creation_process_window_xml = NULL;

gint timer=0;
GThread * creation_process_window_thread = NULL;


void creation_process_window_error_dialog (gchar *message) 
{

   GtkWidget *dialog, *widget;
   
   widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window");
   
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

void creation_process_window_ca_finish (void) 
{
	GtkWidget *widget = NULL, *dialog = NULL;
	
	g_thread_join (creation_process_window_thread);
	gtk_timeout_remove (timer);	       
	timer = 0;
	
	widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window");
	
        ca_refresh_model();

        dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_MESSAGE_INFO,
                                         GTK_BUTTONS_CLOSE,
                                         "%s",
                                         _("CA creation process finished"));
        gtk_dialog_run (GTK_DIALOG(dialog));
        
        gtk_widget_destroy (GTK_WIDGET(dialog));
        gtk_widget_destroy (widget);
			

}



gint creation_process_window_ca_pulse (gpointer data)
{
	GtkWidget * widget = NULL;
	gchar *error_message = NULL;
	gint status = 0;

	gtk_progress_bar_set_pulse_step (GTK_PROGRESS_BAR(data), 0.1);
	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(data));

	widget = glade_xml_get_widget (creation_process_window_xml, "status_message_label");

	ca_creation_lock_status_mutex();

	if (strcmp(ca_creation_get_thread_message(), gtk_label_get_text(GTK_LABEL(widget)))) {
		gtk_label_set_text (GTK_LABEL(widget), ca_creation_get_thread_message());
	}
	
	status = ca_creation_get_thread_status(); 

	ca_creation_unlock_status_mutex();

	gtk_main_iteration();

	if (status > 0) {
		creation_process_window_ca_finish ();
	} else if (status < 0) {
		error_message = (gchar *) g_thread_join (creation_process_window_thread);
		gtk_timeout_remove (timer);	       
		timer = 0;
		if (error_message) {
			creation_process_window_error_dialog (error_message);
			printf ("%s\n\n", error_message);
		}
		widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window");
		gtk_widget_destroy (widget);
	}



	return 1;
}





void creation_process_window_ca_display (CaCreationData * ca_creation_data)
{
	gchar     * xml_file = NULL;
	GtkWidget * widget = NULL;
	
	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	creation_process_window_xml = glade_xml_new (xml_file, "creation_process_window", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (creation_process_window_xml); 	
	
	creation_process_window_thread = ca_creation_launch_thread (ca_creation_data);

	widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window_progressbar");

	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(widget));

	timer = g_timeout_add (100, creation_process_window_ca_pulse, widget);


}


void on_cancel_creation_process_clicked (GtkButton *button,
			      gpointer user_data) 
{
	
   GtkWidget *dialog, *widget;

   if (timer) {
	   gtk_timeout_remove (timer);	       
	   timer = 0;
   }
   
   widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window");

   /* Create the widgets */

   dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
				    GTK_DIALOG_DESTROY_WITH_PARENT,
				    GTK_MESSAGE_INFO,
				    GTK_BUTTONS_CLOSE,
				    "%s",
				    _("Creation process cancelled"));
   
   gtk_dialog_run (GTK_DIALOG(dialog));

   gtk_widget_destroy (GTK_WIDGET(dialog));

   gtk_widget_destroy (widget);
	
}



// ********************** CSRs

void creation_process_window_csr_finish (void) {
	GtkWidget *widget = NULL, *dialog = NULL;
	
	g_thread_join (creation_process_window_thread);
	gtk_timeout_remove (timer);	       
	timer = 0;
	
	widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window");
	
	dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_INFO,
					 GTK_BUTTONS_CLOSE,
					 "%s",
					 _("CSR creation process finished"));
	gtk_dialog_run (GTK_DIALOG(dialog));
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	gtk_widget_destroy (widget);

	ca_refresh_model ();
}

gint creation_process_window_csr_pulse (gpointer data)
{
	GtkWidget * widget = NULL;
	gchar *error_message = NULL;
	gint status = 0;

	gtk_progress_bar_set_pulse_step (GTK_PROGRESS_BAR(data), 0.1);
	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(data));

	widget = glade_xml_get_widget (creation_process_window_xml, "status_message_label");

	csr_creation_lock_status_mutex();

	if (strcmp(csr_creation_get_thread_message(), gtk_label_get_text(GTK_LABEL(widget)))) {
		gtk_label_set_text (GTK_LABEL(widget), csr_creation_get_thread_message());
	}
	
	status = csr_creation_get_thread_status(); 

	csr_creation_unlock_status_mutex();

	gtk_main_iteration();

	if (status > 0) {
		creation_process_window_csr_finish ();
	} else if (status < 0) {
		error_message = (gchar *) g_thread_join (creation_process_window_thread);
		gtk_timeout_remove (timer);	       
		timer = 0;
		if (error_message) {
			creation_process_window_error_dialog (error_message);
			printf ("%s\n\n", error_message);
		}
		widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window");
		gtk_widget_destroy (widget);
	}



	return 1;
}

void creation_process_window_csr_display (CaCreationData * ca_creation_data)
{
	gchar     * xml_file = NULL;
	GtkWidget * widget = NULL;
	
	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	 
	creation_process_window_xml = glade_xml_new (xml_file, "creation_process_window", NULL);
	
	g_free (xml_file);
	
	glade_xml_signal_autoconnect (creation_process_window_xml); 	
	
	widget = glade_xml_get_widget (creation_process_window_xml, "titleLabel");
	gtk_label_set_text (GTK_LABEL (widget), _("Creating Certificate Signing Request"));

	creation_process_window_thread = csr_creation_launch_thread (ca_creation_data);

	widget = glade_xml_get_widget (creation_process_window_xml, "creation_process_window_progressbar");

	gtk_progress_bar_pulse (GTK_PROGRESS_BAR(widget));

	timer = g_timeout_add (100, creation_process_window_csr_pulse, widget);


}

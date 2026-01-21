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

#include <glib/gi18n.h>


#include "ca_creation.h"
#include "csr_creation.h"
#include "dialog.h"
#include "creation_process_window.h"

GtkBuilder * creation_process_window_gtkb = NULL;

gint timer=0;
GThread * creation_process_window_thread = NULL;


void creation_process_window_error_dialog (gchar *message) 
{

	GtkWidget *dialog;
	GObject *widget;
   
	widget = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window");
   
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
	GObject *widget = NULL;
	GtkWidget *dialog = NULL;
	
	g_thread_join (creation_process_window_thread);
	g_source_remove (timer);	       
	timer = 0;
	
	widget = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window");
	
        dialog_refresh_list();

        dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_MESSAGE_INFO,
                                         GTK_BUTTONS_CLOSE,
                                         "%s",
                                         _("CA creation process finished"));
        gtk_dialog_run (GTK_DIALOG(dialog));
        
        gtk_widget_destroy (GTK_WIDGET(dialog));
        gtk_widget_destroy (GTK_WIDGET(widget));
			

}



gint creation_process_window_ca_pulse (gpointer data)
{
	GObject * widget = NULL;
	gchar *error_message = NULL;
	gint status = 0;

	/* Only pulse if we have a valid progress bar widget */
	if (data && GTK_IS_PROGRESS_BAR(data)) {
		gtk_progress_bar_set_pulse_step (GTK_PROGRESS_BAR(data), 0.1);
		gtk_progress_bar_pulse (GTK_PROGRESS_BAR(data));
	}

	widget = gtk_builder_get_object (creation_process_window_gtkb, "status_message_label");

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
		g_source_remove (timer);	       
		timer = 0;
		if (error_message) {
			creation_process_window_error_dialog (error_message);
			printf ("%s\n\n", error_message);
		}
		widget = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window");
		gtk_widget_destroy (GTK_WIDGET(widget));
	}



	return 1;
}





void creation_process_window_ca_display (TlsCreationData * ca_creation_data)
{
	GObject * widget = NULL;
	GObject * progressbar = NULL;
	GError * error = NULL;
		 
	creation_process_window_gtkb = gtk_builder_new();
	
	if (!gtk_builder_add_from_file (creation_process_window_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "creation_process_window.ui", NULL ),
				   &error)) {
		g_critical("Failed to load UI file: %s", error ? error->message : "unknown error");
		if (error) g_error_free(error);
		return;
	}
	
	gtk_builder_connect_signals (creation_process_window_gtkb, NULL); 	
	
	widget = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window");
	if (!widget) {
		g_critical("Failed to get creation_process_window widget");
		return;
	}
	
	gtk_widget_show_all (GTK_WIDGET(widget));
	
	/* Process pending events to ensure window is displayed */
	while (gtk_events_pending())
		gtk_main_iteration();

	creation_process_window_thread = ca_creation_launch_thread (ca_creation_data);

	progressbar = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window_progressbar");
	
	/* Timer must always start to monitor thread status */
	if (progressbar && GTK_IS_PROGRESS_BAR(progressbar)) {
		/* Ensure progress bar is visible and pulse it initially */
		gtk_widget_show (GTK_WIDGET(progressbar));
		gtk_progress_bar_pulse (GTK_PROGRESS_BAR(progressbar));
		timer = g_timeout_add (100, creation_process_window_ca_pulse, progressbar);
	} else {
		/* Fallback: start timer with NULL, pulse callback will handle it */
		if (!progressbar) {
			g_warning("Progress bar widget 'creation_process_window_progressbar' not found in UI file");
		} else {
			g_warning("Widget 'creation_process_window_progressbar' is not a valid GtkProgressBar");
		}
		timer = g_timeout_add (100, creation_process_window_ca_pulse, NULL);
	}

}


G_MODULE_EXPORT void on_cancel_creation_process_clicked (GtkButton *button,
					 gpointer user_data) 
{
	
	GtkWidget *dialog, *widget;

	if (timer) {
		g_source_remove (timer);	       
		timer = 0;
	}
   
	widget = GTK_WIDGET(gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window"));

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
	g_source_remove (timer);	       
	timer = 0;
	
	widget = GTK_WIDGET(gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window"));
	
	dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
					 GTK_DIALOG_DESTROY_WITH_PARENT,
					 GTK_MESSAGE_INFO,
					 GTK_BUTTONS_CLOSE,
					 "%s",
					 _("CSR creation process finished"));
	gtk_dialog_run (GTK_DIALOG(dialog));
	
	gtk_widget_destroy (GTK_WIDGET(dialog));
	gtk_widget_destroy (widget);

	dialog_refresh_list ();
}

gint creation_process_window_csr_pulse (gpointer data)
{
	GtkWidget * widget = NULL;
	gchar *error_message = NULL;
	gint status = 0;

	/* Only pulse if we have a valid progress bar widget */
	if (data && GTK_IS_PROGRESS_BAR(data)) {
		gtk_progress_bar_set_pulse_step (GTK_PROGRESS_BAR(data), 0.1);
		gtk_progress_bar_pulse (GTK_PROGRESS_BAR(data));
	}

	widget = GTK_WIDGET(gtk_builder_get_object (creation_process_window_gtkb, "status_message_label"));

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
		g_source_remove (timer);	       
		timer = 0;
		if (error_message) {
			creation_process_window_error_dialog (error_message);
			printf ("%s\n\n", error_message);
		}
		widget = GTK_WIDGET(gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window"));
		gtk_widget_destroy (widget);
	}



	return 1;
}

void creation_process_window_csr_display (TlsCreationData * ca_creation_data)
{
	GObject * widget = NULL;
	GObject * progressbar = NULL;
	GError * error = NULL;
	
	creation_process_window_gtkb = gtk_builder_new();
	
	if (!gtk_builder_add_from_file (creation_process_window_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "creation_process_window.ui", NULL),
				   &error)) {
		g_critical("Failed to load UI file: %s", error ? error->message : "unknown error");
		if (error) g_error_free(error);
		return;
	}
	
	gtk_builder_connect_signals (creation_process_window_gtkb, NULL); 	
	
	widget = gtk_builder_get_object (creation_process_window_gtkb, "titleLabel");
	if (widget) {
		gtk_label_set_text (GTK_LABEL (widget), _("Creating Certificate Signing Request"));
	}

	widget = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window");
	if (!widget) {
		g_critical("Failed to get creation_process_window widget");
		return;
	}
	
	gtk_widget_show_all (GTK_WIDGET(widget));
	
	/* Process pending events to ensure window is displayed */
	while (gtk_events_pending())
		gtk_main_iteration();

	creation_process_window_thread = csr_creation_launch_thread (ca_creation_data);

	progressbar = gtk_builder_get_object (creation_process_window_gtkb, "creation_process_window_progressbar");
	
	/* Timer must always start to monitor thread status */
	if (progressbar && GTK_IS_PROGRESS_BAR(progressbar)) {
		/* Ensure progress bar is visible and pulse it initially */
		gtk_widget_show (GTK_WIDGET(progressbar));
		gtk_progress_bar_pulse (GTK_PROGRESS_BAR(progressbar));
		timer = g_timeout_add (100, creation_process_window_csr_pulse, progressbar);
	} else {
		/* Fallback: start timer with NULL, pulse callback will handle it */
		if (!progressbar) {
			g_warning("Progress bar widget 'creation_process_window_progressbar' not found in UI file");
		} else {
			g_warning("Widget 'creation_process_window_progressbar' is not a valid GtkProgressBar");
		}
		timer = g_timeout_add (100, creation_process_window_csr_pulse, NULL);
	}

}

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

#include <libintl.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#include "new_ca_window.h"
#include "tls.h"

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

gchar * PACKAGE_AUTHORS[] = {
	"David Marín Carreño <davefx@gmail.com>",
	NULL
};

GladeXML * main_window_xml = NULL;

gchar * gnomint_current_opened_file = NULL;
gchar * gnomint_temp_created_file = NULL;

void __disable_widget (gchar *widget_name)
{
	GtkWidget * widget = NULL;

	widget = glade_xml_get_widget (main_window_xml, widget_name);

	gtk_widget_set_sensitive (widget, FALSE);
}

void __enable_widget (gchar *widget_name)
{
	GtkWidget * widget = NULL;

	widget = glade_xml_get_widget (main_window_xml, widget_name);

	gtk_widget_set_sensitive (widget, TRUE);
}

int main (int   argc,
	  char *argv[])
{
/* 	gboolean silent = FALSE; */
/* 	gchar *savefile = NULL; */
	GOptionContext *ctx;
	GError *err = NULL;
	GOptionEntry entries[] = {
/* 		{ "silent", 's', 0, G_OPTION_ARG_NONE, &silent, 0, */
/* 		  "do not output status information", NULL }, */
/* 		{ "output", 'o', 0, G_OPTION_ARG_STRING, &savefile, 0, */
/* 		  "save xml representation of pipeline to FILE and exit", "FILE" }, */
		{ NULL }
	};

	gchar     * xml_file = NULL;


#ifdef ENABLE_NLS
	bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	g_set_application_name (PACKAGE);
	g_set_prgname (PACKAGE);

	tls_init ();

	g_thread_init (NULL);
	gtk_init (&argc, &argv);

	ctx = g_option_context_new (_("- A graphical Certification Authority manager"));
	g_option_context_add_main_entries (ctx, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
		g_print (_("Failed to initialize: %s\n"), err->message);
		g_error_free (err);
		return 1;
	}
	

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );

	main_window_xml = glade_xml_new (xml_file, "main_window1", NULL);

	g_free (xml_file);

	glade_xml_signal_autoconnect (main_window_xml);	       	

	__disable_widget ("new_certificate1");
	__disable_widget ("save_as1");
	__disable_widget ("properties1");
	__disable_widget ("preferences1");
	

	if (argc >= 2)
		ca_open (g_strdup(argv[1]));

	gtk_main ();

	return 0;
}


gboolean on_main_window1_delete (GtkWidget *widget,
				  GdkEvent *event,
				  gpointer user_data)
{
	exit (0);
	return TRUE;
}


/*
 *
 *   FILE MENU CALLBACKS
 *
 */ 


void on_new1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	new_ca_window_display();
	
}

void on_new_certificate1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	new_cert_window_display();
	
}

void on_open1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	gchar *filename;

	GtkWidget *dialog, *widget;
	
	widget = glade_xml_get_widget (main_window_xml, "main_window");
	
	dialog = gtk_file_chooser_dialog_new (_("Open CA database"),
					      GTK_WINDOW(widget),
					      GTK_FILE_CHOOSER_ACTION_OPEN,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					      NULL);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
	{
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		gtk_widget_destroy (dialog);
	} else {
		gtk_widget_destroy (dialog);
		return;
	}		
	
	if (! ca_open (filename)) {
		dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when opening '%s' CA database"),
						 filename);
		
		gtk_dialog_run (GTK_DIALOG(dialog));
		
		gtk_widget_destroy (dialog);
	}
	return;
}

void on_save_as1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	gchar *filename;

	GtkWidget *dialog, *widget;
	
	widget = glade_xml_get_widget (main_window_xml, "main_window");
	
	dialog = gtk_file_chooser_dialog_new (_("Save CA database as..."),
					      GTK_WINDOW(widget),
					      GTK_FILE_CHOOSER_ACTION_SAVE,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					      NULL);
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		gtk_widget_destroy (dialog);
	} else {
		gtk_widget_destroy (dialog);
		return;
	}		
	
	ca_file_save_as (filename);

}

void on_quit1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	on_main_window1_delete(NULL, NULL, NULL);
}



/*
 *
 *   EDIT MENU CALLBACKS
 *
 */ 

void on_clear1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	printf ("clear1 Activated\n");
}

void on_properties1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	printf ("properties1 Activated\n");
}

void on_preferences1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	printf ("Preferences1 Activated\n");
}


/*
 *
 *   VIEW MENU CALLBACKS
 *
 */ 


/*
 *
 *   HELP MENU CALLBACKS
 *
 */ 

void on_about1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	
	GtkAboutDialog *dialog;
	GtkWidget *widget;
	
	widget = glade_xml_get_widget (main_window_xml, "main_window");
	
/* 	dialog = gtk_about_dialog_new (); */

/* 	gtk_about_dialog_set_version (dialog, PACKAGE_VERSION); */
/* 	gtk_about_dialog_set_copyright (dialog, PACKAGE_COPYRIGHT); */
/* 	gtk_about_dialog_set_comments (dialog, _("gnoMint is a program for creating and managing Certification Authorities, and their certificates")); */
/* 	gtk_about_dialog_set_license (dialog, _("This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. \n\nYou should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.")); */
/* 	gtk_about_dialog_set_wrap_license (dialog, TRUE); */
/* 	gtk_about_dialog_set_website (dialog, PACKAGE_WEBSITE); */
/* 	gtk_about_dialog_set_authors (dialog, PACKAGE_AUTHORS); */
/* 	gtk_about_dialog_set_translator_credits (dialog, _("translator-credits")); */

	gtk_show_about_dialog (GTK_WINDOW(widget), 
			       "version", PACKAGE_VERSION,
			       "copyright", PACKAGE_COPYRIGHT,
			       "comments", _("gnoMint is a program for creating and managing Certification Authorities, and their certificates"),
			       "license",  _("This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. \n\nYou should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA."),
			       "wrap_license", TRUE,
			       "website", PACKAGE_WEBSITE,
			       "authors", PACKAGE_AUTHORS,
			       "translator_credits", _("translator-credits"),
			       NULL);
}



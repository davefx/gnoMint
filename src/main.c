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

#include <libintl.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <stdlib.h>

#include "main.h"
#include "ca.h"
#include "dialog.h"
#include "tls.h"
#include "ca_file.h"
#include "preferences-gui.h"

#define GNOMINT_MIME_TYPE "application/x-gnomint"

GtkBuilder * main_window_gtkb = NULL;
GtkBuilder * csr_popup_menu_gtkb = NULL;
GtkBuilder * cert_popup_menu_gtkb = NULL;

gchar * gnomint_current_opened_file = NULL;

static GtkRecentManager *recent_manager;

void __recent_add_utf8_filename (const gchar *utf8_filename);
void __disable_widget (gchar *widget_name);
void __enable_widget (gchar *widget_name);
GtkWidget * __recent_create_menu (void);
void __recent_add_utf8_filename (const gchar *utf8_filename);



void __disable_widget (gchar *widget_name)
{
	GtkWidget * widget = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, widget_name));

	gtk_widget_set_sensitive (widget, FALSE);
}

void __enable_widget (gchar *widget_name)
{
	GtkWidget * widget = NULL;

	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, widget_name));

	gtk_widget_set_sensitive (widget, TRUE);
}

/*****************************************************************************/
/* Create a menu of recent files.                                            */
/*****************************************************************************/
GtkWidget * __recent_create_menu (void)
{
        GtkWidget               *recent_menu;
        GtkRecentFilter         *recent_filter;
	
        recent_menu = gtk_recent_chooser_menu_new_for_manager (recent_manager);
        gtk_recent_chooser_menu_set_show_numbers (GTK_RECENT_CHOOSER_MENU (recent_menu), FALSE);
        gtk_recent_chooser_set_show_icons (GTK_RECENT_CHOOSER (recent_menu), TRUE);
        gtk_recent_chooser_set_limit (GTK_RECENT_CHOOSER (recent_menu), 4);
        gtk_recent_chooser_set_sort_type (GTK_RECENT_CHOOSER (recent_menu), GTK_RECENT_SORT_MRU);
        gtk_recent_chooser_set_local_only (GTK_RECENT_CHOOSER (recent_menu), TRUE);

        recent_filter = gtk_recent_filter_new ();
        gtk_recent_filter_add_mime_type (recent_filter, GNOMINT_MIME_TYPE);
        gtk_recent_chooser_set_filter (GTK_RECENT_CHOOSER (recent_menu), recent_filter);

        return recent_menu;
}


int main (int   argc,
	  char *argv[])
{
        gchar *defaultfile = NULL;
	GOptionContext *ctx;
	GError *err = NULL;
	GOptionEntry entries[] = {
		{ NULL }
	};
	
	GtkWidget * recent_menu = NULL;
        gchar     * size_str = NULL;

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
	
	preferences_gui_set_csr_visible_callback (ca_update_csr_view);
	preferences_gui_set_revoked_visible_callback (ca_update_revoked_view);

        preferences_init (argc, argv);

	ctx = g_option_context_new (_("- A graphical Certification Authority manager"));
	g_option_context_add_main_entries (ctx, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
		g_print (_("Failed to initialize: %s\n"), err->message);
		g_error_free (err);
		return 1;
	}
	
	main_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (main_window_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "main_window.ui", NULL),
				   NULL);

	csr_popup_menu_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (csr_popup_menu_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "csr_popup_menu.ui", NULL),
				   NULL);

	cert_popup_menu_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (cert_popup_menu_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "certificate_popup_menu.ui", NULL),
				   NULL);


        size_str = preferences_get_size ();
        if (size_str) {
                gchar ** result = NULL;
                guint width, height;

                result = g_strsplit_set (size_str, "(,)", -1);
                
                if (result[0] && result[1]) {
                        width = atoi (result[1]);
                        if (result[2]) {
                                height = atoi (result[2]);
                                gtk_window_resize (GTK_WINDOW(gtk_builder_get_object(main_window_gtkb, "main_window1")), width, height);
                        }

                }

                g_free (size_str);
                g_strfreev (result);
        }
        ca_update_revoked_view (preferences_get_revoked_visible(), FALSE);
        ca_update_csr_view (preferences_get_crq_visible(), FALSE);
        

	gtk_builder_connect_signals (main_window_gtkb, NULL);	       	
	gtk_builder_connect_signals (cert_popup_menu_gtkb, NULL);	       	
	gtk_builder_connect_signals (csr_popup_menu_gtkb, NULL);	       	

	recent_manager = gtk_recent_manager_get_default ();
	recent_menu = __recent_create_menu();
	g_signal_connect (G_OBJECT (recent_menu), "item-activated",
			  G_CALLBACK (on_open_recent_activate), NULL);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (gtk_builder_get_object (main_window_gtkb, "openrecentsmenuitem")), recent_menu);


	__disable_widget ("new_certificate1");
	__disable_widget ("save_as1");
	__disable_widget ("properties1");
	__disable_widget ("preferences1");

	dialog_establish_refresh_function (ca_refresh_model_callback);
	

	if (argc >= 2 && ca_open (g_strdup(argv[1]), TRUE)) {
                /* The file has opened OK */
		__recent_add_utf8_filename (argv[1]);
        } else {
                /* No arguments, or failure when opening file */
                defaultfile = g_build_filename (g_get_home_dir(), ".gnomint", "default.gnomint", NULL);
		__recent_add_utf8_filename (defaultfile);
                ca_open (defaultfile, TRUE);
        }

	gtk_main ();

	return 0;
}



gboolean on_main_window1_delete (GtkWidget *widget,
				  GdkEvent *event,
				  gpointer user_data)
{
        GtkWindow *window = GTK_WINDOW(widget);
        int width, height;
        gchar *new_size_value;
        
        gtk_window_get_size (window, &width, &height);
        new_size_value = g_strdup_printf ("(%d,%d)", width, height);
        
        preferences_set_size (new_size_value);

        g_free (new_size_value);
        preferences_deinit();

	exit (0);
	return TRUE;
}

void __recent_add_utf8_filename (const gchar *utf8_filename)
{
        GtkRecentData *recent_data;
        gchar         *filename;
        gchar         *uri;
	gchar         *pwd;

        static gchar *groups[2] = {
                "gnomint",
                NULL
        };


        recent_data = g_slice_new (GtkRecentData);

        recent_data->display_name = NULL;
        recent_data->description  = NULL;
        recent_data->mime_type    = GNOMINT_MIME_TYPE;
        recent_data->app_name     = (gchar *) g_get_application_name ();
        recent_data->app_exec     = g_strjoin (" ", g_get_prgname (), "%f", NULL);
        recent_data->groups       = groups;
        recent_data->is_private = FALSE;

        filename = g_filename_from_utf8 (utf8_filename, -1, NULL, NULL, NULL);
        if ( filename != NULL )
        {

		if (! g_path_is_absolute (filename)) {
			gchar *absolute_filename;

			pwd = g_get_current_dir ();
			absolute_filename = g_build_filename (pwd, filename, NULL);
			g_free (pwd);
			g_free (filename);
			filename = absolute_filename;
		}


                uri = g_filename_to_uri (filename, NULL, NULL);
                if ( uri != NULL )
                {

                        gtk_recent_manager_add_full (recent_manager, uri, recent_data);
                        g_free (uri);

                }
                g_free (filename);

        }

        g_free (recent_data->app_exec);
        g_slice_free (GtkRecentData, recent_data);

}

void on_new1_activate (GtkMenuItem *menuitem, gpointer     user_data)
{
	gchar *filename;
        gchar *error = NULL;

	GtkWidget *dialog, *widget;
	
	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window"));
	
	dialog = gtk_file_chooser_dialog_new (_("Create new CA database"),
					      GTK_WINDOW(widget),
					      GTK_FILE_CHOOSER_ACTION_SAVE,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					      NULL);
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);

	
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
	{
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		gtk_widget_destroy (dialog);
	} else {
		gtk_widget_destroy (dialog);
		return;
	}		
	
        if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
                /* The file already exists. The user has confirmed its overwriting.
                   So we, first, rename it to "filename~", after deleting "filename~" if it already exists */

                gchar *backup_filename = g_strdup_printf ("%s~", filename);
                if (g_file_test (backup_filename, G_FILE_TEST_EXISTS)) {
                        g_remove (backup_filename);
                }

                g_rename (filename, backup_filename);
                
                g_free (backup_filename);
        }

        error = ca_file_create (filename);
        if (error) {
		dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when creating '%s' CA database:\n%s"),
						 filename, error);
		
		gtk_dialog_run (GTK_DIALOG(dialog));
		                
                return;
        }

	if (! ca_open (filename, FALSE)) {
		dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when opening new '%s' CA database"),
						 filename);
		
		gtk_dialog_run (GTK_DIALOG(dialog));
		
		gtk_widget_destroy (dialog);
	} else {
		__recent_add_utf8_filename (filename);
        }
	return;

}

void on_open1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	gchar *filename;

	GtkWidget *dialog, *widget;
	
	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window"));
	
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
	
	

	if (! ca_open (filename, FALSE)) {
		dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when opening '%s' CA database"),
						 filename);
		
		gtk_dialog_run (GTK_DIALOG(dialog));
		
		gtk_widget_destroy (dialog);
	} else {
		__recent_add_utf8_filename (filename);
	}
	return;
}

void on_open_recent_activate (GtkRecentChooser *chooser, gpointer user_data)
{
        GtkRecentInfo *item;
	gchar *filename;
	gchar *utf8_filename = NULL;
	GtkWidget *dialog;
	const gchar *uri;

        g_return_if_fail (chooser && GTK_IS_RECENT_CHOOSER(chooser));

        item = gtk_recent_chooser_get_current_item (chooser);
        if (!item)
                return;

	uri = gtk_recent_info_get_uri (item);

        filename = g_filename_from_uri (uri, NULL, NULL);
        if ( filename != NULL )
        {
                utf8_filename = g_filename_to_utf8 (filename, -1, NULL, NULL, NULL);
                g_free (filename);
        }

        if (! utf8_filename || ! ca_open (utf8_filename, FALSE)) {
		dialog = gtk_message_dialog_new (NULL,
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when opening '%s' CA database"),
						 utf8_filename);
		
		gtk_dialog_run (GTK_DIALOG(dialog));
		
		gtk_widget_destroy (dialog);
	} else {
		__recent_add_utf8_filename (utf8_filename);
	}

        gtk_recent_info_unref (item);


	return;
}


void on_save_as1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	gchar *filename;

	GtkWidget *dialog, *widget;
	
	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window"));
	
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
	
	if (ca_file_save_as (filename))
                __recent_add_utf8_filename (filename);

}



void on_quit1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	on_main_window1_delete(NULL, NULL, NULL);
}





/*
 *
 *   HELP MENU CALLBACKS
 *
 */ 

void on_about1_activate  (GtkMenuItem *menuitem, gpointer     user_data)
{
	
	GtkWidget *widget;
	gchar *authors[2];
	
	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window"));

	authors[0] = PACKAGE_AUTHORS;
	authors[1] = NULL;
	
	gtk_show_about_dialog (GTK_WINDOW(widget), 
			       "version", PACKAGE_VERSION, 
			       "copyright", PACKAGE_COPYRIGHT,
			       "comments", _("gnoMint is a program for creating and managing Certification Authorities, and their certificates"),
			       "license",  _("This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. \n\nYou should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA."),
			       "wrap_license", TRUE,
			       "website", PACKAGE_WEBSITE,
			       "authors", authors, 
			       "translator_credits", _("translator-credits"),
			       NULL); 
}

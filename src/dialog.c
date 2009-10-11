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


#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "dialog.h"

DialogRefreshCallback dialog_refresh_callback = NULL;

void dialog_establish_refresh_function (DialogRefreshCallback callback)
{
	dialog_refresh_callback = callback;
}

gboolean dialog_refresh_list (void)
{
	return dialog_refresh_callback();
}


#ifdef GNOMINTCLI

#include <readline/readline.h>
#include <readline/history.h>


void dialog_info (gchar *message) {
        printf ("\nInfo: %s\n\n", message);
}

void dialog_error (gchar *message) {
        fprintf (stderr, "\nError: %s\n\n", message);
}

gchar * dialog_get_password (gchar *info_message, 
                                gchar *password_message, gchar *confirm_message, 
                                gchar *distinct_error_message, guint minimum_length)
{
	gchar * res = NULL;
        gchar * password = NULL;
	gchar * password2 = NULL;

	printf ("%s\n\n", info_message);

	do {
		if (res) {
			g_free (res);
			res = NULL;
		}

		password = getpass(password_message);

		if (! password || password[0]=='\0')
			return NULL;

		res = g_strdup (password);
		if (strlen (res) < minimum_length) {
			fprintf (stderr, _("\nThe password must have, at least, %d characters\n"), minimum_length); 
			continue;
		}
		memset (password, 0, strlen (res));

		password2 = getpass(confirm_message);

		if (strcmp (res, password2)) {
			fprintf (stderr, "\n%s\n", distinct_error_message);
			memset (password, 0, strlen (password2));		
		}

	} while (strlen (res) < minimum_length || strcmp (res, password2) );

	memset (password, 0, strlen (password2));		

	return res;
}


gboolean dialog_ask_for_confirmation (gchar *message, gchar *prompt, gboolean default_answer)
{
	gchar *line;

	const gchar *positive_answers = Q_("List of affirmative answers, separated with #|Yes#yes#Y#y");
	const gchar *negative_answers = Q_("List of negative answers, separated with #|No#no#N#n");
	
	gchar **aux;
	gint i;

	if (message)
		printf ("%s\n", message);

	while (TRUE) {

		line = readline (prompt);
		
		if (line == NULL)
			return default_answer;
		
		if (strlen (line) == 0)
			return default_answer;
		

		aux = g_strsplit (positive_answers, "#", -1);
		i = 0;

		while (aux[i]) {
			if (!strcmp (line, aux[i])) {
				free (line);
				g_strfreev (aux);
				return TRUE;
			}
			i++;
		}
		g_strfreev (aux);

		aux = g_strsplit (negative_answers, "#", -1);
		i = 0;

		while (aux[i]) {
			if (!strcmp (line, aux[i])) {
				free (line);
				g_strfreev (aux);
				return FALSE;
			}
			i++;
		}
		g_strfreev (aux);

		free (line);
	} 
		
	
}


gint dialog_ask_for_number (gchar *message, gint minimum, gint maximum, gint default_value)
{
	gchar *line;
	gchar *prompt = NULL;
	gint result;
	gboolean keep_trying = TRUE;

	if (! message)
		message = "";

	g_assert (minimum <= default_value);
	g_assert (maximum >= default_value);

	if (maximum == default_value)
		prompt = g_strdup_printf ("%s (%d - [%d]): ", message, minimum, maximum);
	else if (minimum == default_value)
		prompt = g_strdup_printf ("%s ([%d] - %d): ", message, minimum, maximum);
	else 
		prompt = g_strdup_printf ("%s (%d - [%d] - %d): ", message, minimum, default_value, maximum);

	while (keep_trying) {
		line = readline (prompt);
		
		if (line == NULL || strlen (line) == 0) {
			result = default_value;
			keep_trying = FALSE;		
		}
		if (atoi (line) <= maximum && atoi(line) >= minimum) {
			result = (atoi (line));
			keep_trying = FALSE;
		}
		
		if (line)
			free (line);
	} 	

	g_free (prompt);
	return result;
	
}

gchar * dialog_ask_for_password (gchar *message)
{
	gchar *password;
	gchar *aux = NULL;


	aux = getpass (message);
	
	if (!aux || aux[0] == '\0') {
		return NULL;
	} else {
		password = g_strdup (aux);
		memset (aux, 0, strlen(aux));
	}
	
	return password;
}

gchar * dialog_ask_for_string (gchar *message, gchar *default_answer)
{
	gchar *prompt;
	gchar *result = NULL;
	char *line;

	printf ("%s\n", message);
	
	if (default_answer) {
		prompt = g_strdup_printf ("[%s] : ", default_answer);
	} else {
		prompt = g_strdup (": ");
	}


	line = readline (prompt);
	
	if (line == NULL || strlen(line) == 0) {
		if (default_answer)
			result = g_strdup(default_answer);
		else
			result = NULL;
	} else {
		result = g_strdup (line);
	}

	g_free (prompt);
	return result;
	
}

#else


#include <gtk/gtk.h>
#include <gdk/gdk.h>

void dialog_info (gchar *message) {
        GtkWidget *dialog;
   
        /* Create the widgets */
   
        dialog = gtk_message_dialog_new (NULL,
                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_MESSAGE_INFO,
                                         GTK_BUTTONS_CLOSE,
                                         "%s",
                                         message);
   
        gtk_dialog_run (GTK_DIALOG(dialog));
   
        gtk_widget_destroy (dialog);

}

void dialog_error (gchar *message) {
        GtkWidget *dialog;
   
        /* Create the widgets */
   
        dialog = gtk_message_dialog_new (NULL,
                                         GTK_DIALOG_DESTROY_WITH_PARENT,
                                         GTK_MESSAGE_ERROR,
                                         GTK_BUTTONS_CLOSE,
                                         "%s",
                                         message);
   
        gtk_dialog_run (GTK_DIALOG(dialog));
   
        gtk_widget_destroy (dialog);

}

gchar * dialog_get_password (gchar *info_message, 
			     gchar *password_message, gchar *confirm_message, 
			     gchar *distinct_error_message, guint minimum_length)
{
	GObject * widget = NULL, * password_widget = NULL;
	//GtkDialog * dialog = NULL;
	GtkBuilder * dialog_gtkb = NULL;
	gint response = 0;
	gchar *password = NULL;
	const gchar *passwordagain = NULL;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb, 
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "get_password_dialog.ui", NULL ),
				   NULL);
	gtk_builder_connect_signals (dialog_gtkb, NULL); 	
	
	widget = gtk_builder_get_object (dialog_gtkb, "info_message");
	gtk_label_set_text (GTK_LABEL(widget), info_message);
	widget = gtk_builder_get_object (dialog_gtkb, "password_message");
	gtk_label_set_text (GTK_LABEL(widget), password_message);
	widget = gtk_builder_get_object (dialog_gtkb, "confirm_message");
	gtk_label_set_text (GTK_LABEL(widget), confirm_message);

	password_widget = gtk_builder_get_object (dialog_gtkb, "password_entry");
	widget = gtk_builder_get_object (dialog_gtkb, "password_dialog_ok_button");
	g_object_set_data (G_OBJECT(password_widget), "minimum_length", 
                           GINT_TO_POINTER(minimum_length));
	g_object_set_data (G_OBJECT(password_widget), "ok_button", widget);

	do {
		gtk_widget_grab_focus (GTK_WIDGET(password_widget));

		if (password)
			g_free (password);

		widget = gtk_builder_get_object (dialog_gtkb, "get_password_dialog");
		response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
		if (!response) {
			gtk_widget_destroy (GTK_WIDGET(widget));
			g_object_unref (G_OBJECT(dialog_gtkb));
			return NULL;
		} else {
			widget = gtk_builder_get_object (dialog_gtkb, "password_entry");
			password = g_strdup(gtk_entry_get_text (GTK_ENTRY(widget)));
			widget = gtk_builder_get_object (dialog_gtkb, "confirm_entry");
			passwordagain = gtk_entry_get_text (GTK_ENTRY(widget));
		}
		
		if (strcmp (password, passwordagain)) {
			dialog_error (distinct_error_message);
		}

	} while (strcmp (password, passwordagain));

	widget = gtk_builder_get_object (dialog_gtkb, "get_password_dialog");
	gtk_widget_destroy (GTK_WIDGET(widget));
	g_object_unref (G_OBJECT(dialog_gtkb));
	
	return password;
}

void dialog_password_entry_changed_cb (GtkEditable *password_entry, gpointer user_data)
{
	GtkWidget * button = GTK_WIDGET(g_object_get_data (G_OBJECT(password_entry), "ok_button"));
	guint minimum_length = GPOINTER_TO_INT (g_object_get_data (G_OBJECT(password_entry), 
                                                                   "minimum_length"));

	if (strlen (gtk_entry_get_text (GTK_ENTRY(password_entry))) >= minimum_length)
		gtk_widget_set_sensitive (button, TRUE);
	else
		gtk_widget_set_sensitive (button, FALSE);
	
}




#endif


void dialog_todo ()
{
	dialog_error (_("To do. Feature not implemented yet."));
}

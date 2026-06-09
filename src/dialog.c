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


#include <config.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "dialog.h"


#ifdef WIN32
#include <conio.h>
char *getpass(const char *prompt)
{
	static char buf[128];
        size_t i;

        fputs(prompt, stderr);
        fflush(stderr);
	for (i = 0; i < sizeof(buf) - 1; i++)
       	{
		buf[i] = _getch();
                if (buf[i] == '\r')
			break;
	}
	buf[i] = 0;
	fputs("\n", stderr);
	return buf;
}
#endif


DialogRefreshCallback dialog_refresh_callback = NULL;

void dialog_establish_refresh_function (DialogRefreshCallback callback)
{
	dialog_refresh_callback = callback;
}

gboolean dialog_refresh_list (void)
{
	/* The CLI doesn't register a refresh callback — calling through a
	 * NULL function pointer would segfault. The GUI registers via
	 * dialog_establish_refresh_function in main.c. */
	if (!dialog_refresh_callback)
		return TRUE;
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
	gint result = default_value;
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

		if (line == NULL) {
			result = default_value;
			break;
		}
		if (strlen (line) == 0) {
			result = default_value;
			free (line);
			break;
		}
		if (atoi (line) <= maximum && atoi(line) >= minimum) {
			result = atoi (line);
			free (line);
			break;
		}
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

extern GtkBuilder *main_window_gtkb;

GtkWindow *
dialog_get_main_window (void)
{
        if (!main_window_gtkb) return NULL;
        GObject *w = gtk_builder_get_object (main_window_gtkb, "main_window1");
        return w ? GTK_WINDOW (w) : NULL;
}

void dialog_info (gchar *message) {
        GtkAlertDialog *alert = gtk_alert_dialog_new ("%s", message);
        gtk_alert_dialog_show (alert, dialog_get_main_window ());
        g_object_unref (alert);
}

void dialog_error (gchar *message) {
        GtkAlertDialog *alert = gtk_alert_dialog_new ("%s", message);
        gtk_alert_dialog_show (alert, dialog_get_main_window ());
        g_object_unref (alert);
}

/* --- Async password dialog (GUI) --- */

typedef struct {
	GtkBuilder             *dialog_gtkb;
	gchar                  *distinct_error_message;
	DialogPasswordCallback  cb;
	gpointer                user_data;
} _DialogGetPasswordCtx;

static void
_dialog_get_password_response (GtkDialog *dialog,
                               gint       response_id,
                               gpointer   user_data)
{
	_DialogGetPasswordCtx *ctx = (_DialogGetPasswordCtx *) user_data;
	GObject *widget;
	gchar *password;
	const gchar *passwordagain;

	if (!response_id || response_id == GTK_RESPONSE_CANCEL
	    || response_id == GTK_RESPONSE_DELETE_EVENT) {
		gtk_window_destroy (GTK_WINDOW (dialog));
		g_object_unref (G_OBJECT (ctx->dialog_gtkb));
		ctx->cb (NULL, ctx->user_data);
		g_free (ctx->distinct_error_message);
		g_free (ctx);
		return;
	}

	/* OK pressed -- validate */
	widget = gtk_builder_get_object (ctx->dialog_gtkb, "password_entry");
	password = g_strdup (gtk_editable_get_text (GTK_EDITABLE (widget)));
	widget = gtk_builder_get_object (ctx->dialog_gtkb, "confirm_entry");
	passwordagain = gtk_editable_get_text (GTK_EDITABLE (widget));

	if (strcmp (password, passwordagain)) {
		g_free (password);
		dialog_error (ctx->distinct_error_message);
		/* Re-present the dialog so the user can try again */
		widget = gtk_builder_get_object (ctx->dialog_gtkb, "password_entry");
		gtk_editable_set_text (GTK_EDITABLE (widget), "");
		widget = gtk_builder_get_object (ctx->dialog_gtkb, "confirm_entry");
		gtk_editable_set_text (GTK_EDITABLE (widget), "");
		widget = gtk_builder_get_object (ctx->dialog_gtkb, "password_entry");
		gtk_widget_grab_focus (GTK_WIDGET (widget));
		gtk_window_present (GTK_WINDOW (dialog));
		return;
	}

	/* Passwords match -- success */
	gtk_window_destroy (GTK_WINDOW (dialog));
	g_object_unref (G_OBJECT (ctx->dialog_gtkb));
	ctx->cb (password, ctx->user_data);
	g_free (ctx->distinct_error_message);
	g_free (ctx);
}

void dialog_get_password (gchar *info_message,
			  gchar *password_message, gchar *confirm_message,
			  gchar *distinct_error_message, guint minimum_length,
			  DialogPasswordCallback cb, gpointer user_data)
{
	GObject * widget = NULL, * password_widget = NULL;
	GtkBuilder * dialog_gtkb = NULL;
	_DialogGetPasswordCtx *ctx;

	dialog_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (dialog_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "get_password_dialog.ui", NULL ),
				   NULL);

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

	ctx = g_new0 (_DialogGetPasswordCtx, 1);
	ctx->dialog_gtkb = dialog_gtkb;
	ctx->distinct_error_message = g_strdup (distinct_error_message);
	ctx->cb = cb;
	ctx->user_data = user_data;

	widget = gtk_builder_get_object (dialog_gtkb, "get_password_dialog");
	g_signal_connect (GTK_DIALOG (widget), "response",
	                  G_CALLBACK (_dialog_get_password_response), ctx);

	gtk_widget_grab_focus (GTK_WIDGET (password_widget));
	gtk_window_set_transient_for (GTK_WINDOW (widget), dialog_get_main_window ());
	gtk_window_present (GTK_WINDOW (widget));
}

G_MODULE_EXPORT void dialog_password_entry_changed_cb (GtkEditable *password_entry, gpointer user_data)
{
	GtkWidget * button = GTK_WIDGET(g_object_get_data (G_OBJECT(password_entry), "ok_button"));
	guint minimum_length = GPOINTER_TO_INT (g_object_get_data (G_OBJECT(password_entry), 
                                                                   "minimum_length"));

	if (strlen (gtk_editable_get_text(GTK_EDITABLE(password_entry))) >= minimum_length)
		gtk_widget_set_sensitive (button, TRUE);
	else
		gtk_widget_set_sensitive (button, FALSE);
	
}




/* GtkNotebook Tab-focus fix for wizard pages.
 *
 * GtkNotebook's focus() override cycles Tab within the current page
 * content but never reaches sibling button boxes (Help/Cancel/Next)
 * at the bottom of the page.  This capture-phase key handler
 * intercepts Tab: when focus is NOT already in the button box, it
 * redirects focus there instead of letting the notebook wrap.
 */

typedef struct {
	GtkNotebook *notebook;
	GtkWidget  **button_boxes;
	int          n_pages;
} NotebookFocusFixData;

static GtkWidget *
_find_ancestor_child_of (GtkWidget *widget, GtkWidget *ancestor)
{
	GtkWidget *child = widget;
	GtkWidget *parent = gtk_widget_get_parent (child);
	while (parent && parent != ancestor) {
		child = parent;
		parent = gtk_widget_get_parent (child);
	}
	return (parent == ancestor) ? child : NULL;
}

static gboolean
_notebook_tab_capture_cb (GtkEventControllerKey *ctrl,
                          guint                  keyval,
                          guint                  keycode,
                          GdkModifierType        state,
                          gpointer               user_data)
{
	NotebookFocusFixData *data = user_data;
	GtkWidget *focused, *bbox;
	int page;

	if (keyval != GDK_KEY_Tab && keyval != GDK_KEY_ISO_Left_Tab)
		return FALSE;

	gboolean forward = !(state & GDK_SHIFT_MASK);

	page = gtk_notebook_get_current_page (data->notebook);
	if (page < 0 || page >= data->n_pages)
		return FALSE;

	bbox = data->button_boxes[page];
	if (!bbox)
		return FALSE;

	focused = gtk_window_get_focus (
	    GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (data->notebook))));
	if (!focused)
		return FALSE;

	GtkWidget *page_child = gtk_notebook_get_nth_page (data->notebook, page);
	if (!page_child)
		return FALSE;

	if (forward) {
		if (gtk_widget_is_ancestor (focused, bbox))
			return FALSE;

		/* Find which direct child of the page contains focus. */
		GtkWidget *focus_section = _find_ancestor_child_of (focused, page_child);
		if (!focus_section)
			return FALSE;

		/* Try to move within the current section first. */
		gboolean moved = gtk_widget_child_focus (focus_section, GTK_DIR_TAB_FORWARD);
		GtkWidget *after = gtk_window_get_focus (
		    GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (data->notebook))));

		if (moved && after != focused &&
		    !gtk_widget_is_ancestor (focused, after) &&
		    !gtk_widget_is_ancestor (after, focused))
			return TRUE; /* Moved to a different widget. */

		/* Section exhausted or focus moved within same widget tree
		 * — try the next sibling section, then the button box. */
		GtkWidget *next = gtk_widget_get_next_sibling (focus_section);
		while (next) {
			if (next == bbox) {
				gtk_widget_child_focus (bbox, GTK_DIR_TAB_FORWARD);
				return TRUE;
			}
			if (gtk_widget_child_focus (next, GTK_DIR_TAB_FORWARD)) {
				GtkWidget *now = gtk_window_get_focus (
				    GTK_WINDOW (gtk_widget_get_root (GTK_WIDGET (data->notebook))));
				if (now != focused)
					return TRUE;
			}
			next = gtk_widget_get_next_sibling (next);
		}

		/* No more siblings — go to button box. */
		gtk_widget_child_focus (bbox, GTK_DIR_TAB_FORWARD);
		return TRUE;
	} else {
		if (!gtk_widget_is_ancestor (focused, bbox))
			return FALSE;

		/* Shift+Tab from button box: go to last widget before it. */
		GtkWidget *prev = gtk_widget_get_prev_sibling (bbox);
		while (prev) {
			if (gtk_widget_child_focus (prev, GTK_DIR_TAB_BACKWARD))
				return TRUE;
			prev = gtk_widget_get_prev_sibling (prev);
		}
		return FALSE;
	}
}

void
dialog_notebook_fix_tab_focus (GtkNotebook *notebook,
                               const char **button_box_ids,
                               GtkBuilder  *builder)
{
	int n = 0;
	while (button_box_ids[n])
		n++;

	NotebookFocusFixData *data = g_new0 (NotebookFocusFixData, 1);
	data->notebook = notebook;
	data->n_pages = n;
	data->button_boxes = g_new0 (GtkWidget *, n);

	for (int i = 0; i < n; i++)
		data->button_boxes[i] = GTK_WIDGET (
		    gtk_builder_get_object (builder, button_box_ids[i]));

	GtkEventController *kc = gtk_event_controller_key_new ();
	gtk_event_controller_set_propagation_phase (kc, GTK_PHASE_CAPTURE);
	g_signal_connect (kc, "key-pressed",
	                  G_CALLBACK (_notebook_tab_capture_cb), data);
	gtk_widget_add_controller (GTK_WIDGET (notebook), kc);
}

#endif


void dialog_todo ()
{
	dialog_error (_("To do. Feature not implemented yet."));
}

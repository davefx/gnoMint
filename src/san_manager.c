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

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <string.h>
#include <arpa/inet.h>
#include <regex.h>

#include "san_manager.h"

// Private data structure for SAN manager
typedef struct {
	GtkTreeView *treeview;
	GtkListStore *model;
	GtkButton *add_button;
	GtkButton *edit_button;
	GtkButton *remove_button;
	GtkBuilder *editor_builder;
} SanManagerData;

static const gchar * san_type_to_string(SanType type) {
	switch (type) {
		case SAN_TYPE_DNS: return "DNS";
		case SAN_TYPE_IP: return "IP";
		case SAN_TYPE_EMAIL: return "EMAIL";
		case SAN_TYPE_URI: return "URI";
		default: return "DNS";
	}
}

static SanType san_type_from_string(const gchar *type_str) {
	if (g_ascii_strcasecmp(type_str, "IP") == 0 || g_ascii_strcasecmp(type_str, "IP Address") == 0)
		return SAN_TYPE_IP;
	if (g_ascii_strcasecmp(type_str, "EMAIL") == 0 || g_ascii_strcasecmp(type_str, "Email") == 0 || 
	    g_ascii_strcasecmp(type_str, "RFC822") == 0)
		return SAN_TYPE_EMAIL;
	if (g_ascii_strcasecmp(type_str, "URI") == 0)
		return SAN_TYPE_URI;
	return SAN_TYPE_DNS;
}

gboolean san_validate(SanType type, const gchar *value, gchar **error_message) {
	if (!value || !value[0]) {
		if (error_message)
			*error_message = g_strdup(_("Value cannot be empty"));
		return FALSE;
	}
	
	switch (type) {
		case SAN_TYPE_DNS: {
			// Basic DNS validation - must be alphanumeric with dots, dashes, and asterisk for wildcards
			regex_t regex;
			int ret = regcomp(&regex, "^(\\*\\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", REG_EXTENDED);
			if (ret == 0) {
				ret = regexec(&regex, value, 0, NULL, 0);
				regfree(&regex);
				if (ret == 0)
					return TRUE;
			} else {
				regfree(&regex);
			}
			if (error_message)
				*error_message = g_strdup(_("Invalid DNS name. Use format: example.com or *.example.com"));
			return FALSE;
		}
		
		case SAN_TYPE_IP: {
			// Validate IPv4 or IPv6
			struct in_addr ipv4;
			struct in6_addr ipv6;
			if (inet_pton(AF_INET, value, &ipv4) == 1 || inet_pton(AF_INET6, value, &ipv6) == 1)
				return TRUE;
			if (error_message)
				*error_message = g_strdup(_("Invalid IP address. Use IPv4 (e.g., 192.168.1.1) or IPv6 format"));
			return FALSE;
		}
		
		case SAN_TYPE_EMAIL: {
			// Basic email validation
			const gchar *at = strchr(value, '@');
			if (at && at != value && at[1] != '\0' && strchr(at + 1, '.'))
				return TRUE;
			if (error_message)
				*error_message = g_strdup(_("Invalid email address. Use format: user@example.com"));
			return FALSE;
		}
		
		case SAN_TYPE_URI: {
			// Basic URI validation - must start with a scheme
			if (g_str_has_prefix(value, "http://") || g_str_has_prefix(value, "https://") ||
			    g_str_has_prefix(value, "ftp://") || g_str_has_prefix(value, "ldap://"))
				return TRUE;
			if (error_message)
				*error_message = g_strdup(_("Invalid URI. Must start with http://, https://, ftp://, or ldap://"));
			return FALSE;
		}
	}
	
	return TRUE;
}

static void san_manager_selection_changed(GtkTreeSelection *selection, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	gboolean has_selection = gtk_tree_selection_get_selected(selection, NULL, NULL);
	
	gtk_widget_set_sensitive(GTK_WIDGET(data->edit_button), has_selection);
	gtk_widget_set_sensitive(GTK_WIDGET(data->remove_button), has_selection);
}

/* Context for the async SAN editor dialog. */
typedef struct {
	SanManagerData *data;
	gboolean        editing;       /* TRUE = edit existing row, FALSE = add new */
	GtkTreeIter     edit_iter;     /* valid only when editing == TRUE */
	gulong          response_handler_id;
} SanEditorCtx;

/* Forward declaration. */
static void san_editor_response (GtkDialog *dialog, gint response_id, gpointer user_data);

/* Fire-and-forget handler for the validation error dialog. */
static void
san_editor_error_response (GtkDialog *dialog,
                           gint       response_id G_GNUC_UNUSED,
                           gpointer   user_data   G_GNUC_UNUSED)
{
	gtk_window_destroy (GTK_WINDOW (dialog));
}

/* Response callback for the SAN editor dialog.
 * On OK: validate; if invalid show error and re-present; if valid update model.
 * On CANCEL / DELETE_EVENT: destroy dialog, clean up. */
static void
san_editor_response (GtkDialog *dialog, gint response_id, gpointer user_data)
{
	SanEditorCtx *ctx = (SanEditorCtx *) user_data;
	SanManagerData *data = ctx->data;

	if (response_id != GTK_RESPONSE_OK) {
		/* Cancel / close / delete-event */
		g_signal_handler_disconnect (dialog, ctx->response_handler_id);
		gtk_window_destroy (GTK_WINDOW (dialog));
		g_free (ctx);
		return;
	}

	/* OK pressed — validate input. */
	GtkComboBox *type_combo = GTK_COMBO_BOX (
		gtk_builder_get_object (data->editor_builder, "san_type_combo"));
	GtkEntry *value_entry = GTK_ENTRY (
		gtk_builder_get_object (data->editor_builder, "san_value_entry"));

	GtkTreeIter combo_iter;
	SanType type;
	if (gtk_combo_box_get_active_iter (type_combo, &combo_iter)) {
		GtkTreeModel *combo_model = gtk_combo_box_get_model (type_combo);
		gint type_int;
		gtk_tree_model_get (combo_model, &combo_iter, 1, &type_int, -1);
		type = (SanType) type_int;
	} else {
		type = SAN_TYPE_DNS;
	}

	const gchar *value = gtk_editable_get_text (GTK_EDITABLE (value_entry));
	gchar *error_msg = NULL;

	if (!san_validate (type, value, &error_msg)) {
		/* Show fire-and-forget error dialog, then re-present editor. */
		GtkWidget *err_dlg = gtk_message_dialog_new (
			GTK_WINDOW (dialog),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_MESSAGE_ERROR,
			GTK_BUTTONS_OK,
			"%s", error_msg);
		g_signal_connect (err_dlg, "response",
		                  G_CALLBACK (san_editor_error_response), NULL);
		gtk_window_present (GTK_WINDOW (err_dlg));
		g_free (error_msg);
		/* Re-present the same editor dialog so the user can correct. */
		gtk_window_present (GTK_WINDOW (dialog));
		return;
	}

	/* Valid — update the model. */
	gchar *type_str = g_strdup (san_type_to_string (type));
	gchar *value_str = g_strdup (value);

	if (ctx->editing) {
		gtk_list_store_set (data->model, &ctx->edit_iter,
		                    0, type_str,
		                    1, value_str,
		                    -1);
	} else {
		GtkTreeIter new_iter;
		gtk_list_store_append (data->model, &new_iter);
		gtk_list_store_set (data->model, &new_iter,
		                    0, type_str,
		                    1, value_str,
		                    -1);
	}

	g_free (type_str);
	g_free (value_str);

	g_signal_handler_disconnect (dialog, ctx->response_handler_id);
	gtk_window_destroy (GTK_WINDOW (dialog));
	g_free (ctx);
}

/* Present the SAN editor dialog asynchronously.  When the user confirms,
 * the response callback validates and updates the model. */
static void san_manager_show_editor_async(SanManagerData *data, const gchar *initial_type, const gchar *initial_value, gboolean editing, GtkTreeIter *edit_iter) {
	GtkDialog *dialog;
	GtkComboBox *type_combo;
	GtkEntry *value_entry;
	GtkWidget *parent;
	gchar *ui_file;

	// Load editor dialog if not already loaded
	if (!data->editor_builder) {
		data->editor_builder = gtk_builder_new();
		ui_file = g_build_filename(PACKAGE_DATA_DIR, "gnomint", "san_editor_dialog.ui", NULL);
		if (!gtk_builder_add_from_file(data->editor_builder, ui_file, NULL)) {
			g_free(ui_file);
			return;
		}
		g_free(ui_file);
	}

	dialog = GTK_DIALOG(gtk_builder_get_object(data->editor_builder, "san_editor_dialog"));
	type_combo = GTK_COMBO_BOX(gtk_builder_get_object(data->editor_builder, "san_type_combo"));
	value_entry = GTK_ENTRY(gtk_builder_get_object(data->editor_builder, "san_value_entry"));

	// Set parent window
	parent = GTK_WIDGET(gtk_widget_get_root(GTK_WIDGET(data->treeview)));
	if (GTK_IS_WINDOW(parent))
		gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(parent));

	// Set initial values
	if (initial_type) {
		SanType type = san_type_from_string(initial_type);
		gtk_combo_box_set_active(type_combo, type);
	} else {
		gtk_combo_box_set_active(type_combo, 0);
	}

	if (initial_value)
		gtk_editable_set_text(GTK_EDITABLE(value_entry), initial_value);
	else
		gtk_editable_set_text(GTK_EDITABLE(value_entry), "");

	gtk_widget_grab_focus(GTK_WIDGET(value_entry));

	/* Build async context and connect response. */
	SanEditorCtx *ctx = g_new0 (SanEditorCtx, 1);
	ctx->data = data;
	ctx->editing = editing;
	if (editing && edit_iter)
		ctx->edit_iter = *edit_iter;

	ctx->response_handler_id = g_signal_connect (
		dialog, "response", G_CALLBACK (san_editor_response), ctx);

	gtk_window_present (GTK_WINDOW (dialog));
}

static void san_manager_add_clicked(GtkButton *button, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	san_manager_show_editor_async (data, NULL, NULL, FALSE, NULL);
}

static void san_manager_edit_clicked(GtkButton *button, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(data->treeview);
	GtkTreeIter iter;
	GtkTreeModel *model;

	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gchar *old_type, *old_value;

		gtk_tree_model_get(model, &iter, 0, &old_type, 1, &old_value, -1);

		san_manager_show_editor_async (data, old_type, old_value, TRUE, &iter);

		g_free(old_type);
		g_free(old_value);
	}
}

static void san_manager_remove_clicked(GtkButton *button, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	GtkTreeSelection *selection = gtk_tree_view_get_selection(data->treeview);
	GtkTreeIter iter;
	GtkTreeModel *model;
	
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gtk_list_store_remove(data->model, &iter);
	}
}

GtkWidget * san_manager_create(GtkBuilder *builder, const gchar *widget_id) {
	GtkWidget *vbox;
	GtkTreeView *treeview;
	GtkListStore *model;
	GtkButton *add_button, *edit_button, *remove_button;
	GtkTreeSelection *selection;
	SanManagerData *data;
	
	vbox = GTK_WIDGET(gtk_builder_get_object(builder, widget_id));
	if (!vbox)
		return NULL;
	
	treeview = GTK_TREE_VIEW(gtk_builder_get_object(builder, "san_treeview"));
	model = GTK_LIST_STORE(gtk_builder_get_object(builder, "san_list_model"));
	add_button = GTK_BUTTON(gtk_builder_get_object(builder, "add_button"));
	edit_button = GTK_BUTTON(gtk_builder_get_object(builder, "edit_button"));
	remove_button = GTK_BUTTON(gtk_builder_get_object(builder, "remove_button"));
	
	// Create data structure
	data = g_new0(SanManagerData, 1);
	data->treeview = treeview;
	data->model = model;
	data->add_button = add_button;
	data->edit_button = edit_button;
	data->remove_button = remove_button;
	data->editor_builder = NULL;
	
	// Store data in widget
	g_object_set_data_full(G_OBJECT(vbox), "san_manager_data", data, g_free);
	
	// Connect signals
	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
	g_signal_connect(selection, "changed", G_CALLBACK(san_manager_selection_changed), data);
	g_signal_connect(add_button, "clicked", G_CALLBACK(san_manager_add_clicked), data);
	g_signal_connect(edit_button, "clicked", G_CALLBACK(san_manager_edit_clicked), data);
	g_signal_connect(remove_button, "clicked", G_CALLBACK(san_manager_remove_clicked), data);
	
	return vbox;
}

gchar * san_manager_get_string(GtkWidget *san_manager) {
	SanManagerData *data = (SanManagerData *)g_object_get_data(G_OBJECT(san_manager), "san_manager_data");
	if (!data)
		return g_strdup("");
	
	GString *result = g_string_new(NULL);
	GtkTreeIter iter;
	gboolean valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(data->model), &iter);
	gboolean first = TRUE;
	
	while (valid) {
		gchar *type, *value;
		gtk_tree_model_get(GTK_TREE_MODEL(data->model), &iter,
		                   0, &type,
		                   1, &value,
		                   -1);
		
		if (!first)
			g_string_append(result, ",");
		first = FALSE;
		
		g_string_append_printf(result, "%s:%s", type, value);
		
		g_free(type);
		g_free(value);
		
		valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(data->model), &iter);
	}
	
	return g_string_free(result, FALSE);
}

void san_manager_set_string(GtkWidget *san_manager, const gchar *san_string) {
	SanManagerData *data = (SanManagerData *)g_object_get_data(G_OBJECT(san_manager), "san_manager_data");
	if (!data || !san_string || !san_string[0])
		return;
	
	// Clear existing
	gtk_list_store_clear(data->model);
	
	// Parse and add entries
	gchar **entries = g_strsplit(san_string, ",", -1);
	for (int i = 0; entries[i] != NULL; i++) {
		gchar *entry = g_strstrip(entries[i]);
		if (entry[0]) {
			gchar **parts = g_strsplit(entry, ":", 2);
			if (parts[0] && parts[1]) {
				GtkTreeIter iter;
				gtk_list_store_append(data->model, &iter);
				gtk_list_store_set(data->model, &iter,
				                   0, g_strstrip(parts[0]),
				                   1, g_strstrip(parts[1]),
				                   -1);
			}
			g_strfreev(parts);
		}
	}
	g_strfreev(entries);
}

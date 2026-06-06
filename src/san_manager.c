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
#include "dialog.h"

#include "san_manager.h"
#include "san_entry.h"

// Private data structure for SAN manager
typedef struct {
	GtkColumnView      *columnview;
	GListStore         *model;
	GtkSingleSelection *selection;
	GtkButton          *add_button;
	GtkButton          *edit_button;
	GtkButton          *remove_button;
	GtkBuilder         *editor_builder;
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

/* ------------------------------------------------------------------ */
/*  GtkColumnView factory callbacks                                    */
/* ------------------------------------------------------------------ */

static void
san_type_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                GtkListItem *list_item,
                gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_list_item_set_child (list_item, label);
}

static void
san_type_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
               GtkListItem *list_item,
               gpointer user_data G_GNUC_UNUSED)
{
	GnomintSanEntry *entry = GNOMINT_SAN_ENTRY (gtk_list_item_get_item (list_item));
	GtkWidget *label = gtk_list_item_get_child (list_item);
	gtk_label_set_text (GTK_LABEL (label),
	                    gnomint_san_entry_get_san_type (entry));
}

static void
san_value_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                 GtkListItem *list_item,
                 gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_list_item_set_child (list_item, label);
}

static void
san_value_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                GtkListItem *list_item,
                gpointer user_data G_GNUC_UNUSED)
{
	GnomintSanEntry *entry = GNOMINT_SAN_ENTRY (gtk_list_item_get_item (list_item));
	GtkWidget *label = gtk_list_item_get_child (list_item);
	gtk_label_set_text (GTK_LABEL (label),
	                    gnomint_san_entry_get_value (entry));
}

/* ------------------------------------------------------------------ */
/*  Selection changed                                                  */
/* ------------------------------------------------------------------ */

static void san_manager_selection_changed(GtkSingleSelection *sel,
                                          GParamSpec *pspec G_GNUC_UNUSED,
                                          gpointer user_data)
{
	SanManagerData *data = (SanManagerData *)user_data;
	gboolean has_selection = (gtk_single_selection_get_selected (sel) != GTK_INVALID_LIST_POSITION);

	gtk_widget_set_sensitive(GTK_WIDGET(data->edit_button), has_selection);
	gtk_widget_set_sensitive(GTK_WIDGET(data->remove_button), has_selection);
}

/* Context for the async SAN editor dialog. */
typedef struct {
	SanManagerData *data;
	gboolean        editing;       /* TRUE = edit existing row, FALSE = add new */
	guint           edit_position; /* valid only when editing == TRUE */
	gulong          response_handler_id;
} SanEditorCtx;

/* Forward declaration. */
static void san_editor_response (GtkDialog *dialog, gint response_id, gpointer user_data);

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

	/* OK pressed -- validate input. */
	GtkDropDown *type_dropdown = GTK_DROP_DOWN (
		gtk_builder_get_object (data->editor_builder, "san_type_combo"));
	GtkEntry *value_entry = GTK_ENTRY (
		gtk_builder_get_object (data->editor_builder, "san_value_entry"));

	guint selected = gtk_drop_down_get_selected (type_dropdown);
	SanType type = (SanType) selected;

	const gchar *value = gtk_editable_get_text (GTK_EDITABLE (value_entry));
	gchar *error_msg = NULL;

	if (!san_validate (type, value, &error_msg)) {
		/* Show fire-and-forget error dialog, then re-present editor. */
		GtkAlertDialog *err_alert = gtk_alert_dialog_new ("%s", error_msg);
		gtk_alert_dialog_show (err_alert, GTK_WINDOW (dialog));
		g_object_unref (err_alert);
		g_free (error_msg);
		/* Re-present the same editor dialog so the user can correct. */
		gtk_window_present (GTK_WINDOW (dialog));
		return;
	}

	/* Valid -- update the model. */
	const gchar *type_str = san_type_to_string (type);

	if (ctx->editing) {
		GnomintSanEntry *entry = g_list_model_get_item (
			G_LIST_MODEL (data->model), ctx->edit_position);
		if (entry) {
			gnomint_san_entry_set_san_type (entry, type_str);
			gnomint_san_entry_set_value (entry, value);
			/* Notify the model of the change so the view refreshes. */
			g_list_store_splice (data->model, ctx->edit_position, 1, (gpointer *) &entry, 1);
			g_object_unref (entry);
		}
	} else {
		GnomintSanEntry *entry = gnomint_san_entry_new (type_str, value);
		g_list_store_append (data->model, entry);
		g_object_unref (entry);
	}

	g_signal_handler_disconnect (dialog, ctx->response_handler_id);
	gtk_window_destroy (GTK_WINDOW (dialog));
	g_free (ctx);
}

/* Present the SAN editor dialog asynchronously.  When the user confirms,
 * the response callback validates and updates the model. */
static void san_manager_show_editor_async(SanManagerData *data, const gchar *initial_type, const gchar *initial_value, gboolean editing, guint edit_position) {
	GtkDialog *dialog;
	GtkDropDown *type_dropdown;
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
	type_dropdown = GTK_DROP_DOWN(gtk_builder_get_object(data->editor_builder, "san_type_combo"));
	value_entry = GTK_ENTRY(gtk_builder_get_object(data->editor_builder, "san_value_entry"));

	// Set parent window
	parent = GTK_WIDGET(gtk_widget_get_root(GTK_WIDGET(data->columnview)));
	if (GTK_IS_WINDOW(parent))
		gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(parent));

	// Set initial values
	if (initial_type) {
		SanType type = san_type_from_string(initial_type);
		gtk_drop_down_set_selected(type_dropdown, (guint) type);
	} else {
		gtk_drop_down_set_selected(type_dropdown, 0);
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
	ctx->edit_position = edit_position;

	ctx->response_handler_id = g_signal_connect (
		dialog, "response", G_CALLBACK (san_editor_response), ctx);

	gtk_window_present (GTK_WINDOW (dialog));
}

static void san_manager_add_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	san_manager_show_editor_async (data, NULL, NULL, FALSE, 0);
}

static void san_manager_edit_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	guint pos = gtk_single_selection_get_selected (data->selection);

	if (pos != GTK_INVALID_LIST_POSITION) {
		GnomintSanEntry *entry = g_list_model_get_item (
			G_LIST_MODEL (data->model), pos);
		if (entry) {
			san_manager_show_editor_async (data,
				gnomint_san_entry_get_san_type (entry),
				gnomint_san_entry_get_value (entry),
				TRUE, pos);
			g_object_unref (entry);
		}
	}
}

static void san_manager_remove_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data) {
	SanManagerData *data = (SanManagerData *)user_data;
	guint pos = gtk_single_selection_get_selected (data->selection);

	if (pos != GTK_INVALID_LIST_POSITION) {
		g_list_store_remove (data->model, pos);
	}
}

GtkWidget * san_manager_create(GtkBuilder *builder, const gchar *widget_id) {
	GtkWidget *vbox;
	GtkColumnView *columnview;
	GtkButton *add_button, *edit_button, *remove_button;
	SanManagerData *data;

	vbox = GTK_WIDGET(gtk_builder_get_object(builder, widget_id));
	if (!vbox)
		return NULL;

	columnview = GTK_COLUMN_VIEW(gtk_builder_get_object(builder, "san_treeview"));
	add_button = GTK_BUTTON(gtk_builder_get_object(builder, "add_button"));
	edit_button = GTK_BUTTON(gtk_builder_get_object(builder, "edit_button"));
	remove_button = GTK_BUTTON(gtk_builder_get_object(builder, "remove_button"));

	/* Create GListStore of GnomintSanEntry objects. */
	GListStore *model = g_list_store_new (GNOMINT_TYPE_SAN_ENTRY);

	/* Wrap in a GtkSingleSelection for the column view. */
	GtkSingleSelection *sel = gtk_single_selection_new (G_LIST_MODEL (model));
	gtk_single_selection_set_autoselect (sel, FALSE);
	gtk_single_selection_set_can_unselect (sel, TRUE);
	gtk_column_view_set_model (columnview, GTK_SELECTION_MODEL (sel));

	// Create data structure
	data = g_new0(SanManagerData, 1);
	data->columnview = columnview;
	data->model = model;
	data->selection = sel;
	data->add_button = add_button;
	data->edit_button = edit_button;
	data->remove_button = remove_button;
	data->editor_builder = NULL;

	// Store data in widget
	g_object_set_data_full(G_OBJECT(vbox), "san_manager_data", data, g_free);

	/* Set up columns programmatically. */

	/* Type column */
	{
		GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
		g_signal_connect (f, "setup", G_CALLBACK (san_type_setup), NULL);
		g_signal_connect (f, "bind",  G_CALLBACK (san_type_bind),  NULL);
		GtkColumnViewColumn *col = gtk_column_view_column_new (_("Type"), f);
		gtk_column_view_append_column (columnview, col);
		g_object_unref (col);
	}

	/* Value column */
	{
		GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
		g_signal_connect (f, "setup", G_CALLBACK (san_value_setup), NULL);
		g_signal_connect (f, "bind",  G_CALLBACK (san_value_bind),  NULL);
		GtkColumnViewColumn *col = gtk_column_view_column_new (_("Value"), f);
		gtk_column_view_column_set_expand (col, TRUE);
		gtk_column_view_append_column (columnview, col);
		g_object_unref (col);
	}

	// Connect signals
	g_signal_connect(sel, "notify::selected", G_CALLBACK(san_manager_selection_changed), data);
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
	guint n = g_list_model_get_n_items (G_LIST_MODEL (data->model));

	for (guint i = 0; i < n; i++) {
		GnomintSanEntry *entry = g_list_model_get_item (G_LIST_MODEL (data->model), i);
		if (!entry)
			continue;

		if (i > 0)
			g_string_append(result, ",");

		g_string_append_printf(result, "%s:%s",
		                       gnomint_san_entry_get_san_type (entry),
		                       gnomint_san_entry_get_value (entry));
		g_object_unref (entry);
	}

	return g_string_free(result, FALSE);
}

void san_manager_set_string(GtkWidget *san_manager, const gchar *san_string) {
	SanManagerData *data = (SanManagerData *)g_object_get_data(G_OBJECT(san_manager), "san_manager_data");
	if (!data || !san_string || !san_string[0])
		return;

	// Clear existing
	g_list_store_remove_all (data->model);

	// Parse and add entries
	gchar **entries = g_strsplit(san_string, ",", -1);
	for (int i = 0; entries[i] != NULL; i++) {
		gchar *entry_str = g_strstrip(entries[i]);
		if (entry_str[0]) {
			gchar **parts = g_strsplit(entry_str, ":", 2);
			if (parts[0] && parts[1]) {
				GnomintSanEntry *entry = gnomint_san_entry_new (
					g_strstrip(parts[0]),
					g_strstrip(parts[1]));
				g_list_store_append (data->model, entry);
				g_object_unref (entry);
			}
			g_strfreev(parts);
		}
	}
	g_strfreev(entries);
}

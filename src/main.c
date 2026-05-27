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
#include <gio/gio.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <stdlib.h>

#include "main.h"
#include "ca.h"
#include "dialog.h"
#include "tls.h"
#include "ca_file.h"
#include "preferences-gui.h"
#include "gtk4-compat.h"

#define GNOMINT_MIME_TYPE "application/x-gnomint"

GtkBuilder * main_window_gtkb = NULL;
GtkBuilder * csr_popup_menu_gtkb = NULL;
GtkBuilder * cert_popup_menu_gtkb = NULL;

gchar * gnomint_current_opened_file = NULL;

static GtkRecentManager *recent_manager;

void __recent_add_utf8_filename (const gchar *utf8_filename);
void __disable_widget (gchar *widget_name);
void __enable_widget (gchar *widget_name);
void __recent_add_utf8_filename (const gchar *utf8_filename);

/* Extern declarations for handlers defined in other files */
extern void on_add_self_signed_ca_activate (gpointer sender, gpointer user_data);
extern void on_add_csr_activate (gpointer sender, gpointer user_data);
extern void on_wizard_web_activate (gpointer sender, gpointer user_data);
extern void on_wizard_email_activate (gpointer sender, gpointer user_data);
extern void on_import1_activate (gpointer sender, gpointer user_data);
extern void on_properties1_activate (gpointer sender, gpointer user_data);
extern void on_preferences1_activate (gpointer sender, gpointer user_data);
extern void ca_expiry_infobar_response (GtkInfoBar *bar, gint response, gpointer user_data);
extern void ca_on_search_changed (GtkSearchEntry *entry, gpointer user_data);
extern void ca_treeview_popup_handler (GtkGestureClick *gesture, int n_press, double x, double y, gpointer user_data);
extern gboolean ca_on_key_pressed (GtkEventControllerKey *controller, guint keyval, guint keycode, GdkModifierType state, gpointer user_data);


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


/* ------------------------------------------------------------------ */
/*  GAction wrappers for window actions                                */
/* ------------------------------------------------------------------ */

static void action_new_db      (GSimpleAction *a, GVariant *p, gpointer d) { on_new1_activate(NULL, NULL); }
static void action_open_db     (GSimpleAction *a, GVariant *p, gpointer d) { on_open1_activate(NULL, NULL); }
static void action_open_recents(GSimpleAction *a, GVariant *p, gpointer d) { /* no-op for now */ }
static void action_save_as     (GSimpleAction *a, GVariant *p, gpointer d) { on_save_as1_activate(NULL, NULL); }
static void action_add_ca      (GSimpleAction *a, GVariant *p, gpointer d) { on_add_self_signed_ca_activate(NULL, NULL); }
static void action_add_csr     (GSimpleAction *a, GVariant *p, gpointer d) { on_add_csr_activate(NULL, NULL); }
static void action_wizard_web  (GSimpleAction *a, GVariant *p, gpointer d) { on_wizard_web_activate(NULL, NULL); }
static void action_wizard_email(GSimpleAction *a, GVariant *p, gpointer d) { on_wizard_email_activate(NULL, NULL); }
static void action_extract_pkey(GSimpleAction *a, GVariant *p, gpointer d) { ca_on_extractprivatekey1_activate(NULL, NULL); }
static void action_renew       (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_renew_activate(NULL, NULL); }
static void action_revoke      (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_revoke_activate(NULL, NULL); }
static void action_sign        (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_sign1_activate(NULL, NULL); }
static void action_delete      (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_delete2_activate(NULL, NULL); }
static void action_generate_crl(GSimpleAction *a, GVariant *p, gpointer d) { ca_generate_crl(NULL, NULL); }
static void action_generate_dh (GSimpleAction *a, GVariant *p, gpointer d) { ca_generate_dh_param_show(NULL, NULL); }
static void action_change_pwd  (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_change_pwd_menuitem_activate(NULL, NULL); }
static void action_import      (GSimpleAction *a, GVariant *p, gpointer d) { on_import1_activate(NULL, NULL); }
static void action_export      (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_export1_activate(NULL, NULL); }
static void action_export_chain(GSimpleAction *a, GVariant *p, gpointer d) { ca_on_export_chain_activate(NULL, NULL); }
static void action_bulk_revoke (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_bulk_revoke_activate(NULL, NULL); }
static void action_bulk_delete_csrs(GSimpleAction *a, GVariant *p, gpointer d) { ca_on_bulk_delete_csrs_activate(NULL, NULL); }
static void action_properties  (GSimpleAction *a, GVariant *p, gpointer d) { on_properties1_activate(NULL, NULL); }
static void action_preferences (GSimpleAction *a, GVariant *p, gpointer d) { on_preferences1_activate(NULL, NULL); }
static void action_compare_pem (GSimpleAction *a, GVariant *p, gpointer d) { ca_on_compare_with_activate(NULL, NULL); }

static void action_toggle_view_csrs(GSimpleAction *action, GVariant *param, gpointer data)
{
    GVariant *state = g_action_get_state(G_ACTION(action));
    gboolean val = !g_variant_get_boolean(state);
    g_simple_action_set_state(action, g_variant_new_boolean(val));
    ca_update_csr_view(val, TRUE);
    g_variant_unref(state);
}

static void action_toggle_view_revoked(GSimpleAction *action, GVariant *param, gpointer data)
{
    GVariant *state = g_action_get_state(G_ACTION(action));
    gboolean val = !g_variant_get_boolean(state);
    g_simple_action_set_state(action, g_variant_new_boolean(val));
    ca_update_revoked_view(val, TRUE);
    g_variant_unref(state);
}

static void action_toggle_view_expired(GSimpleAction *action, GVariant *param, gpointer data)
{
    GVariant *state = g_action_get_state(G_ACTION(action));
    gboolean val = !g_variant_get_boolean(state);
    g_simple_action_set_state(action, g_variant_new_boolean(val));
    ca_update_expired_view(val, TRUE);
    g_variant_unref(state);
}

/* ------------------------------------------------------------------ */
/*  GAction wrappers for app actions                                   */
/* ------------------------------------------------------------------ */

static void action_quit (GSimpleAction *a, GVariant *p, gpointer d)
{
    on_quit1_activate(NULL, NULL);
}

static void action_about (GSimpleAction *a, GVariant *p, gpointer d)
{
    on_about1_activate(NULL, NULL);
}


/* ------------------------------------------------------------------ */
/*  gnomint_register_actions                                           */
/* ------------------------------------------------------------------ */

void gnomint_register_actions(GtkWindow *window, GtkApplication *app)
{
    /* Regular window actions */
    const GActionEntry win_entries[] = {
        { "new-db",            action_new_db,       NULL, NULL, NULL },
        { "open-db",           action_open_db,      NULL, NULL, NULL },
        { "open-recents",      action_open_recents, NULL, NULL, NULL },
        { "save-as",           action_save_as,      NULL, NULL, NULL },
        { "add-ca",            action_add_ca,       NULL, NULL, NULL },
        { "add-csr",           action_add_csr,      NULL, NULL, NULL },
        { "wizard-web",        action_wizard_web,   NULL, NULL, NULL },
        { "wizard-email",      action_wizard_email, NULL, NULL, NULL },
        { "extract-pkey",      action_extract_pkey, NULL, NULL, NULL },
        { "renew",             action_renew,        NULL, NULL, NULL },
        { "revoke",            action_revoke,       NULL, NULL, NULL },
        { "sign",              action_sign,         NULL, NULL, NULL },
        { "delete",            action_delete,       NULL, NULL, NULL },
        { "generate-crl",      action_generate_crl, NULL, NULL, NULL },
        { "generate-dh",       action_generate_dh,  NULL, NULL, NULL },
        { "change-password",   action_change_pwd,   NULL, NULL, NULL },
        { "import",            action_import,       NULL, NULL, NULL },
        { "export",            action_export,       NULL, NULL, NULL },
        { "export-chain",      action_export_chain, NULL, NULL, NULL },
        { "bulk-revoke",       action_bulk_revoke,  NULL, NULL, NULL },
        { "bulk-delete-csrs",  action_bulk_delete_csrs, NULL, NULL, NULL },
        { "properties",        action_properties,   NULL, NULL, NULL },
        { "preferences",       action_preferences,  NULL, NULL, NULL },
        { "compare-pem",       action_compare_pem,  NULL, NULL, NULL },
    };

    g_action_map_add_action_entries(G_ACTION_MAP(window),
                                    win_entries, G_N_ELEMENTS(win_entries),
                                    window);

    /* Stateful toggle actions for window */
    GSimpleAction *act;

    act = g_simple_action_new_stateful("view-csrs",
                                       NULL,
                                       g_variant_new_boolean(TRUE));
    g_signal_connect(act, "activate", G_CALLBACK(action_toggle_view_csrs), NULL);
    g_action_map_add_action(G_ACTION_MAP(window), G_ACTION(act));
    g_object_unref(act);

    act = g_simple_action_new_stateful("view-revoked",
                                       NULL,
                                       g_variant_new_boolean(TRUE));
    g_signal_connect(act, "activate", G_CALLBACK(action_toggle_view_revoked), NULL);
    g_action_map_add_action(G_ACTION_MAP(window), G_ACTION(act));
    g_object_unref(act);

    act = g_simple_action_new_stateful("view-expired",
                                       NULL,
                                       g_variant_new_boolean(TRUE));
    g_signal_connect(act, "activate", G_CALLBACK(action_toggle_view_expired), NULL);
    g_action_map_add_action(G_ACTION_MAP(window), G_ACTION(act));
    g_object_unref(act);

    /* Disable open-recents for now (GtkRecentChooserMenu is gone) */
    GAction *recents_action = g_action_map_lookup_action(G_ACTION_MAP(window), "open-recents");
    if (recents_action)
        g_simple_action_set_enabled(G_SIMPLE_ACTION(recents_action), FALSE);

    /* App actions */
    const GActionEntry app_entries[] = {
        { "quit",  action_quit,  NULL, NULL, NULL },
        { "about", action_about, NULL, NULL, NULL },
    };

    g_action_map_add_action_entries(G_ACTION_MAP(app),
                                    app_entries, G_N_ELEMENTS(app_entries),
                                    NULL);
}


/* ------------------------------------------------------------------ */
/*  gnomint_activate — called by GtkApplication                        */
/* ------------------------------------------------------------------ */

static void gnomint_activate(GtkApplication *app, gpointer user_data);

static void gnomint_activate(GtkApplication *app, gpointer user_data)
{
        gchar *defaultfile = NULL;
        gchar     * size_str = NULL;

	preferences_gui_set_csr_visible_callback (ca_update_csr_view);
	preferences_gui_set_revoked_visible_callback (ca_update_revoked_view);
	preferences_gui_set_expired_visible_callback (ca_update_expired_view);

        preferences_init (0, NULL);

	main_window_gtkb = gtk_builder_new();
	gtk_builder_set_translation_domain (main_window_gtkb, GETTEXT_PACKAGE);
	gtk_builder_add_from_file (main_window_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "main_window.ui", NULL),
				   NULL);

	csr_popup_menu_gtkb = gtk_builder_new();
	gtk_builder_set_translation_domain (csr_popup_menu_gtkb, GETTEXT_PACKAGE);
	gtk_builder_add_from_file (csr_popup_menu_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "csr_popup_menu.ui", NULL),
				   NULL);

	cert_popup_menu_gtkb = gtk_builder_new();
	gtk_builder_set_translation_domain (cert_popup_menu_gtkb, GETTEXT_PACKAGE);
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
                                gtk_window_set_default_size (GTK_WINDOW(gtk_builder_get_object(main_window_gtkb, "main_window1")), width, height);
                        }

                }

                g_free (size_str);
                g_strfreev (result);
        }
        ca_update_revoked_view (preferences_get_revoked_visible(), FALSE);
        ca_update_csr_view (preferences_get_crq_visible(), FALSE);
        ca_update_expired_view (preferences_get_expired_visible(), FALSE);


	/* Fix toolbar icon paths: GtkImage file= in .ui uses bare
	 * filenames; in GTK 4 these must be absolute paths. */
	static const char *icon_widgets[] = {
		"addcaimg", "addcsrimg", "extractpkeyimg", "signimg",
		"wizardwebimg", "wizardemailimg", NULL
	};
	static const char *icon_files[] = {
		"addca.png", "addcsr.png", "extractpkey.png", "sign.png",
		"wizard-webserver.png", "wizard-email.png", NULL
	};
	for (int i = 0; icon_widgets[i]; i++) {
		GtkImage *img = GTK_IMAGE(gtk_builder_get_object(main_window_gtkb, icon_widgets[i]));
		if (img) {
			gchar *path = g_build_filename(PACKAGE_DATA_DIR, "gnomint", icon_files[i], NULL);
			gtk_image_set_from_file(img, path);
			g_free(path);
		}
	}

	/* GTK 4: signal auto-connection is no longer available via
	 * gtk_builder_connect_signals(). Toolbar button handlers are
	 * connected explicitly below; menu items use GActions instead. */
	GtkWidget *w;
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "toolbutton1"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_new1_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "toolbutton2"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_open1_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "addca_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_add_self_signed_ca_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "addcsr_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_add_csr_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "extractpkey_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(ca_on_extractprivatekey1_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "revoke_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(ca_on_revoke_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "sign_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(ca_on_sign1_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "delete_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(ca_on_delete2_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "wizard_web_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_wizard_web_activate), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "wizard_email_toolbutton"));
	if (w) g_signal_connect(w, "clicked", G_CALLBACK(on_wizard_email_activate), NULL);

	/* InfoBar, search, tree view signals */
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "expiry_infobar"));
	if (w) g_signal_connect(w, "response", G_CALLBACK(ca_expiry_infobar_response), NULL);
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "search_entry"));
	if (w) g_signal_connect(w, "search-changed", G_CALLBACK(ca_on_search_changed), NULL);
	/* Selection-changed and activate signals are connected by
	 * ca_refresh_model_callback when the GtkColumnView columns are
	 * set up for the first time. Only the right-click popup
	 * handler is wired here. */
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "ca_treeview"));
	if (w) {
		/* Right-click context menu via GtkGestureClick (GTK 4) */
		GtkGesture *click = gtk_gesture_click_new();
		gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(click), 3);
		g_signal_connect(click, "pressed", G_CALLBACK(ca_treeview_popup_handler), w);
		gtk_widget_add_controller(w, GTK_EVENT_CONTROLLER(click));
	}

	/* close-request on main window */
	w = GTK_WIDGET(gtk_builder_get_object(main_window_gtkb, "main_window1"));
	if (w) {
		g_signal_connect(w, "close-request", G_CALLBACK(on_main_window1_delete), NULL);
		/* Ctrl+F key handler via GtkEventControllerKey (GTK 4) */
		GtkEventController *key_ctrl = gtk_event_controller_key_new();
		g_signal_connect(key_ctrl, "key-pressed", G_CALLBACK(ca_on_key_pressed), NULL);
		gtk_widget_add_controller(w, key_ctrl);
	}

	recent_manager = gtk_recent_manager_get_default ();

	/* Recent menu setup skipped — GtkRecentChooserMenu is gone in GTK 4 */

	dialog_establish_refresh_function (ca_refresh_model_callback);

	/* Associate the window with the GtkApplication */
	GtkWindow *main_win = GTK_WINDOW(gtk_builder_get_object(main_window_gtkb, "main_window1"));
	gtk_window_set_application(main_win, app);

	/* Register GActions */
	gnomint_register_actions(main_win, app);

	{
                const gchar *data_dir = g_get_user_data_dir();
                gchar *gnomint_data_dir = g_build_filename (data_dir, "gnomint", NULL);

                /* Ensure the directory exists */
                g_mkdir_with_parents (gnomint_data_dir, 0700);

                defaultfile = g_build_filename (gnomint_data_dir, "default.gnomint", NULL);
                g_free (gnomint_data_dir);

                /* Check if we need to migrate from old location */
                if (!g_file_test(defaultfile, G_FILE_TEST_EXISTS)) {
                        gchar *old_defaultfile = g_build_filename (g_get_home_dir(), ".gnomint", "default.gnomint", NULL);
                        if (g_file_test(old_defaultfile, G_FILE_TEST_EXISTS)) {
                                /* Copy the old file to the new location */
                                GFile *old_file = g_file_new_for_path(old_defaultfile);
                                GFile *new_file = g_file_new_for_path(defaultfile);
                                GError *error = NULL;

                                if (!g_file_copy(old_file, new_file, G_FILE_COPY_NONE, NULL, NULL, NULL, &error)) {
                                        g_warning("Failed to migrate database from %s to %s: %s",
                                                  old_defaultfile, defaultfile, error ? error->message : "unknown error");
                                        if (error) {
                                                g_error_free(error);
                                        }
                                }

                                g_object_unref(old_file);
                                g_object_unref(new_file);
                        }
                        g_free (old_defaultfile);
                }

		__recent_add_utf8_filename (defaultfile);
                ca_open (defaultfile, TRUE);
        }

	gtk_window_present (main_win);
}


#ifndef GNOMINT_UI_TEST
int main (int   argc,
	  char *argv[])
{
    GtkApplication *app;
    int status;

#ifdef ENABLE_NLS
    bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
    bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
    textdomain (GETTEXT_PACKAGE);
#endif

    g_set_application_name (PACKAGE);
    g_set_prgname (PACKAGE);
    gtk_window_set_default_icon_name ("gnomint");

    tls_init ();

    app = gtk_application_new ("org.gnome.gnomint", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect (app, "activate", G_CALLBACK (gnomint_activate), NULL);
    status = g_application_run (G_APPLICATION (app), argc, argv);
    g_object_unref (app);
    return status;
}
#endif /* GNOMINT_UI_TEST */



G_MODULE_EXPORT gboolean on_main_window1_delete (GtkWindow *window)
{
        int width, height;
        gchar *new_size_value;

        gtk_window_get_default_size (window, &width, &height);
        new_size_value = g_strdup_printf ("(%d,%d)", width, height);
        preferences_set_size (new_size_value);
        g_free (new_size_value);
        preferences_deinit();
        return FALSE; /* allow close */
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


        recent_data = g_new (GtkRecentData, 1);

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
        g_free (recent_data);

}

G_MODULE_EXPORT void on_new1_activate (gpointer sender, gpointer     user_data)
{
	gchar *filename;
        gchar *error = NULL;

	GtkWidget *dialog, *widget;

	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window1"));

	dialog = gtk_file_chooser_dialog_new (_("Create new CA database"),
					      GTK_WINDOW(widget),
					      GTK_FILE_CHOOSER_ACTION_SAVE,
					      _("_Cancel"), GTK_RESPONSE_CANCEL,
					      _("_Open"), GTK_RESPONSE_ACCEPT,
					      NULL);


	if (compat_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
	{
		GFile *file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (dialog));
		filename = g_file_get_path (file);
		g_object_unref (file);
		gtk_window_destroy (GTK_WINDOW (dialog));
	} else {
		gtk_window_destroy (GTK_WINDOW (dialog));
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

		compat_dialog_run (GTK_DIALOG(dialog));

                return;
        }

	if (! ca_open (filename, FALSE)) {
		dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when opening new '%s' CA database"),
						 filename);

		compat_dialog_run (GTK_DIALOG(dialog));

		gtk_window_destroy (GTK_WINDOW (dialog));
	} else {
		__recent_add_utf8_filename (filename);
        }
	return;

}

G_MODULE_EXPORT void on_open1_activate  (gpointer sender, gpointer     user_data)
{
	gchar *filename;

	GtkWidget *dialog, *widget;

	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window1"));

	dialog = gtk_file_chooser_dialog_new (_("Open CA database"),
					      GTK_WINDOW(widget),
					      GTK_FILE_CHOOSER_ACTION_OPEN,
					      _("_Cancel"), GTK_RESPONSE_CANCEL,
					      _("_Open"), GTK_RESPONSE_ACCEPT,
					      NULL);

	if (compat_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
	{
		GFile *file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (dialog));
		filename = g_file_get_path (file);
		g_object_unref (file);
		gtk_window_destroy (GTK_WINDOW (dialog));
	} else {
		gtk_window_destroy (GTK_WINDOW (dialog));
		return;
	}



	if (! ca_open (filename, FALSE)) {
		dialog = gtk_message_dialog_new (GTK_WINDOW(widget),
						 GTK_DIALOG_DESTROY_WITH_PARENT,
						 GTK_MESSAGE_ERROR,
						 GTK_BUTTONS_CLOSE,
						 _("Problem when opening '%s' CA database"),
						 filename);

		compat_dialog_run (GTK_DIALOG(dialog));

		gtk_window_destroy (GTK_WINDOW (dialog));
	} else {
		__recent_add_utf8_filename (filename);
	}
	return;
}


G_MODULE_EXPORT void on_save_as1_activate  (gpointer sender, gpointer     user_data)
{
	gchar *filename;

	GtkWidget *dialog, *widget;

	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window1"));

	dialog = gtk_file_chooser_dialog_new (_("Save CA database as..."),
					      GTK_WINDOW(widget),
					      GTK_FILE_CHOOSER_ACTION_SAVE,
					      _("_Cancel"), GTK_RESPONSE_CANCEL,
					      _("_Open"), GTK_RESPONSE_ACCEPT,
					      NULL);

	if (compat_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		GFile *file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (dialog));
		filename = g_file_get_path (file);
		g_object_unref (file);
		gtk_window_destroy (GTK_WINDOW (dialog));
	} else {
		gtk_window_destroy (GTK_WINDOW (dialog));
		return;
	}

	if (ca_file_save_as (filename))
                __recent_add_utf8_filename (filename);

}



G_MODULE_EXPORT void on_quit1_activate  (gpointer sender, gpointer     user_data)
{
	GtkWindow *window = GTK_WINDOW(gtk_builder_get_object(main_window_gtkb, "main_window1"));
	on_main_window1_delete(window);
	GApplication *app = G_APPLICATION(gtk_window_get_application(window));
	if (app)
		g_application_quit(app);
}





/*
 *
 *   HELP MENU CALLBACKS
 *
 */

G_MODULE_EXPORT void on_about1_activate  (gpointer sender, gpointer     user_data)
{
	GtkWidget *widget;

	widget = GTK_WIDGET(gtk_builder_get_object (main_window_gtkb, "main_window1"));

	const gchar *authors[] = {
		"David Marín Carreño <davefx@gmail.com>",
		NULL
	};
	const gchar *collaborators[] = {
		"Ahmed Baizid <ahmed@baizid.org>",
		"Jaroslav Imrich <jariq@jariq.sk>",
		"Staněk Luboš <lubek@users.sourceforge.net>",
		NULL
	};

	GtkAboutDialog *dlg = GTK_ABOUT_DIALOG (gtk_about_dialog_new ());
	gtk_window_set_transient_for (GTK_WINDOW (dlg), GTK_WINDOW (widget));
	gtk_window_set_modal (GTK_WINDOW (dlg), TRUE);

	gchar *logo_path = g_build_filename (PACKAGE_DATA_DIR, "gnomint",
	                                     "gnomint192x192.png", NULL);
	GdkTexture *logo = gdk_texture_new_from_filename (logo_path, NULL);
	if (logo) {
		gtk_about_dialog_set_logo (dlg, GDK_PAINTABLE (logo));
		g_object_unref (logo);
	}
	g_free (logo_path);

	gtk_about_dialog_set_program_name (dlg, "gnoMint");
	gtk_about_dialog_set_version (dlg, PACKAGE_VERSION);
	gtk_about_dialog_set_copyright (dlg, PACKAGE_COPYRIGHT);
	gtk_about_dialog_set_comments (dlg,
		_("gnoMint is a program for creating and managing "
		  "Certification Authorities, and their certificates"));
	gtk_about_dialog_set_license (dlg,
		_("This program is free software; you can redistribute it "
		  "and/or modify it under the terms of the GNU General Public "
		  "License as published by the Free Software Foundation; either "
		  "version 3 of the License, or (at your option) any later "
		  "version.\n\nThis program is distributed in the hope that it "
		  "will be useful, but WITHOUT ANY WARRANTY; without even the "
		  "implied warranty of MERCHANTABILITY or FITNESS FOR A "
		  "PARTICULAR PURPOSE.  See the GNU General Public License for "
		  "more details.\n\nYou should have received a copy of the GNU "
		  "General Public License along with this program; if not, "
		  "write to the Free Software Foundation, Inc., 51 Franklin "
		  "Street, Fifth Floor, Boston, MA  02110-1301, USA."));
	gtk_about_dialog_set_wrap_license (dlg, TRUE);
	gtk_about_dialog_set_website (dlg, PACKAGE_WEBSITE);
	gtk_about_dialog_set_authors (dlg, authors);
	gtk_about_dialog_add_credit_section (dlg,
		_("Code collaborators"), collaborators);
	gtk_about_dialog_set_translator_credits (dlg, _("translator-credits"));

	gtk_window_present (GTK_WINDOW (dlg));
}

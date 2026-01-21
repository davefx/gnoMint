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
#include <gio/gio.h>
#include <glib/gi18n.h>
#include <stdlib.h>

#include "tls.h"
#include "ca_file.h"
#include "ca-cli.h"
#include "preferences.h"

gchar * gnomint_current_opened_file = NULL;

int main (int argc, char **argv)
{
        gchar *defaultfile = NULL;
	GOptionContext *ctx;
	GError *err = NULL;
	GOptionEntry entries[] = {
		{ NULL }
	};
	

#ifdef ENABLE_NLS
        #include <locale.h>
        setlocale (LC_ALL, "");
	bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	g_set_application_name (PACKAGE);
	g_set_prgname (PACKAGE);

	tls_init ();

        preferences_init (argc, argv);

	ctx = g_option_context_new (_("- A Certification Authority manager"));
	g_option_context_add_main_entries (ctx, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
		g_print (_("Failed to initialize: %s\n"), err->message);
		g_error_free (err);
		return 1;
	}
	
        
	if (argc >= 2 && ca_open (g_strdup(argv[1]), TRUE)) {

        } else {
                /* No arguments, or failure when opening file */
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
                                g_file_copy(old_file, new_file, G_FILE_COPY_NONE, NULL, NULL, NULL, NULL);
                                g_object_unref(old_file);
                                g_object_unref(new_file);
                        }
                        g_free (old_defaultfile);
                }
                
                ca_open (defaultfile, TRUE);
        }

        ca_command_line ();

	return 0;
}

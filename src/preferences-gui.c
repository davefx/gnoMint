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

#include <string.h>
#include <gio/gio.h>


#include "preferences-gui.h"

#include <glib/gi18n.h>


static GSettings * preferences_settings;

PreferencesGuiChangeCallback csr_visible_callback = NULL;
PreferencesGuiChangeCallback revoked_visible_callback = NULL;

void preferences_gui_set_csr_visible_callback (PreferencesGuiChangeCallback callback)
{
	csr_visible_callback = callback;
}

void preferences_gui_set_revoked_visible_callback (PreferencesGuiChangeCallback callback)
{
	revoked_visible_callback = callback;
}


void preferences_changed_callback(GSettings* settings,
                                   const gchar *key,
                                   gpointer user_data)
{

        if (! strcmp (key, "crq-visible") && csr_visible_callback) {
                gboolean value = g_settings_get_boolean (settings, key);
                csr_visible_callback (value, TRUE);
        }

        if (! strcmp (key, "revoked-visible") && revoked_visible_callback) {
                gboolean value = g_settings_get_boolean (settings, key);
                revoked_visible_callback (value, TRUE);
        }

}



void preferences_init (int argc, char ** argv)
{
        preferences_settings = g_settings_new ("org.gnome.gnomint");

        g_signal_connect (preferences_settings, "changed::revoked-visible",
                          G_CALLBACK (preferences_changed_callback),
                          NULL);

        g_signal_connect (preferences_settings, "changed::crq-visible",
                          G_CALLBACK (preferences_changed_callback),
                          NULL);

}


gchar * preferences_get_size ()
{
        return g_settings_get_string (preferences_settings, "size");
}

void preferences_set_size (const gchar *new_value)
{
        g_settings_set_string (preferences_settings, "size", new_value);
}


gboolean preferences_get_revoked_visible ()
{
        return g_settings_get_boolean (preferences_settings, "revoked-visible");
}

void preferences_set_revoked_visible (gboolean new_value)
{
        g_settings_set_boolean (preferences_settings, "revoked-visible", new_value);
}

gboolean preferences_get_crq_visible ()
{
        return g_settings_get_boolean (preferences_settings, "crq-visible");
}

void preferences_set_crq_visible (gboolean new_value)
{
        g_settings_set_boolean (preferences_settings, "crq-visible", new_value);
}

gboolean preferences_get_gnome_keyring_export ()
{
        return g_settings_get_boolean (preferences_settings, "gnome-keyring-export");
}

void preferences_set_gnome_keyring_export (gboolean new_value)
{
        g_settings_set_boolean (preferences_settings, "gnome-keyring-export", new_value);
}


void preferences_deinit ()
{
        g_object_unref (preferences_settings);
        preferences_settings = NULL;
}


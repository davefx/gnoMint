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
#include <gio/gio.h>

#include <glib/gi18n.h>

#include "preferences.h"


static GSettings * preferences_settings;

void preferences_init (int argc, char **argv)
{
        preferences_settings = g_settings_new ("org.gnome.gnomint");
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


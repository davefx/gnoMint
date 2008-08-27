//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007,2008 David Marín Carreño <davefx@gmail.com>
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
#include <string.h>
#include <gconf/gconf-client.h>


#include "ca.h"

#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)



static GConfClient * preferences_client;



void preferences_changed_callback(GConfClient* client,
                                  guint cnxn_id,
                                  GConfEntry *entry,
                                  gpointer user_data)
{
        gboolean value = gconf_value_get_bool (gconf_entry_get_value(entry));
        if (! strcmp (gconf_entry_get_key(entry), "/apps/gnomint/crq_visible"))
                ca_update_csr_view (value, TRUE);

        if (! strcmp (gconf_entry_get_key(entry), "/apps/gnomint/revoked_visible"))
                ca_update_revoked_view (value, TRUE);

}



void preferences_init (int argc, char ** argv)
{
        gconf_init(argc, argv, NULL);
        
        preferences_client = gconf_client_get_default();

        gconf_client_add_dir(preferences_client,
                             "/apps/gnomint",
                             GCONF_CLIENT_PRELOAD_NONE,
                             NULL);

        gconf_client_notify_add (preferences_client, "/apps/gnomint/revoked_visible",
                                 preferences_changed_callback,
                                 NULL, NULL, NULL);

        gconf_client_notify_add (preferences_client, "/apps/gnomint/crq_visible",
                                 preferences_changed_callback,
                                 NULL, NULL, NULL);


}


gchar * preferences_get_size ()
{
        return gconf_client_get_string (preferences_client, "/apps/gnomint/size", NULL);
}

void preferences_set_size (const gchar *new_value)
{
        gconf_client_set_string (preferences_client, "/apps/gnomint/size", new_value, NULL);
}


gboolean preferences_get_revoked_visible ()
{
        return gconf_client_get_bool (preferences_client, "/apps/gnomint/revoked_visible", NULL);
}

void preferences_set_revoked_visible (gboolean new_value)
{
        gconf_client_set_bool (preferences_client, "/apps/gnomint/revoked_visible", new_value, NULL);
}

gboolean preferences_get_crq_visible ()
{
        return gconf_client_get_bool (preferences_client, "/apps/gnomint/crq_visible", NULL);
}

void preferences_set_crq_visible (gboolean new_value)
{
        gconf_client_set_bool (preferences_client, "/apps/gnomint/crq_visible", new_value, NULL);
}

gboolean preferences_get_gnome_keyring_export ()
{
        return gconf_client_get_bool (preferences_client, "/apps/gnomint/gnome_keyring_export", NULL);
}

void preferences_set_gnome_keyring_export (gboolean new_value)
{
        gconf_client_set_bool (preferences_client, "/apps/gnomint/gnome_keyring_export", new_value, NULL);
}


void preferences_deinit ()
{
        g_object_unref (preferences_client);
        preferences_client = NULL;
}


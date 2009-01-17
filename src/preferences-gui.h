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

#ifndef _PREFERENCES_H_
#define _PREFERENCES_H_

typedef void (* PreferencesGuiChangeCallback) (gboolean, gboolean);

void preferences_gui_set_csr_visible_callback (PreferencesGuiChangeCallback callback);

void preferences_gui_set_revoked_visible_callback (PreferencesGuiChangeCallback callback);

void preferences_init (int, char**);

gchar *preferences_get_size(void);
void preferences_set_size (const gchar *new_value);

gboolean preferences_get_revoked_visible(void);
void preferences_set_revoked_visible (gboolean new_value);

gboolean preferences_get_crq_visible(void);
void preferences_set_crq_visible (gboolean new_value);

gboolean preferences_get_gnome_keyring_export (void);
void preferences_set_gnome_keyring_export (gboolean new_value);

void preferences_deinit (void);


#include <gconf/gconf-client.h>
void preferences_changed_callback(GConfClient* client,
                                  guint cnxn_id,
                                  GConfEntry *entry,
                                  gpointer user_data);


#endif

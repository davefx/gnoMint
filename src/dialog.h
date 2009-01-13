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

#ifndef _DIALOG_H_
#define _DIALOG_H_

#include <glib.h>
#include <glib/gstdio.h>

#ifndef GNOMINTCLI
#include <gtk/gtk.h>
#endif

void dialog_error (gchar *message);

gchar * dialog_get_password (gchar *info_message, 
			     gchar *password_message, gchar *confirm_message, 
			     gchar *distinct_error_message, guint minimum_length);

void dialog_todo_callback (void);

typedef gboolean (* DialogRefreshCallback) (void);
void dialog_establish_refresh_function (DialogRefreshCallback callback);
gboolean dialog_refresh_list (void);

#ifndef GNOMINTCLI

void dialog_password_entry_changed_cb (GtkEditable *password_entry, gpointer user_data);

#else

gboolean dialog_ask_for_confirmation (gchar *message, gchar *prompt, gboolean default_answer);

gint dialog_ask_for_number (gchar *message, gint minimum, gint maximum, gint default_value);

gchar * dialog_ask_for_password (gchar *message);

gchar * dialog_ask_for_string (gchar *message, gchar *default_answer);


#endif

#endif

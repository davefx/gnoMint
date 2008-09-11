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

#ifndef _CA_H_
#define _CA_H_

#include <glib.h>
#include <glib/gstdio.h>
#include <gtk/gtk.h>

gboolean ca_open (gchar *filename, gboolean create);
gboolean ca_refresh_model (void);
void ca_update_csr_view (gboolean new_value, gboolean refresh);
void ca_update_revoked_view (gboolean new_value, gboolean refresh);
void ca_todo_callback(void);
gint ca_get_selected_row_id (void);
gchar * ca_get_selected_row_pem (void);
gboolean ca_treeview_row_activated (GtkTreeView *tree_view, GtkTreePath *path, GtkTreeViewColumn *column, gpointer user_data);
gboolean ca_import (gchar *filename);
void ca_error_dialog(gchar *message);



#endif

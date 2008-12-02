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

#ifndef _CA_CLI_H_
#define _CA_CLI_H_

#include <glib.h>
#include <glib/gstdio.h>


void ca_error_dialog (gchar *message);
gchar * ca_dialog_get_password (gchar *info_message, 
                                gchar *password_message, gchar *confirm_message, 
                                gchar *distinct_error_message, guint minimum_length);
void ca_todo_callback (void);
gboolean ca_open (gchar *filename, gboolean create);

void ca_command_line ();

/* void ca_password_entry_changed_cb (GtkEditable *password_entry, gpointer user_data); */
/* void ca_on_export1_activate (GtkMenuItem *menuitem, gpointer user_data); */
/* void ca_on_extractprivatekey1_activate (GtkMenuItem *menuitem, gpointer user_data); */
/* void ca_on_revoke_activate (GtkMenuItem *menuitem, gpointer user_data); */
/* void ca_on_delete2_activate (GtkMenuItem *menuitem, gpointer user_data); */
/* void ca_on_sign1_activate (GtkMenuItem *menuitem, gpointer user_data); */

/* guint64 ca_get_selected_row_id (void); */
/* gchar * ca_get_selected_row_pem (void); */
/* void ca_update_csr_view (gboolean new_value, gboolean refresh); */
/* gboolean ca_csr_view_toggled (GtkCheckMenuItem *button, gpointer user_data); */
/* void ca_update_revoked_view (gboolean new_value, gboolean refresh); */
/* gboolean ca_rcrt_view_toggled (GtkCheckMenuItem *button, gpointer user_data); */
/* void ca_generate_crl (GtkCheckMenuItem *button, gpointer user_data); */
/* gboolean ca_treeview_popup_timeout_program_cb (gpointer data); */
/* void ca_treeview_popup_timeout_program (GdkEventButton *event); */
/* gboolean ca_treeview_popup_handler (GtkTreeView *tree_view, */
/* 				    GdkEvent *event, gpointer user_data); */
/* void ca_on_change_pwd_menuitem_activate (GtkMenuItem *menuitem, gpointer user_data); */
/* gboolean ca_changepwd_newpwd_entry_changed (GtkWidget *entry, gpointer user_data); */
/* gboolean ca_changepwd_pwd_protect_radiobutton_toggled (GtkWidget *button, gpointer user_data); */
/* void ca_generate_dh_param (GtkWidget *menuitem, gpointer user_data); */


#endif

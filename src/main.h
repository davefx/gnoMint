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

#ifndef __MAIN_H_
#define __MAIN_H_


#include <libintl.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

void on_open_recent_activate (GtkRecentChooser *chooser, gpointer user_data);
gboolean on_main_window1_delete (GtkWidget *widget, GdkEvent *event, gpointer user_data);
void on_add_self_signed_ca_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_add_csr_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_new1_activate (GtkMenuItem *menuitem, gpointer     user_data);
void on_open1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_open_recent_activate (GtkRecentChooser *chooser, gpointer user_data);
void on_save_as1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_import1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_quit1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_clear1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_properties1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_preferences1_activate  (GtkMenuItem *menuitem, gpointer     user_data);
void on_about1_activate  (GtkMenuItem *menuitem, gpointer     user_data);

#endif

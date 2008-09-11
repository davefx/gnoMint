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

#ifndef _NEW_REQ_WINDOW_H_
#define _NEW_REQ_WINDOW_H_


void new_req_window_display (void);
void new_req_inherit_fields_toggled (GtkToggleButton *button, gpointer user_data);
void new_req_tab_activate (int tab_number);
void on_new_req_cn_entry_changed (GtkEditable *editable,
                                  gpointer user_data);
void on_new_req_next1_clicked (GtkButton *button,
                               gpointer user_data);
void on_new_req_previous2_clicked (GtkButton *widget,
                                   gpointer user_data);
void on_new_req_next2_clicked (GtkButton *widget,
                               gpointer user_data); 
void on_new_req_previous3_clicked (GtkButton *widget,
                                   gpointer user_data);
void on_new_req_cancel_clicked (GtkButton *widget,
                                gpointer user_data); 
void on_new_req_commit_clicked (GtkButton *widg,
                                gpointer user_data);




#endif

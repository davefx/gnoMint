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

#ifndef _NEW_CA_WINDOW_H_
#define _NEW_CA_WINDOW_H_

#ifndef GNOMINTCLI

void new_ca_window_display (void);
void new_ca_populate_country_combobox(GtkComboBox *country_combobox);
void new_ca_tab_activate (int tab_number);
void on_cn_entry_changed (GtkEditable *editable,
                          gpointer user_data) ;
void on_new_ca_next1_clicked (GtkButton *widget,
			      gpointer user_data);
void on_new_ca_previous2_clicked (GtkButton *widget,
				  gpointer user_data); 
void on_new_ca_next2_clicked (GtkButton *widget,
			      gpointer user_data);
void on_new_ca_previous3_clicked (GtkButton *widget,
				  gpointer user_data);
void on_new_ca_cancel_clicked (GtkButton *widget,
			       gpointer user_data);
void on_new_ca_pwd_entry_changed (GtkEntry *entry,
                                  gpointer user_data);
void on_new_ca_pwd_protect_radiobutton_toggled (GtkRadioButton *radiobutton, 
                                                gpointer user_data);
void on_new_ca_commit_clicked (GtkButton *widg,
			       gpointer user_data);
void populate_country_table(void);
void new_ca_populate_country_combobox(GtkComboBox *country_combobox);

#endif 

#endif

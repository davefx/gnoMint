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

#ifndef _NEW_CERT_WINDOW_H_
#define _NEW_CERT_WINDOW_H_

#include "tls.h"

#ifndef GNOMINTCLI
void new_cert_window_display (const guint64 csr_id, const gchar * csr_pem, const gchar * csr_parent_id);
void new_cert_signing_ca_treeview_cursor_changed (GtkTreeView *treeview, gpointer userdata);
void new_cert_tab_activate (int tab_number);
void on_new_cert_next2_clicked (GtkButton *button,
                                gpointer user_data); 
void on_new_cert_previous2_clicked (GtkButton *widget,
                                    gpointer user_data) ;
void on_new_cert_next1_clicked (GtkButton *button,
                                gpointer user_data);
void on_new_cert_previous3_clicked (GtkButton *widget,
                                    gpointer user_data);
void on_new_cert_cancel_clicked (GtkButton *widget,
                                 gpointer user_data);
void on_new_cert_property_toggled (GtkWidget *toggle, 
                                   gpointer user_data);
void on_new_cert_commit_clicked (GtkButton *widg,
				 gpointer user_data);
#endif

const gchar *new_cert_window_sign_csr (guint64 csr_id, guint64 ca_id, CertCreationData *cert_creation_data);


#endif

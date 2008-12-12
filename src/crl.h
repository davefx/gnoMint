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

#ifndef _CRL_WINDOW_H_
#define _CRL_WINDOW_H_

#ifndef GNOMINTCLI
void crl_window_display (void);
void crl_treeview_cursor_changed_cb (GtkTreeView *treeview, gpointer userdata);
void crl_cancel_clicked_cb (GtkButton *button, gpointer userdata);
void crl_ok_clicked_cb (GtkButton *button, gpointer userdata);
#endif

gchar * crl_generate (guint64 ca_id, gchar *filename);

#endif

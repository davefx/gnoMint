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

#ifndef _CREATION_PROCESS_WINDOW_H_
#define _CREATION_PROCESS_WINDOW_H_

#include "tls.h"

#ifndef GNOMINTCLI
void creation_process_window_error_dialog (gchar *message);
void on_cancel_creation_process_clicked (GtkButton *button,
                                         gpointer user_data);

void creation_process_window_ca_display (TlsCreationData * ca_creation_data);
void creation_process_window_csr_display (TlsCreationData * ca_creation_data);

void creation_process_window_ca_finish (void);
gint creation_process_window_ca_pulse (gpointer data);

void creation_process_window_csr_finish (void);
gint creation_process_window_csr_pulse (gpointer data);
#endif

#endif

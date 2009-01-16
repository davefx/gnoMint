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

#ifndef _CA_CREATION_H_
#define _CA_CREATION_H_

#include <glib.h>
#include <time.h>

#include "uint160.h"
#include "tls.h"

GThread * ca_creation_launch_thread (TlsCreationData *creation_data);


void ca_creation_lock_status_mutex (void);
void ca_creation_unlock_status_mutex (void);

gint ca_creation_get_thread_status (void);

gchar * ca_creation_get_thread_message(void);

gpointer ca_creation_thread (gpointer data);

#endif

//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006 David Marín Carreño <davefx@gmail.com>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or   
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

#ifndef _CSR_CREATION_H_
#define _CSR_CREATION_H_

#include <glib.h>
#include <time.h>

#include "ca_creation.h"

GThread * csr_creation_launch_thread (CaCreationData *creation_data);

void csr_creation_lock_status_mutex ();
void csr_creation_unlock_status_mutex ();

gint csr_creation_get_thread_status ();

gchar * csr_creation_get_thread_message();

#endif

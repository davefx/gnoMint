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

#ifndef _CA_FILE_H_
#define _CA_FILE_H_

#include <sqlite.h>
#include "ca_creation.h"

gchar * ca_file_create (CaCreationData * creation_data, 
				  gchar *pem_ca_private_key,
				  gchar *pem_ca_certificate);

gboolean ca_file_open (gchar *file_name);

void ca_file_close ();

gboolean ca_file_save_as (gchar *new_file_name);

gboolean ca_file_rename_tmp_file (gchar *new_file_name);

gboolean ca_file_delete_tmp_file ();



gchar ** ca_file_get_single_row (const gchar *query, ...);


gchar * ca_file_insert_cert (CertCreationData * creation_data,
			     gchar *pem_private_key,
			     gchar *pem_certificate);

gchar * ca_file_insert_csr (CaCreationData * creation_data,
			    gchar *pem_private_key,
			    gchar *pem_csr);
gchar * ca_file_remove_csr (gint id);


#endif

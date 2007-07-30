//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007 David Marín Carreño <davefx@gmail.com>
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

#ifndef _CA_FILE_H_
#define _CA_FILE_H_

#include <sqlite3.h>
#include "ca_creation.h"

gchar * ca_file_create (CaCreationData * creation_data, 
				  gchar *pem_ca_private_key,
				  gchar *pem_ca_certificate);

gboolean ca_file_open (gchar *file_name);

gboolean ca_file_check_and_update_version ();

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
gchar * ca_file_revoke_crt (gint id);

GList * ca_file_get_revoked_certs (void);

gint ca_file_begin_new_crl_transaction (gint ca_id, time_t timestamp);
void ca_file_commit_new_crl_transaction ();
void ca_file_rollback_new_crl_transaction ();


#endif

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

#ifndef _CA_FILE_H_
#define _CA_FILE_H_

#include <sqlite3.h>
#include "ca_creation.h"
#include "uint160.h"

typedef int (*CaFileCallbackFunc) (void *pArg, int argc, char **argv, char **columnNames);

typedef enum {
	CA_FILE_ELEMENT_TYPE_CERT=0,
	CA_FILE_ELEMENT_TYPE_CSR=1 
} CaFileElementType;

gchar * ca_file_create (const gchar *filename);

gboolean ca_file_open (gchar *file_name, gboolean create);

gboolean ca_file_check_and_update_version (void);

void ca_file_close (void);

gboolean ca_file_save_as (gchar *new_file_name);

void ca_file_get_next_serial (UInt160 *serial, guint64 ca_id);

gchar * ca_file_insert_self_signed_ca (CaCreationData * creation_data, 
                                       gchar *pem_ca_private_key,
                                       gchar *pem_ca_certificate);

gchar * ca_file_insert_cert (CertCreationData * creation_data,
                             gboolean is_ca,
                             gboolean private_key_in_db,
			     gchar *pem_private_key_info,
			     gchar *pem_certificate);

gchar * ca_file_insert_csr (CaCreationData * creation_data,
			    gchar *pem_private_key,
			    gchar *pem_csr);
gchar * ca_file_remove_csr (gint id);
gchar * ca_file_revoke_crt (gint id);

GList * ca_file_get_revoked_certs (guint64 ca_id, gchar **error);


gboolean ca_file_foreach_ca (CaFileCallbackFunc func, gpointer userdata);
gboolean ca_file_foreach_crt (CaFileCallbackFunc func, gboolean view_revoked, gpointer userdata);
gboolean ca_file_foreach_csr (CaFileCallbackFunc func, gpointer userdata);
gboolean ca_file_foreach_policy (CaFileCallbackFunc func, guint64 ca_id, gpointer userdata);

gchar * ca_file_get_dn_from_id (CaFileElementType type, guint64 db_id);
gchar * ca_file_get_public_pem_from_id (CaFileElementType type, guint64 db_id);
gchar * ca_file_get_pkey_field_from_id (CaFileElementType type, guint64 db_id);
gboolean ca_file_get_pkey_in_db_from_id (CaFileElementType type, guint64 db_id);

gboolean ca_file_set_pkey_field_for_id (CaFileElementType type, const gchar *new_value, guint64 db_id);
gboolean ca_file_mark_pkey_as_extracted_for_id (CaFileElementType type, const gchar *filename, guint64 db_id);

gint ca_file_begin_new_crl_transaction (guint64 ca_id, time_t timestamp);
void ca_file_commit_new_crl_transaction (guint64 ca_id, const GList *revoked_certs);
void ca_file_rollback_new_crl_transaction (void);

guint ca_file_policy_get (guint64 ca_id, gchar *property_name);
gboolean ca_file_policy_set (guint64 ca_id, gchar *property_name, guint value);

gboolean ca_file_is_password_protected(void);
gboolean ca_file_check_password (const gchar *password);
gboolean ca_file_password_unprotect(const gchar *old_password);
gboolean ca_file_password_protect(const gchar *new_password);
gboolean ca_file_password_change(const gchar *old_password, const gchar *new_password);

#endif

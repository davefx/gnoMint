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

#ifndef _CA_FILE_H_
#define _CA_FILE_H_

#include <sqlite3.h>
#include "uint160.h"

typedef int (*CaFileCallbackFunc) (void *pArg, int argc, char **argv, char **columnNames);

typedef enum {
	CA_FILE_ELEMENT_TYPE_CERT=0,
	CA_FILE_ELEMENT_TYPE_CSR=1 
} CaFileElementType;

gchar * ca_file_create (const gchar *filename);

gboolean ca_file_open (gchar *file_name, gboolean create);

void ca_file_close (void);

gboolean ca_file_save_as (gchar *new_file_name);

gint ca_file_get_number_of_certs ();
gint ca_file_get_number_of_csrs ();

void ca_file_get_next_serial (UInt160 *serial, guint64 ca_id);
gboolean ca_file_set_next_serial (UInt160 *serial, guint64 ca_id);

gchar * ca_file_insert_self_signed_ca (gchar *pem_ca_private_key,
                                       gchar *pem_ca_certificate);                                      

gchar * ca_file_insert_cert (gboolean is_ca,
                             gboolean private_key_in_db,
			     gchar *pem_private_key_info,
			     gchar *pem_certificate);

gchar * ca_file_insert_imported_cert (gboolean is_ca,
                                      const UInt160 serial,
                                      const gchar *pem_certificate,
                                      guint64 *id);

gchar * ca_file_insert_csr (gchar *pem_private_key,
			    gchar *pem_csr,
	                    gchar *parent_ca_id_str,
                            guint64 *id);
gchar * ca_file_insert_imported_privkey (const gchar *privkey_pem);

gchar * ca_file_remove_csr (guint64 id);
gchar * ca_file_revoke_crt (guint64 id);
gchar * ca_file_revoke_crt_with_date (guint64 id, time_t date);

GList * ca_file_get_revoked_certs (guint64 ca_id, gchar **error);

// CaFileCAColumns
enum CaFileCAColumns {CA_FILE_CA_COLUMN_ID=0,
      CA_FILE_CA_COLUMN_SERIAL=1,
      CA_FILE_CA_COLUMN_SUBJECT=2,
      CA_FILE_CA_COLUMN_DN=3,
      CA_FILE_CA_COLUMN_PARENT_DN=4,
      CA_FILE_CA_COLUMN_PEM=5,
      CA_FILE_CA_COLUMN_EXPIRATION=6,
      CA_FILE_CA_COLUMN_SUBJECT_COUNT=7,
      CA_FILE_CA_COLUMN_NUMBER=8};

// CaFileCertColumns
enum CaFileCertColumns {CA_FILE_CERT_COLUMN_ID=0,
      CA_FILE_CERT_COLUMN_IS_CA=1,
      CA_FILE_CERT_COLUMN_SERIAL=2,
      CA_FILE_CERT_COLUMN_SUBJECT=3,
      CA_FILE_CERT_COLUMN_ACTIVATION=4,
      CA_FILE_CERT_COLUMN_EXPIRATION=5,
      CA_FILE_CERT_COLUMN_REVOCATION=6,
      CA_FILE_CERT_COLUMN_PRIVATE_KEY_IN_DB=7,
      CA_FILE_CERT_COLUMN_PEM=8,
      CA_FILE_CERT_COLUMN_DN=9,
      CA_FILE_CERT_COLUMN_PARENT_DN=10,
      CA_FILE_CERT_COLUMN_PARENT_ROUTE=11,
      CA_FILE_CERT_COLUMN_NUMBER=12};

// CaFileCSRColumns
enum CaFileCSRColumns {CA_FILE_CSR_COLUMN_ID=0,
      CA_FILE_CSR_COLUMN_SUBJECT=1,
      CA_FILE_CSR_COLUMN_PRIVATE_KEY_IN_DB=2,
      CA_FILE_CSR_COLUMN_PEM=3,
      CA_FILE_CSR_COLUMN_PARENT_ID=4,
      CA_FILE_CSR_COLUMN_NUMBER=5};


gboolean ca_file_foreach_ca (CaFileCallbackFunc func, gpointer userdata);
gboolean ca_file_foreach_crt (CaFileCallbackFunc func, gboolean view_revoked, gpointer userdata);
gboolean ca_file_foreach_csr (CaFileCallbackFunc func, gpointer userdata);
gboolean ca_file_foreach_policy (CaFileCallbackFunc func, guint64 ca_id, gpointer userdata);

gboolean ca_file_get_id_from_serial_issuer_id (const UInt160 *serial, const guint64 issuer_id, guint64 *db_id);
gboolean ca_file_get_id_from_dn (CaFileElementType type, const gchar *dn, guint64 *db_id);
gchar * ca_file_get_dn_from_id (CaFileElementType type, guint64 db_id);
gchar * ca_file_get_public_pem_from_id (CaFileElementType type, guint64 db_id);
gchar * ca_file_get_pkey_field_from_id (CaFileElementType type, guint64 db_id);
gboolean ca_file_get_pkey_in_db_from_id (CaFileElementType type, guint64 db_id);

gboolean ca_file_set_pkey_field_for_id (CaFileElementType type, const gchar *new_value, guint64 db_id);
gboolean ca_file_mark_pkey_as_extracted_for_id (CaFileElementType type, const gchar *filename, guint64 db_id);

gint ca_file_begin_new_crl_transaction (guint64 ca_id, time_t timestamp);
void ca_file_commit_new_crl_transaction (guint64 ca_id, const GList *revoked_certs);
void ca_file_rollback_new_crl_transaction (void);

gchar * ca_file_policy_get (guint64 ca_id, gchar *property_name);
gboolean ca_file_policy_set (guint64 ca_id, gchar *property_name, const gchar *value);
gint  ca_file_policy_get_int (guint64 ca_id, gchar *property_name);
gboolean ca_file_policy_set_int (guint64 ca_id, gchar *property_name, gint value);

gboolean ca_file_is_password_protected(void);
gboolean ca_file_check_password (const gchar *password);
gboolean ca_file_password_unprotect(const gchar *old_password);
gboolean ca_file_password_protect(const gchar *new_password);
gboolean ca_file_password_change(const gchar *old_password, const gchar *new_password);


gboolean ca_file_check_if_is_ca_id (guint64 ca_id);
gboolean ca_file_check_if_is_cert_id (guint64 cert_id);
gboolean ca_file_check_if_is_csr_id (guint64 csr_id);

gchar * ca_file_format_subject_with_expiration (const gchar *subject, const gchar *expiration_str, const gchar *subject_count_str);


#endif

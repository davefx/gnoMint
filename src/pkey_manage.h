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

#ifndef _PKEY_MANAGE_H_
#define _PKEY_MANAGE_H_

#include <glib.h>
/* #include <gtk/gtk.h> */

/* FUNCTIONS RELATED WITH PRIVATE KEY BEING SAVED IN EXTERNAL FILES */

typedef struct {
	gchar *pkey_data;
	gboolean is_in_db;
	gboolean is_ciphered_with_db_pwd;	
	gchar *external_file;
} PkeyManageData;

PkeyManageData * pkey_manage_get_certificate_pkey (guint64 id);
PkeyManageData * pkey_manage_get_csr_pkey (guint64 id);

void pkey_manage_data_free (PkeyManageData *pkeydata);


/* PRIVATE KEY PASSWORD PROTECTION RELATED FUNCTIONS */

void pkey_manage_crypt_auto (gchar *password,
			     gchar **pem_private_key,
			     const gchar *pem_root_certificate);

gchar * pkey_manage_ask_password (void);
gboolean pkey_manage_check_password (const gchar *checking_password, const gchar *hashed_password);

gchar * pkey_manage_crypt   (const gchar *pem_private_key, const gchar *dn);
gchar * pkey_manage_uncrypt (PkeyManageData *pkey, const gchar *dn);
gchar * pkey_manage_crypt_w_pwd   (const gchar *pem_private_key, const gchar *dn, const gchar *pwd);
gchar * pkey_manage_uncrypt_w_pwd (PkeyManageData *pkey, const gchar *dn, const gchar *pwd);

gchar * pkey_manage_encrypt_password (const gchar *pwd);



#endif

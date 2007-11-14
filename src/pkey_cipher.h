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

#ifndef _PKEY_CIPHER_H_
#define _PKEY_CIPHER_H_

void pkey_cipher_crypt_auto (CaCreationData *creation_data,
			     gchar **pem_private_key,
			     const gchar *pem_root_certificate);

gchar * pkey_cipher_crypt   (const gchar *pem_private_key, const gchar *dn);
gchar * pkey_cipher_uncrypt (const gchar *pem_private_key, const gchar *dn);
gchar * pkey_cipher_ask_password ();
gchar * pkey_cipher_crypt_w_pwd   (const gchar *pem_private_key, const gchar *dn, const gchar *pwd);
gchar * pkey_cipher_uncrypt_w_pwd (const gchar *pem_private_key, const gchar *dn, const gchar *pwd);

gchar * pkey_cipher_encrypt_password (const gchar *pwd);
gboolean pkey_cipher_check_password (const gchar *checking_password, const gchar *hashed_password);

#endif

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

#ifndef _SSL_H_
#define _SSL_H_

#include "ca_creation.h"

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif


gchar * ssl_generate_rsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       EVP_PKEY ** key);

gchar * ssl_generate_dsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       EVP_PKEY ** key);

gchar * ssl_generate_self_signed_certificate (CaCreationData * creation_data, 
					      EVP_PKEY *key,
					      gchar ** certificate);

#endif

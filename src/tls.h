//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007 David Marín Carreño <davefx@gmail.com>
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

#ifndef _TLS_H_
#define _TLS_H_

#include "ca_creation.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>

typedef struct __TlsCert {	
	guint64 serial_number;

	gchar * cn;
	gchar * o;
	gchar * ou;
	gchar * c;
	gchar * st;
	gchar * l;

	gchar * i_cn;
	gchar * i_o;
	gchar * i_ou;
	gchar * i_c;
	gchar * i_st;
	gchar * i_l;

	gchar * sha1;
	gchar * md5;

	GList * uses;

	time_t expiration_time;
	time_t activation_time;
} TlsCert;

typedef struct __TlsCsr {	
	gchar * cn;
	gchar * o;
	gchar * ou;
	gchar * c;
	gchar * st;
	gchar * l;
} TlsCsr;

void tls_init ();

gchar * tls_generate_rsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key);

gchar * tls_generate_dsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key);

gchar * tls_generate_pkcs8_encrypted_private_key (gchar *private_key, gchar *passphrase);

gchar * tls_generate_self_signed_certificate (CaCreationData * creation_data, 
					      gnutls_x509_privkey_t *key,
					      gchar ** certificate);

gchar * tls_generate_csr (CaCreationData * creation_data, 
			  gnutls_x509_privkey_t *key,
			  gchar ** csr);

gchar * tls_generate_certificate (CertCreationData * creation_data,
				  gchar *csr_pem,
				  gchar *ca_cert_pem,
				  gchar *ca_priv_key_pem,
				  gchar **certificate);

TlsCert * tls_parse_cert_pem (const char * pem_certificate);
gboolean tls_is_ca_pem (const char * pem_certificate);
void tls_cert_free (TlsCert *);

TlsCsr * tls_parse_csr_pem (const char * pem_csr);
void tls_csr_free (TlsCsr *);



#endif

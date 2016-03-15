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

#ifndef _TLS_H_
#define _TLS_H_

#include "uint160.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#include <stdio.h>

#define TLS_INVALID_PASSWORD GNUTLS_E_DECRYPTION_FAILED
#define TLS_NON_MATCHING_PRIVATE_KEY -2000

typedef struct {
	gchar * country;
	gchar * state;
	gchar * city;
	gchar * org;
	gchar * ou;
	gchar * cn;
	gchar * emailAddress;

	gint key_type;
	gint key_bitlength;

	gint key_months_before_expiration;
	time_t activation;
	time_t expiration;

	gchar * crl_distribution_point;

	gchar * password; 

        gchar * parent_ca_id_str;
} TlsCreationData;

typedef struct {
	gint key_months_before_expiration;
	time_t activation;
	time_t expiration;
	
	UInt160 serial;

        gboolean ca;
        gboolean crl_signing;
	gboolean digital_signature;
	gboolean data_encipherment;
	gboolean key_encipherment;
	gboolean non_repudiation;
	gboolean key_agreement;

	gboolean email_protection;
	gboolean code_signing;
	gboolean web_client;
	gboolean web_server;
	gboolean time_stamping;
	gboolean ocsp_signing;
	gboolean any_purpose;

	gchar * crl_distribution_point;

	gchar * cadb_password;

} TlsCertCreationData;

typedef struct __TlsCert {	
	UInt160 serial_number;

	gchar * cn;
	gchar * o;
	gchar * ou;
	gchar * c;
	gchar * st;
	gchar * l;
	gchar * dn;

	gchar * i_cn;
	gchar * i_o;
	gchar * i_ou;
	gchar * i_c;
	gchar * i_st;
	gchar * i_l;
	gchar * i_dn;

	gchar * sha1;
	gchar * md5;
	gchar * sha256;
	gchar * sha512;

	gchar * key_id;

        gchar * subject_key_id;
        gchar * issuer_key_id;

	gchar * crl_distribution_point;

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
	gchar * dn;

	gchar * key_id;
} TlsCsr;

void tls_init (void);

gchar * tls_generate_rsa_keys (TlsCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key);

gchar * tls_generate_dsa_keys (TlsCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key);

gchar * tls_generate_pkcs8_encrypted_private_key (gchar *private_key, gchar *passphrase);
gchar * tls_load_pkcs8_private_key (gchar *pem, gchar *passphrase, const gchar * key_id, gint *tls_error);

gnutls_datum_t * tls_generate_pkcs12 (gchar *certificate, gchar *private_key, gchar *passphrase);

gchar * tls_generate_self_signed_certificate (TlsCreationData * creation_data, 
					      gnutls_x509_privkey_t *key,
					      gchar ** certificate);

gchar * tls_generate_csr (TlsCreationData * creation_data, 
			  gnutls_x509_privkey_t *key,
			  gchar ** csr);

gchar * tls_generate_certificate (TlsCertCreationData * creation_data,
				  gchar *csr_pem,
				  gchar *ca_cert_pem,
				  gchar *ca_priv_key_pem,
				  gchar **certificate);

TlsCert * tls_parse_cert_pem (const char * pem_certificate);
gboolean tls_is_ca_pem (const char * pem_certificate);
void tls_cert_free (TlsCert *);

TlsCsr * tls_parse_csr_pem (const char * pem_csr);
void tls_csr_free (TlsCsr *);

void tls_creation_data_free (TlsCreationData *cd);

gchar * tls_generate_crl (GList * revoked_certs, 
                          guchar *ca_pem, 
                          guchar *ca_private_key,
                          gint crl_version,
                          time_t current_timestamp,
                          time_t next_crl_timestamp);

gchar * tls_generate_dh_params (guint bits);

gboolean tls_cert_check_issuer (const gchar *cert_pem, const gchar *ca_pem);

gchar * tls_get_private_key_id (const gchar *privkey_pem);
gchar * tls_get_public_key_id (const gchar *certificate_pem);

#ifdef ADVANCED_GNUTLS
gchar * tls_get_csr_public_key_id (const gchar *csr_pem);
#endif

#endif

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

#include "ssl.h"

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

#include <time.h>


int __add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	/* This sets the 'context' of the extensions. */
	/* No configuration database */

	X509V3_set_ctx_nodb(&ctx);

	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);

	return 1;
}




gchar * ssl_generate_rsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       EVP_PKEY ** key)
{
	RSA * new_key_RSA = NULL;
	BIO * bio_private_key = NULL;

	gint private_key_len = 0;

	new_key_RSA = RSA_generate_key (creation_data->key_bitlength, 65537, NULL, NULL);
	if (! new_key_RSA) { // failure
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when generating RSA key: %s"), ERR_error_string(ERR_get_error(), NULL));
	}	

	bio_private_key = BIO_new (BIO_s_mem());

	if (! bio_private_key) { // failure
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error creating BIOs for public and private key: %s"), ERR_error_string(ERR_get_error(), NULL));
	}	


	if (! PEM_write_bio_RSAPrivateKey (bio_private_key, new_key_RSA, NULL, NULL, 0, NULL, NULL)) {
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error writing RSA Private key in BIO: %s"), ERR_error_string(ERR_get_error(), NULL));
	} 

	private_key_len = BIO_ctrl_pending(bio_private_key);	
	if (! private_key_len) {
		return g_strdup_printf(_("Error: the length of RSA Private key in BIO is 0"));
	}
	
	if (! ((* key) = EVP_PKEY_new ())) {
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error creating EVP_PKEY structure for saving data: %s"), ERR_error_string(ERR_get_error(), NULL));
	}

	EVP_PKEY_assign_RSA ((*key), new_key_RSA);


/* 	RSA_free (new_key_RSA); */
	
	(* private_key) = g_new0 (gchar, private_key_len + 1);
	if (BIO_read (bio_private_key, (* private_key), private_key_len ) < 1) {
		return g_strdup_printf(_("Error: the length of read RSA Private key in BIO is 0"));		
	}


	BIO_free (bio_private_key);
	
	return NULL;

}


gchar * ssl_generate_dsa_keys (CaCreationData *creation_data,
			    gchar ** private_key,
			    EVP_PKEY ** key)
{
	DSA * new_key_DSA = NULL;
	BIO * bio_private_key = NULL;

	gint private_key_len = 0;

	new_key_DSA = DSA_generate_parameters(creation_data->key_bitlength, NULL, 0, NULL, NULL, NULL, NULL);		
	if (! new_key_DSA) { // failure
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when generating DSA parameters: %s"), ERR_error_string(ERR_get_error(), NULL));
	}

	DSA_generate_key (new_key_DSA);
	if (! new_key_DSA) { // failure
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when generating DSA key: %s"), ERR_error_string(ERR_get_error(), NULL));
	}	
	
	EVP_PKEY_assign_DSA ((*key), new_key_DSA);

	bio_private_key = BIO_new (BIO_s_mem());
	
	PEM_write_bio_DSAPrivateKey (bio_private_key, new_key_DSA, NULL, NULL, 0, NULL, NULL); 
	private_key_len = BIO_ctrl_pending(bio_private_key);	
	
/* 	DSA_free (new_key_DSA); */
	
	(* private_key) = g_new0 (gchar, private_key_len + 1);
	if (BIO_read (bio_private_key, (* private_key), private_key_len ) != private_key_len) {
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when writing private key: %s"), ERR_error_string(ERR_get_error(), NULL));
	}		  
	
	BIO_free (bio_private_key);
	
	return NULL;
	
}

gchar * ssl_generate_self_signed_certificate (CaCreationData * creation_data, 
					      EVP_PKEY *signing_key,
					      gchar ** cert)
{
/* 	EVP_PKEY * signing_key = NULL; */

/* 	BIO * bio_public_key = NULL; */
/* 	BIO * bio_signing_private_key = NULL; */
	BIO * bio_cert = NULL;

	X509     * certificate = NULL;
	X509_NAME *name=NULL;
	
	gint certificate_len = 0;

	glong days_before_expiration = 0;
	time_t tmp;
	struct tm expiration_time;

	// Calculate expiration
	tmp = time(NULL);
	gmtime_r (&tmp, &expiration_time);
	expiration_time.tm_mon = expiration_time.tm_mon + creation_data->key_months_before_expiration;
	expiration_time.tm_year = expiration_time.tm_year + (expiration_time.tm_mon / 12);
	expiration_time.tm_mon = expiration_time.tm_mon % 12;
	days_before_expiration = mktime(&expiration_time) - tmp;

/*  	// Extract RSA structure from public_key string  */

/* 	bio_public_key = BIO_new_mem_buf (public_key, -1); */
	
/* 	signing_key = PEM_read_bio_PUBKEY (bio_public_key, NULL, NULL, NULL); */
/* 	if (! signing_key){ */

/* 		printf ("Remaining Public key:\n\n"); */
/* 		while (! BIO_eof(bio_public_key)) { */
/* 			if (BIO_gets (bio_public_key, tst, 254) < 1) */
/* 				printf ("Error while reading BIO\n\n"); */
/* 			else  */
/* 				printf ("%s\n",tst); */
/* 		} */
		
/* 		BIO_reset (bio_public_key); */

/* 		printf ("Public key:\n\n"); */
/* 		while (! BIO_eof(bio_public_key)) { */
/* 			if (BIO_gets (bio_public_key, tst, 254) < 1) */
/* 				printf ("Error while reading BIO\n\n"); */
/* 			else  */
/* 				printf ("%s\n",tst); */
/* 		} */


/* 		ERR_load_crypto_strings(); */
/* 		return g_strdup_printf(_("Error when processing public key: %s"), ERR_error_string(ERR_get_error(), NULL)); */
/* 	} */

/* 	BIO_free (bio_public_key); */

/*  	// Complete RSA structure from private_key string  */

/* 	bio_signing_private_key = BIO_new_mem_buf (private_key, -1); */

/* 	signing_key = PEM_read_bio_PrivateKey (bio_signing_private_key, &signing_key, NULL, NULL); */
/* 	if (! signing_key){ */
/* 		ERR_load_crypto_strings(); */
/* 		return g_strdup_printf(_("Error when processing private key: %s"), ERR_error_string(ERR_get_error(), NULL)); */
/* 	}	 */
	
/* 	BIO_free (bio_signing_private_key); */
	
	certificate = X509_new ();	
	if (! certificate){
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when creating certificate: %s"), ERR_error_string(ERR_get_error(), NULL));
	}	

	// We are making a X509 v3 certificate (version = 2)
	if (X509_set_version (certificate, 2) == 0){
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when setting certificate version: %s"), ERR_error_string(ERR_get_error(), NULL));
	}

	ASN1_INTEGER_set (X509_get_serialNumber(certificate), 1);
	X509_gmtime_adj (X509_get_notBefore(certificate), 0);
	X509_gmtime_adj (X509_get_notAfter(certificate), days_before_expiration);
	X509_set_pubkey (certificate, signing_key);

	name = X509_get_subject_name (certificate);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
	if (creation_data->country)
		X509_NAME_add_entry_by_txt (name, "C",
					    MBSTRING_ASC, creation_data->country, -1, -1, 0);
	if (creation_data->state)
		X509_NAME_add_entry_by_txt (name, "ST",
					    MBSTRING_ASC, creation_data->state, -1, -1, 0);
	if (creation_data->city)
		X509_NAME_add_entry_by_txt (name, "L",
					    MBSTRING_ASC, creation_data->city, -1, -1, 0);
	if (creation_data->org)
		X509_NAME_add_entry_by_txt (name, "O",
					    MBSTRING_ASC, creation_data->org, -1, -1, 0);
	if (creation_data->ou)
		X509_NAME_add_entry_by_txt (name, "OU",
					    MBSTRING_ASC, creation_data->ou, -1, -1, 0);
	if (creation_data->cn)
		X509_NAME_add_entry_by_txt (name, "CN",
					    MBSTRING_ASC, creation_data->cn, -1, -1, 0);
	if (creation_data->emailAddress)
		X509_NAME_add_entry_by_txt (name, "emailAddress",
					    MBSTRING_ASC, creation_data->emailAddress, -1, -1, 0);

	name = X509_get_issuer_name (certificate);

	if (creation_data->country)
		X509_NAME_add_entry_by_txt (name, "C",
					    MBSTRING_ASC, creation_data->country, -1, -1, 0);
	if (creation_data->state)
		X509_NAME_add_entry_by_txt (name, "ST",
					    MBSTRING_ASC, creation_data->state, -1, -1, 0);
	if (creation_data->city)
		X509_NAME_add_entry_by_txt (name, "L",
					    MBSTRING_ASC, creation_data->city, -1, -1, 0);
	if (creation_data->org)
		X509_NAME_add_entry_by_txt (name, "O",
					    MBSTRING_ASC, creation_data->org, -1, -1, 0);
	if (creation_data->ou)
		X509_NAME_add_entry_by_txt (name, "OU",
					    MBSTRING_ASC, creation_data->ou, -1, -1, 0);
	if (creation_data->cn)
		X509_NAME_add_entry_by_txt (name, "CN",
					    MBSTRING_ASC, creation_data->cn, -1, -1, 0);
	if (creation_data->emailAddress)
		X509_NAME_add_entry_by_txt (name, "emailAddress",
					    MBSTRING_ASC, creation_data->emailAddress, -1, -1, 0);


	/* Add various extensions: standard extensions */
	__add_ext (certificate, NID_basic_constraints, "critical,CA:TRUE");
	__add_ext (certificate, NID_key_usage, "critical,keyCertSign,cRLSign");

	__add_ext (certificate, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	__add_ext (certificate, NID_netscape_cert_type, "sslCA");

	__add_ext (certificate, NID_netscape_comment, "Generated by gnoMint, by David Marin");

	
	if (! X509_sign (certificate, signing_key, EVP_md5())) {
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when signing certificate: %s"), ERR_error_string(ERR_get_error(), NULL));
	}

	if (X509_verify (certificate, signing_key) < 0){
		ERR_load_crypto_strings();
		return g_strdup_printf(_("Error when verifying certificate: %s"), ERR_error_string(ERR_get_error(), NULL));
	}

	bio_cert = BIO_new (BIO_s_mem());
	PEM_write_bio_X509 (bio_cert, certificate);

	X509_free (certificate);

	certificate_len = BIO_ctrl_pending(bio_cert);	
	(* cert) = g_new0 (gchar, certificate_len + 1);
	BIO_read (bio_cert, (* cert), certificate_len);

	BIO_free (bio_cert);

	return NULL;
}


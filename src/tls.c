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

#include "tls.h"

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

#include <time.h>
#include <string.h>

void tls_init ()
{
	gnutls_global_init ();

}

gchar * tls_generate_rsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key)
{

	gint private_key_len = 0;

	(*key) = g_new0 (gnutls_x509_privkey_t, 1);
	if (gnutls_x509_privkey_init (*key) < 0) {
		return g_strdup_printf(_("Error initializing private key structure."));
	}

	/* Generate a 1024 bit RSA private key. */
	if (gnutls_x509_privkey_generate ((** key), GNUTLS_PK_RSA, creation_data->key_bitlength, 0) < 0) {
		return g_strdup_printf(_("Error creating private key."));
	}


	/* Calculate private key length */
	(* private_key) = g_new0 (gchar, 1);	
	gnutls_x509_privkey_export ((** key), GNUTLS_X509_FMT_PEM, (* private_key), &private_key_len);
	g_free (* private_key);

	/* Save the private key to a PEM format */
	(* private_key) = g_new0 (gchar, private_key_len);	
	if (gnutls_x509_privkey_export ((** key), GNUTLS_X509_FMT_PEM, (* private_key), &private_key_len) < 0) {
		return g_strdup_printf(_("Error exporting private key to PEM structure."));
	}

	return NULL;
}

gchar * tls_generate_dsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key)
{

	gint private_key_len = 0;

	(*key) = g_new0 (gnutls_x509_privkey_t, 1);
	if (gnutls_x509_privkey_init (*key) < 0) {
		return g_strdup_printf(_("Error initializing private key structure."));
	}

	/* Generate a 1024 bit RSA private key. */
	if (gnutls_x509_privkey_generate ((** key), GNUTLS_PK_DSA, creation_data->key_bitlength, 0) < 0) {
		return g_strdup_printf(_("Error creating private key."));
	}


	/* Calculate private key length */
	(* private_key) = g_new0 (gchar, 1);	
	gnutls_x509_privkey_export ((** key), GNUTLS_X509_FMT_PEM, (* private_key), &private_key_len);
	g_free (* private_key);

	/* Save the private key to a PEM format */
	(* private_key) = g_new0 (gchar, private_key_len);	
	if (gnutls_x509_privkey_export ((** key), GNUTLS_X509_FMT_PEM, (* private_key), &private_key_len) < 0) {
		return g_strdup_printf(_("Error exporting private key to PEM structure."));
	}

	return NULL;

}

gchar * tls_generate_self_signed_certificate (CaCreationData * creation_data, 
					      gnutls_x509_privkey_t *key,
					      gchar ** certificate)
{
	gnutls_x509_crt_t crt;
	gint serial=1;
	struct tm expiration_time;
	gchar * keyid = NULL;
	gint keyidsize = 0;
	gint certificate_len = 0;
	time_t tmp;

	if (gnutls_x509_crt_init (&crt) < 0) {
		return g_strdup_printf(_("Error when initializing certificate structure"));
	}

	if (gnutls_x509_crt_set_version (crt, 3) < 0){
		return g_strdup_printf(_("Error when setting certificate version"));
	}
	
	if (gnutls_x509_crt_set_serial (crt, &serial, sizeof (gint)) < 0) {
		return g_strdup_printf(_("Error when setting certificate serial number"));
	}

	if (gnutls_x509_crt_set_activation_time (crt, time(NULL)) < 0) {
		return g_strdup_printf(_("Error when setting activation time"));
	}

	tmp = time (NULL);
	gmtime_r (&tmp, &expiration_time);
	expiration_time.tm_mon = expiration_time.tm_mon + creation_data->key_months_before_expiration;
	expiration_time.tm_year = expiration_time.tm_year + (expiration_time.tm_mon / 12);
	expiration_time.tm_mon = expiration_time.tm_mon % 12;	

	if (gnutls_x509_crt_set_expiration_time (crt, mktime(&expiration_time)) < 0) {
		return g_strdup_printf(_("Error when setting expiration time"));
	}

	gnutls_x509_crt_set_key (crt, (* key));

	if (creation_data->country) {
		gnutls_x509_crt_set_dn_by_oid (crt, GNUTLS_OID_X520_COUNTRY_NAME,
					       0, creation_data->country, strlen(creation_data->country));
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_COUNTRY_NAME,
						      0, creation_data->country, strlen(creation_data->country));
	}

	if (creation_data->state) {
		gnutls_x509_crt_set_dn_by_oid (crt, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME,
					       0, creation_data->state, strlen(creation_data->state));
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME,
					       0, creation_data->state, strlen(creation_data->state));
	}
	if (creation_data->city) {
		gnutls_x509_crt_set_dn_by_oid (crt, GNUTLS_OID_X520_LOCALITY_NAME,
					       0, creation_data->city, strlen(creation_data->city));
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_LOCALITY_NAME,
					       0, creation_data->city, strlen(creation_data->city));
	}
	if (creation_data->org) {
		gnutls_x509_crt_set_dn_by_oid (crt, GNUTLS_OID_X520_ORGANIZATION_NAME,
					       0, creation_data->org, strlen(creation_data->org));
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_ORGANIZATION_NAME,
					       0, creation_data->org, strlen(creation_data->org));
	}
	if (creation_data->ou) {
		gnutls_x509_crt_set_dn_by_oid (crt, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,
					       0, creation_data->ou, strlen(creation_data->ou));
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,
					       0, creation_data->ou, strlen(creation_data->ou));
	}
	if (creation_data->cn) {
		gnutls_x509_crt_set_dn_by_oid (crt, GNUTLS_OID_X520_COMMON_NAME,
					       0, creation_data->cn, strlen(creation_data->cn));	
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_COMMON_NAME,
						      0, creation_data->cn, strlen(creation_data->cn));	
	}

	
	if (gnutls_x509_crt_set_ca_status (crt, 1) != 0) {
			return g_strdup_printf(_("Error when setting basicConstraint extension"));
	}
	
	if (gnutls_x509_crt_set_key_usage (crt, GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN) != 0) {
			return g_strdup_printf(_("Error when setting keyUsage extension"));
	}

	keyid = g_new0 (gchar,1);	
	gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
	g_free (keyid);

	keyid = g_new0 (gchar,keyidsize);
	gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
	if (gnutls_x509_crt_set_subject_key_id(crt, keyid, keyidsize) !=0) {
		return g_strdup_printf(_("Error when setting subject key identifier extension"));
	}
       

	// __add_ext (certificate, NID_netscape_cert_type, "sslCA");
	//
	// __add_ext (certificate, NID_netscape_comment, "Generated by gnoMint, by David Marin");

	if (gnutls_x509_crt_sign(crt, crt, (* key))) {
		return g_strdup_printf(_("Error when signing self-signed certificate"));
	}
	
	/* Calculate certificate length */
	(* certificate) = g_new0 (gchar, 1);	
	gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, (* certificate), &certificate_len);
	g_free (* certificate);

	/* Save the private key to a PEM format */
	(* certificate) = g_new0 (gchar, certificate_len);	
	if (gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, (* certificate), &certificate_len) < 0) {
		return g_strdup_printf(_("Error exporting private key to PEM structure."));
	}

	gnutls_x509_crt_deinit (crt);

	return NULL;

}

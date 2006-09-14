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

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "tls.h"

void tls_init ()
{
	gnutls_global_init ();

}

gchar * tls_generate_rsa_keys (CaCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key)
{

	guint private_key_len = 0;

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

	guint private_key_len = 0;

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

gchar * tls_generate_pkcs8_encrypted_private_key (gchar *pem_private_key, gchar *passphrase)
{
	gnutls_datum_t pem_datum;
	gchar *pkcs8_private_key = NULL;
	guint pkcs8_private_key_len = 0;
	gnutls_x509_privkey_t key;
	gint errorcode;

	pem_datum.data = (unsigned char *) pem_private_key;
	pem_datum.size = strlen(pem_private_key);

	if (gnutls_x509_privkey_init (&key) < 0) {
		return NULL;
	}

	/* Import PEM private key into internal structure. */
	if (gnutls_x509_privkey_import (key, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
		return NULL;
	}

	/* Calculate pkcs8 length */
	pkcs8_private_key = g_new0 (gchar, 1);
	errorcode = gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_PEM, passphrase, GNUTLS_PKCS_USE_PKCS12_3DES, pkcs8_private_key, &pkcs8_private_key_len);
	g_free (pkcs8_private_key);

	/* Save the private key to a PEM format */
	pkcs8_private_key = g_new0 (gchar, pkcs8_private_key_len);	
	if (gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_PEM, passphrase, GNUTLS_PKCS_USE_PKCS12_3DES, pkcs8_private_key, &pkcs8_private_key_len) < 0) {
		return NULL;
	}

	return pkcs8_private_key;
}


gchar * tls_generate_self_signed_certificate (CaCreationData * creation_data, 
					      gnutls_x509_privkey_t *key,
					      gchar ** certificate)
{
	gnutls_x509_crt_t crt;
	guint64 sn = G_GUINT64_CONSTANT(1);
	gchar * serial = NULL;
	guchar * keyid = NULL;
	guint keyidsize = 0;
	guint certificate_len = 0;

	if (gnutls_x509_crt_init (&crt) < 0) {
		return g_strdup_printf(_("Error when initializing certificate structure"));
	}

	if (gnutls_x509_crt_set_version (crt, 3) < 0){
		return g_strdup_printf(_("Error when setting certificate version"));
	}
	
	serial = g_strdup_printf ("%llX", sn);
	if (gnutls_x509_crt_set_serial (crt, serial, strlen (serial)) < 0) {
		return g_strdup_printf(_("Error when setting certificate serial number"));
	}
	g_free (serial);

	if (gnutls_x509_crt_set_activation_time (crt, creation_data->activation) < 0) {
		return g_strdup_printf(_("Error when setting activation time"));
	}

	if (gnutls_x509_crt_set_expiration_time (crt, creation_data->expiration) < 0) {
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

	keyid = g_new0 (guchar,1);	
	gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
	g_free (keyid);

	keyid = g_new0 (guchar,keyidsize);
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


gchar * tls_generate_csr (CaCreationData * creation_data, 
			  gnutls_x509_privkey_t *key,
			  gchar ** csr)
{
	gnutls_x509_crq_t crq;
	guint csr_len = 0;

	if (gnutls_x509_crq_init (&crq) < 0) {
		return g_strdup_printf(_("Error when initializing csr structure"));
	}

	if (gnutls_x509_crq_set_version (crq, 1) < 0){
		return g_strdup_printf(_("Error when setting csr version"));
	}
	
	gnutls_x509_crq_set_key (crq, (* key));

	if (creation_data->country) {
		gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_COUNTRY_NAME,
					       0, creation_data->country, strlen(creation_data->country));
	}

	if (creation_data->state) {
		gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME,
					       0, creation_data->state, strlen(creation_data->state));
	}
	if (creation_data->city) {
		gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_LOCALITY_NAME,
					       0, creation_data->city, strlen(creation_data->city));
	}
	if (creation_data->org) {
		gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_ORGANIZATION_NAME,
					       0, creation_data->org, strlen(creation_data->org));
	}
	if (creation_data->ou) {
		gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,
					       0, creation_data->ou, strlen(creation_data->ou));
	}
	if (creation_data->cn) {
		gnutls_x509_crq_set_dn_by_oid (crq, GNUTLS_OID_X520_COMMON_NAME,
					       0, creation_data->cn, strlen(creation_data->cn));	
	}
	

	if (gnutls_x509_crq_sign(crq, (* key))) {
		return g_strdup_printf(_("Error when signing self-signed csr"));
	}
	
	/* Calculate csr length */
	(* csr) = g_new0 (gchar, 1);	
	gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, (* csr), &csr_len);
	g_free (* csr);

	/* Save the private key to a PEM format */
	(* csr) = g_new0 (gchar, csr_len);	
	if (gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, (* csr), &csr_len) < 0) {
		return g_strdup_printf(_("Error exporting private key to PEM structure."));
	}

	gnutls_x509_crq_deinit (crq);

	return NULL;

}

gchar * tls_generate_certificate (CertCreationData * creation_data,
				  gchar *csr_pem,
				  gchar *ca_cert_pem,
				  gchar *ca_priv_key_pem,
				  gchar **certificate)
{
	gnutls_datum_t csr_pem_datum, ca_cert_pem_datum, ca_priv_key_pem_datum;
	gnutls_x509_crt_t crt;
	gnutls_x509_crq_t csr;
	gnutls_x509_crt_t ca_crt;
	gnutls_x509_privkey_t ca_pkey;

	gchar * serial;
	gint key_usage;
	guint certificate_len;

	TlsCert *ca_cert_data = tls_parse_cert_pem (ca_cert_pem);
	
	csr_pem_datum.data = (unsigned char *) csr_pem;
	csr_pem_datum.size = strlen(csr_pem);

	ca_cert_pem_datum.data = (unsigned char *) ca_cert_pem;
	ca_cert_pem_datum.size = strlen(ca_cert_pem);

	ca_priv_key_pem_datum.data = (unsigned char *) ca_priv_key_pem;
	ca_priv_key_pem_datum.size = strlen(ca_priv_key_pem);

	gnutls_x509_crq_init (&csr);
	gnutls_x509_crq_import (csr, &csr_pem_datum, GNUTLS_X509_FMT_PEM);

	gnutls_x509_crt_init (&ca_crt);
	gnutls_x509_crt_import (ca_crt, &ca_cert_pem_datum, GNUTLS_X509_FMT_PEM);

	gnutls_x509_privkey_init (&ca_pkey);
	gnutls_x509_privkey_import (ca_pkey, &ca_priv_key_pem_datum, GNUTLS_X509_FMT_PEM);
	
	if (gnutls_x509_crt_init (&crt) < 0) {
		return g_strdup_printf(_("Error when initializing crt structure"));
	}

	if (gnutls_x509_crt_set_crq (crt, csr) < 0) {
		return g_strdup_printf(_("Error when copying data from CSR to certificate structure"));
	}

	if (gnutls_x509_crt_set_version (crt, 3) < 0){
		return g_strdup_printf(_("Error when setting certificate version"));
	}
	
	serial = g_strdup_printf ("%llX", creation_data->serial);
	if (gnutls_x509_crt_set_serial (crt, serial, strlen (serial)) < 0) {
		return g_strdup_printf(_("Error when setting certificate serial number"));
	}
	g_free (serial);

	if (gnutls_x509_crt_set_activation_time (crt, creation_data->activation) < 0) {
		return g_strdup_printf(_("Error when setting activation time"));
	}

	if (gnutls_x509_crt_set_expiration_time (crt, creation_data->expiration) < 0) {
		return g_strdup_printf(_("Error when setting expiration time"));
	}

	if (ca_cert_data->c)
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_COUNTRY_NAME,
						      0, ca_cert_data->c, strlen(ca_cert_data->c));

	if (ca_cert_data->st)
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME,
						      0, ca_cert_data->st, strlen(ca_cert_data->st));

	if (ca_cert_data->l)
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_LOCALITY_NAME,
					       0, ca_cert_data->l, strlen(ca_cert_data->l));

	if (ca_cert_data->o) 
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_ORGANIZATION_NAME,
					       0, ca_cert_data->o, strlen(ca_cert_data->o));
	
	if (ca_cert_data->ou) 
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,
					       0, ca_cert_data->ou, strlen(ca_cert_data->ou));

	if (ca_cert_data->cn)
		gnutls_x509_crt_set_issuer_dn_by_oid (crt, GNUTLS_OID_X520_COMMON_NAME,
						      0, ca_cert_data->cn, strlen(ca_cert_data->cn));	

	
	if (gnutls_x509_crt_set_ca_status (crt, 0) != 0) {
			return g_strdup_printf(_("Error when setting basicConstraint extension"));
	}
	
	key_usage = 0;
	if (creation_data->digital_signature)
		key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE;
	if (creation_data->data_encipherment)
		key_usage |= GNUTLS_KEY_DATA_ENCIPHERMENT;
	if (creation_data->key_encipherment)
		key_usage |= GNUTLS_KEY_KEY_ENCIPHERMENT;
	if (creation_data->non_repudiation)
		key_usage |= GNUTLS_KEY_NON_REPUDIATION;
	if (creation_data->key_agreement)
		key_usage |= GNUTLS_KEY_KEY_AGREEMENT;


	if (gnutls_x509_crt_set_key_usage (crt, key_usage) != 0) {
		return g_strdup_printf(_("Error when setting keyUsage extension"));
	}

	if (creation_data->email_protection)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_EMAIL_PROTECTION, FALSE);

	if (creation_data->code_signing)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_CODE_SIGNING, FALSE);

	if (creation_data->web_client)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_TLS_WWW_CLIENT, FALSE);

	if (creation_data->web_server)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_TLS_WWW_SERVER, FALSE);

	if (creation_data->time_stamping)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_TIME_STAMPING, FALSE);

	if (creation_data->ocsp_signing)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_OCSP_SIGNING, FALSE);

	if (creation_data->any_purpose)
		gnutls_x509_crt_set_key_purpose_oid (crt, GNUTLS_KP_ANY, FALSE);


	if (gnutls_x509_crt_sign(crt, ca_crt, ca_pkey)) {
		return g_strdup_printf(_("Error when signing certificate"));
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

	return NULL;
}




TlsCert * tls_parse_cert_pem (const char * pem_certificate)
{
	gnutls_datum_t pem_datum;
	gnutls_x509_crt_t * cert = g_new0 (gnutls_x509_crt_t, 1);
	gchar *aux = NULL;
	guchar *uaux = NULL;
	guint key_usage;
	gint i;
	guint critical;
	
	guint size;

	TlsCert *res = g_new0 (TlsCert, 1);

	pem_datum.data = (unsigned char *) pem_certificate;
	pem_datum.size = strlen(pem_certificate);

	gnutls_x509_crt_init (cert);
	gnutls_x509_crt_import (*cert, &pem_datum, GNUTLS_X509_FMT_PEM);

	res->activation_time = gnutls_x509_crt_get_activation_time (*cert);
	res->expiration_time = gnutls_x509_crt_get_expiration_time (*cert);

	
	size = 0;
	gnutls_x509_crt_get_serial (*cert, NULL, &size);
	if (size) {
		aux = g_new0 (gchar, size);
		gnutls_x509_crt_get_serial (*cert, aux, &size);
		res->serial_number = strtoull (aux, NULL, 16);
		g_free(aux);
		aux = NULL;
	}
	

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		res->cn = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
		res->o = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
		res->ou = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		res->i_cn = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
		res->i_o = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
		res->i_ou = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
		res->c = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
		res->st = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
		res->l = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_MD5, uaux, &size);
	uaux = g_new0(guchar, size);
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_MD5, uaux, &size);
	res->md5 = g_new0(gchar, size*3);
	for (i=0; i<size; i++) {
		snprintf (&res->md5[i*3], 3, "%02X", uaux[i]);
		if (i != size - 1)
			res->md5[(i*3) + 2] = ':';
	}
	g_free (uaux);
	uaux = NULL;

	size = 0;
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_SHA1, uaux, &size);
	uaux = g_new0(guchar, size);
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_SHA1, uaux, &size);
	res->sha1 = g_new0(gchar, size*3);
	for (i=0; i<size; i++) {
		snprintf (&res->sha1[i*3], 3, "%02X", uaux[i]);
		if (i != size - 1)
			res->sha1[(i*3) + 2] = ':';
	}
	g_free (uaux);
	uaux = NULL;

	if (gnutls_x509_crt_get_ca_status (*cert, &critical)) {
		res->uses = g_list_append (res->uses, _("Certification Authority"));
	}

	if (gnutls_x509_crt_get_key_usage (*cert, &key_usage, &critical) >= 0) {
		if (key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE)
			res->uses = g_list_append (res->uses, _("Digital signature"));
		if (key_usage & GNUTLS_KEY_NON_REPUDIATION)
			res->uses = g_list_append (res->uses, _("Non repudiation"));
		if (key_usage & GNUTLS_KEY_KEY_ENCIPHERMENT)
			res->uses = g_list_append (res->uses, _("Key encipherment"));
		if (key_usage & GNUTLS_KEY_DATA_ENCIPHERMENT)
			res->uses = g_list_append (res->uses, _("Data encipherment"));
		if (key_usage & GNUTLS_KEY_KEY_AGREEMENT)
			res->uses = g_list_append (res->uses, _("Key agreement"));
		if (key_usage & GNUTLS_KEY_KEY_CERT_SIGN)
			res->uses = g_list_append (res->uses, _("Certificate signing"));
		if (key_usage & GNUTLS_KEY_CRL_SIGN)
			res->uses = g_list_append (res->uses, _("CRL signing"));
		if (key_usage & GNUTLS_KEY_ENCIPHER_ONLY)
			res->uses = g_list_append (res->uses, _("Key encipher only"));
		if (key_usage & GNUTLS_KEY_DECIPHER_ONLY)
			res->uses = g_list_append (res->uses, _("Key decipher only"));
	}


	i = 0;
	size = 0;
	while (gnutls_x509_crt_get_key_purpose_oid (*cert, i, aux, &size, &critical) >= 0) {
		uaux = g_new0(guchar, size);
		gnutls_x509_crt_get_key_purpose_oid (*cert, i, aux, &size, &critical);
		if (strcasecmp (aux, GNUTLS_KP_TLS_WWW_SERVER) == 0)
			res->uses = g_list_append (res->uses, _("TLS WWW Server"));
		else if (strcasecmp (aux, GNUTLS_KP_TLS_WWW_CLIENT) == 0)
			res->uses = g_list_append (res->uses, _("TLS WWW Client."));
		else if (strcasecmp (aux, GNUTLS_KP_CODE_SIGNING) == 0)
			res->uses = g_list_append (res->uses, _("Code signing"));
		else if (strcasecmp (aux, GNUTLS_KP_EMAIL_PROTECTION) == 0)
			res->uses = g_list_append (res->uses, _("Email protection"));
		else if (strcasecmp (aux, GNUTLS_KP_TIME_STAMPING) == 0)
			res->uses = g_list_append (res->uses, _("Time stamping"));
		else if (strcasecmp (aux, GNUTLS_KP_OCSP_SIGNING) == 0)
			res->uses = g_list_append (res->uses, _("OCSP signing"));
		else if (strcasecmp (aux, GNUTLS_KP_ANY) == 0)
			res->uses = g_list_append (res->uses, _("Any purpose"));
		g_free (uaux);
		size = 0;
		i++;

	}		

	gnutls_x509_crt_deinit (*cert);
	g_free (cert);

	return res;	
	
}

void tls_cert_free (TlsCert *tlscert)
{
	if (tlscert->cn) {
		g_free (tlscert->cn);
	}	
	if (tlscert->o) {
		g_free (tlscert->o);
	}	
	if (tlscert->ou) {
		g_free (tlscert->ou);
	}	
	if (tlscert->c) {
		g_free (tlscert->c);
	}	
	if (tlscert->st) {
		g_free (tlscert->st);
	}	
	if (tlscert->l) {
		g_free (tlscert->l);
	}	

	if (tlscert->i_cn) {
		g_free (tlscert->i_cn);
	}	
	if (tlscert->i_o) {
		g_free (tlscert->i_o);
	}	
	if (tlscert->i_ou) {
		g_free (tlscert->i_ou);
	}	
	if (tlscert->i_c) {
		g_free (tlscert->i_c);
	}	
	if (tlscert->i_st) {
		g_free (tlscert->i_st);
	}	
	if (tlscert->i_l) {
		g_free (tlscert->i_l);
	}	

	if (tlscert->sha1) {
		g_free (tlscert->sha1);
	}	
	if (tlscert->md5) {
		g_free (tlscert->md5);
	}	

	g_free (tlscert);
}


TlsCsr * tls_parse_csr_pem (const char * pem_csr)
{
	gnutls_datum_t pem_datum;
	gnutls_x509_crq_t * csr = g_new0 (gnutls_x509_crq_t, 1);
	gchar *aux = NULL;
	
	guint size;

	TlsCsr *res = g_new0 (TlsCsr, 1);

	pem_datum.data = (unsigned char *) pem_csr;
	pem_datum.size = strlen(pem_csr);

	gnutls_x509_crq_init (csr);
	gnutls_x509_crq_import (*csr, &pem_datum, GNUTLS_X509_FMT_PEM);

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		res->cn = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
		res->o = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
		res->ou = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
		res->c = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
		res->st = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
		res->l = strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	gnutls_x509_crq_deinit (*csr);
	g_free (csr);

	return res;	
	
}


void tls_csr_free (TlsCsr *tlscsr)
{
	if (tlscsr->cn) {
		g_free (tlscsr->cn);
	}	
	if (tlscsr->o) {
		g_free (tlscsr->o);
	}	
	if (tlscsr->ou) {
		g_free (tlscsr->ou);
	}	

	if (tlscsr->c) {
		g_free (tlscsr->c);
	}	
	if (tlscsr->st) {
		g_free (tlscsr->st);
	}	
	if (tlscsr->l) {
		g_free (tlscsr->l);
	}	

	g_free (tlscsr);
}

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

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include "uint160.h"
#include "tls.h"

void tls_init ()
{
	gnutls_global_init ();

}

gchar * tls_generate_rsa_keys (TlsCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key)
{

	size_t private_key_len = 0;
        gint error;

	(*key) = g_new0 (gnutls_x509_privkey_t, 1);
	if (gnutls_x509_privkey_init (*key) < 0) {
		return g_strdup_printf(_("Error initializing private key structure."));
	}

	/* Generate a RSA private key. */
        error = gnutls_x509_privkey_generate ((** key), GNUTLS_PK_RSA, creation_data->key_bitlength, 0);
	if (error < 0) {
		return g_strdup_printf(_("Error creating private key: %d"), error);
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

gchar * tls_generate_dsa_keys (TlsCreationData *creation_data,
			       gchar ** private_key,
			       gnutls_x509_privkey_t **key)
{

	size_t private_key_len = 0;
        gint error;

	(*key) = g_new0 (gnutls_x509_privkey_t, 1);
	if (gnutls_x509_privkey_init (*key) < 0) {
		return g_strdup_printf(_("Error initializing private key structure."));
	}

	/* Generate DSA private key. */
        error = gnutls_x509_privkey_generate ((** key), GNUTLS_PK_DSA, creation_data->key_bitlength, 0);
	if (error < 0) {
		return g_strdup_printf(_("Error creating private key: %d"), error);
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
	size_t pkcs8_private_key_len = 0;
	gnutls_x509_privkey_t key;

	pem_datum.data = (unsigned char *) pem_private_key;
	pem_datum.size = strlen(pem_private_key);

	if (gnutls_x509_privkey_init (&key) < 0) {
		return NULL;
	}

	/* Import PEM private key into internal structure. */
	if (gnutls_x509_privkey_import (key, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
		gnutls_x509_privkey_deinit (key);
		return NULL;
	}

	/* Calculate pkcs8 length */
	pkcs8_private_key = g_new0 (gchar, 1);
	gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_PEM, passphrase, GNUTLS_PKCS_USE_PKCS12_3DES, pkcs8_private_key, &pkcs8_private_key_len);
	g_free (pkcs8_private_key);

	/* Save the private key to a PEM format */
	pkcs8_private_key = g_new0 (gchar, pkcs8_private_key_len);	
	if (gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_PEM, passphrase, GNUTLS_PKCS_USE_PKCS12_3DES, pkcs8_private_key, &pkcs8_private_key_len) < 0) {
		gnutls_x509_privkey_deinit (key);
		return NULL;
	}

	gnutls_x509_privkey_deinit (key);

	return pkcs8_private_key;
}

gchar * tls_load_pkcs8_private_key (gchar *pkcs8_pem, gchar *passphrase, const gchar *cert_key_id, gint *error)
{
	gnutls_datum_t pkcs8_datum;
	gchar * pem_private_key = NULL;
	size_t pem_private_key_len = 0;
	gnutls_x509_privkey_t key;
	gchar * pkey_key_id = NULL;
	size_t pkey_key_id_len = 0;
	guchar * uaux;
	guint i;

	pkcs8_datum.data = (unsigned char *) pkcs8_pem;
	pkcs8_datum.size = strlen (pkcs8_pem);

	if (gnutls_x509_privkey_init (&key) < 0) {
		return NULL;
	}

	*error = gnutls_x509_privkey_import_pkcs8 (key, &pkcs8_datum, GNUTLS_X509_FMT_PEM, passphrase, 0);
	if (*error) {
		gnutls_x509_privkey_deinit (key);
		return NULL;
	}
		
	/* Calculate private key length */
	pem_private_key = g_new0 (gchar, 1);	
	gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, pem_private_key, &pem_private_key_len);
	g_free (pem_private_key);

	/* Save the private key to a PEM format */
	pem_private_key = g_new0 (gchar, pem_private_key_len);	
	if (gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, pem_private_key, &pem_private_key_len) < 0) {
		g_free (pem_private_key);
		gnutls_x509_privkey_deinit (key);
		return NULL;
	}

	uaux = NULL;
	pkey_key_id_len = 0;
	gnutls_x509_privkey_get_key_id (key, 0, uaux, &pkey_key_id_len);
	uaux = g_new0(guchar, pkey_key_id_len);
	if (gnutls_x509_privkey_get_key_id (key, 0, uaux, &pkey_key_id_len)) {
		g_free (uaux);
		g_free (pem_private_key);
		gnutls_x509_privkey_deinit (key);
		return NULL;
	}
	pkey_key_id = g_new0(gchar, pkey_key_id_len*3);
	for (i=0; i<pkey_key_id_len; i++) {
		snprintf (&pkey_key_id[i*3], 3, "%02X", uaux[i]);
		if (i != pkey_key_id_len - 1)
			pkey_key_id[(i*3) + 2] = ':';
	}
	g_free (uaux);

	if (strcmp (pkey_key_id, cert_key_id)) {
		// The private key's key_id doesn't match with the certificate's key_id
		g_free (pkey_key_id);
		g_free (pem_private_key);
		gnutls_x509_privkey_deinit (key);
		*error = TLS_NON_MATCHING_PRIVATE_KEY;
		return NULL;
	}

	g_free (pkey_key_id);
	gnutls_x509_privkey_deinit (key);
	*error = 0;

	return pem_private_key;

}


gnutls_datum_t * tls_generate_pkcs12 (gchar *pem_cert, gchar *pem_private_key, gchar *passphrase)
{
        gnutls_datum_t pem_datum, cert_datum, pkcs8_pkey_datum, key_id_datum;
        gnutls_datum_t * pkcs12_datum; 
	gchar *pkcs8_private_key = NULL;
	size_t pkcs8_private_key_len = 0;
        gchar *cert_der = NULL;
        size_t cert_der_len = 0;
        guchar* key_id = NULL;
        size_t key_id_size = 0;
	gnutls_x509_privkey_t key;
        gnutls_x509_crt_t crt;
        gnutls_pkcs12_t pkcs12;
        gnutls_pkcs12_bag_t bag, key_bag;

        gchar *friendly_name;
        size_t friendly_name_size = 0;
        
        gint ret, bag_index;
        gchar *pkcs12_struct = NULL;
        size_t pkcs12_struct_size = 0;


        /* First of all, we need to generate a PKCS8 structure holding the private key */

	pem_datum.data = (unsigned char *) pem_private_key;
	pem_datum.size = strlen(pem_private_key);

	if (gnutls_x509_privkey_init (&key) < 0) {
		return NULL;
	}

        if (gnutls_x509_crt_init (&crt) < 0) {
                return NULL;
        }

	/* Import PEM private key into internal structure. */
	if (gnutls_x509_privkey_import (key, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
		gnutls_x509_privkey_deinit (key);
		gnutls_x509_crt_deinit (crt);
		return NULL;
	}

	/* Calculate pkcs8 length */
	pkcs8_private_key = g_new0 (gchar, 1);
	gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_DER, passphrase, GNUTLS_PKCS_USE_PKCS12_3DES, pkcs8_private_key, &pkcs8_private_key_len);
	g_free (pkcs8_private_key);

	/* Save the private key to a DER format */
	pkcs8_private_key = g_new0 (gchar, pkcs8_private_key_len);	
	if (gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_DER, passphrase, GNUTLS_PKCS_USE_PKCS12_3DES, pkcs8_private_key, &pkcs8_private_key_len) < 0) {
		gnutls_x509_privkey_deinit (key);
		gnutls_x509_crt_deinit (crt);
		return NULL;
	}

        pkcs8_pkey_datum.data = (unsigned char *) pkcs8_private_key;
        pkcs8_pkey_datum.size = pkcs8_private_key_len;

        /* Now, we convert the given PEM certificate into DER format */
        pem_datum.data = (unsigned char *) pem_cert;
        pem_datum.size = strlen(pem_cert);

	/* Import PEM certificate into internal structure. */
	if (gnutls_x509_crt_import (crt, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
		gnutls_x509_privkey_deinit (key);
		gnutls_x509_crt_deinit (crt);
		return NULL;
	}

	/* Calculate DER cert length */
	cert_der = g_new0 (gchar, 1);
	gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len);
	g_free (cert_der);

	/* Save the private key to a DER format */
	cert_der = g_new0 (gchar, cert_der_len);	
	if (gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_DER, cert_der, &cert_der_len) < 0) {
		gnutls_x509_privkey_deinit (key);
		gnutls_x509_crt_deinit (crt);
		return NULL;
	}
        cert_datum.data = (unsigned char *) cert_der;
        cert_datum.size = cert_der_len;

  
        /* We obtain a unique ID, from the key_id from the certificate private key.
         */
        key_id = g_new0 (guchar, 1);
        gnutls_x509_privkey_get_key_id(key, 0, key_id, &key_id_size);
        g_free (key_id);

        key_id = g_new0 (guchar, key_id_size);
        if (gnutls_x509_privkey_get_key_id(key, 0, key_id, &key_id_size) < 0) {
                gnutls_x509_privkey_deinit (key);
                gnutls_x509_crt_deinit (crt);
                return NULL;
        }

        key_id_datum.data = (unsigned char *) key_id;
        key_id_datum.size = key_id_size;


        /* We create two helper bags, which hold the certificate,
         * and the (encrypted) key.
         */

        gnutls_pkcs12_bag_init (&bag);
        gnutls_pkcs12_bag_init (&key_bag);

        ret = gnutls_pkcs12_bag_set_data (bag, GNUTLS_BAG_CERTIFICATE, &cert_datum);
        if (ret < 0) {
                gnutls_x509_privkey_deinit (key);
                gnutls_x509_crt_deinit (crt);

                return NULL;
        }

        /* ret now holds the bag's index.
         */
        bag_index = ret;

        /* Associate a friendly name with the given certificate. Used
         * by browsers.
         */
        friendly_name = g_new0 (gchar, 1);
        gnutls_x509_crt_get_dn (crt, friendly_name, &friendly_name_size);
        g_free (friendly_name);

        friendly_name = g_new0 (gchar, friendly_name_size);
        gnutls_x509_crt_get_dn (crt, friendly_name, &friendly_name_size);
        
        gnutls_pkcs12_bag_set_friendly_name (bag, bag_index, friendly_name);


        gnutls_x509_privkey_deinit (key);
        gnutls_x509_crt_deinit (crt);


        /* Associate the certificate with the key using a unique key
         * ID.
         */
        gnutls_pkcs12_bag_set_key_id (bag, bag_index, &key_id_datum);

        /* use weak encryption for the certificate. 
         */
        gnutls_pkcs12_bag_encrypt (bag, passphrase, GNUTLS_PKCS_USE_PKCS12_RC2_40);

        /* Now the key.
         */

        ret = gnutls_pkcs12_bag_set_data (key_bag,
                                          GNUTLS_BAG_PKCS8_ENCRYPTED_KEY,
                                          &pkcs8_pkey_datum);
        if (ret < 0) {
            return NULL;
        }

        /* Note that since the PKCS #8 key is already encrypted we don't
         * bother encrypting that bag.
         */
        bag_index = ret;

        gnutls_pkcs12_bag_set_friendly_name (key_bag, bag_index, friendly_name);

        gnutls_pkcs12_bag_set_key_id (key_bag, bag_index, &key_id_datum);


        /* The bags were filled. Now create the PKCS #12 structure.
         */
        gnutls_pkcs12_init (&pkcs12);

        /* Insert the two bags in the PKCS #12 structure.
         */

        gnutls_pkcs12_set_bag (pkcs12, bag);
        gnutls_pkcs12_set_bag (pkcs12, key_bag);


        /* Generate a message authentication code for the PKCS #12
         * structure.
         */
        gnutls_pkcs12_generate_mac (pkcs12, passphrase);

        pkcs12_struct = g_new0 (gchar, 1);
        ret = gnutls_pkcs12_export (pkcs12, GNUTLS_X509_FMT_DER, pkcs12_struct,
                                    &pkcs12_struct_size);
        g_free (pkcs12_struct);

        pkcs12_struct = g_new0 (gchar, pkcs12_struct_size);
        ret = gnutls_pkcs12_export (pkcs12, GNUTLS_X509_FMT_DER, pkcs12_struct,
                                    &pkcs12_struct_size);        

        gnutls_pkcs12_bag_deinit (bag);
        gnutls_pkcs12_bag_deinit (key_bag);
        gnutls_pkcs12_deinit (pkcs12);

        pkcs12_datum = g_new0 (gnutls_datum_t, 1);
        pkcs12_datum->data = (unsigned char *) pkcs12_struct;
        pkcs12_datum->size = pkcs12_struct_size;

        return pkcs12_datum;
}


gchar * tls_generate_self_signed_certificate (TlsCreationData * creation_data, 
					      gnutls_x509_privkey_t *key,
					      gchar ** certificate)
{
	gnutls_x509_crt_t crt;
        UInt160 *sn = uint160_new();
	guchar * keyid = NULL;
	size_t keyidsize = 0;
	guchar * serialstr = NULL;
	size_t serialsize = 0;
	size_t certificate_len = 0;

	uint160_assign (sn, G_GUINT64_CONSTANT(1));

	if (gnutls_x509_crt_init (&crt) < 0) {
                uint160_free (sn);
		return g_strdup_printf(_("Error when initializing certificate structure"));
	}

	if (gnutls_x509_crt_set_version (crt, 3) < 0){
		gnutls_x509_crt_deinit (crt);
                uint160_free (sn);
		return g_strdup_printf(_("Error when setting certificate version"));
	}
	
        uint160_write (sn, NULL, &serialsize);
        serialstr = g_new0 (guchar, serialsize);
        uint160_write (sn, serialstr, &serialsize);

	if (gnutls_x509_crt_set_serial (crt, serialstr, serialsize) < 0) {
		gnutls_x509_crt_deinit (crt);
                uint160_free (sn);
		return g_strdup_printf(_("Error when setting certificate serial number"));
	}

        g_free (serialstr);

        uint160_free (sn);

	if (gnutls_x509_crt_set_activation_time (crt, creation_data->activation) < 0) {
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error when setting activation time"));
	}

	if (gnutls_x509_crt_set_expiration_time (crt, creation_data->expiration) < 0) {
		gnutls_x509_crt_deinit (crt);
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
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error when setting basicConstraint extension"));
	}
	
	if (gnutls_x509_crt_set_key_usage (crt, GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN) != 0) {
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error when setting keyUsage extension"));
	}

	if (creation_data->crl_distribution_point) {
		gnutls_x509_crt_set_crl_dist_points (crt, GNUTLS_SAN_URI, creation_data->crl_distribution_point, 0);
	}

	keyid = g_new0 (guchar,1);	
	gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
	g_free (keyid);

	keyid = g_new0 (guchar,keyidsize);
	gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
	if (gnutls_x509_crt_set_subject_key_id(crt, keyid, keyidsize) !=0) {
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error when setting subject key identifier extension"));
	}
	if (gnutls_x509_crt_set_authority_key_id(crt, keyid, keyidsize) !=0) {
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error when setting authority key identifier extension"));
	}
       

	// __add_ext (certificate, NID_netscape_cert_type, "sslCA");
	//
	//__add_ext (certificate, NID_netscape_comment, "gnoMint Generated Certificate");

	if (gnutls_x509_crt_sign2(crt, crt, (* key), GNUTLS_DIG_SHA512, 0)) {
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error when signing self-signed certificate"));
	}
	
	/* Calculate certificate length */
	(* certificate) = g_new0 (gchar, 1);	
	gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, (* certificate), &certificate_len);
	g_free (* certificate);

	/* Save the private key to a PEM format */
	(* certificate) = g_new0 (gchar, certificate_len);	
	if (gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, (* certificate), &certificate_len) < 0) {
		gnutls_x509_crt_deinit (crt);
		return g_strdup_printf(_("Error exporting private key to PEM structure."));
	}

	gnutls_x509_crt_deinit (crt);

	return NULL;

}


gchar * tls_generate_csr (TlsCreationData * creation_data, 
			  gnutls_x509_privkey_t *key,
			  gchar ** csr)
{
	gnutls_x509_crq_t crq;
	size_t csr_len = 0;

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
	

	if (gnutls_x509_crq_sign2(crq, (* key), GNUTLS_DIG_SHA512, 0)) {
		return g_strdup_printf(_("Error when signing self-signed csr"));
	}
	
	/* Calculate csr length */
	(* csr) = g_new0 (gchar, 1);	
	gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, (* csr), &csr_len);
	g_free (* csr);

	/* Save the private key to a PEM format */
	(* csr) = g_new0 (gchar, csr_len);	
	if (gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, (* csr), &csr_len) < 0) {
		return g_strdup_printf(_("Error exporting CSR to PEM structure."));
	}

	gnutls_x509_crq_deinit (crq);

	return NULL;

}

gchar * tls_generate_certificate (TlsCertCreationData * creation_data,
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
	guchar * serialstr = NULL;
        guchar * keyid = NULL;
        guchar * ca_keyid = NULL;
        size_t keyidsize = 0;
        size_t ca_keyidsize = 0;
	size_t serialsize = 0;

	gint key_usage;
	size_t certificate_len = 0;

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
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when initializing crt structure"));
	}

	if (gnutls_x509_crt_set_crq (crt, csr) < 0) {
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when copying data from CSR to certificate structure"));
	}

	if (gnutls_x509_crt_set_version (crt, 3) < 0){
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when setting certificate version"));
	}
	
        uint160_write (&creation_data->serial, NULL, &serialsize);
        serialstr = g_new0 (guchar, serialsize);
        uint160_write (&creation_data->serial, serialstr, &serialsize);

	if (gnutls_x509_crt_set_serial (crt, serialstr, serialsize) < 0) {
		g_free (serialstr);
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when setting certificate serial number"));
	}
	g_free (serialstr);

	if (gnutls_x509_crt_set_activation_time (crt, creation_data->activation) < 0) {
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when setting activation time"));
	}

	if (gnutls_x509_crt_set_expiration_time (crt, creation_data->expiration) < 0) {
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
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

	
        ca_keyid = g_new0 (guchar,1);	
        gnutls_x509_crt_get_subject_key_id(ca_crt, ca_keyid, &ca_keyidsize, NULL);
        g_free (ca_keyid);        
        if (ca_keyidsize) {
                ca_keyid = g_new0 (guchar,ca_keyidsize);
                gnutls_x509_crt_get_subject_key_id(ca_crt, ca_keyid, &ca_keyidsize, NULL);
                if (gnutls_x509_crt_set_authority_key_id(crt, ca_keyid, ca_keyidsize) !=0) {
                        gnutls_x509_crq_deinit (csr);
                        gnutls_x509_crt_deinit (crt);
                        gnutls_x509_crt_deinit (ca_crt);
                        gnutls_x509_privkey_deinit (ca_pkey);
                        return g_strdup_printf(_("Error when setting authority key identifier extension"));
                }
        }


	if (gnutls_x509_crt_set_ca_status (crt, creation_data->ca) != 0) {
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when setting basicConstraint extension"));
	}
	

        if (creation_data->ca) {
                keyid = g_new0 (guchar,1);	
                gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
                g_free (keyid);
                
                keyid = g_new0 (guchar,keyidsize);
                gnutls_x509_crt_get_key_id(crt, 0, keyid, &keyidsize);
                if (gnutls_x509_crt_set_subject_key_id(crt, keyid, keyidsize) !=0) {
                        gnutls_x509_crq_deinit (csr);
                        gnutls_x509_crt_deinit (crt);
                        gnutls_x509_crt_deinit (ca_crt);
                        gnutls_x509_privkey_deinit (ca_pkey);
                        return g_strdup_printf(_("Error when setting subject key identifier extension"));
                }
        }       
        
	key_usage = 0;
	if (creation_data->ca)
		key_usage |= GNUTLS_KEY_KEY_CERT_SIGN;
	if (creation_data->crl_signing)
		key_usage |= GNUTLS_KEY_CRL_SIGN;
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
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
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


	if (creation_data->crl_distribution_point && creation_data->crl_distribution_point[0])
		gnutls_x509_crt_set_crl_dist_points (crt, GNUTLS_SAN_URI, creation_data->crl_distribution_point, 0);
	else
		gnutls_x509_crt_cpy_crl_dist_points (crt, ca_crt);
		

	if (gnutls_x509_crt_sign2(crt, ca_crt, ca_pkey, GNUTLS_DIG_SHA512, 0)) {
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error when signing certificate"));
	}
	
	/* Calculate certificate length */
	(* certificate) = g_new0 (gchar, 1);	
	gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, (* certificate), &certificate_len);
	g_free (* certificate);

	/* Save the private key to a PEM format */
	(* certificate) = g_new0 (gchar, certificate_len);	
	if (gnutls_x509_crt_export (crt, GNUTLS_X509_FMT_PEM, (* certificate), &certificate_len) < 0) {
		gnutls_x509_crq_deinit (csr);
		gnutls_x509_crt_deinit (crt);
		gnutls_x509_crt_deinit (ca_crt);
		gnutls_x509_privkey_deinit (ca_pkey);
		return g_strdup_printf(_("Error exporting private key to PEM structure."));
	}	

	gnutls_x509_crq_deinit (csr);
	gnutls_x509_crt_deinit (crt);
	gnutls_x509_crt_deinit (ca_crt);
	gnutls_x509_privkey_deinit (ca_pkey);
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
	guint aux_uint;
	
	size_t size;

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
		uaux = g_new0 (guchar, size);
		gnutls_x509_crt_get_serial (*cert, uaux, &size);
                uint160_read (&res->serial_number, uaux, size);
		g_free(uaux);
		uaux = NULL;
	}
	

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		res->cn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
		res->o = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
		res->ou = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}


	size = 0;
	gnutls_x509_crt_get_dn (*cert, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn (*cert, aux, &size);
		res->dn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		res->i_cn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
		res->i_o = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn_by_oid (*cert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
		res->i_ou = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_issuer_dn (*cert, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_issuer_dn (*cert, aux, &size);
		res->i_dn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
		res->c = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
		res->st = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_get_dn_by_oid (*cert, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
		res->l = g_strdup (aux);
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

	size = 0;
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_SHA256, uaux, &size);
	uaux = g_new0(guchar, size);
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_SHA256, uaux, &size);
	res->sha256 = g_new0(gchar, size*3);
	for (i=0; i<size; i++) {
		snprintf (&res->sha256[i*3], 3, "%02X", uaux[i]);
		if (i != size - 1)
			res->sha256[(i*3) + 2] = ':';
	}
	g_free (uaux);
	uaux = NULL;

	size = 0;
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_SHA512, uaux, &size);
	uaux = g_new0(guchar, size);
	gnutls_x509_crt_get_fingerprint (*cert, GNUTLS_DIG_SHA512, uaux, &size);
	res->sha512 = g_new0(gchar, size*3);
	for (i=0; i<size; i++) {
		snprintf (&res->sha512[i*3], 3, "%02X", uaux[i]);
		if (i != size - 1)
			res->sha512[(i*3) + 2] = ':';
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

	size = 0;
	gnutls_x509_crt_get_key_id (*cert, 0, uaux, &size);
	uaux = g_new0(guchar, size);
	gnutls_x509_crt_get_key_id (*cert, 0, uaux, &size);
	res->key_id = g_new0(gchar, size*3);
	for (i=0; i<size; i++) {
		snprintf (&res->key_id[i*3], 3, "%02X", uaux[i]);
		if (i != size - 1)
			res->key_id[(i*3) + 2] = ':';
	}
	g_free (uaux);
	uaux = NULL;

	size = 0;
	gnutls_x509_crt_get_crl_dist_points (*cert, 0, aux, &size, &aux_uint, &critical);
	if (size) {
		aux = g_new0(gchar, size);
		if (gnutls_x509_crt_get_crl_dist_points (*cert, 0, aux, &size, &aux_uint, &critical) == GNUTLS_SAN_URI &&
		    aux_uint == 0)
			res->crl_distribution_point = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}


	size = 0;
	gnutls_x509_crt_get_subject_key_id (*cert, uaux, &size, NULL);
        uaux = g_new0(guchar, size);
        gnutls_x509_crt_get_subject_key_id (*cert, uaux, &size, NULL);
        res->subject_key_id = g_new0(gchar, size*3);
        for (i=0; i<size; i++) {
                snprintf (&res->subject_key_id[i*3], 3, "%02X", uaux[i]);
                if (i != size - 1)
                        res->subject_key_id[(i*3) + 2] = ':';
        }
        g_free (uaux);
        uaux = NULL;

        size = 0;
        gnutls_x509_crt_get_authority_key_id (*cert, uaux, &size, NULL);
        uaux = g_new0(guchar, size);
        gnutls_x509_crt_get_authority_key_id (*cert, uaux, &size, NULL);
        res->issuer_key_id = g_new0(gchar, size*3);
        for (i=0; i<size; i++) {
                snprintf (&res->issuer_key_id[i*3], 3, "%02X", uaux[i]);
                if (i != size - 1)
                        res->issuer_key_id[(i*3) + 2] = ':';
        }
        g_free (uaux);
        uaux = NULL;

	gnutls_x509_crt_deinit (*cert);
	g_free (cert);

	return res;	
	
}

gboolean tls_is_ca_pem (const char * pem_certificate)
{
	gnutls_datum_t pem_datum;
	gnutls_x509_crt_t * cert = g_new0 (gnutls_x509_crt_t, 1);

	guint critical;

	gboolean res = FALSE;

	pem_datum.data = (unsigned char *) pem_certificate;
	pem_datum.size = strlen(pem_certificate);

	gnutls_x509_crt_init (cert);
	gnutls_x509_crt_import (*cert, &pem_datum, GNUTLS_X509_FMT_PEM);

	if (gnutls_x509_crt_get_ca_status (*cert, &critical)) {
		res = TRUE;
	}


	gnutls_x509_crt_deinit (*cert);
	g_free (cert);

	return res;
}



void tls_cert_free (TlsCert *tlscert)
{
	g_free (tlscert->cn);
	g_free (tlscert->o);
	g_free (tlscert->ou);
	g_free (tlscert->c);
	g_free (tlscert->st);
	g_free (tlscert->l);
	g_free (tlscert->dn);
	g_free (tlscert->i_cn);
	g_free (tlscert->i_o);
	g_free (tlscert->i_ou);
	g_free (tlscert->i_c);
	g_free (tlscert->i_st);
	g_free (tlscert->i_l);
	g_free (tlscert->i_dn);
	g_free (tlscert->sha1);
	g_free (tlscert->sha256);
	g_free (tlscert->sha512);
	g_free (tlscert->md5);
	g_free (tlscert->key_id);
        g_free (tlscert->crl_distribution_point);

	g_free (tlscert);
}


TlsCsr * tls_parse_csr_pem (const char * pem_csr)
{
	gnutls_datum_t pem_datum;
	gnutls_x509_crq_t * csr = g_new0 (gnutls_x509_crq_t, 1);
	gchar *aux = NULL;
#ifdef ADVANCED_GNUTLS
	guchar *uaux = NULL;
#endif

	size_t size;

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
		res->cn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, aux, &size);
		res->o = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, 0, aux, &size);
		res->ou = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_COUNTRY_NAME, 0, 0, aux, &size);
		res->c = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, 0, aux, &size);
		res->st = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*csr, GNUTLS_OID_X520_LOCALITY_NAME, 0, 0, aux, &size);
		res->l = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

	size = 0;
	gnutls_x509_crq_get_dn (*csr, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn (*csr, aux, &size);
		res->dn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}

#ifdef ADVANCED_GNUTLS
	size = 0;
	gnutls_x509_crq_get_key_id (*csr, 0, uaux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_key_id (*csr, 0, uaux, &size);
		res->key_id = g_strdup (aux);
		g_free (aux);
		uaux = NULL;
	}
#endif


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

	if (tlscsr->dn) {
		g_free (tlscsr->dn);
	}	

	if (tlscsr->key_id) {
		g_free (tlscsr->key_id);
	}

	g_free (tlscsr);
}

gchar * tls_generate_crl (GList * revoked_certs, 
                          guchar *ca_pem, 
                          guchar *ca_private_key,
                          gint crl_version,
                          time_t current_timestamp,
                          time_t next_crl_timestamp)
{
        gnutls_datum_t pem_datum;

        gnutls_x509_crl_t crl;
        gnutls_x509_crt_t rcrt;
        guchar *certificate_pem;
        time_t revocation;

        gnutls_x509_crt_t ca_crt;
        gnutls_x509_privkey_t ca_pkey;

        GList *cursor = NULL;

        gchar *result = NULL;
        size_t result_size = 0;
        
        gnutls_x509_crl_init (&crl);
        
        cursor = g_list_first (revoked_certs);
        
        while (cursor) {
                gnutls_datum_t pem_datum;

                certificate_pem = cursor->data;
                cursor = g_list_next (cursor);
                
                revocation = atol (cursor->data);
                cursor = g_list_next (cursor);

                gnutls_x509_crt_init (&rcrt);
                pem_datum.data = certificate_pem;
                pem_datum.size = strlen((gchar *) certificate_pem);
                
                if (gnutls_x509_crt_import (rcrt, &pem_datum, GNUTLS_X509_FMT_PEM)) {
                        return NULL;
                }
                                        
                if (gnutls_x509_crl_set_crt (crl, rcrt, revocation))
                        return NULL;

                gnutls_x509_crt_deinit (rcrt);
        }

        fprintf (stderr, "Number of certificates in CRL: %d\n", gnutls_x509_crl_get_crt_count (crl));
        
        if (gnutls_x509_crl_set_version (crl, 2)) {
		fprintf (stderr, "Error setting version\n");
                return NULL;
	}

        if (gnutls_x509_crl_set_this_update (crl, current_timestamp)) {
		fprintf (stderr, "Error setting this update\n");
                return NULL;
	}

	if (! next_crl_timestamp) {
		next_crl_timestamp = current_timestamp + 60*24;
	}

	if (gnutls_x509_crl_set_next_update (crl, next_crl_timestamp)) {
		fprintf (stderr, "Error setting next update\n");
		return NULL;
	}

        gnutls_x509_crt_init (&ca_crt);

        pem_datum.data = ca_pem;
        pem_datum.size = strlen((gchar *)ca_pem);
        
        if (gnutls_x509_crt_import (ca_crt, &pem_datum, GNUTLS_X509_FMT_PEM)) {
		fprintf (stderr, "Error importing ca_pem\n");
                return NULL;
        }

        gnutls_x509_privkey_init (&ca_pkey);

        pem_datum.data = ca_private_key;
        pem_datum.size = strlen((gchar *) ca_private_key);

        if (gnutls_x509_privkey_import (ca_pkey, &pem_datum, GNUTLS_X509_FMT_PEM)) {
		fprintf (stderr, "Error importing ca privkey\n");
                return NULL;
	}
        
        if (gnutls_x509_crl_sign2 (crl, ca_crt, ca_pkey, GNUTLS_DIG_SHA512, 0)) {
		fprintf (stderr, "Error signing CRL: %d\n", gnutls_x509_crl_sign2 (crl, ca_crt, ca_pkey, GNUTLS_DIG_SHA512, 0));
                return NULL;
        }

        gnutls_x509_privkey_deinit (ca_pkey);
        gnutls_x509_crt_deinit (ca_crt);

        result = g_new0 (gchar, 0);
        gnutls_x509_crl_export (crl, GNUTLS_X509_FMT_PEM, result, &result_size);
        g_free (result);

        result = g_new0 (gchar, result_size);
        if (gnutls_x509_crl_export (crl, GNUTLS_X509_FMT_PEM, result, &result_size)) {
		fprintf (stderr, "Error exporting CRL pem\n");
                return NULL;
	}
        
        return result;
}

gchar * tls_generate_dh_params (guint bits)
{
	gnutls_dh_params_t dh_params;
	size_t dh_params_pem_len = 0;
	guchar * result = NULL;
	gint ret;

	gnutls_dh_params_init (&dh_params);
	
	ret = gnutls_dh_params_generate2 (dh_params, bits);
	if (ret < 0)
	{
		fprintf (stderr, "Error generating parameters: %s\n",
			 gnutls_strerror (ret));
		return NULL;
	}
		
	result = g_new (guchar, 0);
	gnutls_dh_params_export_pkcs3 (dh_params, GNUTLS_X509_FMT_PEM, result, &dh_params_pem_len);
	g_free (result);

	result = g_new (guchar, dh_params_pem_len);
	if (gnutls_dh_params_export_pkcs3 (dh_params, GNUTLS_X509_FMT_PEM, result, &dh_params_pem_len)) {
		fprintf (stderr, "Error exporting DH params pem\n");
		return NULL;
	}
	
	return (gchar *) result;
}

gboolean tls_cert_check_issuer (const gchar *cert_pem, const gchar *ca_pem) 
{
	gnutls_datum_t pem_datum;
        gnutls_x509_crt_t crt;
        gnutls_x509_crt_t ca_crt;
        gboolean result = FALSE;

	if (gnutls_x509_crt_init (&crt) < 0) {
		return FALSE;
	}

        pem_datum.data = (unsigned char *) cert_pem;
        pem_datum.size = strlen(cert_pem);

	if (gnutls_x509_crt_import (crt, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
                gnutls_x509_crt_deinit (crt);
		return FALSE;
	}

	if (gnutls_x509_crt_init (&ca_crt) < 0) {
                gnutls_x509_crt_deinit (crt);
		return FALSE;
	}

        pem_datum.data = (unsigned char *) ca_pem;
        pem_datum.size = strlen(ca_pem);

	if (gnutls_x509_crt_import (ca_crt, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
                gnutls_x509_crt_deinit (crt);
                gnutls_x509_crt_deinit (ca_crt);
		return FALSE;
	}

        result = gnutls_x509_crt_check_issuer(crt, ca_crt);
        gnutls_x509_crt_deinit (crt);
        gnutls_x509_crt_deinit (ca_crt);

        return result;
}

gchar * tls_get_private_key_id (const gchar *privkey_pem)
{
	gnutls_datum_t pem_datum;
        gnutls_x509_privkey_t privkey;

	gchar * pkey_key_id = NULL;
        gsize pkey_key_id_len;
        guchar *uaux = NULL;

        guint i;
        
	if (gnutls_x509_privkey_init (&privkey) < 0) {
		return FALSE;
	}

        pem_datum.data = (unsigned char *) privkey_pem;
        pem_datum.size = strlen(privkey_pem);

	if (gnutls_x509_privkey_import (privkey, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
                gnutls_x509_privkey_deinit (privkey);
		return FALSE;
	}

	uaux = NULL;
	pkey_key_id_len = 0;
	gnutls_x509_privkey_get_key_id (privkey, 0, uaux, &pkey_key_id_len);
	uaux = g_new0(guchar, pkey_key_id_len);
	if (gnutls_x509_privkey_get_key_id (privkey, 0, uaux, &pkey_key_id_len)) {
		g_free (uaux);
		gnutls_x509_privkey_deinit (privkey);
		return NULL;
	}
	pkey_key_id = g_new0(gchar, pkey_key_id_len*3);
	for (i=0; i<pkey_key_id_len; i++) {
		snprintf (&pkey_key_id[i*3], 3, "%02X", uaux[i]);
		if (i != pkey_key_id_len - 1)
			pkey_key_id[(i*3) + 2] = ':';
	}
	g_free (uaux);

        return pkey_key_id;
        
}

gchar * tls_get_public_key_id (const gchar *certificate_pem)
{
	gnutls_datum_t pem_datum;
        gnutls_x509_crt_t crt;

	gchar * key_id = NULL;
        gsize key_id_len;
        guchar *uaux = NULL;
        
        guint i;

	if (gnutls_x509_crt_init (&crt) < 0) {
		return FALSE;
	}

        pem_datum.data = (unsigned char *) certificate_pem;
        pem_datum.size = strlen(certificate_pem);

	if (gnutls_x509_crt_import (crt, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
                gnutls_x509_crt_deinit (crt);
		return FALSE;
	}

	uaux = NULL;
	key_id_len = 0;
	gnutls_x509_crt_get_key_id (crt, 0, uaux, &key_id_len);
	uaux = g_new0(guchar, key_id_len);
	if (gnutls_x509_crt_get_key_id (crt, 0, uaux, &key_id_len)) {
		g_free (uaux);
		gnutls_x509_crt_deinit (crt);
		return NULL;
	}
	key_id = g_new0(gchar, key_id_len*3);
	for (i=0; i<key_id_len; i++) {
		snprintf (&key_id[i*3], 3, "%02X", uaux[i]);
		if (i != key_id_len - 1)
			key_id[(i*3) + 2] = ':';
	}
	g_free (uaux);

        return key_id;
        

}

void tls_creation_data_free (TlsCreationData *cd)
{
	if (cd->country)
		g_free (cd->country);
	if (cd->state)
		g_free (cd->state);
	if (cd->city)
		g_free (cd->city);
	if (cd->org)
		g_free (cd->org);
	if (cd->ou)
		g_free (cd->ou);
	if (cd->cn)
		g_free (cd->cn);
	if (cd->emailAddress)
		g_free (cd->emailAddress);
	if (cd->password)
		g_free (cd->password);
        if (cd->crl_distribution_point)
                g_free (cd->crl_distribution_point);
        if (cd->parent_ca_id_str)
                g_free (cd->parent_ca_id_str);
	if (cd->crl_distribution_point)
		g_free (cd->crl_distribution_point);

	g_free (cd);
}


#ifdef ADVANCED_GNUTLS

gchar * tls_get_csr_public_key_id (const gchar *csr_pem)
{
	gnutls_datum_t pem_datum;
        gnutls_x509_crq_t crq;

	gchar * key_id = NULL;
        gsize key_id_len;
        guchar *uaux = NULL;
        
        guint i;

	if (gnutls_x509_crq_init (&crq) < 0) {
		return FALSE;
	}

        pem_datum.data = (unsigned char *) csr_pem;
        pem_datum.size = strlen(csr_pem);

	if (gnutls_x509_crq_import (crq, &pem_datum, GNUTLS_X509_FMT_PEM) < 0) {
                gnutls_x509_crq_deinit (crq);
		return FALSE;
	}

	uaux = NULL;
	key_id_len = 0;
	gnutls_x509_crq_get_key_id (crq, 0, uaux, &key_id_len);
	uaux = g_new0(guchar, key_id_len);
	if (gnutls_x509_crq_get_key_id (crq, 0, uaux, &key_id_len)) {
		g_free (uaux);
		gnutls_x509_crq_deinit (crq);
		return NULL;
	}
	key_id = g_new0(gchar, key_id_len*3);
	for (i=0; i<key_id_len; i++) {
		snprintf (&key_id[i*3], 3, "%02X", uaux[i]);
		if (i != key_id_len - 1)
			key_id[(i*3) + 2] = ':';
	}
	g_free (uaux);

        return key_id;
        

}



#endif

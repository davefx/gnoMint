//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007,2008 David Marín Carreño <davefx@gmail.com>
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


#include <glib-object.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "import.h"
#include "tls.h"
#include "ca.h"
#include "ca_file.h"

gboolean import_csr (guchar *file_contents, gsize file_contents_size) 
{	
	gboolean successful_import = FALSE;
	gnutls_x509_crq_t crq;
	gnutls_datum_t file_datum;

	gchar *aux = NULL;

        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Certificate Signing Request in PEM format

	if (gnutls_x509_crq_init (&crq) < 0)
		return FALSE;

	if (gnutls_x509_crq_import (crq, &file_datum, GNUTLS_X509_FMT_PEM) == 0) {
		CaCreationData * creation_data = g_new0(CaCreationData, 1);
		gchar * pem_csr=NULL;
		size_t size;
		gchar * error_msg;

		size = 0;
		gnutls_x509_crq_get_dn_by_oid (crq, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		if (size) {
			aux = g_new0(gchar, size);
			gnutls_x509_crq_get_dn_by_oid (crq, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
			creation_data->cn = g_strdup (aux);
			g_free (aux);
			aux = NULL;
		}	        

		pem_csr = (gchar *) file_datum.data; 
		
		error_msg = ca_file_insert_csr (creation_data, NULL, pem_csr);

		
		if (error_msg) {
			gchar *message = g_strdup_printf (_("Couldn't import the certificate request. \n"
							    "The database returned this error: \n\n'%s'"),
							  error_msg);
			ca_error_dialog (message);
			g_free (message);
		}
		successful_import = TRUE;
		
	}

	// Trying to import a Certificate Signing Request in DER format

	if (gnutls_x509_crq_import (crq, &file_datum, GNUTLS_X509_FMT_DER) == 0) {
		CaCreationData * creation_data = g_new0(CaCreationData, 1);
		gchar * pem_csr=NULL;
		size_t size;

		size = 0;
		gnutls_x509_crq_get_dn_by_oid (crq, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		if (size) {
			aux = g_new0(gchar, size);
			gnutls_x509_crq_get_dn_by_oid (crq, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
			creation_data->cn = g_strdup (aux);
			g_free (aux);
			aux = NULL;
		}	        

		size = 0;
		gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, pem_csr, &size)  ; 
		if (size) {
			pem_csr = g_new0(gchar, size);
			gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, pem_csr, &size);
			
		}

		ca_file_insert_csr (creation_data, NULL, pem_csr);

		successful_import = TRUE;
	}
	
	return successful_import;

}



gboolean import_certlist (guchar *file_contents, gsize file_contents_size)
{
 	gboolean successful_import = FALSE;
	gnutls_x509_crt_t cert;
	gnutls_x509_crt_t *certs = NULL;
	gnutls_datum_t file_datum;
        guint num_certs = 0;

	gchar *aux = NULL;

	file_datum.size = file_contents_size;
	file_datum.data = file_contents;


	// Trying to import a list of certificates in PEM format
        gnutls_x509_crt_list_import (NULL, &num_certs, &file_datum, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);

        certs = g_new0 (gnutls_x509_crt_t, num_certs);

	if (gnutls_x509_crt_list_import (certs, &num_certs, &file_datum, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED) > 0) {

                int i;

                // We go through all the certificates in inverse
                // order, as it's usual having a list of certificates conforming a
                // certification path, with the root CA certificate as the last 
                // certificate

                for (i = num_certs - 1; i>=0; i--) {
                        CertCreationData * creation_data = g_new0(CertCreationData, 1);
                        guchar *serial_str = NULL;
                        UInt160 serial;
                        gchar * pem_cert=NULL;
                        size_t size;
                        gchar * error_msg;
                        gboolean is_ca;
                        guint is_critical;
                        
                        // For inserting the cert into the database we must get:
                        // - if the certificate is a CA certificate
                        // - serial
                        // - activation time
                        // - expiration time

                        // Is_CA?
                        is_ca = gnutls_x509_crt_get_ca_status (certs[i], &is_critical);
                        if (is_ca == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
                                is_ca = FALSE;

                        // Serial
                        size = 0;
                        gnutls_x509_crt_get_serial (certs[i], aux, &size);
                        aux = NULL;
                        if (size) {
                                serial_str = g_new0(guchar, size);
                                gnutls_x509_crt_get_serial (certs[i], serial_str, &size);
                                uint160_read (&serial, serial_str, size);
                                g_free (serial_str);
                        }
                        

                        // Activation
                        creation_data->activation = gnutls_x509_crt_get_activation_time (certs[i]);

                        // Expiration
                        creation_data->expiration = gnutls_x509_crt_get_expiration_time (certs[i]);
                        
   
                        // Now we re-export the PEM (as the original PEM can be a list of certs)
                        size = 0;
                        gnutls_x509_crt_export (certs[i], GNUTLS_X509_FMT_PEM, aux, &size);
                        if (size) {
                                aux = g_new0(gchar, size);
                                gnutls_x509_crt_export (certs[i], GNUTLS_X509_FMT_PEM, aux, &size);
                                pem_cert = g_strdup (aux);
                                g_free (aux);
                                aux = NULL;
                        }
		
                        error_msg = ca_file_insert_imported_cert (creation_data, is_ca, serial, pem_cert);
                        
                        if (pem_cert)
                                g_free (pem_cert);

		
                        if (error_msg) {
                                gchar *message = g_strdup_printf (_("Couldn't import the certificate. \n"
                                                                    "The database returned this error: \n\n'%s'"),
                                                                  error_msg);
                                ca_error_dialog (message);
                                g_free (message);
                        }

                }
                successful_import = TRUE;

                g_free (certs);
                        
                return successful_import;
	}

	// Trying to import a single certificate in DER format
        
        if (gnutls_x509_crt_init (&cert) < 0)
                return FALSE;

	if (gnutls_x509_crt_import (cert, &file_datum, GNUTLS_X509_FMT_DER) == 0) {
                CertCreationData * creation_data = g_new0(CertCreationData, 1);
                guchar *serial_str = NULL;
                UInt160 serial;
                gchar * pem_cert=NULL;
                size_t size;
                gchar * error_msg;
                gboolean is_ca;
                guint is_critical;
                
                // For inserting the cert into the database we must get:
                // - if the certificate is a CA certificate
                // - serial
                // - activation time
                // - expiration time
                
                // Is_CA?
                is_ca = gnutls_x509_crt_get_ca_status (cert, &is_critical);
                if (is_ca == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
                        is_ca = FALSE;
                
                // Serial
                size = 0;
                gnutls_x509_crt_get_serial (cert, aux, &size);
                aux = NULL;
                if (size) {
                        serial_str = g_new0(guchar, size);
                        gnutls_x509_crt_get_serial (cert, serial_str, &size);
                        uint160_read (&serial, serial_str, size);
                        g_free (serial_str);
                }
                
                
                // Activation
                creation_data->activation = gnutls_x509_crt_get_activation_time (cert);
                
                // Expiration
                creation_data->expiration = gnutls_x509_crt_get_expiration_time (cert);
                
                
                // Now we export the certificate as PEM (as the original was in DER-format)
                size = 0;
                gnutls_x509_crt_export (cert, GNUTLS_X509_FMT_PEM, aux, &size);
                if (size) {
                        aux = g_new0(gchar, size);
                        gnutls_x509_crt_export (cert, GNUTLS_X509_FMT_PEM, aux, &size);
                        pem_cert = g_strdup (aux);
                        g_free (aux);
                        aux = NULL;
                }
		
                error_msg = ca_file_insert_imported_cert (creation_data, is_ca, serial, pem_cert);
                
                if (pem_cert)
                        g_free (pem_cert);
                
		
                if (error_msg) {
                        gchar *message = g_strdup_printf (_("Couldn't import the certificate. \n"
                                                            "The database returned this error: \n\n'%s'"),
                                                          error_msg);
                        ca_error_dialog (message);
                        g_free (message);
                }
                
                successful_import = TRUE;
	}
	

	return successful_import;
}

gboolean import_pkey_wo_passwd (guchar *file_contents, gsize file_contents_size)
{
	gboolean successful_import = FALSE;
	gnutls_x509_privkey_t privkey;
	gnutls_datum_t file_datum;

        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Certificate Signing Request in PEM format

	if (gnutls_x509_privkey_init (&privkey) < 0)
		return FALSE;

	if (gnutls_x509_privkey_import (privkey, &file_datum, GNUTLS_X509_FMT_PEM) == 0) {
		gchar * pem_privkey=NULL;
		gchar * error_msg;

		pem_privkey = (gchar *) file_datum.data; 
		
		error_msg = ca_file_import_privkey (pem_privkey);
		
		if (error_msg) {
			gchar *message = g_strdup_printf (_("Couldn't import the given private key. \n"
							    "%s"),
							  error_msg);
			ca_error_dialog (message);
			g_free (message);
		}
		successful_import = TRUE;
		
	}

	// Trying to import a Certificate Signing Request in DER format

	if (gnutls_x509_privkey_import (privkey, &file_datum, GNUTLS_X509_FMT_DER) == 0) {
		gchar * pem_privkey=NULL;
		size_t size;


		size = 0;
		gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size)  ; 
		if (size) {
			pem_privkey = g_new0(gchar, size);
			gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size);
			
		}

		ca_file_import_privkey (pem_privkey);

		successful_import = TRUE;
	}
	
	return successful_import;
}

gboolean import_crl (guchar *file_contents, gsize file_contents_size)
{
        return FALSE;
}

gboolean import_pkcs7 (guchar *file_contents, gsize file_contents_size)
{
        return FALSE;
}

gboolean import_pkcs12 (guchar *file_contents, gsize file_contents_size)
{
        return FALSE;
}

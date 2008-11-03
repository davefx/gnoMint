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


#include <glade/glade.h>
#include <glib-object.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "import.h"
#include "tls.h"
#include "ca.h"
#include "ca_file.h"


gchar * __import_ask_password (const gchar *crypted_part_description);
gint __import_csr (gnutls_x509_crq_t *crq);
gint __import_cert (gnutls_x509_crt_t *cert);

gchar * __import_ask_password (const gchar *crypted_part_description)
{
	gchar *password;
	GtkWidget * widget = NULL, * password_widget = NULL, *description_widget = NULL;
	GladeXML * dialog_xml = NULL;
	gchar     * xml_file = NULL;
        gchar     * label = NULL;
	gint response = 0;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "import_password_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	
	
	password_widget = glade_xml_get_widget (dialog_xml, "import_password_entry");
	description_widget = glade_xml_get_widget (dialog_xml, "import_crypted_part_description");

        label = g_strdup_printf ("<small><i>%s</i></small>", crypted_part_description);
        gtk_label_set_markup (GTK_LABEL(description_widget), (const gchar *) label);
        g_free (label);

        gtk_widget_grab_focus (password_widget);
        widget = glade_xml_get_widget (dialog_xml, "import_password_dialog");
        response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
        if (!response) {
                gtk_widget_destroy (widget);
                g_object_unref (G_OBJECT(dialog_xml));
                return NULL;
        } else {
                password = g_strdup ((gchar *) gtk_entry_get_text (GTK_ENTRY(password_widget)));
        }

	widget = glade_xml_get_widget (dialog_xml, "import_password_dialog");
	gtk_widget_destroy (widget);
	g_object_unref (G_OBJECT(dialog_xml));

	return password;
}


gint __import_csr (gnutls_x509_crq_t *crq)
{
	CaCreationData * creation_data = g_new0(CaCreationData, 1);
	gchar * pem_csr=NULL;
	size_t size;
	gchar * error_msg;
        gint result = -1;
	gchar *aux = NULL;
	
	size = 0;
	gnutls_x509_crq_get_dn_by_oid (*crq, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crq_get_dn_by_oid (*crq, GNUTLS_OID_X520_COMMON_NAME, 0, 0, aux, &size);
		creation_data->cn = g_strdup (aux);
		g_free (aux);
		aux = NULL;
	}	        
	
	size = 0;
	gnutls_x509_crq_export (*crq, GNUTLS_X509_FMT_PEM, pem_csr, &size)  ; 
	if (size) {
		pem_csr = g_new0(gchar, size);
		gnutls_x509_crq_export (*crq, GNUTLS_X509_FMT_PEM, pem_csr, &size);
		
	}
	
	error_msg = ca_file_insert_csr (creation_data, NULL, pem_csr);
	
	
	if (error_msg) {
		gchar *message = g_strdup_printf (_("Couldn't import the certificate request. \n"
						    "The database returned this error: \n\n'%s'"),
						  error_msg);
		ca_error_dialog (message);
		g_free (message);
	} else {
                result = 1;
        }
        return result;
}

gint __import_cert (gnutls_x509_crt_t *cert)
{
	CertCreationData * creation_data = g_new0(CertCreationData, 1);
	guchar *serial_str = NULL;
	UInt160 serial;
	gchar * pem_cert=NULL;
	size_t size;
	gchar * error_msg;
	gboolean is_ca;
	guint is_critical;
	gchar *aux = NULL;
        gint result = -1;
        
	// For inserting the cert into the database we must get:
	// - if the certificate is a CA certificate
	// - serial
	// - activation time
	// - expiration time
	
	// Is_CA?
	is_ca = gnutls_x509_crt_get_ca_status (*cert, &is_critical);
	if (is_ca == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		is_ca = FALSE;
	
	// Serial
	size = 0;
	gnutls_x509_crt_get_serial (*cert, aux, &size);
	aux = NULL;
	if (size) {
		serial_str = g_new0(guchar, size);
		gnutls_x509_crt_get_serial (*cert, serial_str, &size);
		uint160_read (&serial, serial_str, size);
		g_free (serial_str);
	}
        
	
	// Activation
	creation_data->activation = gnutls_x509_crt_get_activation_time (*cert);
	
	// Expiration
	creation_data->expiration = gnutls_x509_crt_get_expiration_time (*cert);
        
	
	// Now we re-export the PEM (as the original PEM can be a list of certs)
	size = 0;
	gnutls_x509_crt_export (*cert, GNUTLS_X509_FMT_PEM, aux, &size);
	if (size) {
		aux = g_new0(gchar, size);
		gnutls_x509_crt_export (*cert, GNUTLS_X509_FMT_PEM, aux, &size);
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
	} else {
                result = 1;
        }

        return result;
}

gint __import_crl (gnutls_x509_crl_t *crl)
{
        gint result = -1;
	gnutls_x509_crt_t issuer_crt;
        gsize size = 0;
        gchar *issuer_dn = NULL;
        gchar *cert_pem = NULL;
        guint64 issuer_id;
	gnutls_datum_t file_datum;


        size = 0;
        gnutls_x509_crl_get_issuer_dn (*crl, issuer_dn, &size)  ; 
        if (size) {
                issuer_dn = g_new0(gchar, size);
                gnutls_x509_crl_get_issuer_dn (*crl, issuer_dn, &size);		
        }

        // First, we search the issuer in the database, using DN
        if (ca_file_get_id_from_dn (CA_FILE_ELEMENT_TYPE_CERT, issuer_dn, &issuer_id)) {
        
                // We check if the supposed issuer is the actual issuer
                cert_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, issuer_id);

                if (gnutls_x509_crt_init (&issuer_crt) < 0) {
                        g_free (issuer_dn);
                        g_free (cert_pem);
                        return result;
                }

                file_datum.data = (guchar *) cert_pem;
                file_datum.size = strlen(cert_pem);

                if (gnutls_x509_crt_import (issuer_crt, &file_datum, GNUTLS_X509_FMT_PEM) == GNUTLS_E_SUCCESS) {

                        if (gnutls_x509_crl_check_issuer (*crl, issuer_crt)) {
                                int number_of_certs;
                                int i;

                                // If it is, we recover all the certificates 
                                number_of_certs = gnutls_x509_crl_get_crt_count(*crl);

                                for (i=0; i<number_of_certs; i++) {
                                        guchar *serialcrt = NULL;
                                        UInt160 serial;
                                        time_t revocation = 0;

                                        // We look up each of the certificates in the crl

                                        size = 0;
                                        gnutls_x509_crl_get_crt_serial (*crl, i, serialcrt, &size, &revocation);
                                        if (size) {
                                                guint64 cert_id;

                                                serialcrt = g_new0 (guchar, size);
                                                gnutls_x509_crl_get_crt_serial (*crl, i, serialcrt, &size, &revocation);
                                                uint160_read (&serial, serialcrt, size);
                                                g_free (serialcrt);
                                                serialcrt = NULL;

                                                if (ca_file_get_id_from_serial_issuer_id (&serial, issuer_id, &cert_id)) {
                                                        // If found, we revoke it with the correct date
                                                        ca_file_revoke_crt_with_date (cert_id, revocation);
                                                        result = 1;
                                                }
                                        }
                                }

                        }
                }

                gnutls_x509_crt_deinit (issuer_crt);
        }        
        return result;
}

gint import_csr (guchar *file_contents, gsize file_contents_size) 
{	
	gnutls_x509_crq_t crq;
	gnutls_datum_t file_datum;
        gint result = 0;

        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Certificate Signing Request 

	if (gnutls_x509_crq_init (&crq) < 0)
		return result;

	if (gnutls_x509_crq_import (crq, &file_datum, GNUTLS_X509_FMT_PEM) == 0 ||
	    gnutls_x509_crq_import (crq, &file_datum, GNUTLS_X509_FMT_DER) == 0) {

		result = __import_csr (&crq);
	}

	gnutls_x509_crq_deinit (crq);
	
	return result;

}


gint import_certlist (guchar *file_contents, gsize file_contents_size)
{
	gnutls_x509_crt_t cert;
	gnutls_x509_crt_t *certs = NULL;
	gnutls_datum_t file_datum;
        guint num_certs = 0;
        gint result = 0;

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
                result = -1;
                for (i = num_certs - 1; i>=0; i--) {
			if (__import_cert (&certs[i]) > 0)
                                result = 1;
                }

                g_free (certs);
                        
                return result;
	}

	// Trying to import a single certificate in DER format
        
        if (gnutls_x509_crt_init (&cert) < 0)
                return 0;

	if (gnutls_x509_crt_import (cert, &file_datum, GNUTLS_X509_FMT_DER) == 0) {
                result = __import_cert (&cert);
        }

	gnutls_x509_crt_deinit (cert);

	return result;
}

gint import_pkey_wo_passwd (guchar *file_contents, gsize file_contents_size)
{
        gint result = 0;
	gnutls_x509_privkey_t privkey;
	gnutls_datum_t file_datum;
        gchar *result_import;
        
        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Private Key in PEM format

	if (gnutls_x509_privkey_init (&privkey) < 0)
		return 0;

	// Trying to import a Private Key in DER format

	if (gnutls_x509_privkey_import (privkey, &file_datum, GNUTLS_X509_FMT_PEM) == 0 ||
	    gnutls_x509_privkey_import (privkey, &file_datum, GNUTLS_X509_FMT_DER) == 0) {
		gchar * pem_privkey=NULL;
		size_t size;
                result = -1;

		size = 0;
		gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size)  ; 
		if (size) {
			pem_privkey = g_new0(gchar, size);
			gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size);
			
		}

                result_import = ca_file_import_privkey (pem_privkey);
		if (result_import) {
                        ca_error_dialog (result_import);
                } else {
                        result = 1;
                }
		g_free (pem_privkey);

	}

	gnutls_x509_privkey_deinit (privkey);
	
	return result;
}

gint import_crl (guchar *file_contents, gsize file_contents_size)
{
        gint result = 0;
	gnutls_x509_crl_t crl;
	gnutls_datum_t file_datum;

        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Certificate Revocation List in PEM format

	if (gnutls_x509_crl_init (&crl) < 0)
		return 0;

	if (gnutls_x509_crl_import (crl, &file_datum, GNUTLS_X509_FMT_PEM) != 0 && 
            gnutls_x509_crl_import (crl, &file_datum, GNUTLS_X509_FMT_DER) != 0) {
                // The given file is not a DER-coded CRL, neither a PEM-coded CRL

                gnutls_x509_crl_deinit (crl);
                return 0;
        }
                
        result = __import_crl (&crl);
                		
	gnutls_x509_crl_deinit (crl);
	
	return result;
}

/* PKCS#7 importing was removed in libgnutls 2.6.0 */

/* gint import_pkcs7 (guchar *file_contents, gsize file_contents_size) */
/* { */
/* 	gboolean successful_import = FALSE; */
/* 	gnutls_pkcs7_t pkcs7; */
/* 	gnutls_datum_t file_datum; */

/*         file_datum.data = file_contents; */
/*         file_datum.size = file_contents_size; */

/* 	// Trying to import a Private Key in PEM format */

/* 	if (gnutls_pkcs7_init (&pkcs7) < 0) */
/* 		return FALSE; */

/* 	// Trying to import a Private Key in DER format */

/* 	if (gnutls_pkcs7_import (pkcs7, &file_datum, GNUTLS_X509_FMT_PEM) == 0 || */
/* 	    gnutls_pkcs7_import (pkcs7, &file_datum, GNUTLS_X509_FMT_DER) == 0) { */
/* 		int i; */
/* 		int certs_no = gnutls_pkcs7_get_crt_count (pkcs7); */
/* 		int crl_no = gnutls_pkcs7_get_crl_count (pkcs7); */

/* 		for (i=0; i < certs_no; i++) { */
/* 			guchar *raw_cert = NULL; */
/* 			gsize raw_cert_size = 0; */

/* 			gnutls_pkcs7_get_crt_raw (pkcs7, i, raw_cert, &raw_cert_size); */

/* 			raw_cert = g_new0(guchar, raw_cert_size); */
/* 			gnutls_pkcs7_get_crt_raw (pkcs7, i, raw_cert, &raw_cert_size); */

/* 			import_certlist (raw_cert, raw_cert_size); */

/* 			g_free (raw_cert); */
/* 		} */

/* 		for (i=0; i < crl_no; i++) { */
/* 			guchar *raw_crl = NULL; */
/* 			gsize raw_crl_size = 0; */
			
/* 			gnutls_pkcs7_get_crl_raw (pkcs7, i, raw_crl, &raw_crl_size); */

/* 			raw_crl = g_new0(guchar, raw_crl_size); */
/* 			gnutls_pkcs7_get_crl_raw (pkcs7, i, raw_crl, &raw_crl_size); */

/* 			import_crl (raw_crl, raw_crl_size); */

/* 			g_free (raw_crl); */
/* 		} */

/* 		successful_import = TRUE; */
/* 	} */

/* 	gnutls_pkcs7_deinit (pkcs7); */
	
/* 	return successful_import; */
/* } */

gint import_pkcs8 (guchar *file_contents, gsize file_contents_size)
{
	gint result = 0;
	gnutls_x509_privkey_t privkey;
	gnutls_datum_t file_datum;

        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Private Key in PEM format

	if (gnutls_x509_privkey_init (&privkey) < 0)
		return 0;

	// Trying to import a Private Key in DER format

	if (gnutls_x509_privkey_import_pkcs8 (privkey, &file_datum, GNUTLS_X509_FMT_PEM, NULL, GNUTLS_PKCS_PLAIN) == 0 ||
	    gnutls_x509_privkey_import_pkcs8 (privkey, &file_datum, GNUTLS_X509_FMT_DER, NULL, GNUTLS_PKCS_PLAIN) == 0) {
                result = -1;
		gchar * pem_privkey=NULL;
                gchar * error_msg = NULL;
		size_t size;

		size = 0;
		gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size)  ; 
		if (size) {
			pem_privkey = g_new0(gchar, size);
			gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size);
			
		}

                error_msg = ca_file_import_privkey (pem_privkey);
		if (error_msg) {
                        ca_error_dialog (error_msg);
                } else {
                        result = 1;
                }

		g_free (pem_privkey);

	} else {
                // Now we check if the given file is a PEM codified encrypted private key: while trying to import,
                // the password won't be correct.
                
                gint result_decryption = gnutls_x509_privkey_import_pkcs8 (privkey, &file_datum, GNUTLS_X509_FMT_PEM, NULL, 0);

                while (result_decryption==GNUTLS_E_DECRYPTION_FAILED) {

                        // We mark a successful import, as it is a PKCS#8 cyphered file: it must not be probed with other formats.
                        result = -1;

                        // We launch a window for asking the password.
                        gchar * password = __import_ask_password (_("PKCS#8 crypted private key"));

                        if (! password) {
                                gnutls_x509_privkey_deinit (privkey);
                                return result;
                        }
                        
                        result_decryption = gnutls_x509_privkey_import_pkcs8 (privkey, &file_datum, GNUTLS_X509_FMT_PEM, password, 0);
                        g_free (password);

                        if (result_decryption == GNUTLS_E_DECRYPTION_FAILED) {
                                ca_error_dialog (_("The given password doesn't match the one used for crypting this part"));
                        }
                }

                if (result_decryption == GNUTLS_E_SUCCESS) {
                        gchar * pem_privkey=NULL;
                        size_t size;
                        gchar * error_msg = NULL;

                        result = -1;
                        
                        size = 0;
                        gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size)  ; 
                        if (size) {
                                pem_privkey = g_new0(gchar, size);
                                gnutls_x509_privkey_export (privkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size);
                                
                        }
                        
                        error_msg = ca_file_import_privkey (pem_privkey);
                        if (error_msg) {
                                ca_error_dialog (error_msg);
                        } else {
                                result = 1;
                        }
                        g_free (pem_privkey);
                }

                // Importing DER-codified encrypted private keys is not supported, as they cannot be probed without
                // a password.
        }

	gnutls_x509_privkey_deinit (privkey);
	
	return result;
}

gint import_pkcs12 (guchar *file_contents, gsize file_contents_size)
{
        gint result = 0;
	gnutls_pkcs12_t pkcs12;
	gnutls_datum_t file_datum;

        file_datum.data = file_contents;
        file_datum.size = file_contents_size;

	// Trying to import a Private Key in PEM format

	if (gnutls_pkcs12_init (&pkcs12) < 0)
		return result;

        // Trying to import a PKCS#12 in PEM or DER format 
	if (gnutls_pkcs12_import (pkcs12, &file_datum, GNUTLS_X509_FMT_PEM, 0) == 0 ||
	    gnutls_pkcs12_import (pkcs12, &file_datum, GNUTLS_X509_FMT_DER, 0) == 0) {                
                guint n_bags = 0;
                gnutls_pkcs12_bag_t *pkcs12_aux_bag = NULL;
                GArray *pkcs_bag_array = g_array_new (FALSE, TRUE, sizeof(gnutls_pkcs12_bag_t));
                gint get_bag_status;
                gchar *password = NULL;
                guint i;

                result = -1;

                // Now, we walk through all the bags in the PKCS12 structure
                // inserting them into an array for walking through them afterwards
                do {
                        pkcs12_aux_bag = g_new0 (gnutls_pkcs12_bag_t, 1);
                        gnutls_pkcs12_bag_init (pkcs12_aux_bag);
                        
                        get_bag_status = gnutls_pkcs12_get_bag (pkcs12, n_bags, *pkcs12_aux_bag);
                        
                        if (get_bag_status == GNUTLS_E_SUCCESS) {
                                g_array_append_val (pkcs_bag_array, pkcs12_aux_bag);
                                n_bags ++;
                        } else {
                                gnutls_pkcs12_bag_deinit (*pkcs12_aux_bag);
                                g_free (pkcs12_aux_bag);
                        }

                } while (get_bag_status == GNUTLS_E_SUCCESS);

                if (n_bags == 0) {
                        // Couldn't get any bag.
                        // Exiting with error
                        gnutls_pkcs12_deinit (pkcs12);
                        return result;
                }


                // Now, we first uncrypt all crypted bags
                for (i=0; i<n_bags; i++) {
                        if (gnutls_pkcs12_bag_get_type (* g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i), 0) == GNUTLS_BAG_ENCRYPTED) {
                                gboolean pkcs12_bag_decrypted = FALSE;
                                if (! password) 
                                        password = __import_ask_password (_("Encrypted PKCS#12 bag"));

                                if (! password) {
                                        // The user cancelled the operation
                                        for (i=0; i<n_bags; i++) {
                                                gnutls_pkcs12_bag_deinit (* g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i));
                                                g_free (g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i));
                                                gnutls_pkcs12_deinit (pkcs12);
                                                g_array_free (pkcs_bag_array, TRUE);
                                                return result;
                                        }
                                } 
                                
                                pkcs12_bag_decrypted = ! (gnutls_pkcs12_bag_decrypt (* g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i),
                                                                                     password));
                                if (!pkcs12_bag_decrypted) {                                                
                                        gint j;
                                        ca_error_dialog (_("The given password doesn't match with the password used for encrypting this part."));
                                        for (j=0; j<n_bags; j++) {
                                                gnutls_pkcs12_bag_deinit (* g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, j));
                                                g_free (g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, j));
                                        }
                                        gnutls_pkcs12_deinit (pkcs12);
                                        g_array_free (pkcs_bag_array, TRUE);
                                        return result;
                                }
                        }
                }

                // After having all the parts unencrypted, we import all certificates first.
                for (i=0; i<n_bags; i++) {
                        gnutls_pkcs12_bag * pkcs12_bag = g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i);
                        guint num_elements_in_bag = gnutls_pkcs12_bag_get_count (*pkcs12_bag);
                        
                        for (i=0; i < num_elements_in_bag; i++) {
                                gnutls_datum data;
                                if (gnutls_pkcs12_bag_get_type (*pkcs12_bag, i) == GNUTLS_BAG_CERTIFICATE) {
                                        gnutls_x509_crt cert;
                                        
                                        gnutls_x509_crt_init (&cert);
                                        if (gnutls_pkcs12_bag_get_data(*pkcs12_bag, i, &data) < 0) {
                                                gnutls_x509_crt_deinit (cert);
                                                continue;
                                        }
                                        if (gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_DER) < 0) {
                                                gnutls_x509_crt_deinit (cert);
                                                continue;
                                        }
                                        __import_cert (& cert);
                                        
                                        gnutls_x509_crt_deinit (cert);
                                }
                        }
                }
                
                
                // Then, we import all PKCS8 private keys.
                for (i=0; i<n_bags; i++) {
                        gnutls_pkcs12_bag * pkcs12_bag = g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i);
                        guint num_elements_in_bag = gnutls_pkcs12_bag_get_count (*pkcs12_bag);
                        
                        for (i=0; i < num_elements_in_bag; i++) {
                                gnutls_datum data;
                                if (gnutls_pkcs12_bag_get_type (*pkcs12_bag, i) == GNUTLS_BAG_PKCS8_KEY ||
                                    gnutls_pkcs12_bag_get_type (*pkcs12_bag, i) == GNUTLS_BAG_PKCS8_ENCRYPTED_KEY) {
                                        gnutls_x509_privkey pkey;
                                        gint result_decryption;
                                        
                                        gnutls_x509_privkey_init (&pkey);
                                        if (gnutls_pkcs12_bag_get_data(*pkcs12_bag, i, &data) < 0) {
                                                gnutls_x509_privkey_deinit (pkey);
                                                continue;
                                        }

                                        result_decryption = gnutls_x509_privkey_import_pkcs8(pkey, &data, GNUTLS_X509_FMT_DER, password, 0);
                                        if (result_decryption < 0) {
                                                while (result_decryption==GNUTLS_E_DECRYPTION_FAILED) {
                                                        if (password)
                                                                g_free (password);

                                                        // We launch a window for asking the password.
                                                        password = __import_ask_password (_("PKCS#8 crypted private key"));
                                                        
                                                        if (! password) {
                                                                break;
                                                        }
                        
                                                        result_decryption = gnutls_x509_privkey_import_pkcs8 (pkey, &data, GNUTLS_X509_FMT_DER, 
                                                                                                              password, 0);

                                                        if (result_decryption == GNUTLS_E_DECRYPTION_FAILED) {
                                                                ca_error_dialog (_("The given password doesn't match the one used "
                                                                                   "for crypting this part"));
                                                        }
                                                }
                                                if (result_decryption < 0) {
                                                        // The user pressed "Cancel" button, or 
                                                        // the decryption has failed
                                                        gnutls_x509_privkey_deinit (pkey);
                                                        continue;
                                                }
                                        }
                                        if (result_decryption == GNUTLS_E_SUCCESS) {
                                                gchar * pem_privkey=NULL;
                                                size_t size;
                                                gchar * error_msg = NULL;
                                                
                                                result = -1;
                                                
                                                size = 0;
                                                gnutls_x509_privkey_export (pkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size)  ; 
                                                if (size) {
                                                        pem_privkey = g_new0(gchar, size);
                                                        gnutls_x509_privkey_export (pkey, GNUTLS_X509_FMT_PEM, pem_privkey, &size);
                                                        
                                                }
                                                
                                                error_msg = ca_file_import_privkey (pem_privkey);
                                                if (error_msg) {
                                                        ca_error_dialog (error_msg);
                                                } else {
                                                        result = 1;
                                                }
                                                g_free (pem_privkey);
                                                gnutls_x509_privkey_deinit (pkey);
                                        }
                                }
                        }
                }       
                // Then we import the CRLs

                for (i=0; i<n_bags; i++) {
                        gnutls_pkcs12_bag * pkcs12_bag = g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i);
                        guint num_elements_in_bag = gnutls_pkcs12_bag_get_count (*pkcs12_bag);
                        
                        for (i=0; i < num_elements_in_bag; i++) {
                                gnutls_datum data;
                                if (gnutls_pkcs12_bag_get_type (*pkcs12_bag, i) == GNUTLS_BAG_CRL) {
                                        gnutls_x509_crl crl;
                                        
                                        gnutls_x509_crl_init (&crl);
                                        if (gnutls_pkcs12_bag_get_data(*pkcs12_bag, i, &data) < 0) {
                                                gnutls_x509_crl_deinit (crl);
                                                continue;
                                        }
                                        if (gnutls_x509_crl_import(crl, &data, GNUTLS_X509_FMT_DER) < 0) {
                                                gnutls_x509_crl_deinit (crl);
                                                continue;
                                        }
                                        __import_crl (& crl);
                                        
                                        gnutls_x509_crl_deinit (crl);
                                }
                        }
                }

                // Ok. Now we free all the bags
                for (i=0; i<n_bags; i++) {
                        gnutls_pkcs12_bag_deinit (* g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i));
                        g_free (g_array_index (pkcs_bag_array, gnutls_pkcs12_bag_t *, i));
                }
                g_array_free (pkcs_bag_array, TRUE);
                
	}

	gnutls_pkcs12_deinit (pkcs12);
	
	return result;
}

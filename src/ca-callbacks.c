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

#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>
#include <stdio.h>
#include <glib/gi18n.h>

#include "ca-callbacks.h"
#include "ca.h"
#include "ca_file.h"
#include "ca_policy.h"
#include "pkey_manage.h"
#include "preferences.h"
#include "tls.h"

extern CaCommand ca_commands[];
#define CA_COMMAND_NUMBER 31

extern gchar * gnomint_current_opened_file;


int ca_callback_newdb (int argc, char **argv)
{
        gchar *filename = argv[1];
        gchar *error = NULL;

        if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
                /* The file already exists. We ask the user about overwriting it */
                
                if (! ca_ask_for_confirmation (_("The file already exists, so it will be overwritten."), _("Are you sure? Yes/[No] "), FALSE)) 
			return 1;

                /* If he wants to overwrite it, we first rename it to "filename~", after deleting "filename~" if it already exists */

                gchar *backup_filename = g_strdup_printf ("%s~", filename);
                if (g_file_test (backup_filename, G_FILE_TEST_EXISTS)) {
                        g_remove (backup_filename);
                }
                
                g_rename (filename, backup_filename);
                
                g_free (backup_filename);
        }

        error = ca_file_create (filename);
        if (error) {
                fprintf (stderr, "%s\n", error);
                return 1;
        }

	if (! ca_open (filename, FALSE)) {
                fprintf (stderr, _("Problem when opening new '%s' CA database\n"), filename);
                return 1;
        }

	printf (_("File '%s' opened\n"), filename);

	return 0;
}

int ca_callback_opendb (int argc, char **argv)
{
	gchar *filename = argv[1];

	if (! ca_open (filename, FALSE)) {
                fprintf (stderr, _("Problem when opening '%s' CA database\n"), filename);
	} 

	return 0;
}

int ca_callback_savedbas (int argc, char **argv)
{
        gchar *filename = argv[1];
        
        if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
                /* The file already exists. We ask the user about overwriting it */
                
                if (! ca_ask_for_confirmation (_("The file already exists, so it will be overwritten."), _("Are you sure? Yes/[No] "), FALSE)) 
			return 1;

                /* If he wants to overwrite it, we first rename it to "filename~", after deleting "filename~" if it already exists */

                gchar *backup_filename = g_strdup_printf ("%s~", filename);
                if (g_file_test (backup_filename, G_FILE_TEST_EXISTS)) {
                        g_remove (backup_filename);
                }
                
                g_rename (filename, backup_filename);
                
                g_free (backup_filename);
        }

        return ca_file_save_as (filename);

}

int ca_callback_status (int argc, char **argv)
{
	printf (_("Current opened file: %s\n"), gnomint_current_opened_file);
	printf (_("Number of certificates in file: %d\n"), ca_file_get_number_of_certs());
	printf (_("Number of CSRs in file: %d\n"), ca_file_get_number_of_csrs());

	return 0;
}

int __ca_callback_listcert_aux (void *pArg, int argc, char **argv, char **columnNames)
{
	struct tm tmp;
	time_t aux_date;
	gchar model_time_str[100];

	printf (Q_("CertList ID|%s\t"), argv[CA_FILE_CERT_COLUMN_ID]);
	
	if (atoi(argv[CA_FILE_CERT_COLUMN_IS_CA]))
		printf (Q_("CertList IsCA|Y\t"));
	else
		printf (Q_("CertList IsCA|N\t"));

	if (strlen(argv[CA_FILE_CERT_COLUMN_SUBJECT]) > 16)
		argv[CA_FILE_CERT_COLUMN_SUBJECT][16] = '\0';

	printf (Q_("CertList Subject|%s\t"), argv[CA_FILE_CERT_COLUMN_SUBJECT]);

	if (strlen (argv[CA_FILE_CERT_COLUMN_SUBJECT]) / 8 < 2)
		printf (Q_("CertList PadIfSubject<16|\t"));
	if (strlen (argv[CA_FILE_CERT_COLUMN_SUBJECT]) / 8 < 1)
		printf (Q_("CertList PadIfSubject<8|\t"));

	if (atoi(argv[CA_FILE_CERT_COLUMN_PRIVATE_KEY_IN_DB]))
		printf (Q_("CertList PKeyInDB|Y\t\t"));
	else
		printf (Q_("CertList PKeyInDB|N\t\t"));

	aux_date = atol(argv[CA_FILE_CERT_COLUMN_ACTIVATION]);
	if (aux_date == 0) {
		printf (Q_("CertList Activation|\t"));
	} else {	
		gmtime_r (&aux_date, &tmp);
	
		strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tmp);
		printf (Q_("CertList Activation|%s\t"), model_time_str);
	}

	aux_date = atol(argv[CA_FILE_CERT_COLUMN_EXPIRATION]);
	if (aux_date == 0) {
		printf (Q_("CertList Expiration|\t"));
	} else {	
		gmtime_r (&aux_date, &tmp);
	
		strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tmp);
		printf (Q_("CertList Expiration|%s\t"), model_time_str);
	}

	if (argc > CA_FILE_CERT_COLUMN_REVOCATION && argv[CA_FILE_CERT_COLUMN_REVOCATION]) {
		aux_date = atol(argv[CA_FILE_CERT_COLUMN_REVOCATION]);
		if (aux_date == 0) {
			printf (Q_("CertList Revocation|\n"));
		} else {	
			gmtime_r (&aux_date, &tmp);
			
			strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tmp);
			printf (Q_("CertList Revocation|%s\n"), model_time_str);
		}
	} else {
		printf ("\n");
	}

	return 0;
}


int ca_callback_listcert (int argc, char **argv)
{
	gboolean see_revoked = FALSE;

	if (argc==2 && !strcmp (argv[1], "--see-revoked"))
		see_revoked = TRUE;

	printf (_("Certificates in Database:\n"));
	printf (_("Id.\tIs CA?\tCertificate Subject\tKey in DB?\tActivation\t\tExpiration"));

	if (see_revoked)
		printf (_("\t\tRevocation\n"));
	else
		printf ("\n");

	ca_file_foreach_crt (__ca_callback_listcert_aux, see_revoked, GINT_TO_POINTER(see_revoked));
	return 0;
}

int __ca_callback_listcsr_aux (void *pArg, int argc, char **argv, char **columnNames)
{
	printf (Q_("CsrList ID|%s\t"), argv[CA_FILE_CSR_COLUMN_ID]);

	printf (Q_("CsrList ParentID|%s\t"), (argv[CA_FILE_CSR_COLUMN_PARENT_ID] ? argv[CA_FILE_CSR_COLUMN_PARENT_ID] : Q_("CsrList ParentID|\t")));
	
	if (strlen(argv[CA_FILE_CSR_COLUMN_SUBJECT]) > 16)
		argv[CA_FILE_CSR_COLUMN_SUBJECT][16] = '\0';

	printf (Q_("CsrList Subject|%s\t"), argv[CA_FILE_CSR_COLUMN_SUBJECT]);

	if (strlen (argv[CA_FILE_CSR_COLUMN_SUBJECT]) / 8 < 2)
		printf (Q_("CsrList PadIfSubject<16|\t"));
	if (strlen (argv[CA_FILE_CSR_COLUMN_SUBJECT]) / 8 < 1)
		printf (Q_("CsrList PadIfSubject<8|\t"));

	if (atoi(argv[CA_FILE_CSR_COLUMN_PRIVATE_KEY_IN_DB]))
		printf (Q_("CsrList PKeyInDB|Y\n"));
	else
		printf (Q_("CsrList PKeyInDB|N\n"));

	return 0;
}


int ca_callback_listcsr (int argc, char **argv)
{
	printf (_("Certificate Requests in Database:\n"));
	printf (_("Id.\tParent Id.\tCSR Subject\t\tKey in DB?\n"));

	ca_file_foreach_csr (__ca_callback_listcsr_aux, NULL);
	return 0;
}









int ca_callback_addcsr (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}




int ca_callback_addca (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}








int ca_callback_extractcertpkey (int argc, char **argv)
{
	guint64 id_cert = atoll(argv[1]);
	gchar *filename = argv[2];

	GIOChannel * file = NULL;
	gchar * password = NULL;
	GError * error = NULL;
	gchar * dn = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * privatekey = NULL;
	gchar * pem = NULL;


	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
		g_free (password);
		return 1;
	} 
	
	crypted_pkey = pkey_manage_get_certificate_pkey (id_cert);
	dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id_cert);
			
	if (!crypted_pkey || !dn) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		ca_error_dialog (_("There was an error while getting private key."));
		return 2;
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);
	
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	if (! privatekey) {
		ca_error_dialog (_("There was an error while uncrypting private key."));
		return 3;
	}
	
	password = ca_dialog_get_password (_("You need to supply a passphrase for protecting the exported private key, "
					     "so nobody else but authorized people can use it. This passphrase will be asked "
					     "by any application that will make use of the private key."),
					   _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"), 
					   _("The introduced passphrases are distinct."), 8);
	if (! password) {
		ca_error_dialog (_("Operation cancelled."));
		g_free (privatekey);
		return 4;
	}

	pem = tls_generate_pkcs8_encrypted_private_key (privatekey, password); 
	g_free (password);
	g_free (privatekey);
	
	if (!pem) {
		ca_error_dialog (_("There was an error while password-protecting private key."));
		return 5;
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		g_free (pem);
		ca_error_dialog (_("There was an error while exporting private key."));
		return 6;
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
		g_io_channel_unref (file);
		return 7;
	} 
	
	g_io_channel_unref (file);
	
	printf (_("Private key extracted successfully into file '%s'\n"), filename);

	ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CERT, filename, id_cert);
	
	return 0;
}


int ca_callback_extractcsrpkey (int argc, char **argv)
{
	guint64 id_csr = atoll(argv[1]);
	gchar *filename = argv[2];

	GIOChannel * file = NULL;
	gchar * password = NULL;
	GError * error = NULL;
	gchar * dn = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * privatekey = NULL;
	gchar * pem = NULL;


	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
		g_free (password);
		return 1;
	} 
	
	crypted_pkey = pkey_manage_get_certificate_pkey (id_csr);
	dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CSR, id_csr);
			
	if (!crypted_pkey || !dn) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		ca_error_dialog (_("There was an error while getting private key."));
		return 2;
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);
	
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	if (! privatekey) {
		ca_error_dialog (_("There was an error while uncrypting private key."));
		return 3;
	}
	
	password = ca_dialog_get_password (_("You need to supply a passphrase for protecting the exported private key, "
					     "so nobody else but authorized people can use it. This passphrase will be asked "
					     "by any application that will make use of the private key."),
					   _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"), 
					   _("The introduced passphrases are distinct."), 8);
	if (! password) {
		ca_error_dialog (_("Operation cancelled."));
		g_free (privatekey);
		return 4;
	}

	pem = tls_generate_pkcs8_encrypted_private_key (privatekey, password); 
	g_free (password);
	g_free (privatekey);
	
	if (!pem) {
		ca_error_dialog (_("There was an error while password-protecting private key."));
		return 5;
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		g_free (pem);
		ca_error_dialog (_("There was an error while exporting private key."));
		return 6;
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		ca_error_dialog (_("There was an error while exporting private key."));
		g_io_channel_unref (file);
		return 7;
	} 
	
	g_io_channel_unref (file);
	
	printf (_("Private key extracted successfully into file '%s'\n"), filename);

	ca_file_mark_pkey_as_extracted_for_id (CA_FILE_ELEMENT_TYPE_CSR, filename, id_csr);
	
	return 0;
}



int ca_callback_revoke (int argc, char **argv)
{
	gchar *errmsg = NULL;
	guint64 id = atoll (argv[1]);

	ca_callback_showcert (argc, argv);

	if (ca_ask_for_confirmation (_("This certificate will be revoked."), _("Are you sure? Yes/[No] "),  FALSE)) {
		errmsg = ca_file_revoke_crt (id);
		if (errmsg) {
			ca_error_dialog (_(errmsg));
			
		} else {
			printf (_("Certificate revoked.\n"));
		}

	} else {
		printf (_("Operation cancelled.\n"));
	}


	return 0;
}


void __ca_callback_show_uses_and_purposes (CertCreationData *cert_creation_data)
{
	printf (_("Certificate uses:\n"));

	if (cert_creation_data->ca) {
		printf (_("* Certification Authority use enabled.\n"));		
	} else {
		printf (_("* Certification Authority use disabled.\n"));		
	}

	if (cert_creation_data->crl_signing) {
		printf (_("* CRL signing use enabled.\n"));
	} else {
		printf (_("* CRL signing use disabled.\n"));
	}

	if (cert_creation_data->digital_signature) {
		printf (_("* Digital Signature use enabled.\n"));
	} else {
		printf (_("* Digital Signature use disabled.\n"));
	}

	if (cert_creation_data->data_encipherment) {
		printf (_("* Data Encipherment use enabled.\n"));
	} else {
		printf (_("* Data Encipherment use enabled.\n"));
	}

	if (cert_creation_data->key_encipherment) {
		printf (_("* Key Encipherment use enabled.\n"));
	} else {
		printf (_("* Key Encipherment use disabled.\n"));
	}

	if (cert_creation_data->non_repudiation) {
		printf (_("* Non Repudiation use enabled.\n"));
	} else {
		printf (_("* Non Repudiation use disabled.\n"));
	}

	if (cert_creation_data->key_agreement) {
		printf (_("* Key Agreement use enabled.\n"));
	} else {
		printf (_("* Key Agreement use disabled.\n"));
	}

	printf (_("Certificate purposes:\n"));

	if (cert_creation_data->email_protection) {
		printf (_("* Email Protection purpose enabled.\n"));
	} else {
		printf (_("* Email Protection purpose disabled.\n"));
	}

	if (cert_creation_data->code_signing) {
		printf (_("* Code Signing purpose enabled.\n"));
	} else {
		printf (_("* Code Signing purpose disabled.\n"));
	}

	if (cert_creation_data->web_client) {
		printf (_("* TLS Web Client purpose enabled.\n"));
	} else {
		printf (_("* TLS Web Client purpose disabled.\n"));
	}

	if (cert_creation_data->web_server) {
		printf (_("* TLS Web Server purpose enabled.\n"));
	} else {
		printf (_("* TLS Web Server purpose disabled.\n"));
	}

	if (cert_creation_data->time_stamping) {
		printf (_("* Time Stamping purpose enabled.\n"));
	} else {
		printf (_("* Time Stamping purpose disabled.\n"));
	}

	if (cert_creation_data->ocsp_signing) {
		printf (_("* OCSP Signing purpose enabled.\n"));
	} else {
		printf (_("* OCSP Signing purpose disabled.\n"));
	}

	if (cert_creation_data->any_purpose) {
		printf (_("* Any purpose enabled.\n"));
	} else {
		printf (_("* Any purpose disabled.\n"));
	}

}


int ca_callback_sign (int argc, char **argv)
{
	CertCreationData *cert_creation_data = NULL;
	gchar *csr_pem = NULL;
	
	gchar *certificate;
        gchar *error = NULL;

	gchar *pem;
	gchar *dn;
	gchar *pkey_pem;
	guint64 csr_id;
	guint64 ca_id;
	PkeyManageData *crypted_pkey;

	time_t tmp;
	struct tm * expiration_time;

	csr_id = atoll(argv[1]);
	ca_id = atoll(argv[2]);
	cert_creation_data = g_new0 (CertCreationData, 1);

	printf (_("You are about to sign the following Certificate Signing Request:\n"));
	ca_callback_showcsr (argc, argv);
	printf (_("with the certificate corresponding to the next CA:\n"));
	ca_callback_showcert (argc - 1, &argv[1]);

	cert_creation_data->key_months_before_expiration = ca_ask_for_number (_("Introduce number of months before expiration of the new certificate (0 to cancel)"),
									      0,
									      ca_policy_get (ca_id, "MONTHS_TO_EXPIRE"), 
									      ca_policy_get (ca_id, "MONTHS_TO_EXPIRE"));
	
	if (cert_creation_data->key_months_before_expiration == -1) {
		g_free (cert_creation_data);
		return 1;
	}

	tmp = time (NULL);	
	cert_creation_data->activation = tmp;
	
	expiration_time = g_new (struct tm,1);
	localtime_r (&tmp, expiration_time);      
	expiration_time->tm_mon = expiration_time->tm_mon + cert_creation_data->key_months_before_expiration;
	expiration_time->tm_year = expiration_time->tm_year + (expiration_time->tm_mon / 12);
	expiration_time->tm_mon = expiration_time->tm_mon % 12;	
	cert_creation_data->expiration = mktime(expiration_time);
	g_free (expiration_time);

	printf (_("The certificate will be generated with the following uses and purposes:\n"));

	cert_creation_data->ca = ca_policy_get (ca_id, "CA");
	cert_creation_data->crl_signing = ca_policy_get (ca_id, "CRL_SIGN");
	cert_creation_data->digital_signature = ca_policy_get (ca_id, "DIGITAL_SIGNATURE");
	cert_creation_data->data_encipherment =  ca_policy_get (ca_id, "DATA_ENCIPHERMENT");
	cert_creation_data->key_encipherment = ca_policy_get (ca_id, "KEY_ENCIPHERMENT");
	cert_creation_data->non_repudiation = ca_policy_get (ca_id, "NON_REPUDIATION");
	cert_creation_data->key_agreement = ca_policy_get (ca_id, "KEY_AGREEMENT");

	cert_creation_data->email_protection = ca_policy_get (ca_id, "EMAIL_PROTECTION");
	cert_creation_data->code_signing = ca_policy_get (ca_id, "CODE_SIGNING");
	cert_creation_data->web_client =  ca_policy_get (ca_id, "TLS_WEB_CLIENT");
	cert_creation_data->web_server = ca_policy_get (ca_id, "TLS_WEB_SERVER");
	cert_creation_data->time_stamping = ca_policy_get (ca_id, "TIME_STAMPING");
	cert_creation_data->ocsp_signing = ca_policy_get (ca_id, "OCSP_SIGNING");
	cert_creation_data->any_purpose = ca_policy_get (ca_id, "ANY_PURPOSE");

	printf (_("The new certificate will be created with the following uses and purposes:\n"));
	__ca_callback_show_uses_and_purposes (cert_creation_data);
	
	while (ca_ask_for_confirmation (NULL, _("Do you want to change any property of the new certificate? Yes/[No]"), FALSE)) {

		if (ca_policy_get (ca_id, "CA")) {
			cert_creation_data->ca = ca_ask_for_confirmation (NULL, _("* Enable Certification Authority use? [Yes]/No"), TRUE);
		} else {
			printf (_("* Certification Authority use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "CRL_SIGN")) {
			cert_creation_data->crl_signing = ca_ask_for_confirmation (NULL, _("* Enable CRL Signing? [Yes]/No"), TRUE);
		} else {
			printf (_("* CRL signing use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "DIGITAL_SIGNATURE")) {
			cert_creation_data->digital_signature = ca_ask_for_confirmation (NULL, _("* Enable Digital Signature use? [Yes]/No"), TRUE);
		} else {
			printf (_("* Digital Signature use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "DATA_ENCIPHERMENT")) {
			cert_creation_data->data_encipherment = ca_ask_for_confirmation (NULL, _("Enable Data Encipherment use? [Yes]/No"), TRUE);
		} else {
			printf (_("* Data Encipherment use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "KEY_ENCIPHERMENT")) {
			cert_creation_data->key_encipherment = ca_ask_for_confirmation (NULL, _("Enable Key Encipherment use? [Yes]/No"), TRUE);
		} else {
			printf (_("* Key Encipherment use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "NON_REPUDIATION")) {
			cert_creation_data->non_repudiation = ca_ask_for_confirmation (NULL, _("Enable Non Repudiation use? [Yes]/No"), TRUE);
		} else {
			printf (_("* Non Repudiation use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "KEY_AGREEMENT")) {
			cert_creation_data->key_agreement = ca_ask_for_confirmation (NULL, _("Enable Key Agreement use? [Yes]/No"), TRUE);
		} else {
			printf (_("* Key Agreement use disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "EMAIL_PROTECTION")) {
			cert_creation_data->email_protection = ca_ask_for_confirmation (NULL, _("Enable Email Protection purpose? [Yes]/No"), TRUE);
		} else {
			printf (_("* Email Protection purpose disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "CODE_SIGNING")) {
			cert_creation_data->code_signing = ca_ask_for_confirmation (NULL, _("Enable Code Signing purpose? [Yes]/No"), TRUE);
		} else {
			printf (_("* Code Signing purpose disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "TLS_WEB_CLIENT")) {
			cert_creation_data->web_client = ca_ask_for_confirmation (NULL, _("Enable TLS Web Client purpose? [Yes]/No"), TRUE);
		} else {
			printf (_("* TLS Web Client purpose disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "TLS_WEB_SERVER")) {
			cert_creation_data->web_server = ca_ask_for_confirmation (NULL, _("Enable TLS Web Server purpose? [Yes]/No"), TRUE);
		} else {
			printf (_("* TLS Web Server purpose disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "TIME_STAMPING")) {
			cert_creation_data->time_stamping = ca_ask_for_confirmation (NULL, _("Enable Time Stamping purpose? [Yes]/No"), TRUE);
		} else {
			printf (_("* Time Stamping purpose disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "OCSP_SIGNING")) {
			cert_creation_data->ocsp_signing = ca_ask_for_confirmation (NULL, _("Enable OCSP Signing purpose? [Yes]/No"), TRUE);		} else {
			printf (_("* OCSP Signing purpose disabled by policy\n"));
		}

		if (ca_policy_get (ca_id, "ANY_PURPOSE")) {
			cert_creation_data->any_purpose = ca_ask_for_confirmation (NULL, _("Enable any purpose? [Yes]/No"), TRUE);
		} else {
			printf (_("* Any purpose disabled by policy\n"));
		}

		printf (_("The new certificate will be created with the following uses and purposes:\n"));
		__ca_callback_show_uses_and_purposes (cert_creation_data);
	
	}
	
	if (ca_ask_for_confirmation (_("All the mandatory data for the certificate generation has been gathered."), _("Do you want to proceed with the signing? [Yes]/No "), TRUE)) {

		ca_file_get_next_serial (&cert_creation_data->serial, ca_id);

		csr_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CSR, csr_id);
		pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
		crypted_pkey = pkey_manage_get_certificate_pkey (ca_id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
					      
		if (pem && crypted_pkey && dn) {
			PkeyManageData *csr_pkey = NULL;

			pkey_pem = pkey_manage_uncrypt (crypted_pkey, dn);

			if (! pkey_pem) {
				g_free (pem);
				pkey_manage_data_free (crypted_pkey);
				g_free (dn);
				return 2;
			}

			error = tls_generate_certificate (cert_creation_data, csr_pem, pem, pkey_pem, &certificate);
			if (error)
				ca_error_dialog (error);

			g_free (pkey_pem);
			if (! error) {
		
				csr_pkey = pkey_manage_get_csr_pkey (csr_id);
                        
				if (csr_pkey)
					if (csr_pkey->is_in_db)
						error = ca_file_insert_cert (cert_creation_data, cert_creation_data->ca, 1, csr_pkey->pkey_data, certificate);
					else
						error = ca_file_insert_cert (cert_creation_data, cert_creation_data->ca, 0, csr_pkey->external_file, certificate);			
				else
					error = ca_file_insert_cert (cert_creation_data, cert_creation_data->ca, 0, NULL, certificate);
                        
				if (!error)
					ca_file_remove_csr (csr_id);
				else 
					ca_error_dialog (error);
                        
				pkey_manage_data_free (csr_pkey);
			}
		}
		
		if (!error && preferences_get_gnome_keyring_export()) {
			TlsCert * cert = NULL;
			gchar *filename = NULL;
			gchar *directory = NULL;
			gchar *aux = NULL;
			cert = tls_parse_cert_pem (certificate);

			// We must calculate the name of the file. 
			// Basically, it will be the subject DN + issuer DN + sha1 fingerprint
			// with substitution of non-valid filename characters

			aux = g_strdup_printf ("%s_%s_%s.pem", cert->dn, cert->i_dn, cert->sha1);
                
			aux = g_strcanon (aux,
					  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.",
					  '_');
                
			directory = g_build_filename (g_get_home_dir(), ".gnome2", "keystore", NULL);
			filename = g_build_filename (g_get_home_dir(), ".gnome2", "keystore", aux, NULL);

			if (! g_mkdir_with_parents (directory, 0700)) {
				g_file_set_contents (filename, certificate, strlen(certificate), NULL);
			}

		}

		g_free (pem);
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);

		if (! error)
			printf (_("Certificate signed.\n"));

	} else {
		printf (_("Operation cancelled.\n"));
	}


	return 0;
}

int ca_callback_delete (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_crlgen (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_dhgen (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_changepassword (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_importfile (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_importdir (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showcert (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showcsr (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showpolicy (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_setpolicy (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showpreferences (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_setpreference (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_about (int argc, char **argv)
{
        printf (_("%s version %s\n%s\n"), PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_COPYRIGHT);
        printf (_("\nAuthors:\n%s\n\n"), PACKAGE_AUTHORS);
        if (strcmp ("translator-credits", _("translator-credits")))
            printf (_("Translators:\n%s\n"), _("translator-credits"));
	return 0;
}

int ca_callback_warranty  (int argc, char **argv)
{
        printf ("%s",
                _("THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY\n"
                  "APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT\n"
                  "HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY\n"
                  "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,\n"
                  "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\n"
                  "PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM\n"
                  "IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF\n"
                  "ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\n\n"
                  "For more information about warranty, see section 15 onwards of the GNU\n"
                  "General Public License. You should have received a copy of the GNU General\n"
                  "Public License along with this program. If not, see\n"
                  "<http://www.gnu.org/licenses/>.\n\n"));
	return 0;
}

int ca_callback_distribution  (int argc, char **argv)
{
        printf ("%s",
                _("This program is free software: you can redistribute it and/or modify\n"
                  "it under the terms of the GNU General Public License as published by\n"
                  "the Free Software Foundation, either version 3 of the License, or\n"
                  "(at your option) any later version.\n\n"
                  "This program is distributed in the hope that it will be useful,\n"
                  "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
                  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
                  "GNU General Public License for more details.\n\n"
                  "You should have received a copy of the GNU General Public License\n"
                  "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\n"));
	return 0;
}

int ca_callback_version  (int argc, char **argv)
{
        printf (_("%s version %s\n"), PACKAGE_NAME, PACKAGE_VERSION); 
	return 0;
}

int ca_callback_help  (int argc, char **argv)
{
	gint i;

	printf ("\n");
	printf (_("Available commands:\n"));
	printf (_("===================\n"));

	for (i=0; i < CA_COMMAND_NUMBER; i++) {
		printf ("* %s\n    %s\n", _(ca_commands[i].syntax), _(ca_commands[i].help));
	}
	return 0;
}

int ca_callback_exit (int argc, char **argv)
{
        printf (_("Exiting gnomint-cli...\n"));
        exit (0);
        return 0;
}

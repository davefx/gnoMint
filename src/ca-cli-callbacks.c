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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <glib-object.h>
#include <glib/gi18n.h>

#include "ca-cli-callbacks.h"
#include "ca-cli.h"
#include "dialog.h"
#include "ca_creation.h"
#include "ca_file.h"
#include "csr_creation.h"
#include "export.h"
#include "import.h"
#include "new_cert.h"
#include "pkey_manage.h"
#include "preferences.h"
#include "tls.h"
#include "crl.h"

extern CaCommand ca_commands[];
#define CA_COMMAND_NUMBER 31

extern gchar * gnomint_current_opened_file;
extern gchar * ca_creation_message;
extern gchar * csr_creation_message;


int ca_cli_callback_newdb (int argc, char **argv)
{
        gchar *filename = argv[1];
        gchar *error = NULL;

        if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
                /* The file already exists. We ask the user about overwriting it */
                
                if (! dialog_ask_for_confirmation (_("The file already exists, so it will be overwritten."), _("Are you sure? Yes/[No] "), FALSE)) 
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

int ca_cli_callback_opendb (int argc, char **argv)
{
	gchar *filename = argv[1];

	if (! ca_open (filename, FALSE)) {
                fprintf (stderr, _("Problem when opening '%s' CA database\n"), filename);
	} 

	return 0;
}

int ca_cli_callback_savedbas (int argc, char **argv)
{
        gchar *filename = argv[1];
        
        if (g_file_test(filename, G_FILE_TEST_EXISTS)) {
                /* The file already exists. We ask the user about overwriting it */
                
                if (! dialog_ask_for_confirmation (_("The file already exists, so it will be overwritten."), _("Are you sure? Yes/[No] "), FALSE)) 
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

int ca_cli_callback_status (int argc, char **argv)
{
	printf (_("Current opened file: %s\n"), gnomint_current_opened_file);
	printf (_("Number of certificates in file: %d\n"), ca_file_get_number_of_certs());
	printf (_("Number of CSRs in file: %d\n"), ca_file_get_number_of_csrs());

	return 0;
}

int __ca_cli_callback_listcert_aux (void *pArg, int argc, char **argv, char **columnNames)
{
#ifndef WIN32
	struct tm tmp;
#else
	struct tm *tmp = NULL;
#endif
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
#ifndef WIN32	
		gmtime_r (&aux_date, &tmp);
		strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tmp);
#else
		tmp = gmtime (&aux_date);
		strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tmp);
#endif
		printf (Q_("CertList Activation|%s\t"), model_time_str);
	}

	aux_date = atol(argv[CA_FILE_CERT_COLUMN_EXPIRATION]);
	if (aux_date == 0) {
		printf (Q_("CertList Expiration|\t"));
	} else {
#ifndef WIN32
		gmtime_r (&aux_date, &tmp);
		strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tmp);
#else
		tmp = gmtime (&aux_date);
		strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tmp);
#endif
		printf (Q_("CertList Expiration|%s\t"), model_time_str);
	}

	if (argc > CA_FILE_CERT_COLUMN_REVOCATION && argv[CA_FILE_CERT_COLUMN_REVOCATION]) {
		aux_date = atol(argv[CA_FILE_CERT_COLUMN_REVOCATION]);
		if (aux_date == 0) {
			printf (Q_("CertList Revocation|\n"));
		} else {	
#ifndef WIN32
			gmtime_r (&aux_date, &tmp);		
			strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tmp);
#else
			tmp = gmtime (&aux_date);
			strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tmp);
#endif
			printf (Q_("CertList Revocation|%s\n"), model_time_str);
		}
	} else {
		printf ("\n");
	}

	return 0;
}


int ca_cli_callback_listcert (int argc, char **argv)
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

	ca_file_foreach_crt (__ca_cli_callback_listcert_aux, see_revoked, GINT_TO_POINTER(see_revoked));
	return 0;
}

int __ca_cli_callback_listcsr_aux (void *pArg, int argc, char **argv, char **columnNames)
{
	printf (Q_("CsrList ID|%s\t"), argv[CA_FILE_CSR_COLUMN_ID]);

	printf (Q_("CsrList ParentID|%s\t"), (argv[CA_FILE_CSR_COLUMN_PARENT_ID] ? argv[CA_FILE_CSR_COLUMN_PARENT_ID] : Q_("CsrList ParentID|\t")));
	
	if (strlen(argv[CA_FILE_CSR_COLUMN_SUBJECT]) > 24)
		argv[CA_FILE_CSR_COLUMN_SUBJECT][24] = '\0';

	printf (Q_("CsrList Subject|%-24s\t"), argv[CA_FILE_CSR_COLUMN_SUBJECT]);

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


int ca_cli_callback_listcsr (int argc, char **argv)
{
	printf (_("Certificate Requests in Database:\n"));
	printf (_("Id.\tParent Id.\tCSR Subject\t\tKey in DB?\n"));

	ca_file_foreach_csr (__ca_cli_callback_listcsr_aux, NULL);
	return 0;
}




int ca_cli_callback_addcsr (int argc, char **argv)
{
	gboolean with_ca_id = FALSE;
	guint64 ca_id;

	gboolean c_force_same = FALSE;
	gboolean st_force_same = FALSE;
	gboolean l_force_same = FALSE;
	gboolean o_force_same = FALSE;
	gboolean ou_force_same = FALSE;

	gboolean change_data = FALSE;

	TlsCreationData *csr_creation_data = NULL;
	guint max_key_length;


	if (argc == 2) {
		ca_id = atoll (argv[1]);
		with_ca_id = TRUE;
		if (! ca_file_check_if_is_ca_id (ca_id)) {
			dialog_error (_("The given CA id. is not valid"));
			return -1;
		}
	}

	csr_creation_data = g_new0 (TlsCreationData, 1);

	if (with_ca_id) {
		TlsCert *tlscert = NULL;
		gchar *pem = NULL;

		pem = ca_file_get_public_pem_from_id (ca_id, CA_FILE_ELEMENT_TYPE_CERT);
		g_assert (pem);

                tlscert = tls_parse_cert_pem (pem);

                if (ca_file_policy_get_int (ca_id, "C_INHERIT")) {
                        c_force_same = ca_file_policy_get_int (ca_id, "C_FORCE_SAME");
			csr_creation_data->country = g_strdup (tlscert->c);
                } 
		
		if (ca_file_policy_get_int (ca_id, "ST_INHERIT")) {
			st_force_same = ca_file_policy_get_int (ca_id, "ST_FORCE_SAME");
			csr_creation_data->state = g_strdup (tlscert->st);
		}

		if (ca_file_policy_get_int (ca_id, "L_INHERIT")) {
			l_force_same = ca_file_policy_get_int (ca_id, "L_FORCE_SAME");
			csr_creation_data->city = g_strdup (tlscert->l);
		}

		if (ca_file_policy_get_int (ca_id, "O_INHERIT")) {
			o_force_same = ca_file_policy_get_int (ca_id, "O_FORCE_SAME");
			csr_creation_data->org = g_strdup (tlscert->o);
		}

		if (ca_file_policy_get_int (ca_id, "OU_INHERIT")) {
			ou_force_same = ca_file_policy_get_int (ca_id, "OU_FORCE_SAME");
			csr_creation_data->ou = g_strdup (tlscert->ou);
		}

		csr_creation_data->parent_ca_id_str = g_strdup_printf ("%"G_GUINT64_FORMAT, ca_id);
                
                tls_cert_free (tlscert);
	}

	// Enter default values
	csr_creation_data->key_type = 0;
	csr_creation_data->key_bitlength = 2048;

	do {
		gchar * aux;

		printf (_("Please enter data corresponding to subject of the Certificate Signing Request:\n"));

		if (! c_force_same) {
			aux = dialog_ask_for_string (_("Enter country (C)"), csr_creation_data->country);
			if (csr_creation_data->country)
				g_free (csr_creation_data->country);
			csr_creation_data->country = aux;
		}
		aux = NULL;

		if (! st_force_same) {
			aux = dialog_ask_for_string (_("Enter state or province (ST)"), csr_creation_data->state);
			if (csr_creation_data->state)
				g_free (csr_creation_data->state);
			csr_creation_data->state = aux;
			aux = NULL;
		}

		
		if (! l_force_same) {
			aux = dialog_ask_for_string (_("Enter locality or city (L)"), csr_creation_data->city);
			if (csr_creation_data->city)
				g_free (csr_creation_data->city);
			csr_creation_data->city = aux;
			aux = NULL;
		}
		
		if (! o_force_same) {
			aux = dialog_ask_for_string (_("Enter organization (O)"), csr_creation_data->org);
			if (csr_creation_data->org)
				g_free (csr_creation_data->org);
			csr_creation_data->org = aux;
			aux = NULL;
		}

		if (! ou_force_same) {
			aux = dialog_ask_for_string (_("Enter organizational unit (OU)"), csr_creation_data->ou);
			if (csr_creation_data->ou)
				g_free (csr_creation_data->ou);
			csr_creation_data->ou = aux;
			aux = NULL;
		}

		aux = dialog_ask_for_string (_("Enter common name (CN)"), csr_creation_data->cn);
		if (csr_creation_data->cn)
			g_free (csr_creation_data->cn);
		csr_creation_data->cn = aux;
		aux = NULL;

		do {
			if (aux)
				g_free (aux);

			aux = dialog_ask_for_string (_("Enter type of key you are going to create (RSA/DSA)"), (csr_creation_data->key_type ? "DSA" : "RSA"));
		} while (g_ascii_strcasecmp (aux, "RSA") && g_ascii_strcasecmp (aux, "DSA"));

		if (! g_ascii_strcasecmp (aux, "RSA")) {
			csr_creation_data->key_type = 0;
			max_key_length = 10240;
		} else if (! g_ascii_strcasecmp (aux, "DSA")) {
			csr_creation_data->key_type = 1;
			max_key_length = 3072;
		}
		g_free (aux);
		aux = NULL;
		
		do {
				csr_creation_data->key_bitlength = dialog_ask_for_number (_("Enter bitlength for the key (it must be a whole multiple of 1024)"),
											  1024, max_key_length, csr_creation_data->key_bitlength);
				
		} while (csr_creation_data->key_bitlength % 1024);

		printf (_("These are the provided CSR properties:\n"));

		printf (_("Subject:\n"));
		printf (_("\tDistinguished Name: "));
		if (csr_creation_data->country)
			printf ("C=%s/", csr_creation_data->country);
		if (csr_creation_data->state)
			printf ("ST=%s/", csr_creation_data->state);
		if (csr_creation_data->city)
			printf ("L=%s/", csr_creation_data->city);
		if (csr_creation_data->org)
			printf ("O=%s/", csr_creation_data->org);
		if (csr_creation_data->ou)
			printf ("OU=%s/", csr_creation_data->ou);
		if (csr_creation_data->cn)
			printf ("CN=%s", csr_creation_data->cn);
		printf ("\n");
		printf (_("Key pair\n"));
		printf (_("\tType: %s\n"), (csr_creation_data->key_type ? "DSA" : "RSA"));
		printf (_("\tKey bitlength: %d\n"), csr_creation_data->key_bitlength);

		change_data = dialog_ask_for_confirmation (NULL, _("Do you want to change anything? Yes/[No] "), FALSE);

	} while (change_data);

	if (dialog_ask_for_confirmation (_("You are about to create a Certificate Signing Request with these properties."),
				     _("Are you sure? [Yes]/No "), TRUE)) {
		csr_creation_thread (csr_creation_data);
		printf ("%s\n", csr_creation_message);
		
	} else {
		printf (_("Operation cancelled.\n"));
	}

	return 0;
}




int ca_cli_callback_addca (int argc, char **argv)
{
	gboolean change_data = FALSE;

	TlsCreationData *ca_creation_data = NULL;

	time_t tmp;
	struct tm * expiration_time;
#ifndef WIN32
	struct tm timer;
#else
	struct tm *timer = NULL;
#endif
	char model_time_str[100];

	ca_creation_data = g_new0 (TlsCreationData, 1);


	// Enter default values

	ca_creation_data->key_type = 0;
	ca_creation_data->key_bitlength = 2048;

	ca_creation_data->key_months_before_expiration = 240;


	do {
		gchar * aux;

		printf (_("Please enter data corresponding to subject of the new Certification Authority:\n"));

		aux = dialog_ask_for_string (_("Enter country (C)"), ca_creation_data->country);
		if (ca_creation_data->country)
			g_free (ca_creation_data->country);
		ca_creation_data->country = aux;
		aux = NULL;

		aux = dialog_ask_for_string (_("Enter state or province (ST)"), ca_creation_data->state);
		if (ca_creation_data->state)
			g_free (ca_creation_data->state);
		ca_creation_data->state = aux;
		aux = NULL;

		aux = dialog_ask_for_string (_("Enter locality or city (L)"), ca_creation_data->city);
		if (ca_creation_data->city)
			g_free (ca_creation_data->city);
		ca_creation_data->city = aux;
		aux = NULL;

		aux = dialog_ask_for_string (_("Enter organization (O)"), ca_creation_data->org);
		if (ca_creation_data->org)
			g_free (ca_creation_data->org);
		ca_creation_data->org = aux;
		aux = NULL;

		aux = dialog_ask_for_string (_("Enter organizational unit (OU)"), ca_creation_data->ou);
		if (ca_creation_data->ou)
			g_free (ca_creation_data->ou);
		ca_creation_data->ou = aux;
		aux = NULL;

		aux = dialog_ask_for_string (_("Enter common name (CN)"), ca_creation_data->cn);
		if (ca_creation_data->cn)
			g_free (ca_creation_data->cn);
		ca_creation_data->cn = aux;
		aux = NULL;

		do {
			if (aux)
				g_free (aux);

			aux = dialog_ask_for_string (_("Enter type of key you are going to create (RSA/DSA)"), (ca_creation_data->key_type ? "DSA" : "RSA"));
		} while (g_ascii_strcasecmp (aux, "RSA") && g_ascii_strcasecmp (aux, "DSA"));
		
		if (! g_ascii_strcasecmp (aux, "RSA")) {
			ca_creation_data->key_type = 0;
		} else if (! g_ascii_strcasecmp (aux, "DSA")) {
			ca_creation_data->key_type = 1;
		}
		g_free (aux);
		aux = NULL;
		
		do {
			ca_creation_data->key_bitlength = dialog_ask_for_number (_("Enter bitlength for the key (it must be a whole multiple of 1024)"),
									     1024,10240,ca_creation_data->key_bitlength);
		} while (ca_creation_data->key_bitlength % 1024);


		ca_creation_data->key_months_before_expiration = dialog_ask_for_number (_("Introduce number of months before expiration of the new certification authority"),
										    1, 600, 240);

		tmp = time (NULL);	
		ca_creation_data->activation = tmp;
	
		expiration_time = g_new (struct tm,1);

#ifndef WIN32
		localtime_r (&tmp, expiration_time);
#else
		expiration_time = localtime (&tmp);
#endif
		expiration_time->tm_mon = expiration_time->tm_mon + ca_creation_data->key_months_before_expiration;
		expiration_time->tm_year = expiration_time->tm_year + (expiration_time->tm_mon / 12);
		expiration_time->tm_mon = expiration_time->tm_mon % 12;	
		ca_creation_data->expiration = mktime(expiration_time);
#ifndef WIN32
		g_free (expiration_time);
#endif

		printf (_("These are the provided new CA properties:\n"));

		printf (_("Subject:\n"));
		printf (_("\tDistinguished Name: "));
		if (ca_creation_data->country)
			printf ("C=%s/", ca_creation_data->country);
		if (ca_creation_data->state)
			printf ("ST=%s/", ca_creation_data->state);
		if (ca_creation_data->city)
			printf ("L=%s/", ca_creation_data->city);
		if (ca_creation_data->org)
			printf ("O=%s/", ca_creation_data->org);
		if (ca_creation_data->ou)
			printf ("OU=%s/", ca_creation_data->ou);
		if (ca_creation_data->cn)
			printf ("CN=%s", ca_creation_data->cn);
		printf ("\n");
		printf (_("Key pair\n"));
		printf (_("\tType: %s\n"), (ca_creation_data->key_type ? "DSA" : "RSA"));
		printf (_("\tKey bitlength: %d\n"), ca_creation_data->key_bitlength);
		printf (_("Validity\n"));
		printf (_("Validity:\n"));
#ifndef WIN32
		gmtime_r (&ca_creation_data->activation, &timer);
		strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &timer);
#else
		timer = gmtime (&ca_creation_data->activation);
		strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), timer);
#endif		
		printf (_("\tActivated on: %s\n"), model_time_str);
		
#ifndef WIN32
		gmtime_r (&ca_creation_data->expiration, &timer);
		strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &timer);	
#else
		timer = gmtime (&ca_creation_data->expiration);
		strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), timer);	
#endif
		printf (_("\tExpires on: %s\n"), model_time_str);

		change_data = dialog_ask_for_confirmation (NULL, _("Do you want to change anything? Yes/[No] "), FALSE);

	} while (change_data);

	if (dialog_ask_for_confirmation (_("You are about to create a new Certification Authority with these properties."),
				     _("Are you sure? [Yes]/No "), TRUE)) {
		ca_creation_thread (ca_creation_data);
		printf ("%s\n", ca_creation_message);
		
	} else {
		printf (_("Operation cancelled.\n"));
	}

	return 0;
}








int ca_cli_callback_extractcertpkey (int argc, char **argv)
{
	guint64 id_cert = atoll(argv[1]);
	gchar *filename = argv[2];
	gchar *error = NULL;

	if (! ca_file_check_if_is_cert_id (id_cert)) {
		dialog_error (_("The given certificate id. is not valid"));
		return -1;
	}

	error = export_private_pkcs8 (id_cert, CA_FILE_ELEMENT_TYPE_CERT, filename);

	if (! error) {
		printf (_("Private key extracted successfully into file '%s'\n"), filename);
	} else {
		dialog_error (error);
		return 1;
	}

	return 0;
}


int ca_cli_callback_extractcsrpkey (int argc, char **argv)
{
	guint64 id_csr = atoll(argv[1]);
	gchar *filename = argv[2];
	gchar *error = NULL;

	if (! ca_file_check_if_is_csr_id (id_csr)) {
		dialog_error (_("The given CSR id. is not valid"));
		return -1;
	}

	error = export_private_pkcs8 (id_csr, CA_FILE_ELEMENT_TYPE_CSR, filename);

	if (! error) {
		printf (_("Private key extracted successfully into file '%s'\n"), filename);
	} else {
		dialog_error (error);
		return 1;
	}

	return 0;
}



int ca_cli_callback_revoke (int argc, char **argv)
{
	gchar *errmsg = NULL;
	guint64 id = atoll (argv[1]);

	if (! ca_file_check_if_is_cert_id (id)) {
		dialog_error (_("The given certificate id. is not valid"));
		return -1;
	}

	ca_cli_callback_showcert (argc, argv);

	if (dialog_ask_for_confirmation (_("This certificate will be revoked."), _("Are you sure? Yes/[No] "),  FALSE)) {
		errmsg = ca_file_revoke_crt (id);
		if (errmsg) {
			dialog_error (_(errmsg));
			
		} else {
			printf (_("Certificate revoked.\n"));
		}

	} else {
		printf (_("Operation cancelled.\n"));
	}


	return 0;
}


void __ca_cli_callback_show_uses_and_purposes (TlsCertCreationData *cert_creation_data)
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


int ca_cli_callback_sign (int argc, char **argv)
{
	TlsCertCreationData *cert_creation_data = NULL;
	
	guint64 csr_id;
	guint64 ca_id;

	csr_id = atoll(argv[1]);
	ca_id = atoll(argv[2]);

	if (! ca_file_check_if_is_csr_id (csr_id)) {
		dialog_error (_("The given CSR id. is not valid"));
		return -1;
	}


	cert_creation_data = g_new0 (TlsCertCreationData, 1);

	printf (_("You are about to sign the following Certificate Signing Request:\n"));
	ca_cli_callback_showcsr (argc, argv);
	printf (_("with the certificate corresponding to the next CA:\n"));
	ca_cli_callback_showcert (argc - 1, &argv[1]);

	cert_creation_data->key_months_before_expiration = dialog_ask_for_number (_("Introduce number of months before expiration of the new certificate (0 to cancel)"),
									      0,
									      ca_file_policy_get_int (ca_id, "MONTHS_TO_EXPIRE"), 
									      ca_file_policy_get_int (ca_id, "MONTHS_TO_EXPIRE"));
	
	if (cert_creation_data->key_months_before_expiration == 0) {
		g_free (cert_creation_data);
		printf (_("Operation cancelled.\n"));
	}

	cert_creation_data->ca = ca_file_policy_get_int (ca_id, "CA");
	cert_creation_data->crl_signing = ca_file_policy_get_int (ca_id, "CRL_SIGN");
	cert_creation_data->digital_signature = ca_file_policy_get_int (ca_id, "DIGITAL_SIGNATURE");
	cert_creation_data->data_encipherment =  ca_file_policy_get_int (ca_id, "DATA_ENCIPHERMENT");
	cert_creation_data->key_encipherment = ca_file_policy_get_int (ca_id, "KEY_ENCIPHERMENT");
	cert_creation_data->non_repudiation = ca_file_policy_get_int (ca_id, "NON_REPUDIATION");
	cert_creation_data->key_agreement = ca_file_policy_get_int (ca_id, "KEY_AGREEMENT");

	cert_creation_data->email_protection = ca_file_policy_get_int (ca_id, "EMAIL_PROTECTION");
	cert_creation_data->code_signing = ca_file_policy_get_int (ca_id, "CODE_SIGNING");
	cert_creation_data->web_client =  ca_file_policy_get_int (ca_id, "TLS_WEB_CLIENT");
	cert_creation_data->web_server = ca_file_policy_get_int (ca_id, "TLS_WEB_SERVER");
	cert_creation_data->time_stamping = ca_file_policy_get_int (ca_id, "TIME_STAMPING");
	cert_creation_data->ocsp_signing = ca_file_policy_get_int (ca_id, "OCSP_SIGNING");
	cert_creation_data->any_purpose = ca_file_policy_get_int (ca_id, "ANY_PURPOSE");

	printf (_("The new certificate will be created with the following uses and purposes:\n"));
	__ca_cli_callback_show_uses_and_purposes (cert_creation_data);
	
	while (dialog_ask_for_confirmation (NULL, _("Do you want to change any property of the new certificate? Yes/[No] "), FALSE)) {

		if (ca_file_policy_get_int (ca_id, "CA")) {
			cert_creation_data->ca = dialog_ask_for_confirmation (NULL, _("* Enable Certification Authority use? [Yes]/No "), TRUE);
		} else {
			printf (_("* Certification Authority use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "CRL_SIGN")) {
			cert_creation_data->crl_signing = dialog_ask_for_confirmation (NULL, _("* Enable CRL Signing? [Yes]/No "), TRUE);
		} else {
			printf (_("* CRL signing use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "DIGITAL_SIGNATURE")) {
			cert_creation_data->digital_signature = dialog_ask_for_confirmation (NULL, _("* Enable Digital Signature use? [Yes]/No "), TRUE);
		} else {
			printf (_("* Digital Signature use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "DATA_ENCIPHERMENT")) {
			cert_creation_data->data_encipherment = dialog_ask_for_confirmation (NULL, _("Enable Data Encipherment use? [Yes]/No "), TRUE);
		} else {
			printf (_("* Data Encipherment use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "KEY_ENCIPHERMENT")) {
			cert_creation_data->key_encipherment = dialog_ask_for_confirmation (NULL, _("Enable Key Encipherment use? [Yes]/No "), TRUE);
		} else {
			printf (_("* Key Encipherment use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "NON_REPUDIATION")) {
			cert_creation_data->non_repudiation = dialog_ask_for_confirmation (NULL, _("Enable Non Repudiation use? [Yes]/No "), TRUE);
		} else {
			printf (_("* Non Repudiation use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "KEY_AGREEMENT")) {
			cert_creation_data->key_agreement = dialog_ask_for_confirmation (NULL, _("Enable Key Agreement use? [Yes]/No "), TRUE);
		} else {
			printf (_("* Key Agreement use disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "EMAIL_PROTECTION")) {
			cert_creation_data->email_protection = dialog_ask_for_confirmation (NULL, _("Enable Email Protection purpose? [Yes]/No "), TRUE);
		} else {
			printf (_("* Email Protection purpose disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "CODE_SIGNING")) {
			cert_creation_data->code_signing = dialog_ask_for_confirmation (NULL, _("Enable Code Signing purpose? [Yes]/No "), TRUE);
		} else {
			printf (_("* Code Signing purpose disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "TLS_WEB_CLIENT")) {
			cert_creation_data->web_client = dialog_ask_for_confirmation (NULL, _("Enable TLS Web Client purpose? [Yes]/No "), TRUE);
		} else {
			printf (_("* TLS Web Client purpose disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "TLS_WEB_SERVER")) {
			cert_creation_data->web_server = dialog_ask_for_confirmation (NULL, _("Enable TLS Web Server purpose? [Yes]/No "), TRUE);
		} else {
			printf (_("* TLS Web Server purpose disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "TIME_STAMPING")) {
			cert_creation_data->time_stamping = dialog_ask_for_confirmation (NULL, _("Enable Time Stamping purpose? [Yes]/No "), TRUE);
		} else {
			printf (_("* Time Stamping purpose disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "OCSP_SIGNING")) {
			cert_creation_data->ocsp_signing = dialog_ask_for_confirmation (NULL, _("Enable OCSP Signing purpose? [Yes]/No "), TRUE);		} else {
			printf (_("* OCSP Signing purpose disabled by policy\n"));
		}

		if (ca_file_policy_get_int (ca_id, "ANY_PURPOSE")) {
			cert_creation_data->any_purpose = dialog_ask_for_confirmation (NULL, _("Enable any purpose? [Yes]/No "), TRUE);
		} else {
			printf (_("* Any purpose disabled by policy\n"));
		}

		printf (_("The new certificate will be created with the following uses and purposes:\n"));
		__ca_cli_callback_show_uses_and_purposes (cert_creation_data);
	
	}
	
	if (dialog_ask_for_confirmation (_("All the mandatory data for the certificate generation has been gathered."), _("Do you want to proceed with the signing? [Yes]/No "), TRUE)) {

		const gchar * strerror = new_cert_sign_csr (csr_id, ca_id, cert_creation_data);
		if (strerror)
			dialog_error ((gchar *) strerror);
		else
			printf (_("Certificate signed.\n"));

	} else {
		printf (_("Operation cancelled.\n"));
	}


	return 0;
}

int ca_cli_callback_delete (int argc, char **argv)
{
	gchar *errmsg = NULL;
	guint64 id = atoll (argv[1]);

	if (! ca_file_check_if_is_csr_id (id)) {
		dialog_error (_("The given CSR id. is not valid"));
		return -1;
	}

	ca_cli_callback_showcsr (argc, argv);

	if (dialog_ask_for_confirmation (_("This Certificate Signing Request will be deleted."), _("This operation cannot be undone. Are you sure? Yes/[No] "),  FALSE)) {
		errmsg = ca_file_remove_csr (id);
		if (errmsg) {
			dialog_error (_(errmsg));
			
		} else {
			printf (_("Certificate Signing Request deleted.\n"));
		}

	} else {
		printf (_("Operation cancelled.\n"));
	}


	return 0;
}

int ca_cli_callback_crlgen (int argc, char **argv)
{
	guint64 id_ca = atoll(argv[1]);
	gchar *filename = argv[2];
	gchar *error = NULL;

	if (! ca_file_check_if_is_ca_id (id_ca)) {
		dialog_error (_("The given CA id. is not valid"));
		return -1;
	}

	error = crl_generate (id_ca, g_strdup(filename));

	if (! error) {
		printf (_("CRL generated successfully into file '%s'\n"), filename);
	} else {
		dialog_error (error);
		return 1;
	}

	return 0;
}

int ca_cli_callback_dhgen (int argc, char **argv)
{
	gint primebitlength = atoi (argv[1]);
	gchar *filename = argv[2];
	
	gchar *error = NULL;

	if (primebitlength == 0 || primebitlength % 1024) {
		dialog_error (_("The bit-length of the prime number must be whole multiple of 1024"));
		return 1;
	}

	error = export_dh_param (primebitlength, filename);

	if (error)
		dialog_error (error);
	else
		printf (_("Diffie-Hellman parameters created and saved successfully in file '%s'\n"), filename);
	return 0;
}

int ca_cli_callback_changepassword (int argc, char **argv)
{
	gchar *current_pwd = NULL;
	gchar *password = NULL;

	// First, we check the current status

	if (! ca_file_is_password_protected()) {
		if (dialog_ask_for_confirmation (_("Currently, the database is not password-protected."), _("Do you want to password protect it? [Yes]/No "),  TRUE)) {
			password = dialog_get_password (_("OK. You need to supply a password for protecting the private keys in the\n"
							     "database, so nobody else but authorized people can use them. This password\n"
							     "will be asked any time gnoMint will make use of any private key in database."),
							   _("Insert password:"), _("Insert password (confirm):"), 
							   _("The introduced passwords are distinct."), 0);
			if (! password) {
				printf (_("Operation cancelled.\n"));
				return 1;
			} 
			
			if (! ca_file_password_protect (password)) {
				dialog_error (_("Error while establishing database password. The operation was cancelled."));
				g_free (password);
				return 2;
			} else {
				printf (_("Password established successfully.\n"));
				g_free (password);
				return 0;
			}
			

		} else {
			printf (_("Nothing done.\n"));
			return 0;
		}
	} else {
		if (dialog_ask_for_confirmation (_("Currently, the database IS password-protected."), _("Do you want to remove this password protection? Yes/[No] "),  FALSE)) {
			do {
				if (current_pwd)
					g_free (current_pwd);
				printf (_("For removing the password-protection, the current database password\nmust be supplied.\n"));
				current_pwd = dialog_ask_for_password (_("Please, insert the current database password (Empty to cancel): "));
				if (! current_pwd) {
					printf (_("Operation cancelled.\n"));
					return 3;
				}

				if (! ca_file_check_password (current_pwd)) {
					dialog_error (_("The current password you have entered\ndoesn't match with the actual current database password."));
				} 
			} while (! ca_file_check_password(current_pwd));

			if (! ca_file_password_unprotect (current_pwd)) {
				dialog_error (_("Error while removing database password. \n"
						   "The operation was cancelled."));
				g_free (current_pwd);
				return 4;
			} else {
				printf (_("Password removed successfully.\n"));
				g_free (current_pwd);
				g_free (password);				
				return 0;
			}

		} else {
			do {
				if (current_pwd)
					g_free (current_pwd);
				printf (_("You must supply the current database password before changing the password.\n"));
				current_pwd = dialog_ask_for_password (_("Please, insert the current database password (Empty to cancel): "));
				if (! current_pwd) {
					printf (_("Operation cancelled.\n"));
					return 3;
				}

				if (! ca_file_check_password (current_pwd)) {
					dialog_error (_("The current password you have entered\ndoesn't match with the actual current database password."));
				}
			} while (! ca_file_check_password(current_pwd));

			password = dialog_get_password (_("OK. Now you must supply a new password for protecting the private keys in the\n"
							     "database, so nobody else but authorized people can use them. This password\n"
							     "will be asked any time gnoMint will make use of any private key in database."),
							   _("Insert new password:"), _("Insert new password (confirm):"), 
							   _("The introduced passwords are distinct."), 0);
			if (! password) {
				printf (_("Operation cancelled.\n"));
				g_free (current_pwd);
				return 4;
			} 

			if (! ca_file_password_change (current_pwd, password)) {
				dialog_error (_("Error while changing database password. \n"
						   "The operation was cancelled."));
				g_free (current_pwd);
				g_free (password);
				return 5;
			} else {
				printf (_("Password changed successfully.\n"));
				g_free (current_pwd);
				g_free (password);				
				return 0;
			}				

		
		}
	}

	return 0;
}

int ca_cli_callback_importfile (int argc, char **argv)
{
	gchar *filename = argv[1];

	if (! import_single_file (filename, NULL, NULL)) {
		dialog_error (_("Problem when importing the given file."));
		return 1;
	} else {
		printf (_("File imported successfully.\n"));
	}

	return 0;
}

int ca_cli_callback_importdir (int argc, char **argv)
{
	gchar *filename = argv[1];
	gchar *error = NULL;

	error = import_whole_dir (filename);
	if (error) {
		dialog_error (error);
		return 1;
	} else {
		printf (_("Directory imported successfully.\n"));
	}

	
	return 0;
}

int ca_cli_callback_showcert (int argc, char **argv)
{
	guint64 cert_id = atoll(argv[1]);
	gchar * certificate_pem;
	
	TlsCert * cert = NULL;
#ifndef WIN32
	struct tm tim;
#else
	struct tm *tim = NULL;
#endif
	gchar model_time_str[100];
	gchar *aux;
	UInt160 *serial_number;

	gint i;

	if (! ca_file_check_if_is_cert_id (cert_id)) {
		dialog_error (_("The given certificate id. is not valid"));
		return -1;
	}

	certificate_pem = ca_file_get_public_pem_from_id(CA_FILE_ELEMENT_TYPE_CERT, cert_id);

	cert = tls_parse_cert_pem (certificate_pem);
	
	printf (_("Certificate:\n"));

	serial_number = &cert->serial_number;
        aux = uint160_strdup_printf (&cert->serial_number);
	printf (_("\tSerial number: %s\n"), aux);
        g_free (aux);

	printf (_("Subject:\n"));
	printf (_("\tDistinguished Name: %s\n"), (cert->dn ? cert->dn : _("None.")));
	printf (_("\tUnique ID: %s\n"), (cert->subject_key_id ? cert->subject_key_id : _("None.")));
	
	printf (_("Issuer:\n"));
	printf (_("\tDistinguished Name: %s\n"), (cert->i_dn ? cert->i_dn : _("None.")));
	printf (_("\tUnique ID: %s\n"), (cert->issuer_key_id ? cert->issuer_key_id : _("None.")));
	
	printf (_("Validity:\n"));
#ifndef WIN32
	gmtime_r (&cert->activation_time, &tim);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tim);	
#else
	tim = gmtime (&cert->activation_time);
	strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tim);	
#endif
	printf (_("\tActivated on: %s\n"), model_time_str);

#ifndef WIN32
	gmtime_r (&cert->expiration_time, &tim);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tim);	
#else
	tim = gmtime (&cert->expiration_time);
	strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tim);	
#endif
	printf (_("\tExpires on: %s\n"), model_time_str);

	printf (_("Fingerprints:\n"));
	printf (_("\tSHA1 fingerprint: %s\n"), cert->sha1);
	printf (_("\tMD5 fingerprint: %s\n"), cert->md5);
	printf (_("\tSHA256 fingerprint: %s\n"), cert->sha256);

	if (g_list_length (cert->uses)) {
		printf (_("Certificate uses:\n"));
		for (i = g_list_length(cert->uses) - 1; i >= 0; i--) {
			printf ("\t%s\n", (gchar *) g_list_nth_data (cert->uses, i));
		}
	}

	tls_cert_free (cert);

	return 0;
}

int ca_cli_callback_showcsr (int argc, char **argv)
{
	guint64 csr_id = atoll(argv[1]);
	gchar * csr_pem;
	
	TlsCsr * csr = NULL;

	if (! ca_file_check_if_is_csr_id (csr_id)) {
		dialog_error (_("The given CSR id. is not valid"));
		return -1;
	}


	csr_pem = ca_file_get_public_pem_from_id(CA_FILE_ELEMENT_TYPE_CSR, csr_id);

	csr = tls_parse_csr_pem (csr_pem);
	
	printf (_("Certificate Signing Request:\n"));

	printf (_("Subject:\n"));
	printf (_("\tDistinguished Name: %s\n"), csr->dn);
	#ifdef ADVANCED_GNUTLS
	printf (_("\tUnique ID: %s\n"), csr->key_id);
	#endif

	tls_csr_free (csr);

	return 0;
}

typedef enum {
	CA_CLI_CALLBACK_POLICY_C_INHERIT = 0,
	CA_CLI_CALLBACK_POLICY_ST_INHERIT = 1,
	CA_CLI_CALLBACK_POLICY_L_INHERIT = 2,
	CA_CLI_CALLBACK_POLICY_O_INHERIT = 3,
	CA_CLI_CALLBACK_POLICY_OU_INHERIT = 4,
	CA_CLI_CALLBACK_POLICY_C_FORCE_SAME = 5,
	CA_CLI_CALLBACK_POLICY_ST_FORCE_SAME = 6,
	CA_CLI_CALLBACK_POLICY_L_FORCE_SAME = 7,
	CA_CLI_CALLBACK_POLICY_O_FORCE_SAME = 8,
	CA_CLI_CALLBACK_POLICY_OU_FORCE_SAME = 9,
	CA_CLI_CALLBACK_POLICY_HOURS_BETWEEN_CRL_UPDATES = 10,
	CA_CLI_CALLBACK_POLICY_CRL_DISTRIBUTION_POINT = 11,
	CA_CLI_CALLBACK_POLICY_MONTHS_TO_EXPIRE = 12,
	CA_CLI_CALLBACK_POLICY_CA = 13,
	CA_CLI_CALLBACK_POLICY_CRL_SIGN = 14,
	CA_CLI_CALLBACK_POLICY_NON_REPUTATION = 15,
	CA_CLI_CALLBACK_POLICY_DIGITAL_SIGNATURE = 16,
	CA_CLI_CALLBACK_POLICY_KEY_ENCIPHERMENT = 17,
	CA_CLI_CALLBACK_POLICY_KEY_AGREEMENT = 18,
	CA_CLI_CALLBACK_POLICY_DATA_ENCIPHERMENT = 19,
	CA_CLI_CALLBACK_POLICY_TLS_WEB_SERVER = 20,
	CA_CLI_CALLBACK_POLICY_TLS_WEB_CLIENT = 21,
	CA_CLI_CALLBACK_POLICY_TIME_STAMPING = 22,
	CA_CLI_CALLBACK_POLICY_CODE_SIGNING = 23,
	CA_CLI_CALLBACK_POLICY_EMAIL_PROTECTION = 24,
	CA_CLI_CALLBACK_POLICY_OCSP_SIGNING = 25,
	CA_CLI_CALLBACK_POLICY_ANY_PURPOSE = 26,
	CA_CLI_CALLBACK_POLICY_NUMBER = 27
} CaCallbackPolicy;

static gchar *CaCallbackPolicyName[CA_CLI_CALLBACK_POLICY_NUMBER] = {
	"C_INHERIT",
	"ST_INHERIT",
	"L_INHERIT",
	"O_INHERIT",
	"OU_INHERIT",
	"C_FORCE_SAME",
	"ST_FORCE_SAME",
	"L_FORCE_SAME",
	"O_FORCE_SAME",
	"OU_FORCE_SAME",
	"HOURS_BETWEEN_CRL_UPDATES",
	"CRL_DISTRIBUTION_POINT",
	"MONTHS_TO_EXPIRE",
	"CA",
	"CRL_SIGN",
	"NON_REPUDIATION",
	"DIGITAL_SIGNATURE",
	"KEY_ENCIPHERMENT",
	"KEY_AGREEMENT",
	"DATA_ENCIPHERMENT",
	"TLS_WEB_SERVER",
	"TLS_WEB_CLIENT",
	"TIME_STAMPING",
	"CODE_SIGNING",
	"EMAIL_PROTECTION",
	"OCSP_SIGNING",
	"ANY_PURPOSE"
};

static gchar *CaCallbackPolicyDescriptions[CA_CLI_CALLBACK_POLICY_NUMBER] = {
	N_("Generated certs inherit Country from CA                           "),
	N_("Generated certs inherit State from CA                             "),
	N_("Generated certs inherit Locality from CA                          "),
	N_("Generated certs inherit Organization from CA                      "),
	N_("Generated certs inherit Organizational Unit from CA               "),
	N_("Country in generated certs must be the same than in CA            "),
	N_("State in generated certs must be the same than in CA              "),
	N_("Locality in generated certs must be the same than in CA           "),
	N_("Organization in generated certs must be the same than in CA       "),
	N_("Organizational Unit in generated certs must be the same than in CA"),
	N_("Maximum number of hours between CRL updates                       "),
	N_("CRL distribution point (URL where CRL is published)               "),
	N_("Maximum number of months before expiration of new certs           "),
	N_("CA use enabled in generated certs                                 "),
	N_("CRL Sign use enabled in generated certs                           "),
	N_("Non reputation use enabled in generated certs                     "),
	N_("Digital signature use enabled in generated certs                  "),
	N_("Key encipherment use enabled in generated certs                   "),
	N_("Key agreement use enabled in generated certs                      "),
	N_("Data encipherment use enabled in generated certs                  "),
	N_("TLS web server purpose enabled in generated certs                 "),
	N_("TLS web client purpose enabled in generated certs                 "),
	N_("Time stamping purpose enabled in generated certs                  "),
	N_("Code signing server purpose enabled in generated certs            "),
	N_("Email protection purpose enabled in generated certs               "),
	N_("OCSP signing purpose enabled in generated certs                   "),
	N_("Any purpose enabled in generated certs                            ")};
                                                                                

int ca_cli_callback_showpolicy (int argc, char **argv)
{
	guint64 ca_id = atoll(argv[1]);
	gint i;


	if (! ca_file_check_if_is_ca_id (ca_id)) {
		dialog_error (_("The given CA id. is not valid"));
		return -1;
	}
	
	printf (_("Showing policies of the following certificate:\n"));
	ca_cli_callback_showcert (argc, argv);
	printf (_("\nPolicies:\n"));
	
	printf (_("Id.\tDescription\t\t\t\t\t\t\t\tValue\n"));
	for (i = 0; i < CA_CLI_CALLBACK_POLICY_NUMBER; i++) {

		printf ("%d\t%s\t%s\n", i, CaCallbackPolicyDescriptions[i], ca_file_policy_get(ca_id, CaCallbackPolicyName[i]));

	}


	return 0;
}

int ca_cli_callback_setpolicy (int argc, char **argv)
{
	guint64 ca_id = atoll(argv[1]);
	gint policy_id = atoi (argv[2]);
	gchar *value = argv[3];
	gchar *message = NULL;
	gchar *description = NULL;
	gint i;

	if (! ca_file_check_if_is_ca_id (ca_id)) {
		dialog_error (_("The given CA id. is not valid"));
		return -1;
	}
	
	if (policy_id < 0 || policy_id >= CA_CLI_CALLBACK_POLICY_NUMBER) {
		dialog_error (_("The given policy id is not valid"));
		return -2;
	}

	description = g_strdup (CaCallbackPolicyDescriptions[policy_id]);
	for (i=strlen (description) - 1; i>=0; i--) {
		if (description[i] != ' ') {
			description[i+1] = '\0';
			break;
		}
	}

	message = g_strdup_printf (_("You are about to assign to the policy\n'%s' the new value '%s'."), description, value);
	g_free (description);


	if (dialog_ask_for_confirmation (message, _("Are you sure? Yes/[No] : "), FALSE)) {
		if (! ca_file_policy_set (ca_id, CaCallbackPolicyName[policy_id], value)) {
			g_free (message);
			return -1;
		} else
			printf (_("Policy set correctly to '%s'.\n"), value);
			
		
	} else {
		printf (_("Operation cancelled.\n"));
	}

	g_free (message);

	return 0;
}

int ca_cli_callback_showpreferences (int argc, char **argv)
{
	printf (_("gnoMint-cli current preferences:\n"));

	printf (_("Id.\tName\t\t\tValue\n"));
	printf (_("0\tGnome keyring support\t%d\n"), preferences_get_gnome_keyring_export());
	
	return 0;
}

int ca_cli_callback_setpreference (int argc, char **argv)
{
	gint preference_id = atoi (argv[1]);
	gint value = atoi (argv[2]);
	gchar *message = NULL;

	if (preference_id != 0) {
		dialog_error (_("The given preference id is not valid"));
		return -1;
	}

	switch (preference_id) {
	case 0:
		message = g_strdup_printf (_("You are about to assign to the preference 'Gnome keyring support' the new value '%d'."), value);
		break;
	}

	if (dialog_ask_for_confirmation (message, _("Are you sure? Yes/[No] : "), FALSE)) {
		switch (preference_id) {
		case 0:
			preferences_set_gnome_keyring_export (value);
			break;
		}

	} else {
		printf (_("Operation cancelled.\n"));
	}
	
	g_free (message);
	
	return 0;
}

int ca_cli_callback_about (int argc, char **argv)
{
        printf (_("%s version %s\n%s\n"), PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_COPYRIGHT);
        printf (_("\nAuthors:\n%s\n\n"), PACKAGE_AUTHORS);
        if (strcmp ("translator-credits", _("translator-credits")))
            printf (_("Translators:\n%s\n"), _("translator-credits"));
	return 0;
}

int ca_cli_callback_warranty  (int argc, char **argv)
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

int ca_cli_callback_distribution  (int argc, char **argv)
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

int ca_cli_callback_version  (int argc, char **argv)
{
        printf (_("%s version %s\n"), PACKAGE_NAME, PACKAGE_VERSION); 
	return 0;
}

int ca_cli_callback_help  (int argc, char **argv)
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

int ca_cli_callback_exit (int argc, char **argv)
{
        printf (_("Exiting gnomint-cli...\n"));
        exit (0);
        return 0;
}

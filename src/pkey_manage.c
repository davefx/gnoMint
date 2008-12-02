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

#ifndef GNOMINTCLI
#include <glade/glade.h>
#include <glib-object.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#endif

#include <glib.h>
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tls.h"
#include "ca_file.h"
#include "ca.h"
#include "pkey_manage.h"

#include <glib/gi18n.h>

#define PKEY_MANAGE_ENCRYPTED_PKCS8_HEADER "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define PKEY_MANAGE_UNCRYPTED_PKCS8_HEADER "-----BEGIN PRIVATE KEY-----"

gchar * __pkey_manage_ask_external_file_password (const gchar *cert_dn);
gchar * __pkey_retrieve_from_file (gchar **fn, gchar *cert_pem);
gchar * __pkey_manage_to_hex (const guchar *buffer, size_t len);
guchar * __pkey_manage_from_hex (const gchar *input);
guchar *__pkey_manage_create_key(const gchar *password);
gchar * __pkey_manage_aes_encrypt (const gchar *in, const gchar *password);
gchar * __pkey_manage_aes_decrypt (const gchar *string, const gchar *password);

#ifndef GNOMINTCLI
// CALLBACKS
gboolean pkey_manage_filechooser_file_set_cb (GtkFileChooserButton *widget, gpointer user_data);

gchar * __pkey_manage_ask_external_file_password (const gchar *cert_dn)
{
	gchar *password;
	GtkWidget * widget = NULL, * password_widget = NULL, *remember_password_widget = NULL;
	GladeXML * dialog_xml = NULL;
	gchar     * xml_file = NULL;
	gint response = 0;
	gchar *message = NULL;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "get_db_password_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	

	password_widget = glade_xml_get_widget (dialog_xml, "cadb_password_entry");

	remember_password_widget = glade_xml_get_widget (dialog_xml, "remember_password_checkbutton");
	g_object_set (G_OBJECT(remember_password_widget), "visible", FALSE, NULL);

	widget = glade_xml_get_widget (dialog_xml, "get_passwd_msg_label");

	message = g_strdup_printf (_("The file that holds private key for certificate '%s' is password-protected.\n\n"
				     "Please, insert the password corresponding to this file."), cert_dn);
	gtk_label_set_text (GTK_LABEL(widget), message);

	gtk_widget_grab_focus (password_widget);
	
	widget = glade_xml_get_widget (dialog_xml, "get_db_password_dialog");
	response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
	if (!response) {
		gtk_widget_destroy (widget);
		g_object_unref (G_OBJECT(dialog_xml));
		g_free (message);
		return NULL;
	} else {
		password = g_strdup ((gchar *) gtk_entry_get_text (GTK_ENTRY(password_widget)));
	}
	
	widget = glade_xml_get_widget (dialog_xml, "get_db_password_dialog");
	gtk_widget_destroy (widget);
	g_object_unref (G_OBJECT(dialog_xml));

	g_free (message);

	return password;
}


gboolean pkey_manage_filechooser_file_set_cb (GtkFileChooserButton *widget, gpointer user_data)
{
	GtkWidget *remember_filepath_widget = NULL;

	remember_filepath_widget = g_object_get_data (G_OBJECT(widget), "save_filename_checkbutton");
	g_object_set (G_OBJECT(remember_filepath_widget), "visible", TRUE, NULL);

	return FALSE;
}

#else
gchar * __pkey_manage_ask_external_file_password (const gchar *cert_dn)
{
        /* FIXME */
        return NULL;
}

#endif

gchar * __pkey_retrieve_from_file (gchar **fn, gchar *cert_pem)
{
	gsize file_length = 0;
	GError *error = NULL;
	gboolean cancel = FALSE;

	gboolean save_new_filename = FALSE;
	gchar *file_name = g_strdup(* fn);

	gchar *file_contents = NULL;

	gchar *pem_pkey = NULL;

	gint tls_error = 0;
	gchar *password = NULL;

	TlsCert *cert = tls_parse_cert_pem (cert_pem);		

	do {
		if (g_file_test(file_name, G_FILE_TEST_EXISTS)) {
			GIOChannel *gc = g_io_channel_new_file (file_name, "r", &error);
			if (gc) {
				g_io_channel_read_to_end (gc, &file_contents, &file_length, &error);
				g_io_channel_close (gc);
				
				do {
					pem_pkey = tls_load_pkcs8_private_key (file_contents, password, cert->key_id, &tls_error);
					
					if (tls_error == TLS_INVALID_PASSWORD) {
						// We ask for a password
						password = __pkey_manage_ask_external_file_password (cert->dn);
						
						if (! password)
							cancel = TRUE;
					} 
					
				} while (tls_error == TLS_INVALID_PASSWORD && ! cancel);
				
				g_free (password);
				
				if (! pem_pkey) {
					if (tls_error == TLS_NON_MATCHING_PRIVATE_KEY) {
						// The file could be opened, but it didn't contain any recognized private key
						ca_error_dialog (_("The designated file contains a private key, but it "
								   "is not the private key corresponding to the certificate."));
					} else {
						// The file could be opened, but it didn't contain any recognized private key
						ca_error_dialog (_("The designated file didn't contain any recognized private key."));
					}
				}
			} else {
				// The file cannot be opened
				ca_error_dialog (_("The designated file couldn't be opened."));
				
			}
		} else {
			// The file doesn't exist
			ca_error_dialog (_("File designated in database doesn't exist."));
			
		}
		
		if (! pem_pkey && ! cancel) {

                        #ifndef GNOMINTCLI
			// Show file open dialog
			
			GtkWidget * widget = NULL, * filepath_widget = NULL, *remember_filepath_widget = NULL;
			GladeXML * dialog_xml = NULL;
			gchar     * xml_file = NULL;
			gint response = 0;
			
			xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
			dialog_xml = glade_xml_new (xml_file, "get_pkey_dialog", NULL);
			g_free (xml_file);
			glade_xml_signal_autoconnect (dialog_xml); 	
			
			filepath_widget = glade_xml_get_widget (dialog_xml, "pkey_filechooser");
			
			remember_filepath_widget = glade_xml_get_widget (dialog_xml, "save_filename_checkbutton");
			g_object_set (G_OBJECT(remember_filepath_widget), "visible", FALSE, NULL);
			
			gtk_widget_grab_focus (filepath_widget);
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER(filepath_widget), file_name); 
			g_object_set_data (G_OBJECT(filepath_widget), "save_filename_checkbutton", remember_filepath_widget);

			widget = glade_xml_get_widget (dialog_xml, "cert_dn_label");
			gtk_label_set_text (GTK_LABEL(widget), cert->dn);
			
			widget = glade_xml_get_widget (dialog_xml, "get_pkey_dialog");
			response = gtk_dialog_run(GTK_DIALOG(widget)); 
			
			if (! response) {
				cancel = TRUE;
			} else {
				g_free (file_name);
				file_name = g_strdup ((gchar *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER(filepath_widget)));
				save_new_filename = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(remember_filepath_widget));
			}
			
			widget = glade_xml_get_widget (dialog_xml, "get_pkey_dialog");
			gtk_widget_destroy (widget);
			g_object_unref (G_OBJECT(dialog_xml));

                        #else
                        cancel = TRUE;
                        #endif

		}
	} while (! pem_pkey && ! cancel);

	tls_cert_free (cert);
	g_free (file_contents);					
	g_error_free (error);

	if (cancel) {
		g_free (file_name);
		return NULL;
	}

	if (save_new_filename) {
		g_free (*fn);
		(* fn) = file_name;
	}
	
	return pem_pkey;						
}


PkeyManageData * pkey_manage_get_certificate_pkey (guint64 id)
{
	PkeyManageData *res = NULL;
	
	res = g_new0 (PkeyManageData, 1);
	
	if (ca_file_get_pkey_in_db_from_id (CA_FILE_ELEMENT_TYPE_CERT, id)) {
		res->pkey_data = ca_file_get_pkey_field_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
		res->is_in_db = TRUE;
		res->is_ciphered_with_db_pwd = ca_file_is_password_protected();
	} else {
		gchar *cert_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
		gchar *file_name = ca_file_get_pkey_field_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
		gchar *old_filename = g_strdup (file_name);

		gchar *file_contents = __pkey_retrieve_from_file (&file_name, cert_pem);

		if (strcmp (file_name, old_filename)) {
			/* The private key location has changed, and the user wants us to remember it */
			ca_file_set_pkey_field_for_id (CA_FILE_ELEMENT_TYPE_CERT, file_name, id);
		}

		if (file_contents) {
			res->pkey_data = file_contents;
			res->is_in_db = FALSE;
			res->external_file = file_name;
		} else {
			g_free (file_name);
			g_free (res);
			res = NULL;
		}

		g_free (old_filename);
		g_free (cert_pem);
	}

	return res;
}

PkeyManageData * pkey_manage_get_csr_pkey (guint64 id)
{
	PkeyManageData *res = NULL;

	res = g_new0 (PkeyManageData, 1);
	
	if (ca_file_get_pkey_in_db_from_id (CA_FILE_ELEMENT_TYPE_CSR, id)) {
		res->pkey_data = ca_file_get_pkey_field_from_id (CA_FILE_ELEMENT_TYPE_CSR, id);
		res->is_in_db = TRUE;
		res->is_ciphered_with_db_pwd = ca_file_is_password_protected();
	} else {
		// Retrieving external private keys for CSRs is not supported, as it is impossible to check if 
		// a private key corresponds to a public key/CSR.
                // However, we fill the structure with enough data for recovering the private key.
                res->pkey_data = NULL;
                res->is_in_db = FALSE;
                res->external_file = ca_file_get_pkey_field_from_id (CA_FILE_ELEMENT_TYPE_CSR, id);
	}

	return res;
}

void pkey_manage_data_free (PkeyManageData *pkeydata)
{
	if (! pkeydata)
		return;

	g_free (pkeydata->pkey_data);
	g_free (pkeydata->external_file);
}








unsigned char iv[16] =
    { 'a', 'g', 'z', 'e', 'Q', '5', 'E', '7', 'c', '+', '*', 'G', '1', 'D',
	'u', '='
};

unsigned char ctr[16] =
    { 'd', 'g', '4', 'e', 'J', '5', '3', 'l', 'c', '-', '!', 'G', 'z', 'A',
	'z', '='
};

gchar *saved_password = NULL;


gchar * __pkey_manage_to_hex (const guchar *buffer, size_t len)
{
	gchar *res = g_new0 (gchar, len*2+1);
	guint i;

	for (i=0; i<len; i++) {
		sprintf (&res[i*2], "%02X", buffer[i]);
	}
	
	return res;
}

guchar * __pkey_manage_from_hex (const gchar *input)
{
	guint i;

	guchar *res = g_new0 (guchar, (strlen(input)/2) + 1);
	
	for (i=0; i<strlen(input); i++) {
		res[i/2] = res[i/2] << 4;
		if (input[i] >= '0' && input[i] <= '9') {
			res[i/2] += (input[i] - '0');
		}
		if (input[i] >='A' && input[i] <= 'F') {
			res[i/2] += 10 + (input[i] - 'A');
		}
	}

	return res;

}

guchar *__pkey_manage_create_key(const gchar *password)
{
	guchar *key = g_new0 (guchar, 33);
	guint i, j;

	if (strlen(password) <= 32) {

		for (i=0; i<32; i=i+strlen(password)) {
			snprintf ((gchar *) &key[i], 
				  32 - i, "%s", password);
		}
	} else {
		i = 0;
		do {
			for (j=0; j<32 && j<strlen(&password[i]); j++) {
				key[j] = key[j] ^ (password[i+j]);
			}
			i += 32;
		} while (i<strlen(password));
		
	}

	return key;
}

gchar * __pkey_manage_aes_encrypt (const gchar *in, const gchar *password)
{
	guchar *key = __pkey_manage_create_key (password);
	guchar *out = (guchar *) g_strdup(in);
	gchar *res;
	gcry_error_t get;

	gcry_cipher_hd_t cry_ctxt;

	get = gcry_cipher_open (&cry_ctxt, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	get = gcry_cipher_setiv(cry_ctxt, &iv, 16);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}
	get = gcry_cipher_setctr(cry_ctxt, &ctr, 16);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	get = gcry_cipher_setkey (cry_ctxt, key, 32);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	get = gcry_cipher_encrypt(cry_ctxt, out, strlen(in), NULL, 0);	
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	gcry_cipher_close (cry_ctxt);	

	res = __pkey_manage_to_hex (out, strlen(in));
	
	g_free (out);

	return res;
}

gchar * __pkey_manage_aes_decrypt (const gchar *string, const gchar *password)
{
	guchar *out = __pkey_manage_from_hex(string);

	guchar *key = __pkey_manage_create_key (password);

	gcry_cipher_hd_t cry_ctxt;
	gcry_error_t get;

	get = gcry_cipher_open (&cry_ctxt, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	get = gcry_cipher_setiv(cry_ctxt, &iv, 16);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}
	get = gcry_cipher_setctr(cry_ctxt, &ctr, 16);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	get = gcry_cipher_setkey (cry_ctxt, key, 32);
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	get = gcry_cipher_decrypt(cry_ctxt, out, strlen(string)/2, NULL, 0);	
	if (get) {
		fprintf (stderr, "ERR GCRYPT: %ud\n", gcry_err_code(get));
		return NULL;
	}

	gcry_cipher_close (cry_ctxt);	

	return (gchar *) out;
}

gchar *pkey_manage_encrypt_password (const gchar *pwd)
{
	gchar *password = NULL;
	gchar *res1, *res2;

	gchar salt[3];

	salt[0]= 32 + (random() % 140);
	salt[1]= 32 + (random() % 140);
	salt[2]=0;

	password = g_strdup_printf ("%sgnoMintPassword%s", salt, pwd);

	res1 = __pkey_manage_aes_encrypt (password, password);
	res2 = g_strdup_printf ("%s%s", salt, res1);

	g_free (res1);
	g_free (password);

	return res2;
}

gboolean pkey_manage_check_password (const gchar *checking_password, const gchar *hashed_password) 
{
	
	gchar salt[3];
	gchar *password = NULL;
	gchar *cp;
	gboolean res;

	salt[0] = hashed_password[0];
	salt[1] = hashed_password[1];
	salt[2] = 0;

	password = g_strdup_printf ("%sgnoMintPassword%s", salt, checking_password);

	cp = __pkey_manage_aes_encrypt (password, password);

	res = (! strcmp(cp, &hashed_password[2]));

	g_free (cp);
	g_free (password);

	return res;
}

void pkey_manage_crypt_auto (CaCreationData *creation_data,
			     gchar **pem_private_key,
			     const gchar *pem_ca_certificate)
{
	gchar *clean_private_key = *pem_private_key;
	gchar *res = NULL;
	TlsCert *tls_cert = NULL;

	tls_cert = tls_parse_cert_pem (pem_ca_certificate);

	res = pkey_manage_crypt_w_pwd (clean_private_key, tls_cert->dn, creation_data->password);

	tls_cert_free (tls_cert);

	*pem_private_key = res;

	g_free (clean_private_key);

	return;
}

#ifndef GNOMINTCLI
gchar * pkey_manage_ask_password ()
{
	gchar *password;
	gboolean is_key_ok;
	gboolean remember = 0;
	GtkWidget * widget = NULL, * password_widget = NULL, *remember_password_widget = NULL;
	GladeXML * dialog_xml = NULL;
	gchar     * xml_file = NULL;
	gint response = 0;

	if (! ca_file_is_password_protected())
		return NULL;

	xml_file = g_build_filename (PACKAGE_DATA_DIR, "gnomint", "gnomint.glade", NULL );
	dialog_xml = glade_xml_new (xml_file, "get_db_password_dialog", NULL);
	g_free (xml_file);
	glade_xml_signal_autoconnect (dialog_xml); 	
	
	password_widget = glade_xml_get_widget (dialog_xml, "cadb_password_entry");
	remember_password_widget = glade_xml_get_widget (dialog_xml, "remember_password_checkbutton");
	widget = glade_xml_get_widget (dialog_xml, "cadb_password_dialog_ok_button");

	is_key_ok = FALSE;

	if (saved_password && ca_file_check_password (saved_password)) {
		is_key_ok = TRUE;
		password = g_strdup (saved_password);
	}

	while (! is_key_ok) {
		gtk_widget_grab_focus (password_widget);

		widget = glade_xml_get_widget (dialog_xml, "get_db_password_dialog");
		response = gtk_dialog_run(GTK_DIALOG(widget)); 
	
		if (!response) {
			gtk_widget_destroy (widget);
			g_object_unref (G_OBJECT(dialog_xml));
			return NULL;
		} else {
			password = g_strdup ((gchar *) gtk_entry_get_text (GTK_ENTRY(password_widget)));
			remember = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(remember_password_widget));
		}

		is_key_ok = ca_file_check_password (password);
		
		if (! is_key_ok) {
			ca_error_dialog (_("The given password doesn't match the one used in the database"));
		}

	}

	if (remember) {
		if (saved_password)
			g_free (saved_password);

		saved_password = g_strdup(password);
	}

	widget = glade_xml_get_widget (dialog_xml, "get_db_password_dialog");
	gtk_widget_destroy (widget);
	g_object_unref (G_OBJECT(dialog_xml));


	return password;
}
#else
gchar * pkey_manage_ask_password ()
{
        /* FIXME */
        return NULL;
}
#endif

gchar * pkey_manage_crypt (const gchar *pem_private_key, const gchar *dn)
{
 	gchar *res; 	
	gchar *password;
	
	password = pkey_manage_ask_password();

	res = pkey_manage_crypt_w_pwd (pem_private_key, dn, password);

	g_free (password);

	return res;
}

gchar * pkey_manage_crypt_w_pwd (const gchar *pem_private_key, const gchar *dn, const gchar *pwd)
{
 	gchar *res; 
	gchar *password;

	if (! ca_file_is_password_protected())
		return g_strdup(pem_private_key);
		
	password = g_strdup_printf ("gnoMintPrivateKey%s%s", pwd, dn);

	res = __pkey_manage_aes_encrypt (pem_private_key, password);

	g_free (password);

	return res;
}

gchar * pkey_manage_uncrypt (PkeyManageData *pem_private_key, const gchar *dn)
{
 	gchar *res = NULL; 	
	gchar *password = NULL;
	
	if (pem_private_key->is_in_db) {
                if (pem_private_key->is_ciphered_with_db_pwd) {
                        password = pkey_manage_ask_password();
                        
                        if (password) {
                                res = pkey_manage_uncrypt_w_pwd (pem_private_key, dn, password);		
                                g_free (password);
                        }

                } else {
                        res = g_strdup (pem_private_key->pkey_data);
                }
        }
	return res;
}

gchar * pkey_manage_uncrypt_w_pwd (PkeyManageData *pem_private_key, const gchar *dn, const gchar *pwd)
{
 	gchar *res; 
	gchar *password;

	if (! pem_private_key->is_in_db || ! pem_private_key->is_ciphered_with_db_pwd)
		return g_strdup(pem_private_key->pkey_data);
		
	password = g_strdup_printf ("gnoMintPrivateKey%s%s", pwd, dn);

	res = __pkey_manage_aes_decrypt (pem_private_key->pkey_data, password);

	g_free (password);

	return res;
}




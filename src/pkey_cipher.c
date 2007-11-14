//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007 David Marín Carreño <davefx@gmail.com>
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
#include <gdk/gdk.h>
#include <glib.h>
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tls.h"
#include "ca_file.h"
#include "ca.h"
#include "pkey_cipher.h"

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

unsigned char iv[16] =
    { 'a', 'g', 'z', 'e', 'Q', '5', 'E', '7', 'c', '+', '*', 'G', '1', 'D',
	'u', '='
};

unsigned char ctr[16] =
    { 'd', 'g', '4', 'e', 'J', '5', '3', 'l', 'c', '-', '!', 'G', 'z', 'A',
	'z', '='
};

gchar *saved_password = NULL;


gchar * pkey_cipher_to_hex (const guchar *buffer, size_t len)
{
	gchar *res = g_new0 (gchar, len*2+1);
	guint i;

	for (i=0; i<len; i++) {
		sprintf (&res[i*2], "%02X", buffer[i]);
	}
	
	return res;
}

guchar * pkey_cipher_from_hex (const gchar *input)
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

guchar *__pkey_cipher_create_key(const gchar *password)
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

gchar * pkey_cipher_aes_encrypt (const gchar *in, const gchar *password)
{
	guchar *key = __pkey_cipher_create_key (password);
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

	res = pkey_cipher_to_hex (out, strlen(in));
	
	g_free (out);

	return res;
}

gchar * pkey_cipher_aes_decrypt (const gchar *string, const gchar *password)
{
	guchar *out = pkey_cipher_from_hex(string);

	guchar *key = __pkey_cipher_create_key (password);

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

gchar *pkey_cipher_encrypt_password (const gchar *pwd)
{
	gchar *password = NULL;
	gchar *res1, *res2;

	gchar salt[3];

	salt[0]= 32 + (random() % 140);
	salt[1]= 32 + (random() % 140);
	salt[2]=0;

	password = g_strdup_printf ("%sgnoMintPassword%s", salt, pwd);

	res1 = pkey_cipher_aes_encrypt (password, password);
	res2 = g_strdup_printf ("%s%s", salt, res1);

	g_free (res1);
	g_free (password);

	return res2;
}

gboolean pkey_cipher_check_password (const gchar *checking_password, const gchar *hashed_password) 
{
	
	gchar salt[3];
	gchar *password = NULL;
	gchar *cp;
	gboolean res;

	salt[0] = hashed_password[0];
	salt[1] = hashed_password[1];
	salt[2] = 0;

	password = g_strdup_printf ("%sgnoMintPassword%s", salt, checking_password);

	cp = pkey_cipher_aes_encrypt (password, password);

	res = (! strcmp(cp, &hashed_password[2]));

	g_free (cp);
	g_free (password);

	return res;
}

void pkey_cipher_crypt_auto (CaCreationData *creation_data,
			     gchar **pem_private_key,
			     const gchar *pem_ca_certificate)
{
	gchar *clean_private_key = *pem_private_key;
	gchar *password = NULL;
	gchar *res = NULL;
	TlsCert *tls_cert = NULL;

	if (! creation_data->is_pwd_protected)
		return;

	tls_cert = tls_parse_cert_pem (pem_ca_certificate);

	password = g_strdup_printf ("gnoMintPrivateKey%s%s", creation_data->password, tls_cert->dn);

	res = pkey_cipher_aes_encrypt (clean_private_key, password);

	g_free (password);

	tls_cert_free (tls_cert);

	*pem_private_key = res;

	g_free (clean_private_key);

	return;
}


gchar * pkey_cipher_ask_password ()
{
	gchar *password;
	gboolean is_key_ok;
	gboolean remember;
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

gchar * pkey_cipher_crypt (const gchar *pem_private_key, const gchar *dn)
{
 	gchar *res; 	
	gchar *password;
	
	password = pkey_cipher_ask_password();

	res = pkey_cipher_crypt_w_pwd (pem_private_key, dn, password);

	g_free (password);

	return res;
}

gchar * pkey_cipher_crypt_w_pwd (const gchar *pem_private_key, const gchar *dn, const gchar *pwd)
{
 	gchar *res; 
	gchar *password;

	if (! ca_file_is_password_protected())
		return g_strdup(pem_private_key);
		
	password = g_strdup_printf ("gnoMintPrivateKey%s%s", pwd, dn);

	res = pkey_cipher_aes_encrypt (pem_private_key, password);

	g_free (password);

	return res;
}

gchar * pkey_cipher_uncrypt (const gchar *pem_private_key, const gchar *dn)
{
 	gchar *res; 	
	gchar *password;

	password = pkey_cipher_ask_password();

	res = pkey_cipher_uncrypt_w_pwd (pem_private_key, dn, password);

	g_free (password);

	return res;
}

gchar * pkey_cipher_uncrypt_w_pwd (const gchar *pem_private_key, const gchar *dn, const gchar *pwd)
{
 	gchar *res; 
	gchar *password;

	if (! ca_file_is_password_protected())
		return g_strdup(pem_private_key);
		
	password = g_strdup_printf ("gnoMintPrivateKey%s%s", pwd, dn);

	res = pkey_cipher_aes_decrypt (pem_private_key, password);

	g_free (password);

	return res;
}




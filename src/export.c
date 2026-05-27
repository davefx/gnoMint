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

#include <glib/gi18n.h>
#include <stdlib.h>
#include <string.h>


#include "ca_file.h"
#include "dialog.h"
#include "export.h"
#include "tls.h"
#include "pkey_manage.h"

gchar *export_dh_param (guint dh_size, gchar *filename)
{
	GIOChannel * file = NULL;
	gchar *pem = NULL;
	GError * error = NULL;

	pem = tls_generate_dh_params (dh_size);

	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		return (_("There was an error while saving Diffie-Hellman parameters."));
	} 

	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		return (_("There was an error while saving Diffie-Hellman parameters."));
	} 

	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		return (_("There was an error while saving Diffie-Hellman parameters."));
	} 

	g_io_channel_unref (file);

	return NULL;
}


#ifdef GNOMINTCLI

gchar * export_private_pkcs8 (guint64 id, gint type, gchar *filename)
{
	GIOChannel * file = NULL;
	gchar * password = NULL;
	GError * error = NULL;
	gchar * dn = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * privatekey = NULL;
	gchar * pem = NULL;


	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while exporting private key."));
	}

	switch (type) {
	case CA_FILE_ELEMENT_TYPE_CERT:
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		break;
	case CA_FILE_ELEMENT_TYPE_CSR:
		crypted_pkey = pkey_manage_get_csr_pkey (id);
		break;
	default:
		break;
	}
	dn = ca_file_get_dn_from_id (type, id);

	if (!crypted_pkey || !dn) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while getting private key."));
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);

	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	if (! privatekey) {
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while uncrypting private key."));
	}

	password = dialog_get_password (_("You need to supply a passphrase for protecting the exported private key, "
					     "so nobody else but authorized people can use it. This passphrase will be asked "
					     "by any application that will make use of the private key."),
					   _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"),
					   _("The introduced passphrases are distinct."), 8);
	if (! password) {
		g_free (privatekey);
		return (_("Operation cancelled."));
	}

	pem = tls_generate_pkcs8_encrypted_private_key (privatekey, password);
	g_free (password);
	g_free (privatekey);

	if (!pem) {
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while password-protecting private key."));
	}

	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		g_free (pem);
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while exporting private key."));
	}
	g_free (pem);


	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_io_channel_unref (file);
		return (_("There was an error while exporting private key."));
	}

	g_io_channel_unref (file);

	ca_file_mark_pkey_as_extracted_for_id (type, filename, id);

	return NULL;
}

#else /* GUI async variant */

typedef struct {
	GIOChannel            *file;
	gchar                 *privatekey;
	gchar                 *filename;
	guint64                id;
	gint                   type;
	ExportPkcs8Callback    cb;
	gpointer               cb_user_data;
} _ExportPkcs8Ctx;

static void
_export_private_pkcs8_password_cb (gchar *password, gpointer user_data)
{
	_ExportPkcs8Ctx *ctx = (_ExportPkcs8Ctx *) user_data;
	gchar *pem = NULL;
	GError *error = NULL;

	if (! password) {
		g_io_channel_unref (ctx->file);
		g_free (ctx->privatekey);
		ctx->cb (_("Operation cancelled."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	pem = tls_generate_pkcs8_encrypted_private_key (ctx->privatekey, password);
	g_free (password);
	g_free (ctx->privatekey);

	if (!pem) {
		g_io_channel_unref (ctx->file);
		ctx->cb (_("There was an error while password-protecting private key."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	g_io_channel_write_chars (ctx->file, pem, strlen(pem), NULL, &error);
	if (error) {
		g_free (pem);
		g_io_channel_unref (ctx->file);
		ctx->cb (_("There was an error while exporting private key."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}
	g_free (pem);

	g_io_channel_shutdown (ctx->file, TRUE, &error);
	if (error) {
		g_io_channel_unref (ctx->file);
		ctx->cb (_("There was an error while exporting private key."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	g_io_channel_unref (ctx->file);

	ca_file_mark_pkey_as_extracted_for_id (ctx->type, ctx->filename, ctx->id);

	ctx->cb (NULL, ctx->cb_user_data);
	g_free (ctx->filename);
	g_free (ctx);
}

void export_private_pkcs8 (guint64 id, gint type, gchar *filename,
                           ExportPkcs8Callback cb, gpointer user_data)
{
	GIOChannel * file = NULL;
	GError * error = NULL;
	gchar * dn = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * privatekey = NULL;
	_ExportPkcs8Ctx *ctx;

	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		if (file)
			g_io_channel_unref (file);
		cb (_("There was an error while exporting private key."), user_data);
		return;
	}

	switch (type) {
	case CA_FILE_ELEMENT_TYPE_CERT:
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		break;
	case CA_FILE_ELEMENT_TYPE_CSR:
		crypted_pkey = pkey_manage_get_csr_pkey (id);
		break;
	default:
		break;
	}
	dn = ca_file_get_dn_from_id (type, id);

	if (!crypted_pkey || !dn) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		if (file)
			g_io_channel_unref (file);
		cb (_("There was an error while getting private key."), user_data);
		return;
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);

	pkey_manage_data_free (crypted_pkey);
	g_free (dn);

	if (! privatekey) {
		if (file)
			g_io_channel_unref (file);
		cb (_("There was an error while uncrypting private key."), user_data);
		return;
	}

	ctx = g_new0 (_ExportPkcs8Ctx, 1);
	ctx->file = file;
	ctx->privatekey = privatekey;
	ctx->filename = g_strdup (filename);
	ctx->id = id;
	ctx->type = type;
	ctx->cb = cb;
	ctx->cb_user_data = user_data;

	dialog_get_password (_("You need to supply a passphrase for protecting the exported private key, "
			       "so nobody else but authorized people can use it. This passphrase will be asked "
			       "by any application that will make use of the private key."),
			     _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"),
			     _("The introduced passphrases are distinct."), 8,
			     _export_private_pkcs8_password_cb, ctx);
}

#endif /* GNOMINTCLI */

gchar * export_private_pem (guint64 id, gint type, gchar *filename)
{
	GIOChannel * file = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * dn = NULL;
	gchar * pem = NULL;
	GError * error = NULL;
        
        file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while exporting private key."));
	} 
	
	if (type == CA_FILE_ELEMENT_TYPE_CERT) {
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
	} else {
		crypted_pkey = pkey_manage_get_csr_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CSR, id);
	}
	
	if (!crypted_pkey || !dn) {
		pkey_manage_data_free(crypted_pkey);
		g_free (dn);
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while getting private key."));
	}
	
	pem = pkey_manage_uncrypt (crypted_pkey, dn);

	pkey_manage_data_free (crypted_pkey);
	g_free (dn);
	
	if (!pem) {
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while decrypting private key."));
	}
	
	g_io_channel_write_chars (file, pem, strlen(pem), NULL, &error);
	if (error) {
		g_free (pem);
		if (file)
			g_io_channel_unref (file);
		return (_("There was an error while exporting private key."));
	} 
	g_free (pem);
	
	
	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_io_channel_unref (file);
		return (_("There was an error while exporting private key."));
	} 
	
	g_io_channel_unref (file);
        
        return NULL;

}

#ifdef GNOMINTCLI

gchar * export_pkcs12 (guint64 id, gint type, gchar *filename)
{
	GIOChannel * file = NULL;
	gchar * password = NULL;
	GError * error = NULL;
	gchar * crt_pem = NULL;
	PkeyManageData * crypted_pkey = NULL;
	gchar * dn = NULL;
	gchar * privatekey = NULL;
        gnutls_datum_t * pkcs12_datum = NULL;

	if (type == CA_FILE_ELEMENT_TYPE_CERT) {
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
		crt_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
	} else {
		return (_("Unsupported operation: you cannot generate a PKCS#12 for a CSR."));
	}


	if (! crypted_pkey || ! dn || ! crt_pem) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		return (_("There was an error while getting the certificate and private key from the internal database."));
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);

	if (! privatekey) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		return (_("There was an error while getting the certificate and private key from the internal database."));
	}

	password = dialog_get_password (_("You need to supply a passphrase for protecting the exported certificate, "
					  "so nobody else but authorized people can use it. This passphrase will be asked "
					  "by any application that will import the certificate."),
					_("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"),
					_("The introduced passphrases are distinct."), 8);
	if (! password) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		g_free (privatekey);
		return "";
	}

	pkcs12_datum = tls_generate_pkcs12 (crt_pem, privatekey, password);
	g_free (password);
	g_free (privatekey);
	pkey_manage_data_free (crypted_pkey);
	g_free (dn);
	g_free (crt_pem);


	if (!pkcs12_datum) {
		return (_("There was an error while generating the PKCS#12 package."));
	}

	file = g_io_channel_new_file (filename, "w", &error);
	if (error) {
		return (_("There was an error while exporting certificate."));
	}

        g_io_channel_set_encoding (file, NULL, NULL);

	g_io_channel_write_chars (file, (gchar *) pkcs12_datum->data, pkcs12_datum->size, NULL, &error);
	if (error) {
                g_free (pkcs12_datum->data);
                g_free (pkcs12_datum);
		return (_("There was an error while exporting the certificate."));
	}
        g_free (pkcs12_datum->data);
	g_free (pkcs12_datum);


	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_io_channel_unref (file);
		return (_("There was an error while exporting the certificate."));
	}

	g_io_channel_unref (file);

        return NULL;
}

#else /* GUI async variant */

typedef struct {
	gchar                 *crt_pem;
	gchar                 *privatekey;
	PkeyManageData        *crypted_pkey;
	gchar                 *dn;
	gchar                 *filename;
	ExportPkcs12Callback   cb;
	gpointer               cb_user_data;
} _ExportPkcs12Ctx;

static void
_export_pkcs12_password_cb (gchar *password, gpointer user_data)
{
	_ExportPkcs12Ctx *ctx = (_ExportPkcs12Ctx *) user_data;
	gnutls_datum_t *pkcs12_datum = NULL;
	GIOChannel *file = NULL;
	GError *error = NULL;

	if (! password) {
		pkey_manage_data_free (ctx->crypted_pkey);
		g_free (ctx->dn);
		g_free (ctx->crt_pem);
		g_free (ctx->privatekey);
		ctx->cb ("", ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	pkcs12_datum = tls_generate_pkcs12 (ctx->crt_pem, ctx->privatekey, password);
	g_free (password);
	g_free (ctx->privatekey);
	pkey_manage_data_free (ctx->crypted_pkey);
	g_free (ctx->dn);
	g_free (ctx->crt_pem);
	ctx->privatekey = NULL;
	ctx->crypted_pkey = NULL;
	ctx->dn = NULL;
	ctx->crt_pem = NULL;

	if (!pkcs12_datum) {
		ctx->cb (_("There was an error while generating the PKCS#12 package."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	file = g_io_channel_new_file (ctx->filename, "w", &error);
	if (error) {
		g_free (pkcs12_datum->data);
		g_free (pkcs12_datum);
		ctx->cb (_("There was an error while exporting certificate."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	g_io_channel_set_encoding (file, NULL, NULL);

	g_io_channel_write_chars (file, (gchar *) pkcs12_datum->data, pkcs12_datum->size, NULL, &error);
	if (error) {
		g_free (pkcs12_datum->data);
		g_free (pkcs12_datum);
		g_io_channel_unref (file);
		ctx->cb (_("There was an error while exporting the certificate."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}
	g_free (pkcs12_datum->data);
	g_free (pkcs12_datum);

	g_io_channel_shutdown (file, TRUE, &error);
	if (error) {
		g_io_channel_unref (file);
		ctx->cb (_("There was an error while exporting the certificate."), ctx->cb_user_data);
		g_free (ctx->filename);
		g_free (ctx);
		return;
	}

	g_io_channel_unref (file);

	ctx->cb (NULL, ctx->cb_user_data);
	g_free (ctx->filename);
	g_free (ctx);
}

void export_pkcs12 (guint64 id, gint type, gchar *filename,
                    ExportPkcs12Callback cb, gpointer user_data)
{
	PkeyManageData * crypted_pkey = NULL;
	gchar * dn = NULL;
	gchar * crt_pem = NULL;
	gchar * privatekey = NULL;
	_ExportPkcs12Ctx *ctx;

	if (type == CA_FILE_ELEMENT_TYPE_CERT) {
		crypted_pkey = pkey_manage_get_certificate_pkey (id);
		dn = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
		crt_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, id);
	} else {
		cb (_("Unsupported operation: you cannot generate a PKCS#12 for a CSR."), user_data);
		return;
	}

	if (! crypted_pkey || ! dn || ! crt_pem) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		cb (_("There was an error while getting the certificate and private key from the internal database."), user_data);
		return;
	}

	privatekey = pkey_manage_uncrypt (crypted_pkey, dn);

	if (! privatekey) {
		pkey_manage_data_free (crypted_pkey);
		g_free (dn);
		g_free (crt_pem);
		cb (_("There was an error while getting the certificate and private key from the internal database."), user_data);
		return;
	}

	ctx = g_new0 (_ExportPkcs12Ctx, 1);
	ctx->crt_pem = crt_pem;
	ctx->privatekey = privatekey;
	ctx->crypted_pkey = crypted_pkey;
	ctx->dn = dn;
	ctx->filename = g_strdup (filename);
	ctx->cb = cb;
	ctx->cb_user_data = user_data;

	dialog_get_password (_("You need to supply a passphrase for protecting the exported certificate, "
			       "so nobody else but authorized people can use it. This passphrase will be asked "
			       "by any application that will import the certificate."),
			     _("Insert passphrase (8 characters or more):"), _("Insert passphrase (confirm):"),
			     _("The introduced passphrases are distinct."), 8,
			     _export_pkcs12_password_cb, ctx);
}

#endif /* GNOMINTCLI */

/*  gnoMint — certificate renewal.
 *  See cert_renewal.h for the contract.
 */

#include <config.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <string.h>
#include <time.h>

#include "cert_renewal.h"
#include "ca_file.h"
#include "dialog.h"
#include "tls.h"
#include "pkey_manage.h"

/* Read an integer policy with a fallback. */
static gint
policy_int_default (guint64 ca_id, const gchar *key, gint fallback)
{
	gint v = ca_file_policy_get_int (ca_id, (gchar *) key);
	return v ? v : fallback;
}

/* Continuation: sign and insert the new cert after the parent pkey is
 * decrypted.  `db_password` may be NULL when the DB is not encrypted.
 * When non-NULL it is used to re-encrypt the newly-generated private key
 * under the new certificate's DN via pkey_manage_crypt_w_pwd. */
static gchar *
__cert_renewal_finish (TlsCert *old_cert, guint64 parent_ca_id,
                       gchar *parent_pem, gchar *parent_pkey_pem,
                       const gchar *db_password,
                       guint64 *new_cert_id_out)
{
	gchar  *new_private_key_pem = NULL;
	gchar  *new_csr_pem = NULL;
	gchar  *new_cert_pem = NULL;
	gchar  *crypted_new_pkey = NULL;
	gnutls_x509_privkey_t *new_key = NULL;
	TlsCreationData    *csr_cd  = NULL;
	TlsCertCreationData *cert_cd = NULL;
	gchar  *error = NULL;

	/* 3. Build TlsCreationData for the new keypair + CSR. */
	csr_cd = g_new0 (TlsCreationData, 1);
	csr_cd->cn           = g_strdup (old_cert->cn);
	csr_cd->org          = g_strdup (old_cert->o);
	csr_cd->ou           = g_strdup (old_cert->ou);
	csr_cd->country      = g_strdup (old_cert->c);
	csr_cd->state        = g_strdup (old_cert->st);
	csr_cd->city         = g_strdup (old_cert->l);
	csr_cd->emailAddress = g_strdup (old_cert->emailAddress);
	csr_cd->subject_alt_name = g_strdup (old_cert->subject_alt_name);
	csr_cd->key_type     = 0;     /* RSA */
	csr_cd->key_bitlength = 2048;
	csr_cd->activation   = time (NULL);
	csr_cd->expiration   = csr_cd->activation + 86400 * 30; /* placeholder */

	/* 4. Generate fresh RSA keypair. */
	error = tls_generate_rsa_keys (csr_cd, &new_private_key_pem, &new_key);
	if (error) goto out;

	/* 5. Generate CSR using the old cert's subject info. */
	error = tls_generate_csr (csr_cd, new_key, &new_csr_pem);
	if (error) goto out;

	/* 6. Build TlsCertCreationData from parent CA's policy. */
	cert_cd = g_new0 (TlsCertCreationData, 1);
	{
		gint months = policy_int_default (parent_ca_id, "MONTHS_TO_EXPIRE", 12);
		time_t now = time (NULL);
		cert_cd->activation = now;
		cert_cd->expiration = now + (time_t) months * 30 * 86400;
		cert_cd->key_months_before_expiration = months;
	}
	cert_cd->ca                = ca_file_policy_get_int (parent_ca_id, "CA");
	cert_cd->crl_signing       = ca_file_policy_get_int (parent_ca_id, "CRL_SIGN");
	cert_cd->non_repudiation   = ca_file_policy_get_int (parent_ca_id, "NON_REPUDIATION");
	cert_cd->digital_signature = ca_file_policy_get_int (parent_ca_id, "DIGITAL_SIGNATURE");
	cert_cd->key_encipherment  = ca_file_policy_get_int (parent_ca_id, "KEY_ENCIPHERMENT");
	cert_cd->key_agreement     = ca_file_policy_get_int (parent_ca_id, "KEY_AGREEMENT");
	cert_cd->data_encipherment = ca_file_policy_get_int (parent_ca_id, "DATA_ENCIPHERMENT");
	cert_cd->web_server        = ca_file_policy_get_int (parent_ca_id, "TLS_WEB_SERVER");
	cert_cd->web_client        = ca_file_policy_get_int (parent_ca_id, "TLS_WEB_CLIENT");
	cert_cd->time_stamping     = ca_file_policy_get_int (parent_ca_id, "TIME_STAMPING");
	cert_cd->ocsp_signing      = ca_file_policy_get_int (parent_ca_id, "OCSP_SIGNING");
	cert_cd->code_signing      = ca_file_policy_get_int (parent_ca_id, "CODE_SIGNING");
	cert_cd->email_protection  = ca_file_policy_get_int (parent_ca_id, "EMAIL_PROTECTION");

	if (!cert_cd->digital_signature && !cert_cd->key_encipherment &&
	    !cert_cd->web_server && !cert_cd->web_client &&
	    !cert_cd->code_signing && !cert_cd->email_protection) {
		cert_cd->digital_signature = TRUE;
		cert_cd->key_encipherment  = TRUE;
		cert_cd->web_server        = TRUE;
	}

	ca_file_get_next_serial (&cert_cd->serial, parent_ca_id);

	/* 7. Sign the CSR with the parent CA. */
	error = tls_generate_certificate (cert_cd, new_csr_pem,
	                                  parent_pem, parent_pkey_pem,
	                                  &new_cert_pem);
	if (error) goto out;

	/* 8. Encrypt the new private key under the new cert's DN. */
	{
		TlsCsr *new_csr_info = tls_parse_csr_pem (new_csr_pem);
		if (!new_csr_info) {
			error = g_strdup (_("Cannot parse generated CSR."));
			goto out;
		}
		if (db_password) {
			crypted_new_pkey = pkey_manage_crypt_w_pwd (new_private_key_pem,
			                                             new_csr_info->dn,
			                                             db_password);
		} else {
			crypted_new_pkey = pkey_manage_crypt_w_pwd (new_private_key_pem,
			                                             new_csr_info->dn,
			                                             "");
		}
		tls_csr_free (new_csr_info);
		if (!crypted_new_pkey) {
			error = g_strdup (_("Cannot encrypt new private key."));
			goto out;
		}
	}

	/* 9. Insert the new certificate. */
	{
		gchar *insert_err = ca_file_insert_cert (
		    FALSE /* is_ca */, TRUE /* private_key_in_db */,
		    crypted_new_pkey, new_cert_pem);
		if (insert_err) {
			error = g_strdup (insert_err);
			goto out;
		}
	}

	if (new_cert_id_out) {
		TlsCert *new_cert = tls_parse_cert_pem (new_cert_pem);
		if (new_cert) {
			ca_file_get_id_from_dn (CA_FILE_ELEMENT_TYPE_CERT,
			                        new_cert->dn, new_cert_id_out);
			tls_cert_free (new_cert);
		}
	}

out:
	if (new_key) {
		gnutls_x509_privkey_deinit (*new_key);
		g_free (new_key);
	}
	g_free (new_private_key_pem);
	g_free (new_csr_pem);
	g_free (new_cert_pem);
	g_free (crypted_new_pkey);
	if (csr_cd) tls_creation_data_free (csr_cd);
	g_free (cert_cd);
	return error;
}

#ifdef GNOMINTCLI

gchar *
cert_renewal_renew (guint64 cert_id, guint64 *new_cert_id_out)
{
	gchar  *old_pem = NULL;
	TlsCert *old_cert = NULL;
	guint64 parent_ca_id = 0;
	gchar  *parent_pem = NULL;
	gchar  *parent_dn = NULL;
	PkeyManageData *parent_crypted_pkey = NULL;
	gchar  *parent_pkey_pem = NULL;
	gchar  *db_password = NULL;
	gchar  *error = NULL;

	old_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, cert_id);
	if (!old_pem) {
		error = g_strdup (_("Cannot read certificate PEM from database."));
		goto out;
	}
	old_cert = tls_parse_cert_pem (old_pem);
	if (!old_cert) {
		error = g_strdup (_("Cannot parse certificate."));
		goto out;
	}

	if (!ca_file_get_id_from_dn (CA_FILE_ELEMENT_TYPE_CERT,
	                             old_cert->i_dn, &parent_ca_id)) {
		error = g_strdup_printf (
		    _("Cannot find issuer CA in this database (issuer DN: %s)."),
		    old_cert->i_dn ? old_cert->i_dn : "(null)");
		goto out;
	}

	parent_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT,
	                                              parent_ca_id);
	parent_dn  = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT,
	                                      parent_ca_id);
	parent_crypted_pkey = pkey_manage_get_certificate_pkey (parent_ca_id);
	if (!parent_pem || !parent_dn || !parent_crypted_pkey) {
		error = g_strdup (_("Cannot load parent CA material from database."));
		goto out;
	}

	/* Get DB password for both uncrypt and re-crypt */
	if (parent_crypted_pkey->is_in_db && parent_crypted_pkey->is_ciphered_with_db_pwd) {
		db_password = pkey_manage_ask_password ();
		if (!db_password) {
			error = g_strdup (_("Cannot decrypt parent CA's private key."));
			goto out;
		}
		parent_pkey_pem = pkey_manage_uncrypt_w_pwd (parent_crypted_pkey, parent_dn, db_password);
	} else {
		parent_pkey_pem = g_strdup (parent_crypted_pkey->pkey_data);
	}

	if (!parent_pkey_pem) {
		error = g_strdup (_("Cannot decrypt parent CA's private key."));
		goto out;
	}

	error = __cert_renewal_finish (old_cert, parent_ca_id,
	                                parent_pem, parent_pkey_pem,
	                                db_password,
	                                new_cert_id_out);

out:
	g_free (old_pem);
	if (old_cert) tls_cert_free (old_cert);
	g_free (parent_pem);
	g_free (parent_dn);
	pkey_manage_data_free (parent_crypted_pkey);
	g_free (parent_pkey_pem);
	g_free (db_password);
	return error;
}

#else /* GUI async cert_renewal_renew */

typedef struct {
	guint64              cert_id;
	guint64             *new_cert_id_out;
	gchar               *old_pem;
	TlsCert             *old_cert;
	guint64              parent_ca_id;
	gchar               *parent_pem;
	gchar               *parent_dn;
	PkeyManageData      *parent_crypted_pkey;
	gchar               *db_password;
	CertRenewalCallback  cb;
	gpointer             cb_user_data;
} _CertRenewalCtx;

static void
_cert_renewal_password_cb (gchar *db_password, gpointer data)
{
	_CertRenewalCtx *ctx = (_CertRenewalCtx *) data;
	gchar *parent_pkey_pem = NULL;
	gchar *error = NULL;

	if (!db_password && ctx->parent_crypted_pkey->is_ciphered_with_db_pwd) {
		error = g_strdup (_("Cannot decrypt parent CA's private key."));
		goto done;
	}

	ctx->db_password = db_password;

	if (db_password) {
		parent_pkey_pem = pkey_manage_uncrypt_w_pwd (ctx->parent_crypted_pkey,
		                                              ctx->parent_dn,
		                                              db_password);
	} else {
		parent_pkey_pem = g_strdup (ctx->parent_crypted_pkey->pkey_data);
	}

	if (!parent_pkey_pem) {
		error = g_strdup (_("Cannot decrypt parent CA's private key."));
		goto done;
	}

	error = __cert_renewal_finish (ctx->old_cert, ctx->parent_ca_id,
	                                ctx->parent_pem, parent_pkey_pem,
	                                db_password,
	                                ctx->new_cert_id_out);
	g_free (parent_pkey_pem);

done:
	g_free (ctx->old_pem);
	if (ctx->old_cert) tls_cert_free (ctx->old_cert);
	g_free (ctx->parent_pem);
	g_free (ctx->parent_dn);
	pkey_manage_data_free (ctx->parent_crypted_pkey);
	g_free (ctx->db_password);

	ctx->cb (error, ctx->cb_user_data);
	g_free (ctx);
}

static void
_cert_renewal_got_pkey_cb (PkeyManageData *parent_crypted_pkey, gpointer data)
{
	_CertRenewalCtx *ctx = (_CertRenewalCtx *) data;

	ctx->parent_crypted_pkey = parent_crypted_pkey;

	if (!ctx->parent_pem || !ctx->parent_dn || !parent_crypted_pkey) {
		g_free (ctx->old_pem);
		if (ctx->old_cert) tls_cert_free (ctx->old_cert);
		g_free (ctx->parent_pem);
		g_free (ctx->parent_dn);
		pkey_manage_data_free (parent_crypted_pkey);
		ctx->cb (g_strdup (_("Cannot load parent CA material from database.")),
		         ctx->cb_user_data);
		g_free (ctx);
		return;
	}

	/* Ask for the DB password once; it will be used for both uncrypt
	 * and re-crypt of the new private key. */
	if (parent_crypted_pkey->is_in_db && parent_crypted_pkey->is_ciphered_with_db_pwd) {
		pkey_manage_ask_password (_cert_renewal_password_cb, ctx);
	} else {
		_cert_renewal_password_cb (NULL, ctx);
	}
}

void
cert_renewal_renew (guint64 cert_id, guint64 *new_cert_id_out,
                    CertRenewalCallback cb, gpointer user_data)
{
	_CertRenewalCtx *ctx;
	gchar *old_pem = NULL;
	TlsCert *old_cert = NULL;
	guint64 parent_ca_id = 0;

	old_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, cert_id);
	if (!old_pem) {
		cb (g_strdup (_("Cannot read certificate PEM from database.")), user_data);
		return;
	}
	old_cert = tls_parse_cert_pem (old_pem);
	if (!old_cert) {
		g_free (old_pem);
		cb (g_strdup (_("Cannot parse certificate.")), user_data);
		return;
	}

	if (!ca_file_get_id_from_dn (CA_FILE_ELEMENT_TYPE_CERT,
	                             old_cert->i_dn, &parent_ca_id)) {
		gchar *err = g_strdup_printf (
		    _("Cannot find issuer CA in this database (issuer DN: %s)."),
		    old_cert->i_dn ? old_cert->i_dn : "(null)");
		g_free (old_pem);
		tls_cert_free (old_cert);
		cb (err, user_data);
		return;
	}

	ctx = g_new0 (_CertRenewalCtx, 1);
	ctx->cert_id = cert_id;
	ctx->new_cert_id_out = new_cert_id_out;
	ctx->old_pem = old_pem;
	ctx->old_cert = old_cert;
	ctx->parent_ca_id = parent_ca_id;
	ctx->parent_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT,
	                                                    parent_ca_id);
	ctx->parent_dn  = ca_file_get_dn_from_id (CA_FILE_ELEMENT_TYPE_CERT,
	                                            parent_ca_id);
	ctx->cb = cb;
	ctx->cb_user_data = user_data;

	pkey_manage_get_certificate_pkey (parent_ca_id,
	                                  _cert_renewal_got_pkey_cb, ctx);
}

#endif /* GNOMINTCLI */

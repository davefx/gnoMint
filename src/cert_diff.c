/* Pairwise X.509 certificate diff. See cert_diff.h. */

#include "cert_diff.h"
#include "tls.h"
#include "uint160.h"

#include <glib/gi18n.h>
#include <string.h>
#include <time.h>


static void
__append_field (CertDiff *d, const gchar *name,
                const gchar *left, const gchar *right)
{
	CertDiffField *f = g_new0 (CertDiffField, 1);
	f->field_name = g_strdup (name);
	f->left  = left  ? g_strdup (left)  : NULL;
	f->right = right ? g_strdup (right) : NULL;
	f->differs = (g_strcmp0 (left, right) != 0);
	d->fields = g_list_append (d->fields, f);
}

static gchar *
__format_time (time_t t)
{
	if (t == 0) return NULL;
	struct tm tm;
#ifndef WIN32
	gmtime_r (&t, &tm);
#else
	tm = *gmtime (&t);
#endif
	gchar buf[64];
	if (strftime (buf, sizeof (buf), "%Y-%m-%d %H:%M:%S GMT", &tm) == 0)
		return NULL;
	return g_strdup (buf);
}

/* Join a TlsCert's GList<gchar*> uses field into a comma-separated
 * string. uses is built by tls_parse_cert_pem and entries are
 * translated user-visible strings — fine for display. */
static gchar *
__join_uses (GList *uses)
{
	if (!uses) return NULL;
	GString *s = g_string_new (NULL);
	for (GList *l = uses; l; l = l->next) {
		if (s->len > 0) g_string_append (s, ", ");
		g_string_append (s, (const gchar *) l->data);
	}
	return g_string_free (s, FALSE);
}

static gchar *
__format_serial (const UInt160 *s)
{
	return uint160_strdup_printf ((UInt160 *) s);
}


CertDiff *
cert_diff_new (const gchar *pem_left, const gchar *pem_right)
{
	CertDiff *d = g_new0 (CertDiff, 1);

	TlsCert *L = pem_left  ? tls_parse_cert_pem (pem_left)  : NULL;
	TlsCert *R = pem_right ? tls_parse_cert_pem (pem_right) : NULL;

	if (pem_left && !L)
		d->parse_error_left = g_strdup (_("Cannot parse left certificate"));
	if (pem_right && !R)
		d->parse_error_right = g_strdup (_("Cannot parse right certificate"));

	const gchar *Lcn  = L ? L->cn  : NULL;  const gchar *Rcn  = R ? R->cn  : NULL;
	const gchar *Lo   = L ? L->o   : NULL;  const gchar *Ro   = R ? R->o   : NULL;
	const gchar *Lou  = L ? L->ou  : NULL;  const gchar *Rou  = R ? R->ou  : NULL;
	const gchar *Lc   = L ? L->c   : NULL;  const gchar *Rc   = R ? R->c   : NULL;
	const gchar *Lst  = L ? L->st  : NULL;  const gchar *Rst  = R ? R->st  : NULL;
	const gchar *Ll   = L ? L->l   : NULL;  const gchar *Rl   = R ? R->l   : NULL;
	const gchar *Lem  = L ? L->emailAddress : NULL;
	const gchar *Rem  = R ? R->emailAddress : NULL;
	const gchar *Ldn  = L ? L->dn  : NULL;  const gchar *Rdn  = R ? R->dn  : NULL;

	const gchar *Lidn = L ? L->i_dn : NULL; const gchar *Ridn = R ? R->i_dn : NULL;

	gchar *Lserial = L ? __format_serial (&L->serial_number) : NULL;
	gchar *Rserial = R ? __format_serial (&R->serial_number) : NULL;

	gchar *Lact  = L ? __format_time (L->activation_time) : NULL;
	gchar *Ract  = R ? __format_time (R->activation_time) : NULL;
	gchar *Lexp  = L ? __format_time (L->expiration_time) : NULL;
	gchar *Rexp  = R ? __format_time (R->expiration_time) : NULL;

	gchar *Luses = L ? __join_uses (L->uses) : NULL;
	gchar *Ruses = R ? __join_uses (R->uses) : NULL;

	const gchar *Lsan = L ? L->subject_alt_name : NULL;
	const gchar *Rsan = R ? R->subject_alt_name : NULL;

	const gchar *Lski = L ? L->subject_key_id : NULL;
	const gchar *Rski = R ? R->subject_key_id : NULL;
	const gchar *Laki = L ? L->issuer_key_id  : NULL;
	const gchar *Raki = R ? R->issuer_key_id  : NULL;

	const gchar *Lcrl = L ? L->crl_distribution_point : NULL;
	const gchar *Rcrl = R ? R->crl_distribution_point : NULL;

	const gchar *Lsha1 = L ? L->sha1 : NULL;
	const gchar *Rsha1 = R ? R->sha1 : NULL;
	const gchar *Lsha256 = L ? L->sha256 : NULL;
	const gchar *Rsha256 = R ? R->sha256 : NULL;

	__append_field (d, _("Subject CN"),       Lcn,  Rcn);
	__append_field (d, _("Subject O"),        Lo,   Ro);
	__append_field (d, _("Subject OU"),       Lou,  Rou);
	__append_field (d, _("Subject Country"),  Lc,   Rc);
	__append_field (d, _("Subject State"),    Lst,  Rst);
	__append_field (d, _("Subject Locality"), Ll,   Rl);
	__append_field (d, _("Subject email"),    Lem,  Rem);
	__append_field (d, _("Subject DN"),       Ldn,  Rdn);
	__append_field (d, _("Issuer DN"),        Lidn, Ridn);
	__append_field (d, _("Serial"),           Lserial, Rserial);
	__append_field (d, _("Activation"),       Lact, Ract);
	__append_field (d, _("Expiration"),       Lexp, Rexp);
	__append_field (d, _("SAN"),              Lsan, Rsan);
	__append_field (d, _("Key usage / EKU"),  Luses, Ruses);
	__append_field (d, _("Subject Key ID"),   Lski, Rski);
	__append_field (d, _("Authority Key ID"), Laki, Raki);
	__append_field (d, _("CRL distribution"), Lcrl, Rcrl);
	__append_field (d, _("SHA-1 fingerprint"), Lsha1, Rsha1);
	__append_field (d, _("SHA-256 fingerprint"), Lsha256, Rsha256);

	g_free (Lserial); g_free (Rserial);
	g_free (Lact);    g_free (Ract);
	g_free (Lexp);    g_free (Rexp);
	g_free (Luses);   g_free (Ruses);

	if (L) tls_cert_free (L);
	if (R) tls_cert_free (R);
	return d;
}

void
cert_diff_free (CertDiff *d)
{
	if (!d) return;
	for (GList *l = d->fields; l; l = l->next) {
		CertDiffField *f = (CertDiffField *) l->data;
		g_free (f->field_name);
		g_free (f->left);
		g_free (f->right);
		g_free (f);
	}
	g_list_free (d->fields);
	g_free (d->parse_error_left);
	g_free (d->parse_error_right);
	g_free (d);
}

gint
cert_diff_count_differences (const CertDiff *d)
{
	if (!d) return 0;
	gint n = 0;
	for (GList *l = d->fields; l; l = l->next)
		if (((CertDiffField *) l->data)->differs)
			n++;
	return n;
}

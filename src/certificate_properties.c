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


#include <glib-object.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "tls.h"
#include "ca_policy.h"
#include "certificate_properties.h"
#include "prop_node.h"

#include <glib/gi18n.h>

typedef struct
{
	const gchar *oid;
	const gchar *label;
} certificate_properties_oid_label_couple_t;

typedef void (*certificate_properties_fill_t) (GnomintPropNode *, gnutls_x509_crt_t *);

typedef struct
{
	const gchar *oid;
	certificate_properties_fill_t function;
} certificate_properties_oid_function_couple_t;

const certificate_properties_oid_label_couple_t certificate_properties_oid_label_table[] = {
	{"1.3.6.1.5.5.7.3.1", "TLS WWW Server"},
	{"1.3.6.1.5.5.7.3.2", "TLS WWW Client"},
	{"1.3.6.1.5.5.7.3.3", "Code signing"},
	{"1.3.6.1.5.5.7.3.4", "Email protection"},
	{"1.3.6.1.5.5.7.3.8", "Time stamping"},
	{"1.3.6.1.5.5.7.3.9", "OCSP signing"},
	{"2.5.29.37.0", "Any purpose"},
	{"2.5.29.9", "Subject Directory Attributes"},
	{"2.5.29.14", "Subject Key Identifier"},
	{"2.5.29.15", "Key Usage"},
	{"2.5.29.16", "Private Key Usage Period"},
	{"2.5.29.17", "Subject Alternative Name"},
	{"2.5.29.19", "Basic Constraints"},
	{"2.5.29.30", "Name Constraints"},
	{"2.5.29.31", "CRL Distribution Points"},
	{"2.5.29.32", "Certificate Policies"},
	{"2.5.29.33", "Policy Mappings"},
	{"2.5.29.35", "Authority Key Identifier"},
	{"2.5.29.36", "Policy Constraints"},
	{"2.5.29.37", "Extended Key Usage"},
	{"2.5.29.46", "Delta CRL Distribution Point"},
	{"2.5.29.54", "Inhibit Any-Policy"},
	{0, 0},
};

void __certificate_properties_fill_cert_ext_SubjectKeyIdentifier(GnomintPropNode *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_KeyUsage(GnomintPropNode *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_SubjectAltName(GnomintPropNode *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_BasicConstraints(GnomintPropNode *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_CRLDistributionPoints(GnomintPropNode *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_AuthorityKeyIdentifier(GnomintPropNode *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_ExtKeyUsage(GnomintPropNode *, gnutls_x509_crt_t *);
gchar * __certificate_properties_dump_raw_data(const unsigned char *buffer, size_t buffer_size);
const gchar * __certificate_properties_lookup_oid_label(const certificate_properties_oid_label_couple_t *oid_label_table, const gchar *oid);
certificate_properties_fill_t __certificate_properties_lookup_oid_function (const certificate_properties_oid_function_couple_t *oid_func_table,
									    const gchar *oid);
gchar * __certificate_properties_dump_RDNSequence(const gchar *buffer, gsize buffer_size);
gchar * __certificate_properties_dump_key_usage(guint key_usage);
void __certificate_properties_fill_cert_version(GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_serialNumber(GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_signature(GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_issuer(GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_validity (GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_subject (GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_subjectPublicKeyInfo (GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_issuerUniqueID (GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_subjectUniqueID (GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_ext (GnomintPropNode *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert (GListStore *root_store, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_signatureAlgorithm (GListStore *root_store, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_signatureValue (GListStore *root_store, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_certificate(GListStore *root_store, gnutls_x509_crt_t *certificate);



const certificate_properties_oid_function_couple_t certificate_properties_oid_function_table[] = {
	{"2.5.29.14", __certificate_properties_fill_cert_ext_SubjectKeyIdentifier},
	{"2.5.29.15", __certificate_properties_fill_cert_ext_KeyUsage},
	{"2.5.29.17", __certificate_properties_fill_cert_ext_SubjectAltName},
	{"2.5.29.19", __certificate_properties_fill_cert_ext_BasicConstraints},
	{"2.5.29.31", __certificate_properties_fill_cert_ext_CRLDistributionPoints},
	{"2.5.29.35", __certificate_properties_fill_cert_ext_AuthorityKeyIdentifier},
	{"2.5.29.37", __certificate_properties_fill_cert_ext_ExtKeyUsage},
	{0, 0},
};


GtkBuilder * certificate_properties_window_gtkb = NULL;

void __certificate_properties_populate (const char *certificate_pem);
void __certificate_details_populate (const char *certificate_pem);

void certificate_properties_display(guint64 cert_id, const char *certificate_pem, gboolean privkey_in_db,
				    gboolean is_ca)
{
	GObject * widget = NULL;

	certificate_properties_window_gtkb = gtk_builder_new();
	gtk_builder_add_from_file (certificate_properties_window_gtkb,
				   g_build_filename (PACKAGE_DATA_DIR, "gnomint", "certificate_properties_dialog.ui", NULL),
				   NULL);

	__certificate_properties_populate (certificate_pem);
	__certificate_details_populate (certificate_pem);

	if (! is_ca) {
		widget = gtk_builder_get_object (certificate_properties_window_gtkb, "notebook2");
		gtk_notebook_remove_page (GTK_NOTEBOOK(widget), 2);
	} else {
		ca_policy_populate (cert_id);
	}

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certificate_properties_dialog");

	g_object_set_data (G_OBJECT(widget), "cert_id", g_strdup_printf("%" G_GUINT64_FORMAT,
                                                                        cert_id));

	gtk_widget_set_visible(GTK_WIDGET(widget), TRUE);
}


void __certificate_properties_populate (const char *certificate_pem)
{
	GObject *widget = NULL;
#ifndef WIN32
	struct tm tim;
#else
	struct tm* tim = NULL;
#endif
	TlsCert * cert = NULL;
	gchar model_time_str[100];
        gchar * aux;
	UInt160 * serial_number;

	cert = tls_parse_cert_pem (certificate_pem);

	serial_number = &cert->serial_number;

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certActivationDateLabel");
#ifndef WIN32
	gmtime_r (&cert->activation_time, &tim);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tim);
#else
	tim = gmtime (&cert->activation_time);
	strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tim);
#endif
	gtk_label_set_text (GTK_LABEL(widget), model_time_str);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certExpirationDateLabel");
#ifndef WIN32
	gmtime_r (&cert->expiration_time, &tim);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tim);
#else
	tim = gmtime (&cert->expiration_time);
	strftime (model_time_str, 100, _("%m/%d/%Y %H:%M GMT"), tim);
#endif
	gtk_label_set_text (GTK_LABEL(widget), model_time_str);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSNLabel");
        aux = uint160_strdup_printf (serial_number);
	gtk_label_set_text (GTK_LABEL(widget), aux);
        g_free (aux);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectCNLabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->cn);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectOLabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->o);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectOULabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->ou);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectEmailLabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->emailAddress ? cert->emailAddress : "");

	// Display Subject Alternative Names if present
	if (cert->subject_alt_name && cert->subject_alt_name[0]) {
		widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectAltNameLabel");
		gtk_label_set_text (GTK_LABEL(widget), cert->subject_alt_name);
	}

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerCNLabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->i_cn);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerOLabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->i_o);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerOULabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->i_ou);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerEmailLabel");
	gtk_label_set_text (GTK_LABEL(widget), cert->i_emailAddress ? cert->i_emailAddress : "");

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "sha1Label");
	gtk_label_set_text (GTK_LABEL(widget), cert->sha1);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "md5Label");
	gtk_label_set_text (GTK_LABEL(widget), cert->md5);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "sha256Label");
	gtk_label_set_text (GTK_LABEL(widget), cert->sha256);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "sha512Label");
	gtk_label_set_text (GTK_LABEL(widget), cert->sha512);


	if (g_list_length (cert->uses)) {
		GValue * valtrue = g_new0 (GValue, 1);
		int i;

		g_value_init (valtrue, G_TYPE_BOOLEAN);
		g_value_set_boolean (valtrue, TRUE);

		widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certPropSeparator");
		gtk_widget_set_visible(GTK_WIDGET(widget), TRUE);

		widget = gtk_builder_get_object (certificate_properties_window_gtkb, "vboxCertCapabilities");

		for (i = g_list_length(cert->uses) - 1; i >= 0; i--) {
			GtkLabel *label = NULL;
			label = GTK_LABEL(gtk_label_new ((gchar *) g_list_nth_data (cert->uses, i)));
			gtk_label_set_xalign (label, 0.0);
			gtk_label_set_yalign (label, 0.5);
			gtk_box_append(GTK_BOX(widget), GTK_WIDGET(label));
		}
		gtk_widget_set_visible(GTK_WIDGET(widget), TRUE);

		g_free (valtrue);
	}



	tls_cert_free (cert);

	return;
}

G_MODULE_EXPORT void certificate_properties_close_clicked (const char *certificate_pem)
{
	GObject *widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certificate_properties_dialog");
	gtk_window_destroy(GTK_WINDOW(GTK_WIDGET(widget)));
}


gchar * __certificate_properties_dump_raw_data(const unsigned char *buffer, size_t buffer_size)
{
	const gint BYTES_PER_LINE = 16;
	gchar *result = g_new0 (gchar, 4 * buffer_size);
	size_t i;
	gchar *result_iterator = result;
	if (!result)
	{
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, "Not enough memory\n");
		return result;
	}
	for (i = 0; i < buffer_size; i++)
	{
		size_t remaining = 4 * buffer_size - (result_iterator - result);
		int written = snprintf(result_iterator, remaining, "%02x:", buffer[i]);
		if (written < 0 || written >= (int) remaining)
			break;
		result_iterator += written;
		if ((i % BYTES_PER_LINE) == BYTES_PER_LINE - 1)
			*result_iterator++ = '\n';
	}
	if ((i % BYTES_PER_LINE) == 0)
		*(result_iterator - 1) = 0;
	return result;
}


const gchar * __certificate_properties_lookup_oid_label(const certificate_properties_oid_label_couple_t *oid_label_table, const gchar *oid)
{
	const certificate_properties_oid_label_couple_t *i;

	if (!oid)
		return 0;

	for (i = certificate_properties_oid_label_table; i->oid; i++)
		if (strcmp(i->oid, oid) == 0)
			break;

	if (i->label)
		return _(i->label);
	else
		return _("Unknown");
}


certificate_properties_fill_t __certificate_properties_lookup_oid_function (const certificate_properties_oid_function_couple_t *oid_func_table,
									    const gchar *oid)
{
	const certificate_properties_oid_function_couple_t *i;
	if (!oid)
		return 0;
	for (i = oid_func_table; i->oid; i++)
		if (strcmp(i->oid, oid) == 0)
			break;
	return i->function;
}


gchar * __certificate_properties_dump_RDNSequence(const gchar *buffer, gsize buffer_size)
{
	const char ESCAPE = '\\';
	const char SEPARATOR = ',';
	gchar *result = g_new0 (gchar, buffer_size + 1);
	gsize i;
	gchar *result_iterator = result;
	gint previous_was_escape = 0;
	if (! result) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, "Not enough memory\n");
		return result;
	}

	for (i = 0; i < buffer_size; i++)
	{
		if (previous_was_escape)
		{
			*result_iterator++ = *buffer++;
			previous_was_escape = 0;
		}
		else if (*buffer == ESCAPE)
		{
			buffer++;
			previous_was_escape = 1;
		}
		else if (*buffer == SEPARATOR)
		{
			*result_iterator++ = '\n';
			buffer++;
		}
		else
			*result_iterator++ = *buffer++;
	}
	*result_iterator++ = 0;
	return result;
}

gchar * __certificate_properties_dump_key_usage(guint key_usage)
{
	const gint BUFFER_SIZE_MAX = 1024;
	gchar *result = g_new0 (gchar, BUFFER_SIZE_MAX + 1);
	gchar *buffer_iterator = result;
	if (key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Digital signature"));
	if (key_usage & GNUTLS_KEY_NON_REPUDIATION)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Non repudiation"));
	if (key_usage & GNUTLS_KEY_KEY_ENCIPHERMENT)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Key encipherment"));
	if (key_usage & GNUTLS_KEY_DATA_ENCIPHERMENT)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Data encipherment"));
	if (key_usage & GNUTLS_KEY_KEY_AGREEMENT)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Key agreement"));
	if (key_usage & GNUTLS_KEY_KEY_CERT_SIGN)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Certificate signing"));
	if (key_usage & GNUTLS_KEY_CRL_SIGN)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("CRL signing"));
	if (key_usage & GNUTLS_KEY_ENCIPHER_ONLY)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Key encipherment only"));
	if (key_usage & GNUTLS_KEY_DECIPHER_ONLY)
		buffer_iterator += sprintf(buffer_iterator, "%s\n", _("Key decipherment only"));
	*(buffer_iterator - 1) = 0;
	return result;
}

void __certificate_properties_fill_cert_version(GnomintPropNode *parent, gnutls_x509_crt_t *certificate)
{
	gint result;
	gchar value[4];

	result = gnutls_x509_crt_get_version(*certificate);
	sprintf(value, "v%d", result);

	GnomintPropNode *child = gnomint_prop_node_new(_("Version"), value);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);
}

void __certificate_properties_fill_cert_serialNumber(GnomintPropNode *parent, gnutls_x509_crt_t *certificate)
{
	gint result;
	gsize buffer_size = 0;
	gchar *buffer = NULL;
	gchar *value = NULL;

	result = gnutls_x509_crt_get_serial(*certificate, 0, &buffer_size);
	if (result != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}
	buffer = g_new0(gchar, buffer_size);

	if (!buffer) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, "Not enough memory!");
		return;
	}

	result = gnutls_x509_crt_get_serial(*certificate, buffer, &buffer_size);

	if (result < 0) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}

	value = __certificate_properties_dump_raw_data((unsigned char *) buffer, buffer_size);

	g_free(buffer);

	GnomintPropNode *child = gnomint_prop_node_new(_("Serial Number"), value);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);

	g_free(value);
}

void __certificate_properties_fill_cert_signature(GnomintPropNode *parent, gnutls_x509_crt_t *certificate)
{
	int result;
        const gchar *name = NULL;

	result = gnutls_x509_crt_get_signature_algorithm(*certificate);
	name = gnutls_sign_algorithm_get_name(result);

	GnomintPropNode *sig_node = gnomint_prop_node_new(_("Signature"), NULL);
	g_list_store_append(gnomint_prop_node_get_children(parent), sig_node);

	GnomintPropNode *alg_child = gnomint_prop_node_new(_("Algorithm"), name);
	g_list_store_append(gnomint_prop_node_get_children(sig_node), alg_child);
	g_object_unref(alg_child);

	GnomintPropNode *params_child = gnomint_prop_node_new(_("Parameters"), _("(unknown)"));
	g_list_store_append(gnomint_prop_node_get_children(sig_node), params_child);
	g_object_unref(params_child);

	g_object_unref(sig_node);
}

void __certificate_properties_fill_cert_issuer(GnomintPropNode *parent, gnutls_x509_crt_t *certificate)
{
	int result;
	size_t buffer_size = 0;
	gchar * buffer = NULL;
	gchar * value = NULL;

	result = gnutls_x509_crt_get_issuer_dn(*certificate, 0, &buffer_size);
	if (result != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}
	buffer = g_new (gchar, buffer_size);
	if (!buffer) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, "Not enough memory!");
		return;
	}
	result = gnutls_x509_crt_get_issuer_dn(*certificate, buffer, &buffer_size);
	if (result < 0) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}

	value = __certificate_properties_dump_RDNSequence(buffer, buffer_size);

	g_free(buffer);

	GnomintPropNode *child = gnomint_prop_node_new(_("Issuer"), value);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);

	g_free(value);
}

void __certificate_properties_fill_cert_validity (GnomintPropNode *parent, gnutls_x509_crt_t *certificate)
{
	time_t not_before;
#ifndef WIN32
	struct tm not_before_broken_down_time;
#else
	struct tm *not_before_broken_down_time = NULL;
#endif
	gchar not_before_asctime[32];
	time_t not_after;
#ifndef WIN32
	struct tm not_after_broken_down_time;
#else
	struct tm *not_after_broken_down_time = NULL;
#endif
	gchar not_after_asctime[32];

#ifndef WIN32
	not_before = gnutls_x509_crt_get_activation_time(*certificate);
	gmtime_r (&not_before, &not_before_broken_down_time);
	asctime_r(&not_before_broken_down_time, not_before_asctime);
	not_before_asctime[strlen(not_before_asctime) - 1] = 0;
#else
	not_before = gnutls_x509_crt_get_activation_time(*certificate);
	not_before_broken_down_time = gmtime(&not_before);
	snprintf(not_before_asctime, sizeof(not_before_asctime), "%s", asctime(not_before_broken_down_time));
	// not_before_asctime[strlen(not_before_asctime) - 1] = 0; // ???
#endif

#ifndef WIN32
	not_after = gnutls_x509_crt_get_expiration_time(*certificate);
	gmtime_r(&not_after, &not_after_broken_down_time);
	asctime_r(&not_after_broken_down_time, not_after_asctime);
	not_after_asctime[strlen(not_after_asctime) - 1] = 0;
#else
	not_after = gnutls_x509_crt_get_expiration_time(*certificate);
	not_after_broken_down_time = gmtime(&not_after);
	snprintf(not_after_asctime, sizeof(not_after_asctime), "%s", asctime(not_after_broken_down_time));
	// not_after_asctime[strlen(not_after_asctime) - 1] = 0; // ???
#endif

	GnomintPropNode *validity_node = gnomint_prop_node_new(_("Validity"), NULL);
	g_list_store_append(gnomint_prop_node_get_children(parent), validity_node);

	GnomintPropNode *nb_child = gnomint_prop_node_new(_("Not Before"), not_before_asctime);
	g_list_store_append(gnomint_prop_node_get_children(validity_node), nb_child);
	g_object_unref(nb_child);

	GnomintPropNode *na_child = gnomint_prop_node_new(_("Not After"), not_after_asctime);
	g_list_store_append(gnomint_prop_node_get_children(validity_node), na_child);
	g_object_unref(na_child);

	g_object_unref(validity_node);
}

void __certificate_properties_fill_cert_subject (GnomintPropNode *parent, gnutls_x509_crt_t *certificate)
{
	int result;
	size_t buffer_size = 0;
	gchar *buffer = NULL;
	gchar *value = NULL;

	result = gnutls_x509_crt_get_dn(*certificate, 0, &buffer_size);
	if (result != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}
	buffer = g_new0 (gchar, buffer_size);
	if (!buffer) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, "Not enough memory!");
		return;
	}

	result = gnutls_x509_crt_get_dn(*certificate, buffer, &buffer_size);
	if (result < 0) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}
	value = __certificate_properties_dump_RDNSequence(buffer, buffer_size);

	g_free(buffer);

	GnomintPropNode *child = gnomint_prop_node_new(_("Subject"), value);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);

	g_free(value);
}

void __certificate_properties_fill_cert_subjectPublicKeyInfo (GnomintPropNode *parent,
                                                              gnutls_x509_crt_t *certificate)
{
	int result;
	unsigned int bits = 0;
	const gchar * name = NULL;
	gchar *value;
	gnutls_datum_t modulus, publicExponent;
	gnutls_datum_t p, q, g, y;

	result = gnutls_x509_crt_get_pk_algorithm(*certificate, &bits);
	name = gnutls_pk_algorithm_get_name(result);

	GnomintPropNode *spki_node = gnomint_prop_node_new(_("Subject Public Key Info"), NULL);
	g_list_store_append(gnomint_prop_node_get_children(parent), spki_node);

	GnomintPropNode *alg_node = gnomint_prop_node_new(_("Algorithm"), NULL);
	g_list_store_append(gnomint_prop_node_get_children(spki_node), alg_node);

	GnomintPropNode *alg_child = gnomint_prop_node_new(_("Algorithm"), name);
	g_list_store_append(gnomint_prop_node_get_children(alg_node), alg_child);
	g_object_unref(alg_child);

	switch (result) {
	case GNUTLS_PK_RSA:
	{
		GnomintPropNode *params_child = gnomint_prop_node_new(_("Parameters"), _("(unknown)"));
		g_list_store_append(gnomint_prop_node_get_children(alg_node), params_child);
		g_object_unref(params_child);

		GnomintPropNode *rsa_node = gnomint_prop_node_new(_("RSA PublicKey"), NULL);
		g_list_store_append(gnomint_prop_node_get_children(spki_node), rsa_node);

		result = gnutls_x509_crt_get_pk_rsa_raw(*certificate, &modulus, &publicExponent);
		if (result < 0) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			g_object_unref(rsa_node);
			break;
		}
		value = __certificate_properties_dump_raw_data(modulus.data, modulus.size);
		gnutls_free(modulus.data);

		GnomintPropNode *mod_child = gnomint_prop_node_new(_("Modulus"), value);
		g_list_store_append(gnomint_prop_node_get_children(rsa_node), mod_child);
		g_object_unref(mod_child);
		g_free(value);

		value = __certificate_properties_dump_raw_data(publicExponent.data, publicExponent.size);
		gnutls_free(publicExponent.data);

		GnomintPropNode *exp_child = gnomint_prop_node_new(_("Public Exponent"), value);
		g_list_store_append(gnomint_prop_node_get_children(rsa_node), exp_child);
		g_object_unref(exp_child);
		g_free(value);

		g_object_unref(rsa_node);
		break;
	}
	case GNUTLS_PK_DSA:
	{
		result = gnutls_x509_crt_get_pk_dsa_raw(*certificate, &p, &q, &g, &y);
		if (result < 0) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}

		GnomintPropNode *params_node = gnomint_prop_node_new(_("Parameters"), NULL);
		g_list_store_append(gnomint_prop_node_get_children(alg_node), params_node);

		value = __certificate_properties_dump_raw_data(p.data, p.size);
		gnutls_free(p.data);
		GnomintPropNode *p_child = gnomint_prop_node_new("p", value);
		g_list_store_append(gnomint_prop_node_get_children(params_node), p_child);
		g_object_unref(p_child);
		g_free(value);

		value = __certificate_properties_dump_raw_data(q.data, q.size);
		gnutls_free(q.data);
		GnomintPropNode *q_child = gnomint_prop_node_new("p", value);
		g_list_store_append(gnomint_prop_node_get_children(params_node), q_child);
		g_object_unref(q_child);
		g_free(value);

		value = __certificate_properties_dump_raw_data(g.data, g.size);
		gnutls_free(g.data);
		GnomintPropNode *g_child = gnomint_prop_node_new("g", value);
		g_list_store_append(gnomint_prop_node_get_children(params_node), g_child);
		g_object_unref(g_child);
		g_free(value);

		g_object_unref(params_node);

		value = __certificate_properties_dump_raw_data(y.data, y.size);
		gnutls_free(y.data);

		GnomintPropNode *dsa_child = gnomint_prop_node_new(_("DSA PublicKey"), value);
		g_list_store_append(gnomint_prop_node_get_children(spki_node), dsa_child);
		g_object_unref(dsa_child);
		g_free(value);
		break;
	}
	default:
	{
		GnomintPropNode *params_child = gnomint_prop_node_new(_("Parameters"), _("(unknown)"));
		g_list_store_append(gnomint_prop_node_get_children(alg_node), params_child);
		g_object_unref(params_child);

		GnomintPropNode *spk_child = gnomint_prop_node_new(_("Subject Public Key"), _("(unknown)"));
		g_list_store_append(gnomint_prop_node_get_children(spki_node), spk_child);
		g_object_unref(spk_child);
		break;
	}
	}

	g_object_unref(alg_node);
	g_object_unref(spki_node);
}

void __certificate_properties_fill_cert_issuerUniqueID (GnomintPropNode *parent,
							  gnutls_x509_crt_t *certificate)
{
	GnomintPropNode *child = gnomint_prop_node_new(_("Issuer Unique ID"), _("(unknown)"));
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);
	(void)certificate;
}

void __certificate_properties_fill_cert_subjectUniqueID (GnomintPropNode *parent,
							   gnutls_x509_crt_t *certificate)
{
	GnomintPropNode *child = gnomint_prop_node_new(_("Subject Unique ID"), _("(unknown)"));
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);
	(void)certificate;
}

void __certificate_properties_fill_cert_ext_SubjectKeyIdentifier (GnomintPropNode *parent,
								   gnutls_x509_crt_t *certificate)
{
	guint critical;
	gint result;
	const gint BUFFER_SIZE_MAX = 256;
	gchar buffer[BUFFER_SIZE_MAX];
	gsize buffer_size = BUFFER_SIZE_MAX;
	gchar *hex_buffer;

	result = gnutls_x509_crt_get_subject_key_id(*certificate, buffer, &buffer_size, &critical);
	if (result < 0) {
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}
	hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);

	GnomintPropNode *child = gnomint_prop_node_new(_("Value"), hex_buffer);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);

	g_free(hex_buffer);
}

void __certificate_properties_fill_cert_ext_KeyUsage (GnomintPropNode *parent,
						       gnutls_x509_crt_t *certificate)
{
	guint critical;
	guint key_usage;
	gint result;
        gchar * buffer = NULL;

	result = gnutls_x509_crt_get_key_usage(*certificate, &key_usage, &critical);

	if (result < 0) {
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}
	buffer = __certificate_properties_dump_key_usage(key_usage);

	GnomintPropNode *child = gnomint_prop_node_new(_("Value"), buffer);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);

	g_free(buffer);
}

void __certificate_properties_fill_cert_ext_SubjectAltName (GnomintPropNode *parent,
							     gnutls_x509_crt_t *certificate)
{
	gint i = 0;
	while (1)
	{
		gint result;
		guint critical;
		const gint BUFFER_SIZE_MAX = 1024;
		gchar buffer[BUFFER_SIZE_MAX];
		gsize buffer_size = BUFFER_SIZE_MAX;
		gchar *hex_buffer;

		result = gnutls_x509_crt_get_subject_alt_name(*certificate, i, buffer, &buffer_size, &critical);

		if (result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			break;
		}

		if (result == GNUTLS_E_SHORT_MEMORY_BUFFER) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}

		if (result < 0) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}

		switch (result) {
		case GNUTLS_SAN_DNSNAME:
		{
			GnomintPropNode *child = gnomint_prop_node_new(_("DNS Name"), buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			break;
		}
		case GNUTLS_SAN_RFC822NAME:
		{
			GnomintPropNode *child = gnomint_prop_node_new(_("RFC822 Name"), buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			break;
		}
		case GNUTLS_SAN_URI:
		{
			GnomintPropNode *child = gnomint_prop_node_new(_("URI"), buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			break;
		}
		case GNUTLS_SAN_IPADDRESS:
			// Convert binary IP to readable format
			if (buffer_size == 4) {
				// IPv4
				gchar ip_str[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, buffer, ip_str, sizeof(ip_str))) {
					GnomintPropNode *child = gnomint_prop_node_new(_("IP Address"), ip_str);
					g_list_store_append(gnomint_prop_node_get_children(parent), child);
					g_object_unref(child);
				} else {
					hex_buffer = __certificate_properties_dump_raw_data ((guchar *) buffer, buffer_size);
					GnomintPropNode *child = gnomint_prop_node_new(_("IP"), hex_buffer);
					g_list_store_append(gnomint_prop_node_get_children(parent), child);
					g_object_unref(child);
					g_free(hex_buffer);
				}
			} else if (buffer_size == 16) {
				// IPv6
				gchar ip_str[INET6_ADDRSTRLEN];
				if (inet_ntop(AF_INET6, buffer, ip_str, sizeof(ip_str))) {
					GnomintPropNode *child = gnomint_prop_node_new(_("IP Address"), ip_str);
					g_list_store_append(gnomint_prop_node_get_children(parent), child);
					g_object_unref(child);
				} else {
					hex_buffer = __certificate_properties_dump_raw_data ((guchar *) buffer, buffer_size);
					GnomintPropNode *child = gnomint_prop_node_new(_("IP"), hex_buffer);
					g_list_store_append(gnomint_prop_node_get_children(parent), child);
					g_object_unref(child);
					g_free(hex_buffer);
				}
			} else {
				// Unknown format, fall back to hex
				hex_buffer = __certificate_properties_dump_raw_data ((guchar *) buffer, buffer_size);
				GnomintPropNode *child = gnomint_prop_node_new(_("IP"), hex_buffer);
				g_list_store_append(gnomint_prop_node_get_children(parent), child);
				g_object_unref(child);
				g_free(hex_buffer);
			}
			break;
		case GNUTLS_SAN_DN:
		{
			hex_buffer = __certificate_properties_dump_RDNSequence (buffer, buffer_size);
			GnomintPropNode *child = gnomint_prop_node_new(_("Directory Name"), hex_buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			g_free(hex_buffer);
			break;
		}
		default:
		{
			hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);
			GnomintPropNode *child = gnomint_prop_node_new(_("Value"), hex_buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			g_free(hex_buffer);
			break;
		}
		}
		i++;
	}
}

void __certificate_properties_fill_cert_ext_BasicConstraints (GnomintPropNode *parent,
							       gnutls_x509_crt_t *certificate)
{
	guint critical;
	gint result;
	guint ca;
	gint path_len_constraint;
	gchar *pathlen_as_string = NULL;
        gchar *ca_as_string = NULL;

	result = gnutls_x509_crt_get_basic_constraints(*certificate, &critical, &ca, &path_len_constraint);

	if (result < 0)	{
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}

	ca_as_string = ca ? _("TRUE") : _("FALSE");

	pathlen_as_string = g_strdup_printf ("%d", path_len_constraint);

	GnomintPropNode *ca_child = gnomint_prop_node_new(_("CA"), ca_as_string);
	g_list_store_append(gnomint_prop_node_get_children(parent), ca_child);
	g_object_unref(ca_child);

	GnomintPropNode *pl_child = gnomint_prop_node_new(_("Path Length Constraint"), pathlen_as_string);
	g_list_store_append(gnomint_prop_node_get_children(parent), pl_child);
	g_object_unref(pl_child);

	g_free (pathlen_as_string);
}

void __certificate_properties_fill_cert_ext_CRLDistributionPoints (GnomintPropNode *parent,
								    gnutls_x509_crt_t *certificate)
{
	gint i;
	for (i = 0;; i++)
	{
		gint result;
		guint critical;
		const gint BUFFER_SIZE_MAX = 1024;
		gchar buffer[BUFFER_SIZE_MAX];
		gsize buffer_size = BUFFER_SIZE_MAX;
		gchar *hex_buffer;

		result = gnutls_x509_crt_get_crl_dist_points(*certificate, i, buffer, &buffer_size, 0, &critical);
		if (result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;

		if (result == GNUTLS_E_SHORT_MEMORY_BUFFER) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}

		if (result < 0)	{
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}

		switch (result)	{
		case GNUTLS_SAN_DNSNAME:
		{
			GnomintPropNode *child = gnomint_prop_node_new(_("DNS Name"), buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			break;
		}
		case GNUTLS_SAN_RFC822NAME:
		{
			GnomintPropNode *child = gnomint_prop_node_new(_("RFC822 Name"), buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			break;
		}
		case GNUTLS_SAN_URI:
		{
			GnomintPropNode *child = gnomint_prop_node_new(_("URI"), buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			break;
		}
		case GNUTLS_SAN_IPADDRESS:
		{
			hex_buffer = __certificate_properties_dump_raw_data ((guchar *) buffer, buffer_size);
			GnomintPropNode *child = gnomint_prop_node_new(_("IP Address"), hex_buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			g_free(hex_buffer);
			break;
		}
		case GNUTLS_SAN_DN:
		{
			hex_buffer = __certificate_properties_dump_RDNSequence (buffer, buffer_size);
			GnomintPropNode *child = gnomint_prop_node_new(_("Directory Name"), hex_buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			g_free(hex_buffer);
			break;
		}
		default:
		{
			hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);
			GnomintPropNode *child = gnomint_prop_node_new(_("Value"), hex_buffer);
			g_list_store_append(gnomint_prop_node_get_children(parent), child);
			g_object_unref(child);
			g_free(hex_buffer);
			break;
		}
		}
	}
}

void __certificate_properties_fill_cert_ext_AuthorityKeyIdentifier (GnomintPropNode *parent,
								     gnutls_x509_crt_t *certificate)
{
	gint result;
	guint critical;
	const gint BUFFER_SIZE_MAX = 256;
	gchar buffer[BUFFER_SIZE_MAX];
	gsize buffer_size = BUFFER_SIZE_MAX;
	gchar *hex_buffer = NULL;

	result = gnutls_x509_crt_get_authority_key_id(*certificate, buffer, &buffer_size, &critical);
	if (result < 0) {
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}
	hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);

	GnomintPropNode *child = gnomint_prop_node_new(_("Value"), hex_buffer);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);

	g_free(hex_buffer);
}

void __certificate_properties_fill_cert_ext_ExtKeyUsage (GnomintPropNode *parent,
							  gnutls_x509_crt_t *certificate)
{
	gint i;
	const gint BUFFER_SIZE_MAX = 1024;
	gchar usage_buffer[BUFFER_SIZE_MAX];
	gchar *usage_buffer_iterator = usage_buffer;

	for (i = 0;; i++) {
		gint result;
		gchar buffer[BUFFER_SIZE_MAX];
		gsize buffer_size = BUFFER_SIZE_MAX;
                const gchar *label = NULL;
		result = gnutls_x509_crt_get_key_purpose_oid(*certificate, i, buffer, &buffer_size, 0);

		if (result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			break;
		}
		if (result == GNUTLS_E_SHORT_MEMORY_BUFFER) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			return;
		}
		if (result < 0) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			return;
		}
		label = __certificate_properties_lookup_oid_label(certificate_properties_oid_label_table, buffer);
		usage_buffer_iterator += sprintf(usage_buffer_iterator, "%s\n", label);
	}

	*(usage_buffer_iterator - 1) = 0;

	GnomintPropNode *child = gnomint_prop_node_new(_("Value"), usage_buffer);
	g_list_store_append(gnomint_prop_node_get_children(parent), child);
	g_object_unref(child);
}

void __certificate_properties_fill_cert_ext (GnomintPropNode *parent,
					      gnutls_x509_crt_t *certificate)
{
	gint result;
	const gint OID_SIZE_MAX = 128;
	gchar oid[OID_SIZE_MAX];
	gsize oid_size = OID_SIZE_MAX;
	guint critical;
	guint i;
	GnomintPropNode *ext_node = NULL;

	for (i = 0;; i++) {
                const gchar *label = NULL;
                const gchar *critical_as_string = NULL;
		certificate_properties_fill_t function;

		oid_size = OID_SIZE_MAX;
		result = gnutls_x509_crt_get_extension_info(*certificate, i, oid, &oid_size, &critical);
		if (result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (result < 0)	{
			fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
			break;
		}
		if (i == 0) {
			ext_node = gnomint_prop_node_new(_("Extensions"), NULL);
			g_list_store_append(gnomint_prop_node_get_children(parent), ext_node);
		}
		label = __certificate_properties_lookup_oid_label(certificate_properties_oid_label_table, oid);
		if (!label)
			label = oid;

		GnomintPropNode *ext_item = gnomint_prop_node_new(label, NULL);
		g_list_store_append(gnomint_prop_node_get_children(ext_node), ext_item);

		critical_as_string = critical ? _("TRUE") : _("FALSE");

		GnomintPropNode *crit_child = gnomint_prop_node_new(_("Critical"), critical_as_string);
		g_list_store_append(gnomint_prop_node_get_children(ext_item), crit_child);
		g_object_unref(crit_child);

		function = __certificate_properties_lookup_oid_function(certificate_properties_oid_function_table, oid);
		if (function)
			function(ext_item, certificate);
		else {
			const gint BUFFER_SIZE_MAX = 1024;
			gchar buffer[BUFFER_SIZE_MAX];
			gsize buffer_size = BUFFER_SIZE_MAX;
                        gchar *hex_buffer = NULL;

			gnutls_x509_crt_get_extension_data(*certificate, i, buffer, &buffer_size);
			hex_buffer = __certificate_properties_dump_raw_data((unsigned char *) buffer, buffer_size);

			GnomintPropNode *val_child = gnomint_prop_node_new(_("Value"), hex_buffer);
			g_list_store_append(gnomint_prop_node_get_children(ext_item), val_child);
			g_object_unref(val_child);

			g_free(hex_buffer);
		}

		g_object_unref(ext_item);
	}

	if (ext_node)
		g_object_unref(ext_node);
}

void __certificate_properties_fill_cert (GListStore *root_store,
					   gnutls_x509_crt_t *certificate)
{
	GnomintPropNode *cert_node = gnomint_prop_node_new(_("Certificate"), NULL);
	g_list_store_append(root_store, cert_node);

	__certificate_properties_fill_cert_version(cert_node, certificate);
	__certificate_properties_fill_cert_serialNumber(cert_node, certificate);
	__certificate_properties_fill_cert_signature(cert_node, certificate);
	__certificate_properties_fill_cert_issuer(cert_node, certificate);
	__certificate_properties_fill_cert_validity(cert_node, certificate);
	__certificate_properties_fill_cert_subject(cert_node, certificate);
	__certificate_properties_fill_cert_subjectPublicKeyInfo(cert_node, certificate);
	__certificate_properties_fill_cert_issuerUniqueID(cert_node, certificate);
	__certificate_properties_fill_cert_subjectUniqueID(cert_node, certificate);
	__certificate_properties_fill_cert_ext(cert_node, certificate);

	g_object_unref(cert_node);
}

void __certificate_properties_fill_signatureAlgorithm (GListStore *root_store,
						       gnutls_x509_crt_t *certificate)
{
	gint result;
        const gchar *name = NULL;

	result = gnutls_x509_crt_get_signature_algorithm(*certificate);
	name = gnutls_sign_algorithm_get_name(result);

	GnomintPropNode *sigalg_node = gnomint_prop_node_new(_("Signature Algorithm"), NULL);
	g_list_store_append(root_store, sigalg_node);

	GnomintPropNode *alg_child = gnomint_prop_node_new(_("Algorithm"), name);
	g_list_store_append(gnomint_prop_node_get_children(sigalg_node), alg_child);
	g_object_unref(alg_child);

	GnomintPropNode *params_child = gnomint_prop_node_new(_("Parameters"), _("(unknown)"));
	g_list_store_append(gnomint_prop_node_get_children(sigalg_node), params_child);
	g_object_unref(params_child);

	g_object_unref(sigalg_node);
}

void __certificate_properties_fill_signatureValue (GListStore *root_store, gnutls_x509_crt_t *certificate)
{
	gint result;
	gchar *buffer = NULL;
	gsize buffer_size = 0;
	gchar *hex_buffer = NULL;

	result = gnutls_x509_crt_get_signature(*certificate, 0, &buffer_size);
	if (result != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}

	buffer = g_new0 (gchar, buffer_size);

	result = gnutls_x509_crt_get_signature(*certificate, buffer, &buffer_size);
	if (result < 0) {
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}

	hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);

	GnomintPropNode *sig_child = gnomint_prop_node_new(_("Signature"), hex_buffer);
	g_list_store_append(root_store, sig_child);
	g_object_unref(sig_child);

	g_free(hex_buffer);
}

void __certificate_properties_fill_certificate(GListStore *root_store, gnutls_x509_crt_t *certificate)
{
	__certificate_properties_fill_cert(root_store, certificate);
	__certificate_properties_fill_signatureAlgorithm(root_store, certificate);
	__certificate_properties_fill_signatureValue(root_store, certificate);
}


/* ------------------------------------------------------------------ */
/*  GtkColumnView factory callbacks for the certificate details tree  */
/* ------------------------------------------------------------------ */

/* Helper: extract the GnomintPropNode from a GtkListItem. The item in
 * a GtkTreeListModel-backed column view is a GtkTreeListRow; the
 * actual data object is obtained via gtk_tree_list_row_get_item(). */
static GnomintPropNode *
__cert_prop_node_from_list_item (GtkListItem *list_item)
{
	GtkTreeListRow *tree_row = GTK_TREE_LIST_ROW (
	    gtk_list_item_get_item (list_item));
	if (!tree_row)
		return NULL;
	return GNOMINT_PROP_NODE (gtk_tree_list_row_get_item (tree_row));
}

/* --- Name column (GtkTreeExpander + GtkLabel) --- */

static void
__cert_name_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                   GtkListItem *list_item,
                   gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *expander = gtk_tree_expander_new ();
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	gtk_tree_expander_set_child (GTK_TREE_EXPANDER (expander), label);
	gtk_list_item_set_child (list_item, expander);
}

static void
__cert_name_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                  GtkListItem *list_item,
                  gpointer user_data G_GNUC_UNUSED)
{
	GtkTreeListRow *tree_row = GTK_TREE_LIST_ROW (
	    gtk_list_item_get_item (list_item));
	GtkWidget *expander = gtk_list_item_get_child (list_item);
	gtk_tree_expander_set_list_row (GTK_TREE_EXPANDER (expander), tree_row);

	GnomintPropNode *node = GNOMINT_PROP_NODE (
	    gtk_tree_list_row_get_item (tree_row));
	GtkWidget *label = gtk_tree_expander_get_child (
	    GTK_TREE_EXPANDER (expander));

	const gchar *name = gnomint_prop_node_get_name (node);
	gtk_label_set_text (GTK_LABEL (label), name ? name : "");

	g_object_unref (node);
}

/* --- Value column (GtkLabel, monospace) --- */

static void
__cert_value_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                    GtkListItem *list_item,
                    gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_widget_set_halign (label, GTK_ALIGN_START);

	/* Apply monospace font via CSS, matching the old cell renderer. */
	GtkCssProvider *prov = gtk_css_provider_new ();
	gtk_css_provider_load_from_data (prov, "label { font-family: Monospace; }", -1);
	gtk_style_context_add_provider (
	    gtk_widget_get_style_context (label),
	    GTK_STYLE_PROVIDER (prov),
	    GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (prov);

	gtk_list_item_set_child (list_item, label);
}

static void
__cert_value_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                   GtkListItem *list_item,
                   gpointer user_data G_GNUC_UNUSED)
{
	GnomintPropNode *node = __cert_prop_node_from_list_item (list_item);
	GtkWidget *label = gtk_list_item_get_child (list_item);

	const gchar *value = gnomint_prop_node_get_value (node);
	gtk_label_set_text (GTK_LABEL (label), value ? value : "");

	g_object_unref (node);
}

/* GtkTreeListModel child-model callback: given a GnomintPropNode,
 * return its children GListStore (or NULL if empty/leaf). */
static GListModel *
__cert_tree_list_create_model (gpointer item, gpointer user_data G_GNUC_UNUSED)
{
	GnomintPropNode *node = GNOMINT_PROP_NODE (item);
	GListStore *children = gnomint_prop_node_get_children (node);
	if (g_list_model_get_n_items (G_LIST_MODEL (children)) == 0)
		return NULL;
	return G_LIST_MODEL (g_object_ref (children));
}

/* Helper: recursively expand all rows in the tree list model. */
static void
__cert_expand_all (GtkTreeListModel *tree_model)
{
	guint n = g_list_model_get_n_items (G_LIST_MODEL (tree_model));
	for (guint i = 0; i < n; i++) {
		GtkTreeListRow *tlr = gtk_tree_list_model_get_row (tree_model, i);
		if (tlr) {
			gtk_tree_list_row_set_expanded (tlr, TRUE);
			g_object_unref (tlr);
		}
		/* After expanding, new items may have been inserted. */
		n = g_list_model_get_n_items (G_LIST_MODEL (tree_model));
	}
}


void
__certificate_details_populate(const char *certificate_pem)
{
	gint result;
	gnutls_datum_t pem_datum;
	gnutls_x509_crt_t certificate;

	pem_datum.data = (guchar *) certificate_pem;
	pem_datum.size = strlen(certificate_pem);
	result = gnutls_x509_crt_init(&certificate);

	if (result < 0)
	{
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}

	gnutls_x509_crt_import(certificate, &pem_datum, GNUTLS_X509_FMT_PEM);
	if (result < 0)
	{
		fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
		return;
	}

	/* Build the prop-node tree. */
	GListStore *root_store = g_list_store_new (GNOMINT_TYPE_PROP_NODE);
	__certificate_properties_fill_certificate(root_store, &certificate);
	gnutls_x509_crt_deinit(certificate);

	/* Create a GtkTreeListModel wrapping the root store. */
	GtkTreeListModel *tree_model = gtk_tree_list_model_new (
	    G_LIST_MODEL (g_object_ref (root_store)),
	    FALSE,   /* passthrough = FALSE so items are GtkTreeListRow */
	    TRUE,    /* autoexpand */
	    __cert_tree_list_create_model,
	    NULL, NULL);

	/* Expand all rows. */
	__cert_expand_all (tree_model);

	/* Wrap in a GtkNoSelection (read-only display). */
	GtkNoSelection *no_sel = gtk_no_selection_new (G_LIST_MODEL (tree_model));

	/* Get the column view from the builder. */
	GObject *view = gtk_builder_get_object (certificate_properties_window_gtkb, "certTreeView");
	GtkColumnView *colview = GTK_COLUMN_VIEW (view);

	/* Set headers invisible to match the old tree view appearance. */
	gtk_column_view_set_show_column_separators (colview, FALSE);
	gtk_column_view_set_show_row_separators (colview, FALSE);

	/* Build and attach columns if not already present. */
	{
		/* Name column with tree expander. */
		GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
		g_signal_connect (f, "setup", G_CALLBACK (__cert_name_setup), NULL);
		g_signal_connect (f, "bind",  G_CALLBACK (__cert_name_bind),  NULL);
		GtkColumnViewColumn *col = gtk_column_view_column_new (_("Name"), f);
		gtk_column_view_column_set_expand (col, TRUE);
		gtk_column_view_column_set_resizable (col, TRUE);
		gtk_column_view_append_column (colview, col);
		g_object_unref (col);
	}
	{
		/* Value column with monospace font. */
		GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
		g_signal_connect (f, "setup", G_CALLBACK (__cert_value_setup), NULL);
		g_signal_connect (f, "bind",  G_CALLBACK (__cert_value_bind),  NULL);
		GtkColumnViewColumn *col = gtk_column_view_column_new (_("Value"), f);
		gtk_column_view_column_set_expand (col, TRUE);
		gtk_column_view_column_set_resizable (col, TRUE);
		gtk_column_view_append_column (colview, col);
		g_object_unref (col);
	}

	/* Set the model on the column view. */
	gtk_column_view_set_model (colview, GTK_SELECTION_MODEL (no_sel));

	g_object_unref (no_sel);
	g_object_unref (root_store);
}

#if 0

//Function included for generating extra gettext strings. Do not remove.

void useless_function ()
{
	printf ("%s",_("TLS WWW Server"));
	printf ("%s",_("TLS WWW Client"));
	printf ("%s",_("Code signing"));
	printf ("%s",_("Email protection"));
	printf ("%s",_("Time stamping"));
	printf ("%s",_("OCSP signing"));
	printf ("%s",_("Any purpose"));
	printf ("%s",_("Subject Directory Attributes"));
	printf ("%s",_("Subject Key Identifier"));
	printf ("%s",_("Key Usage"));
	printf ("%s",_("Private Key Usage Period"));
	printf ("%s",_("Subject Alternative Name"));
	printf ("%s",_("Basic Constraints"));
	printf ("%s",_("Name Constraints"));
	printf ("%s",_("CRL Distribution Points"));
	printf ("%s",_("Certificate Policies"));
	printf ("%s",_("Policy Mappings"));
	printf ("%s",_("Authority Key Identifier"));
	printf ("%s",_("Policy Constraints"));
	printf ("%s",_("Extended Key Usage"));
	printf ("%s",_("Delta CRL Distribution Point"));
	printf ("%s",_("Inhibit Any-Policy"));

}

#endif

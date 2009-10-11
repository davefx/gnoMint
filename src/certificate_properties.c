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

#include "tls.h"
#include "ca_policy.h"
#include "certificate_properties.h"

#include <glib/gi18n.h>

typedef struct
{
	const gchar *oid;
	const gchar *label;
} certificate_properties_oid_label_couple_t;

enum
{
	CERTIFICATE_PROPERTIES_COL_NAME = 0,
	CERTIFICATE_PROPERTIES_COL_VALUE,
	CERTIFICATE_PROPERTIES_N_COLUMNS
};

typedef void (*certificate_properties_fill_t) (GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);

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

void __certificate_properties_fill_cert_ext_SubjectKeyIdentifier(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_KeyUsage(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_SubjectAltName(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_BasicConstraints(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_CRLDistributionPoints(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_AuthorityKeyIdentifier(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
void __certificate_properties_fill_cert_ext_ExtKeyUsage(GtkTreeStore *, GtkTreeIter *, gnutls_x509_crt_t *);
gchar * __certificate_properties_dump_raw_data(const unsigned char *buffer, size_t buffer_size);
const gchar * __certificate_properties_lookup_oid_label(const certificate_properties_oid_label_couple_t *oid_label_table, const gchar *oid);
certificate_properties_fill_t __certificate_properties_lookup_oid_function (const certificate_properties_oid_function_couple_t *oid_func_table, 
									    const gchar *oid);
gchar * __certificate_properties_dump_RDNSequence(const gchar *buffer, gsize buffer_size);
gchar * __certificate_properties_dump_key_usage(guint key_usage);
void __certificate_properties_fill_cert_version(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_serialNumber(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_signature(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_issuer(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_validity (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_subject (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_subjectPublicKeyInfo (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_issuerUniqueID (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_subjectUniqueID (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert_ext (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_cert (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_signatureAlgorithm (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_signatureValue (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate);
void __certificate_properties_fill_certificate(GtkTreeStore *store, gnutls_x509_crt_t *certificate);



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
	gtk_builder_connect_signals (certificate_properties_window_gtkb, NULL);
	
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

	gtk_widget_show (GTK_WIDGET(widget));
}


void __certificate_properties_populate (const char *certificate_pem)
{
	GObject *widget = NULL;
	struct tm tim;
	TlsCert * cert = NULL;
	gchar model_time_str[100];
        gchar * aux;
	UInt160 * serial_number;

	cert = tls_parse_cert_pem (certificate_pem);

	serial_number = &cert->serial_number;

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certActivationDateLabel");
	gmtime_r (&cert->activation_time, &tim);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tim);	
	gtk_label_set_text (GTK_LABEL(widget), model_time_str);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certExpirationDateLabel");
	gmtime_r (&cert->expiration_time, &tim);
	strftime (model_time_str, 100, _("%m/%d/%Y %R GMT"), &tim);	
	gtk_label_set_text (GTK_LABEL(widget), model_time_str);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSNLabel");	
        aux = uint160_strdup_printf (&cert->serial_number);
	gtk_label_set_text (GTK_LABEL(widget), aux);
        g_free (aux);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectCNLabel");	
	gtk_label_set_text (GTK_LABEL(widget), cert->cn);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectOLabel");	
	gtk_label_set_text (GTK_LABEL(widget), cert->o);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certSubjectOULabel");	
	gtk_label_set_text (GTK_LABEL(widget), cert->ou);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerCNLabel");	
	gtk_label_set_text (GTK_LABEL(widget), cert->i_cn);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerOLabel");	
	gtk_label_set_text (GTK_LABEL(widget), cert->i_o);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certIssuerOULabel");	
	gtk_label_set_text (GTK_LABEL(widget), cert->i_ou);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "sha1Label");	
	gtk_label_set_text (GTK_LABEL(widget), cert->sha1);

	widget = gtk_builder_get_object (certificate_properties_window_gtkb, "md5Label");	
	gtk_label_set_text (GTK_LABEL(widget), cert->md5);


	if (g_list_length (cert->uses)) {
		GValue * valtrue = g_new0 (GValue, 1);
		int i;
		
		g_value_init (valtrue, G_TYPE_BOOLEAN);
		g_value_set_boolean (valtrue, TRUE);

		widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certPropSeparator");
		gtk_widget_show (GTK_WIDGET(widget));
		
		widget = gtk_builder_get_object (certificate_properties_window_gtkb, "vboxCertCapabilities");
		
		for (i = g_list_length(cert->uses) - 1; i >= 0; i--) {
			GtkLabel *label = NULL;
			label = GTK_LABEL(gtk_label_new ((gchar *) g_list_nth_data (cert->uses, i)));
			gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.5);
			gtk_box_pack_end (GTK_BOX(widget), GTK_WIDGET(label), 0, 0, 0);
		}
		gtk_widget_show_all (GTK_WIDGET(widget));
		
		g_free (valtrue);
	}



	tls_cert_free (cert);
	
	return;
}

void certificate_properties_close_clicked (const char *certificate_pem)
{
	GObject *widget = gtk_builder_get_object (certificate_properties_window_gtkb, "certificate_properties_dialog");
	gtk_widget_destroy (GTK_WIDGET(widget));
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
		result_iterator += sprintf(result_iterator, "%02x:", buffer[i]);
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
	return _(i->label);
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

void __certificate_properties_fill_cert_version(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	gint result;
	gchar value[4];
	GtkTreeIter j;

	result = gnutls_x509_crt_get_version(*certificate);
	sprintf(value, "v%d", result);
	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Version"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
}

void __certificate_properties_fill_cert_serialNumber(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	gint result;
	gsize buffer_size = 0;
	GtkTreeIter j;
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

	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Serial Number"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);

	g_free(value);
}

void __certificate_properties_fill_cert_signature(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	int result;
	GtkTreeIter j;
	GtkTreeIter k;
        const gchar *name = NULL;

	result = gnutls_x509_crt_get_signature_algorithm(*certificate);
	name = gnutls_sign_algorithm_get_name(result);

	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Signature"), -1);

	gtk_tree_store_append(store, &k, &j);
	gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("Algorithm"), CERTIFICATE_PROPERTIES_COL_VALUE, name, -1);

	gtk_tree_store_append(store, &k, &j);
	gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("Parameters"), CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
}

void __certificate_properties_fill_cert_issuer(GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	int result;
	size_t buffer_size = 0;
	gchar * buffer = NULL;
	gchar * value = NULL;
	GtkTreeIter j;

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

	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Issuer"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);

	g_free(value);
}

void __certificate_properties_fill_cert_validity (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	time_t not_before;
	struct tm not_before_broken_down_time;
	gchar not_before_asctime[32];
	time_t not_after;
	struct tm not_after_broken_down_time;
	gchar not_after_asctime[32];
	GtkTreeIter j;
	GtkTreeIter k;

	not_before = gnutls_x509_crt_get_activation_time(*certificate);
	gmtime_r(&not_before, &not_before_broken_down_time);
	asctime_r(&not_before_broken_down_time, not_before_asctime);

	not_before_asctime[strlen(not_before_asctime) - 1] = 0;
	not_after = gnutls_x509_crt_get_expiration_time(*certificate);
	gmtime_r(&not_after, &not_after_broken_down_time);

	asctime_r(&not_after_broken_down_time, not_after_asctime);
	not_after_asctime[strlen(not_after_asctime) - 1] = 0;

	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Validity"), -1);

	gtk_tree_store_append(store, &k, &j);
	gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("Not Before"), CERTIFICATE_PROPERTIES_COL_VALUE, not_before_asctime, -1);

	gtk_tree_store_append(store, &k, &j);
	gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("Not After"), CERTIFICATE_PROPERTIES_COL_VALUE, not_after_asctime, -1);
}

void __certificate_properties_fill_cert_subject (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	int result;
	size_t buffer_size = 0;
	gchar *buffer = NULL;
	gchar *value = NULL;
	GtkTreeIter j;

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

	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Subject"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);

	g_free(value);
}

void __certificate_properties_fill_cert_subjectPublicKeyInfo (GtkTreeStore *store, 
                                                              GtkTreeIter *parent, 
                                                              gnutls_x509_crt_t *certificate)
{
	int result;
	unsigned int bits = 0;
	const gchar * name = NULL;
	GtkTreeIter j;
	GtkTreeIter k;
	GtkTreeIter l;
	gchar *value;
	GtkTreeIter m;
	gnutls_datum_t modulus, publicExponent;
	gnutls_datum_t p, q, g, y;

	result = gnutls_x509_crt_get_pk_algorithm(*certificate, &bits);
	name = gnutls_pk_algorithm_get_name(result);

	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Subject Public Key Info"), -1);

	gtk_tree_store_append(store, &k, &j);
	gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("Algorithm"), -1);

	gtk_tree_store_append(store, &l, &k);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Algorithm"), CERTIFICATE_PROPERTIES_COL_VALUE, name, -1);

	switch (result) {
	case GNUTLS_PK_RSA:
		gtk_tree_store_append(store, &l, &k);
		gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Parameters"), CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
		gtk_tree_store_append(store, &k, &j);
		gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("RSA PublicKey"), -1);
		result = gnutls_x509_crt_get_pk_rsa_raw(*certificate, &modulus, &publicExponent);
		if (result < 0) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}
		value = __certificate_properties_dump_raw_data(modulus.data, modulus.size);
		gnutls_free(modulus.data);

		gtk_tree_store_append(store, &l, &k);
		gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Modulus"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
		g_free(value);

		value = __certificate_properties_dump_raw_data(publicExponent.data, publicExponent.size);
		gnutls_free(publicExponent.data);
		gtk_tree_store_append(store, &l, &k);
		gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Public Exponent"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
		g_free(value);
		break;
	case GNUTLS_PK_DSA:
		result = gnutls_x509_crt_get_pk_dsa_raw(*certificate, &p, &q, &g, &y);
		if (result < 0) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
			break;
		}
		gtk_tree_store_append(store, &l, &k);
		gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Parameters"), -1);

		value = __certificate_properties_dump_raw_data(p.data, p.size);
		gnutls_free(p.data);
		gtk_tree_store_append(store, &m, &l);
		gtk_tree_store_set(store, &m, CERTIFICATE_PROPERTIES_COL_NAME, "p", CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
		g_free(value);

		value = __certificate_properties_dump_raw_data(q.data, q.size);
		gnutls_free(q.data);
		gtk_tree_store_append(store, &m, &l);
		gtk_tree_store_set(store, &m, CERTIFICATE_PROPERTIES_COL_NAME, "p", CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
		g_free(value);

		value = __certificate_properties_dump_raw_data(g.data, g.size);
		gnutls_free(g.data);
		gtk_tree_store_append(store, &m, &l);
		gtk_tree_store_set(store, &m, CERTIFICATE_PROPERTIES_COL_NAME, "g", CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
		g_free(value);

		value = __certificate_properties_dump_raw_data(y.data, y.size);
		gnutls_free(y.data);
		gtk_tree_store_append(store, &k, &j);
		gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("DSA PublicKey"), CERTIFICATE_PROPERTIES_COL_VALUE, value, -1);
		g_free(value);
		break;
	default:
		gtk_tree_store_append(store, &l, &k);
		gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Parameters"), CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
		gtk_tree_store_append(store, &k, &j);
		gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, _("Subject Public Key"), CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
		break;
	}
}

void __certificate_properties_fill_cert_issuerUniqueID (GtkTreeStore *store, 
								  GtkTreeIter *parent, 
								  gnutls_x509_crt_t *certificate)
{
	GtkTreeIter j;
	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Issuer Unique ID"), CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
} 

void __certificate_properties_fill_cert_subjectUniqueID (GtkTreeStore *store, 
								   GtkTreeIter *parent, 
								   gnutls_x509_crt_t *certificate)
{
	GtkTreeIter j;
	gtk_tree_store_append(store, &j, parent);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Subject Unique ID"), CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
}

void __certificate_properties_fill_cert_ext_SubjectKeyIdentifier (GtkTreeStore *store, 
										   GtkTreeIter *parent, 
										   gnutls_x509_crt_t *certificate)
{
	guint critical;
	gint result;
	const gint BUFFER_SIZE_MAX = 256;
	gchar buffer[BUFFER_SIZE_MAX];
	gsize buffer_size = BUFFER_SIZE_MAX;
	gchar *hex_buffer;
	GtkTreeIter l;

	result = gnutls_x509_crt_get_subject_key_id(*certificate, buffer, &buffer_size, &critical);
	if (result < 0) {
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}
	hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);
	gtk_tree_store_append(store, &l, parent);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
	g_free(hex_buffer);
}

void __certificate_properties_fill_cert_ext_KeyUsage (GtkTreeStore *store, 
								       GtkTreeIter *parent, 
								       gnutls_x509_crt_t *certificate)
{
	guint critical;
	guint key_usage;
	gint result;
        gchar * buffer = NULL;
        GtkTreeIter l;

	result = gnutls_x509_crt_get_key_usage(*certificate, &key_usage, &critical);

	if (result < 0) {
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}
	buffer = __certificate_properties_dump_key_usage(key_usage);

	gtk_tree_store_append(store, &l, parent);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
	g_free(buffer);
}

void __certificate_properties_fill_cert_ext_SubjectAltName (GtkTreeStore *store, 
									     GtkTreeIter *parent, 
									     gnutls_x509_crt_t *certificate)
{
	gint i;
	for (i = 0; i < 1; i++)
	{
		gint result;
		guint critical;
		const gint BUFFER_SIZE_MAX = 1024;
		gchar buffer[BUFFER_SIZE_MAX];
		gsize buffer_size = BUFFER_SIZE_MAX;
		gchar *hex_buffer;
		GtkTreeIter l;

		result = gnutls_x509_crt_get_subject_alt_name(*certificate, i, buffer, &buffer_size, &critical);

		if (result == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			fprintf(stderr, "Error: (%s,%d): %s\n", __FILE__, __LINE__, gnutls_strerror(result));
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
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("DNS Name"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
			break;
		case GNUTLS_SAN_RFC822NAME:
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("RFC822 Name"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
			break;
		case GNUTLS_SAN_URI:
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("URI"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
			break;
		case GNUTLS_SAN_IPADDRESS:
			hex_buffer = __certificate_properties_dump_raw_data ((guchar *) buffer, buffer_size);
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("IP"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
			break;
		case GNUTLS_SAN_DN:
			hex_buffer = __certificate_properties_dump_RDNSequence (buffer, buffer_size);
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Directory Name"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
			break;
		default:
			hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);
			gtk_tree_store_append (store, &l, parent);
			gtk_tree_store_set (store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), 
					    CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
			break;
		}
	}
}

void __certificate_properties_fill_cert_ext_BasicConstraints (GtkTreeStore *store, 
									       GtkTreeIter *parent, 
									       gnutls_x509_crt_t *certificate)
{
	guint critical;
	gint result;
	gint ca;
	gint path_len_constraint;
	gchar *pathlen_as_string = NULL;
	GtkTreeIter l;
        gchar *ca_as_string = NULL;

	result = gnutls_x509_crt_get_basic_constraints(*certificate, &critical, &ca, &path_len_constraint);

	if (result < 0)	{
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}

	ca_as_string = ca ? _("TRUE") : _("FALSE");
	
	g_strdup_printf (pathlen_as_string, "%d", path_len_constraint);

	gtk_tree_store_append(store, &l, parent);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("CA"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, ca_as_string, -1);

	gtk_tree_store_append(store, &l, parent);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Path Length Constraint"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, pathlen_as_string, -1);

	g_free (pathlen_as_string);
}

void __certificate_properties_fill_cert_ext_CRLDistributionPoints (GtkTreeStore *store, 
										    GtkTreeIter *parent, 
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
		GtkTreeIter l;

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
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("DNS Name"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
			break;
		case GNUTLS_SAN_RFC822NAME:
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("RFC822 Name"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
			break;
		case GNUTLS_SAN_URI:
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("URI"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, buffer, -1);
			break;
		case GNUTLS_SAN_IPADDRESS:
			hex_buffer = __certificate_properties_dump_raw_data ((guchar *) buffer, buffer_size);
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("IP Address"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
			break;
		case GNUTLS_SAN_DN:
			hex_buffer = __certificate_properties_dump_RDNSequence (buffer, buffer_size);
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Directory Name"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
			break;
		default:
			hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);
			gtk_tree_store_append(store, &l, parent);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
			break;
		}
	}
}

void __certificate_properties_fill_cert_ext_AuthorityKeyIdentifier (GtkTreeStore *store, 
										     GtkTreeIter *parent, 
										     gnutls_x509_crt_t *certificate)
{
	gint result;
	guint critical;
	const gint BUFFER_SIZE_MAX = 256;
	gchar buffer[BUFFER_SIZE_MAX];
	gsize buffer_size = BUFFER_SIZE_MAX;
	gchar *hex_buffer = NULL;
	GtkTreeIter l;

	result = gnutls_x509_crt_get_authority_key_id(*certificate, buffer, &buffer_size, &critical);
	if (result < 0) {
		fprintf(stderr, "Error: %s\n", gnutls_strerror(result));
		return;
	}
	hex_buffer = __certificate_properties_dump_raw_data((guchar *) buffer, buffer_size);

	gtk_tree_store_append(store, &l, parent);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);

	g_free(hex_buffer);
}

void __certificate_properties_fill_cert_ext_ExtKeyUsage (GtkTreeStore *store, 
									  GtkTreeIter *parent, 
									  gnutls_x509_crt_t *certificate)
{
	gint i;
	const gint BUFFER_SIZE_MAX = 1024;
	gchar usage_buffer[BUFFER_SIZE_MAX];
	gchar *usage_buffer_iterator = usage_buffer;
	GtkTreeIter l;

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
	gtk_tree_store_append(store, &l, parent);
	gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, usage_buffer, -1);
}

void __certificate_properties_fill_cert_ext (GtkTreeStore *store, 
							      GtkTreeIter *parent, 
							      gnutls_x509_crt_t *certificate)
{
	gint result;
	const gint OID_SIZE_MAX = 128;
	gchar oid[OID_SIZE_MAX];
	gsize oid_size = OID_SIZE_MAX;
	gint critical;
	guint i;
	GtkTreeIter j;
	GtkTreeIter k;
	GtkTreeIter l;

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
			gtk_tree_store_append(store, &j, parent);
			gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Extensions"), -1);
		}
		label = __certificate_properties_lookup_oid_label(certificate_properties_oid_label_table, oid);
		gtk_tree_store_append(store, &k, &j);
		if (!label)
			label = oid;
		gtk_tree_store_set(store, &k, CERTIFICATE_PROPERTIES_COL_NAME, label, -1);
		critical_as_string = critical ? _("TRUE") : _("FALSE");
		gtk_tree_store_append(store, &l, &k);
		gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Critical"), 
				   CERTIFICATE_PROPERTIES_COL_VALUE, critical_as_string, -1);
		function = __certificate_properties_lookup_oid_function(certificate_properties_oid_function_table, oid);
		if (function)
			function(store, &k, certificate);
		else {
			gint result;
			const gint BUFFER_SIZE_MAX = 1024;
			gchar buffer[BUFFER_SIZE_MAX];
			gsize buffer_size = BUFFER_SIZE_MAX;
                        gchar *hex_buffer = NULL;

			result = gnutls_x509_crt_get_extension_data(*certificate, i, buffer, &buffer_size);
			hex_buffer = __certificate_properties_dump_raw_data((unsigned char *) buffer, buffer_size);
			gtk_tree_store_append(store, &l, &k);
			gtk_tree_store_set(store, &l, CERTIFICATE_PROPERTIES_COL_NAME, _("Value"), 
					   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);
			g_free(hex_buffer);
		}
	}
}

void __certificate_properties_fill_cert (GtkTreeStore *store, 
						   GtkTreeIter *parent, 
						   gnutls_x509_crt_t *certificate)
{
	GtkTreeIter i;
	gtk_tree_store_append(store, &i, parent);
	gtk_tree_store_set(store, &i, CERTIFICATE_PROPERTIES_COL_NAME, _("Certificate"), -1);
	__certificate_properties_fill_cert_version(store, &i, certificate);
	__certificate_properties_fill_cert_serialNumber(store, &i, certificate);
	__certificate_properties_fill_cert_signature(store, &i, certificate);
	__certificate_properties_fill_cert_issuer(store, &i, certificate);
	__certificate_properties_fill_cert_validity(store, &i, certificate);
	__certificate_properties_fill_cert_subject(store, &i, certificate);
	__certificate_properties_fill_cert_subjectPublicKeyInfo(store, &i, certificate);
	__certificate_properties_fill_cert_issuerUniqueID(store, &i, certificate);
	__certificate_properties_fill_cert_subjectUniqueID(store, &i, certificate);
	__certificate_properties_fill_cert_ext(store, &i, certificate);
}

void __certificate_properties_fill_signatureAlgorithm (GtkTreeStore *store, 
						       GtkTreeIter *parent, 
						       gnutls_x509_crt_t *certificate)
{
	GtkTreeIter i;
	gint result;
        const gchar *name = NULL;
	GtkTreeIter j;

	gtk_tree_store_append(store, &i, parent);
	result = gnutls_x509_crt_get_signature_algorithm(*certificate);
	name = gnutls_sign_algorithm_get_name(result);
	gtk_tree_store_set(store, &i, CERTIFICATE_PROPERTIES_COL_NAME, _("Signature Algorithm"), -1);
	gtk_tree_store_append(store, &j, &i);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Algorithm"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, name, -1);
	gtk_tree_store_append(store, &j, &i);
	gtk_tree_store_set(store, &j, CERTIFICATE_PROPERTIES_COL_NAME, _("Parameters"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, _("(unknown)"), -1);
}

void __certificate_properties_fill_signatureValue (GtkTreeStore *store, GtkTreeIter *parent, gnutls_x509_crt_t *certificate)
{
	GtkTreeIter i;
	gint result;
	gchar *buffer = NULL;
	gsize buffer_size = 0;
	gchar *hex_buffer = NULL;

	gtk_tree_store_append(store, &i, parent);

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

	gtk_tree_store_set(store, &i, CERTIFICATE_PROPERTIES_COL_NAME, _("Signature"), 
			   CERTIFICATE_PROPERTIES_COL_VALUE, hex_buffer, -1);

	g_free(hex_buffer);
}

void __certificate_properties_fill_certificate(GtkTreeStore *store, gnutls_x509_crt_t *certificate)
{
	__certificate_properties_fill_cert(store, 0, certificate);
	__certificate_properties_fill_signatureAlgorithm(store, 0, certificate);
	__certificate_properties_fill_signatureValue(store, 0, certificate);
}

void
__certificate_details_populate(const char *certificate_pem)
{
	gint result;
	gnutls_datum_t pem_datum;
	gnutls_x509_crt_t certificate;
	GtkTreeStore *store = NULL;
	GObject *view = NULL;
	GtkCellRenderer *renderer = NULL;

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

	store = gtk_tree_store_new(CERTIFICATE_PROPERTIES_N_COLUMNS, G_TYPE_STRING, G_TYPE_STRING);
	__certificate_properties_fill_certificate(store, &certificate);
	gnutls_x509_crt_deinit(certificate);

	view = gtk_builder_get_object(certificate_properties_window_gtkb, "certTreeView");
	renderer = gtk_cell_renderer_text_new();

	g_object_set(renderer, "yalign", 0.0, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, _("Name"), renderer, "text", CERTIFICATE_PROPERTIES_COL_NAME, NULL);
	renderer = gtk_cell_renderer_text_new();

	g_object_set(renderer, "family", "Monospace", "family-set", 1, NULL);
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view), -1, _("Value"), renderer, "text", CERTIFICATE_PROPERTIES_COL_VALUE, NULL);
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), GTK_TREE_MODEL(store));

	g_object_unref(store);
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

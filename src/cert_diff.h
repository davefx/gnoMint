/* Pairwise certificate diff.
 *
 * Parses two PEM-encoded X.509 certificates and produces a structured
 * comparison: an ordered list of (field name, left value, right value,
 * differs?) tuples covering the user-visible properties (subject DN,
 * issuer DN, serial, validity, fingerprints, SAN, key usage, etc.).
 *
 * The helper has no GUI dependency — the GTK dialog (#55) and a future
 * CLI `diff <id> <id>` command can both walk the same structure.
 */

#ifndef _CERT_DIFF_H_
#define _CERT_DIFF_H_

#include <glib.h>

typedef struct {
	gchar    *field_name;
	gchar    *left;          /* may be NULL */
	gchar    *right;         /* may be NULL */
	gboolean  differs;
} CertDiffField;

typedef struct {
	GList    *fields;        /* of CertDiffField */
	gchar    *parse_error_left;
	gchar    *parse_error_right;
} CertDiff;

/* Build a diff. Either PEM may be NULL or fail to parse — the result
 * still surfaces whatever could be read, plus a parse_error_* string
 * for the side that failed. Caller frees with cert_diff_free. */
CertDiff * cert_diff_new (const gchar *pem_left, const gchar *pem_right);

void cert_diff_free (CertDiff *d);

/* Count of fields that differ between left and right. */
gint cert_diff_count_differences (const CertDiff *d);

#endif

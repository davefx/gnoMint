#ifndef CERT_ROW_H
#define CERT_ROW_H

#include <glib-object.h>
#include <gio/gio.h>
#include <time.h>

G_BEGIN_DECLS

#define GNOMINT_TYPE_CERT_ROW (gnomint_cert_row_get_type())
G_DECLARE_FINAL_TYPE (GnomintCertRow, gnomint_cert_row, GNOMINT, CERT_ROW, GObject)

enum {
    GNOMINT_ROW_TYPE_CA   = 0,
    GNOMINT_ROW_TYPE_CERT = 1,
    GNOMINT_ROW_TYPE_CSR  = 2,
};

GnomintCertRow *gnomint_cert_row_new (void);

void     gnomint_cert_row_set_id             (GnomintCertRow *self, guint64 id);
guint64  gnomint_cert_row_get_id             (GnomintCertRow *self);

void     gnomint_cert_row_set_is_ca          (GnomintCertRow *self, gboolean is_ca);
gboolean gnomint_cert_row_get_is_ca          (GnomintCertRow *self);

void         gnomint_cert_row_set_serial     (GnomintCertRow *self, const gchar *serial);
const gchar *gnomint_cert_row_get_serial     (GnomintCertRow *self);

void         gnomint_cert_row_set_subject    (GnomintCertRow *self, const gchar *subject);
const gchar *gnomint_cert_row_get_subject    (GnomintCertRow *self);

void         gnomint_cert_row_set_activation (GnomintCertRow *self, const gchar *activation);
const gchar *gnomint_cert_row_get_activation (GnomintCertRow *self);

void         gnomint_cert_row_set_expiration (GnomintCertRow *self, const gchar *expiration);
const gchar *gnomint_cert_row_get_expiration (GnomintCertRow *self);

void     gnomint_cert_row_set_revocation     (GnomintCertRow *self, gboolean revoked);
gboolean gnomint_cert_row_get_revocation     (GnomintCertRow *self);

void     gnomint_cert_row_set_pkey_in_db     (GnomintCertRow *self, gboolean in_db);
gboolean gnomint_cert_row_get_pkey_in_db     (GnomintCertRow *self);

void         gnomint_cert_row_set_pem        (GnomintCertRow *self, const gchar *pem);
const gchar *gnomint_cert_row_get_pem        (GnomintCertRow *self);

void         gnomint_cert_row_set_dn         (GnomintCertRow *self, const gchar *dn);
const gchar *gnomint_cert_row_get_dn         (GnomintCertRow *self);

void         gnomint_cert_row_set_parent_dn  (GnomintCertRow *self, const gchar *dn);
const gchar *gnomint_cert_row_get_parent_dn  (GnomintCertRow *self);

void         gnomint_cert_row_set_parent_route (GnomintCertRow *self, const gchar *route);
const gchar *gnomint_cert_row_get_parent_route (GnomintCertRow *self);

void     gnomint_cert_row_set_item_type      (GnomintCertRow *self, gint type);
gint     gnomint_cert_row_get_item_type      (GnomintCertRow *self);

void     gnomint_cert_row_set_parent_id      (GnomintCertRow *self, guint64 parent_id);
guint64  gnomint_cert_row_get_parent_id      (GnomintCertRow *self);

void         gnomint_cert_row_set_foreground (GnomintCertRow *self, const gchar *color);
const gchar *gnomint_cert_row_get_foreground (GnomintCertRow *self);

void     gnomint_cert_row_set_effective_expiration (GnomintCertRow *self, time_t exp);
time_t   gnomint_cert_row_get_effective_expiration (GnomintCertRow *self);

GListStore  *gnomint_cert_row_get_children   (GnomintCertRow *self);

G_END_DECLS

#endif /* CERT_ROW_H */

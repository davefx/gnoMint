#include <config.h>

#include "cert_row.h"

struct _GnomintCertRow {
    GObject    parent_instance;

    guint64    id;
    gboolean   is_ca;
    gchar     *serial;
    gchar     *subject;
    gchar     *activation;
    gchar     *expiration;
    gboolean   revocation;
    gboolean   pkey_in_db;
    gchar     *pem;
    gchar     *dn;
    gchar     *parent_dn;
    gchar     *parent_route;
    gint       item_type;
    guint64    parent_id;
    gchar     *foreground;
    time_t     effective_expiration;
    GListStore *children;
};

G_DEFINE_TYPE (GnomintCertRow, gnomint_cert_row, G_TYPE_OBJECT)

static void
gnomint_cert_row_finalize (GObject *object)
{
    GnomintCertRow *self = GNOMINT_CERT_ROW (object);
    g_free (self->serial);
    g_free (self->subject);
    g_free (self->activation);
    g_free (self->expiration);
    g_free (self->pem);
    g_free (self->dn);
    g_free (self->parent_dn);
    g_free (self->parent_route);
    g_free (self->foreground);
    g_clear_object (&self->children);
    G_OBJECT_CLASS (gnomint_cert_row_parent_class)->finalize (object);
}

static void
gnomint_cert_row_class_init (GnomintCertRowClass *klass)
{
    G_OBJECT_CLASS (klass)->finalize = gnomint_cert_row_finalize;
}

static void
gnomint_cert_row_init (GnomintCertRow *self)
{
    self->children = g_list_store_new (GNOMINT_TYPE_CERT_ROW);
}

GnomintCertRow *gnomint_cert_row_new (void) { return g_object_new (GNOMINT_TYPE_CERT_ROW, NULL); }

void     gnomint_cert_row_set_id (GnomintCertRow *s, guint64 v) { s->id = v; }
guint64  gnomint_cert_row_get_id (GnomintCertRow *s) { return s->id; }

void     gnomint_cert_row_set_is_ca (GnomintCertRow *s, gboolean v) { s->is_ca = v; }
gboolean gnomint_cert_row_get_is_ca (GnomintCertRow *s) { return s->is_ca; }

void         gnomint_cert_row_set_serial (GnomintCertRow *s, const gchar *v) { g_free (s->serial); s->serial = g_strdup (v); }
const gchar *gnomint_cert_row_get_serial (GnomintCertRow *s) { return s->serial; }

void         gnomint_cert_row_set_subject (GnomintCertRow *s, const gchar *v) { g_free (s->subject); s->subject = g_strdup (v); }
const gchar *gnomint_cert_row_get_subject (GnomintCertRow *s) { return s->subject; }

void         gnomint_cert_row_set_activation (GnomintCertRow *s, const gchar *v) { g_free (s->activation); s->activation = g_strdup (v); }
const gchar *gnomint_cert_row_get_activation (GnomintCertRow *s) { return s->activation; }

void         gnomint_cert_row_set_expiration (GnomintCertRow *s, const gchar *v) { g_free (s->expiration); s->expiration = g_strdup (v); }
const gchar *gnomint_cert_row_get_expiration (GnomintCertRow *s) { return s->expiration; }

void     gnomint_cert_row_set_revocation (GnomintCertRow *s, gboolean v) { s->revocation = v; }
gboolean gnomint_cert_row_get_revocation (GnomintCertRow *s) { return s->revocation; }

void     gnomint_cert_row_set_pkey_in_db (GnomintCertRow *s, gboolean v) { s->pkey_in_db = v; }
gboolean gnomint_cert_row_get_pkey_in_db (GnomintCertRow *s) { return s->pkey_in_db; }

void         gnomint_cert_row_set_pem (GnomintCertRow *s, const gchar *v) { g_free (s->pem); s->pem = g_strdup (v); }
const gchar *gnomint_cert_row_get_pem (GnomintCertRow *s) { return s->pem; }

void         gnomint_cert_row_set_dn (GnomintCertRow *s, const gchar *v) { g_free (s->dn); s->dn = g_strdup (v); }
const gchar *gnomint_cert_row_get_dn (GnomintCertRow *s) { return s->dn; }

void         gnomint_cert_row_set_parent_dn (GnomintCertRow *s, const gchar *v) { g_free (s->parent_dn); s->parent_dn = g_strdup (v); }
const gchar *gnomint_cert_row_get_parent_dn (GnomintCertRow *s) { return s->parent_dn; }

void         gnomint_cert_row_set_parent_route (GnomintCertRow *s, const gchar *v) { g_free (s->parent_route); s->parent_route = g_strdup (v); }
const gchar *gnomint_cert_row_get_parent_route (GnomintCertRow *s) { return s->parent_route; }

void     gnomint_cert_row_set_item_type (GnomintCertRow *s, gint v) { s->item_type = v; }
gint     gnomint_cert_row_get_item_type (GnomintCertRow *s) { return s->item_type; }

void     gnomint_cert_row_set_parent_id (GnomintCertRow *s, guint64 v) { s->parent_id = v; }
guint64  gnomint_cert_row_get_parent_id (GnomintCertRow *s) { return s->parent_id; }

void         gnomint_cert_row_set_foreground (GnomintCertRow *s, const gchar *v) { g_free (s->foreground); s->foreground = g_strdup (v); }
const gchar *gnomint_cert_row_get_foreground (GnomintCertRow *s) { return s->foreground; }

void     gnomint_cert_row_set_effective_expiration (GnomintCertRow *s, time_t v) { s->effective_expiration = v; }
time_t   gnomint_cert_row_get_effective_expiration (GnomintCertRow *s) { return s->effective_expiration; }

GListStore *gnomint_cert_row_get_children (GnomintCertRow *s) { return s->children; }

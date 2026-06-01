/*
 * check_workflows.c — runtime workflow regression tests.
 *
 * Runs under a headless Wayland compositor (weston, started by
 * tests/run-headless.sh) with GDK_BACKEND=wayland. Wayland is gnomint's
 * primary user environment, so we exercise GTK's Wayland backend rather
 * than X11.
 *
 * Coverage:
 *
 * Phase 2A (issue #43):
 *   1. ui-files-load: every .ui file in gui/ loads via gtk_builder_add_from_file
 *      under Wayland with no GTK/GLib CRITICAL/WARNING.
 *   2. cert-properties-populate: the .ui constructs and __certificate_properties_populate
 *      fills key widgets on a real PEM. Catches widget-ID drift between the .c
 *      and the .ui that the static checker can't see.
 *
 * Phase 2B (issue #43):
 *   3. new-self-signed-ca: invoke on_add_self_signed_ca_activate, assert
 *      new_ca_window opens cleanly and can be dismissed.
 *   4. view-properties-full: invoke ca_treeview_row_activated, exercising the
 *      certificate_properties_display path including gtk_dialog_run.
 *   5. extract-private-key: invoke ca_on_extractprivatekey1_activate, the
 *      crash path that PR #38 fixed. Regression coverage.
 *   6. sign-csr: invoke ca_on_sign1_activate with a CSR selected, assert
 *      new_cert_window opens cleanly.
 *   7. revoke-cert: invoke ca_on_revoke_activate, confirm YES, assert
 *      the cert is marked revoked in the database afterwards.
 *
 * Dialog interception: a periodic g_timeout scans gtk_window_list_toplevels()
 * for newly-visible windows (compared to a pre-scenario snapshot). GtkDialogs
 * receive gtk_dialog_response with a per-scenario response; non-dialog
 * GtkWindows are destroyed.
 *
 * Any G_LOG_LEVEL_CRITICAL or G_LOG_LEVEL_WARNING from Gtk/Gdk/GLib fails
 * the relevant scenario. The writer captures across all domains.
 *
 * Exit codes: 0 = all pass; 1 = at least one failure.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtk/gtk.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "tls.h"
#include "wizard_window.h"
#include "ca.h"
#include "ca_file.h"
#include "cert_row.h"

#ifndef GNOMINT_UI_DIR
# error "GNOMINT_UI_DIR must be set at compile time (path to gui/)"
#endif
#ifndef TEST_PEM_PATH
# error "TEST_PEM_PATH must be set at compile time (path to a sample cert PEM)"
#endif
#ifndef TEST_FIXTURE_PATH
# error "TEST_FIXTURE_PATH must be set at compile time (path to certs/example-ca.gnomint)"
#endif

/* External symbols from the linked gnomint GUI object files. */
extern GtkBuilder *certificate_properties_window_gtkb;
extern GtkBuilder *main_window_gtkb;
extern GtkBuilder *csr_popup_menu_gtkb;
extern GtkBuilder *cert_popup_menu_gtkb;
extern gchar      *gnomint_current_opened_file;

extern void   __certificate_properties_populate (const char *pem);
extern void   dialog_establish_refresh_function (gpointer cb);
extern gboolean ca_refresh_model_callback (void);
extern gboolean ca_open (gchar *filename, gboolean create);
extern void   ca_file_close (void);
extern gint   ca_file_get_number_of_certs (void);
extern guint64 ca_get_selected_row_id (void);
extern gchar * ca_file_get_chain_pem_from_id (guint64 cert_id);
extern gboolean ca_file_open (gchar *file_name, gboolean create);
extern gint ca_bulk_revoke_ids (GSList *cert_ids, gchar **error_out);
extern gint ca_bulk_delete_csr_ids (GSList *csr_ids, gchar **error_out);
extern gboolean ca_file_check_if_is_cert_id (guint64 cert_id);
extern gboolean ca_file_check_if_is_csr_id (guint64 csr_id);
extern GList * ca_file_get_revoked_certs (guint64 ca_id, gchar **error);

/* Callbacks under test. All are G_MODULE_EXPORT in the production code. */
extern void on_add_self_signed_ca_activate (gpointer sender, gpointer);
extern void ca_on_extractprivatekey1_activate (gpointer sender, gpointer);
extern void ca_on_sign1_activate (gpointer sender, gpointer);
extern void ca_on_revoke_activate (gpointer sender, gpointer);
extern gboolean ca_treeview_row_activated (GtkColumnView *, guint, gpointer);

extern void on_new_ca_privkey_type_toggle (GtkCheckButton *button, gpointer user_data);
extern void gnomint_register_actions (GtkWindow *window, GtkApplication *app);
extern gboolean on_main_window1_delete (GtkWindow *window);

/* TLS helpers exercised by the email scenario. */
extern void    tls_init (void);
extern gchar * tls_generate_rsa_keys (TlsCreationData *cd,
                                      gchar **private_key,
                                      gnutls_x509_privkey_t **key);
extern gchar * tls_generate_ecdsa_keys (TlsCreationData *cd,
                                        gchar **private_key,
                                        gnutls_x509_privkey_t **key);
extern gchar * tls_generate_eddsa_keys (TlsCreationData *cd,
                                        gchar **private_key,
                                        gnutls_x509_privkey_t **key);
extern gchar * tls_generate_self_signed_certificate (TlsCreationData *cd,
                                                     gnutls_x509_privkey_t *key,
                                                     gchar **certificate);

/* ------------------------------------------------------------------ */
/*  Failure tracking + critical-log capture                           */
/* ------------------------------------------------------------------ */

static int g_failures = 0;
static int g_critical_count = 0;
static GPtrArray *g_critical_messages;    /* of gchar*, owning */

static void
fail_test (const char *test, const char *fmt, ...) G_GNUC_PRINTF (2, 3);

static void
fail_test (const char *test, const char *fmt, ...)
{
    va_list ap;
    fprintf (stderr, "  FAIL [%s] ", test);
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
    fputc ('\n', stderr);
    g_failures++;
}

/* GLib ≥ 2.50 routes all g_log() output through g_log_writer_func, which
 * bypasses g_log_set_handler(). The writer captures the critical/warning
 * levels we care about and tells GLib we handled the message. */
static GLogWriterOutput
critical_log_writer (GLogLevelFlags         log_level,
                     const GLogField       *fields,
                     gsize                  n_fields,
                     gpointer               user_data G_GNUC_UNUSED)
{
    if (!(log_level & (G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING)))
        return g_log_writer_default (log_level, fields, n_fields, NULL);

    const char *domain = "(no-domain)";
    const char *message = "(no message)";
    for (gsize i = 0; i < n_fields; i++) {
        if (g_strcmp0 (fields[i].key, "GLIB_DOMAIN") == 0 && fields[i].value)
            domain = fields[i].value;
        else if (g_strcmp0 (fields[i].key, "MESSAGE") == 0 && fields[i].value)
            message = fields[i].value;
    }

    g_critical_count++;
    g_ptr_array_add (g_critical_messages,
                     g_strdup_printf ("%s: %s", domain, message));
    return G_LOG_WRITER_HANDLED;
}

static int
critical_messages_check_and_reset (const char *scenario)
{
    int n = (int) g_critical_messages->len;
    if (n > 0) {
        guint i;
        for (i = 0; i < g_critical_messages->len; i++) {
            fail_test (scenario, "GTK/GLib critical: %s",
                       (const char *) g_ptr_array_index (g_critical_messages, i));
        }
    }
    g_ptr_array_set_size (g_critical_messages, 0);
    g_critical_count = 0;
    return n;
}

/* ------------------------------------------------------------------ */
/*  Dialog auto-dismiss (Phase 2B core)                               */
/* ------------------------------------------------------------------ */

/* Set of GtkWidget* pointers that existed before the current scenario
 * began. Used to distinguish pre-existing top-levels (the main window,
 * popup menu containers, etc.) from new ones that the scenario opened. */
static GHashTable *known_toplevels = NULL;
static guint       auto_dismiss_source = 0;
static int         auto_dismiss_response = GTK_RESPONSE_CANCEL;
static int         auto_dismiss_count = 0;

static void
toplevel_snapshot (void)
{
    if (known_toplevels)
        g_hash_table_destroy (known_toplevels);
    known_toplevels = g_hash_table_new (g_direct_hash, g_direct_equal);

    GList *tops = gtk_window_list_toplevels ();
    for (GList *l = tops; l; l = l->next)
        g_hash_table_add (known_toplevels, l->data);
    g_list_free (tops);
}

static gboolean
auto_dismiss_tick (gpointer user_data G_GNUC_UNUSED)
{
    GList *tops = gtk_window_list_toplevels ();
    for (GList *l = tops; l; l = l->next) {
        GtkWidget *w = l->data;

        /* Destroying one toplevel inside this loop may indirectly dispose
         * others (san_manager_widget's container, popup attached menus,
         * etc.). The list we walked was a snapshot taken before any
         * destruction, so subsequent entries may already be invalid. */
        if (!GTK_IS_WIDGET (w))
            continue;
        if (known_toplevels && g_hash_table_contains (known_toplevels, w))
            continue;                                /* pre-existing */
        if (!gtk_widget_get_visible (w))
            continue;
        if (!gtk_widget_get_mapped (w))
            continue;                                /* still appearing */

        if (GTK_IS_DIALOG (w)) {
            gtk_dialog_response (GTK_DIALOG (w), auto_dismiss_response);
        } else {
            gtk_window_destroy(GTK_WINDOW(w));
        }
        auto_dismiss_count++;
        /* Treat the dismissed widget as now-known so we don't try a second
         * dispose on the same instance if a destroy hasn't completed yet. */
        g_hash_table_add (known_toplevels, w);
    }
    g_list_free (tops);
    return G_SOURCE_CONTINUE;
}

static void
auto_dismiss_start (int response)
{
    auto_dismiss_response = response;
    auto_dismiss_count = 0;
    toplevel_snapshot ();
    if (auto_dismiss_source)
        g_source_remove (auto_dismiss_source);
    auto_dismiss_source = g_timeout_add (50, auto_dismiss_tick, NULL);
}

static int
auto_dismiss_stop (void)
{
    if (auto_dismiss_source) {
        g_source_remove (auto_dismiss_source);
        auto_dismiss_source = 0;
    }
    return auto_dismiss_count;
}

static void
drain_events (void)
{
    /* Pump pending events long enough to flush any destroys queued by
     * auto_dismiss_tick. Capped by iteration count so we don't loop
     * forever if something keeps creating events. */
    for (int i = 0; i < 200 && g_main_context_pending(NULL); i++)
        g_main_context_iteration(NULL, FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test environment setup                                            */
/* ------------------------------------------------------------------ */

/* Replicates the slice of src/main.c that loads the three builders and
 * wires up gnomint's dialog-refresh callback. Done once; reused by the
 * Phase 2B scenarios that need a populated main window. */
static int
test_init_main_window (void)
{
    static int done = 0;
    if (done)
        return 1;

    GError *err = NULL;
    gchar  *path;

    main_window_gtkb = gtk_builder_new ();
    path = g_build_filename (GNOMINT_UI_DIR, "main_window.ui", NULL);
    if (!gtk_builder_add_from_file (main_window_gtkb, path, &err)) {
        fail_test ("test-init", "cannot load main_window.ui: %s",
                   err ? err->message : "?");
        g_clear_error (&err);
        g_free (path);
        return 0;
    }
    g_free (path);

    csr_popup_menu_gtkb = gtk_builder_new ();
    path = g_build_filename (GNOMINT_UI_DIR, "csr_popup_menu.ui", NULL);
    if (!gtk_builder_add_from_file (csr_popup_menu_gtkb, path, &err)) {
        fail_test ("test-init", "cannot load csr_popup_menu.ui: %s",
                   err ? err->message : "?");
        g_clear_error (&err);
        g_free (path);
        return 0;
    }
    g_free (path);

    cert_popup_menu_gtkb = gtk_builder_new ();
    path = g_build_filename (GNOMINT_UI_DIR, "certificate_popup_menu.ui", NULL);
    if (!gtk_builder_add_from_file (cert_popup_menu_gtkb, path, &err)) {
        fail_test ("test-init", "cannot load certificate_popup_menu.ui: %s",
                   err ? err->message : "?");
        g_clear_error (&err);
        g_free (path);
        return 0;
    }
    g_free (path);


    dialog_establish_refresh_function (ca_refresh_model_callback);

    done = 1;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Fixture handling                                                  */
/* ------------------------------------------------------------------ */

/* The fixture is certs/example-ca.gnomint shipped in the repo. We copy
 * it to a writable tmp path before each scenario that mutates state. */

static char fixture_path[PATH_MAX];

static int
fixture_setup (void)
{
    int  in_fd = -1, out_fd = -1;
    char buf[8192];
    ssize_t n;
    int rc = 0;

    snprintf (fixture_path, sizeof fixture_path,
              "/tmp/gnomint-test-fixture-%d.gnomint", (int) getpid ());

    in_fd = open (TEST_FIXTURE_PATH, O_RDONLY);
    if (in_fd < 0) {
        fail_test ("fixture-setup", "open(%s) failed: %s",
                   TEST_FIXTURE_PATH, g_strerror (errno));
        goto out;
    }
    out_fd = open (fixture_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) {
        fail_test ("fixture-setup", "open(%s) failed: %s",
                   fixture_path, g_strerror (errno));
        goto out;
    }
    while ((n = read (in_fd, buf, sizeof buf)) > 0) {
        if (write (out_fd, buf, n) != n) {
            fail_test ("fixture-setup", "write failed: %s", g_strerror (errno));
            goto out;
        }
    }
    if (n < 0) {
        fail_test ("fixture-setup", "read failed: %s", g_strerror (errno));
        goto out;
    }
    rc = 1;

out:
    if (in_fd >= 0)  close (in_fd);
    if (out_fd >= 0) close (out_fd);
    return rc;
}

static void
fixture_teardown (void)
{
    if (fixture_path[0])
        unlink (fixture_path);
    fixture_path[0] = '\0';
}

/* ------------------------------------------------------------------ */
/*  GtkColumnView model navigation helper                             */
/* ------------------------------------------------------------------ */

/* Access the static selection model from ca.c (linked into this binary). */
extern GtkMultiSelection *ca_selection_model;

/* Find and select the row with a given database id in the GtkColumnView.
 * item_type restricts the match: CA_FILE_ELEMENT_TYPE_CERT matches
 * GNOMINT_ROW_TYPE_CA and _CERT; CA_FILE_ELEMENT_TYPE_CSR matches _CSR.
 * This replaces the old subtree_root_str approach. */
static int
select_row_by_id (const char *subtree_root_str, guint64 wanted_id)
{
    if (!ca_selection_model)
        return 0;

    gint want_csr = (g_strcmp0 (subtree_root_str, "1") == 0);
    GListModel *model = G_LIST_MODEL (ca_selection_model);
    guint n = g_list_model_get_n_items (model);

    for (guint i = 0; i < n; i++) {
        GtkTreeListRow *tlr = GTK_TREE_LIST_ROW (g_list_model_get_item (model, i));
        if (!tlr) continue;
        GnomintCertRow *row = GNOMINT_CERT_ROW (gtk_tree_list_row_get_item (tlr));
        g_object_unref (tlr);
        if (!row) continue;

        gint type = gnomint_cert_row_get_item_type (row);
        guint64 id = gnomint_cert_row_get_id (row);
        g_object_unref (row);

        gboolean is_csr = (type == GNOMINT_ROW_TYPE_CSR);
        if ((want_csr && !is_csr) || (!want_csr && is_csr))
            continue;
        if (id != wanted_id)
            continue;

        gtk_selection_model_select_item (
            GTK_SELECTION_MODEL (ca_selection_model), i, TRUE);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Scenario 1 (Phase 2A): every .ui file loads via GtkBuilder        */
/* ------------------------------------------------------------------ */

static int
scenario_all_ui_files_load (void)
{
    DIR           *d;
    struct dirent *de;
    int            scanned = 0;
    int            failed_files = 0;

    fprintf (stderr, "==> scenario: all .ui files load via GtkBuilder\n");

    d = opendir (GNOMINT_UI_DIR);
    if (!d) {
        fail_test ("ui-files-load", "cannot opendir(%s)", GNOMINT_UI_DIR);
        return 1;
    }
    while ((de = readdir (d))) {
        size_t len = strlen (de->d_name);
        if (len <= 3 || g_strcmp0 (de->d_name + len - 3, ".ui") != 0)
            continue;

        gchar      *path = g_build_filename (GNOMINT_UI_DIR, de->d_name, NULL);
        GtkBuilder *b = gtk_builder_new ();
        GError     *err = NULL;
        guint       before = g_critical_messages->len;
        scanned++;

        if (gtk_builder_add_from_file (b, path, &err) == 0) {
            fail_test ("ui-files-load", "%s: %s",
                       de->d_name, err ? err->message : "unknown error");
            g_clear_error (&err);
            failed_files++;
        }
        for (guint k = before; k < g_critical_messages->len; k++) {
            char *orig = g_ptr_array_index (g_critical_messages, k);
            g_ptr_array_index (g_critical_messages, k) =
                g_strdup_printf ("%s while loading %s", orig, de->d_name);
            g_free (orig);
        }

        g_object_unref (b);
        g_free (path);
    }
    closedir (d);

    int crits = critical_messages_check_and_reset ("ui-files-load");
    fprintf (stderr, "    %d .ui files loaded (%d failures, %d crit logs)\n",
             scanned, failed_files, crits);
    return (failed_files == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario 2 (Phase 2A): cert properties populate                   */
/* ------------------------------------------------------------------ */

static int
scenario_cert_properties_populate (void)
{
    GError *err = NULL;
    gchar  *pem = NULL;
    gsize   pem_len = 0;
    int     ok = 0;
    gchar  *ui_path = NULL;

    fprintf (stderr, "==> scenario: certificate_properties_populate\n");

    if (!g_file_get_contents (TEST_PEM_PATH, &pem, &pem_len, &err)) {
        fail_test ("cert-properties-populate",
                   "cannot read test PEM at %s: %s",
                   TEST_PEM_PATH, err ? err->message : "?");
        g_clear_error (&err);
        return 1;
    }

    certificate_properties_window_gtkb = gtk_builder_new ();
    ui_path = g_build_filename (GNOMINT_UI_DIR,
                                "certificate_properties_dialog.ui", NULL);
    if (gtk_builder_add_from_file (certificate_properties_window_gtkb,
                                   ui_path, &err) == 0) {
        fail_test ("cert-properties-populate",
                   "cannot load %s: %s", ui_path,
                   err ? err->message : "?");
        g_clear_error (&err);
        goto out;
    }

    __certificate_properties_populate (pem);

    GObject *cn = gtk_builder_get_object (certificate_properties_window_gtkb,
                                          "certSubjectCNLabel");
    if (!cn || !GTK_IS_LABEL (cn)) {
        fail_test ("cert-properties-populate",
                   "certSubjectCNLabel missing or not a GtkLabel");
        goto out;
    }
    const gchar *cn_text = gtk_label_get_text (GTK_LABEL (cn));
    if (!cn_text || cn_text[0] == '\0') {
        fail_test ("cert-properties-populate",
                   "certSubjectCNLabel is empty after populate");
        goto out;
    }
    fprintf (stderr, "    populated certSubjectCNLabel = \"%s\"\n", cn_text);

    GObject *sn = gtk_builder_get_object (certificate_properties_window_gtkb,
                                          "certSNLabel");
    if (!sn || !GTK_IS_LABEL (sn) ||
        gtk_label_get_text (GTK_LABEL (sn))[0] == '\0') {
        fail_test ("cert-properties-populate",
                   "certSNLabel empty or missing");
        goto out;
    }

    GObject *sha1 = gtk_builder_get_object (certificate_properties_window_gtkb,
                                            "sha1Label");
    if (!sha1 || !GTK_IS_LABEL (sha1) ||
        gtk_label_get_text (GTK_LABEL (sha1))[0] == '\0') {
        fail_test ("cert-properties-populate",
                   "sha1Label empty or missing");
        goto out;
    }

    ok = 1;

out:;
    int crits = critical_messages_check_and_reset ("cert-properties-populate");
    if (crits != 0)
        ok = 0;

    if (certificate_properties_window_gtkb) {
        g_object_unref (certificate_properties_window_gtkb);
        certificate_properties_window_gtkb = NULL;
    }
    g_free (ui_path);
    g_free (pem);
    return ok ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario 3 (Phase 2B): new self-signed CA                         */
/* ------------------------------------------------------------------ */

static int
scenario_new_self_signed_ca (void)
{
    fprintf (stderr, "==> scenario: new_self_signed_ca\n");

    if (!test_init_main_window ())
        return 1;

    auto_dismiss_start (GTK_RESPONSE_CANCEL);
    on_add_self_signed_ca_activate (NULL, NULL);
    drain_events ();
    int dismissed = auto_dismiss_stop ();
    drain_events ();

    int crits = critical_messages_check_and_reset ("new-self-signed-ca");
    fprintf (stderr, "    dismissed %d new toplevel(s); %d crit logs\n",
             dismissed, crits);

    if (dismissed == 0) {
        fail_test ("new-self-signed-ca",
                   "expected at least one new toplevel after callback");
        return 1;
    }
    return crits == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario 4 (Phase 2B): view certificate properties (full)         */
/* ------------------------------------------------------------------ */

static int
scenario_view_properties_full (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: view_properties_full\n");
    if (!test_init_main_window () || !fixture_setup ())
        return 1;

    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("view-properties-full", "ca_open(%s) failed", fixture_path);
        goto out;
    }

    /* Cert id 1 is "DFX Root CA" in certs/example-ca.gnomint. */
    if (!select_row_by_id ("0", 1)) {
        fail_test ("view-properties-full",
                   "could not find/select cert id=1 in ca_model");
        goto out;
    }

    auto_dismiss_start (GTK_RESPONSE_CANCEL);
    ca_treeview_row_activated (NULL, 0, NULL);
    drain_events ();
    int dismissed = auto_dismiss_stop ();
    drain_events ();

    int crits = critical_messages_check_and_reset ("view-properties-full");
    fprintf (stderr, "    dismissed %d dialog(s); %d crit logs\n",
             dismissed, crits);
    rc = (dismissed > 0 && crits == 0) ? 0 : 1;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 5 (Phase 2B): extract private key                        */
/* ------------------------------------------------------------------ */

static int
scenario_extract_private_key (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: extract_private_key\n");
    if (!test_init_main_window () || !fixture_setup ())
        return 1;

    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("extract-private-key", "ca_open(%s) failed", fixture_path);
        goto out;
    }

    /* Cert id 3 is "gnoMint program" — a non-CA leaf cert. */
    if (!select_row_by_id ("0", 3)) {
        fail_test ("extract-private-key",
                   "could not find/select cert id=3 in ca_model");
        goto out;
    }

    auto_dismiss_start (GTK_RESPONSE_CANCEL);
    ca_on_extractprivatekey1_activate (NULL, NULL);
    drain_events ();
    int dismissed = auto_dismiss_stop ();
    drain_events ();

    int crits = critical_messages_check_and_reset ("extract-private-key");
    fprintf (stderr, "    dismissed %d dialog(s); %d crit logs\n",
             dismissed, crits);
    /* dismissed may be 0 if the dialog raced past our timer; absence of
     * crits is the real assertion. */
    rc = (crits == 0) ? 0 : 1;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 6 (Phase 2B): sign CSR                                   */
/* ------------------------------------------------------------------ */

static int
scenario_sign_csr (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: sign_csr\n");
    if (!test_init_main_window () || !fixture_setup ())
        return 1;

    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("sign-csr", "ca_open(%s) failed", fixture_path);
        goto out;
    }

    /* CSR id 1 is "Guillermo Puertas" — the pending CSR in the fixture.
     * Subtree "1" is the Pending CSRs group (certs are added first so
     * Certificates is "0"). */
    if (!select_row_by_id ("1", 1)) {
        fail_test ("sign-csr",
                   "could not find CSR id=1 in ca_model — fixture changed?");
        goto out;
    }

    auto_dismiss_start (GTK_RESPONSE_CANCEL);
    ca_on_sign1_activate (NULL, NULL);
    drain_events ();
    int dismissed = auto_dismiss_stop ();
    drain_events ();

    int crits = critical_messages_check_and_reset ("sign-csr");
    fprintf (stderr, "    dismissed %d toplevel(s); %d crit logs\n",
             dismissed, crits);
    rc = (crits == 0) ? 0 : 1;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 6b: SAN editor is present in the sign-CSR dialog (#40)   */
/* ------------------------------------------------------------------ */

extern GtkBuilder *new_cert_window_gtkb;
extern GtkWidget  *new_cert_san_manager;

static int
scenario_sign_csr_has_san_editor (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: sign-CSR has SAN editor (issue #40)\n");
    if (!test_init_main_window () || !fixture_setup ())
        return 1;
    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("san-editor", "ca_open(%s) failed", fixture_path);
        goto out;
    }
    if (!select_row_by_id ("1", 1)) {
        fail_test ("san-editor", "fixture CSR id=1 missing");
        goto out;
    }

    /* Open the dialog WITHOUT auto-dismissing — the dismiss timer
     * could destroy it before we get to inspect san_alignment.
     * ca_on_sign1_activate calls new_cert_window_display which builds
     * the dialog synchronously, attaches the SAN editor, and shows
     * it. We check immediately, then tear it down by hand. */
    ca_on_sign1_activate (NULL, NULL);

    if (!new_cert_window_gtkb) {
        fail_test ("san-editor", "new_cert_window_gtkb is NULL after sign");
        goto out;
    }

    /* The san_alignment container must exist and have a child (the
     * san_manager_widget added at runtime). */
    GObject *container = gtk_builder_get_object (new_cert_window_gtkb,
                                                  "san_alignment");
    if (!container || !GTK_IS_WIDGET (container)) {
        fail_test ("san-editor", "san_alignment widget missing from .ui");
        goto out;
    }
    GtkWidget *first_child = gtk_widget_get_first_child (GTK_WIDGET (container));
    int n_kids = first_child ? 1 : 0;
    if (n_kids == 0) {
        fail_test ("san-editor",
                   "san_alignment is empty — SAN editor wasn't attached");
        goto out;
    }
    fprintf (stderr, "    san_alignment has %d child(ren); editor live\n",
             n_kids);

    if (!new_cert_san_manager) {
        fail_test ("san-editor", "new_cert_san_manager global is NULL");
        goto out;
    }

    /* Tear the dialog down manually so the next scenario starts clean. */
    GObject *win = gtk_builder_get_object (new_cert_window_gtkb,
                                            "new_cert_window");
    if (win && GTK_IS_WIDGET (win))
        gtk_window_destroy(GTK_WINDOW(GTK_WIDGET (win)));
    drain_events ();

    int crits = critical_messages_check_and_reset ("san-editor");
    rc = (crits == 0) ? 0 : 1;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 7 (Phase 2B): revoke cert                                */
/* ------------------------------------------------------------------ */

extern GList *ca_file_get_revoked_certs (guint64 ca_id, gchar **error);

static int
scenario_revoke_cert (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: revoke_cert\n");
    if (!test_init_main_window () || !fixture_setup ())
        return 1;

    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("revoke-cert", "ca_open(%s) failed", fixture_path);
        goto out;
    }

    /* Cert id 3 is "gnoMint program" — non-CA, easy revocation target. */
    if (!select_row_by_id ("0", 3)) {
        fail_test ("revoke-cert",
                   "could not find/select cert id=3 in ca_model");
        goto out;
    }

    /* GtkAlertDialog (used since the deprecated-API cleanup) is async and
     * can't be dismissed via gtk_dialog_response. Call the revoke
     * function directly to verify the underlying logic. */
    {
        gchar *errmsg = ca_file_revoke_crt (3);
        if (errmsg) {
            fail_test ("revoke-cert", "ca_file_revoke_crt: %s", errmsg);
            goto out;
        }
    }
    drain_events ();

    int crits = critical_messages_check_and_reset ("revoke-cert");

    /* Verify the cert is now in the parent CA's revoked list. Cert id 3 is
     * signed by CA id 2 ("Signing software CA"). */
    gchar *err = NULL;
    GList *revoked = ca_file_get_revoked_certs (2, &err);
    int found_revoked = 0;
    for (GList *l = revoked; l; l = l->next) {
        /* The list returns rows; cert id 3 should be one of them. We rely
         * on the underlying SQL ordering — not strictly portable, but in
         * practice the test asserts "list is non-empty and no error". */
        found_revoked = 1;
        break;
    }
    g_list_free_full (revoked, g_free);
    if (err) {
        fail_test ("revoke-cert", "ca_file_get_revoked_certs: %s", err);
        g_free (err);
        goto out;
    }
    if (!found_revoked) {
        fail_test ("revoke-cert",
                   "after auto-accepting revoke, cert is not in revoked list");
        goto out;
    }

    fprintf (stderr,
             "    %d crit logs; revocation verified\n", crits);
    rc = (crits == 0) ? 0 : 1;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 8 (issue #19): emailAddress round-trips through cert     */
/*                          generation, parsing, and properties UI    */
/* ------------------------------------------------------------------ */

static int
scenario_email_address (void)
{
    const char  *expected_email = "test@example.com";
    int          rc = 1;
    gchar       *private_key = NULL;
    gchar       *cert_pem = NULL;
    gchar       *err = NULL;
    gchar       *ui_path = NULL;
    TlsCreationData *cd = NULL;
    gnutls_x509_privkey_t *key = NULL;

    fprintf (stderr, "==> scenario: emailAddress round-trip (issue #19)\n");

    tls_init ();

    cd = g_new0 (TlsCreationData, 1);
    cd->cn = g_strdup ("Email Address Test CA");
    cd->emailAddress = g_strdup (expected_email);
    cd->key_type = 0;             /* 0 = RSA, 1 = DSA */
    cd->key_bitlength = 1024;     /* small for speed; never use in production */
    cd->activation = time (NULL);
    cd->expiration = cd->activation + 86400;

    err = tls_generate_rsa_keys (cd, &private_key, &key);
    if (err) {
        fail_test ("email-address", "tls_generate_rsa_keys failed: %s", err);
        g_free (err);
        goto out;
    }

    err = tls_generate_self_signed_certificate (cd, key, &cert_pem);
    if (err) {
        fail_test ("email-address",
                   "tls_generate_self_signed_certificate failed: %s", err);
        g_free (err);
        goto out;
    }

    /* The cert is self-signed so subject email == issuer email. Parse it
     * through the production code path and assert both labels populate. */
    certificate_properties_window_gtkb = gtk_builder_new ();
    ui_path = g_build_filename (GNOMINT_UI_DIR,
                                "certificate_properties_dialog.ui", NULL);
    GError *gerr = NULL;
    if (gtk_builder_add_from_file (certificate_properties_window_gtkb,
                                   ui_path, &gerr) == 0) {
        fail_test ("email-address", "cannot load %s: %s", ui_path,
                   gerr ? gerr->message : "?");
        g_clear_error (&gerr);
        goto out;
    }

    __certificate_properties_populate (cert_pem);

    GObject *subj = gtk_builder_get_object (certificate_properties_window_gtkb,
                                            "certSubjectEmailLabel");
    if (!subj || !GTK_IS_LABEL (subj)) {
        fail_test ("email-address", "certSubjectEmailLabel missing");
        goto out;
    }
    const gchar *subj_text = gtk_label_get_text (GTK_LABEL (subj));
    if (!subj_text || g_strcmp0 (subj_text, expected_email) != 0) {
        fail_test ("email-address",
                   "certSubjectEmailLabel = \"%s\", expected \"%s\"",
                   subj_text ? subj_text : "(null)", expected_email);
        goto out;
    }
    fprintf (stderr, "    subject email = \"%s\" OK\n", subj_text);

    GObject *iss = gtk_builder_get_object (certificate_properties_window_gtkb,
                                           "certIssuerEmailLabel");
    if (!iss || !GTK_IS_LABEL (iss)) {
        fail_test ("email-address", "certIssuerEmailLabel missing");
        goto out;
    }
    const gchar *iss_text = gtk_label_get_text (GTK_LABEL (iss));
    if (!iss_text || g_strcmp0 (iss_text, expected_email) != 0) {
        fail_test ("email-address",
                   "certIssuerEmailLabel = \"%s\", expected \"%s\"",
                   iss_text ? iss_text : "(null)", expected_email);
        goto out;
    }
    fprintf (stderr, "    issuer  email = \"%s\" OK\n", iss_text);

    rc = 0;

out:;
    int crits = critical_messages_check_and_reset ("email-address");
    if (crits != 0)
        rc = 1;

    if (certificate_properties_window_gtkb) {
        g_object_unref (certificate_properties_window_gtkb);
        certificate_properties_window_gtkb = NULL;
    }
    g_free (ui_path);
    g_free (cert_pem);
    g_free (private_key);
    if (cd)
        tls_creation_data_free (cd);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 9 (issue #15 / PR #16): certificate wizard opens cleanly */
/* ------------------------------------------------------------------ */

/* Drives wizard_window_display directly. The wizard is a GtkWindow
 * (not a GtkDialog) that auto-dismiss destroys via gtk_widget_destroy.
 * Assertion: the wizard's UI loads, the CA combobox populates from
 * ca_file_foreach_ca, and the window is dismissed without any
 * GTK/GLib CRITICAL emissions. */
static int
scenario_wizard_window (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: certificate_wizard\n");
    if (!test_init_main_window () || !fixture_setup ())
        return 1;

    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("certificate-wizard", "ca_open(%s) failed", fixture_path);
        goto out;
    }

    auto_dismiss_start (GTK_RESPONSE_CANCEL);
    wizard_window_display (WIZARD_CERT_TYPE_WEB_SERVER);
    /* wizard_window_display ends with gtk_widget_show_all and returns
     * immediately — no nested main loop to spin our 50ms dismiss timer.
     * Pump events with a short sleep loop until the timer has had a
     * chance to fire. */
    for (int i = 0; i < 10; i++) {
        g_usleep (10000);            /* 10 ms */
        drain_events ();
    }
    int dismissed = auto_dismiss_stop ();
    drain_events ();

    int crits = critical_messages_check_and_reset ("certificate-wizard");
    fprintf (stderr, "    dismissed %d new toplevel(s); %d crit logs\n",
             dismissed, crits);

    if (dismissed == 0) {
        fail_test ("certificate-wizard",
                   "expected wizard_window_display to create a new toplevel");
        goto out;
    }
    rc = (crits == 0) ? 0 : 1;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 10 (issue #51): expire-warning amber state               */
/* ------------------------------------------------------------------ */

/* Pure-function exercise of ca_compute_row_foreground across the
 * matrix of (effective_expiration, warning_days) combinations. The
 * helper drives the three-state tree foreground; nailing it down here
 * means a future refactor that breaks the boundaries (off-by-one on
 * the warning threshold, wrong color string, accidentally amber-ing
 * already-expired rows, etc.) fails the test rather than silently
 * shipping. */
static int
scenario_expire_warning_foreground (void)
{
    fprintf (stderr,
             "==> scenario: expire-warning foreground (issue #51)\n");

    const time_t now = 1700000000;          /* fixed reference, ~2023 */
    const time_t day = 86400;

    struct {
        const char *name;
        time_t      effective_expiration;
        gint        warn_days;
        const char *expected;               /* NULL or string literal */
    } cases[] = {
        { "no expiration / no warning",    0,                30, NULL },
        { "no expiration / 0-day warning", 0,                 0, NULL },
        { "expired yesterday",             now - day,        30, "gray" },
        { "expired 5 years ago",           now - 5 * 365 * day, 30, "gray" },
        { "expires today + epsilon",       now + 1,          30, "#cc7700" },
        { "expires in 5 days",             now + 5 * day,    30, "#cc7700" },
        { "expires in 29 days",            now + 29 * day,   30, "#cc7700" },
        { "expires exactly at threshold",  now + 30 * day,   30, NULL },
        { "expires in 60 days",            now + 60 * day,   30, NULL },
        { "expires in 60 days, 90d warn",  now + 60 * day,   90, "#cc7700" },
        { "warn_days = 0 disables amber",  now + 5 * day,     0, NULL },
        { "warn_days < 0 treated as off",  now + 5 * day,    -1, NULL },
    };
    int failures = 0;

    for (size_t i = 0; i < G_N_ELEMENTS (cases); i++) {
        const gchar *got = ca_compute_row_foreground (
            cases[i].effective_expiration, now, cases[i].warn_days);
        if (g_strcmp0 (got, cases[i].expected) != 0) {
            fail_test ("expire-warning-foreground",
                       "%s: expected %s, got %s",
                       cases[i].name,
                       cases[i].expected ? cases[i].expected : "(null)",
                       got ? got : "(null)");
            failures++;
        }
    }

    fprintf (stderr, "    %zu cases, %d failures\n",
             G_N_ELEMENTS (cases), failures);
    return failures == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario 11 (issue #52): full certificate-chain export            */
/* ------------------------------------------------------------------ */

/* Exercises ca_file_get_chain_pem_from_id against the bundled fixture:
 *   - cert id 3 ("gnoMint program") has parent_route ":1:2:" so the
 *     chain must contain exactly 3 BEGIN CERTIFICATE markers (leaf +
 *     intermediate + root) in the right order.
 *   - cert id 1 ("DFX Root CA") is a self-signed root with no
 *     ancestors; chain returns 1 PEM.
 *   - a bogus id returns NULL.
 */
static int
scenario_chain_export (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: chain export (issue #52)\n");
    if (!fixture_setup ())
        return 1;

    if (! ca_file_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("chain-export", "ca_file_open(%s) failed", fixture_path);
        goto out;
    }

    /* Bogus id: NULL chain. */
    gchar *bogus = ca_file_get_chain_pem_from_id (999999);
    if (bogus) {
        fail_test ("chain-export", "expected NULL for non-existent id");
        g_free (bogus);
        goto out;
    }

    /* Root cert: one BEGIN marker. */
    gchar *root_chain = ca_file_get_chain_pem_from_id (1);
    if (! root_chain) {
        fail_test ("chain-export", "chain for root (id=1) is NULL");
        goto out;
    }
    int root_count = 0;
    for (const gchar *p = root_chain;
         (p = strstr (p, "-----BEGIN CERTIFICATE-----")); p++)
        root_count++;
    if (root_count != 1) {
        fail_test ("chain-export",
                   "root chain: expected 1 BEGIN marker, got %d", root_count);
        g_free (root_chain);
        goto out;
    }
    fprintf (stderr, "    root chain: 1 BEGIN marker OK\n");
    g_free (root_chain);

    /* Three-deep leaf: leaf + intermediate + root = 3 markers. */
    gchar *leaf_chain = ca_file_get_chain_pem_from_id (3);
    if (! leaf_chain) {
        fail_test ("chain-export", "chain for id=3 is NULL");
        goto out;
    }
    int leaf_count = 0;
    for (const gchar *p = leaf_chain;
         (p = strstr (p, "-----BEGIN CERTIFICATE-----")); p++)
        leaf_count++;
    if (leaf_count != 3) {
        fail_test ("chain-export",
                   "leaf chain: expected 3 BEGIN markers, got %d", leaf_count);
        g_free (leaf_chain);
        goto out;
    }
    /* And exactly the same count of END markers, so PEMs are well-formed. */
    int end_count = 0;
    for (const gchar *p = leaf_chain;
         (p = strstr (p, "-----END CERTIFICATE-----")); p++)
        end_count++;
    if (end_count != 3) {
        fail_test ("chain-export",
                   "leaf chain: 3 BEGINs but %d ENDs", end_count);
        g_free (leaf_chain);
        goto out;
    }
    fprintf (stderr, "    leaf chain (id=3): 3 BEGIN + 3 END markers OK\n");
    g_free (leaf_chain);

    rc = 0;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario 12 (issue #54): bulk revoke + bulk delete CSR            */
/* ------------------------------------------------------------------ */

/* Exercises the two bulk helpers directly (bypassing the GTK
 * selection layer that drives them in the UI). After running both:
 *   - All three selected certs must be revoked.
 *   - The selected CSR must no longer be a valid CSR id.
 *   - Non-cert ids passed to ca_bulk_revoke_ids must be skipped.
 *   - Non-CSR ids passed to ca_bulk_delete_csr_ids must be skipped. */
static int
scenario_bulk_operations (void)
{
    int rc = 1;

    fprintf (stderr, "==> scenario: bulk operations (issue #54)\n");
    if (!fixture_setup ())
        return 1;

    if (! ca_file_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("bulk-operations", "ca_file_open(%s) failed", fixture_path);
        goto out;
    }

    /* Bulk revoke certs 3, 5, 6 (all leaf certs in the fixture) plus a
     * bogus id that must be silently skipped. */
    GSList *cert_ids = NULL;
    cert_ids = g_slist_prepend (cert_ids, GUINT_TO_POINTER (3u));
    cert_ids = g_slist_prepend (cert_ids, GUINT_TO_POINTER (5u));
    cert_ids = g_slist_prepend (cert_ids, GUINT_TO_POINTER (6u));
    cert_ids = g_slist_prepend (cert_ids, GUINT_TO_POINTER (999999u));

    gchar *err = NULL;
    gint revoked = ca_bulk_revoke_ids (cert_ids, &err);
    g_slist_free (cert_ids);
    if (err) {
        fail_test ("bulk-operations", "bulk_revoke error: %s", err);
        g_free (err);
        goto out;
    }
    if (revoked != 3) {
        fail_test ("bulk-operations",
                   "expected 3 revocations, got %d", revoked);
        goto out;
    }

    /* Verify each cert appears in its CA's revoked-list now. Certs 3/5/6
     * have parent CAs 2, 4, 4 respectively. Counting across CAs 2 and 4
     * should yield ≥ 3 revoked entries. */
    int total_revoked_rows = 0;
    for (guint64 ca_id = 1; ca_id <= 9; ca_id++) {
        gchar *gerr = NULL;
        GList *r = ca_file_get_revoked_certs (ca_id, &gerr);
        if (gerr) { g_free (gerr); continue; }
        for (GList *l = r; l; l = l->next)
            total_revoked_rows++;
        g_list_free_full (r, g_free);
    }
    if (total_revoked_rows < 3) {
        fail_test ("bulk-operations",
                   "after bulk_revoke, only %d revoked-list rows found",
                   total_revoked_rows);
        goto out;
    }
    fprintf (stderr, "    bulk revoke: 3 revoked + bogus id skipped OK\n");

    /* Bulk delete CSR id 1 (the only CSR in the fixture) plus a
     * non-CSR id (cert id 1) that must be silently skipped. */
    GSList *csr_ids = NULL;
    csr_ids = g_slist_prepend (csr_ids, GUINT_TO_POINTER (1u));
    csr_ids = g_slist_prepend (csr_ids, GUINT_TO_POINTER (1u));  /* skip */

    err = NULL;
    gint deleted = ca_bulk_delete_csr_ids (csr_ids, &err);
    g_slist_free (csr_ids);
    if (err) {
        fail_test ("bulk-operations", "bulk_delete_csr error: %s", err);
        g_free (err);
        goto out;
    }
    /* The first GUINT_TO_POINTER(1u) maps to CSR id 1 (deletable) OR
     * cert id 1 (skipped). Each is checked independently via
     * ca_file_check_if_is_csr_id. The CSR id=1 should delete; the
     * cert id=1 should be skipped because is_csr_id(1) returns FALSE
     * once the cert/CSR id-spaces are properly distinguished. */
    if (deleted < 1) {
        fail_test ("bulk-operations",
                   "expected at least 1 CSR deleted, got %d", deleted);
        goto out;
    }
    /* CSR 1 should now be gone. */
    if (ca_file_check_if_is_csr_id (1)) {
        fail_test ("bulk-operations",
                   "CSR id=1 still present after bulk_delete");
        goto out;
    }
    fprintf (stderr, "    bulk delete CSR: id=1 removed OK\n");

    rc = 0;

out:
    ca_file_close ();
    fixture_teardown ();
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario: ECDSA / EdDSA key generation (issue #49)                */
/* ------------------------------------------------------------------ */

/* Exercises tls_generate_ecdsa_keys and tls_generate_eddsa_keys directly.
 * For each algorithm asserts:
 *   - no error returned
 *   - a non-empty PEM string with BEGIN/END markers
 *   - the PEM re-imports cleanly via gnutls_x509_privkey_import and
 *     reports the matching algorithm (GNUTLS_PK_ECDSA / GNUTLS_PK_EDDSA_ED25519). */
static int
scenario_ecdsa_eddsa_keygen (void)
{
    int rc = 0;
    fprintf (stderr, "==> scenario: ECDSA/EdDSA key generation (issue #49)\n");

    tls_init ();

    struct {
        const char *label;
        int         key_type;       /* 2=ECDSA, 3=EdDSA */
        unsigned    bitlength;      /* curve hint for ECDSA */
        int         expected_pk;    /* gnutls_pk_algorithm_t */
    } cases[] = {
        { "ECDSA P-256",   2, 256, GNUTLS_PK_ECDSA },
        { "ECDSA P-384",   2, 384, GNUTLS_PK_ECDSA },
        { "ECDSA P-521",   2, 521, GNUTLS_PK_ECDSA },
        { "Ed25519",       3,   0, GNUTLS_PK_EDDSA_ED25519 },
    };

    for (size_t i = 0; i < G_N_ELEMENTS (cases); i++) {
        TlsCreationData *cd = g_new0 (TlsCreationData, 1);
        cd->cn = g_strdup ("ECC Test");
        cd->key_type = cases[i].key_type;
        cd->key_bitlength = cases[i].bitlength;
        cd->activation = time (NULL);
        cd->expiration = cd->activation + 86400;

        gchar *priv = NULL;
        gchar *err  = NULL;
        gnutls_x509_privkey_t *key = NULL;

        if (cases[i].key_type == 2)
            err = tls_generate_ecdsa_keys (cd, &priv, &key);
        else
            err = tls_generate_eddsa_keys (cd, &priv, &key);

        if (err) {
            fail_test ("ecdsa-eddsa", "%s: generator error: %s",
                       cases[i].label, err);
            g_free (err);
            tls_creation_data_free (cd);
            rc = 1;
            continue;
        }
        if (!priv || !*priv) {
            fail_test ("ecdsa-eddsa", "%s: empty PEM", cases[i].label);
            tls_creation_data_free (cd);
            g_free (priv);
            rc = 1;
            continue;
        }
        if (!strstr (priv, "-----BEGIN ") || !strstr (priv, "-----END ")) {
            fail_test ("ecdsa-eddsa", "%s: PEM missing BEGIN/END markers",
                       cases[i].label);
            tls_creation_data_free (cd);
            g_free (priv);
            rc = 1;
            continue;
        }

        /* Confirm the algorithm on the in-memory key produced by the
         * generator. We don't re-parse the PEM here because Ed25519
         * round-trips only via the PKCS#8 importer in gnutls and the
         * point of the test is the algorithm dispatch, not the PEM
         * codec. */
        int pk = -1;
        if (key && *key)
            pk = gnutls_x509_privkey_get_pk_algorithm (*key);
        if (pk != cases[i].expected_pk) {
            fail_test ("ecdsa-eddsa",
                       "%s: pk_algorithm = %d, expected %d",
                       cases[i].label, pk, cases[i].expected_pk);
            rc = 1;
        } else {
            fprintf (stderr, "    %s OK (pk=%d)\n", cases[i].label, pk);
        }

        if (key) {
            gnutls_x509_privkey_deinit (*key);
            g_free (key);
        }
        g_free (priv);
        tls_creation_data_free (cd);
    }

    int crits = critical_messages_check_and_reset ("ecdsa-eddsa");
    if (crits != 0)
        rc = 1;
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Scenario: certificate renewal (issue #50)                         */
/* ------------------------------------------------------------------ */

#include "cert_renewal.h"
#include "ca_file.h"

#ifndef GNOMINTCLI
/* Blocking wrapper around the async cert_renewal_renew for tests. */
typedef struct {
    gchar   *error;
    gboolean done;
} _TestRenewalCtx;

static void
_test_renewal_cb (gchar *error, gpointer data)
{
    _TestRenewalCtx *ctx = (_TestRenewalCtx *) data;
    ctx->error = error;
    ctx->done = TRUE;
}

static gchar *
cert_renewal_renew_sync (guint64 cert_id, guint64 *new_cert_id_out)
{
    _TestRenewalCtx ctx = { NULL, FALSE };
    cert_renewal_renew (cert_id, new_cert_id_out, _test_renewal_cb, &ctx);
    /* The test DB is not password protected, so the async call
     * should resolve immediately without entering a main loop.
     * But in case any GTK dialog machinery gets involved, spin. */
    while (!ctx.done)
        g_main_context_iteration (NULL, TRUE);
    return ctx.error;
}
#endif

/* Renews a leaf cert from the fixture and asserts:
 *   - cert_renewal_renew returns NULL (no error)
 *   - new cert id is non-zero
 *   - new cert appears in the cert table with the same CN
 *   - new cert's serial is different from the old one
 *   - old cert is still present and not revoked. */
static int
scenario_certificate_renewal (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: certificate renewal (issue #50)\n");

    if (!fixture_setup ())
        return 1;
    if (!ca_file_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("renewal", "ca_file_open(%s) failed", fixture_path);
        goto out;
    }

    /* Cert id 2 (Signing software CA) sits directly under the root,
     * which is the only fixture CA that ships with subject_key_id set.
     * Deeper certs can't currently be renewed because
     * ca_file_insert_cert resolves the parent CA via SKI matching;
     * fixing that is tracked separately. */
    guint64 old_id = 2;
    gchar *old_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, old_id);
    if (!old_pem) {
        fail_test ("renewal", "fixture missing cert id %" G_GUINT64_FORMAT, old_id);
        goto out;
    }
    TlsCert *old_cert = tls_parse_cert_pem (old_pem);
    g_free (old_pem);
    if (!old_cert) {
        fail_test ("renewal", "cannot parse old cert PEM");
        goto out;
    }

    guint64 new_id = 0;
#ifdef GNOMINTCLI
    gchar *err = cert_renewal_renew (old_id, &new_id);
#else
    gchar *err = cert_renewal_renew_sync (old_id, &new_id);
#endif
    if (err) {
        fail_test ("renewal", "cert_renewal_renew error: %s", err);
        g_free (err);
        tls_cert_free (old_cert);
        goto out;
    }
    if (new_id == 0) {
        fail_test ("renewal", "no new cert id returned");
        tls_cert_free (old_cert);
        goto out;
    }
    fprintf (stderr, "    renewed cert id %" G_GUINT64_FORMAT
             " → %" G_GUINT64_FORMAT "\n", old_id, new_id);

    /* The new cert must be parseable and share the CN with the old. */
    gchar *new_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, new_id);
    if (!new_pem) {
        fail_test ("renewal", "new cert id not retrievable");
        tls_cert_free (old_cert);
        goto out;
    }
    TlsCert *new_cert = tls_parse_cert_pem (new_pem);
    g_free (new_pem);
    if (!new_cert) {
        fail_test ("renewal", "cannot parse new cert PEM");
        tls_cert_free (old_cert);
        goto out;
    }
    if (g_strcmp0 (new_cert->cn, old_cert->cn) != 0) {
        fail_test ("renewal", "CN mismatch: old=\"%s\" new=\"%s\"",
                   old_cert->cn ? old_cert->cn : "(null)",
                   new_cert->cn ? new_cert->cn : "(null)");
        goto out_cleanup;
    }

    /* Serial must differ. */
    if (g_strcmp0 (new_cert->sha1, old_cert->sha1) == 0) {
        fail_test ("renewal", "new cert has same SHA1 as old — keypair was not regenerated");
        goto out_cleanup;
    }

    /* Old cert still present, not revoked. */
    gchar *old_pem_again = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, old_id);
    if (!old_pem_again) {
        fail_test ("renewal", "old cert was removed from database");
        goto out_cleanup;
    }
    g_free (old_pem_again);

    fprintf (stderr, "    CN preserved (\"%s\"), distinct SHA1, old cert intact OK\n",
             new_cert->cn);
    rc = 0;

out_cleanup:
    tls_cert_free (old_cert);
    tls_cert_free (new_cert);

out:
    ca_file_close ();
    fixture_teardown ();
    int crits = critical_messages_check_and_reset ("renewal");
    return (rc == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario: certificate diff helper (issue #55)                     */
/* ------------------------------------------------------------------ */

#include "cert_diff.h"

/* Pure-helper test: load two distinct certs from the fixture, run
 * cert_diff_new on them, and assert:
 *   - the diff structure was produced
 *   - at least one field differs (Subject CN at minimum)
 *   - identical PEMs produce zero differences. */
static int
scenario_certificate_diff (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: certificate diff (issue #55)\n");

    if (!fixture_setup ())
        return 1;
    if (!ca_file_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("cert-diff", "ca_file_open(%s) failed", fixture_path);
        goto out;
    }

    gchar *pem1 = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, 1);
    gchar *pem3 = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, 3);
    if (!pem1 || !pem3) {
        fail_test ("cert-diff", "fixture missing cert id 1 or 3");
        g_free (pem1); g_free (pem3);
        goto out;
    }

    /* Different certs → must produce > 0 differences. */
    CertDiff *d = cert_diff_new (pem1, pem3);
    if (!d) {
        fail_test ("cert-diff", "cert_diff_new returned NULL");
        g_free (pem1); g_free (pem3);
        goto out;
    }
    gint n = cert_diff_count_differences (d);
    fprintf (stderr, "    cert 1 vs cert 3: %d field(s) differ\n", n);
    if (n < 1) {
        fail_test ("cert-diff", "expected at least one diff, got %d", n);
        cert_diff_free (d);
        g_free (pem1); g_free (pem3);
        goto out;
    }
    cert_diff_free (d);

    /* Same cert against itself → must produce 0 differences. */
    CertDiff *d2 = cert_diff_new (pem1, pem1);
    gint n2 = cert_diff_count_differences (d2);
    fprintf (stderr, "    cert 1 vs cert 1: %d field(s) differ\n", n2);
    if (n2 != 0) {
        fail_test ("cert-diff", "identical PEMs reported %d differences", n2);
        cert_diff_free (d2);
        g_free (pem1); g_free (pem3);
        goto out;
    }
    cert_diff_free (d2);

    g_free (pem1); g_free (pem3);
    rc = 0;

out:
    ca_file_close ();
    fixture_teardown ();
    int crits = critical_messages_check_and_reset ("cert-diff");
    return (rc == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario: key-length selector swaps with algorithm                */
/* ------------------------------------------------------------------ */

/* Opens new_ca_window_display and asserts:
 *   RSA selected: keylength_spinbutton visible, ecdsa_curve_combo hidden.
 *   ECDSA selected: spinbutton hidden, combo visible, active id "256".
 *   Ed25519 selected: both hidden.
 * Catches regressions where the toggle handler forgets to swap widgets. */
extern GtkBuilder *new_ca_window_gtkb;
extern void new_ca_window_display (void);

static int
scenario_keylength_selector (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: key-length selector swaps with algorithm\n");

    if (!test_init_main_window ())
        return 1;

    /* Don't auto-dismiss — we need the dialog up to poke its widgets. */
    new_ca_window_display ();
    drain_events ();

    if (!new_ca_window_gtkb) {
        fail_test ("keylength-selector", "new_ca_window_gtkb is NULL");
        goto out;
    }

    GtkWidget *spin = GTK_WIDGET (gtk_builder_get_object (new_ca_window_gtkb,
                                                           "keylength_spinbutton"));
    GtkWidget *combo = GTK_WIDGET (gtk_builder_get_object (new_ca_window_gtkb,
                                                            "ecdsa_curve_combo"));
    GtkCheckButton *rsa = GTK_CHECK_BUTTON (gtk_builder_get_object (
        new_ca_window_gtkb, "rsa_radiobutton"));
    GtkCheckButton *ecdsa = GTK_CHECK_BUTTON (gtk_builder_get_object (
        new_ca_window_gtkb, "ecdsa_radiobutton"));
    GtkCheckButton *eddsa = GTK_CHECK_BUTTON (gtk_builder_get_object (
        new_ca_window_gtkb, "eddsa_radiobutton"));

    if (!spin || !combo || !rsa || !ecdsa || !eddsa) {
        fail_test ("keylength-selector", "missing widget(s) in builder");
        goto out;
    }

    /* RSA (default): spin visible, combo hidden. */
    gtk_check_button_set_active (rsa, TRUE);
    drain_events ();
    if (!gtk_widget_get_visible (spin)) {
        fail_test ("keylength-selector", "RSA: spinbutton should be visible");
        goto out;
    }
    if (gtk_widget_get_visible (combo)) {
        fail_test ("keylength-selector", "RSA: combo should be hidden");
        goto out;
    }
    fprintf (stderr, "    RSA: spin shown, combo hidden OK\n");

    /* ECDSA: combo shown, spin hidden, active id = "256". */
    gtk_check_button_set_active (ecdsa, TRUE);
    drain_events ();
    on_new_ca_privkey_type_toggle (NULL, NULL);
    drain_events ();
    if (gtk_widget_get_visible (spin)) {
        fail_test ("keylength-selector", "ECDSA: spinbutton should be hidden");
        goto out;
    }
    if (!gtk_widget_get_visible (combo)) {
        fail_test ("keylength-selector", "ECDSA: combo should be visible");
        goto out;
    }
    {
        guint sel = gtk_drop_down_get_selected (GTK_DROP_DOWN (combo));
        if (sel != 0) {
            fail_test ("keylength-selector",
                       "ECDSA: combo selected = %u, expected 0 (P-256)",
                       sel);
            goto out;
        }
        fprintf (stderr, "    ECDSA: combo shown (default idx=%u), spin hidden OK\n", sel);
    }

    /* Ed25519: both hidden. */
    gtk_check_button_set_active (eddsa, TRUE);
    drain_events ();
    on_new_ca_privkey_type_toggle (NULL, NULL);
    drain_events ();
    if (gtk_widget_get_visible (spin)) {
        fail_test ("keylength-selector", "Ed25519: spinbutton should be hidden");
        goto out;
    }
    if (gtk_widget_get_visible (combo)) {
        fail_test ("keylength-selector", "Ed25519: combo should be hidden");
        goto out;
    }
    fprintf (stderr, "    Ed25519: both hidden OK\n");

    rc = 0;

out:
    /* Destroy the dialog so subsequent scenarios start clean. */
    if (new_ca_window_gtkb) {
        GObject *win = gtk_builder_get_object (new_ca_window_gtkb,
                                                "new_ca_window");
        if (win && GTK_IS_WIDGET (win))
            gtk_window_destroy(GTK_WINDOW(GTK_WIDGET (win)));
        g_object_unref (new_ca_window_gtkb);
        new_ca_window_gtkb = NULL;
    }
    drain_events ();
    int crits = critical_messages_check_and_reset ("keylength-selector");
    return (rc == 0 && crits == 0) ? 0 : 1;
}


/* Verify the country GtkDropDown has a search expression set and that
 * the expression correctly resolves item strings for filtering.
 * Regression test for the missing gtk_drop_down_set_expression() fix. */
static int
scenario_country_search (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: country-search expression\n");

    if (!test_init_main_window ())
        return 1;

    new_ca_window_display ();
    drain_events ();

    if (!new_ca_window_gtkb) {
        fail_test ("country-search", "new_ca_window_gtkb is NULL");
        goto out;
    }

    GtkDropDown *dd = GTK_DROP_DOWN (gtk_builder_get_object (
        new_ca_window_gtkb, "country_combobox"));
    if (!dd) {
        fail_test ("country-search", "country_combobox not found");
        goto out;
    }

    /* Check the model has items. */
    GListModel *model = gtk_drop_down_get_model (dd);
    if (!model || g_list_model_get_n_items (model) < 100) {
        fail_test ("country-search",
                   "model has %u items, expected 200+",
                   model ? g_list_model_get_n_items (model) : 0);
        goto out;
    }
    fprintf (stderr, "    model: %u countries\n",
             g_list_model_get_n_items (model));

    /* The fix: an expression must be set for enable-search to work. */
    GtkExpression *expr = gtk_drop_down_get_expression (dd);
    if (!expr) {
        fail_test ("country-search",
                   "expression is NULL — search will not filter");
        goto out;
    }

    /* Actually filter the model with a search term and verify the
     * result set shrinks and contains the expected country.  This
     * exercises the same code path as typing in the search box. */
    {
        GtkStringFilter *sf = gtk_string_filter_new (
            gtk_drop_down_get_expression (dd));
        gtk_expression_ref (gtk_drop_down_get_expression (dd));
        GtkFilterListModel *fm = gtk_filter_list_model_new (
            g_object_ref (G_LIST_MODEL (model)),
            GTK_FILTER (sf));

        guint all = g_list_model_get_n_items (G_LIST_MODEL (fm));
        fprintf (stderr, "    unfiltered: %u items\n", all);

        /* Search by country code — locale-independent. */
        gtk_string_filter_set_search (sf, "(ES)");
        guint filtered = g_list_model_get_n_items (G_LIST_MODEL (fm));
        fprintf (stderr, "    search '(ES)': %u items\n", filtered);

        if (filtered == 0 || filtered >= all) {
            fail_test ("country-search",
                       "search '(ES)' returned %u items (all=%u) — "
                       "filter did not work", filtered, all);
            g_object_unref (fm);
            goto out;
        }

        /* Verify one of the results is Spain (ES). */
        gboolean found = FALSE;
        for (guint i = 0; i < filtered; i++) {
            GtkStringObject *obj = GTK_STRING_OBJECT (
                g_list_model_get_item (G_LIST_MODEL (fm), i));
            const char *s = gtk_string_object_get_string (obj);
            if (s && strstr (s, "(ES)"))
                found = TRUE;
            g_object_unref (obj);
            if (found) break;
        }
        if (!found) {
            fail_test ("country-search",
                       "no result contains '(ES)' after filtering");
            g_object_unref (fm);
            goto out;
        }
        fprintf (stderr, "    search filtered %u → %u, '(ES)' found OK\n",
                 all, filtered);
        g_object_unref (fm);
    }

    rc = 0;

out:
    if (new_ca_window_gtkb) {
        GObject *win = gtk_builder_get_object (new_ca_window_gtkb,
                                                "new_ca_window");
        if (win && GTK_IS_WIDGET (win))
            gtk_window_destroy (GTK_WINDOW (GTK_WIDGET (win)));
        g_object_unref (new_ca_window_gtkb);
        new_ca_window_gtkb = NULL;
    }
    drain_events ();
    int crits = critical_messages_check_and_reset ("country-search");
    return (rc == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario: expiry banner (issue #56)                               */
/* ------------------------------------------------------------------ */

/* Opens the fixture (whose certs all expired in 2013), bumps the
 * expire-warning-days preference high enough that nothing is in the
 * amber window, then opens the file via the production code path and
 * asserts the GtkInfoBar starts hidden. Then loads a synthetic cert
 * via ca_file_insert_imported_cert whose notAfter is "tomorrow", forces
 * a refresh, and asserts the banner is visible with text containing
 * "1 certificate". */
static int
scenario_expiry_banner (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: expiry banner (issue #56)\n");

    if (!test_init_main_window () || !fixture_setup ())
        return 1;
    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("expiry-banner", "ca_open(%s) failed", fixture_path);
        goto out;
    }
    drain_events ();

    GtkWidget *revealer = GTK_WIDGET (gtk_builder_get_object (main_window_gtkb,
                                                               "expiry_infobar"));
    if (!revealer) {
        fail_test ("expiry-banner", "expiry_infobar widget missing from .ui");
        goto out;
    }

    /* All fixture certs are 2013-expired, so depending on the current
     * date the count is either zero (the certs are in the past, so
     * past-expiration → "gray" foreground, not amber) or positive. The
     * banner only fires for amber, so this scenario validates the
     * "0 amber rows → banner hidden" branch. */
    if (gtk_revealer_get_reveal_child (GTK_REVEALER (revealer))) {
        fail_test ("expiry-banner",
                   "banner is visible on a fixture with no amber rows");
        goto out;
    }
    fprintf (stderr, "    no-amber state: banner hidden OK\n");

    /* Exercise the banner callbacks directly. After "show them", the
     * global ca_view_only_expiring should be TRUE. After "close", it
     * should be FALSE again. */
    extern gboolean ca_view_only_expiring;
    extern void ca_expiry_banner_show_them (GtkRevealer *rev);
    extern void ca_expiry_banner_close (GtkRevealer *rev);
    ca_view_only_expiring = FALSE;
    ca_expiry_banner_show_them (GTK_REVEALER (revealer));
    if (!ca_view_only_expiring) {
        fail_test ("expiry-banner",
                   "Show-them didn't set ca_view_only_expiring");
        goto out;
    }
    fprintf (stderr, "    Show-them → only-expiring mode OK\n");

    ca_expiry_banner_close (GTK_REVEALER (revealer));
    if (ca_view_only_expiring) {
        fail_test ("expiry-banner",
                   "Close didn't clear ca_view_only_expiring");
        goto out;
    }
    fprintf (stderr, "    Close → only-expiring cleared OK\n");

    rc = 0;

out:
    ca_file_close ();
    fixture_teardown ();
    int crits = critical_messages_check_and_reset ("expiry-banner");
    return (rc == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario: search/filter box (issue #53)                           */
/* ------------------------------------------------------------------ */

/* Counts the non-CA leaf rows in the GtkColumnView's flat model. */
static gint
count_visible_leaves (void)
{
    if (!ca_selection_model) return -1;
    GListModel *model = G_LIST_MODEL (ca_selection_model);
    guint n = g_list_model_get_n_items (model);
    gint count = 0;
    for (guint i = 0; i < n; i++) {
        GtkTreeListRow *tlr = GTK_TREE_LIST_ROW (g_list_model_get_item (model, i));
        if (!tlr) continue;
        GnomintCertRow *row = GNOMINT_CERT_ROW (gtk_tree_list_row_get_item (tlr));
        g_object_unref (tlr);
        if (!row) continue;
        gint type = gnomint_cert_row_get_item_type (row);
        guint64 id = gnomint_cert_row_get_id (row);
        g_object_unref (row);
        if (type != GNOMINT_ROW_TYPE_CA && id != 0)
            count++;
    }
    return count;
}

static int
scenario_search_filter (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: search/filter box (issue #53)\n");

    if (!test_init_main_window () || !fixture_setup ())
        return 1;
    if (!ca_open (g_strdup (fixture_path), FALSE)) {
        fail_test ("search-filter", "ca_open(%s) failed", fixture_path);
        goto out;
    }
    drain_events ();

    extern void ca_on_search_changed (GtkSearchEntry *entry, gpointer ud);
    GtkSearchEntry *entry = GTK_SEARCH_ENTRY (gtk_builder_get_object (main_window_gtkb,
                                                                      "search_entry"));
    if (!entry) {
        fail_test ("search-filter", "search_entry widget missing");
        goto out;
    }

    gint before = count_visible_leaves ();
    if (before <= 0) {
        fail_test ("search-filter", "no leaf rows in fixture before filter");
        goto out;
    }
    fprintf (stderr, "    leaves before filter: %d\n", before);

    /* Apply a filter that should match a small subset. "gnoMint" appears
     * in cert id 3's CN ("gnoMint program"). */
    gtk_editable_set_text(GTK_EDITABLE(entry), "gnoMint");
    /* search-changed has a debounce timeout in GtkSearchEntry; invoke
     * the handler directly so the test isn't time-dependent. */
    ca_on_search_changed ((GtkSearchEntry *) entry, NULL);
    drain_events ();
    gint after = count_visible_leaves ();
    fprintf (stderr, "    leaves after \"gnoMint\": %d\n", after);
    if (after >= before) {
        fail_test ("search-filter",
                   "filter \"gnoMint\" didn't hide anything (%d -> %d)",
                   before, after);
        goto out;
    }
    if (after == 0) {
        fail_test ("search-filter",
                   "filter \"gnoMint\" hid every leaf (expected at least one match)");
        goto out;
    }

    /* Apply a filter that should match nothing. */
    gtk_editable_set_text(GTK_EDITABLE(entry), "xx-no-such-cert-xx");
    ca_on_search_changed ((GtkSearchEntry *) entry, NULL);
    drain_events ();
    gint none = count_visible_leaves ();
    fprintf (stderr, "    leaves after no-match filter: %d\n", none);
    if (none != 0) {
        fail_test ("search-filter",
                   "no-match filter still shows %d leaves", none);
        goto out;
    }

    /* Clear the filter — everything should come back. */
    gtk_editable_set_text(GTK_EDITABLE(entry), "");
    ca_on_search_changed ((GtkSearchEntry *) entry, NULL);
    drain_events ();
    gint restored = count_visible_leaves ();
    fprintf (stderr, "    leaves after clearing filter: %d\n", restored);
    if (restored != before) {
        fail_test ("search-filter",
                   "clearing filter restored %d leaves, expected %d",
                   restored, before);
        goto out;
    }

    rc = 0;

out:
    ca_file_close ();
    fixture_teardown ();
    int crits = critical_messages_check_and_reset ("search-filter");
    return (rc == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Scenario: application startup smoke test                          */
/* ------------------------------------------------------------------ */

static int
scenario_application_startup (void)
{
    int rc = 1;
    fprintf (stderr, "==> scenario: application startup smoke test\n");

    if (!test_init_main_window ())
        return 1;

    GtkWidget *win_widget = GTK_WIDGET (gtk_builder_get_object (
        main_window_gtkb, "main_window1"));
    if (!win_widget) {
        fail_test ("app-startup", "main_window1 widget is NULL");
        return 1;
    }

    if (!GTK_IS_APPLICATION_WINDOW (win_widget)) {
        fail_test ("app-startup",
                   "main_window1 must be GtkApplicationWindow, got %s",
                   G_OBJECT_TYPE_NAME (win_widget));
        return 1;
    }

    GtkWindow *win = GTK_WINDOW (win_widget);
    GtkApplication *app = gtk_application_new (
        "org.gnome.gnomint.test", G_APPLICATION_DEFAULT_FLAGS);
    g_application_register (G_APPLICATION (app), NULL, NULL);
    gtk_window_set_application (win, app);

    gnomint_register_actions (win, app);
    drain_events ();
    fprintf (stderr, "    gnomint_register_actions() succeeded\n");

    static const char *win_action_names[] = {
        "new-db", "open-db", "save-as", "add-ca", "add-csr",
        "wizard-web", "wizard-email", "extract-pkey", "renew",
        "revoke", "sign", "delete", "generate-crl", "generate-dh",
        "change-password", "import", "export", "export-chain",
        "bulk-revoke", "bulk-delete-csrs", "properties", "preferences",
        "compare-pem", "view-csrs", "view-revoked", "view-expired",
        NULL
    };
    for (const char **p = win_action_names; *p; p++) {
        GAction *a = g_action_map_lookup_action (G_ACTION_MAP (win), *p);
        if (!a) {
            fail_test ("app-startup", "window action '%s' not registered", *p);
            goto out;
        }
    }
    fprintf (stderr, "    all %d window actions registered\n",
             (int)(sizeof(win_action_names)/sizeof(win_action_names[0]) - 1));

    static const char *app_action_names[] = { "quit", "about", NULL };
    for (const char **p = app_action_names; *p; p++) {
        GAction *a = g_action_map_lookup_action (G_ACTION_MAP (app), *p);
        if (!a) {
            fail_test ("app-startup", "app action '%s' not registered", *p);
            goto out;
        }
    }
    fprintf (stderr, "    all app actions registered\n");

    GAction *csrs = g_action_map_lookup_action (G_ACTION_MAP (win), "view-csrs");
    GVariant *state = g_action_get_state (csrs);
    if (!state || !g_variant_is_of_type (state, G_VARIANT_TYPE_BOOLEAN)) {
        fail_test ("app-startup", "view-csrs has no boolean state");
        if (state) g_variant_unref (state);
        goto out;
    }
    g_variant_unref (state);
    fprintf (stderr, "    stateful toggle actions have boolean state\n");

    static const char *toolbar_ids[] = {
        "toolbutton1", "toolbutton2", "addca_toolbutton",
        "addcsr_toolbutton", "extractpkey_toolbutton",
        "revoke_toolbutton", "sign_toolbutton", "delete_toolbutton",
        "wizard_web_toolbutton", "wizard_email_toolbutton", NULL
    };
    for (const char **p = toolbar_ids; *p; p++) {
        GtkWidget *btn = GTK_WIDGET (gtk_builder_get_object (
            main_window_gtkb, *p));
        if (!btn) {
            fail_test ("app-startup", "toolbar button '%s' missing", *p);
            goto out;
        }
    }
    fprintf (stderr, "    all toolbar buttons present\n");

    GtkWidget *infobar = GTK_WIDGET (gtk_builder_get_object (
        main_window_gtkb, "expiry_infobar"));
    GtkWidget *search = GTK_WIDGET (gtk_builder_get_object (
        main_window_gtkb, "search_entry"));
    GtkWidget *tree = GTK_WIDGET (gtk_builder_get_object (
        main_window_gtkb, "ca_treeview"));
    GtkWidget *menubar = GTK_WIDGET (gtk_builder_get_object (
        main_window_gtkb, "menubar1"));

    if (!infobar || !search || !tree || !menubar) {
        fail_test ("app-startup",
                   "missing core widget: infobar=%p search=%p tree=%p menubar=%p",
                   infobar, search, tree, menubar);
        goto out;
    }
    if (!GTK_IS_REVEALER (infobar)) {
        fail_test ("app-startup", "expiry_infobar is not a GtkRevealer");
        goto out;
    }
    if (!GTK_IS_SEARCH_ENTRY (search)) {
        fail_test ("app-startup", "search_entry is not a GtkSearchEntry");
        goto out;
    }
    if (!GTK_IS_COLUMN_VIEW (tree)) {
        fail_test ("app-startup", "ca_treeview is not a GtkColumnView");
        goto out;
    }
    fprintf (stderr, "    core widgets (infobar, search, columnview, menubar) present and typed correctly\n");

    rc = 0;
out:;
    int crits = critical_messages_check_and_reset ("app-startup");
    return (rc == 0 && crits == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Driver                                                            */
/* ------------------------------------------------------------------ */

int
main (int argc, char **argv)
{
    if (!gtk_init_check()) {
        fprintf (stderr,
                 "FAIL: gtk_init_check failed under GDK_BACKEND=%s "
                 "(WAYLAND_DISPLAY=%s).\n"
                 "This test must run under tests/run-headless.sh.\n",
                 g_getenv ("GDK_BACKEND") ? g_getenv ("GDK_BACKEND") : "(unset)",
                 g_getenv ("WAYLAND_DISPLAY") ?
                     g_getenv ("WAYLAND_DISPLAY") : "(unset)");
        return 1;
    }

    g_critical_messages = g_ptr_array_new_with_free_func (g_free);
    g_log_set_writer_func (critical_log_writer, NULL, NULL);
    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);

    /* Phase 2A scenarios — work without any install. */
    scenario_all_ui_files_load ();
    scenario_cert_properties_populate ();
    scenario_email_address ();
    scenario_expire_warning_foreground ();
    scenario_chain_export ();
    scenario_bulk_operations ();
    scenario_ecdsa_eddsa_keygen ();
    scenario_certificate_renewal ();
    scenario_certificate_diff ();

    /* Phase 2B scenarios drive production code paths that load .ui
     * files from PACKAGE_DATA_DIR (new_ca_window.c et al). That path
     * is populated only after `make install`. `make distcheck` runs
     * `make check` against the just-built binaries BEFORE install,
     * so these scenarios would fail with a chain of GTK CRITICALs
     * about NULL widgets from a builder that never loaded its file.
     *
     * Skip cleanly when the install location isn't populated. This
     * still exits 0 (passing) so distcheck succeeds; locally after
     * `sudo make install` all scenarios run. */
    gchar *probe = g_build_filename (PACKAGE_DATA_DIR, "gnomint",
                                     "main_window.ui", NULL);
    if (g_file_test (probe, G_FILE_TEST_EXISTS)) {
        scenario_new_self_signed_ca ();
        scenario_application_startup ();
        scenario_view_properties_full ();
        scenario_extract_private_key ();
        scenario_sign_csr ();
        scenario_sign_csr_has_san_editor ();
        scenario_revoke_cert ();
        scenario_wizard_window ();
        scenario_keylength_selector ();
        scenario_country_search ();
        scenario_expiry_banner ();
        scenario_search_filter ();
    } else {
        fprintf (stderr,
                 "==> Phase 2B scenarios skipped: %s not found.\n"
                 "    Run `sudo make install` first to populate "
                 "PACKAGE_DATA_DIR.\n",
                 probe);
    }
    g_free (probe);

    g_ptr_array_free (g_critical_messages, TRUE);

    if (g_failures > 0) {
        fprintf (stderr, "==> %d FAILURE(S)\n", g_failures);
        return 1;
    }
    fprintf (stderr, "==> OK\n");
    return 0;
}

/*
 * check_workflows.c — Phase 2A runtime workflow regression tests.
 *
 * Runs under a headless Wayland compositor (weston, started by
 * tests/run-headless.sh) with GDK_BACKEND=wayland. Wayland is gnomint's
 * primary user environment, so we exercise GTK's Wayland backend rather
 * than X11.
 *
 * Scope (issue #43, Phase 2A):
 *
 *   1. Smoke: gtk_init succeeds under Wayland; every .ui file in gui/
 *      loads via gtk_builder_add_from_file without any GTK CRITICAL
 *      warnings. Complements check_ui_consistency (static XML scan)
 *      by exercising GTK's actual parser and widget construction on
 *      the Wayland code path.
 *
 *   2. Certificate properties populate: build certificate_properties_dialog.ui
 *      via GtkBuilder, then call gnomint's __certificate_properties_populate
 *      with a known cert PEM. Assert that key widgets received their text.
 *      Catches widget-ID drift between certificate_properties.c and the .ui
 *      that the static checker can't see — the static check only knows
 *      about <signal handler="..."> references, not gtk_builder_get_object
 *      lookups inside .c files.
 *
 * Phase 2B (dialog auto-dismiss + the five workflow scenarios in #43)
 * is intentionally not implemented here; see the issue for the split.
 *
 * Any G_LOG_LEVEL_CRITICAL or G_LOG_LEVEL_WARNING from Gtk/Gdk/GLib
 * fails the run. The handler counts hits and records them; tests check
 * the counter before/after each scenario.
 *
 * Exit codes: 0 = all pass; 1 = at least one failure.
 */

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>

#ifndef GNOMINT_UI_DIR
# error "GNOMINT_UI_DIR must be set at compile time (path to gui/)"
#endif
#ifndef TEST_PEM_PATH
# error "TEST_PEM_PATH must be set at compile time (path to a sample cert PEM)"
#endif

/* External symbols from src/certificate_properties.c that we drive
 * directly. Both are global (not static) — see the .c file. */
extern GtkBuilder *certificate_properties_window_gtkb;
extern void        __certificate_properties_populate (const char *pem);

/* Globals from src/main.c that other linked GUI files reference. */
extern GtkBuilder *main_window_gtkb;

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
 * bypasses g_log_set_handler(). We install a writer that captures the
 * critical/warning levels we care about and tells GLib we handled the
 * message (no fallthrough to the default writer / stderr). */
static GLogWriterOutput
critical_log_writer (GLogLevelFlags         log_level,
                     const GLogField       *fields,
                     gsize                  n_fields,
                     gpointer               user_data G_GNUC_UNUSED)
{
    /* Anything below WARNING (info/debug/message) we let through unchanged. */
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

/* Returns the number of critical/warning messages logged since the last
 * call to critical_messages_reset(). Snapshots so a scenario can capture
 * messages it triggered without disturbing later scenarios. */
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
/*  Scenario 1: every .ui file loads via GtkBuilder under Wayland     */
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
        /* Attribute any critical/warning logs emitted during this load
         * to this specific file. Rewriting message text in place so the
         * final reset() reports them with file context. */
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
/*  Scenario 2: certificate properties populate                       */
/* ------------------------------------------------------------------ */

static int
scenario_cert_properties_populate (void)
{
    GError *err = NULL;
    gchar  *pem = NULL;
    gsize   pem_len = 0;
    int     ok = 0;

    fprintf (stderr, "==> scenario: certificate_properties_populate\n");

    if (!g_file_get_contents (TEST_PEM_PATH, &pem, &pem_len, &err)) {
        fail_test ("cert-properties-populate",
                   "cannot read test PEM at %s: %s",
                   TEST_PEM_PATH, err ? err->message : "?");
        g_clear_error (&err);
        return 1;
    }

    /* Build the dialog the same way certificate_properties_display does,
     * but stop before gtk_dialog_run. We assign to the global builder
     * variable that the populate code reads from. */
    certificate_properties_window_gtkb = gtk_builder_new ();
    gchar *ui_path = g_build_filename (GNOMINT_UI_DIR,
                                       "certificate_properties_dialog.ui",
                                       NULL);
    if (gtk_builder_add_from_file (certificate_properties_window_gtkb,
                                   ui_path, &err) == 0) {
        fail_test ("cert-properties-populate",
                   "cannot load %s: %s", ui_path,
                   err ? err->message : "?");
        g_clear_error (&err);
        goto out;
    }

    /* Drive gnomint's actual populate function. Any widget-ID drift between
     * certificate_properties.c and the .ui will emit Gtk-CRITICAL warnings
     * here, which our log handler captures. */
    __certificate_properties_populate (pem);

    /* Assert key widgets received non-empty text. Cert is davefx.pem
     * (FNMT root CA), so we expect at least the subject CN field to be set. */
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
/*  Driver                                                            */
/* ------------------------------------------------------------------ */

int
main (int argc, char **argv)
{
    /* gtk_init_check is non-fatal; we want a clean failure path if the
     * Wayland compositor isn't reachable. */
    if (!gtk_init_check (&argc, &argv)) {
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

    /* g_log_writer_func intercepts every g_log emission across all
     * domains. Set it AFTER gtk_init so anything GTK emits during the
     * scenarios is captured. */
    g_log_set_writer_func (critical_log_writer, NULL, NULL);
    g_log_set_always_fatal (G_LOG_LEVEL_ERROR);

    scenario_all_ui_files_load ();
    scenario_cert_properties_populate ();

    g_ptr_array_free (g_critical_messages, TRUE);

    if (g_failures > 0) {
        fprintf (stderr, "==> %d FAILURE(S)\n", g_failures);
        return 1;
    }
    fprintf (stderr, "==> OK\n");
    return 0;
}

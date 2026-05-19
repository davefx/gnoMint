/*
 * check_ui_consistency.c — static .ui file consistency checker
 *
 * Implements stage 1 of the test suite (issue #42). Three checks:
 *
 *   1. GTK 2-only properties that GTK 3 GtkBuilder refuses (e.g.
 *      has_separator on GtkDialog). Caught the stale-install
 *      segfault chain seen during PR #38's smoke test.
 *
 *   2. GtkGrid / GtkTable cell-position collisions: no two children
 *      of the same grid may share an identical (left_attach,
 *      top_attach) pair. Caught the latent #39 row 9 collision.
 *
 *   3. Signal handler completeness: every <signal handler="X"/>
 *      referenced in any .ui file must resolve to a symbol via
 *      dlsym(RTLD_DEFAULT, "X"). Requires the test binary to be
 *      linked against the GUI .c files (see tests/Makefile.am).
 *
 * Runs offline. No display, no GTK init, no Xvfb.
 *
 * Exit codes: 0 = all checks pass; 1 = at least one failure.
 */

#include <dirent.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>

#ifndef GNOMINT_UI_DIR
# error "GNOMINT_UI_DIR must be set at compile time (path to gui/)"
#endif

/* ---------- known GTK 2-only properties --------------------------- */

/* Properties that exist in GTK 2 but were removed in GTK 3. If any of
 * these appears in a .ui file, GtkBuilder under GTK 3 logs a critical
 * warning and the entire file may fail to construct — which is exactly
 * what bit us when /usr/local/share/gnomint/ held stale GTK 2 layouts.
 * Extend this list as new offenders are discovered. */
static const char *GTK2_ONLY_PROPERTIES[] = {
    "has_separator",   /* GtkDialog, removed in GTK 3.0 */
    NULL
};

/* ---------- failure accumulator ----------------------------------- */

static int g_failures = 0;

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

/* ---------- per-file parsing state -------------------------------- */

typedef struct {
    const char *filename;     /* basename, for diagnostics */

    /* Stack of GHashTable* — one entry per nested GtkGrid/GtkTable.
     * Each table maps "L,T" string keys to GINT_TO_POINTER(1). */
    GQueue     *grid_stack;

    /* Current <property> being read. */
    char       *current_property_name;
    GString    *current_property_text;

    /* Most recent packing pair, accumulated as we walk a <packing>
     * block. Reset on entry to <packing>, consumed on exit. */
    char       *pending_left;
    char       *pending_top;
    int         in_packing;

    /* Global handler-name set, shared across files. */
    GHashTable *handlers;     /* set of strings (key owned) */
} FileCtx;

/* ---------- GMarkupParser callbacks ------------------------------- */

static void
on_start (GMarkupParseContext  *ctx G_GNUC_UNUSED,
          const gchar          *name,
          const gchar         **attr_names,
          const gchar         **attr_values,
          gpointer              user_data,
          GError              **error G_GNUC_UNUSED)
{
    FileCtx *fc = user_data;
    int      i;

    if (g_strcmp0 (name, "object") == 0) {
        const char *cls = NULL;
        for (i = 0; attr_names[i]; i++) {
            if (g_strcmp0 (attr_names[i], "class") == 0) {
                cls = attr_values[i];
                break;
            }
        }
        /* Push for every object so the stack tracks XML object nesting
         * precisely. Grid/Table objects get a real hashtable; everything
         * else gets a NULL sentinel. peek_tail() of grid_stack at packing
         * time gives us the immediate parent container (the inner object
         * has already been popped by the time <packing> appears). */
        if (cls && (g_strcmp0 (cls, "GtkGrid") == 0 ||
                    g_strcmp0 (cls, "GtkTable") == 0)) {
            g_queue_push_tail (fc->grid_stack,
                               g_hash_table_new_full (g_str_hash, g_str_equal,
                                                      g_free, NULL));
        } else {
            g_queue_push_tail (fc->grid_stack, NULL);
        }
        return;
    }

    if (g_strcmp0 (name, "packing") == 0) {
        fc->in_packing = 1;
        g_free (fc->pending_left);
        g_free (fc->pending_top);
        fc->pending_left = fc->pending_top = NULL;
        return;
    }

    if (g_strcmp0 (name, "property") == 0) {
        const char *pname = NULL;
        for (i = 0; attr_names[i]; i++) {
            if (g_strcmp0 (attr_names[i], "name") == 0) {
                pname = attr_values[i];
                break;
            }
        }
        if (pname) {
            fc->current_property_name = g_strdup (pname);
            if (fc->current_property_text)
                g_string_free (fc->current_property_text, TRUE);
            fc->current_property_text = g_string_new ("");

            /* Check 1: GTK 2-only property name? */
            for (i = 0; GTK2_ONLY_PROPERTIES[i]; i++) {
                if (g_strcmp0 (pname, GTK2_ONLY_PROPERTIES[i]) == 0) {
                    fail_test ("gtk2-only-property",
                               "%s declares <property name=\"%s\"> "
                               "(removed in GTK 3)",
                               fc->filename, pname);
                    break;
                }
            }
        }
        return;
    }

    if (g_strcmp0 (name, "signal") == 0) {
        const char *handler = NULL;
        for (i = 0; attr_names[i]; i++) {
            if (g_strcmp0 (attr_names[i], "handler") == 0) {
                handler = attr_values[i];
                break;
            }
        }
        if (handler && fc->handlers)
            g_hash_table_add (fc->handlers, g_strdup (handler));
        return;
    }
}

static void
on_text (GMarkupParseContext  *ctx G_GNUC_UNUSED,
         const gchar          *text,
         gsize                 text_len,
         gpointer              user_data,
         GError              **error G_GNUC_UNUSED)
{
    FileCtx *fc = user_data;
    if (fc->current_property_text)
        g_string_append_len (fc->current_property_text, text, text_len);
}

static void
on_end (GMarkupParseContext  *ctx G_GNUC_UNUSED,
        const gchar          *name,
        gpointer              user_data,
        GError              **error G_GNUC_UNUSED)
{
    FileCtx *fc = user_data;

    if (g_strcmp0 (name, "property") == 0 && fc->current_property_name) {
        if (fc->in_packing && fc->current_property_text) {
            if (g_strcmp0 (fc->current_property_name, "left_attach") == 0) {
                g_free (fc->pending_left);
                fc->pending_left = g_strdup (fc->current_property_text->str);
            } else if (g_strcmp0 (fc->current_property_name, "top_attach") == 0) {
                g_free (fc->pending_top);
                fc->pending_top = g_strdup (fc->current_property_text->str);
            }
        }
        g_free (fc->current_property_name);
        fc->current_property_name = NULL;
        if (fc->current_property_text) {
            g_string_free (fc->current_property_text, TRUE);
            fc->current_property_text = NULL;
        }
        return;
    }

    if (g_strcmp0 (name, "packing") == 0) {
        fc->in_packing = 0;
        GHashTable *grid = g_queue_peek_tail (fc->grid_stack);
        if (grid) {
            /* Default top_attach in GtkGrid is 0 if absent; same for
             * left_attach. Treat absent as "0" for collision detection. */
            const char *l = fc->pending_left ? fc->pending_left : "0";
            const char *t = fc->pending_top  ? fc->pending_top  : "0";
            char *key = g_strdup_printf ("%s,%s", l, t);
            if (g_hash_table_contains (grid, key)) {
                fail_test ("grid-cell-collision",
                           "%s: two children at cell (left_attach=%s, "
                           "top_attach=%s)",
                           fc->filename, l, t);
                g_free (key);
            } else {
                g_hash_table_add (grid, key);   /* takes ownership */
            }
        }
        g_free (fc->pending_left);
        g_free (fc->pending_top);
        fc->pending_left = fc->pending_top = NULL;
        return;
    }

    if (g_strcmp0 (name, "object") == 0) {
        /* Always pop in on_start <object> always pushed something. */
        GHashTable *ht = g_queue_pop_tail (fc->grid_stack);
        if (ht)
            g_hash_table_destroy (ht);
        return;
    }
}

/* ---------- driver ------------------------------------------------ */

static int
check_one_file (const char *path, GHashTable *handlers)
{
    char       *contents = NULL;
    gsize       length = 0;
    GError     *err = NULL;
    FileCtx     fc = {0};
    GMarkupParser parser = { on_start, on_end, on_text, NULL, NULL };
    GMarkupParseContext *pc;

    if (!g_file_get_contents (path, &contents, &length, &err)) {
        fail_test ("read", "cannot read %s: %s", path, err->message);
        g_clear_error (&err);
        return 1;
    }

    fc.filename = path;
    fc.grid_stack = g_queue_new ();
    fc.handlers = handlers;

    pc = g_markup_parse_context_new (&parser, 0, &fc, NULL);
    if (!g_markup_parse_context_parse (pc, contents, length, &err) ||
        !g_markup_parse_context_end_parse (pc, &err)) {
        fail_test ("parse", "%s: %s", path, err ? err->message : "unknown");
        g_clear_error (&err);
    }

    /* Cleanup. In a well-formed file the stack should be empty here;
     * defensive in case of a parser error mid-document. NULL entries
     * are sentinels for non-grid objects. */
    g_markup_parse_context_free (pc);
    while (!g_queue_is_empty (fc.grid_stack)) {
        GHashTable *ht = g_queue_pop_head (fc.grid_stack);
        if (ht)
            g_hash_table_destroy (ht);
    }
    g_queue_free (fc.grid_stack);
    g_free (fc.current_property_name);
    if (fc.current_property_text)
        g_string_free (fc.current_property_text, TRUE);
    g_free (fc.pending_left);
    g_free (fc.pending_top);
    g_free (contents);
    return 0;
}

static int
str_cmp_qsort (const void *a, const void *b)
{
    return g_strcmp0 (*(const char * const *)a, *(const char * const *)b);
}

static void
check_handler_symbols (GHashTable *handlers)
{
    void           *self;
    GList          *names = g_hash_table_get_keys (handlers);
    guint           n = g_list_length (names);
    const gchar   **arr = g_new0 (const gchar *, n);
    guint           i = 0;

    self = dlopen (NULL, RTLD_NOW | RTLD_GLOBAL);
    if (!self) {
        fail_test ("dlopen", "dlopen(NULL) failed: %s", dlerror ());
        g_list_free (names);
        g_free (arr);
        return;
    }

    for (GList *l = names; l; l = l->next)
        arr[i++] = l->data;
    qsort (arr, n, sizeof *arr, str_cmp_qsort);

    for (i = 0; i < n; i++) {
        dlerror ();
        if (!dlsym (self, arr[i])) {
            fail_test ("orphan-signal-handler",
                       "no symbol named \"%s\" in test binary "
                       "(referenced as a signal handler in some .ui file)",
                       arr[i]);
        }
    }

    g_free (arr);
    g_list_free (names);
    dlclose (self);
}

int
main (void)
{
    const char *uidir = GNOMINT_UI_DIR;
    DIR        *d;
    struct dirent *de;
    GPtrArray  *files;
    GHashTable *handlers;
    guint       i;

    fprintf (stderr, "==> check_ui_consistency: scanning %s\n", uidir);

    files = g_ptr_array_new_with_free_func (g_free);
    d = opendir (uidir);
    if (!d) {
        fprintf (stderr, "FAIL: cannot opendir(%s)\n", uidir);
        return 1;
    }
    while ((de = readdir (d))) {
        size_t len = strlen (de->d_name);
        if (len > 3 && g_strcmp0 (de->d_name + len - 3, ".ui") == 0)
            g_ptr_array_add (files, g_build_filename (uidir, de->d_name, NULL));
    }
    closedir (d);
    g_ptr_array_sort (files, (GCompareFunc) str_cmp_qsort);

    if (files->len == 0) {
        fprintf (stderr, "FAIL: no .ui files found in %s\n", uidir);
        g_ptr_array_free (files, TRUE);
        return 1;
    }

    handlers = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    for (i = 0; i < files->len; i++) {
        const char *path = g_ptr_array_index (files, i);
        fprintf (stderr, "    %s\n", path);
        check_one_file (path, handlers);
    }

    fprintf (stderr, "==> %u .ui files scanned, %u unique signal handlers\n",
             files->len, g_hash_table_size (handlers));

    check_handler_symbols (handlers);

    g_hash_table_destroy (handlers);
    g_ptr_array_free (files, TRUE);

    if (g_failures > 0) {
        fprintf (stderr, "==> %d FAILURE(S)\n", g_failures);
        return 1;
    }
    fprintf (stderr, "==> OK\n");
    return 0;
}

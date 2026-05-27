//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006-2009 David Marin Carreno <davefx@gmail.com>
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

#include <glib/gi18n.h>
#include <stdlib.h>
#include <string.h>

#include "ca_selector.h"
#include "ca_file.h"

/* ------------------------------------------------------------------ */
/* Column indices returned by ca_file_foreach_ca (SQLite callback)     */
/* ------------------------------------------------------------------ */

enum {
	CA_SEL_COL_ID           = 0,
	CA_SEL_COL_SERIAL       = 1,
	CA_SEL_COL_SUBJECT      = 2,
	CA_SEL_COL_DN           = 3,
	CA_SEL_COL_PARENT_DN    = 4,
	CA_SEL_COL_PEM          = 5,
	CA_SEL_COL_EXPIRATION   = 6,
	CA_SEL_COL_SUBJECT_COUNT = 7
};

/* ------------------------------------------------------------------ */
/* Population state passed through the SQLite callback                 */
/* ------------------------------------------------------------------ */

typedef struct {
	GListStore      *root_store;
	GnomintCertRow  *last_row;       /* last row inserted (any level) */
	GnomintCertRow  *last_parent;    /* current parent row (or NULL)  */
} _CaSelectorPopCtx;

/* Recursive helper: find a GnomintCertRow with the given DN in a store. */
static GnomintCertRow *
_find_row_with_dn (GListStore *store, const gchar *dn)
{
	guint n = g_list_model_get_n_items (G_LIST_MODEL (store));
	for (guint i = 0; i < n; i++) {
		GnomintCertRow *row = g_list_model_get_item (G_LIST_MODEL (store), i);
		const gchar *row_dn = gnomint_cert_row_get_dn (row);
		if (row_dn && !strcmp (row_dn, dn)) {
			/* Found -- return without unref; caller must unref. */
			return row;
		}
		/* Search children. */
		GListStore *children = gnomint_cert_row_get_children (row);
		GnomintCertRow *found = _find_row_with_dn (children, dn);
		g_object_unref (row);
		if (found)
			return found;
	}
	return NULL;
}

/* SQLite callback for ca_file_foreach_ca(). */
static int
_ca_selector_add_ca (void *pArg, int argc, char **argv, char **columnNames)
{
	(void) argc;
	(void) columnNames;

	_CaSelectorPopCtx *ctx = (_CaSelectorPopCtx *) pArg;

	gchar *subject_with_expiration = ca_file_format_subject_with_expiration (
	    argv[CA_SEL_COL_SUBJECT],
	    argv[CA_SEL_COL_EXPIRATION],
	    argv[CA_SEL_COL_SUBJECT_COUNT]);

	GnomintCertRow *row = gnomint_cert_row_new ();
	gnomint_cert_row_set_id (row, (guint64) atoll (argv[CA_SEL_COL_ID]));
	gnomint_cert_row_set_serial (row, argv[CA_SEL_COL_SERIAL]);
	gnomint_cert_row_set_subject (row, subject_with_expiration);
	gnomint_cert_row_set_dn (row, argv[CA_SEL_COL_DN]);
	gnomint_cert_row_set_parent_dn (row, argv[CA_SEL_COL_PARENT_DN]);
	gnomint_cert_row_set_pem (row, argv[CA_SEL_COL_PEM]);
	gnomint_cert_row_set_expiration (row, argv[CA_SEL_COL_EXPIRATION]);
	gnomint_cert_row_set_is_ca (row, TRUE);
	gnomint_cert_row_set_item_type (row, GNOMINT_ROW_TYPE_CA);

	g_free (subject_with_expiration);

	/* Determine where to insert: top-level or child of a parent. */
	const gchar *dn = argv[CA_SEL_COL_DN];
	const gchar *parent_dn = argv[CA_SEL_COL_PARENT_DN];

	GListStore *target_store = ctx->root_store;

	if (dn && parent_dn && strcmp (dn, parent_dn) != 0) {
		/* Not self-signed -- find parent row by DN. */
		GnomintCertRow *parent = _find_row_with_dn (ctx->root_store, parent_dn);
		if (parent) {
			target_store = gnomint_cert_row_get_children (parent);
			ctx->last_parent = parent;
			/* parent ref will be released when ctx->last_parent is replaced. */
		}
	} else {
		/* Self-signed: clear parent tracking. */
		ctx->last_parent = NULL;
	}

	g_list_store_append (target_store, row);

	if (ctx->last_row)
		g_object_unref (ctx->last_row);
	ctx->last_row = row;  /* transfer ownership */

	return 0;
}

GListStore *
ca_selector_populate (void)
{
	GListStore *root_store = g_list_store_new (GNOMINT_TYPE_CERT_ROW);

	_CaSelectorPopCtx ctx;
	ctx.root_store   = root_store;
	ctx.last_row     = NULL;
	ctx.last_parent  = NULL;

	ca_file_foreach_ca (_ca_selector_add_ca, &ctx);

	if (ctx.last_row)
		g_object_unref (ctx.last_row);

	return root_store;
}

/* ------------------------------------------------------------------ */
/* GtkTreeListModel child-model callback                               */
/* ------------------------------------------------------------------ */

static GListModel *
_ca_selector_create_child_model (gpointer item,
                                 gpointer user_data G_GNUC_UNUSED)
{
	GnomintCertRow *row = GNOMINT_CERT_ROW (item);
	GListStore *children = gnomint_cert_row_get_children (row);
	if (g_list_model_get_n_items (G_LIST_MODEL (children)) == 0)
		return NULL;
	return G_LIST_MODEL (g_object_ref (children));
}

/* Helper: expand all rows. */
static void
_ca_selector_expand_all (GtkTreeListModel *tree_model)
{
	guint n = g_list_model_get_n_items (G_LIST_MODEL (tree_model));
	for (guint i = 0; i < n; i++) {
		GtkTreeListRow *tlr = gtk_tree_list_model_get_row (tree_model, i);
		if (tlr) {
			gtk_tree_list_row_set_expanded (tlr, TRUE);
			g_object_unref (tlr);
		}
		n = g_list_model_get_n_items (G_LIST_MODEL (tree_model));
	}
}

/* ------------------------------------------------------------------ */
/* GtkColumnView factory callbacks (Subject column with tree expander)  */
/* ------------------------------------------------------------------ */

static void
_ca_selector_subject_setup (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                            GtkListItem *list_item,
                            gpointer user_data G_GNUC_UNUSED)
{
	GtkWidget *expander = gtk_tree_expander_new ();
	GtkWidget *label = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (label), 0);
	gtk_label_set_use_markup (GTK_LABEL (label), TRUE);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_tree_expander_set_child (GTK_TREE_EXPANDER (expander), label);
	gtk_list_item_set_child (list_item, expander);
}

static void
_ca_selector_subject_bind (GtkSignalListItemFactory *factory G_GNUC_UNUSED,
                           GtkListItem *list_item,
                           gpointer user_data G_GNUC_UNUSED)
{
	GtkTreeListRow *tree_row = GTK_TREE_LIST_ROW (
	    gtk_list_item_get_item (list_item));
	GtkWidget *expander = gtk_list_item_get_child (list_item);
	gtk_tree_expander_set_list_row (GTK_TREE_EXPANDER (expander), tree_row);

	GnomintCertRow *row = GNOMINT_CERT_ROW (
	    gtk_tree_list_row_get_item (tree_row));
	GtkWidget *label = gtk_tree_expander_get_child (
	    GTK_TREE_EXPANDER (expander));

	const gchar *subject = gnomint_cert_row_get_subject (row);
	gtk_label_set_markup (GTK_LABEL (label), subject ? subject : "");

	g_object_unref (row);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

GtkSingleSelection *
ca_selector_setup (GtkColumnView    *colview,
                   GListStore       *root_store,
                   GtkTreeListModel **tree_model_out)
{
	/* Create a GtkTreeListModel wrapping the root store. */
	GtkTreeListModel *tree_model = gtk_tree_list_model_new (
	    G_LIST_MODEL (g_object_ref (root_store)),
	    FALSE,  /* passthrough = FALSE so items are GtkTreeListRow */
	    TRUE,   /* autoexpand */
	    _ca_selector_create_child_model,
	    NULL, NULL);

	/* Wrap in a single-selection model. */
	GtkSingleSelection *sel = gtk_single_selection_new (
	    G_LIST_MODEL (tree_model));
	gtk_single_selection_set_autoselect (sel, FALSE);
	gtk_single_selection_set_can_unselect (sel, TRUE);

	/* Set up the Subject column with a tree expander. */
	{
		GtkListItemFactory *f = gtk_signal_list_item_factory_new ();
		g_signal_connect (f, "setup",
		                  G_CALLBACK (_ca_selector_subject_setup), NULL);
		g_signal_connect (f, "bind",
		                  G_CALLBACK (_ca_selector_subject_bind), NULL);
		GtkColumnViewColumn *col = gtk_column_view_column_new (
		    _("Subject"), f);
		gtk_column_view_column_set_expand (col, TRUE);
		gtk_column_view_append_column (colview, col);
		g_object_unref (col);
	}

	/* Set the model on the column view. */
	gtk_column_view_set_model (colview, GTK_SELECTION_MODEL (sel));

	/* Expand all rows. */
	_ca_selector_expand_all (tree_model);

	/* Return tree model if requested. */
	if (tree_model_out)
		*tree_model_out = g_object_ref (tree_model);

	return sel;
}

guint64
ca_selector_get_selected_id (GtkSingleSelection *sel)
{
	GnomintCertRow *row = ca_selector_get_selected_row (sel);
	if (!row)
		return 0;
	guint64 id = gnomint_cert_row_get_id (row);
	g_object_unref (row);
	return id;
}

GnomintCertRow *
ca_selector_get_selected_row (GtkSingleSelection *sel)
{
	GtkTreeListRow *tree_row = GTK_TREE_LIST_ROW (
	    gtk_single_selection_get_selected_item (sel));
	if (!tree_row)
		return NULL;
	return GNOMINT_CERT_ROW (gtk_tree_list_row_get_item (tree_row));
}

gboolean
ca_selector_select_by_id (GtkSingleSelection *sel, guint64 ca_id)
{
	GListModel *model = gtk_single_selection_get_model (sel);
	guint n = g_list_model_get_n_items (model);
	for (guint i = 0; i < n; i++) {
		GtkTreeListRow *tlr = g_list_model_get_item (model, i);
		if (!tlr) continue;
		GnomintCertRow *row = GNOMINT_CERT_ROW (
		    gtk_tree_list_row_get_item (tlr));
		if (row) {
			guint64 rid = gnomint_cert_row_get_id (row);
			g_object_unref (row);
			if (rid == ca_id) {
				gtk_single_selection_set_selected (sel, i);
				g_object_unref (tlr);
				return TRUE;
			}
		}
		g_object_unref (tlr);
	}
	return FALSE;
}

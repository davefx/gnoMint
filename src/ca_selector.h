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

#ifndef CA_SELECTOR_H
#define CA_SELECTOR_H

#include <gtk/gtk.h>
#include "cert_row.h"

/* Shared CA-selector widget used by crl.c, new_cert.c, and new_req_window.c.
 *
 * Replaces the old GtkTreeView + GtkTreeStore pattern with a
 * GtkColumnView + GtkTreeListModel backed by GnomintCertRow objects.
 */

/* Populate a GListStore with GnomintCertRow objects obtained from
 * ca_file_foreach_ca(). The store is created internally and returned
 * via *store_out. */
GListStore *ca_selector_populate (void);

/* Set up a GtkColumnView for CA selection. Creates a GtkTreeListModel,
 * wraps it in a GtkSingleSelection, adds a Subject column with a
 * GtkTreeExpander, and expands all rows.
 *
 * The GtkColumnView must already exist (typically from the UI file).
 *
 * Returns the GtkSingleSelection model (caller owns a ref).
 * Also returns the GtkTreeListModel via *tree_model_out if non-NULL. */
GtkSingleSelection *ca_selector_setup (GtkColumnView *colview,
                                       GListStore    *root_store,
                                       GtkTreeListModel **tree_model_out);

/* Convenience: get the selected GnomintCertRow's ID.
 * Returns 0 if nothing is selected. */
guint64 ca_selector_get_selected_id (GtkSingleSelection *sel);

/* Convenience: get the selected GnomintCertRow itself (caller must
 * g_object_unref).  Returns NULL if nothing is selected. */
GnomintCertRow *ca_selector_get_selected_row (GtkSingleSelection *sel);

/* Find a CA row by its numeric id and select it.
 * Returns TRUE if found and selected. */
gboolean ca_selector_select_by_id (GtkSingleSelection *sel,
                                   guint64 ca_id);

#endif /* CA_SELECTOR_H */

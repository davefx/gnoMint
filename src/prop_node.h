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

#ifndef PROP_NODE_H
#define PROP_NODE_H

#include <glib-object.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define GNOMINT_TYPE_PROP_NODE (gnomint_prop_node_get_type())
G_DECLARE_FINAL_TYPE (GnomintPropNode, gnomint_prop_node, GNOMINT, PROP_NODE, GObject)

GnomintPropNode *gnomint_prop_node_new          (const gchar *name,
                                                  const gchar *value);

void             gnomint_prop_node_set_name      (GnomintPropNode *self,
                                                  const gchar *name);
const gchar     *gnomint_prop_node_get_name      (GnomintPropNode *self);

void             gnomint_prop_node_set_value     (GnomintPropNode *self,
                                                  const gchar *value);
const gchar     *gnomint_prop_node_get_value     (GnomintPropNode *self);

GListStore      *gnomint_prop_node_get_children  (GnomintPropNode *self);

G_END_DECLS

#endif /* PROP_NODE_H */

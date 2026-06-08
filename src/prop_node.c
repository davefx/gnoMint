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

#include <config.h>

#include "prop_node.h"

struct _GnomintPropNode {
    GObject     parent_instance;
    gchar      *name;
    gchar      *value;
    GListStore *children;
};

G_DEFINE_TYPE (GnomintPropNode, gnomint_prop_node, G_TYPE_OBJECT)

static void
gnomint_prop_node_finalize (GObject *object)
{
    GnomintPropNode *self = GNOMINT_PROP_NODE (object);
    g_free (self->name);
    g_free (self->value);
    g_clear_object (&self->children);
    G_OBJECT_CLASS (gnomint_prop_node_parent_class)->finalize (object);
}

static void
gnomint_prop_node_class_init (GnomintPropNodeClass *klass)
{
    G_OBJECT_CLASS (klass)->finalize = gnomint_prop_node_finalize;
}

static void
gnomint_prop_node_init (GnomintPropNode *self)
{
    self->children = g_list_store_new (GNOMINT_TYPE_PROP_NODE);
}

GnomintPropNode *
gnomint_prop_node_new (const gchar *name, const gchar *value)
{
    GnomintPropNode *node = g_object_new (GNOMINT_TYPE_PROP_NODE, NULL);
    node->name  = g_strdup (name);
    node->value = g_strdup (value);
    return node;
}

void
gnomint_prop_node_set_name (GnomintPropNode *self, const gchar *name)
{
    g_free (self->name);
    self->name = g_strdup (name);
}

const gchar *
gnomint_prop_node_get_name (GnomintPropNode *self)
{
    return self->name;
}

void
gnomint_prop_node_set_value (GnomintPropNode *self, const gchar *value)
{
    g_free (self->value);
    self->value = g_strdup (value);
}

const gchar *
gnomint_prop_node_get_value (GnomintPropNode *self)
{
    return self->value;
}

GListStore *
gnomint_prop_node_get_children (GnomintPropNode *self)
{
    return self->children;
}

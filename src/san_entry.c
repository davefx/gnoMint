//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006-2009 David Marín Carreño <davefx@gmail.com>
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

#include "san_entry.h"

struct _GnomintSanEntry {
    GObject  parent_instance;
    gchar   *san_type;
    gchar   *value;
};

G_DEFINE_TYPE (GnomintSanEntry, gnomint_san_entry, G_TYPE_OBJECT)

static void
gnomint_san_entry_finalize (GObject *object)
{
    GnomintSanEntry *self = GNOMINT_SAN_ENTRY (object);
    g_free (self->san_type);
    g_free (self->value);
    G_OBJECT_CLASS (gnomint_san_entry_parent_class)->finalize (object);
}

static void
gnomint_san_entry_class_init (GnomintSanEntryClass *klass)
{
    G_OBJECT_CLASS (klass)->finalize = gnomint_san_entry_finalize;
}

static void
gnomint_san_entry_init (GnomintSanEntry *self)
{
    self->san_type = NULL;
    self->value = NULL;
}

GnomintSanEntry *
gnomint_san_entry_new (const gchar *san_type, const gchar *value)
{
    GnomintSanEntry *self = g_object_new (GNOMINT_TYPE_SAN_ENTRY, NULL);
    self->san_type = g_strdup (san_type);
    self->value = g_strdup (value);
    return self;
}

void
gnomint_san_entry_set_san_type (GnomintSanEntry *self, const gchar *san_type)
{
    g_free (self->san_type);
    self->san_type = g_strdup (san_type);
}

const gchar *
gnomint_san_entry_get_san_type (GnomintSanEntry *self)
{
    return self->san_type;
}

void
gnomint_san_entry_set_value (GnomintSanEntry *self, const gchar *value)
{
    g_free (self->value);
    self->value = g_strdup (value);
}

const gchar *
gnomint_san_entry_get_value (GnomintSanEntry *self)
{
    return self->value;
}

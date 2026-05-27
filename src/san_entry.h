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

#ifndef SAN_ENTRY_H
#define SAN_ENTRY_H

#include <glib-object.h>

G_BEGIN_DECLS

#define GNOMINT_TYPE_SAN_ENTRY (gnomint_san_entry_get_type())
G_DECLARE_FINAL_TYPE (GnomintSanEntry, gnomint_san_entry, GNOMINT, SAN_ENTRY, GObject)

GnomintSanEntry *gnomint_san_entry_new           (const gchar *san_type, const gchar *value);

void             gnomint_san_entry_set_san_type   (GnomintSanEntry *self, const gchar *san_type);
const gchar     *gnomint_san_entry_get_san_type   (GnomintSanEntry *self);

void             gnomint_san_entry_set_value      (GnomintSanEntry *self, const gchar *value);
const gchar     *gnomint_san_entry_get_value      (GnomintSanEntry *self);

G_END_DECLS

#endif /* SAN_ENTRY_H */

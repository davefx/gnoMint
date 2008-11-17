//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006,2007,2008 David Marín Carreño <davefx@gmail.com>
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

#ifndef _UINT160_H_
#define _UINT160_H_

#include <glib.h>

typedef struct _UInt160 {
        guint64 value0;
        guint64 value1;
        guint32 value2;
} UInt160;

UInt160 * uint160_new(void);

void uint160_assign (UInt160 *var, guint64 new_value);
gboolean uint160_assign_hexstr (UInt160 *var, gchar *new_value);
void uint160_add (UInt160 *var, guint64 new_value);
void uint160_inc (UInt160 *var);
void uint160_dec (UInt160 *var);
void uint160_shift (UInt160 *var, guint positions);

gboolean uint160_write (const UInt160 *var, guchar *buffer, gsize * max_size);
gboolean uint160_read (UInt160 *var, guchar *buffer, gsize size);

gboolean uint160_write_escaped (const UInt160 *var, gchar *buffer, gsize * max_size);
gboolean uint160_read_escaped (UInt160 *var, gchar *buffer, gsize size);
gboolean uint160_read_escaped_old_format (UInt160 *var, gchar *buffer, gsize size);



gchar * uint160_strdup_printf (const UInt160 *var);

void uint160_free (UInt160 *var);

#endif

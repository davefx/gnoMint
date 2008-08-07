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


#include "uint160.h"
#include <string.h>
#include <glib/gprintf.h>

UInt160 * uint160_new()
{
        UInt160 *res = g_new0(UInt160, 1);
        res->value0=0;
        res->value1=0;
        res->value2=0;

        fprintf (stderr, "Creado nuevo Uint160: %u:%llu:%llu\n", res->value2, res->value1, res->value0);

        return res;
}

void uint160_assign (UInt160 *var, guint64 new_value)
{
        fprintf (stderr, "Antes de asignar Uint160: %u:%llu:%llu\n", var->value2, var->value1, var->value0);
        var->value0=new_value;
        var->value1=0;
        var->value2=0;

        fprintf (stderr, "Asignado valor %llu Uint160: %u:%llu:%llu\n", new_value, var->value2, var->value1, var->value0);
        return;
}

void uint160_add (UInt160 *var, guint64 new_value)
{
        guint64 value0_backup = var->value0;
        guint64 value1_backup = var->value1;

        fprintf (stderr, "Sumando %llu a Uint160: %u:%llu:%llu\n", new_value, var->value2, var->value1, var->value0);

        var->value0 = var->value0 + new_value;
        if (var->value0 < value0_backup) {
                var->value1++;
                if (var->value1 < value1_backup)
                        var->value2++;
        }

        fprintf (stderr, "Resultado: %u:%llu:%llu\n", var->value2, var->value1, var->value0);

        return;
}

void uint160_inc (UInt160 *var)
{
        uint160_add (var, 1);
        return;
}


void uint160_shift (UInt160 *var, guint positions)
{
        fprintf (stderr, "Shifting %u a Uint160: %u:%llu:%llu\n", positions, var->value2, var->value1, var->value0);
        guint64 carry0_to_1;
        guint64 carry1_to_2;

        if (positions > 0) {
                carry0_to_1 = (var->value0 & G_GUINT64_CONSTANT(0x8000000000000000));
                carry1_to_2 = (var->value1 & G_GUINT64_CONSTANT(0x8000000000000000));

                var->value0 = var->value0 * 2;
                var->value1 = (var->value1 * 2) + (carry0_to_1 ? 1 : 0);
                var->value2 = (var->value2 * 2) + (carry1_to_2 ? 1 : 0);

                uint160_shift (var, positions - 1);
        }
        
        return;
}


gboolean uint160_write (UInt160 *var, guchar *buffer, gsize * max_size)
{
        if (*max_size < sizeof(UInt160)) {
                *max_size = sizeof(UInt160);
                return FALSE;
        }

        memcpy (buffer, var, sizeof(UInt160));
        *max_size = sizeof(UInt160);
        return TRUE;
        
}

gboolean uint160_read (UInt160 *var, guchar *buffer, gsize buffer_size)
{
        gint i;
        guchar c;
        
        if (buffer_size > 20)
                return FALSE;

        var->value0=0;
        var->value1=0;
        var->value2=0;

        for (i=buffer_size - 1; i >= 0; i--) {
                c = buffer[i];
                uint160_shift (var, 8);
                uint160_add (var, c);
        }
        return TRUE;
}

gboolean uint160_write_escaped (UInt160 *var, gchar *buffer, gsize * max_size)
{
        int i;
        guchar *current = (guchar *) var;
        int oversize = 0;

        for (i=0; i<sizeof(UInt160); i++) {
                if (current[i] < 32)
                        oversize++;
        }
        
        if (*max_size < sizeof(UInt160) + oversize) {
                *max_size = sizeof(UInt160) + oversize;
                return FALSE;
        }

        oversize = 0;
        for (i=0; i<sizeof(UInt160); i++) {
                if (current[i] < 32) {
                        buffer[i+oversize] = 0x20;
                        oversize++;
                        buffer[i+oversize] = 0x20 + current[i];
                } else {
                        buffer[i+oversize] = current[i];
                }
        }

        return TRUE;
        
}

gboolean uint160_read_escaped (UInt160 *var, gchar *buffer, gsize buffer_size)
{
        gint i;
        guint num_chars;
        guchar c;
        guchar buffer_c[buffer_size];
        
        var->value0=0;
        var->value1=0;
        var->value2=0;

        num_chars = 0;
        for (i=0; i < buffer_size; i++) {
                c = buffer[i];
                if (c < 33) {
                        i++;
                        c = buffer[i] - 0x20;
                }
                buffer_c[num_chars] = c;
                num_chars++;
        }
        
        for (i=num_chars - 1; i>=0; i--) {
                c = buffer_c[i];
                uint160_shift (var, 8);
                uint160_add (var, c);
        }
        return TRUE;
}

gchar * uint160_strdup_printf (UInt160 *var)
{

        if (var->value2==0 && var->value1==0) {
                return g_strdup_printf ("%"G_GUINT64_FORMAT, var->value0);
        } else {
                GString *string = g_string_new("");
                guint64 val;
                gsize size;
                guchar * pointer;
                int i;

                /* First, we calculate how many bytes are filled */
                if (var->value2 != 0) {
                        size = 16;
                        val = var->value2;
                        while (val != 0) {
                                val = val >> 1;
                                size++;
                        }
                } else {
                        size = 8;
                        val = var->value1;
                        while (val != 0) {
                                val = val >> 1;
                                size ++;
                        }
                }
                        
                for (i=size-1; i>=0; i--) {
                        if (i < 8) {
                                pointer = (guchar *) &(var->value0);
                                g_string_append_printf (string, "%s%02X", (i==(size-1)?"":":"), pointer[i]);
                        } else if (i < 16) {
                                pointer = (guchar *) &(var->value1);
                                g_string_append_printf (string, "%s%02X", (i==(size-1)?"":":"), pointer[i-8]);
                        } else {
                                pointer = (guchar *) &(var->value2);
                                g_string_append_printf (string, "%s%02X", (i==(size-1)?"":":"), pointer[i-16]);
                        }
                }
                
                return g_string_free (string, FALSE);

        }
}

void uint160_free (UInt160 *var)
{
        g_free (var);
}

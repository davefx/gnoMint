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
        return res;
}

void uint160_assign (UInt160 *var, guint64 new_value)
{
        var->value0=new_value;
        var->value1=0;
        var->value2=0;

        return;
}

void uint160_add (UInt160 *var, guint64 new_value)
{
        guint64 value0_backup = var->value0;
        guint64 value1_backup = var->value1;

        var->value0 = var->value0 + new_value;
        if (var->value0 < value0_backup) {
                var->value1++;
                if (var->value1 < value1_backup)
                        var->value2++;
        }

        return;
}

void uint160_inc (UInt160 *var)
{
        uint160_add (var, 1);
        return;
}


void uint160_shift (UInt160 *var, guint positions)
{
        gboolean carry0_to_1;
        gboolean carry1_to_2;

        if (positions > 0) {
                carry0_to_1 = (var->value0 & 0x80000000);
                carry1_to_2 = (var->value1 & 0x80000000);

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
        return TRUE;
        
}

gboolean uint160_read (UInt160 *var, guchar *buffer, gsize buffer_size)
{
        guint i;
        guchar c;
        
        if (buffer_size > 20)
                return FALSE;

        var->value0=0;
        var->value1=0;
        var->value2=0;

        for (i=0; i < buffer_size; i++) {
                c = buffer[i];
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
                        
                for (i=0; i< size; i++) {
                        if (i < 8) {
                                pointer = (guchar *) &(var->value0);
                                g_string_append_printf (string, "%s%0X", (i==0?"":":"), pointer[i]);
                        } else if (i < 16) {
                                pointer = (guchar *) &(var->value1);
                                g_string_append_printf (string, ":%0X", pointer[i]);
                        } else {
                                pointer = (guchar *) &(var->value2);
                                g_string_append_printf (string, ":%0X", pointer[i]);
                        }
                }
                
                return g_string_free (string, FALSE);

        }
}

void uint160_free (UInt160 *var)
{
        g_free (var);
}

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

        /* fprintf (stderr, "Creado nuevo Uint160: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n",  */
	/* 	 res->value2, res->value1, res->value0); */

        return res;
}

void uint160_assign (UInt160 *var, guint64 new_value)
{
        /* fprintf (stderr, "Antes de asignar Uint160: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n",  */
	/* 	 var->value2, var->value1, var->value0); */
	
	memset (var, 0, sizeof(UInt160));

        var->value0=new_value;
        var->value1=0;
        var->value2=0;

        /* fprintf (stderr, "Asignado valor %"G_GUINT64_FORMAT" Uint160: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n",  */
	/* 	 new_value, var->value2, var->value1, var->value0); */
        return;
}


gboolean uint160_assign_hexstr (UInt160 *var, gchar *new_value_hex)
{
        guint i;
        gchar c;
        gchar * stripped_value = g_strstrip (new_value_hex);

        /* fprintf (stderr, "Antes de asignar Uint160=%s: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n", */
	/* 	 stripped_value, var->value2, var->value1, var->value0); */
	
	memset (var, 0, sizeof(UInt160));

        for (i=0; i < strlen(stripped_value); i++) {

                c = g_ascii_tolower(stripped_value[i]);

                // Check if the character is valid

                if (!((c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f'))) {
                        memset (var, 0, sizeof(UInt160));
                        fprintf (stderr, "Error al asignar valor %s Uint160: caracter «%c» encontrado.\n",
                                 stripped_value, c);
                        return FALSE;
                }
                
                uint160_shift (var, 4);

                switch(c) {
                case '0': 
                        break;
                case '1': 
                        uint160_add (var, 1); 
                        break;
                case '2': 
                        uint160_add (var, 2); 
                        break;
                case '3': 
                        uint160_add (var, 3); 
                        break;
                case '4': 
                        uint160_add (var, 4); 
                        break;
                case '5': 
                        uint160_add (var, 5); 
                        break;
                case '6': 
                        uint160_add (var, 6); 
                        break;
                case '7': 
                        uint160_add (var, 7); 
                        break;
                case '8': 
                        uint160_add (var, 8); 
                        break;
                case '9': 
                        uint160_add (var, 9); 
                        break;
                case 'a': 
                        uint160_add (var, 10); 
                        break;
                case 'b': 
                        uint160_add (var, 11); 
                        break;
                case 'c': 
                        uint160_add (var, 12); 
                        break;
                case 'd': 
                        uint160_add (var, 13); 
                        break;
                case 'e': 
                        uint160_add (var, 14); 
                        break;
                case 'f': 
                        uint160_add (var, 15); 
                        break;
                }

        }


        /* fprintf (stderr, "Asignado valor %s Uint160: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n", */
	/* 	 stripped_value, var->value2, var->value1, var->value0); */
        return TRUE;
}

void uint160_add (UInt160 *var, guint64 new_value)
{
        guint64 value0_backup = var->value0;
        guint64 value1_backup = var->value1;

        /* fprintf (stderr, "Sumando %"G_GUINT64_FORMAT" a Uint160: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n",  */
	/* 	 new_value, var->value2, var->value1, var->value0); */

        var->value0 = var->value0 + new_value;
        if (var->value0 < value0_backup) {
                var->value1++;
                if (var->value1 < value1_backup)
                        var->value2++;
        }

        /* fprintf (stderr, "Resultado: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n",  */
	/* 	 var->value2, var->value1, var->value0); */

        return;
}

void uint160_inc (UInt160 *var)
{
        uint160_add (var, 1);
        return;
}

void uint160_dec (UInt160 *var)
{
        guint64 value0_backup = var->value0;
        guint64 value1_backup = var->value1;


        var->value0 --;
        if (var->value0 > value0_backup) {
                var->value1 --;
                if (var->value1 > value1_backup)
                        var->value2--;
        }

        return;
}


void uint160_shift (UInt160 *var, guint positions)
{
        /* fprintf (stderr, "Shifting %u a Uint160: %u:%"G_GUINT64_FORMAT":%"G_GUINT64_FORMAT"\n",  */
	/* 	 positions, var->value2, var->value1, var->value0); */
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


gboolean uint160_write (const UInt160 *var, guchar *buffer, gsize * max_size)
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
        gint start, i;
        guchar c;
        
	memset (var, 0, sizeof(UInt160));

        var->value0=0;
        var->value1=0;
        var->value2=0;

        start = 0;

        if (start < buffer_size && buffer[start] == 0)
                start++;

        for (i=start; i < buffer_size; i++) {
                c = buffer[i];
                uint160_shift (var, 8);
                uint160_add (var, c);
        }
        return TRUE;
}

gboolean uint160_write_escaped (const UInt160 *var, gchar *buffer, gsize * max_size)
{
        gsize size = 0;
        guint32 value = 0;
        gsize pos = 0;

        if (var->value2 > 0)
                size = 16 + 16 + 8 + 1;
        else if (var->value1 > 0)
                size = 16 + 16 + 1;
        else
                size = 16 + 1;

        if (size > *max_size) {
                *max_size = size;
                return FALSE;
        }

        memset (buffer, 0, size);

        if (var->value2 > 0) {
                value = var->value2;
                sprintf (&buffer[pos], "%08" G_GINT32_MODIFIER "x", value);
                pos = pos + 8;
        }

        if (var->value2 > 0 || var->value1 > 0) {
                value = (var->value1 / G_GUINT64_CONSTANT(0x100000000));
                sprintf (&buffer[pos], "%08" G_GINT32_MODIFIER "x", value);
                pos = pos + 8;

                value = (var->value1 % G_GUINT64_CONSTANT(0x100000000));
                sprintf (&buffer[pos], "%08" G_GINT32_MODIFIER "x", value);
                pos = pos + 8;
        }

        value = (var->value0 / G_GUINT64_CONSTANT(0x100000000));
        sprintf (&buffer[pos], "%08" G_GINT32_MODIFIER "x", value);
        pos = pos + 8;
        
        value = (var->value0 % G_GUINT64_CONSTANT(0x100000000));
        sprintf (&buffer[pos], "%08" G_GINT32_MODIFIER "x", value);
        pos = pos + 8;

        return TRUE;
        
}

gboolean uint160_read_escaped (UInt160 *var, gchar *buffer, gsize buffer_size)
{
        gchar aux[2];
        guint i;
        guint num;
        gboolean res = TRUE;

        memset (var, 0, sizeof (UInt160));
        memset (aux, 0, 2);
        
        for (i=0; i<buffer_size; i++) {
                aux[1] = buffer[i];
                if (sscanf (aux, "%x", &num)) {
                        uint160_shift (var, 4);
                        uint160_add (var, num);
                } else {
                        memset (var, 0, sizeof (UInt160));
                        res = FALSE;
                        break;
                }
        }

        return res;
}


gboolean uint160_read_escaped_old_format (UInt160 *var, gchar *buffer, gsize buffer_size)
{
        gint i;
        guint num_chars;
        guchar c;
        guchar buffer_c[buffer_size];
        
	memset (var, 0, sizeof (UInt160));

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

gchar * uint160_strdup_printf (const UInt160 *var)
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

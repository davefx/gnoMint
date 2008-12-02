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


#include <glib.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <stdlib.h>
#include <stdio.h>

#include "ca_file.h"


void ca_error_dialog (gchar *message) {
        fprintf (stderr, "%s\n", message);
}

gchar * ca_dialog_get_password (gchar *info_message, 
                                gchar *password_message, gchar *confirm_message, 
                                gchar *distinct_error_message, guint minimum_length)
{
        gchar * password = NULL;

	return password;
}


void ca_todo_callback ()
{
	ca_error_dialog (_("To do. Feature not implemented yet."));
}


gboolean ca_open (gchar *filename, gboolean create) 
{
        gboolean result;

        fprintf (stderr, _("Opening database %s..."), filename);
        result = ca_file_open (filename, create); 
        
        if (result)
                fprintf (stderr, _(" OK.\n"));
        else
                fprintf (stderr, _(" Error.\n"));

	return result;
}

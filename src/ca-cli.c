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
#include <readline/readline.h>
#include <readline/history.h>


#include "ca_file.h"


typedef int  (* CaCommandCallback) (int argc, char **argv);

typedef struct _CaCommand {
        const gchar *command;
        guint mandatory_params;
        guint optional_params;
        gchar *sintax;
        gchar *help;
        CaCommandCallback callback;
} CaCommand;


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

int __ca_newdb (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_opendb (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_savedbas (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_status (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_listcert (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_listcsr (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_addcsr (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_addca (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_extractcertpkey (int argc, char **argv)
{
	//FIXME
	return 0;
}


int __ca_extractcsrpkey (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_revoke (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_sign (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_delete (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_crlgen (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_dhgen (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_changepassword (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_importfile (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_importdir (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_showcert (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_showcsr (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_showpolicy (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_setpolicy (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_showpreferences (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_setpreference (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_about (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_warranty  (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_warranty  (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_distribution  (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_version  (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_help  (int argc, char **argv)
{
	//FIXME
	return 0;
}

int __ca_exit (int argc, char **argv)
{
        //FIXME
        return 0;
}



void __ca_add_commands (GHashTable *table)
{
	g_hash_table_insert (table, "newdb", 
			     &((CaCommand) {"newdb", 1, 1, _("newdb <filename>"), _("Close current file and create a new database with given filename"), __ca_newdb}));
}

void ca_command_line()
{
        const gchar *prompt = "gnoMint > ";
        gchar *line = NULL;

	GHashTable *command_table = g_hash_table_new (g_str_hash, g_str_equal);

	__ca_add_commands (command_table);

        printf (_("\n\n%s version %s\n%s\n\n"), PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_COPYRIGHT); 
        printf (_("This program comes with ABSOLUTELY NO WARRANTY;\nfor details type 'warranty'.\n"));
        printf (_("This is free software, and you are welcome to redistribute it \n"));
        printf (_("under certain conditions; type 'distribution' for details.\n\n"));

        while (TRUE) {
                
                // Wait until read a command
                line = readline (prompt);
                
                // Check for EOF
                if (line == NULL) {
                        printf ("\n\n");
                        return;
                }
                
                // Check for empty commands
                if (strlen (line) != 0) {

                        add_history (line);

                        // Parse line

                        // If the given command is defined

                        // Call it
                
                }

                free (line);

        } 
        
}

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


GHashTable *ca_command_table = NULL;

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
	g_hash_table_insert (table, "newdb", &((CaCommand) 
                {"newdb", 1, 1, _("newdb <filename>"), _("Close current file and create a new database with given filename"), __ca_newdb}));
	g_hash_table_insert (table, "opendb", &((CaCommand) 
                {"opendb", 1, 1, _("opendb <filename>"), _("Close current file and open the file with given filename"), __ca_opendb}));
	g_hash_table_insert (table, "savedbas", &((CaCommand) 
                {"savedbas", 1, 1, _("savedbas <filename>"), _("Save the current file with a different filename"), __ca_savedbas}));
	g_hash_table_insert (table, "status", &((CaCommand) 
                {"status", 0, 0, "status", _("Get current status (opened file, no. of certificates, etc...)"), __ca_status}));
	g_hash_table_insert (table, "listcert", &((CaCommand) 
                {"listcert", 0, 1, "listcert [--see-revoked]", _("List the certificates in database. With option --see-revoked, "
                                                                 "lists also the revoked ones"), __ca_listcert}));
	g_hash_table_insert (table, "listcsr", &((CaCommand) 
                {"listcsr", 0, 0, "listcsr", _("List the CSRs in database"), __ca_listcsr}));
	g_hash_table_insert (table, "addcsr", &((CaCommand) 
                {"addcsr", 0, 0, "addcsr", _("Start a new CSR creation process"), __ca_addcsr}));
	g_hash_table_insert (table, "addca", &((CaCommand) 
                {"addca", 0, 0, "addca", _("Start a new self-signed CA creation process"), __ca_addca}));
	g_hash_table_insert (table, "extractcertpkey", &((CaCommand) 
                {"extractcertpkey", 2, 2, _("extractcertpkey <cert-id> <filename>"), _("Extract the private key of the certificate with the given "
                                                                                    "internal id and saves it into the given file"), 
                                __ca_extractcertpkey}));
	g_hash_table_insert (table, "extractcsrpkey", &((CaCommand) 
                {"extractcsrpkey", 2, 2, _("extractcsrpkey <csr-id> <filename>"), _("Extract the private key of the CSR with the given "
                                                                                "internal id and saves it into the given file"), 
                                __ca_extractcsrpkey}));
        g_hash_table_insert (table, "revoke", &((CaCommand)
                {"revoke", 1, 1, _("revoke <cert-id>"), _("Revoke the certificate with the given internal ID"), __ca_revoke}));
        g_hash_table_insert (table, "sign", &((CaCommand)
                {"sign", 2, 2, _("sign <csr-id> <ca-cert-id>"), _("Generate a certificate signing the given CSR with the given CA"), __ca_sign}));
        g_hash_table_insert (table, "delete", &((CaCommand)
                {"delete", 1, 1, _("delete <csr-id>"), _("Delete the given CSR from the database"), __ca_delete}));
        g_hash_table_insert (table, "dhgen", &((CaCommand)
                {"dhgen", 1, 1, _("dhgen <filename>"), _("Generate a new DH-parameter set, saving it into the file <filename>"), __ca_dhgen}));
        g_hash_table_insert (table, "changepassword", &((CaCommand)
                {"changepassword", 0, 0, "changepassword", _("Change password for the current database"), __ca_changepassword}));
        g_hash_table_insert (table, "importfile", &((CaCommand)
                {"importfile", 1, 1, _("importfile <filename>"), _("Import the file with the given name <filename>"), __ca_importfile}));
        g_hash_table_insert (table, "importdir", &((CaCommand)
                {"importdir", 1, 1, _("importdir <dirname>"), _("Import the given directory, as a OpenSSL-CA directory"), __ca_importdir}));
        g_hash_table_insert (table, "showcert", &((CaCommand)
                {"showcert", 1, 1, _("showcert <cert-id>"), _("Show properties of the given certificate"), __ca_showcert}));
        g_hash_table_insert (table, "showcsr", &((CaCommand)
                {"showcsr", 1, 1, _("showcsr <csr-id>"), _("Show properties of the given CSR"), __ca_showcsr}));
        g_hash_table_insert (table, "showpolicy", &((CaCommand)
                {"showpolicy", 1, 1, _("showpolicy <ca-id>"), _("Show CA policy"), __ca_showpolicy}));
        g_hash_table_insert (table, "setpolicy", &((CaCommand)
                {"setpolicy", 3, 3, _("setpolicy <ca-id> <policy-id> <value>"), _("Change the given CA policy"), __ca_setpolicy}));
        g_hash_table_insert (table, "showpreferences", &((CaCommand)
                {"showpreferences", 0, 0, "showpreferences", _("Show program preferences"), __ca_showpreferences}));
        g_hash_table_insert (table, "setpreference", &((CaCommand)
                {"setpreference", 2, 2, _("setpreference <preference-id> <value>"), _("Set the given program preference"), __ca_setpreference}));
        g_hash_table_insert (table, "about", &((CaCommand)
                {"about", 0, 0, "about", _("Show about message"), __ca_about}));
        g_hash_table_insert (table, "warranty", &((CaCommand)
                {"warranty", 0, 0, "warranty", _("Show warranty information"), __ca_warranty}));
        g_hash_table_insert (table, "distribution", &((CaCommand)
                {"distribution", 0, 0, "distribution", _("Show distribution information"), __ca_distribution}));
        g_hash_table_insert (table, "version", &((CaCommand)
                {"version", 0, 0, "version", _("Show version information"), __ca_version}));
        g_hash_table_insert (table, "help", &((CaCommand)
                {"help", 0, 0, "help", _("Show (this) help message"), __ca_help}));
        g_hash_table_insert (table, "quit", &((CaCommand)
                {"quit", 0, 0, "quit", _("Close database and exit program"), __ca_exit}));
        g_hash_table_insert (table, "exit", &((CaCommand)
                {"exit", 0, 0, "exit", _("Close database and exit program"), __ca_exit}));
        g_hash_table_insert (table, "bye", &((CaCommand)
                {"bye", 0, 0, "bye", _("Close database and exit program"), __ca_exit}));



}

void ca_command_line()
{
        const gchar *prompt = "gnoMint > ";
        gchar *line = NULL;

	ca_command_table = g_hash_table_new (g_str_hash, g_str_equal);

	__ca_add_commands (ca_command_table);

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
                        gint i,j,k;
                        gint argc = 0;
                        gchar *oldaux = NULL;
                        gchar **aux = NULL;
                        gchar **argv = NULL;

                        add_history (line);

                        // Parse line
                        aux = g_strsplit (line, "\"", -1 );

                        for (i = 0; i < (g_strv_length(aux) - 1); i++) {
                                if (aux[i][strlen(aux[i]) - 1] == '\\') {
                                        oldaux = aux[i];
                                        aux[i] = g_strdup_printf ("%s\"%s", aux[i], aux[i+1]);
                                        g_free (oldaux);
                                        for (j = i+1; j < g_strv_length(aux); j++) {
                                                aux[j] = aux[j+1];
                                        }
                                }
                        }

                        if (g_strv_length(aux) % 2 == 0) {
                                // Unpaired quotes
                                fprintf (stderr, _("Unpaired quotes\n"));
                        } else {
                                gchar **aux2[g_strv_length(aux)];
                                for (i=0; i < g_strv_length(aux); i++) {
                                        if (i % 2 == 0) {
                                                aux2[i] = g_strsplit (aux[i], " ", -1);
                                                
                                                for (j = 0; j < (g_strv_length(aux2[i]) - 1); j++) {
                                                        if (aux2[i][j] && aux2[i][j][strlen(aux2[i][j]) - 1] == '\\') {
                                                                oldaux = aux2[i][j];
                                                                aux2[i][j] = g_strdup_printf ("%s\"%s", aux2[i][j], aux2[i][j+1]);
                                                                g_free (oldaux);
                                                                for (k = j+1; k < g_strv_length(aux2[i]); k++) {
                                                                        aux2[i][k] = aux2[i][k+1];
                                                                }
                                                        }

                                                }                                                
                                        } else {
                                                aux2[i] = &(aux[i]);
                                        }
                                        for (j=0; j < g_strv_length(aux2[i]); j++) {
                                                if (aux2[i] && aux2[i][j] && strlen(aux2[i][j]))
                                                        argc++;
                                        }
                                }
                        }
                        g_strfreev (aux);

                        printf ("Argc: %d\n", argc);
                        argc = 0;

                        // If the given command is defined
                        if (argc > 0) {
                                CaCommand *command_entry = g_hash_table_lookup (ca_command_table, argv[0]);

                                if (!command_entry) {
                                        fprintf (stderr, _("Invalid command. Try 'help' for getting a list of recognized commands.\n"));
                                } else {
                                        // Call it
                                        command_entry->callback (argc, argv);
                                }
                        }                

                        if (argv)
                                g_strfreev (argv);

                }

                free (line);

        } 
        
}

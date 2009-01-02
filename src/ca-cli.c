
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
#include <glib/gi18n.h>
#include <glib-object.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <unistd.h>

#include "ca-cli.h"
#include "ca_file.h"
#include "ca-cli-callbacks.h"


CaCommand ca_commands[] = {
	{"newdb", 1, 1, N_("newdb <filename>"), N_("Close current file and create a new database with given filename"), ca_cli_callback_newdb}, // 0
	{"opendb", 1, 1, N_("opendb <filename>"), N_("Close current file and open the file with given filename"), ca_cli_callback_opendb}, // 1
	{"savedbas", 1, 1, N_("savedbas <filename>"), N_("Save the current file with a different filename"), ca_cli_callback_savedbas}, // 2
	{"status", 0, 0, "status", N_("Get current status (opened file, no. of certificates, etc...)"), ca_cli_callback_status}, // 3
	{"listcert", 0, 1, "listcert [--see-revoked]", N_("List the certificates in database. With option --see-revoked, "
							 "lists also the revoked ones"), ca_cli_callback_listcert}, // 4
	{"listcsr", 0, 0, "listcsr", N_("List the CSRs in database"), ca_cli_callback_listcsr}, // 5
	{"addcsr", 0, 1, N_("addcsr [ca-id-for-inherit-fields]"), N_("Start a new CSR creation process"), ca_cli_callback_addcsr}, // 6
	{"addca", 0, 0, "addca", N_("Start a new self-signed CA creation process"), ca_cli_callback_addca}, //7
	{"extractcertpkey", 2, 2, N_("extractcertpkey <cert-id> <filename>"), N_("Extract the private key of the certificate with the given " 
									       "internal id and saves it into the given file"),  
	 ca_cli_callback_extractcertpkey}, // 8
	{"extractcsrpkey", 2, 2, N_("extractcsrpkey <csr-id> <filename>"), N_("Extract the private key of the CSR with the given " 
									    "internal id and saves it into the given file"), 
	 ca_cli_callback_extractcsrpkey}, // 9
	{"revoke", 1, 1, N_("revoke <cert-id>"), N_("Revoke the certificate with the given internal ID"), ca_cli_callback_revoke}, // 10
	{"sign", 2, 2, N_("sign <csr-id> <ca-cert-id>"), N_("Generate a certificate signing the given CSR with the given CA"), ca_cli_callback_sign}, // 11
	{"delete", 1, 1, N_("delete <csr-id>"), N_("Delete the given CSR from the database"), ca_cli_callback_delete}, // 12
	{"dhgen", 2, 2, N_("dhgen <prime-bitlength> <filename>"), N_("Generate a new DH-parameter set, saving it into the file <filename>"), ca_cli_callback_dhgen}, // 13
	{"changepassword", 0, 0, "changepassword", N_("Change password for the current database"), ca_cli_callback_changepassword}, // 14
	{"importfile", 1, 1, N_("importfile <filename>"), N_("Import the file with the given name <filename>"), ca_cli_callback_importfile}, // 15
	{"importdir", 1, 1, N_("importdir <dirname>"), N_("Import the given directory, as a OpenSSL-CA directory"), ca_cli_callback_importdir}, // 16
	{"showcert", 1, 1, N_("showcert <cert-id>"), N_("Show properties of the given certificate"), ca_cli_callback_showcert}, // 17 
	{"showcsr", 1, 1, N_("showcsr <csr-id>"), N_("Show properties of the given CSR"), ca_cli_callback_showcsr}, // 18
	{"showpolicy", 1, 1, N_("showpolicy <ca-id>"), N_("Show CA policy"), ca_cli_callback_showpolicy}, // 19
	{"setpolicy", 3, 3, N_("setpolicy <ca-id> <policy-id> <value>"), N_("Change the given CA policy"), ca_cli_callback_setpolicy}, // 20
	{"showpreferences", 0, 0, "showpreferences", N_("Show program preferences"), ca_cli_callback_showpreferences}, // 21
	{"setpreference", 2, 2, N_("setpreference <preference-id> <value>"), N_("Set the given program preference"), ca_cli_callback_setpreference}, // 22
	{"about", 0, 0, "about", N_("Show about message"), ca_cli_callback_about}, // 23
	{"warranty", 0, 0, "warranty", N_("Show warranty information"), ca_cli_callback_warranty}, // 24
	{"distribution", 0, 0, "distribution", N_("Show distribution information"), ca_cli_callback_distribution}, // 25
	{"version", 0, 0, "version", N_("Show version information"), ca_cli_callback_version}, // 26
	{"help", 0, 0, "help", N_("Show (this) help message"),  ca_cli_callback_help}, // 27
	{"quit", 0, 0, "quit", N_("Close database and exit program"), ca_cli_callback_exit}, // 28
	{"exit", 0, 0, "exit", N_("Close database and exit program"), ca_cli_callback_exit}, // 29
	{"bye", 0, 0, "bye", N_("Close database and exit program"), ca_cli_callback_exit} // 30
};
#define CA_COMMAND_NUMBER 31




GHashTable *ca_command_table = NULL;


gboolean ca_refresh_model (void)
{
	return TRUE;
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




void __ca_add_commands (GHashTable *table)
{
	gint i;

	for (i=0; i < CA_COMMAND_NUMBER; i++) {
		g_hash_table_insert (table, (gchar *) ca_commands[i].command, &(ca_commands[i]));
	}

}

void ca_command_line()
{
        const gchar *prompt = "gnoMint > ";
        gchar *line = NULL;

	ca_command_table = g_hash_table_new (g_str_hash, g_str_equal);

	__ca_add_commands (ca_command_table);

        printf (_("\n\n%s version %s\n%s\n\n"), PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_COPYRIGHT); 
        printf (_("This program comes with ABSOLUTELY NO WARRANTY;\nfor details type 'warranty'.\n"));
        printf (_("This is free software, and you are welcome to redistribute it\nunder certain conditions; type 'distribution' for details.\n\n"));

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
			GSList *arglist = NULL;
                        gchar **argv = NULL;

                        add_history (line);

                        // Parse line
                        aux = g_strsplit (line, "\"", -1 );

			// Detect \" combinations, and discard them as a quote
                        for (i = 0; i < (g_strv_length(aux) - 1); i++) {
                                if (aux[i][strlen(aux[i]) - 1] == '\\') {
                                        oldaux = aux[i];
					aux[i][strlen(aux[i]) - 1] = '\0';
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
				// For each tuple not in quotes, detect spaces
                                gchar **aux2[g_strv_length(aux)];
                                for (i=0; i < g_strv_length(aux); i++) {
					// Only in not-quoted terms (that is: even terms)
                                        if (i % 2 == 0) {
                                                aux2[i] = g_strsplit (aux[i], " ", -1);

						if (*aux2[i]) {

							// Detect "\ " combinations, and discard them as a quote
							for (j = 0; j < (g_strv_length(aux2[i]) - 1); j++) {
								if (aux2[i][j] && aux2[i][j][strlen(aux2[i][j]) - 1] == '\\') {
									oldaux = aux2[i][j];
									aux2[i][j][strlen(aux2[i][j]) - 1] = '\0';
									aux2[i][j] = g_strdup_printf ("%s %s", aux2[i][j], aux2[i][j+1]);
									g_free (oldaux);
									for (k = j+1; k < g_strv_length(aux2[i]); k++) {
										aux2[i][k] = aux2[i][k+1];
									}
								}
								
							}
							
							// If this is a post-quote term, and begins with an empty element
							if (aux2[i][0][0]=='\0' && i > 0) {
								argc++;
								arglist = g_slist_append (arglist, g_strdup (aux[i-1]));
							}
							for (j=0; j < g_strv_length(aux2[i]); j++) {
								if (j < g_strv_length(aux2[i]) - 1 || i == g_strv_length(aux) - 1) {
									if (strlen(aux2[i][j])) {
										argc++;		
										if (j==0 && i > 0) {
											arglist = g_slist_append (arglist, g_strdup_printf ("%s%s",aux[i-1],aux2[i][j]));
										} else {
											arglist = g_slist_append (arglist, g_strdup (aux2[i][j]));
										}
									
									}											
								}
							}
							
						} else {
							if (i > 0) {
								argc++;
								arglist = g_slist_append (arglist, g_strdup (aux[i-1]));
							}
						}
                                        } else {
						if (*aux2[i-1]) {
							oldaux = aux[i];
							aux[i] = g_strdup_printf("%s%s", aux2[i-1][g_strv_length(aux2[i-1]) - 1], aux[i]);
							g_free (oldaux);
						}
					}
                                }
				for (i=0; i < g_strv_length(aux); i=i+2)
					g_strfreev (aux2[i]);
                        }
                        g_strfreev (aux);

                        // fprintf (stderr, "Argc: %d\n", argc);

			argv = g_new (gchar*, argc + 1);
			argv[argc] = NULL;
			for (i=0; i < argc; i++) {
				argv[i] = (gchar *) g_slist_nth_data (arglist,  i);
				// fprintf (stderr, "%d: «%s»\n", i, (gchar *) g_slist_nth_data (arglist,  i));
			}
			g_slist_free (arglist);

                        // If the given command is defined
                        if (argc > 0) {
                                CaCommand *command_entry = ((CaCommand *) g_hash_table_lookup (ca_command_table, argv[0]));

                                if (!command_entry) {
                                        fprintf (stderr, _("Invalid command. Try 'help' for getting a list of recognized commands.\n"));
                                } else {
					// Check for parameter number
					if (argc - 1 < command_entry->mandatory_params || argc - 1 > command_entry->optional_params) {
						fprintf (stderr, _("Incorrect number of parameters.\n"));
						fprintf (stderr, _("Syntax: %s\n"), _(command_entry->syntax));
					} else {
						// Call it
						command_entry->callback (argc, argv);
					}
                                }
                        }                

                        if (argv) {
				for (i=0; i < argc; i++)
					g_free (argv[i]);
			}

                }

                free (line);

        } 
        
}

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
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ca.h"
#include "tls.h"
#include "ca_file.h"
#include "pkey_manage.h"

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

extern gchar * gnomint_current_opened_file;

sqlite3 * ca_db = NULL;


#define CURRENT_GNOMINT_DB_VERSION 10

void __ca_file_concat_string (sqlite3_context *context, int argc, sqlite3_value **argv);
void __ca_file_zeropad (sqlite3_context *context, int argc, sqlite3_value **argv);
void __ca_file_zeropad_route (sqlite3_context *context, int argc, sqlite3_value **argv);
int __ca_file_get_single_row_cb (void *pArg, int argc, char **argv, char **columnNames);
gchar ** __ca_file_get_single_row (const gchar *query, ...);
int __ca_file_get_revoked_certs_add_certificate (void *pArg, int argc, char **argv, char **columnNames);
void __ca_file_mark_expired_and_revoked_certificates_as_already_shown_in_crl (guint64 ca_id, const GList *revoked_certs);
int  __ca_file_password_unprotect_cb (void *pArg, int argc, char **argv, char **columnNames);
int  __ca_file_password_protect_cb (void *pArg, int argc, char **argv, char **columnNames);
int  __ca_file_password_change_cb (void *pArg, int argc, char **argv, char **columnNames);
gchar * __ca_file_get_field_from_id (CaFileElementType type, guint64 db_id, const gchar *field);
gchar * __ca_file_check_and_update_version (void);



void __ca_file_concat_string (sqlite3_context *context, int argc, sqlite3_value **argv)
{
        gchar *result = NULL;
        const guchar *aux1;
        gchar *aux2 = NULL;
        guint i;
        
        for (i=0; i < argc; i++) {
                aux1 = sqlite3_value_text(argv[i]);
                if (! result) {
                        result = g_strdup ((const gchar *) aux1);
                } else {
                        aux2 = g_strdup_printf ("%s%s", result, aux1);
                        g_free (result);
                        result = aux2;
                }
        }


        sqlite3_result_text (context, result, -1, g_free);
}


void __ca_file_zeropad (sqlite3_context *context, int argc, sqlite3_value **argv)
{
        gchar * result = NULL;
        const gchar *value;
        int pad_size;
        gchar *aux = NULL;

        value = (const gchar *) sqlite3_value_text(argv[0]);
        pad_size = sqlite3_value_int (argv[1]);
        if (strlen(value) < pad_size) {
                aux = g_strnfill (pad_size - strlen(value),'0');
                result = g_strconcat (aux, value, NULL);
                g_free (aux);                
        } else {
                result = g_strdup (value);
        }
        
        sqlite3_result_text (context, result, -1, g_free);
}

void __ca_file_zeropad_route (sqlite3_context *context, int argc, sqlite3_value **argv)
{
        gchar * result = NULL;
        const gchar *aux1;
        int pad_size;
        gchar **aux2 = NULL;
        gchar * aux3 = NULL;
        GString * res_str = NULL;

        aux1 = (const gchar *) sqlite3_value_text(argv[0]);
        pad_size = sqlite3_value_int (argv[1]);

        if (!strcmp (aux1, ":")) {
                result = g_strdup (aux1);
        } else {
                int i;

                aux2 = g_strsplit (aux1, ":", -1);                
                res_str = g_string_new ("");

                for (i=0; i<g_strv_length(aux2) - 1; i++) {
                        if (strlen(aux2[i]) && strlen(aux2[i]) < pad_size) {
                                aux3 = g_strnfill (pad_size - strlen(aux2[i]), '0');
                                g_string_append_printf (res_str, "%s%s", aux3, aux2[i]);
                                g_free (aux3);
                        } else {
                                g_string_append_printf (res_str, "%s", aux2[i]);
                        }
                        g_string_append_printf (res_str, ":");
                }
                
                result = g_string_free (res_str, FALSE);
        }


        sqlite3_result_text (context, result, -1, g_free);
        
}



int __ca_file_get_single_row_cb (void *pArg, int argc, char **argv, char **columnNames)
{
	gchar ***result = (gchar ***) pArg;
	int i;

	if (! result)
		return 1;

	(*result) = g_new0 (gchar *, argc+1);
	for (i = 0; i<argc; i++) {
		(*result)[i] = g_strdup (argv[i]);
	}

	return 0;
}

gchar ** __ca_file_get_single_row (const gchar *query, ...)
{
	gchar **result = NULL;
	gchar *sql = NULL;
	gchar * error;
	va_list list;	

	va_start (list, query);
	sql = sqlite3_vmprintf (query, list);
	va_end (list);

	g_assert (ca_db);

	sqlite3_exec (ca_db, sql, __ca_file_get_single_row_cb, &result, &error);
	
	sqlite3_free (sql);

        if (error)
                fprintf (stderr, "%s\n", error);

	return result;
}


gchar * ca_file_create (const gchar *filename)
{
	gchar *sql = NULL;
	gchar *error = NULL;

        // We create a empty file, with correct permissions
        close(open(filename, O_CREAT, 0600));

	if (sqlite3_open (filename, &ca_db))
		return g_strdup_printf(_("Error opening filename '%s'"), filename) ;
        
	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	if (sqlite3_exec (ca_db,
                          "CREATE TABLE ca_properties (id INTEGER PRIMARY KEY, ca_id INTEGER, name TEXT, value TEXT, UNIQUE (name, ca_id));",
                          NULL, NULL, &error)) {
		return error;
	}
	if (sqlite3_exec (ca_db,
                          "CREATE TABLE certificates (id INTEGER PRIMARY KEY, is_ca BOOLEAN, serial TEXT, subject TEXT, "
			  "activation TIMESTAMP, expiration TIMESTAMP, revocation TIMESTAMP, pem TEXT, private_key_in_db BOOLEAN, "
			  "private_key TEXT, dn TEXT, parent_dn TEXT, parent_id INTEGER DEFAULT 0, parent_route TEXT, "
                          "expired_already_in_crl INTEGER, subject_key_id TEXT, issuer_key_id TEXT);",
                          NULL, NULL, &error)) {
		return error;
	}
	if (sqlite3_exec (ca_db,
                          "CREATE TABLE cert_requests (id INTEGER PRIMARY KEY, subject TEXT, pem TEXT, private_key_in_db BOOLEAN, "
			  "private_key TEXT, dn TEXT UNIQUE, parent_ca INTEGER);",
                          NULL, NULL, &error)) {
		return error;
	}

	if (sqlite3_exec (ca_db,
                          "CREATE TABLE ca_policies (id INTEGER PRIMARY KEY, ca_id INTEGER, name TEXT, value TEXT, UNIQUE (ca_id, name));",
                          NULL, NULL, &error)) {
		return error;
	}

	if (sqlite3_exec (ca_db,
                          "CREATE TABLE ca_crl (id INTEGER PRIMARY KEY, ca_id INTEGER, crl_version INTEGER, "
                          "date TIMESTAMP, UNIQUE (ca_id, crl_version));",
                          NULL, NULL, &error)) {
                fprintf (stderr, "%s\n", error);
		return error;
	}

	
	sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, 0, 'ca_db_version', %d);", CURRENT_GNOMINT_DB_VERSION);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	sqlite3_free (sql);

	/* if (creation_data->is_pwd_protected) { */
	/* 	gchar *hashed_pwd = pkey_manage_encrypt_password (creation_data->password); */

	/* 	sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, 0, 'ca_db_is_password_protected', 1);"); */

	/* 	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) */
	/* 		return error; */
	/* 	sqlite3_free (sql); */

	/* 	sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, 0, 'ca_db_hashed_password', '%q');", */
	/* 			       hashed_pwd); */

	/* 	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) */
	/* 		return error; */
	/* 	sqlite3_free (sql); */

	/* 	g_free (hashed_pwd);				        */
	/* } else  { */

        sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, 0, 'ca_db_is_password_protected', '0');");
        
        if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
                return error;
        sqlite3_free (sql);
        
        sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, 0, 'ca_db_hashed_password', '');");
        
        if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
                return error;

        sqlite3_free (sql);
	/* } */

	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

        sqlite3_close (ca_db);

        ca_db = NULL;

        return NULL;
}

gchar * __ca_file_check_and_update_version ()
{
	gchar ** result = NULL;
	gint db_version_in_file = 0;
	gchar * sql = NULL;
	gchar * error;

	result = __ca_file_get_single_row ("SELECT value FROM ca_properties WHERE name = 'ca_db_version';");

	if (result && result[0] && atoi(result[0]) == CURRENT_GNOMINT_DB_VERSION) {
		g_strfreev (result);
		return NULL;
	}

	if (!result || !result[0]) {
		db_version_in_file = 1;
		if (result)
			g_strfreev (result);
	} else {
		db_version_in_file = atoi(result[0]);
		g_strfreev (result);
	}

        if (db_version_in_file > CURRENT_GNOMINT_DB_VERSION) {
                ca_error_dialog (_("The selected database has been created with a newer version of gnoMint than the currently installed."));
                return error;
        }

	switch (db_version_in_file) {
		/* Careful! This switch has not breaks, as all actions must be done for the earliest versions */
	case 1:

		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

		if (sqlite3_exec (ca_db,
                                  "CREATE TABLE ca_policies (id INTEGER PRIMARY KEY, ca_id INTEGER, name TEXT, value TEXT, UNIQUE (ca_id, name));",
                                  NULL, NULL, &error)) {
			return error;
		}
		
		sql = sqlite3_mprintf ("INSERT INTO ca_properties VALUES (NULL, 'ca_db_version', %d);", 2);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);
		
		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error)) {
			return error;
		}

	case 2:
		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)){
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "ALTER TABLE certificates ADD dn TEXT; ALTER TABLE certificates ADD parent_dn TEXT;",
				  NULL, NULL, &error)){
			return error;
		}

		{
			gchar **cert_table;
			gint rows, cols;
			gint i;
			if (sqlite3_get_table (ca_db, 
					       "SELECT id, pem FROM certificates;",
					       &cert_table,
					       &rows,
					       &cols,
					       &error)) {
				return error;
			}
			for (i = 0; i < rows; i++) {
				TlsCert * tls_cert = tls_parse_cert_pem (cert_table[(i*2)+3]);			       				
				sql = sqlite3_mprintf ("UPDATE certificates SET dn='%q', parent_dn='%q' WHERE id=%s;",
						       tls_cert->dn, tls_cert->i_dn, cert_table[(i*2)+2]);

				if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
					return error;
				}

				tls_cert_free (tls_cert);
				tls_cert = NULL;
			}

			sqlite3_free_table (cert_table);

		}

		if (sqlite3_exec (ca_db,
				  "CREATE TABLE cert_requests_new (id INTEGER PRIMARY KEY, subject TEXT, pem TEXT, private_key_in_db BOOLEAN, private_key TEXT, dn TEXT UNIQUE);",
				  NULL, NULL, &error)){
			return error;
		}
		
		if (sqlite3_exec (ca_db,
				  "INSERT OR REPLACE INTO cert_requests_new SELECT *, NULL FROM cert_requests;",
				  NULL, NULL, &error)){
			return error;
		}
		
		if (sqlite3_exec (ca_db,
				  "DROP TABLE cert_requests;",
				  NULL, NULL, &error)){
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "ALTER TABLE cert_requests_new RENAME TO cert_requests;",
				  NULL, NULL, &error)){
			return error;
		}

		{
			gchar **csr_table;
			gint rows, cols;
			gint i;
			if (sqlite3_get_table (ca_db, 
					       "SELECT id, pem FROM cert_requests;",
					       &csr_table,
					       &rows,
					       &cols,
					       &error)) {
				return error;
			}
			for (i = 0; i < rows; i++) {
				TlsCsr * tls_csr = tls_parse_csr_pem (csr_table[(i*2)+3]);			       				
				sql = sqlite3_mprintf ("UPDATE cert_requests SET dn='%q' WHERE id=%s;",
						       tls_csr->dn, csr_table[(i*2)+2]);

				if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
					return error;
				}

				tls_csr_free (tls_csr);
				tls_csr = NULL;
			}

			sqlite3_free_table (csr_table);

		}
		
		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version';", 3);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);
		
		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error)){
			return error;
		}


	case 3:
                
		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)){
			return error;
		}
                
                if (sqlite3_exec (ca_db,
                                  "CREATE TABLE certificates_new (id INTEGER PRIMARY KEY, is_ca BOOLEAN, serial INT, subject TEXT, activation TIMESTAMP, expiration TIMESTAMP, revocation TIMESTAMP, pem TEXT, private_key_in_db BOOLEAN, private_key TEXT, dn TEXT, parent_dn TEXT);",
                                  NULL, NULL, &error)) {
                        return error;
                }

		if (sqlite3_exec (ca_db,
				  "INSERT OR REPLACE INTO certificates_new SELECT id, is_ca, serial, subject, activation, expiration, NULL, pem, private_key_in_db, private_key, dn, parent_dn FROM certificates;",
				  NULL, NULL, &error)){
			return error;
		}
		
		if (sqlite3_exec (ca_db,
				  "DROP TABLE certificates;",
				  NULL, NULL, &error)){
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "ALTER TABLE certificates_new RENAME TO certificates;",
				  NULL, NULL, &error)){
			return error;
		}

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version';", 4);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);
		


                if (sqlite3_exec (ca_db,
                                  "CREATE TABLE ca_crl (id INTEGER PRIMARY KEY, ca_id INTEGER, crl_version INTEGER, "
                                  "date TIMESTAMP, UNIQUE (ca_id, crl_version));",
                                  NULL, NULL, &error)) {
                        return error;
                }

		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error)){
			return error;
		}

	case 4:

		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

		sql = sqlite3_mprintf ("INSERT INTO ca_properties VALUES (NULL, 'ca_db_is_password_protected', 0);");
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
			return error;
		sqlite3_free (sql);

		sql = sqlite3_mprintf ("INSERT INTO ca_properties VALUES (NULL, 'ca_db_hashed_password', '');");
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
			return error;
		sqlite3_free (sql);		

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version';", 5);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);

		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
			return error;

        case 5:
 		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

 		if (sqlite3_exec (ca_db, "ALTER TABLE ca_properties RENAME TO ca_properties_tmp;", NULL, NULL, &error)) {
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "CREATE TABLE ca_properties (id INTEGER PRIMARY KEY, ca_id INTEGER, name TEXT, value TEXT, UNIQUE (ca_id,name));",
				  NULL, NULL, &error)) {
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "INSERT OR REPLACE INTO ca_properties SELECT id, 0, name, value FROM ca_properties_tmp WHERE name LIKE 'ca_db_%';",
				  NULL, NULL, &error)) {
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "INSERT OR REPLACE INTO ca_properties SELECT id, 1, name, value FROM ca_properties_tmp WHERE name LIKE 'ca_root_%';",
				  NULL, NULL, &error)) {
			return error;
		}

		if (sqlite3_exec (ca_db,
				  "DROP TABLE ca_properties_tmp;",
				  NULL, NULL, &error)) {
			return error;
		}


                if (sqlite3_exec (ca_db,
                                  "CREATE TABLE certificates_tmp (id INTEGER PRIMARY KEY, is_ca BOOLEAN, serial TEXT, subject TEXT, "
                                  "activation TIMESTAMP, expiration TIMESTAMP, revocation TIMESTAMP, pem TEXT, private_key_in_db BOOLEAN, "
                                  "private_key TEXT, dn TEXT, parent_dn TEXT, parent_id INTEGER DEFAULT 0, parent_route TEXT);",
                                  NULL, NULL, &error)) {
                        return error;
                }
                
                if (sqlite3_exec (ca_db,
                                  "INSERT OR REPLACE INTO certificates_tmp SELECT *, 0, NULL FROM certificates;",
                                  NULL, NULL, &error)) {
			return error;
		}


		{
			gchar **cert_table;
			gint rows, cols;
			gint i;
			if (sqlite3_get_table (ca_db,
					       "SELECT id, serial FROM certificates;",
					       &cert_table,
					       &rows,
					       &cols,
					       &error)) {
				return error;
			}
			for (i = 1; i <= rows; i++) {
                                gchar *new_serial;
                                UInt160 aux160;
                                guint64 old_serial = atoll(cert_table[(i*cols)+1]);
				gchar *hex_guint64_format_string = g_strdup_printf ("%%0%s", G_GUINT64_FORMAT);
                                gchar *aux = NULL;
				hex_guint64_format_string[strlen(hex_guint64_format_string) - 1] = 'X';
                                aux = g_strdup_printf (hex_guint64_format_string, old_serial);
				g_free (hex_guint64_format_string);
                                uint160_read (&aux160, (guchar *) aux, strlen(aux));
                                new_serial = uint160_strdup_printf(&aux160);

				sql = sqlite3_mprintf ("UPDATE certificates_tmp SET serial='%q' WHERE id=%s;",
                                                       new_serial,
						       cert_table[i*cols]);
                                
                                g_free (aux);

				if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
					return error;
				}
                                
                                sqlite3_free (sql);

			}

			sqlite3_free_table (cert_table);

		}
                {
                        UInt160 aux160;
                        gchar *aux;
                        gsize size = 0;
                        uint160_assign (&aux160, 0);                        
                        uint160_write_escaped (&aux160, NULL, &size);
                        aux = g_new0(gchar, size+1);
                        uint160_write_escaped (&aux160, aux, &size);
                        sql = sqlite3_mprintf ("UPDATE ca_properties SET value='%q' WHERE name='ca_root_last_assigned_serial' and ca_id=1;", 
                                               aux);
                        if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
                                return error;
                        }
                        sqlite3_free (sql);
                        g_free (aux);
                        
                }

                if (sqlite3_exec (ca_db, 
                                  "INSERT INTO ca_properties (id, ca_id, name, value) "
                                  "VALUES (NULL, 1, 'ca_root_must_check_serial_dups', 1);", 
                                  NULL, NULL, &error)) {
                        return error;
                }
                
 
 		if (sqlite3_exec (ca_db,
				  "DROP TABLE certificates;",
				  NULL, NULL, &error)) {
			return error;
		}
               
 		if (sqlite3_exec (ca_db,
				  "ALTER TABLE certificates_tmp RENAME TO certificates;",
				  NULL, NULL, &error)) {
			return error;
		}
               
                
		{
			gchar **cert_table;
			gint rows, cols;
			gint i;
			if (sqlite3_get_table (ca_db, 
					       "SELECT id, dn FROM certificates;",
					       &cert_table,
					       &rows,
					       &cols,
					       &error)) {
				return error;
			}
			for (i = 0; i < rows; i++) {
				sql = sqlite3_mprintf ("UPDATE certificates SET parent_id='%q' WHERE parent_dn='%q';",
						       cert_table[(i*2)+2], cert_table[(i*2)+3]);

				if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
					return error;
				}
                                sqlite3_free (sql);

			}

			sqlite3_free_table (cert_table);

		}


		sql = sqlite3_mprintf ("UPDATE certificates SET parent_route=':' WHERE dn=parent_dn;");
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);

		sql = sqlite3_mprintf ("UPDATE certificates SET parent_route=':1:' WHERE dn<>parent_dn;");
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version' AND ca_id=0;", 6);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);

		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
			return error;

        case 6:

		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

                if (sqlite3_exec (ca_db, "ALTER TABLE certificates ADD COLUMN expired_already_in_crl INTEGER DEFAULT '0';",
                                  NULL, NULL, &error)) {
			return error;
		}

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version' AND ca_id=0;", 7);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);

		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
			return error;

        case 7:
		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

                if (sqlite3_exec (ca_db, "ALTER TABLE cert_requests ADD COLUMN parent_ca INTEGER DEFAULT NULL;",
                                  NULL, NULL, &error)) {
			return error;
		}

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version' AND ca_id=0;", 8);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);

		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
			return error;


        case 8:
		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

                
		if (sqlite3_exec (ca_db, "ALTER TABLE certificates ADD COLUMN subject_key_id TEXT DEFAULT NULL;", NULL, NULL, &error)) {
			return error;
		}

		{
			gchar **cert_table;
			gint rows, cols;
			gint i;
			if (sqlite3_get_table (ca_db, 
					       "SELECT id, pem FROM certificates;",
					       &cert_table,
					       &rows,
					       &cols,
					       &error)) {
				return error;
			}
			for (i = 0; i < rows; i++) {
                                TlsCert *tls_cert = tls_parse_cert_pem (cert_table[(i*2)+3]);
                                if (tls_cert->subject_key_id) {
                                        sql = sqlite3_mprintf ("UPDATE certificates SET subject_key_id='%q' WHERE id='%q';",
                                                               tls_cert->subject_key_id, cert_table[(i*2)+2]);
                                        
                                        if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
                                                return error;
                                        }
                                        sqlite3_free (sql);
                                }
                                tls_cert_free(tls_cert);
                                        
			}

			sqlite3_free_table (cert_table);

		}

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version' AND ca_id=0;", 9);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);


		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
			return error;


        case 9:
		if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error)) {
			return error;
		}

                
		if (sqlite3_exec (ca_db, "ALTER TABLE certificates ADD COLUMN issuer_key_id TEXT DEFAULT NULL;", NULL, NULL, &error)) {
			return error;
		}

		{
			gchar **cert_table;
			gint rows, cols;
			gint i;
			if (sqlite3_get_table (ca_db, 
					       "SELECT id, pem FROM certificates;",
					       &cert_table,
					       &rows,
					       &cols,
					       &error)) {
				return error;
			}
			for (i = 0; i < rows; i++) {
                                TlsCert *tls_cert = tls_parse_cert_pem (cert_table[(i*2)+3]);
                                if (tls_cert->issuer_key_id) {
                                        sql = sqlite3_mprintf ("UPDATE certificates SET issuer_key_id='%q' WHERE id='%q';",
                                                               tls_cert->issuer_key_id, cert_table[(i*2)+2]);
                                        
                                        if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
                                                return error;
                                        }
                                        sqlite3_free (sql);
                                }
                                tls_cert_free(tls_cert);
			}

			sqlite3_free_table (cert_table);

		}

		sql = sqlite3_mprintf ("UPDATE ca_properties SET value=%d WHERE name='ca_db_version' AND ca_id=0;", 10);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
			return error;
		}
		sqlite3_free (sql);


		if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
			return error;


        case 10:
		/* Nothing must be done, as this is the current gnoMint db version */
		break;
	}
	
	return NULL;
}

gboolean ca_file_open (gchar *file_name, gboolean create)
{
        gchar *dirname = NULL;
        gchar *error = NULL;

        dirname = g_path_get_dirname (file_name);

        if (! g_file_test(dirname, G_FILE_TEST_IS_DIR)) {
                if (! create) {
                        g_free (dirname);
                        return FALSE;
                } else {
                        if (g_mkdir_with_parents (dirname, 0700) == -1) {
                                g_free (dirname);
                                return FALSE;
                        }
                }
        }
        g_free (dirname);


	if (! g_file_test(file_name, G_FILE_TEST_EXISTS)) {
                if (! create)
                        return FALSE;
                else
                        ca_file_create (file_name);
        }

	if (sqlite3_open(file_name, &ca_db)) {
		g_printerr ("%s\n\n", sqlite3_errmsg(ca_db));
		return FALSE;
	} else {
		gnomint_current_opened_file = file_name;
                error = __ca_file_check_and_update_version (); 
		if (error) {
                        fprintf (stderr, "Error while updating version: %s\n", error);
                        g_free (error);
                        sqlite3_close (ca_db);
                        ca_db = NULL;
                        return FALSE;
                }
	}

        sqlite3_create_function (ca_db, "concat", -1, SQLITE_ANY, NULL, __ca_file_concat_string, NULL, NULL);
        sqlite3_create_function (ca_db, "zeropad", 2, SQLITE_ANY, NULL, __ca_file_zeropad, NULL, NULL);
        sqlite3_create_function (ca_db, "zeropad_route", 2, SQLITE_ANY, NULL, __ca_file_zeropad_route, NULL, NULL);

        return TRUE;
}

void ca_file_close ()
{
	sqlite3_close (ca_db);
	ca_db = NULL;
	if (gnomint_current_opened_file) {
		g_free (gnomint_current_opened_file);
		gnomint_current_opened_file = NULL;
	}
	       
}

gboolean ca_file_save_as (gchar *new_file_name)
{
	gchar * initial_file = g_strdup(gnomint_current_opened_file);
	GMappedFile *map = NULL;

	ca_file_close ();

	if (! (map = g_mapped_file_new (initial_file, FALSE, NULL)))
		return FALSE;

	if (! g_file_set_contents (new_file_name, 
				   g_mapped_file_get_contents (map),
				   g_mapped_file_get_length (map),
				   NULL)) {
		g_mapped_file_free (map);
		return FALSE;
	}

	g_mapped_file_free (map);

	g_free (initial_file);

	return ca_file_open (new_file_name, FALSE);

}


void ca_file_get_next_serial (UInt160 *serial, guint64 ca_id)
{
	gchar *serialstr = NULL;
	gchar **row = NULL;

	row = __ca_file_get_single_row ("SELECT value FROM ca_properties WHERE name='ca_root_last_assigned_serial' AND ca_id=%"
                                      G_GUINT64_FORMAT";", ca_id);
        uint160_read_escaped (serial, row[0], strlen (row[0]));
	g_strfreev (row);

        row = __ca_file_get_single_row ("SELECT value FROM ca_properties WHERE "
				      "name='ca_root_must_check_serial_dups' AND ca_id=%"G_GUINT64_FORMAT";",
                                      ca_id);
        if (row) {
                if (atoi(row[0])) {
                        while (row) {
                                uint160_inc (serial);
                                g_strfreev (row);
                                serialstr = uint160_strdup_printf (serial);
                                row = __ca_file_get_single_row ("SELECT id FROM certificates WHERE serial='%q' AND parent_id=%"G_GUINT64_FORMAT";", 
                                                              serialstr, ca_id);
                                g_free (serialstr);                                
                        }
                } else {
                        uint160_inc (serial);
                        g_strfreev (row);
                }
        } else {
                uint160_inc (serial);
        }


	return;
}

gchar * ca_file_insert_self_signed_ca (CaCreationData *creation_data, 
                                       gchar *pem_ca_private_key,
                                       gchar *pem_ca_certificate)
{
	gchar *sql = NULL;
	gchar *error = NULL;
        gchar *aux = NULL;
        gsize size;
        UInt160 sn;
        gchar *serialstr;

	gchar **row;
	gint64 rootca_rowid;
	guint64 rootca_id;

        gchar *sql_subject_key_id = NULL;
        gchar *sql_issuer_key_id = NULL;

	TlsCert *tls_cert = tls_parse_cert_pem (pem_ca_certificate);


        uint160_assign (&sn, 1);
        serialstr = uint160_strdup_printf(&sn);

        sql_subject_key_id = (tls_cert->subject_key_id ? 
                              g_strdup_printf ("'%s'",tls_cert->subject_key_id) :
                              g_strdup_printf ("NULL"));
        sql_issuer_key_id = (tls_cert->issuer_key_id ? 
                             g_strdup_printf ("'%s'",tls_cert->issuer_key_id) :
                             g_strdup_printf ("NULL"));

	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	sql = sqlite3_mprintf ("INSERT INTO certificates (id, is_ca, serial, subject, activation, expiration, revocation, pem, private_key_in_db, "
                               "private_key, dn, parent_dn, parent_id, parent_route, subject_key_id, issuer_key_id) "
                               "VALUES (NULL, 1, '%q', '%q', '%ld', '%ld', NULL, '%q', 1, '%q','%q','%q', 0, ':', %s, %s);", 
                               serialstr,
			       creation_data->cn,
			       creation_data->activation,
			       creation_data->expiration,
			       pem_ca_certificate,
			       pem_ca_private_key,
			       tls_cert->dn,
			       tls_cert->i_dn,
                               sql_subject_key_id,
                               sql_issuer_key_id);

        g_free (sql_subject_key_id);
        g_free (sql_issuer_key_id);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	sqlite3_free (sql);
        g_free (serialstr);
        
	rootca_rowid = sqlite3_last_insert_rowid (ca_db);
	row = __ca_file_get_single_row ("SELECT id FROM certificates WHERE ROWID=%"G_GUINT64_FORMAT" ;",
				      rootca_rowid);
	rootca_id = atoll (row[0]);
	g_strfreev (row);

	sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, %"G_GUINT64_FORMAT", 'ca_root_certificate_pem', '%q');", 
			       rootca_id, pem_ca_certificate);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	sqlite3_free (sql);
        
        size = 0;
        uint160_write_escaped (&sn, NULL, &size);
        aux = g_new0 (gchar, size + 1);
        uint160_write_escaped (&sn, aux, &size);
	sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) VALUES (NULL, %"G_GUINT64_FORMAT", 'ca_root_last_assigned_serial', '%q');",
                               rootca_id, aux);
        g_free (aux);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	sqlite3_free (sql);

	ca_file_policy_set (rootca_id, "MONTHS_TO_EXPIRE", 60);
	ca_file_policy_set (rootca_id, "HOURS_BETWEEN_CRL_UPDATES", 24);
	ca_file_policy_set (rootca_id, "DIGITAL_SIGNATURE", 1);
	ca_file_policy_set (rootca_id, "KEY_ENCIPHERMENT", 1);
	ca_file_policy_set (rootca_id, "KEY_AGREEMENT", 1);
	ca_file_policy_set (rootca_id, "DATA_ENCIPHERMENT", 1);
	ca_file_policy_set (rootca_id, "TLS_WEB_SERVER", 1);
	ca_file_policy_set (rootca_id, "TLS_WEB_CLIENT", 1);
	ca_file_policy_set (rootca_id, "EMAIL_PROTECTION", 1);

	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;


	tls_cert_free (tls_cert);
	tls_cert = NULL;
	
	return NULL;


}


gchar * ca_file_insert_cert (CertCreationData *creation_data, 
                             gboolean is_ca,
                             gboolean private_key_in_db, 
			     gchar *private_key_info,                             
			     gchar *pem_certificate)
{
	gchar *sql = NULL;
	gchar *error = NULL;
	gchar **row;        
	UInt160 serial;
        gchar *serialstr;
        gsize size;
	gint64 cert_rowid;
	guint64 cert_id;

	gchar **parent_idstr = NULL;
	guint64 parent_id;
        gchar *parent_route = NULL;

        gchar *sql_subject_key_id = NULL;
        gchar *sql_issuer_key_id = NULL;


	TlsCert *tlscert = tls_parse_cert_pem (pem_certificate);

        sql_subject_key_id = (tlscert->subject_key_id ? 
                              g_strdup_printf ("'%s'",tlscert->subject_key_id) :
                              g_strdup_printf ("NULL"));
        sql_issuer_key_id = (tlscert->issuer_key_id ? 
                             g_strdup_printf ("'%s'",tlscert->issuer_key_id) :
                             g_strdup_printf ("NULL"));

	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	parent_idstr = __ca_file_get_single_row ("SELECT id, parent_route FROM certificates WHERE dn='%q';", tlscert->i_dn);
	if (parent_idstr == NULL) {
                error = _("Cannot find parent CA in database");
                return error;
	} else {
		parent_id = atoll (parent_idstr[0]);
                parent_route = g_strdup_printf("%s%s:",parent_idstr[1], parent_idstr[0]);
		g_strfreev (parent_idstr);
	}

        uint160_assign (&serial, 0);
	ca_file_get_next_serial (&serial, parent_id);

        serialstr = uint160_strdup_printf(&serial);

	if (private_key_info)
		sql = sqlite3_mprintf ("INSERT INTO certificates (id, is_ca, serial, subject, activation, expiration, revocation, "
                                       "pem, private_key_in_db, private_key, dn, parent_dn, parent_id, parent_route, subject_key_id, "
                                       "issuer_key_id) "
                                       "VALUES (NULL, %d, '%q', '%q', '%ld', '%ld', "
				       "NULL, '%q', %d, '%q', '%q', '%q', %"G_GUINT64_FORMAT", '%q', %s, %s);", 
                                       is_ca,
				       serialstr,
				       tlscert->cn,
				       creation_data->activation,
				       creation_data->expiration,
				       pem_certificate,
                                       private_key_in_db,
				       private_key_info,
				       tlscert->dn,
				       tlscert->i_dn,
				       parent_id,
                                       parent_route,
                                       sql_subject_key_id,
                                       sql_issuer_key_id);
	else
		sql = sqlite3_mprintf ("INSERT INTO certificates (id, is_ca, serial, subject, activation, expiration, revocation, "
                                       "pem, private_key_in_db, private_key, dn, parent_dn, parent_id, parent_route, subject_key_id, "
                                       "issuer_key_id) "
                                       "VALUES (NULL, %d, '%q', '%q', '%ld', '%ld', NULL, '%q', 0, NULL, '%q', '%q',"
				       "%"G_GUINT64_FORMAT", '%q', %s, %s);", 
                                       is_ca,
				       serialstr,
				       tlscert->cn,
				       creation_data->activation,
				       creation_data->expiration,
				       pem_certificate,
				       tlscert->dn,
				       tlscert->i_dn,
				       parent_id,
                                       parent_route,
                                       sql_subject_key_id,
                                       sql_issuer_key_id);

        g_free (serialstr);
	tls_cert_free (tlscert);
	tlscert = NULL;

	g_free (parent_route);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
		fprintf (stderr, "%s\n", sql);
		sqlite3_free (sql);
		return error;
	}

	sqlite3_free (sql);

	cert_rowid = sqlite3_last_insert_rowid (ca_db);
	row = __ca_file_get_single_row ("SELECT id FROM certificates WHERE ROWID=%"G_GUINT64_FORMAT" ;",
				      cert_rowid);
	cert_id = atoll (row[0]);
	g_strfreev (row);

        size = 0;
        uint160_write_escaped (&serial, NULL, &size);
        serialstr = g_new0(gchar, size+1);
        uint160_write_escaped (&serial, serialstr, &size);
	sql = sqlite3_mprintf ("UPDATE ca_properties SET value='%q' WHERE name='ca_root_last_assigned_serial' and ca_id=%"G_GUINT64_FORMAT";", 
			       serialstr, parent_id);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
		fprintf (stderr, "%s\n", sql);
		sqlite3_free (sql);
		return error;
	}
        g_free (serialstr);
	sqlite3_free (sql);

	if (is_ca) {
                size = 0;
                uint160_assign (&serial, 0);
                uint160_write_escaped (&serial, NULL, &size);
                serialstr = g_new0(gchar, size+1);
                uint160_write_escaped (&serial, serialstr, &size);                
		sql = sqlite3_mprintf ("INSERT INTO ca_properties (id, ca_id, name, value) "
				       "VALUES (NULL, %"G_GUINT64_FORMAT", 'ca_root_last_assigned_serial', '%q');",
				       cert_id, serialstr);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
			sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
			fprintf (stderr, "%s\n", sql);
			sqlite3_free (sql);
			return error;
		}
		sqlite3_free (sql);
                g_free (serialstr);

		if (! ca_file_policy_set (cert_id, "MONTHS_TO_EXPIRE", 60) || 
		    ! ca_file_policy_set (cert_id, "HOURS_BETWEEN_CRL_UPDATES", 24)||
		    ! ca_file_policy_set (cert_id, "DIGITAL_SIGNATURE", 1)||
		    ! ca_file_policy_set (cert_id, "KEY_ENCIPHERMENT", 1) ||
		    ! ca_file_policy_set (cert_id, "KEY_AGREEMENT", 1) ||
		    ! ca_file_policy_set (cert_id, "DATA_ENCIPHERMENT", 1) ||
		    ! ca_file_policy_set (cert_id, "TLS_WEB_SERVER", 1) ||
		    ! ca_file_policy_set (cert_id, "TLS_WEB_CLIENT", 1) ||
		    ! ca_file_policy_set (cert_id, "EMAIL_PROTECTION", 1)) {
			sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
			sqlite3_free (sql);
			return g_strdup ("Error while establishing policies.");
		}


	}
	

	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}

gchar * ca_file_insert_imported_cert (const CertCreationData *creation_data, 
                                      gboolean is_ca,
                                      const UInt160 serial,
                                      const gchar *pem_certificate)
{
	guint64 cert_id;
	guint64 parent_id;
        gchar *parent_route = NULL;
        gchar *parent_pem = NULL;
	gchar *serialstr = NULL;

        gchar **issuer_res = NULL;
        gchar **orphan_res = NULL;
        gchar *error = NULL;
        gchar *sql_subject_key_id = NULL;
        gchar *sql_issuer_key_id = NULL;
        gchar *sql = NULL;

	TlsCert *tlscert = tls_parse_cert_pem (pem_certificate);

        sql_subject_key_id = (tlscert->subject_key_id ? 
                              g_strdup_printf ("'%s'",tlscert->subject_key_id) :
                              g_strdup_printf ("NULL"));
        sql_issuer_key_id = (tlscert->issuer_key_id ? 
                             g_strdup_printf ("'%s'",tlscert->issuer_key_id) :
                             g_strdup_printf ("NULL"));


	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;
        
        // We first look up if the issuer is already in the database
        // * We first search using issuer_key_id (if the imported certificate has this field)
        if (tlscert->issuer_key_id) {
                issuer_res = __ca_file_get_single_row ("SELECT id, parent_route, pem FROM certificates WHERE is_ca=1 AND subject_key_id='%q';", 
                                                   tlscert->issuer_key_id);
        }

        if ((! issuer_res) && (tlscert->i_dn)) {
                // * If is not found, we seek the issuer through the issuer_dn field
                issuer_res = __ca_file_get_single_row ("SELECT id, parent_route, pem FROM certificates WHERE is_ca=1 AND dn='%q';",
                                                   tlscert->i_dn);
        }
        
        if (issuer_res) {
                parent_id = atoll (issuer_res[0]);
                parent_route = g_strdup_printf("%s%s:",issuer_res[1], issuer_res[0]);
                parent_pem = g_strdup (issuer_res[2]);
                g_strfreev (issuer_res);
        } else {
                // No possible parent certificate was found 
                parent_id = 0; 
                parent_route = g_strdup(":");
                parent_pem = NULL;
        }

        // * Now, if we have found a possible issuer, we verify if the imported certificate has been issued by it
        if (parent_id != 0) {
                if (! tls_cert_check_issuer (pem_certificate, parent_pem)) {
                        // The possible parent is not the issuer.
                        parent_id = 0;
                        g_free (parent_route);
                        parent_route = g_strdup(":");
                }
        }
        g_free (parent_pem);
        parent_pem = NULL;

        // We insert the certificate, with the correct issuer, if this has been found

        serialstr = uint160_strdup_printf(&serial);
        sql = sqlite3_mprintf ("INSERT INTO certificates (id, is_ca, serial, subject, activation, expiration, revocation, "
                               "pem, private_key_in_db, private_key, dn, parent_dn, parent_id, parent_route, subject_key_id, "
                               "issuer_key_id) "
                               "VALUES (NULL, %d, '%q', '%q', '%ld', '%ld', NULL, '%q', 0, NULL, '%q', '%q',"
                               "%"G_GUINT64_FORMAT", '%q', %s, %s);",
                               is_ca,
                               serialstr,
                               tlscert->cn,
                               creation_data->activation,
                               creation_data->expiration,
                               pem_certificate,
                               tlscert->dn,
                               tlscert->i_dn,
                               parent_id,
                               parent_route,
                               sql_subject_key_id,
                               sql_issuer_key_id);
        g_free (serialstr);
        g_free (parent_route);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
		fprintf (stderr, "%s\n", sql);
		sqlite3_free (sql);
		tls_cert_free (tlscert);
                return error;
	}

        sqlite3_free (sql);

        cert_id = sqlite3_last_insert_rowid(ca_db);

        if (is_ca) {
                gint rows, cols;
                gint i;

                // Now we look all "orphan" certificates, for seeing if the just inserted certificate is their issuer
                // so we only look up if their issuer_key_id is the same as the just-inserted-cert subject_key_id, or if
                // their parent_dn is the same as the just-inserted-cert DN.
                sql = sqlite3_mprintf ("SELECT id, pem FROM certificates WHERE "
                                       "parent_route=':' AND parent_id=0 AND (subject_key_id <> issuer_key_id OR dn <> parent_dn) "
                                       "AND (issuer_key_id = %s OR parent_dn = '%q');",
                                       sql_subject_key_id, tlscert->dn);

                if (sqlite3_get_table (ca_db,
                                       sql,
                                       &orphan_res, &rows, &cols, &error)) {
                        sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);
                        sqlite3_free (sql);
                        return error;
                }
                
                sqlite3_free (sql);

                // * So, for each orphan certificate that could have been issued by the just-inserted certificate, 
                for (i=1; i<=rows; i++) {
                        // We verify if the imported certificate has issued it
                        if (tls_cert_check_issuer (orphan_res[(i*2)+1], pem_certificate)) {
                                // * If it has, we update the certificate parent_id, and parent_route
                                //   so it matches with the imported certificate

                                sql = sqlite3_mprintf ("UPDATE certificates SET "
                                                       "parent_dn='%q', "
                                                       "parent_id=%"G_GUINT64_FORMAT", "
                                                       "parent_route='%s%"G_GUINT64_FORMAT":'"
                                                       "WHERE id=%s;",
                                                       tlscert->dn,
                                                       cert_id,
                                                       parent_route,cert_id,
                                                       orphan_res[i*2]);
                                if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
                                        sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
                                        fprintf (stderr, "%s\n", sql);
                                        sqlite3_free (sql);
                                        tls_cert_free (tlscert);
                                        return error;
                                }
                        }
                        
                }
        }

        tls_cert_free (tlscert);

	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}

gchar * ca_file_insert_csr (CaCreationData *creation_data, 
			    gchar *pem_csr_private_key,
			    gchar *pem_csr)
{
	gchar *sql = NULL;
	gchar *error = NULL;

	TlsCsr * tlscsr = tls_parse_csr_pem (pem_csr);

	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	if (pem_csr_private_key)
		sql = sqlite3_mprintf ("INSERT INTO cert_requests (id, subject, pem, private_key_in_db, private_key, dn, parent_ca) "
                                       "VALUES (NULL, '%q', '%q', 1, '%q','%q', %s);", 
				       creation_data->cn,
				       pem_csr,
				       pem_csr_private_key,
				       tlscsr->dn,
                                       (creation_data->parent_ca_id_str ? creation_data->parent_ca_id_str : "NULL")
                        );
	else
		sql = sqlite3_mprintf ("INSERT INTO cert_requests (id, subject, pem, private_key_in_db, private_key, dn, parent_ca) "
                                       "VALUES (NULL, '%q', '%q', 0, NULL, '%q', %s);", 
				       creation_data->cn,
				       pem_csr,
				       tlscsr->dn,
                                       (creation_data->parent_ca_id_str ? creation_data->parent_ca_id_str : "NULL")
                        );

	tls_csr_free (tlscsr);
	tlscsr = NULL;

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
                fprintf (stderr, "%s: %s\n", sql, error);
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
		
		return error;
	}
	sqlite3_free (sql);
	
	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}


gchar * ca_file_remove_csr (gint id)
{
	gchar *sql = NULL;
	gchar *error = NULL;

	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	sql = sqlite3_mprintf ("DELETE FROM cert_requests WHERE id = %d ;", 
			       id);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	sqlite3_free (sql);
	
	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}

gchar * ca_file_revoke_crt (gint id)
{
	gchar *sql = NULL;
	gchar *error = NULL;

	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

        fprintf (stderr, "%ld\n", time(NULL));

	sql = sqlite3_mprintf ("UPDATE certificates SET revocation=%ld WHERE id = %d ;", 
			       time(NULL),
                               id);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	sqlite3_free (sql);
	
	if (sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}


gchar * ca_file_import_privkey (const gchar *privkey_pem)
{
        gchar *pkey_key_id = NULL;
        /* gchar *sql = NULL; */
        gchar *error = NULL;

        // We calculate key-id from the private key
        pkey_key_id = tls_get_private_key_id(privkey_pem);

        {
                gint rows, cols;
                gint i;
                gchar **table;
                
                // I get all certificates in dateabase that have not their private key in
                // the database, and it is not locatable.
                if (sqlite3_get_table (ca_db,
                                       "SELECT id, pem FROM certificates WHERE "
                                       "private_key_in_db=FALSE;",
                                       &table, &rows, &cols, &error)) {
                        return error;
                }
                
                for (i=1; i<=rows; i++) {
                        gchar *public_key_id = NULL;

                        // Foreach of them, we get their key-id from the public-key
                        public_key_id = tls_get_public_key_id (table[(i*cols) + 1]);

                        // If both key-ids match, we cipher (it we must) the private key,
                        // and insert it into the database.
                        if (! strcmp (pkey_key_id, public_key_id)) {
                                

                                // sql = "UPDATE certificates SET private_key_in_db=TRUE WHERE";
                        }

                        g_free (public_key_id);
                }

        }

        
        return NULL;

}


int __ca_file_get_revoked_certs_add_certificate (void *pArg, int argc, char **argv, char **columnNames)
{
        GList **p_list = (GList **) pArg;
        GList *list = (* p_list);

        // Pem of the revoked certificate
        list = g_list_prepend (list, g_strdup(argv[0]));

        // Revocation time
        list = g_list_prepend (list, g_strdup(argv[1]));

        *p_list =  list;

        return 0;
}

GList * ca_file_get_revoked_certs (guint64 ca_id, gchar **error)
{
        GList * list = NULL;
        gchar * error_str = NULL;
        gchar * sql = NULL;

        sql = sqlite3_mprintf ("SELECT pem,revocation FROM certificates "
                               "WHERE parent_id=%"G_GUINT64_FORMAT" AND revocation IS NOT NULL "
                               "AND (expired_already_in_crl=0 OR expiration > strftime('%%s','now')) ORDER BY id",
                               ca_id);

        sqlite3_exec (ca_db, sql, __ca_file_get_revoked_certs_add_certificate, &list, &error_str);
        sqlite3_free (sql);

        if (error_str) {
                fprintf (stderr, "%s\n", error_str);
                (*error) = g_strdup (error_str);
                return NULL;
        }

        list = g_list_reverse (list);

        (*error) = NULL;
        return list;

}



void __ca_file_mark_expired_and_revoked_certificates_as_already_shown_in_crl (guint64 ca_id, const GList *revoked_certs) 
{
        gchar *sql = NULL;
        GList *cursor = NULL;
        gchar * error_str = NULL;
        guchar *certificate_pem;
        time_t revocation;
       
        cursor = g_list_first ((GList *) revoked_certs);

        while (cursor) {
                certificate_pem = cursor->data;
                cursor = g_list_next (cursor);
                
                revocation = atol (cursor->data);
                cursor = g_list_next (cursor);
                
                sql = sqlite3_mprintf ("UPDATE certificates SET expired_already_in_crl=1 "
                                       "WHERE parent_id=%"G_GUINT64_FORMAT" AND revocation IS NOT NULL AND pem='%q' AND "
                                       "expired_already_in_crl=0 AND expiration < strftime('%%s','now'));",
                                       ca_id, certificate_pem);


                sqlite3_exec (ca_db, sql,
                              __ca_file_get_revoked_certs_add_certificate, NULL, &error_str);

                sqlite3_free (sql);
        }
}

gint ca_file_begin_new_crl_transaction (guint64 ca_id, time_t timestamp)
{
        gchar * sql;
        gchar **last_crl;
        gint next_crl_version;
        gchar *error;

        last_crl = __ca_file_get_single_row ("SELECT crl_version FROM ca_crl WHERE ca_id=%"G_GUINT64_FORMAT, ca_id);
        if (! last_crl)
                next_crl_version = 1;
        else {
                next_crl_version = atoi (last_crl[0]) + 1;
                g_strfreev (last_crl);
        }
        
	if (sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return 0;

        sql = sqlite3_mprintf ("INSERT INTO ca_crl (id, ca_id, crl_version, date) VALUES (NULL, %"G_GUINT64_FORMAT", %u, %u);",
                               ca_id, next_crl_version, timestamp);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)){
                sqlite3_free (sql);
                fprintf (stderr, "%s\n", error);
		return 0;        
        }

        sqlite3_free (sql);
        
        return next_crl_version;

}

void ca_file_commit_new_crl_transaction (guint64 ca_id, const GList *revoked_certs)
{
        gchar *error;

        __ca_file_mark_expired_and_revoked_certificates_as_already_shown_in_crl (ca_id, revoked_certs);
        sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error);

}

void ca_file_rollback_new_crl_transaction ()
{
        gchar *error;

	sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);
}

gboolean ca_file_is_password_protected()
{
	gchar **result; 
	gboolean res;

	if (! ca_db)
		return FALSE;
	
	result = __ca_file_get_single_row ("SELECT value FROM ca_properties WHERE name='ca_db_is_password_protected';");
	res = ((result != NULL) && (strcmp(result[0], "0")));
	
	if (result)
		g_strfreev (result);
	
	return res;
}

gboolean ca_file_check_password (const gchar *password)
{
	gchar **result;
	gboolean res;

	if (! ca_file_is_password_protected())
		return FALSE;

	result = __ca_file_get_single_row ("SELECT value FROM ca_properties WHERE name='ca_db_hashed_password';");
	if (! result)
		return FALSE;	

	res = pkey_manage_check_password (password, result[0]);

	g_strfreev (result);

	return res;
}

typedef	struct {
	const gchar *old_password;
	const gchar *new_password;
	const gchar *table;
} CaFilePwdChange;

int  __ca_file_password_unprotect_cb (void *pArg, int argc, char **argv, char **columnNames)
{
	CaFilePwdChange * pwd_change = (CaFilePwdChange *) pArg;
	const gchar *table = pwd_change->table;
	const gchar *pwd = pwd_change->old_password;
	PkeyManageData pkey;
	gchar *error;
	gchar *sql;
	gchar *new_pkey;
	
	
	pkey.pkey_data = argv[2];
	pkey.is_in_db = TRUE;
	pkey.is_ciphered_with_db_pwd = TRUE;
	pkey.external_file = NULL;

	if (atoi(argv[1]) == 0)
		return 0;

	new_pkey = pkey_manage_uncrypt_w_pwd (&pkey, argv[3], pwd);

        sql = sqlite3_mprintf ("UPDATE %q SET private_key='%q' WHERE id='%q';",
                               table, new_pkey, argv[0]);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		fprintf (stderr, "Error while executing: %s. %s", sql, error);
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		sqlite3_free (sql);
		g_free (new_pkey);
		return 1;
	}

	sqlite3_free(sql);

	g_free (new_pkey);

	return 0;
}

gboolean ca_file_password_unprotect(const gchar *old_password)
{
        gchar *error;
	CaFilePwdChange pwd_change;

	if (! ca_file_is_password_protected ())
		return FALSE;

	if (! ca_file_check_password (old_password))
		return FALSE;

	sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error);	
	
	pwd_change.old_password = old_password;

	pwd_change.table = "certificates";
	if (sqlite3_exec (ca_db, "SELECT id, private_key_in_db, private_key, dn FROM certificates",
			  __ca_file_password_unprotect_cb, &pwd_change, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	pwd_change.table = "cert_requests";
	if (sqlite3_exec (ca_db, "SELECT id, private_key_in_db, private_key, dn FROM cert_requests",
			  __ca_file_password_unprotect_cb, &pwd_change, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	if (sqlite3_exec (ca_db, "UPDATE ca_properties SET value='0' WHERE name='ca_db_is_password_protected';", 
			  NULL, NULL, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}	

	sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error);	


	return TRUE;
}

int  __ca_file_password_protect_cb (void *pArg, int argc, char **argv, char **columnNames)
{
	CaFilePwdChange * pwd_change = (CaFilePwdChange *) pArg;
	const gchar *table = pwd_change->table;
	const gchar *pwd = pwd_change->new_password;
	gchar *error;
	gchar *sql;
	gchar *new_pkey;
	
	if (atoi(argv[1]) == 0)
		return 0;

	new_pkey = pkey_manage_crypt_w_pwd (argv[2], argv[3], pwd);

        sql = sqlite3_mprintf ("UPDATE %q SET private_key='%q' WHERE id='%q';",
                               table, new_pkey, argv[0]);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		fprintf (stderr, "Error while executing: %s. %s", sql, error);
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		sqlite3_free (sql);
		g_free (new_pkey);
		return 1;
	}

	sqlite3_free(sql);

	g_free (new_pkey);

	return 0;
}

gboolean ca_file_password_protect(const gchar *new_password)
{
        gchar *error;
	gchar *sql;
	gchar *hashed_pwd;
	CaFilePwdChange pwd_change;

	if (ca_file_is_password_protected ())
		return FALSE;

	sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error);	
	
	pwd_change.new_password = new_password;

	if (sqlite3_exec (ca_db, "UPDATE ca_properties SET value='1' WHERE name='ca_db_is_password_protected';", 
			  NULL, NULL, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}	

	hashed_pwd = pkey_manage_encrypt_password (new_password);
	sql = sqlite3_mprintf ("UPDATE ca_properties SET value='%q' WHERE name='ca_db_hashed_password';",
			       hashed_pwd);
	g_free (hashed_pwd);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		sqlite3_free (sql);
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	pwd_change.table = "certificates";
	if (sqlite3_exec (ca_db, "SELECT id, private_key_in_db, private_key, dn FROM certificates",
			  __ca_file_password_protect_cb, &pwd_change, &error)){
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	pwd_change.table = "cert_requests";
	if (sqlite3_exec (ca_db, "SELECT id, private_key_in_db, private_key, dn FROM cert_requests",
			  __ca_file_password_protect_cb, &pwd_change, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	sqlite3_free (sql);

	sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error);	


	return TRUE;
}

int  __ca_file_password_change_cb (void *pArg, int argc, char **argv, char **columnNames)
{
	CaFilePwdChange * pwd_change = (CaFilePwdChange *) pArg;
	const gchar *table = pwd_change->table;
	const gchar *old_pwd = pwd_change->old_password;
	const gchar *new_pwd = pwd_change->new_password;
	gchar *error;
	gchar *sql;
	gchar *clear_pkey;
	gchar *new_pkey;

	PkeyManageData pkey;
	
	pkey.pkey_data = argv[2];
	pkey.is_in_db = TRUE;
	pkey.is_ciphered_with_db_pwd = TRUE;
	pkey.external_file = NULL;

	
	if (atoi(argv[1]) == 0)
		return 0;

	clear_pkey = pkey_manage_uncrypt_w_pwd (&pkey, argv[3], old_pwd);

	new_pkey = pkey_manage_crypt_w_pwd (clear_pkey, argv[3], new_pwd);

	g_free (clear_pkey);

        sql = sqlite3_mprintf ("UPDATE %q SET private_key='%q' WHERE id='%q';",
                               table, new_pkey, argv[0]);

	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		fprintf (stderr, "Error while executing: %s. %s", sql, error);
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		sqlite3_free (sql);
		g_free (new_pkey);
		return 1;
	}

	sqlite3_free(sql);

	g_free (new_pkey);

	return 0;
}

gboolean ca_file_password_change(const gchar *old_password, const gchar *new_password)
{
        gchar *error;
	gchar *sql;
	gchar *hashed_pwd;
	CaFilePwdChange pwd_change;

	if (!ca_file_is_password_protected ())
		return FALSE;

	if (! ca_file_check_password (old_password))
		return FALSE;

	sqlite3_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error);	
	
	pwd_change.new_password = new_password;
	pwd_change.old_password = old_password;

	pwd_change.table = "certificates";
	if (sqlite3_exec (ca_db, "SELECT id, private_key_in_db, private_key, dn FROM certificates",
			  __ca_file_password_change_cb, &pwd_change, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	pwd_change.table = "cert_requests";
	if (sqlite3_exec (ca_db, "SELECT id, private_key_in_db, private_key, dn FROM cert_requests",
			  __ca_file_password_change_cb, &pwd_change, &error)) {
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	hashed_pwd = pkey_manage_encrypt_password (new_password);
	sql = sqlite3_mprintf ("UPDATE ca_properties SET value='%q' WHERE name='ca_db_hashed_password';",
			       hashed_pwd);
	if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
		sqlite3_free (sql);
		g_free (hashed_pwd);
		sqlite3_exec (ca_db, "ROLLBACK;", NULL, NULL, &error);	
		return FALSE;
	}

	sqlite3_free (sql);
	g_free (hashed_pwd);

	sqlite3_exec (ca_db, "COMMIT;", NULL, NULL, &error);	


	return TRUE;
}


gboolean ca_file_foreach_ca (CaFileCallbackFunc func, gpointer userdata)
{
	gchar *error_str;
        gchar **result;
        guint64 max_id;
        gchar* aux;
        guint num_chars = 1;
        gchar *sql;

        result = __ca_file_get_single_row ("SELECT MAX(id) FROM certificates WHERE is_ca=1 AND revocation IS NULL");

        if (result && result[0]) {
	
		max_id = atoll(result[0]);
		g_strfreev (result);
        
		aux = g_strdup_printf ("%"G_GUINT64_FORMAT, max_id);
		num_chars = strlen (aux);
		g_free (aux);
	} 

        sql = sqlite3_mprintf ("SELECT id, serial, subject, dn, parent_dn, pem "
                               "FROM certificates WHERE is_ca=1 AND revocation IS NULL "
                               "ORDER BY concat(zeropad_route(parent_route, %u), zeropad(id, %u))",
                               num_chars, num_chars);

        sqlite3_exec (ca_db, sql,
                      func, userdata, &error_str);

        sqlite3_free (sql);

	return  (! error_str);
}


gboolean ca_file_foreach_crt (CaFileCallbackFunc func, gboolean view_revoked, gpointer userdata)
{
	gchar *error_str;
        gchar **result;
        guint64 max_id;
        gchar* aux;
        guint num_chars = 1;
        gchar *sql;

        result = __ca_file_get_single_row ("SELECT MAX(id) FROM certificates");

        if (result && result[0]) {
		max_id = atoll(result[0]);
		g_strfreev (result);
        
		aux = g_strdup_printf ("%"G_GUINT64_FORMAT, max_id);
		num_chars = strlen (aux);
		g_free (aux);
	}

	if (view_revoked) {
                sql = sqlite3_mprintf ("SELECT id, is_ca, serial, subject, activation, expiration, revocation, private_key_in_db, pem,"
                                       " dn, parent_dn, parent_route "
				       "FROM certificates ORDER BY concat(zeropad_route(parent_route, %u), zeropad(id, %u)) ",
                                       num_chars, num_chars);
	} else {
                sql = sqlite3_mprintf ("SELECT id, is_ca, serial, subject, activation, expiration, revocation, private_key_in_db, "
                                       "pem, dn, parent_dn, parent_route "
				       "FROM certificates WHERE revocation IS NULL "
                                       "ORDER BY concat(zeropad_route(parent_route, %u), zeropad(id, %u))",
                                       num_chars, num_chars);
	}

        sqlite3_exec (ca_db, sql,
                      func, userdata, &error_str);

        sqlite3_free (sql);

	return  (! error_str);
}

gboolean ca_file_foreach_csr (CaFileCallbackFunc func, gpointer userdata)
{
	gchar *error_str;

	sqlite3_exec 
		(ca_db, 
		 "SELECT id, subject, private_key_in_db, pem, parent_ca FROM cert_requests ORDER BY id",
		 func, userdata, &error_str);

	return  (! error_str);
	
}

gboolean ca_file_foreach_policy (CaFileCallbackFunc func, guint64 ca_id, gpointer userdata)
{
	gchar *error_str;
	gchar * query = g_strdup_printf ("SELECT ca_id, name, value FROM ca_policies WHERE ca_id=%"
					 G_GUINT64_FORMAT ";", ca_id);

	sqlite3_exec (ca_db, query, func, userdata, &error_str);

	sqlite3_free (query);

	return  (! error_str);
	
}


gchar * __ca_file_get_field_from_id (CaFileElementType type, guint64 db_id, const gchar *field)
{
	gchar ** aux;
	gchar * res;

	if (type == CA_FILE_ELEMENT_TYPE_CERT) {
		aux = __ca_file_get_single_row ("SELECT %s FROM certificates WHERE id=%" G_GUINT64_FORMAT ";", field, db_id);
	} else {
		aux = __ca_file_get_single_row ("SELECT %s FROM cert_requests WHERE id=%" G_GUINT64_FORMAT ";", field, db_id);
	}
	
	if (! aux)
		return NULL;

	if (! aux[0]) {
		g_strfreev (aux);
		return NULL;
	}

	res = g_strdup (aux[0]);

	g_strfreev (aux);
	
	return res;

}

gchar * ca_file_get_dn_from_id (CaFileElementType type, guint64 db_id)
{
	return __ca_file_get_field_from_id (type, db_id, "dn");
}

gchar * ca_file_get_public_pem_from_id (CaFileElementType type, guint64 db_id)
{
	return __ca_file_get_field_from_id (type, db_id, "pem");
}

gboolean ca_file_get_pkey_in_db_from_id (CaFileElementType type, guint64 db_id)
{
	gboolean res;
	gchar *aux;

	aux = __ca_file_get_field_from_id (type, db_id, "private_key_in_db");
	res = atoi(aux);
	g_free (aux);
	return res;
}

gchar * ca_file_get_pkey_field_from_id (CaFileElementType type, guint64 db_id)
{
	return __ca_file_get_field_from_id (type, db_id, "private_key");
}

gboolean ca_file_set_pkey_field_for_id (CaFileElementType type, const gchar *new_value, guint64 db_id)
{
	gchar *sql;
	gchar *error;

	if (type == CA_FILE_ELEMENT_TYPE_CERT)  {
		sql = sqlite3_mprintf ("UPDATE certificates SET private_key='%q' WHERE id=%" G_GUINT64_FORMAT,
				       new_value, db_id);
	} else {
		sql = sqlite3_mprintf ("UPDATE cert_requests SET private_key='%q' WHERE id=%" G_GUINT64_FORMAT,
				       new_value, db_id);
	}
       

	sqlite3_exec (ca_db, sql, NULL, NULL, &error);	
	g_free (sql);

	return (! error);
}


gboolean ca_file_mark_pkey_as_extracted_for_id (CaFileElementType type, const gchar *filename, guint64 db_id)
{
	gchar *sql;
	gchar *error;

	if (type == CA_FILE_ELEMENT_TYPE_CERT)  {
		sql = sqlite3_mprintf ("UPDATE certificates SET private_key='%q', private_key_in_db=0 WHERE id=%" G_GUINT64_FORMAT,
				       filename, db_id);
	} else {
		sql = sqlite3_mprintf ("UPDATE cert_requests SET private_key='%q', private_key_in_db=0 WHERE id=%" G_GUINT64_FORMAT,
				       filename, db_id);
	}
       
	sqlite3_exec (ca_db, sql, NULL, NULL, &error);	
	g_free (sql);

	if (error)
		fprintf (stderr, "%s", error);

	return (! error);
}

guint ca_file_policy_get (guint64 ca_id, gchar *property_name)
{
	gchar **row = __ca_file_get_single_row ("SELECT value FROM ca_policies WHERE name='%s' AND ca_id=%"G_GUINT64_FORMAT" ;", 
					      property_name, ca_id);

	guint res;

	if (!row)
		return 0;

	res = atoi(row[0]);

	g_strfreev (row);

	return res;
}


gboolean ca_file_policy_set (guint64 ca_id, gchar *property_name, guint value)
{
	gchar **aux;
	gchar *error = NULL;
	gchar *sql = NULL;

	aux = __ca_file_get_single_row ("SELECT id, ca_id, name, value FROM ca_policies WHERE name='%s' AND ca_id=%"G_GUINT64_FORMAT" ;", 
				      property_name, ca_id);

	if (! aux) {
		sql = sqlite3_mprintf ("INSERT INTO ca_policies(ca_id, name, value) VALUES (%"G_GUINT64_FORMAT", '%q', %d);",
				       ca_id, property_name, value);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
			fprintf (stderr, "%s\n", error);
			sqlite3_free (sql);
			return FALSE;
		}
	} else {
		g_strfreev (aux);
		sql = sqlite3_mprintf ("UPDATE ca_policies SET value=%d WHERE ca_id=%"G_GUINT64_FORMAT" AND name='%s';",
				       value, ca_id, property_name);
		if (sqlite3_exec (ca_db, sql, NULL, NULL, &error)) {
			fprintf (stderr, "%s\n", error);
			sqlite3_free (sql);
			return FALSE;
		}
	}

        sqlite3_free (sql);

	return TRUE;
		
}


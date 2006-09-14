//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006 David Marín Carreño <davefx@gmail.com>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or   
//  (at your option) any later version.
//7
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
#include <sqlite.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "tls.h"
#include "ca_file.h"

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

extern gchar * gnomint_current_opened_file;
extern gchar * gnomint_temp_created_file;

sqlite * ca_db = NULL;
gchar * error_msg = NULL;


gchar * ca_file_create (CaCreationData *creation_data, 
				 gchar *pem_ca_private_key,
				 gchar *pem_ca_certificate)
{
	gchar *sql = NULL;
	gchar *error = NULL;

	gchar *filename = NULL;

	filename = strdup (tmpnam(NULL));

	if (!(ca_db = sqlite_open(filename, 1, NULL)))
		return g_strdup_printf(_("Error opening filename '%s'"), filename) ;

	if (gnomint_temp_created_file)
		ca_file_delete_tmp_file();
	gnomint_temp_created_file = filename;

	if (sqlite_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	if (sqlite_exec (ca_db,
			   "CREATE TABLE ca_properties (id INTEGER PRIMARY KEY, name TEXT UNIQUE, value TEXT);",
			   NULL, NULL, &error)) {
		return error;
	}
	if (sqlite_exec (ca_db,
			   "CREATE TABLE certificates (id INTEGER PRIMARY KEY, is_ca BOOLEAN, serial INT, subject TEXT, activation TIMESTAMP, expiration TIMESTAMP, is_revoked BOOLEAN, pem TEXT, private_key_in_db BOOLEAN, private_key TEXT);",
			   NULL, NULL, &error)) {
		return error;
	}
	if (sqlite_exec (ca_db,
			   "CREATE TABLE cert_requests (id INTEGER PRIMARY KEY, subject TEXT, pem TEXT, private_key_in_db BOOLEAN, private_key TEXT);",
			   NULL, NULL, &error)) {
		return error;
	}
	
	sql = g_strdup_printf ("INSERT INTO ca_properties VALUES (NULL, 'ca_root_certificate_pem', '%s');", pem_ca_certificate);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	g_free (sql);

	sql = g_strdup_printf ("INSERT INTO certificates VALUES (NULL, 1, 1, '%s', '%ld', '%ld', 0, '%s', 1, '%s');", 
			       creation_data->cn,
			       creation_data->activation,
			       creation_data->expiration,
			       pem_ca_certificate,
			       pem_ca_private_key);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	g_free (sql);


	sql = g_strdup_printf ("INSERT INTO ca_properties VALUES (NULL, 'ca_root_last_assigned_serial', 1);");
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	g_free (sql);

	if (sqlite_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	sqlite_close (ca_db);
	ca_db = NULL;

	return NULL;

}

gboolean ca_file_open (gchar *file_name)
{
	if (! (ca_db = sqlite_open(file_name, 1, &error_msg))) {
		g_printerr ("%s\n\n", error_msg);
		return FALSE;
	} else {
		gnomint_current_opened_file = file_name;
		return TRUE;
	}
}

void ca_file_close ()
{
	sqlite_close (ca_db);
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

	return ca_file_open (new_file_name);

}

gboolean ca_file_rename_tmp_file (gchar *new_file_name)
{
	gint result=0;

	if (! gnomint_temp_created_file) 
		return FALSE;
	
	result = g_rename ((const gchar *) gnomint_temp_created_file, (const gchar *) new_file_name);
	
	if (! result) {
		g_free (gnomint_temp_created_file);
		gnomint_temp_created_file = NULL;
		gnomint_current_opened_file = new_file_name;
		
		return TRUE;
	}

	return FALSE;
}


gboolean ca_file_delete_tmp_file ()
{
	gint result=0;

	if (! gnomint_temp_created_file) 
		return FALSE;
	
	result = g_remove ((const gchar *) gnomint_temp_created_file);

	g_free (gnomint_temp_created_file);
	gnomint_temp_created_file = NULL;

	return (! result);
}

int __ca_file_get_single_row_cb (void *pArg, int argc, char **argv, char **columnNames)
{
	gchar ***result = (gchar ***) pArg;
	int i;

	(*result) = g_new0 (gchar *, argc+1);
	for (i = 0; i<argc; i++) {
		(*result)[i] = g_strdup (argv[i]);
	}

	return 0;
}

gchar ** ca_file_get_single_row (const gchar *query, ...)
{
	gchar ***result = g_new0 (gchar **, 1);
	gchar *sql = NULL;
	gchar * error;
	va_list list;	

	va_start (list, query);
	g_vasprintf (&sql, query, list);
	va_end (list);

	sqlite_exec (ca_db, sql, __ca_file_get_single_row_cb, result, &error);
	
	g_free (sql);

	return (*result);
}

gchar * ca_file_insert_cert (CertCreationData *creation_data, 
			     gchar *pem_private_key,
			     gchar *pem_certificate)
{
	gchar *sql = NULL;
	gchar *error = NULL;
	gchar **serialstr = NULL;
	guint64 serial;

	TlsCert *tlscert = tls_parse_cert_pem (pem_certificate);

	if (sqlite_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	serialstr = ca_file_get_single_row ("SELECT value FROM ca_properties WHERE name='ca_root_last_assigned_serial';");
	serial = atoll (serialstr[0]) + 1;
	g_strfreev (serialstr);

	sql = g_strdup_printf ("INSERT INTO certificates VALUES (NULL, 0, %lld, '%s', '%ld', '%ld', 0, '%s', 1, '%s');", 
			       serial,
			       tlscert->cn,
			       creation_data->activation,
			       creation_data->expiration,
			       pem_certificate,
			       pem_private_key);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		sqlite_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
		return error;
	g_free (sql);
	
	sql = g_strdup_printf ("UPDATE ca_properties SET value='%lld' WHERE name='ca_root_last_assigned_serial';", 
			       serial);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		sqlite_exec (ca_db, "ROLLBACK;", NULL, NULL, NULL);
		return error;
	g_free (sql);
	

	if (sqlite_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}

gchar * ca_file_insert_csr (CaCreationData *creation_data, 
			    gchar *pem_csr_private_key,
			    gchar *pem_csr)
{
	gchar *sql = NULL;
	gchar *error = NULL;

	if (sqlite_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	sql = g_strdup_printf ("INSERT INTO cert_requests VALUES (NULL, '%s', '%s', 1, '%s');", 
			       creation_data->cn,
			       pem_csr,
			       pem_csr_private_key);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	g_free (sql);
	
	if (sqlite_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}


gchar * ca_file_remove_csr (gint id)
{
	gchar *sql = NULL;
	gchar *error = NULL;

	if (sqlite_exec (ca_db, "BEGIN TRANSACTION;", NULL, NULL, &error))
		return error;

	sql = g_strdup_printf ("DELETE FROM cert_requests WHERE id = %d ;", 
			       id);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	g_free (sql);
	
	if (sqlite_exec (ca_db, "COMMIT;", NULL, NULL, &error))
		return error;

	return NULL;

}


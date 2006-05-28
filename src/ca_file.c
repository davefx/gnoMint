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

#include <sqlite.h>
#include <stdio.h>
#include <string.h>

#include "ca_file.h"

#include <libintl.h>
#define _(x) gettext(x)
#define N_(x) (x) gettext_noop(x)

extern gchar * gnomint_current_opened_file;
extern gchar * gnomint_temp_created_file;

sqlite * ca_db = NULL;

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

	if (sqlite_exec (ca_db,
			   "CREATE TABLE ca_properties (id INTEGER PRIMARY KEY, name TEXT UNIQUE, value TEXT);",
			   NULL, NULL, &error)) {
		return error;
	}
	if (sqlite_exec (ca_db,
			   "CREATE TABLE certificates (id INTEGER PRIMARY KEY, serial INT UNIQUE, subject TEXT, emission TIMESTAMP, expiration TIMESTAMP, is_revoked BOOLEAN, pem TEXT);",
			   NULL, NULL, &error)) {
		return error;
	}
	
	if (sqlite_exec (ca_db, "INSERT INTO ca_properties VALUES (NULL, 'ca_private_key_is_in_db', 'TRUE');", NULL, NULL, &error)) {
		return error;
	}

	if (sqlite_exec (ca_db, "INSERT INTO ca_properties VALUES (NULL, 'ca_private_key_extern_location', NULL);", NULL, NULL, &error))
		return error;

	sql = g_strdup_printf ("INSERT INTO ca_properties VALUES (NULL, 'ca_private_key', '%s');", pem_ca_private_key);
	if (sqlite_exec (ca_db, sql, NULL, NULL, &error))
		return error;
	g_free (sql);

	sql = g_strdup_printf ("INSERT INTO ca_properties VALUES (NULL, 'ca_certificate', '%s');", pem_ca_certificate);
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
	if (! (ca_db = sqlite_open(file_name, 1, NULL)))
		return FALSE;
	else {
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



//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006 David Marín Carreño <davefx@gmail.com>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or   
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

#include <sqlite.h>
#include "ca_file.h"

sqlite * ca_db = NULL;

gboolean ca_file_create_and_open (CaCreationData *creation_data, 
				  gchar *pem_ca_private_key,
				  gchar *pem_ca_certificate)
{
	gchar *sql = NULL;
	gchar *error = NULL;


	if (!(ca_db = sqlite_open(creation_data->filename, 1, NULL)))
		return FALSE;

	if (sqlite_exec (ca_db,
			   "CREATE TABLE ca_properties (id INTEGER PRIMARY KEY, name TEXT UNIQUE, value TEXT);",
			   NULL, NULL, &error)) {
		g_printerr ("%s\n", error);
		g_free (error);
		return FALSE;
	}
	if (sqlite_exec (ca_db,
			   "CREATE TABLE certificates (id INTEGER PRIMARY KEY, serial INT UNIQUE, subject TEXT, emission TIMESTAMP, expiration TIMESTAMP, is_revoked BOOLEAN, pem TEXT);",
			   NULL, NULL, &error)) {
		g_printerr ("%s\n", error);
		g_free (error);
		return FALSE;
	}
	
	if (sqlite_exec (ca_db, "INSERT INTO ca_properties VALUES (NULL, 'ca_private_key_is_in_db', 'TRUE');", NULL, NULL, &error)) {
		g_printerr ("%s\n", error);
		g_free (error);
		return FALSE;
	}

	if (sqlite_exec (ca_db, "INSERT INTO ca_properties VALUES (NULL, 'ca_private_key_extern_location', NULL);", NULL, NULL, NULL))
		return FALSE;

	sql = g_strdup_printf ("INSERT INTO ca_properties VALUES (NULL, 'ca_private_key', '%s');", pem_ca_private_key);
	if (sqlite_exec (ca_db, sql, NULL, NULL, NULL))
		return FALSE;
	g_free (sql);

	sql = g_strdup_printf ("INSERT INTO ca_properties VALUES (NULL, 'ca_certificate', '%s');", pem_ca_certificate);
	if (sqlite_exec (ca_db, sql, NULL, NULL, NULL))
		return FALSE;
	g_free (sql);

	if (sqlite_exec (ca_db, "COMMIT;", NULL, NULL, NULL))
		return FALSE;

	return TRUE;

}

gboolean ca_file_open (gchar *file_name)
{
	if (! (ca_db = sqlite_open(file_name, 1, NULL)))
		return FALSE;
	else
		return TRUE;
}

void ca_file_close ()
{
	sqlite_close (ca_db);
}


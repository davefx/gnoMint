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

#include <gnome.h>


int main (int   argc,
	  char *argv[])
{
/* 	gboolean silent = FALSE; */
/* 	gchar *savefile = NULL; */
	GOptionContext *ctx;
	GError *err = NULL;
	GOptionEntry entries[] = {
/* 		{ "silent", 's', 0, G_OPTION_ARG_NONE, &silent, 0, */
/* 		  "do not output status information", NULL }, */
/* 		{ "output", 'o', 0, G_OPTION_ARG_STRING, &savefile, 0, */
/* 		  "save xml representation of pipeline to FILE and exit", "FILE" }, */
		{ NULL }
	};
	
	ctx = g_option_context_new (_("- A graphical Certification Authority manager"));
	g_option_context_add_main_entries (ctx, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
		g_print (_("Failed to initialize: %s\n"), err->message);
		g_error_free (err);
		return 1;
	}
	
	printf (_("Run me with --help to see the Application options appended.\n"));

  return 0;
}

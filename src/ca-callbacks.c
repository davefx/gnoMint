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
#include <stdlib.h>
#include <stdio.h>
#include <glib/gi18n.h>

#include "ca-cli.h"

extern CaCommand ca_commands[];
#define CA_COMMAND_NUMBER 31

int ca_callback_newdb (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_opendb (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_savedbas (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_status (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_listcert (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_listcsr (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_addcsr (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_addca (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_extractcertpkey (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}


int ca_callback_extractcsrpkey (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_revoke (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_sign (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_delete (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_crlgen (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_dhgen (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_changepassword (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_importfile (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_importdir (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showcert (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showcsr (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showpolicy (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_setpolicy (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_showpreferences (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_setpreference (int argc, char **argv)
{
	fprintf (stderr, "//FIXME\n");
	return 0;
}

int ca_callback_about (int argc, char **argv)
{
        printf (_("%s version %s\n%s\n"), PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_COPYRIGHT);
        printf (_("\nAuthors:\n%s\n\n"), PACKAGE_AUTHORS);
        if (strcmp ("translator-credits", _("translator-credits")))
            printf (_("Translators:\n%s\n"), _("translator-credits"));
	return 0;
}

int ca_callback_warranty  (int argc, char **argv)
{
        printf ("%s",
                _("THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY\n"
                  "APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT\n"
                  "HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY\n"
                  "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,\n"
                  "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\n"
                  "PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM\n"
                  "IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF\n"
                  "ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\n\n"
                  "For more information about warranty, see section 15 onwards of the GNU\n"
                  "General Public License. You should have received a copy of the GNU General\n"
                  "Public License along with this program. If not, see\n"
                  "<http://www.gnu.org/licenses/>.\n\n"));
	return 0;
}

int ca_callback_distribution  (int argc, char **argv)
{
        printf ("%s",
                _("This program is free software: you can redistribute it and/or modify\n"
                  "it under the terms of the GNU General Public License as published by\n"
                  "the Free Software Foundation, either version 3 of the License, or\n"
                  "(at your option) any later version.\n\n"
                  "This program is distributed in the hope that it will be useful,\n"
                  "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
                  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
                  "GNU General Public License for more details.\n\n"
                  "You should have received a copy of the GNU General Public License\n"
                  "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\n"));
	return 0;
}

int ca_callback_version  (int argc, char **argv)
{
        printf (_("%s version %s\n"), PACKAGE_NAME, PACKAGE_VERSION); 
	return 0;
}

int ca_callback_help  (int argc, char **argv)
{
	gint i;

	printf ("\n");
	printf (_("Available commands:\n"));
	printf (_("===================\n"));

	for (i=0; i < CA_COMMAND_NUMBER; i++) {
		printf ("* %s\n    %s\n", _(ca_commands[i].syntax), _(ca_commands[i].help));
	}
	return 0;
}

int ca_callback_exit (int argc, char **argv)
{
        printf (_("Exiting gnomint-cli...\n"));
        exit (0);
        return 0;
}

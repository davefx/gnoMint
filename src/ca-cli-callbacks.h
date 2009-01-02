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

int ca_cli_callback_newdb (int argc, char **argv);
int ca_cli_callback_opendb (int argc, char **argv);
int ca_cli_callback_savedbas (int argc, char **argv);
int ca_cli_callback_status (int argc, char **argv);
int ca_cli_callback_listcert (int argc, char **argv);
int ca_cli_callback_listcsr (int argc, char **argv);
int ca_cli_callback_addcsr (int argc, char **argv);
int ca_cli_callback_addca (int argc, char **argv);
int ca_cli_callback_extractcertpkey (int argc, char **argv);
int ca_cli_callback_extractcsrpkey (int argc, char **argv);
int ca_cli_callback_revoke (int argc, char **argv);
int ca_cli_callback_sign (int argc, char **argv);
int ca_cli_callback_delete (int argc, char **argv);
int ca_cli_callback_crlgen (int argc, char **argv);
int ca_cli_callback_dhgen (int argc, char **argv);
int ca_cli_callback_changepassword (int argc, char **argv);
int ca_cli_callback_importfile (int argc, char **argv);
int ca_cli_callback_importdir (int argc, char **argv);
int ca_cli_callback_showcert (int argc, char **argv);
int ca_cli_callback_showcsr (int argc, char **argv);
int ca_cli_callback_showpolicy (int argc, char **argv);
int ca_cli_callback_setpolicy (int argc, char **argv);
int ca_cli_callback_showpreferences (int argc, char **argv);
int ca_cli_callback_setpreference (int argc, char **argv);
int ca_cli_callback_about (int argc, char **argv);
int ca_cli_callback_warranty  (int argc, char **argv);
int ca_cli_callback_distribution  (int argc, char **argv);
int ca_cli_callback_version  (int argc, char **argv);
int ca_cli_callback_help  (int argc, char **argv);
int ca_cli_callback_exit (int argc, char **argv);

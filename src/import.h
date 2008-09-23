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

#ifndef _IMPORT_H_
#define _IMPORT_H_

#include <glib.h>
#include <glib/gi18n.h>

gboolean import_csr (guchar *file_contents, gsize file_contents_size);
gboolean import_certlist (guchar *file_contents, gsize file_contents_size);
gboolean import_pkey_wo_passwd (guchar *file_contents, gsize file_contents_size);
gboolean import_crl (guchar *file_contents, gsize file_contents_size);
gboolean import_pkcs7 (guchar *file_contents, gsize file_contents_size);
gboolean import_pkcs12 (guchar *file_contents, gsize file_contents_size);

#endif

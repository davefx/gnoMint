//  gnoMint: a graphical interface for managing a certification authority
//  Copyright (C) 2006-2009 David Marín Carreño <davefx@gmail.com>
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

#ifndef _SAN_MANAGER_H_
#define _SAN_MANAGER_H_

#include <gtk/gtk.h>

typedef enum {
	SAN_TYPE_DNS = 0,
	SAN_TYPE_IP = 1,
	SAN_TYPE_EMAIL = 2,
	SAN_TYPE_URI = 3
} SanType;

// Initialize a SAN manager widget from builder
GtkWidget * san_manager_create(GtkBuilder *builder, const gchar *widget_id);

// Get the SAN list as a formatted string (e.g., "DNS:example.com,IP:192.168.1.1")
gchar * san_manager_get_string(GtkWidget *san_manager);

// Set the SAN list from a formatted string
void san_manager_set_string(GtkWidget *san_manager, const gchar *san_string);

// Validate a SAN value based on type
gboolean san_validate(SanType type, const gchar *value, gchar **error_message);

#endif // _SAN_MANAGER_H_

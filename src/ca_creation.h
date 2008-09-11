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

#ifndef _CA_CREATION_H_
#define _CA_CREATION_H_

#include <glib.h>
#include <time.h>
#include "uint160.h"

typedef struct {
	gchar * country;
	gchar * state;
	gchar * city;
	gchar * org;
	gchar * ou;
	gchar * cn;
	gchar * emailAddress;

	gint key_type;
	gint key_bitlength;

	gint key_months_before_expiration;
	time_t activation;
	time_t expiration;

	/* Now, as the DB is not related to CAs anymore, the field is_pwd_protected has no sense
	   in CA creation process */

	/* gboolean is_pwd_protected; */

	/* However, the password is needed */
	gchar * password; 
	
} CaCreationData;

typedef struct {
	gint key_months_before_expiration;
	time_t activation;
	time_t expiration;
	
	UInt160 serial;

        gboolean ca;
        gboolean crl_signing;
	gboolean digital_signature;
	gboolean data_encipherment;
	gboolean key_encipherment;
	gboolean non_repudiation;
	gboolean key_agreement;

	gboolean email_protection;
	gboolean code_signing;
	gboolean web_client;
	gboolean web_server;
	gboolean time_stamping;
	gboolean ocsp_signing;
	gboolean any_purpose;

	gchar * cadb_password;

} CertCreationData;

GThread * ca_creation_launch_thread (CaCreationData *creation_data);


void ca_creation_lock_status_mutex (void);
void ca_creation_unlock_status_mutex (void);

gint ca_creation_get_thread_status (void);

gchar * ca_creation_get_thread_message(void);

void ca_creation_data_free (CaCreationData *cd);

gpointer ca_creation_thread (gpointer data);

#endif

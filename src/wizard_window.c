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

#include <glib-object.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "wizard_window.h"
#include "ca_file.h"
#include "tls.h"
#include "pkey_manage.h"
#include "dialog.h"
#include "export.h"
#include "new_cert.h"

#include <glib/gi18n.h>

GtkBuilder * wizard_window_gtkb = NULL;
static WizardCertType current_wizard_type = WIZARD_CERT_TYPE_WEB_SERVER;

// External declaration of ca_db from ca_file.c
extern sqlite3 *ca_db;

// Helper function to get the first available CA
static guint64 __wizard_get_first_ca_id (void)
{
    guint64 ca_id = 0;
    gchar *query = "SELECT id FROM certificates WHERE is_ca=1 LIMIT 1;";
    gchar *error = NULL;
    
    // Use a simple callback to get the first CA id
    int callback(void *data, int argc, char **argv, char **columnNames) {
        if (argc > 0 && argv[0]) {
            guint64 *id = (guint64 *)data;
            *id = g_ascii_strtoull(argv[0], NULL, 10);
        }
        return 0;
    }
    
    sqlite3_exec (ca_db, query, callback, &ca_id, &error);
    
    if (error) {
        g_free (error);
    }
    
    return ca_id;
}

// Helper function to create CSR with default settings
static guint64 __wizard_create_csr (const gchar *server_name, WizardCertType cert_type)
{
    TlsCreationData *creation_data = g_new0 (TlsCreationData, 1);
    gchar *private_key = NULL;
    gnutls_x509_privkey_t *csr_key = NULL;
    gchar *certificate_sign_request = NULL;
    gchar *error_message = NULL;
    TlsCsr *tlscsr = NULL;
    guint64 csr_id = 0;
    
    // Set default values
    creation_data->key_type = 0; // RSA
    creation_data->key_bitlength = 2048; // Default key size
    creation_data->country = g_strdup(""); // Empty country
    creation_data->state = g_strdup(""); // Empty state
    creation_data->city = g_strdup(""); // Empty locality
    creation_data->org = g_strdup(""); // Empty organization
    creation_data->ou = g_strdup(""); // Empty organizational unit
    creation_data->cn = g_strdup(server_name); // Server name as CN
    creation_data->emailAddress = g_strdup("");
    creation_data->parent_ca_id_str = NULL;
    
    // Generate RSA key pair
    error_message = tls_generate_rsa_keys (creation_data, &private_key, &csr_key);
    
    if (error_message) {
        dialog_error (g_strdup_printf (_("Key generation failed:\n%s"), error_message));
        tls_creation_data_free(creation_data);
        return 0;
    }
    
    // Generate CSR
    error_message = tls_generate_csr (creation_data, csr_key, &certificate_sign_request);
    
    if (error_message) {
        dialog_error (g_strdup_printf (_("CSR generation failed:\n%s"), error_message));
        g_free(private_key);
        tls_creation_data_free(creation_data);
        return 0;
    }
    
    // Parse CSR to get DN
    tlscsr = tls_parse_csr_pem (certificate_sign_request);
    
    if (!tlscsr) {
        dialog_error (_("Failed to parse generated CSR."));
        g_free(private_key);
        g_free(certificate_sign_request);
        tls_creation_data_free(creation_data);
        return 0;
    }
    
    // Save CSR to database
    error_message = ca_file_insert_csr (private_key, certificate_sign_request, NULL, &csr_id);
    
    if (error_message) {
        dialog_error (g_strdup_printf (_("Failed to save CSR:\n%s"), error_message));
        tls_csr_free(tlscsr);
        g_free(private_key);
        g_free(certificate_sign_request);
        tls_creation_data_free(creation_data);
        return 0;
    }
    
    // Cleanup
    tls_csr_free(tlscsr);
    g_free(private_key);
    g_free(certificate_sign_request);
    tls_creation_data_free(creation_data);
    
    return csr_id;
}

// Helper function to export certificate and key
static gboolean __wizard_export_cert_and_key (guint64 cert_id, const gchar *server_name)
{
    gchar *gnomint_dir = g_build_filename (g_get_home_dir(), ".gnomint", NULL);
    gchar *cert_filename = g_strdup_printf ("%s-cert.pem", server_name);
    gchar *key_filename = g_strdup_printf ("%s-key.pem", server_name);
    gchar *cert_path = g_build_filename (gnomint_dir, cert_filename, NULL);
    gchar *key_path = g_build_filename (gnomint_dir, key_filename, NULL);
    gchar *error = NULL;
    gboolean success = TRUE;
    
    // Create .gnomint directory if it doesn't exist
    if (!g_file_test (gnomint_dir, G_FILE_TEST_EXISTS)) {
        if (g_mkdir_with_parents (gnomint_dir, 0700) != 0) {
            dialog_error (_("Failed to create ~/.gnomint directory."));
            success = FALSE;
            goto cleanup;
        }
    }
    
    // Export certificate PEM
    gchar *cert_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, cert_id);
    if (!cert_pem) {
        dialog_error (_("Failed to get certificate data."));
        success = FALSE;
        goto cleanup;
    }
    
    GError *gerror = NULL;
    if (!g_file_set_contents (cert_path, cert_pem, strlen(cert_pem), &gerror)) {
        dialog_error (g_strdup_printf (_("Failed to save certificate:\n%s"), gerror ? gerror->message : "Unknown error"));
        g_clear_error (&gerror);
        g_free (cert_pem);
        success = FALSE;
        goto cleanup;
    }
    g_free (cert_pem);
    
    // Export private key
    error = export_private_pem (cert_id, CA_FILE_ELEMENT_TYPE_CERT, key_path);
    if (error) {
        dialog_error (g_strdup_printf (_("Failed to export private key:\n%s"), error));
        success = FALSE;
        goto cleanup;
    }
    
    // Show success message
    dialog_info (g_strdup_printf (_("Certificate generated successfully!\n\nFiles saved to:\n• %s\n• %s"), 
                                  cert_path, key_path));
    
cleanup:
    g_free (gnomint_dir);
    g_free (cert_filename);
    g_free (key_filename);
    g_free (cert_path);
    g_free (key_path);
    
    return success;
}

// Button click handlers
static void on_wizard_generate_button_clicked (GtkButton *button, gpointer user_data)
{
    GtkWidget *dialog = GTK_WIDGET(user_data);
    GtkWidget *server_name_entry = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "server_name_entry"));
    const gchar *server_name = gtk_entry_get_text (GTK_ENTRY(server_name_entry));
    
    // Validate server name
    if (!server_name || strlen(server_name) == 0) {
        dialog_error (_("Please enter a server name."));
        return;
    }
    
    // Get first available CA
    guint64 ca_id = __wizard_get_first_ca_id ();
    if (ca_id == 0) {
        dialog_error (_("No Certificate Authority found. Please create a CA first."));
        return;
    }
    
    // Create CSR
    guint64 csr_id = __wizard_create_csr (server_name, current_wizard_type);
    if (csr_id == 0) {
        return; // Error already shown
    }
    
    // Prepare certificate creation data
    TlsCertCreationData *cert_creation_data = g_new0 (TlsCertCreationData, 1);
    cert_creation_data->ca = ca_id;
    cert_creation_data->key_months_before_expiration = 12; // 1 year default
    
    // Set certificate usage based on type
    if (current_wizard_type == WIZARD_CERT_TYPE_WEB_SERVER) {
        cert_creation_data->web_server = TRUE;
        cert_creation_data->web_client = FALSE;
        cert_creation_data->digital_signature = TRUE;
        cert_creation_data->key_encipherment = TRUE;
    } else {
        cert_creation_data->web_server = TRUE;
        cert_creation_data->web_client = TRUE;
        cert_creation_data->email_protection = TRUE;
        cert_creation_data->digital_signature = TRUE;
        cert_creation_data->key_encipherment = TRUE;
    }
    
    // Sign the CSR
    const gchar *error = new_cert_sign_csr (csr_id, ca_id, cert_creation_data);
    
    if (error) {
        dialog_error (g_strdup_printf (_("Failed to sign certificate:\n%s"), error));
        g_free (cert_creation_data);
        return;
    }
    
    // Get the newly created certificate ID
    guint64 cert_id = 0;
    gchar *query = g_strdup_printf("SELECT id FROM certificates WHERE ca=%lu ORDER BY id DESC LIMIT 1;", ca_id);
    gchar *db_error = NULL;
    
    int callback(void *data, int argc, char **argv, char **columnNames) {
        if (argc > 0 && argv[0]) {
            guint64 *id = (guint64 *)data;
            *id = g_ascii_strtoull(argv[0], NULL, 10);
        }
        return 0;
    }
    
    sqlite3_exec (ca_db, query, callback, &cert_id, &db_error);
    g_free(query);
    
    if (db_error) {
        g_free (db_error);
    }
    
    if (cert_id == 0) {
        dialog_error (_("Failed to find newly created certificate."));
        g_free (cert_creation_data);
        return;
    }
    
    // Export certificate and key
    __wizard_export_cert_and_key (cert_id, server_name);
    
    g_free (cert_creation_data);
    
    // Close dialog
    gtk_widget_destroy (dialog);
}

static void on_wizard_cancel_button_clicked (GtkButton *button, gpointer user_data)
{
    GtkWidget *dialog = GTK_WIDGET(user_data);
    gtk_widget_destroy (dialog);
}

void wizard_window_display (WizardCertType cert_type)
{
    GtkWidget *dialog;
    GtkWidget *generate_button;
    GtkWidget *cancel_button;
    GtkWidget *cert_type_combo;
    GError *error = NULL;
    
    current_wizard_type = cert_type;
    
    // Load the UI file
    wizard_window_gtkb = gtk_builder_new ();
    if (!gtk_builder_add_from_file (wizard_window_gtkb, 
                                     PACKAGE_DATA_DIR "/gnomint/wizard_window.ui",
                                     &error)) {
        g_warning ("Couldn't load builder file: %s", error ? error->message : "Unknown error");
        g_clear_error (&error);
        return;
    }
    
    // Get dialog widget
    dialog = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "wizard_dialog"));
    
    if (!dialog) {
        g_warning ("Couldn't find wizard_dialog in UI file");
        g_object_unref (wizard_window_gtkb);
        return;
    }
    
    // Get buttons
    generate_button = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "generate_button"));
    cancel_button = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "cancel_button"));
    
    // Set certificate type combo
    cert_type_combo = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "cert_type_combo"));
    gtk_combo_box_set_active (GTK_COMBO_BOX(cert_type_combo), cert_type);
    
    // Connect signals
    g_signal_connect (generate_button, "clicked", 
                      G_CALLBACK(on_wizard_generate_button_clicked), dialog);
    g_signal_connect (cancel_button, "clicked", 
                      G_CALLBACK(on_wizard_cancel_button_clicked), dialog);
    
    // Show dialog
    gtk_widget_show_all (dialog);
}

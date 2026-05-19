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
#include <time.h>

#include "wizard_window.h"
#include "ca_file.h"
#include "ca.h"
#include "tls.h"
#include "pkey_manage.h"
#include "dialog.h"
#include "new_cert.h"

#include <glib/gi18n.h>

GtkBuilder * wizard_window_gtkb = NULL;
static WizardCertType current_wizard_type = WIZARD_CERT_TYPE_WEB_SERVER;

// External declaration of ca_db from ca_file.c
extern sqlite3 *ca_db;

typedef struct {
    guint64 ca_id;
    gchar *subject;
    time_t expiration;
} CAInfo;

// Helper function to get CA list (non-expired first)
static GList * __wizard_get_ca_list (void)
{
    GList *ca_list = NULL;
    gchar *query = "SELECT id, subject, expiration FROM certificates WHERE is_ca=1 AND revocation IS NULL ORDER BY expiration DESC;";
    gchar *error = NULL;
    
    int callback(void *data, int argc, char **argv, char **columnNames) {
        if (argc >= 3 && argv[0] && argv[1]) {
            GList **list = (GList **)data;
            CAInfo *ca = g_new0(CAInfo, 1);
            ca->ca_id = g_ascii_strtoull(argv[0], NULL, 10);
            ca->subject = g_strdup(argv[1]);
            ca->expiration = argv[2] ? (time_t)g_ascii_strtoull(argv[2], NULL, 10) : 0;
            *list = g_list_append(*list, ca);
        }
        return 0;
    }
    
    sqlite3_exec (ca_db, query, callback, &ca_list, &error);
    
    if (error) {
        g_free (error);
    }
    
    return ca_list;
}

// Helper function to get selected CA from main window or first non-expired
static guint64 __wizard_get_default_ca_id (void)
{
    guint64 selected_ca = ca_get_selected_row_id();
    
    // Check if selected item is a CA
    if (selected_ca > 0) {
        gchar *query = g_strdup_printf("SELECT id FROM certificates WHERE id=%" G_GUINT64_FORMAT " AND is_ca=1 AND revocation IS NULL;", selected_ca);
        gchar *error = NULL;
        guint64 result = 0;
        
        int callback(void *data, int argc, char **argv, char **columnNames) {
            if (argc > 0 && argv[0]) {
                guint64 *id = (guint64 *)data;
                *id = g_ascii_strtoull(argv[0], NULL, 10);
            }
            return 0;
        }
        
        sqlite3_exec (ca_db, query, callback, &result, &error);
        g_free(query);
        
        if (error) {
            g_free (error);
        }
        
        if (result > 0) {
            return result;
        }
    }
    
    // Get first non-expired CA
    time_t now = time(NULL);
    gchar *query = g_strdup_printf("SELECT id FROM certificates WHERE is_ca=1 AND revocation IS NULL AND expiration > %ld ORDER BY expiration DESC LIMIT 1;", (long)now);
    gchar *error = NULL;
    guint64 ca_id = 0;
    
    int callback(void *data, int argc, char **argv, char **columnNames) {
        if (argc > 0 && argv[0]) {
            guint64 *id = (guint64 *)data;
            *id = g_ascii_strtoull(argv[0], NULL, 10);
        }
        return 0;
    }
    
    sqlite3_exec (ca_db, query, callback, &ca_id, &error);
    g_free(query);
    
    if (error) {
        g_free (error);
    }
    
    // If no non-expired CA found, get any CA
    if (ca_id == 0) {
        query = "SELECT id FROM certificates WHERE is_ca=1 AND revocation IS NULL LIMIT 1;";
        sqlite3_exec (ca_db, query, callback, &ca_id, &error);
        
        if (error) {
            g_free (error);
        }
    }
    
    return ca_id;
}

// Helper function to get CA fields for inheritance
static void __wizard_get_ca_fields (guint64 ca_id, TlsCreationData *creation_data)
{
    // Get CA policy settings
    GHashTable *policy_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    
    int policy_callback(void *pArg, int argc, char **argv, char **columnNames) {
        GHashTable *table = (GHashTable *)pArg;
        if (argc >= 3 && argv[1] && argv[2]) {
            g_hash_table_insert (table, g_strdup(argv[1]), g_strdup(argv[2]));
        }
        return 0;
    }
    
    ca_file_foreach_policy (policy_callback, ca_id, policy_table);
    
    // Get CA certificate fields
    gchar *ca_pem = ca_file_get_public_pem_from_id (CA_FILE_ELEMENT_TYPE_CERT, ca_id);
    if (!ca_pem) {
        g_hash_table_destroy (policy_table);
        return;
    }
    
    TlsCert *ca_cert = tls_parse_cert_pem (ca_pem);
    g_free (ca_pem);
    
    if (!ca_cert) {
        g_hash_table_destroy (policy_table);
        return;
    }
    
    // Check and apply inheritance for each field
    gchar *strvalue;
    gint inherit_value;
    
    // Country (C)
    strvalue = (gchar *)g_hash_table_lookup (policy_table, "C_INHERIT");
    inherit_value = strvalue ? atoi(strvalue) : 0;
    if (inherit_value && ca_cert->c) {
        g_free (creation_data->country);
        creation_data->country = g_strdup (ca_cert->c);
    }
    
    // State (ST)
    strvalue = (gchar *)g_hash_table_lookup (policy_table, "ST_INHERIT");
    inherit_value = strvalue ? atoi(strvalue) : 0;
    if (inherit_value && ca_cert->st) {
        g_free (creation_data->state);
        creation_data->state = g_strdup (ca_cert->st);
    }
    
    // Locality (L)
    strvalue = (gchar *)g_hash_table_lookup (policy_table, "L_INHERIT");
    inherit_value = strvalue ? atoi(strvalue) : 0;
    if (inherit_value && ca_cert->l) {
        g_free (creation_data->city);
        creation_data->city = g_strdup (ca_cert->l);
    }
    
    // Organization (O)
    strvalue = (gchar *)g_hash_table_lookup (policy_table, "O_INHERIT");
    inherit_value = strvalue ? atoi(strvalue) : 0;
    if (inherit_value && ca_cert->o) {
        g_free (creation_data->org);
        creation_data->org = g_strdup (ca_cert->o);
    }
    
    // Organizational Unit (OU)
    strvalue = (gchar *)g_hash_table_lookup (policy_table, "OU_INHERIT");
    inherit_value = strvalue ? atoi(strvalue) : 0;
    if (inherit_value && ca_cert->ou) {
        g_free (creation_data->ou);
        creation_data->ou = g_strdup (ca_cert->ou);
    }
    
    tls_cert_free (ca_cert);
    g_hash_table_destroy (policy_table);
}

// Helper function to create CSR with default settings
static guint64 __wizard_create_csr (const gchar *server_name, WizardCertType cert_type, guint64 ca_id)
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
    creation_data->parent_ca_id_str = g_strdup_printf("'%" G_GUINT64_FORMAT "'", ca_id);
    
    // Apply CA field inheritance based on CA policy
    __wizard_get_ca_fields (ca_id, creation_data);
    
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
        g_free (error_message);
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

// Button click handlers
static void on_wizard_generate_button_clicked (GtkButton *button, gpointer user_data)
{
    GtkWidget *dialog = GTK_WIDGET(user_data);
    GtkWidget *server_name_entry = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "server_name_entry"));
    GtkWidget *signing_ca_combo = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "signing_ca_combo"));
    const gchar *server_name = gtk_entry_get_text (GTK_ENTRY(server_name_entry));
    
    // Validate server name
    if (!server_name || strlen(server_name) == 0) {
        dialog_error (_("Please enter a server name."));
        return;
    }
    
    // Get selected CA
    GtkTreeIter iter;
    if (!gtk_combo_box_get_active_iter (GTK_COMBO_BOX(signing_ca_combo), &iter)) {
        dialog_error (_("Please select a Certificate Authority."));
        return;
    }
    
    guint64 ca_id = 0;
    GtkTreeModel *model = gtk_combo_box_get_model (GTK_COMBO_BOX(signing_ca_combo));
    gtk_tree_model_get (model, &iter, 0, &ca_id, -1);
    
    if (ca_id == 0) {
        dialog_error (_("Invalid Certificate Authority selected."));
        return;
    }
    
    // Create CSR
    guint64 csr_id = __wizard_create_csr (server_name, current_wizard_type, ca_id);
    if (csr_id == 0) {
        return; // Error already shown
    }
    
    // Prepare certificate creation data
    TlsCertCreationData *cert_creation_data = g_new0 (TlsCertCreationData, 1);
    cert_creation_data->key_months_before_expiration = 12; // 1 year default
    
    // Generated certificates should NOT be CA certificates
    cert_creation_data->ca = FALSE;
    cert_creation_data->crl_signing = FALSE;
    
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
    
    g_free (cert_creation_data);
    
    // Show success message
    dialog_info (_("Certificate generated successfully!"));
    
    // Refresh the main list to show the new certificate
    dialog_refresh_list();
    
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
    GtkWidget *signing_ca_combo;
    GtkListStore *ca_list_store;
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
    
    // Get widgets
    generate_button = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "generate_button"));
    cancel_button = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "cancel_button"));
    cert_type_combo = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "cert_type_combo"));
    signing_ca_combo = GTK_WIDGET(gtk_builder_get_object (wizard_window_gtkb, "signing_ca_combo"));
    
    // Populate CA list
    ca_list_store = GTK_LIST_STORE(gtk_builder_get_object (wizard_window_gtkb, "ca_list_model"));
    GList *ca_list = __wizard_get_ca_list();
    
    if (!ca_list) {
        dialog_error (_("No Certificate Authority found. Please create a CA first."));
        g_object_unref (wizard_window_gtkb);
        return;
    }
    
    guint64 default_ca_id = __wizard_get_default_ca_id();
    gint default_index = 0;
    gint current_index = 0;
    time_t now = time(NULL);
    
    for (GList *l = ca_list; l != NULL; l = l->next) {
        CAInfo *ca = (CAInfo *)l->data;
        GtkTreeIter iter;
        gchar *display_text;
        
        // Format display text with expiration date to distinguish CAs with same name
        if (ca->expiration > 0) {
            struct tm *exp_tm = localtime(&ca->expiration);
            gchar exp_date[20];
            strftime(exp_date, sizeof(exp_date), "%Y-%m-%d", exp_tm);
            
            if (ca->expiration < now) {
                display_text = g_strdup_printf("%s (exp: %s, expired)", ca->subject, exp_date);
            } else {
                display_text = g_strdup_printf("%s (exp: %s)", ca->subject, exp_date);
            }
        } else {
            display_text = g_strdup(ca->subject);
        }
        
        gtk_list_store_append (ca_list_store, &iter);
        gtk_list_store_set (ca_list_store, &iter,
                           0, ca->ca_id,
                           1, display_text,
                           -1);
        
        g_free(display_text);
        
        if (ca->ca_id == default_ca_id) {
            default_index = current_index;
        }
        current_index++;
        
        g_free(ca->subject);
        g_free(ca);
    }
    
    g_list_free(ca_list);
    
    // Set default CA selection
    gtk_combo_box_set_active (GTK_COMBO_BOX(signing_ca_combo), default_index);
    
    // Set certificate type combo
    gtk_combo_box_set_active (GTK_COMBO_BOX(cert_type_combo), cert_type);
    
    // Connect signals - builder will be unreferenced when dialog is destroyed
    g_signal_connect (dialog, "destroy", G_CALLBACK(gtk_widget_destroyed), &wizard_window_gtkb);
    g_signal_connect_swapped (dialog, "destroy", G_CALLBACK(g_object_unref), wizard_window_gtkb);
    
    g_signal_connect (generate_button, "clicked", 
                      G_CALLBACK(on_wizard_generate_button_clicked), dialog);
    g_signal_connect (cancel_button, "clicked", 
                      G_CALLBACK(on_wizard_cancel_button_clicked), dialog);
    
    // Show dialog
    gtk_widget_show_all (dialog);
}

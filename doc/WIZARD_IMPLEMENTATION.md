# Certificate Wizard Feature - Implementation Summary

## Overview
This implementation adds a wizard feature to gnoMint that simplifies the process of issuing certificates for servers, reducing the number of clicks from approximately 20 to just 2-3 clicks.

## Features

### 1. Two Quick-Access Wizard Buttons
Added to the main toolbar:
- **Web Server Certificate Wizard** - Optimized for web/TLS server certificates
- **Email Server Certificate Wizard** - Optimized for email server certificates with email protection

### 2. Simplified Wizard Dialog
The wizard dialog (wizard_window.ui) provides:
- Server name input field (e.g., my.server.dns.name)
- Certificate type selection dropdown
- Clear instructions and output location information
- Generate and Cancel buttons

### 3. Automated Certificate Creation Process
When the user clicks "Generate Certificate", the wizard automatically:
1. Creates a Certificate Signing Request (CSR) with default settings
   - 2048-bit RSA key
   - Server name as Common Name (CN)
   - Empty values for other fields (country, state, org, etc.)

2. Signs the CSR using the first available Certificate Authority

3. Exports two files to ~/.gnomint/ directory:
   - `servername-cert.pem` - Public certificate
   - `servername-key.pem` - Unprotected private key

## Default Settings Used

### Key Generation
- Key Type: RSA
- Key Size: 2048 bits
- Algorithm: Standard RSA key generation

### Certificate Properties
- Validity Period: 12 months (1 year)
- Digital Signature: Enabled
- Key Encipherment: Enabled

#### Web Server Certificate
- TLS Web Server Authentication: Enabled
- TLS Web Client Authentication: Disabled

#### Email Server Certificate
- TLS Web Server Authentication: Enabled
- TLS Web Client Authentication: Enabled
- Email Protection: Enabled

## Files Modified/Created

### New Files
1. `src/wizard_window.h` - Wizard function declarations and type definitions
2. `src/wizard_window.c` - Wizard implementation (373 lines)
3. `gui/wizard_window.ui` - GTK dialog definition for wizard interface

### Modified Files
1. `src/ca.c` - Added wizard signal handlers
2. `src/Makefile.am` - Added wizard source files to build
3. `gui/Makefile.am` - Added wizard UI file to installation
4. `gui/main_window.ui` - Added two toolbar buttons for wizards

## Implementation Details

### Key Functions

#### `wizard_window_display(WizardCertType cert_type)`
Main entry point that displays the wizard dialog. Takes certificate type as parameter.

#### `__wizard_get_first_ca_id()`
Helper function to find the first available Certificate Authority in the database.

#### `__wizard_create_csr(server_name, cert_type)`
Creates a Certificate Signing Request with minimal inputs:
- Generates RSA key pair
- Creates CSR with server name as CN
- Saves to database
- Returns CSR ID

#### `__wizard_export_cert_and_key(cert_id, server_name)`
Exports the certificate and private key to files:
- Creates ~/.gnomint/ directory if needed
- Exports certificate as PEM
- Exports unprotected private key
- Shows success message with file paths

### Error Handling
- Validates server name input
- Checks for available Certificate Authorities
- Reports errors at each step with descriptive messages
- Proper memory cleanup on all code paths

### Memory Management
- Uses GLib memory functions (g_new0, g_free, g_strdup)
- Calls appropriate cleanup functions (tls_creation_data_free, tls_csr_free, pkey_manage_data_free)
- Fixed memory leaks identified in code review
- GtkBuilder object properly unreferenced when dialog closes

## Security Considerations

### Output Files
- Certificate files (*.pem) created with default file permissions
- Private key files are UNPROTECTED (no password) for convenience
- Files saved to user's home directory (~/.gnomint/)
- Directory created with 0700 permissions (owner-only access)

### Certificate Usage
- Certificates use first available CA automatically
- No custom extensions or constraints beyond default usage flags
- Standard 1-year validity period

### Input Validation
- Server name cannot be empty
- Must have at least one CA in the database

## User Workflow

### Before (Traditional Method) - ~20 Clicks
1. Click "Add CSR" button
2. Fill in multiple form fields (CN, O, OU, C, ST, L, etc.)
3. Select key type and size
4. Click "Next" through multiple wizard pages
5. Generate CSR
6. Select CSR in list
7. Click "Sign" button
8. Select CA to sign with
9. Set certificate properties (validity, usage, etc.)
10. Sign certificate
11. Select certificate in list
12. Click "Export" menu
13. Choose export format
14. Select export location
15. Export certificate
16. Repeat export for private key

### After (Wizard Method) - 2-3 Clicks
1. Click "Web Server Wizard" or "Email Server Wizard" toolbar button
2. Enter server name (e.g., my.server.dns.name)
3. Click "Generate Certificate"
4. Done! Files are automatically saved to ~/.gnomint/

## Testing Validation

All automated validations passed:
- ✓ All wizard source files exist
- ✓ Wizard files integrated in build system
- ✓ Signal handlers added to ca.c
- ✓ Toolbar buttons added to main_window.ui
- ✓ Binary built successfully
- ✓ Key wizard functions present
- ✓ Memory cleanup functions present

## Limitations and Notes

1. **No Custom Configuration**: Wizard uses hardcoded defaults. Users needing custom settings should use the traditional method.

2. **First CA Used**: Wizard automatically uses the first available CA. No option to choose a specific CA.

3. **Unprotected Keys**: Private keys are exported without password protection for maximum convenience. Users should secure these files appropriately.

4. **Single Server Name**: Only accepts one server name. Multiple SANs (Subject Alternative Names) not supported in wizard.

5. **No Policy Configuration**: Uses default certificate policies from the CA.

6. **Fixed Output Location**: Always exports to ~/.gnomint/. No option to choose custom location.

## Future Enhancements (Not Implemented)

Possible improvements for future versions:
- Allow custom output directory selection
- Option to password-protect exported private key
- CA selection dropdown if multiple CAs available
- Configurable validity period
- Support for multiple SANs (Subject Alternative Names)
- Preset templates for different server types
- Integration with preferences for default settings

## Compatibility

- Maintains backward compatibility - does not modify existing functionality
- Works with existing CA database structure
- Uses standard gnoMint APIs for certificate creation and export
- GTK+ 2.16+ required (already a dependency)

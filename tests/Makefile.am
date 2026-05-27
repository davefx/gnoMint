## tests/Makefile.am — make check harness
##
## Stage 1 — static checks, no display needed (issue #42, landed):
##   check_y2k38             Standalone Y2K38 verification (was src/test_y2k38.c)
##   check_ui_consistency    Static .ui consistency checker
##
## Stage 2A — runtime checks under headless Wayland (issue #43):
##   check_workflows         GTK workflow regression tests, run via
##                           run-headless.sh which spawns weston with
##                           the headless backend. Gnomint's primary
##                           user environment is Wayland.

TESTS = check_y2k38 check_ui_consistency check_workflows \
        check_cli_email.sh check_cli_wizard.sh check_cli_parity.sh \
        check_cli_info.sh check_cli_lifecycle.sh \
        check_cli_keys.sh check_cli_banner.sh check_cli_import.sh \
        check_cli_importdir.sh check_cli_dhgen.sh check_cli_passphrase.py \
        check_cli_algorithms.sh
check_PROGRAMS = check_y2k38 check_ui_consistency check_workflows

# Per-test wrapper: only check_workflows runs under a headless Wayland
# compositor. The static tests stay display-free. The CLI shell tests
# spawn gnomint-cli directly so they need no display either.
check_workflows_LOG_COMPILER = $(srcdir)/run-headless.sh

EXTRA_DIST = run-headless.sh check_cli_email.sh check_cli_wizard.sh \
             check_cli_parity.sh check_cli_info.sh check_cli_lifecycle.sh \
             check_cli_keys.sh check_cli_banner.sh check_cli_import.sh \
             check_cli_importdir.sh check_cli_dhgen.sh \
             check_cli_passphrase.py check_cli_algorithms.sh

# ---------------------------------------------------------------
# Y2K38 verification — no GUI dependencies, just stdio + time.h.
# ---------------------------------------------------------------

check_y2k38_SOURCES = check_y2k38.c
check_y2k38_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-D_TIME_BITS=64 \
	-D_FILE_OFFSET_BITS=64 \
	-DHAVE_CONFIG_H

# ---------------------------------------------------------------
# Static UI consistency checker
#
# Links against gnomint's GUI object files so signal handler
# symbols are resolvable via dlsym() at test time. The test
# never invokes GTK directly — it parses .ui XML and looks up
# handler names in the running test binary's symbol table.
#
# src/main.c provides main_window_gtkb and the on_*_activate
# handlers; it is compiled here with -DGNOMINT_UI_TEST so its
# main() is suppressed (see the #ifndef GNOMINT_UI_TEST guard
# at the bottom of src/main.c).
# ---------------------------------------------------------------

check_ui_consistency_SOURCES = \
	check_ui_consistency.c \
	$(top_srcdir)/src/main.c \
	$(top_srcdir)/src/cert_row.c \
	$(top_srcdir)/src/country_table.c \
	$(top_srcdir)/src/new_ca_window.c \
	$(top_srcdir)/src/new_req_window.c \
	$(top_srcdir)/src/new_cert.c \
	$(top_srcdir)/src/cert_renewal.c \
	$(top_srcdir)/src/cert_diff.c \
	$(top_srcdir)/src/ca_bulk.c \
	$(top_srcdir)/src/creation_process_window.c \
	$(top_srcdir)/src/dialog.c \
	$(top_srcdir)/src/ca.c \
	$(top_srcdir)/src/ca_creation.c \
	$(top_srcdir)/src/tls.c \
	$(top_srcdir)/src/ca_file.c \
	$(top_srcdir)/src/certificate_properties.c \
	$(top_srcdir)/src/ca_policy.c \
	$(top_srcdir)/src/csr_creation.c \
	$(top_srcdir)/src/csr_properties.c \
	$(top_srcdir)/src/pkey_manage.c \
	$(top_srcdir)/src/preferences-gui.c \
	$(top_srcdir)/src/preferences-window.c \
	$(top_srcdir)/src/crl.c \
	$(top_srcdir)/src/uint160.c \
	$(top_srcdir)/src/import.c \
	$(top_srcdir)/src/export.c \
	$(top_srcdir)/src/san_entry.c \
	$(top_srcdir)/src/san_manager.c \
	$(top_srcdir)/src/wizard_window.c

check_ui_consistency_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	$(GNOMINT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DGNOMINT_UI_DIR=\""$(abs_top_srcdir)/gui"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H \
	-DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_4_6 \
	-DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_4_10 \
	-DGNOMINT_UI_TEST

check_ui_consistency_LDADD = \
	$(GNOMINT_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(LTLIBINTL) \
	-ldl

check_ui_consistency_LDFLAGS = \
	-export-dynamic

# ---------------------------------------------------------------
# check_workflows — runtime GTK workflow tests under headless Wayland.
# Links the same GUI object files as check_ui_consistency so populate
# functions and global builders are reachable. Run by run-headless.sh
# which manages a weston subprocess.
# ---------------------------------------------------------------

check_workflows_SOURCES = \
	check_workflows.c \
	$(top_srcdir)/src/main.c \
	$(top_srcdir)/src/cert_row.c \
	$(top_srcdir)/src/country_table.c \
	$(top_srcdir)/src/new_ca_window.c \
	$(top_srcdir)/src/new_req_window.c \
	$(top_srcdir)/src/new_cert.c \
	$(top_srcdir)/src/cert_renewal.c \
	$(top_srcdir)/src/cert_diff.c \
	$(top_srcdir)/src/ca_bulk.c \
	$(top_srcdir)/src/creation_process_window.c \
	$(top_srcdir)/src/dialog.c \
	$(top_srcdir)/src/ca.c \
	$(top_srcdir)/src/ca_creation.c \
	$(top_srcdir)/src/tls.c \
	$(top_srcdir)/src/ca_file.c \
	$(top_srcdir)/src/certificate_properties.c \
	$(top_srcdir)/src/ca_policy.c \
	$(top_srcdir)/src/csr_creation.c \
	$(top_srcdir)/src/csr_properties.c \
	$(top_srcdir)/src/pkey_manage.c \
	$(top_srcdir)/src/preferences-gui.c \
	$(top_srcdir)/src/preferences-window.c \
	$(top_srcdir)/src/crl.c \
	$(top_srcdir)/src/uint160.c \
	$(top_srcdir)/src/import.c \
	$(top_srcdir)/src/export.c \
	$(top_srcdir)/src/san_entry.c \
	$(top_srcdir)/src/san_manager.c \
	$(top_srcdir)/src/wizard_window.c

check_workflows_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	$(GNOMINT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DGNOMINT_UI_DIR=\""$(abs_top_srcdir)/gui"\" \
	-DTEST_PEM_PATH=\""$(abs_top_srcdir)/certs/davefx.pem"\" \
	-DTEST_FIXTURE_PATH=\""$(abs_top_srcdir)/certs/example-ca.gnomint"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H \
	-DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_4_6 \
	-DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_4_10 \
	-DGNOMINT_UI_TEST

check_workflows_LDADD = \
	$(GNOMINT_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(LTLIBINTL)

check_workflows_LDFLAGS = \
	-export-dynamic

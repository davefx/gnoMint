## tests/Makefile.am — make check harness
##
## Two stages are planned; this file implements stage 1 (see issue #42).
##
##   check_y2k38             Standalone Y2K38 verification (was src/test_y2k38.c)
##   check_ui_consistency    Static .ui consistency checker
##
## Stage 2 (issue #43) will add check_workflows running under Xvfb.

TESTS = check_y2k38 check_ui_consistency
check_PROGRAMS = $(TESTS)

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
	$(top_srcdir)/src/country_table.c \
	$(top_srcdir)/src/new_ca_window.c \
	$(top_srcdir)/src/new_req_window.c \
	$(top_srcdir)/src/new_cert.c \
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
	$(top_srcdir)/src/san_manager.c

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

bin_PROGRAMS = gnomint gnomint-cli

bin_SCRIPTS = gnomint-upgrade-db

gnomint_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H

gnomint_SOURCES = \
	main.c \
        new_ca_window.c \
        new_req_window.c \
	new_cert_window.c \
	new_cert_creation_process.c \
	ca.c \
	ca_creation.c \
	tls.c \
	ca_file.c \
	certificate_properties.c \
	ca_policy.c \
	csr_creation.c \
	csr_properties.c \
	pkey_manage.c \
	preferences-gui.c \
	preferences-window.c \
	crl.c \
	uint160.c \
	import.c


gnomint_LDADD = \
	$(GNOMINT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(LTLIBINTL)

gnomint_LDFLAGS = \
	-export-dynamic



gnomint_cli_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINTCLI_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H -DGNOMINTCLI

gnomint_cli_SOURCES = \
	gnomint-cli.c \
	ca.c \
	ca-cli.c \
	ca-callbacks.c \
        ca_creation.c \
	ca_file.c \
	ca_policy.c \
	crl.c \
        csr_creation.c \
        import.c \
	new_cert_window.c \
	preferences.c \
	pkey_manage.c \
	tls.c \
	uint160.c 


gnomint_cli_LDADD = \
	$(GNOMINTCLI_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(READLINE_LIBS) \
	$(LTLIBINTL)



EXTRA_DIST = \
	gnomint-upgrade-db \
	ca_creation.h \
	ca_file.h \
	ca.h \
	ca_policy.h \
	certificate_properties.h \
	csr_creation.h \
	csr_properties.h \
	main.h \
	new_cert_creation_process.h \
	new_ca_window.h \
	new_req_window.h \
	new_cert_window.h \
	tls.h\
	pkey_manage.h \
	preferences.h \
	preferences-gui.h \
	preferences-window.h \
	crl.h \
	uint160.h \
	import.h \
	ca-cli.h \
	ca-callbacks.h

bin_PROGRAMS = gnomint gnomint-cli

bin_SCRIPTS = gnomint-upgrade-db

gnomint_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
        $(LIBGCRYPT_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H

gnomint_SOURCES = \
	main.c \
	country_table.c \
        new_ca_window.c \
        new_req_window.c \
	new_cert.c \
	creation_process_window.c \
	dialog.c \
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
	import.c \
	export.c


gnomint_LDADD = \
	$(GNOMINT_LIBS) \
        $(LIBGCRYPT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(LTLIBINTL)

gnomint_LDFLAGS = \
	-export-dynamic



gnomint_cli_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINTCLI_CFLAGS) \
        $(LIBGCRYPT_LIBS) \
	$(LIBGNUTLS_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H -DGNOMINTCLI

gnomint_cli_SOURCES = \
	dialog.c \
	gnomint-cli.c \
	export.c \
	ca-cli.c \
	ca-cli-callbacks.c \
        ca_creation.c \
	ca_file.c \
	ca_policy.c \
	crl.c \
        csr_creation.c \
        import.c \
	new_cert.c \
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
	country_table.h \
	csr_creation.h \
	csr_properties.h \
	dialog.h \
	export.h \
	main.h \
	creation_process_window.h \
	new_ca_window.h \
	new_req_window.h \
	new_cert.h \
	tls.h\
	pkey_manage.h \
	preferences.h \
	preferences-gui.h \
	preferences-window.h \
	crl.h \
	uint160.h \
	import.h \
	ca-cli.h \
	ca-cli-callbacks.h

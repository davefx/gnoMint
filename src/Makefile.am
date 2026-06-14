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
	-DHAVE_CONFIG_H \
	-DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_4_12 \
	-Wall -Werror

gnomint_SOURCES = \
	main.c \
	cert_row.c \
	cert_row.h \
	prop_node.c \
	prop_node.h \
	ca_selector.c \
	ca_selector.h \
	country_table.c \
        new_ca_window.c \
        new_req_window.c \
	new_cert.c \
	cert_renewal.c \
	cert_diff.c \
	ca_bulk.c \
	creation_process_window.c \
	dialog.c \
	gnomint_time.c \
	gnomint_time.h \
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
	export.c \
	san_entry.c \
	san_entry.h \
	san_manager.c \
	san_manager.h \
	wizard_window.c


gnomint_LDADD = \
	$(GNOMINT_LIBS) \
        $(LIBGCRYPT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(WINSOCK_LIBS) \
	$(LTLIBINTL)

gnomint_LDFLAGS = \
	-export-dynamic



gnomint_cli_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINTCLI_CFLAGS) \
        $(LIBGCRYPT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DCOMPILATION_DATE=`date +%s` \
	-DHAVE_CONFIG_H -DGNOMINTCLI \
	-Wall -Werror

gnomint_cli_SOURCES = \
	dialog.c \
	gnomint_time.c \
	gnomint_time.h \
	gnomint-cli.c \
	export.c \
	ca-cli.c \
	ca-cli-callbacks.c \
        ca_creation.c \
	ca_file.c \
	ca_policy.c \
	ca_bulk.c \
	cert_renewal.c \
	cert_diff.c \
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
	$(LIBGCRYPT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(READLINE_LIBS) \
	$(WINSOCK_LIBS) \
	$(LTLIBINTL)



EXTRA_DIST = \
	gnomint-upgrade-db \
	ca_creation.h \
	ca_file.h \
	ca.h \
	ca_selector.h \
	ca_policy.h \
	certificate_properties.h \
	country_table.h \
	csr_creation.h \
	csr_properties.h \
	prop_node.h \
	dialog.h \
	export.h \
	main.h \
	creation_process_window.h \
	new_ca_window.h \
	new_req_window.h \
	new_cert.h \
	cert_renewal.h \
	cert_diff.h \
	ca_bulk.h \
	tls.h\
	pkey_manage.h \
	preferences.h \
	preferences-gui.h \
	preferences-window.h \
	crl.h \
	uint160.h \
	import.h \
	ca-cli.h \
	ca-cli-callbacks.h \
	time64_check.h \
	wizard_window.h

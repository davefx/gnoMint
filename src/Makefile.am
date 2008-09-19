bin_PROGRAMS = gnomint #testuint160

bin_SCRIPTS = gnomint-upgrade-db

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINT_CFLAGS) \
	$(LIBGNUTLS_CFLAGS) \
	$(SQLITE_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DPACKAGE_COPYRIGHT=\""$(PACKAGE_COPYRIGHT)"\" \
	-DPACKAGE_WEBSITE=\""$(PACKAGE_WEBSITE)"\" \
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

# testuint160_LDADD = \
# 	$(GNOMINT_LIBS)

gnomint_LDADD = \
	$(GNOMINT_LIBS) \
	$(LIBGNUTLS_LIBS) \
	$(SQLITE_LIBS) \
	$(LTLIBINTL)

gnomint_LDFLAGS = \
	-export-dynamic

# testuint160_SOURCES = \
# 	uint160.c \
# 	testuint160.c

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
	import.h


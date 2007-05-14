bin_PROGRAMS = gnomint 

bin_SCRIPTS = gnomint-upgrade-db

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINT_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DPACKAGE_COPYRIGHT=\""$(PACKAGE_COPYRIGHT)"\" \
	-DPACKAGE_WEBSITE=\""$(PACKAGE_WEBSITE)"\" \
	-DHAVE_CONFIG_H  -DCOMPILATION_DATE=`date +%s` -g -Wall -Werror

gnomint_SOURCES = \
	main.c \
	new_cert_window.c \
	new_cert_creation_process.c \
	ca.c \
	ca_creation.c \
	tls.c \
	ca_file.c \
	certificate_properties.c \
	ca_policy.c \
	csr_creation.c \
	csr_properties.c 

gnomint_LDADD = \
	$(GNOMINT_LIBS)

gnomint_LDFLAGS = \
	-export-dynamic

EXTRA_DIST = \
	gnomint-upgrade-db \
	ca_creation.h \
	ca_file.h \
	ca.h \
	ca_policy.h \
	certificate_properties.h \
	csr_creation.h \
	csr_properties.h \
	new_cert_creation_process.h \
	new_cert_window.h \
	tls.h

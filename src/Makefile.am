bin_PROGRAMS = gnomint

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GNOMINT_CFLAGS) \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DHAVE_CONFIG_H  -DCOMPILATION_DATE=`date +%s` -g -Wall 

gnomint_SOURCES = \
	main.c \
	new_ca_window.c \
	new_ca_creation_process.c \
	ca_creation.c \
	ssl.c \
	ca_file.c

gnomint_LDADD = \
	$(GNOMINT_LIBS)



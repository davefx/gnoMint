bin_PROGRAMS = gnomint

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/libgnomint \
	$(GNOMINT_CFLAGS) \
	-DGNOMINT_PIXMAPDIR=\""$(GNOMINT_Pixmapdir)"\" \
	-DGNOMINT_UIDIR=\""$(datadir)/gnomint/ui"\"

gnomint_SOURCES = \
	main.c 

gnomint_LDADD = \
	$(GNOMINT_LIBS)



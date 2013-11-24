SUBDIRS = m4 src po gui mime gconf

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = \
    -I$(top_srcdir)

EXTRA_DIST = \
	AUTHORS \
	BUGS \
	MAINTAINERS \
	NEWS \
	README \
	TODO \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	mkinstalldirs

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA = 

# to include gnomint.spec in the distro
dist-hook: gnomint.spec
	cp gnomint.spec $(distdir)

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

SUBDIRS = po src gui mime gconf

INCLUDES =                      \
    -I$(top_srcdir)             \
    -DPACKAGE_LOCALE_DIR=\""$(gnomintlocaledir)"\"

EXTRA_DIST = \
	TODO \
	BUGS \
	MAINTAINERS \
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
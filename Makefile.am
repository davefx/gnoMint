SUBDIRS = po src gui

INCLUDES =

EXTRA_DIST = \
	gnomint.desktop.in \
	gnomint.png \
	gnomint_tables.png \
	gnomint_sequences.png \
	gnomint_queries.png \
	gnomint_foot.png \
	gnomint_connect.png \
	gnomint_connect_small.png \
	gnomint_disconnect.png \
	gnomint_disconnect_small.png \
	gnomint_rels.png \
	gnomint_rels_small.png \
	gnomint_forms.png \
	query-view-query_16x16.png \
	query-view-table_16x16.png \
	query-view-view_16x16.png \
	TODO \
	BUGS \
	MAINTAINERS \
	gnomint.spec.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	mkinstalldirs

pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA = 

# to include gnomint.spec in the distro
dist-hook: gnomint.spec
	cp gnomint.spec $(distdir)

Pixmapdir=$(GNOMINT_Pixmapdir)
Pixmap_DATA=gnomint.png gnomint_tables.png gnomint_sequences.png gnomint_queries.png gnomint_foot.png \
	gnomint_connect.png gnomint_connect_small.png gnomint_disconnect.png gnomint_disconnect_small.png \
	gnomint_rels.png gnomint_rels_small.png gnomint_forms.png query-view-table_16x16.png \
	query-view-query_16x16.png query-view-view_16x16.png

Applicationsdir = $(datadir)/applications/
Applications_in_files = gnomint.desktop.in
Applications_DATA = $(Applications_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

DISTCLEANFILES = \
	gnomint.desktop \
	intltool-extract \
	intltool-merge \
	intltool-update
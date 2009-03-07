desktop_in_files = gnomint.desktop.in
desktopdir = $(datadir)/applications
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

@INTLTOOL_DESKTOP_RULE@

deskicondir = $(datadir)/pixmaps
deskicon_DATA = gnomint.png

gladedir = $(datadir)/gnomint
glade_DATA =   \
	gnomint.glade \
	gnomint.png \
	key-16.png \
	ca-stamp-16.png \
	addca.png \
	addcsr.png \
	extractpkey.png \
	sign.png

EXTRA_DIST = $(glade_DATA) $(deskicon_DATA) $(desktop_in_files)

CLEANFILES = $(desktop_DATA)

mimedir = $(datadir)/mime/packages
mime_in_files = gnomint.xml.in
mime_DATA = $(mime_in_files:.xml.in=.xml)

@INTLTOOL_XML_RULE@

EXTRA_DIST = $(MIMEFILES)

CLEANFILES = $(mime_DATA)

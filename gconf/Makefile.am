#SUBDIRS = pixmaps

gconfdir = $(datadir)/share/gconf/schemas
gconf_DATA =   \
	gnomint.schema

EXTRA_DIST = $(gconf_DATA)


@INTLTOOL_SCHEMAS_RULE@

if GCONF_SCHEMAS_INSTALL
# don't do this if we are building in eg. rpm
install-data-local:
	if test -z "$(DESTDIR)" ; then \
		for p in $(gconf_DATA) ; do \
			GCONF_CONFIG_SOURCE=$(GCONF_SCHEMA_CONFIG_SOURCE) $(GCONFTOOL) --makefile-install-rule $$p; \
		done \
	fi
else
install-data-local:
endif

all:

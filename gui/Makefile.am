desktopdir = $(datadir)/applications
desktop_DATA = gnomint.desktop

appdatadir = $(datadir)/metainfo
appdata_DATA = gnomint.appdata.xml

gnomint.desktop: gnomint.desktop.in $(top_srcdir)/po/*.po
	$(AM_V_GEN)$(MSGFMT) --desktop --template $< -d $(top_srcdir)/po -o $@

gnomint.appdata.xml: gnomint.appdata.xml.in $(top_srcdir)/po/*.po
	$(AM_V_GEN)$(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@

deskicondir = $(datadir)/pixmaps
deskicon_DATA = gnomint.png

icon48dir = $(datadir)/icons/hicolor/48x48/apps
icon48_DATA = gnomint.png

gtkbuilderdir = $(datadir)/gnomint
gtkbuilder_DATA =   \
	certificate_popup_menu.ui \
	certificate_properties_dialog.ui \
	change_password_dialog.ui \
	creation_process_window.ui \
	csr_popup_menu.ui \
	csr_properties_dialog.ui \
	dh_parameters_dialog.ui \
	export_certificate_dialog.ui \
	get_db_password_dialog.ui \
	get_password_dialog.ui \
	get_pkey_dialog.ui \
	import_file_or_directory_dialog.ui \
	import_password_dialog.ui \
	main_window.ui \
	new_ca_window.ui \
	new_cert_window.ui \
	new_crl_dialog.ui \
	new_req_window.ui \
	preferences_dialog.ui \
	san_editor_dialog.ui \
	san_manager_widget.ui \
	wizard_window.ui \
	gnomint.png \
	key-16.png \
	ca-stamp-16.png \
	addca.png \
	addcsr.png \
	extractpkey.png \
	sign.png \
	wizard-webserver.png \
	wizard-email.png \
	gnomint192x192.png

EXTRA_DIST = $(gtkbuilder_DATA) $(deskicon_DATA) gnomint.desktop.in gnomint.appdata.xml.in gnomint64x64.png

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(datadir)/icons/hicolor/64x64/apps
	$(INSTALL_DATA) $(srcdir)/gnomint64x64.png $(DESTDIR)$(datadir)/icons/hicolor/64x64/apps/gnomint.png
	$(MKDIR_P) $(DESTDIR)$(datadir)/icons/hicolor/192x192/apps
	$(INSTALL_DATA) $(srcdir)/gnomint192x192.png $(DESTDIR)$(datadir)/icons/hicolor/192x192/apps/gnomint.png
	-gtk-update-icon-cache -f -t $(DESTDIR)$(datadir)/icons/hicolor 2>/dev/null || true

uninstall-hook:
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/64x64/apps/gnomint.png
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/192x192/apps/gnomint.png
	-gtk-update-icon-cache -f -t $(DESTDIR)$(datadir)/icons/hicolor 2>/dev/null || true

CLEANFILES = $(desktop_DATA) $(appdata_DATA)

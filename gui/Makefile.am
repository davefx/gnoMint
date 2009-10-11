desktop_in_files = gnomint.desktop.in
desktopdir = $(datadir)/applications
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

@INTLTOOL_DESKTOP_RULE@

deskicondir = $(datadir)/pixmaps
deskicon_DATA = gnomint.png

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
	gnomint.png \
	key-16.png \
	ca-stamp-16.png \
	addca.png \
	addcsr.png \
	extractpkey.png \
	sign.png

EXTRA_DIST = $(gtkbuilder_DATA) $(deskicon_DATA) $(desktop_in_files)

CLEANFILES = $(desktop_DATA)

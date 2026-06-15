AC_PREREQ([2.69])

AC_INIT([gnoMint],[1.6.6],[<davefx@gmail.com>],[gnomint])

PACKAGE_CODENAME="Tempered Anvil"
AC_DEFINE_UNQUOTED([PACKAGE_CODENAME], ["$PACKAGE_CODENAME"], [Release codename])

PACKAGE_COPYRIGHT="(c) 2006-2026 David Marín Carreño <davefx@gmail.com>"
PACKAGE_WEBSITE="https://github.com/davefx/gnoMint"
PACKAGE_AUTHORS=$(awk 'NR>1{printf "\\n"}{printf "%s",$0}' AUTHORS)
AC_DEFINE_UNQUOTED([PACKAGE_COPYRIGHT], ["$PACKAGE_COPYRIGHT"], [Copyright notice])
AC_DEFINE_UNQUOTED([PACKAGE_WEBSITE], ["$PACKAGE_WEBSITE"], [Project website URL])
AC_DEFINE_UNQUOTED([PACKAGE_AUTHORS], ["$PACKAGE_AUTHORS"], [Author list])

AM_INIT_AUTOMAKE([1.12 foreign])
AC_CANONICAL_HOST

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
dnl Put the ACLOCAL flags in the Makefile
AC_SUBST([ACLOCAL_AMFLAGS], ["-I $ac_macro_dir \${ACLOCAL_FLAGS}"])

dnl Initialize maintainer mode
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

# Check for programs
AC_SEARCH_LIBS([strerror],[cposix])
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_DISABLE_STATIC
LT_INIT
AM_PROG_CC_C_O

# Use 64-bit file offsets everywhere (safe, independent of the C library ABI).
AC_DEFINE([_FILE_OFFSET_BITS], [64], [Use 64-bit file offsets])

# NOTE: We deliberately do NOT define _TIME_BITS=64 here.
#
# _TIME_BITS is a glibc ABI switch, not a private compiler flag: it changes the
# size of time_t for this program. It MUST stay consistent with every linked
# library (GnuTLS, GLib, SQLite, ...). On platforms where 64-bit time_t is the
# ABI (amd64, and 32-bit ports such as armhf) the toolchain already sets it, so
# forcing it here is redundant. On i386 the distribution toolchains (Debian,
# Ubuntu, Gentoo, openSUSE) keep the legacy 32-bit time_t for binary
# compatibility, and the system GnuTLS/GLib are built that way. Forcing
# _TIME_BITS=64 only in gnoMint made time_t 8 bytes here while GnuTLS still
# expected 4, so gnutls_x509_crt_set_*_time() read the wrong number of bytes off
# the stack and corrupted following arguments (manifesting as "Error when
# setting certificate serial number"). See issue #86. Letting the toolchain
# decide is the only ABI-correct choice.

# Checks for header files.
m4_warn([obsolete],
[The preprocessor macro 'STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  C89 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS([libintl.h locale.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([memset strcasecmp strdup])

# gettext stuff
GETTEXT_PACKAGE=${PACKAGE}
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE], ["$GETTEXT_PACKAGE"], [Gettext package name])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19.8])
dnl Define locale directory — replaces deprecated AM_GLIB_DEFINE_LOCALEDIR
gnomint_save_prefix="$prefix"
gnomint_save_exec_prefix="$exec_prefix"
gnomint_save_datarootdir="$datarootdir"
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix=$prefix
datarootdir=`eval echo "${datarootdir}"`
gnomint_localedir=`eval echo "${datadir}/locale"`
prefix="$gnomint_save_prefix"
exec_prefix="$gnomint_save_exec_prefix"
datarootdir="$gnomint_save_datarootdir"
AC_DEFINE_UNQUOTED([PACKAGE_LOCALE_DIR], ["$gnomint_localedir"],
  [Define the location where the catalogs will be installed])

# required versions
GNUTLS_REQUIRED=2.0
GNUTLS_ADVANCED_FEATURES_MINIMUM_VERSION=2.7.4
SQLITE_REQUIRED=3.0
GLIB_REQUIRED=2.66.0
GTK_REQUIRED=4.12.0
ISO_CODES_REQUIRED=0.35


# check for sqlite
PKG_CHECK_MODULES(SQLITE, sqlite3 >= $SQLITE_REQUIRED)
AC_SUBST(SQLITE_CFLAGS)
AC_SUBST(SQLITE_LIBS)

# check for libgcrypt
gcrypt=0
AM_PATH_LIBGCRYPT(1.2.0, gcrypt=1)
if test $gcrypt = 0
then
  AC_MSG_ERROR([gnoMint needs libgcrypt])
fi



PKG_CHECK_MODULES(GNOMINT, 
	glib-2.0 >= $GLIB_REQUIRED \
	gthread-2.0 >= $GLIB_REQUIRED \
	gio-2.0 >= $GLIB_REQUIRED \
	gtk4 >= $GTK_REQUIRED \
	gnutls >= $GNUTLS_REQUIRED \
)
AC_SUBST(GNOMINT_CFLAGS)
AC_SUBST(GNOMINT_LIBS)

#######################
# Check for readline.
########################
AC_CHECK_HEADER(readline/readline.h, readline_found=true, [AC_MSG_ERROR([libreadline is needed for compiling gnoMint.])] )
old_LIBS=$LIBS
LIBS="-lreadline"

AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[	READLINE_LIBS="-lreadline" ],[ 
                LIBS="$LIBS -ltermcap" 
		AC_TRY_LINK(,,[ READLINE_LIBS='-lreadline -ltermcap' ],[
			AC_MSG_ERROR([Cannot figure out how to link with the readline library; see config.log for more information])
		])
])

LIBS=$old_LIBS

AC_SUBST(READLINE_LIBS)

# On Windows (MinGW), inet_pton/inet_ntop live in ws2_32.
# Also link the GUI (only) with -mwindows so it gets the "Windows GUI"
# PE subsystem and Windows does not open a console window behind it when
# launched from the Start menu. gnomint-cli must stay a console program.
case "$host_os" in
  mingw*|msys*|cygwin*)
    WINSOCK_LIBS="-lws2_32"
    GUI_SUBSYSTEM_LDFLAGS="-mwindows"
    ;;
  *)
    WINSOCK_LIBS=""
    GUI_SUBSYSTEM_LDFLAGS=""
    ;;
esac
AC_SUBST(WINSOCK_LIBS)
AC_SUBST(GUI_SUBSYSTEM_LDFLAGS)

PKG_CHECK_MODULES(GNOMINTCLI, 
	glib-2.0 >= $GLIB_REQUIRED \
	gio-2.0 >= $GLIB_REQUIRED \
	gnutls >= $GNUTLS_REQUIRED \
)
AC_SUBST(GNOMINTCLI_CFLAGS)
AC_SUBST(GNOMINTCLI_LIBS)

dnl Check gnutls version
dnl (if >= GNUTLS_ADVANCED_FEATURES_MINIMUM_VERSION it enables some extra characteristics and functionalities)
AC_MSG_CHECKING([whether gnutls >= $GNUTLS_ADVANCED_FEATURES_MINIMUM_VERSION (for advanced features)])
PKG_CHECK_EXISTS([gnutls >= $GNUTLS_ADVANCED_FEATURES_MINIMUM_VERSION],
		 [have_advanced_gnutls=yes],[have_advanced_gnutls=no])
if test "x$have_advanced_gnutls" = "xyes"; then
   	AC_DEFINE_UNQUOTED([ADVANCED_GNUTLS], ["yes"], [GnuTLS has advanced features])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi

dnl Check iso-codes
dnl (just a chek for packagers, it is required for l10n at runtime)
PKG_CHECK_EXISTS([iso-codes >= $ISO_CODES_REQUIRED],
		 [have_iso_codes=yes],[have_iso_codes=no])
if test "x$have_iso_codes" = "xyes"; then
	AC_MSG_CHECKING([whether iso-codes has iso-639 and iso-3166 domains])
	if $PKG_CONFIG --variable=domains iso-codes | grep 639 > /dev/null && \
	   $PKG_CONFIG --variable=domains iso-codes | grep 3166 > /dev/null ; then
		result=yes
	else
		result=no
		have_iso_codes=no
	fi
	AC_MSG_RESULT([$result])
fi

dnl glib-genmarshal
GLIB_GENMARSHAL=`$PKG_CONFIG --variable=glib_genmarshal glib-2.0`
AC_SUBST(GLIB_GENMARSHAL)

dnl GSettings
GLIB_GSETTINGS


dnl
dnl Check if src should be build with the debug mode
dnl
AC_ARG_ENABLE(debug, 
	[  --enable-debug          debug [default=no]],
	use_debug="Yes";
	AC_DEFINE([debug], [1], [Enable debug mode]), use_debug="No")

dnl
dnl Check if src should be build with the debug_signals mode
dnl
AC_ARG_ENABLE(debug-signal, 
	[  --enable-debug-signal   debug signals sent [default=no]],
	use_debug_sig="Yes";
	AC_DEFINE([debug_signal], [1], [Enable debug signal tracing]), use_debug_sig="No")

dnl

dnl
if test "x$GCC" = "xyes"; then
	CFLAGS="${CFLAGS:--Wall}"
	if test "x$use_debug" = "xYes"; then
   	   CFLAGS="$CFLAGS -g -O0"
	fi
fi




AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_CONFIG_FILES([
Makefile
src/Makefile
gui/Makefile
po/Makefile.in
mime/Makefile
gconf/Makefile
tests/Makefile
gnomint.spec
])
AC_OUTPUT

dnl
dnl Print a little note
dnl
echo "

Configure summary:

	Source code location .......: ${srcdir}
	Compiler ...................: ${CC}
	Compiler flags .............: ${CFLAGS}
	Installing into prefix .....: ${prefix}
	ALL_LINGUAS ................: ${ALL_LINGUAS}

Type make to build ${PACKAGE_STRING}

"

AC_PREREQ([2.64])

AC_INIT(gnoMint, [1.3.0], [<davefx@gmail.com>], gnomint)

PACKAGE_COPYRIGHT="(c) 2006-2016 David Marín Carreño <davefx@gmail.com>"
PACKAGE_WEBSITE="http://gnomint.sourceforge.net"
PACKAGE_AUTHORS=$(cat AUTHORS | tr '\n' ',' | sed 's/,/\\n/g')
AC_DEFINE_UNQUOTED(PACKAGE_COPYRIGHT, "$PACKAGE_COPYRIGHT")
AC_DEFINE_UNQUOTED(PACKAGE_WEBSITE, "$PACKAGE_WEBSITE")
AC_DEFINE_UNQUOTED(PACKAGE_AUTHORS, "$PACKAGE_AUTHORS")

AM_INIT_AUTOMAKE([1.12 foreign])

AC_CONFIG_MACRO_DIR([m4])
dnl Put the ACLOCAL flags in the Makefile
AC_SUBST([ACLOCAL_AMFLAGS], ["-I $ac_macro_dir \${ACLOCAL_FLAGS}"])

dnl Initialize maintainer mode
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

# Check for programs
AC_ISC_POSIX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AM_PROG_CC_C_O

# Checks for header files.
AC_HEADER_STDC
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
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE")
AC_DEFINE_UNQUOTED(BONOBO_EXPLICIT_TRANSLATION_DOMAIN, "$GETTEXT_PACKAGE")
ALL_LINGUAS="ca cs de es fi fr it pt_BR oc ru sk sv"
AM_GLIB_GNU_GETTEXT
AM_GLIB_DEFINE_LOCALEDIR(PACKAGE_LOCALE_DIR)
AC_PROG_INTLTOOL([0.23])

# required versions
GNUTLS_REQUIRED=2.0
GNUTLS_ADVANCED_FEATURES_MINIMUM_VERSION=2.7.4
SQLITE_REQUIRED=3.0
GLIB_REQUIRED=2.6.0
GCONF_REQUIRED=2.0
GTK_REQUIRED=2.12.0
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
	gconf-2.0 >= $GCONF_REQUIRED \
	gtk+-2.0 >= $GTK_REQUIRED \
	gdk-pixbuf-2.0 \
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

AC_TRY_LINK(,,[	READLINE_LIBS="-lreadline" ],[ 
                LIBS="$LIBS -ltermcap" 
		AC_TRY_LINK(,,[ READLINE_LIBS="-lreadline -ltermcap" ],[
			AC_MSG_ERROR([Cannot figure out how to link with the readline library; see config.log for more information])
		])
])

LIBS=$old_LIBS

AC_SUBST(READLINE_LIBS)

PKG_CHECK_MODULES(GNOMINTCLI, 
	glib-2.0 >= $GLIB_REQUIRED \
	gconf-2.0 >= $GCONF_REQUIRED \
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
   	AC_DEFINE_UNQUOTED(ADVANCED_GNUTLS, "yes")
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

dnl The following conditional is set in AM_GCONF_SOURCE_2.
dnl Because we may skip its execution, we have to set a default here.
m4_pattern_allow([^AM_GCONF_SOURCE_2$])
AM_CONDITIONAL([GCONF_SCHEMAS_INSTALL], [false])
GCONFTOOL=""
AC_CHECK_PROG(GCONFTOOL, gconftool-2, gconftool-2)
if test x"$GCONFTOOL" = x; then
	AC_MSG_ERROR([gconftool-2 executable not found in your path - should be installed with GConf])
fi
AM_GCONF_SOURCE_2


dnl
dnl Check if src should be build with the debug mode
dnl
AC_ARG_ENABLE(debug, 
	[  --enable-debug          debug [default=no]],
	use_debug="Yes";
	AC_DEFINE(debug), use_debug="No")

dnl
dnl Check if src should be build with the debug_signals mode
dnl
AC_ARG_ENABLE(debug-signal, 
	[  --enable-debug-signal   debug signals sent [default=no]],
	use_debug_sig="Yes";
	AC_DEFINE(debug_signal), use_debug_sig="No")

dnl

dnl
if test "x$GCC" = "xyes"; then
	CFLAGS="-Wall -Werror "
	if test "x$use_debug" = "xYes"; then
   	   CFLAGS="$CFLAGS -g -O0"
	fi
fi




AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_OUTPUT([
Makefile
src/Makefile
m4/Makefile
gui/Makefile
po/Makefile.in
mime/Makefile
gconf/Makefile
gnomint.spec
])

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

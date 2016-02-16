
AC_PREREQ(2.59)
AC_COPYRIGHT([
See the included file: LICENSE for copyright information.
])
AC_INIT(src/pam_hipchat.c, 0.1.0, [philip@martinfami.ly])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/pam_hipchat.c])
AC_CONFIG_HEADER([config.h])

dnl --------------------------------------------------------------------
dnl Default prefix
test "x${prefix}" = "xNONE" && prefix="/usr/local"
test "x${exec_prefix}" = "xNONE" && exec_prefix="${prefix}"

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

AC_SUBST(PAMDIR, "/lib/security")

AC_ARG_WITH(pam-dir,
	AC_HELP_STRING([--with-pam-dir=DIR],
			       [Where to install PAM module [[PREFIX/lib/security]]]
				  ),
	[case "${withval}" in
		/*) PAMDIR="${withval}";;
		./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
		*)  PAMDIR="/lib/${withval}";;
	 esac]
)

dnl --------------------------------------------------------------------
dnl Checks for libraries.
AC_CHECK_LIB(pam, pam_start, curl)

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([string.h syslog.h unistd.h stdio.h stdlib.h ctype.h curl/curl.h security/pam_appl.h security/pam_modules.h])

dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST


dnl --------------------------------------------------------------------
dnl Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_VPRINTF
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([strlen strdup])

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

AC_CONFIG_MACRO_DIR([m4])
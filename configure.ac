dnl Process this file with autoconf to produce a configure script.
AC_INIT([rtp2httpd],[1.0])
AC_CONFIG_SRCDIR([src/rtp2httpd.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)

dnl Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])
AC_CHECK_HEADERS(stdio.h stdlib.h sys/types.h sys/socket.h netdb.h \
		 stdarg.h errno.h sys/select.h fcntl.h string.h signal.h \
		 sys/wait.h strings.h netinet/in.h arpa/inet.h, ,  
		 AC_MSG_ERROR(Cannot find all required headers))

AC_CHECK_FUNCS(getopt_long getaddrinfo getnameinfo strndup, ,
	       AC_MSG_ERROR(Required functions missing))

# Config location for code to default to
CONFFILE_DIR=$sysconfdir
CONFFILE_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$CONFFILE_DIR"
)`
AC_DEFINE_UNQUOTED(CONFPATH, "$CONFFILE_DIR", system config directory)

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT

echo -e "\nAll done. Run make now."

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([passmanager], [3.2.8])
AC_CONFIG_SRCDIR([src/passmanager.c])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

: ${CFLAGS="-g -Wall -Wextra -pedantic -Wno-self-assign"}

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_LIB(cap,[main], [], [AC_MSG_ERROR(libcap not found)])
#AC_CHECK_LIB(Xmu,[main], [], [AC_MSG_ERROR(libXmu not found)])
#AC_CHECK_LIB(X11,[main], [], [AC_MSG_ERROR(libX11 not found)])

AC_ARG_ENABLE([x11],
            [AS_HELP_STRING([--disable-x11],
              [use xclip binary instead of integrated X11 code to send passwords to clipboard])],
            [with_x11=no],
            [with_x11=yes])
          
          LIBS=
          AS_IF([test "x$with_x11" != xno],
            [AC_CHECK_LIB([X11], [main],
              [AC_SUBST([LIBS], ["-lX11"])
               AC_DEFINE([HAVE_LIBX11], [1],
                         [Define if you have libX11])
              ],
              [AC_MSG_FAILURE(
                 [x11 development files needed for clipboard functions (--disable-x11 to disable)])])])

dnl Order matters!
  if test "$PORTNAME" != "win32"; then
     AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [], [AC_MSG_ERROR([library 'crypto' is required for OpenSSL])])
     FOUND_SSL_LIB="no"
     AC_CHECK_LIB(ssl, OPENSSL_init_ssl, [FOUND_SSL_LIB="yes"])
     AC_CHECK_LIB(ssl, SSL_library_init, [FOUND_SSL_LIB="yes"])
     AS_IF([test "x$FOUND_SSL_LIB" = xno], [AC_MSG_ERROR([library 'ssl' is required for OpenSSL])])
  else
     AC_SEARCH_LIBS(CRYPTO_new_ex_data, eay32 crypto, [], [AC_MSG_ERROR([library 'eay32' or 'crypto' is required for OpenSSL])])
     FOUND_SSL_LIB="no"
     AC_SEARCH_LIBS(OPENSSL_init_ssl, ssleay32 ssl, [FOUND_SSL_LIB="yes"])
     AC_SEARCH_LIBS(SSL_library_init, ssleay32 ssl, [FOUND_SSL_LIB="yes"])
     AS_IF([test "x$FOUND_SSL_LIB" = xno], [AC_MSG_ERROR([library 'ssleay32' or 'ssl' is required for OpenSSL])])
  fi

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdlib.h string.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpass memset])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([passmanager], [3.2.9])
AC_CONFIG_SRCDIR([src/passmanager.c])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

: ${CFLAGS="-g -Wall -Wextra -pedantic -Wno-overlength-strings -Wno-self-assign -fsanitize=undefined"}

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_LIB(cap,[main], [], [AC_MSG_ERROR(libcap not found)])
#AC_CHECK_LIB(Xmu,[main], [], [AC_MSG_ERROR(libXmu not found)])
#AC_CHECK_LIB(X11,[main], [], [AC_MSG_ERROR(libX11 not found)])

AC_ARG_ENABLE([x11],
            [AS_HELP_STRING([--disable-x11],
              [use xsel binary instead of integrated X11 code to send passwords to clipboard])],
            [with_x11=no],
            [with_x11=yes])
          
          X11LIB=
          AS_IF([test "x$with_x11" != xno],
            [AC_CHECK_LIB([X11], [main],
              [AC_SUBST([X11LIB], ["-lX11"])
               AC_DEFINE([HAVE_LIBX11], [1],
                         [Define if you have libX11])
              ],
              [AC_MSG_FAILURE(
                 [x11 development files needed for clipboard functions (--disable-x11 to disable)])])])
                 
AC_ARG_ENABLE([xmu],
            [AS_HELP_STRING([--disable-xmu],
              [disable ability to send to clipboard instead of primary selection])],
            [with_xmu=no],
            [with_xmu=yes])
          
          XMULIB=
          AS_IF([test "x$with_xmu" != xno],
            [AC_CHECK_LIB([Xmu], [main],
              [AC_SUBST([XMULIB], ["-lXmu"])
               AC_DEFINE([HAVE_LIBXMU], [1],
                         [Define if you have libXmu])
              ],
              [AC_MSG_FAILURE(
                 [Xmu development files needed for some clipboard functions (--disable-xmu to disable)])])])
LIBS="$X11LIB $XMULIB"

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

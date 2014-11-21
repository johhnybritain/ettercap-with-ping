dnl Process this file with autoconf to produce a configure script.
AC_INIT
AC_CONFIG_SRCDIR([lft_ifname.h])
AC_CONFIG_HEADER(config/acconfig.h)
AC_CONFIG_AUX_DIR([config])
dnl This keeps configure quiet about the datarootdir setting
AC_DEFUN([AC_DATAROOTDIR_CHECKED])

AC_DIAGNOSE([obsolete],[AC_CYGWIN is obsolete: use AC_CANONICAL_HOST and check if $host_os
matches *cygwin*])dnl
AC_CANONICAL_HOST
case $host_os in
  *cygwin* ) CYGWIN=yes;;
	 * ) CYGWIN=no;;
esac


AC_DEFINE_UNQUOTED(HOST_SYSTEM_TYPE, "$host")

dnl Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL

AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, connect)
AC_CHECK_LIB(resolv, inet_aton)
AC_CHECK_LIB(m, sin)

# Checks for header files and functions
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_ALLOCA
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select setenv socket strchr strdup strstr])

dnl OS specific checks
case "$host" in
*darwin*)
  AC_DEFINE(BSD_IP_STACK)
  dnl we need to define DARWIN to turn off
  dnl some BSD-type features like BIOC_IMMEDIATE
  AC_DEFINE(DARWIN)
;;
*netbsd*)
  AC_DEFINE(BSD_IP_STACK)
  dnl we need to define NETBSD to turn off
  dnl some BSD-type features like BIOC_IMMEDIATE
  AC_DEFINE(NETBSD)
;;
*openbsd*)
  AC_DEFINE(OPENBSD)
  AC_DEFINE(BSD_IP_STACK)
;;
*bsd*)
  AC_DEFINE(BSD_IP_STACK)
;;
*linux*)
  AC_DEFINE(_BSD_SOURCE)
;;
*solaris*)
  dnl some versions of solaris need special treatment
  dnl for the th_sum field, and it varies
  dnl between versions...
  case "$host" in
  *solaris2.4*)
    AC_DEFINE(SOLARIS_LENGTH_IN_CHECKSUM)
    ;;
  *solaris2.5*)
    AC_DEFINE(SOLARIS_LENGTH_IN_CHECKSUM)
    ;;
  esac
;;
esac


case "$host" in
*cygwin*)
: we do not require pcap, but we do require special win32 libraries.
LIBS="-lws2_32 $LIBS"
;;
*)

dnl Option to build universal binaries on Mac OS X
AC_ARG_ENABLE(universal,[  --enable-universal      whether to include intel and ppc arch for Mac OS X],[UNIVERSAL="$enableval"],[UNIVERSAL="no"])

dnl Option to enable gettimeofday checks in addition to pcap header timestamp
AC_ARG_ENABLE(gtod,[  --enable-gtod           use gettimeofday instead of pcap timestamps], [GTOD="$enableval"],[GTOD="no"])


dnl Make sure we have pcap
AC_ARG_WITH(pcap,
[  --with-pcap=PATH        specify path to pcap library],
    [
        AC_MSG_CHECKING(for --with-pcap option)
        case "$withval" in
          yes|no)
            AC_MSG_ERROR(PATH required with pcap option)
            ;;
          *)
            if test '!' -d "$withval"; then
                AC_MSG_ERROR($withval does not exist!)
            else
                AC_MSG_RESULT($withval)
                if test -d "$withval/include"; then
                  CFLAGS="$CFLAGS -I$withval/include"
                  CPPFLAGS="$CPPFLAGS -I$withval/include"
                else
                  CFLAGS="$CFLAGS -I$withval"
                  CPPFLAGS="$CPPFLAGS -I$withval"
                fi
                if test -d "$withval/lib"; then
                  LIBS="$LIBS -L$withval/lib"
                else
                  LIBS="$LIBS -L$withval"
                fi
            fi
            ;;
          esac
    ]
)


for incdir in /usr/local/include /usr/include
do
  if test -d $incdir/pcap
  then
    CFLAGS="$CFLAGS -I$incdir/pcap"
    CPPFLAGS="$CFLAGS -I$incdir/pcap"
  fi
done

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#       include <sys/types.h>
#       include <sys/socket.h>]], [[u_int i = sizeof(((struct sockaddr *)0)->sa_len)]])],[AC_DEFINE(HAVE_SOCKADDR_SA_LEN)],[])


AC_CHECK_LIB(pcap, pcap_lookupdev, , [
        AC_MSG_ERROR([
Can't find the pcap library (libpcap.a); install the pcap library (from
ftp://ftp.ee.lbl.gov/libpcap.tar.Z ) and/or use
--with-pcap to specify the path to it on your system

When installing libpcap do both 'make install' and 'make install-incl'])
])

AC_CHECK_HEADER(pcap.h, , [
        AC_MSG_ERROR([
Can't find pcap.h; install the pcap library (from
ftp://ftp.ee.lbl.gov/libpcap.tar.Z ) and/or use
--with-pcap to specify the path to it on your system

When installing libpcap do both 'make install' and 'make install-incl'])
])

esac

dnl Set universal binary options
AC_MSG_CHECKING(if we should build universal binaries)
if test "$UNIVERSAL" = "yes"; then
  case $host_os in 
    *darwin* )
      CFLAGS="$CFLAGS -arch i386 -arch ppc"
      LDFLAGS="$LDFLAGS -arch i386 -arch ppc"
      AC_DEFINE(UNIVERSAL)
      AC_MSG_RESULT([yes])
    ;;
  esac
else
  AC_MSG_RESULT([no])
fi

dnl Use gettimeofday() on each packet 
AC_MSG_CHECKING(if we should gettimeofday for each packet)
if test "$GTOD" = "yes"; then
  AC_DEFINE(USE_GTOD)
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

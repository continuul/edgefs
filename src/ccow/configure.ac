dnl Process this file with autoconf to produce a configure script.
AC_INIT(ccow, 1.0.0)
AC_CONFIG_HEADER(src/include/config.h)
AC_CONFIG_SRCDIR(src/README)
AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])
AC_PROG_CC
AC_LANG_C
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_MSG_CHECKING([whether to include systemtap tracing support])
AC_ARG_ENABLE([systemtap],
              [AS_HELP_STRING([--enable-systemtap],
                              [Enable inclusion of systemtap trace support])],
              [ENABLE_SYSTEMTAP="${enableval}"], [ENABLE_SYSTEMTAP='yes'])
AM_CONDITIONAL([ENABLE_SYSTEMTAP], [test x$ENABLE_SYSTEMTAP = xyes])
AC_MSG_RESULT(${ENABLE_SYSTEMTAP})

if test "x${ENABLE_SYSTEMTAP}" = xyes; then
  # Additional configuration for --enable-systemtap is HERE
  AC_CHECK_PROGS(DTRACE, dtrace)
  if test -z "$DTRACE"; then
    AC_MSG_ERROR([dtrace not found, install the systemtap-sdt-dev package])
  fi
  AC_CHECK_HEADER([sys/sdt.h], [SDT_H_FOUND='yes'],
                [SDT_H_FOUND='no';
                   AC_MSG_ERROR([systemtap support needs sys/sdt.h header])])
  AC_DEFINE([HAVE_SYSTEMTAP], [1], [Define to 1 if using SystemTap probes.])
  AC_ARG_WITH([tapset-install-dir],
      [AS_HELP_STRING([--with-tapset-install-dir],.
         [The absolute path where the tapset dir will be installed])],
      [if test "x${withval}" = x; then
         ABS_TAPSET_DIR="\$(datadir)/systemtap/tapset"
      else
         ABS_TAPSET_DIR="${withval}"
      fi], [ABS_TAPSET_DIR="\$(datadir)/systemtap/tapset"])
  AC_SUBST(ABS_TAPSET_DIR)
fi

dnl CCOW_COMPILABLE(label, hcode, mcode, rvar)
dnl
dnl Use AC_LINK_IFELSE() rather than AC_COMPILE_IFELSE() so that linker errors
dnl cause failure.
AC_DEFUN([CCOW_COMPILABLE],
[
AC_CACHE_CHECK([whether $1 is compilable],
               [$4],
               [AC_LINK_IFELSE([AC_LANG_PROGRAM([$2],
                                                [$3])],
                               [$4=yes],
                               [$4=no])])
])

dnl ================= ccow_error_injection begin ==========================
AC_ARG_ENABLE([ccow-error-injection],
    [  --enable-ccow-error-injection    enable ccow error injection],
    [ccow_error_injection=yes],
    [ccow_error_injection=no])
CCOW_EI_CPPFLAGS=
CCOW_EI_LIB=

if test "x${ccow_error_injection}" = xyes; then
	CCOW_EI_CPPFLAGS="-DCCOW_EI"
else
	CCOW_EI_CPPFLAGS=""
fi

dnl ================= address_sanitizer begin ==========================
AC_ARG_ENABLE([address-sanitizer],
    [  --disable-address-sanitizer    disable address sanitizer compiler instrumentation],
    [address_sanitizer=${enableval}],
    [address_sanitizer=yes])
dnl ================= jemalloc begin ==========================
AC_ARG_ENABLE([jemalloc],
    [  --disable-jemalloc    disable use of jemalloc],
    [jemalloc=${enableval}],
    [jemalloc=yes])

ASAN_CPPFLAGS=
ASAN_LIB=
if test "x${address_sanitizer}" = xyes; then
        ASAN_CPPFLAGS="-fsanitize=address -fno-omit-frame-pointer -fno-common"
        ASAN_LDFLAGS="-fsanitize=address -fno-omit-frame-pointer -fno-common"
        if test "x${CC}" = xclang; then
                ASAN_LIB=
        else
                ASAN_LIB=-lasan
        fi
elif test "x${jemalloc}" = xyes; then
        ASAN_CPPFLAGS="-DUSE_JE_MALLOC -fno-omit-frame-pointer"
        ASAN_LDFLAGS=
        ASAN_LIB=-ljemalloc
else
        ASAN_CPPFLAGS="-fno-omit-frame-pointer"
        ASAN_LDFLAGS=
        ASAN_LIB=
fi

dnl ================= debug mode begin ==========================
AC_ARG_ENABLE([debug],
    [  --disable-debug         disable debug mode],
    [debug_mode=${enableval}],
    [debug_mode=yes])

ENV_CFLAGS=
if test "x${debug_mode}" = xyes; then
	ENV_CFLAGS="-O0"
else
	ENV_CFLAGS="-O2 -DNEDGE_NDEBUG"
fi
AC_SUBST(ASAN_LIB)

dnl Support Valgrind by default.
AC_ARG_ENABLE([valgrind],
  [AS_HELP_STRING([--enable-valgrind], [Enable support for Valgrind])],
[if test "x$enable_valgrind" = "xno" ; then
  enable_valgrind="0"
else
  enable_valgrind="1"
fi
],
[enable_valgrind="0"]
)
if test "x$enable_valgrind" = "x1" ; then
  CCOW_COMPILABLE([valgrind], [
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>

#if !defined(VALGRIND_RESIZEINPLACE_BLOCK)
#  error "Incompatible Valgrind version"
#endif
], [], [je_cv_valgrind])
  if test "x${je_cv_valgrind}" = "xno" ; then
    enable_valgrind="0"
  fi
  if test "x$enable_valgrind" = "x1" ; then
    AC_DEFINE([CCOW_VALGRIND], [], [Valgrind support])
  fi
fi
AC_SUBST([enable_valgrind])

AC_SUBST([AM_LDFLAGS], ["$ASAN_LDFLAGS"])
AC_SUBST([AM_CPPFLAGS], ["-I\$(top_srcdir)/include -pthread -fPIC -g -std=gnu99 $ENV_CFLAGS -Wall -Wstrict-aliasing=0 -Wendif-labels -Wpointer-arith -Wbad-function-cast -Wcast-align -Wextra -Wno-missing-field-initializers -Wno-unused-variable -Wno-unused-parameter -Wno-cast-align -Wno-unused-function -D_GNU_SOURCE -DINSTALL_PREFIX=\"$prefix\" $ASAN_CPPFLAGS $CCOW_EI_CPPFLAGS"])
AC_SUBST(VERSION)
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	tools/Makefile
	test/Makefile
])
m4_include([src/configure.ac.m4])
AC_OUTPUT

#            _       _
#  _ __ ___ (_)_ __ | | __
# | '_ ` _ \| | '_ \| |/ /
# | | | | | | | | | |   <
# |_| |_| |_|_|_| |_|_|\_\
#
# SPDX-License-Identifier: MIT
#

AC_PREREQ([2.68])
AC_INIT([mink], [1.0], [damir.franusic@gmail.com], , [https://github.com/link-mink])
config_flags="$*"
AC_DEFINE_UNQUOTED([CONFIG_FLAGS],["$config_flags"],[Flags passed to configure])
AC_SUBST(CONFIG_FLAGS, "$config_flags")
AM_INIT_AUTOMAKE([foreign subdir-objects nostdinc])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_LANG([C++])

AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11([noext], [mandatory])
AC_PROG_AWK
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_CPP
AC_PROG_SED
AC_CHECK_PROG(GPERF, gperf, gperf)
AS_IF([test -z "$GPERF"], [AC_MSG_ERROR([gperf not found!])])
AC_USE_SYSTEM_EXTENSIONS
PKG_PROG_PKG_CONFIG
LT_INIT

# antlr3c
AC_MSG_NOTICE([Enabling bundled antlr3c])
AC_CONFIG_SUBDIRS([lib/libantlr3c-3.4])

# enable DEBUG mode
AC_ARG_ENABLE(debug, 
              [AS_HELP_STRING([--enable-debug], [enable DEBUG mode (include debug symbols and disable optimizations) [default=no]])])
AM_CONDITIONAL(ENABLE_DEBUG, test "x$enable_debug" = "xyes")

# mink debug
AC_ARG_ENABLE(mdebug, 
              [AS_HELP_STRING([--enable-mdebug], [enable MINK DBUEG mode [default=no]])])
AM_CONDITIONAL(ENABLE_PMDEBUG, test "x$enable_mdebug" = "xyes")

# clock_gettime
AC_CHECK_LIB([rt], [clock_gettime], , AC_MSG_ERROR([clock_gettime not found!]))

# check for ncurses
AC_CHECK_LIB([ncurses], [mvwinchstr], , AC_MSG_ERROR([ncursesnot found!]))

# pthread
AC_CHECK_LIB([pthread], [pthread_create], , AC_MSG_ERROR([pthread library not found!]))
# sctp
AC_CHECK_LIB([sctp], [sctp_send], , AC_MSG_ERROR([sctp library not found!]))
# Checks for header files.
AC_CHECK_HEADERS([      arpa/inet.h \
                        fcntl.h \
                        inttypes.h \
                        locale.h \
                        netdb.h \
                        netinet/in.h \
                        stddef.h \
                        stdint.h \
                        stdlib.h \
                        string.h \
                        strings.h \
                        sys/ioctl.h \
                        sys/socket.h \
                        sys/time.h \
                        sys/timeb.h \
                        syslog.h \
                        pthread.h \
                        curses.h \
                        unistd.h], , AC_MSG_ERROR([Header file missing!]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm \
                atexit \
                bzero \
                gethostname \
                gettimeofday \
                inet_ntoa \
                isascii \
                localtime_r \
                memmove \
                memset \
                mkdir \
                mkfifo \
                pow \
                select \
                poll \
                setenv \
                socket \
                strchr \
                strdup \
                strerror \
                strncasecmp \
                strstr \
                strtoul \
                strtoull \
                sysinfo], , AC_MSG_ERROR([System function missing!]))

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

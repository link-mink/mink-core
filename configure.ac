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
AC_USE_SYSTEM_EXTENSIONS
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
AX_BOOST_BASE([1.74], [], [AC_MSG_ERROR([Minimum required Boost version not found!])])
AC_USE_SYSTEM_EXTENSIONS
AS_IF([test -z "$GPERF"], [AC_MSG_ERROR([gperf not found!])])
PKG_PROG_PKG_CONFIG
LT_INIT

# save libs
COMMON_LIBS=$LIBS

# enable DEBUG mode
AC_ARG_ENABLE(debug, 
              [AS_HELP_STRING([--enable-debug], [enable DEBUG mode (include debug symbols and disable optimizations) [default=no]])])
AM_CONDITIONAL(ENABLE_DEBUG, test "x$enable_debug" = "xyes")

# mink debug
AC_ARG_ENABLE(mdebug, 
              [AS_HELP_STRING([--enable-mdebug], [enable MINK DBUEG mode [default=no]])],,
              [enable_mdebug=no])
AM_CONDITIONAL(ENABLE_MDEBUG, test "x$enable_mdebug" = "xyes")
if test "x$enable_mdebug" != "xno"; then
    AC_DEFINE([ENABLE_MDEBUG], [1], [Enable MINK debug mode])
fi
# configd
AC_ARG_ENABLE(configd, 
              [AS_HELP_STRING([--enable-configd], [Enable CONFIGD [default=no]])],,
              [enable_configd=no])
AM_CONDITIONAL(ENABLE_CONFIGD, test "x$enable_configd" = "xyes")
if test "x$enable_configd" != "xno"; then
    AC_DEFINE([ENABLE_CONFIGD], [1], [Enable CONFIGD])
    # antlr3c
    AC_MSG_NOTICE([Enabling bundled antlr3c])
    AC_CONFIG_SUBDIRS([lib/libantlr3c-3.4])
fi

# gRPC
AC_ARG_ENABLE(grpc, 
              [AS_HELP_STRING([--enable-grpc], [Enable GRPC [default=no]])],,
              [enable_grpc=no])
AM_CONDITIONAL(ENABLE_GRPC, test "x$enable_grpc" = "xyes")
if test "x$enable_grpc" != "xno"; then
    PKG_CHECK_MODULES([GRPC], [grpc++], [], [AC_MSG_ERROR([gRPC not found!])])
    AC_DEFINE([ENABLE_GRPC], [1], [Enable GRPC])
    # protobuf
    PKG_CHECK_MODULES([PROTOBUF], [protobuf], [], [AC_MSG_ERROR([protobuf not found!])])
fi

# json rpc
AC_ARG_ENABLE(jrpc, 
              [AS_HELP_STRING([--enable-jrpc], [Enable JRPC [default=no]])],,
              [enable_jrpc=no])
AM_CONDITIONAL(ENABLE_JRPC, test "x$enable_jrpc" = "xyes")
if test "x$enable_grpc" != "xno"; then
    AC_DEFINE([ENABLE_JRPC], [1], [Enable JRPC])
fi

# sysagent
AC_ARG_ENABLE(sysagent, 
              [AS_HELP_STRING([--enable-sysagent], [Enable SYSAGENT [default=no]])],,
              [enable_sysagent=no])
AM_CONDITIONAL(ENABLE_SYSAGENT, test "x$enable_sysagent" = "xyes")
if test "x$enable_sysagent" != "xno"; then
    AC_DEFINE([ENABLE_SYSAGENT], [1], [Enable mink sysagent])
    AC_CHECK_LIB([procps], 
                 [readproc], 
                 [AC_SUBST([PROCPS_LIBS], ["-lprocps"])],
                 [AC_MSG_ERROR([procps library not found!])])

    AC_CHECK_LIB([sqlite3], 
                 [sqlite3_open], 
                 [AC_SUBST([SQLITE_LIBS], ["-lsqlite3"])],
                 [AC_MSG_ERROR([sqlite3 library not found!])])

fi

# gdt trapc
AC_ARG_ENABLE(gdttrapc, 
              [AS_HELP_STRING([--enable-gdttrapc], [Enable GDTTRAPC [default=no]])],,
              [enable_gdttrapc=no])
AM_CONDITIONAL(ENABLE_GDTTRAPC, test "x$enable_gdttrapc" = "xyes")
if test "x$enable_gdttrapc" != "xno"; then
    AC_DEFINE([ENABLE_GDTTRAPC], [1], [Enable mink gdttrapc])
fi


# codegen
AC_ARG_ENABLE(codegen, 
              [AS_HELP_STRING([--enable-codegen], [Enable mink codegen [default=no]])],,
              [enable_codegen=no])
AM_CONDITIONAL(ENABLE_CODEGEN, test "x$enable_codegen" = "xyes")
if test "x$enable_codegen" != "xno"; then
    AC_DEFINE([ENABLE_CODEGEN], [1], [Enable mink codegen])
fi

# CLIPS
AC_ARG_ENABLE(clips,
              [AS_HELP_STRING([--enable-clips], [Enable CLIPS support [default=no]])],,
              [enable_clips=no])
AM_CONDITIONAL(ENABLE_CLIPS, test "x$enable_clips" = "xyes")
if test "x$enable_clips" != "xno"; then
    AC_DEFINE([ENABLE_CLIPS], [1], [Enable CLIPS support])
    AC_CHECK_LIB([clips], 
                 [CreateEnvironment], 
                 [AC_SUBST([CLIPS_LIBS], ["-lclips"])],
                 [AC_MSG_ERROR([CLIPS library not found!])])
fi 

# openssl
AC_ARG_ENABLE(openssl,
              [AS_HELP_STRING([--enable-openssl], [Enable OPENSSL support [default=no]])],,
              [enable_openssl=no])
AM_CONDITIONAL(ENABLE_OPENSSL, test "x$enable_openssl" = "xyes")
if test "x$enable_openssl" != "xno"; then
    AC_DEFINE([ENABLE_OPENSSL], [1], [Enable OPENSSL support])

    # libcrypto
    AC_CHECK_LIB([crypto],
                 [CRYPTO_new_ex_data], 
                 [AC_SUBST([CRYPTO_LIBS], ["-lcrypto"])],
                 [AC_MSG_ERROR([crypto library not found])])

    FOUND_SSL_LIB="no"
    # check with OPENSSL_init_ssl method
    AC_CHECK_LIB([ssl],
                 [OPENSSL_init_ssl], [
                    AC_SUBST([SSL_LIBS], ["-lssl"]) 
                    [FOUND_SSL_LIB="yes"]
                 ])

    # check with SSL_library_init method
    AC_CHECK_LIB([ssl],
                 [SSL_library_init], [
                    AC_SUBST([SSL_LIBS], ["-lssl"]) 
                    [FOUND_SSL_LIB="yes"]
                 ])

    if test "x$FOUND_SSL_LIB" = "xno"; then
        AC_MSG_ERROR([SSL library not found])
    fi 

fi 

# enable tlsv1_2
AC_ARG_ENABLE(tlsv12,
             [AS_HELP_STRING([--enable-tlsv12], [Enable TLSv1_2 [default=no]])],,
             [enable_tlsv12=no])
   
AM_CONDITIONAL(ENABLE_TLSV12, test "x$enable_tlsv12" = "xyes")
if test "x$enable_tlsv12" != "xno"; then
    AC_DEFINE([ENABLE_TLSV12], [1], [Enable TLSv1_2 support])
fi

# enable single user session
AC_ARG_ENABLE(ws-single-session,
             [AS_HELP_STRING([--enable-ws-single-session], [Enable WS SINGLE SESSION [default=no]])],,
             [enable_ws_single_session=no])
   
AM_CONDITIONAL(ENABLE_WS_SINGLE_SESSION, test "x$enable_ws_single_session" = "xyes")
if test "x$enable_ws_single_session" != "xno"; then
    AC_DEFINE([ENABLE_WS_SINGLE_SESSION], [1], [Enable WS SINGLE SESSION])
fi

# enable WS (unencrypted)
AC_ARG_ENABLE(plain-ws,
             [AS_HELP_STRING([--enable-plain-ws], [Enable Plain WS (no encryption) [default=no]])],,
             [enable_plain_ws=no])
   
AM_CONDITIONAL(ENABLE_PLAIN_WS, test "x$enable_plain_ws" = "xyes")
if test "x$enable_plain_ws" != "xno"; then
    AC_DEFINE([ENABLE_PLAIN_WS], [1], [Enable Plain WS (no encryption)])
fi

# openwrt
AC_ARG_ENABLE(openwrt,
              [AS_HELP_STRING([--enable-openwrt], [Enable OpenWrt support [default=no]])],,
              [enable_openwrt=no])
AM_CONDITIONAL(ENABLE_OPENWRT, test "x$enable_openwrt" = "xyes")
if test "x$enable_openwrt" != "xno"; then
    AC_DEFINE([ENABLE_OPENWRT], [1], [Enable OpenWrt support])
    AC_CHECK_LIB([ubus], 
                 [ubus_connect], 
                 [AC_SUBST([UBUS_LIBS], ["-lubus"])],
                 [AC_MSG_ERROR([ubus library not found!])])

    AC_CHECK_LIB([ubox], 
                 [blob_buf_init],
                 [AC_SUBST([UBOX_LIBS], ["-lubox"])],
                 [AC_MSG_ERROR([ubox library not found!])])

    AC_CHECK_LIB([blobmsg_json], 
                 [blobmsg_add_object],
                 [AC_SUBST([BLOBMSG_JSON_LIBS], ["-lblobmsg_json"])],
                 [AC_MSG_ERROR([blobmsg_json library not found!])])

    AC_CHECK_LIB([json-c],
                 [json_tokener_new],
                 [AC_SUBST([JSONC_LIBS], ["-ljson-c"])],
                 [AC_MSG_ERROR([json-c library not found!])])

fi

# clock_gettime
AC_CHECK_LIB([rt], [clock_gettime], , AC_MSG_ERROR([clock_gettime not found!]))

# check for ncurses
AC_CHECK_LIB([ncurses], 
             [mvwinchstr],
             [AC_SUBST([NCURSES_LIBS], ["-lncurses"])],
             [AC_MSG_ERROR([ncurses library not found!])])

# pthread
AC_CHECK_LIB([pthread], [pthread_create], , AC_MSG_ERROR([pthread library not found!]))
# sctp
AC_CHECK_LIB([sctp], 
             [sctp_send], 
             [AC_SUBST([SCTP_LIBS], ["-lsctp"])],
             [AC_MSG_ERROR([sctp library not found!])])

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
                        boost/circular_buffer.hpp \
                        boost/asio/local/stream_protocol.hpp \
                        boost/process.hpp \
                        boost/asio/io_service.hpp \
                        boost/beast/core/detail/base64.hpp \
                        boost/asio/signal_set.hpp \
                        boost/beast/core.hpp \
                        boost/beast/websocket.hpp \
                        boost/beast/websocket/ssl.hpp \
                        boost/beast/ssl.hpp \
                        boost/asio/dispatch.hpp \
                        boost/asio/strand.hpp \
                        boost/asio/buffers_iterator.hpp \
                        boost/optional.hpp \
                        boost/algorithm/string/trim.hpp \
                        boost/range/as_array.hpp \
                        boost/tokenizer.hpp \
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

pkglib_LTLIBRARIES += plg_sysagent_unix.la
plg_sysagent_unix_la_SOURCES = src/services/sysagent/plugins/unix/plg_sysagent_unix.cpp
plg_sysagent_unix_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                ${GRPC_CFLAGS} \
                                -Isrc/proto \
                                -Isrc/services/sysagent
plg_sysagent_unix_la_LDFLAGS = -version-info 1:0:0 \
                               -shared \
                               -module \
                               -export-dynamic

plg_sysagent_unix_la_LIBADD = libjsonrpc.la \
                              ${BOOST_FILESYSTEM_LIB}

pkglib_LTLIBRARIES += plg_sysagent_system.la
plg_sysagent_system_la_SOURCES = %reldir%/plg_system.cpp
plg_sysagent_system_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                  ${GRPC_CFLAGS} \
                                  -Isrc/services/sysagent \
                                  -Isrc/proto
plg_sysagent_system_la_LDFLAGS = -version-info 1:0:0 \
                                 -shared \
                                 -module \
                                 -export-dynamic
plg_sysagent_system_la_LIBADD = libjsonrpc.la \
                                ${PROCPS_LIBS}

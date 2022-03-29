pkglib_LTLIBRARIES += plg_sysagent_systemd.la
plg_sysagent_systemd_la_SOURCES = %reldir%/plg_sysagent_systemd.cpp
plg_sysagent_systemd_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                   ${GRPC_CFLAGS} \
                                   -Isrc/proto
plg_sysagent_systemd_la_LDFLAGS = -version-info 1:0:0 \
                                  -shared \
                                  -module \
                                  -export-dynamic
plg_sysagent_systemd_la_LIBADD = ${SYSTEMD_LIBS}

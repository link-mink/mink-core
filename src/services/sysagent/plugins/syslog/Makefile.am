pkglib_LTLIBRARIES += plg_sysagent_syslog.la
plg_sysagent_syslog_la_SOURCES = src/services/sysagent/plugins/syslog/plg_sysagent_syslog.cpp
plg_sysagent_syslog_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                  ${GRPC_CFLAGS} \
                                  -Isrc/services/sysagent \
                                  -Isrc/proto
plg_sysagent_syslog_la_LDFLAGS = -version-info 1:0:0 -shared -module -export-dynamic

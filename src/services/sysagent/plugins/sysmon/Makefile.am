pkglib_LTLIBRARIES += plg_sysagent_sysmon.la
plg_sysagent_sysmon_la_SOURCES = %reldir%/plg_sysagent_sysmon.cpp
plg_sysagent_sysmon_la_CPPFLAGS = ${COMMON_INCLUDES} ${GRPC_CFLAGS} \
                                 -Isrc/proto \
                                 -Isrc/services/sysagent
plg_sysagent_sysmon_la_LDFLAGS = -version-info 1:0:0 \
                                 -shared \
                                 -module \
                                 -export-dynamic

pkglib_LTLIBRARIES += plg_sysagent_cfgd.la
plg_sysagent_cfgd_la_SOURCES = %reldir%/plg_sysagent_cfgd.cpp
plg_sysagent_cfgd_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                   ${GRPC_CFLAGS} \
                                   -Isrc/proto \
                                   -Isrc/services/sysagent
plg_sysagent_cfgd_la_LDFLAGS = -version-info 1:0:0 \
                                  -shared \
                                  -module \
                                  -export-dynamic

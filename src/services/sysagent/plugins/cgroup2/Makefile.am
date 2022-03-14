pkglib_LTLIBRARIES += plg_sysagent_cgroup2.la
plg_sysagent_cgroup2_la_SOURCES = src/services/sysagent/plugins/cgroup2/plg_sysagent_cgroup2.cpp
plg_sysagent_cgroup2_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                   ${GRPC_CFLAGS} \
                                   -Isrc/proto \
                                   -Isrc/services/sysagent 
plg_sysagent_cgroup2_la_LDFLAGS = -version-info 1:0:0 \
                                  -shared \
                                  -module \
                                  -export-dynamic
plg_sysagent_cgroup2_la_LIBADD = ${BOOST_FILESYSTEM_LIB}

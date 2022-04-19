pkglib_LTLIBRARIES += plg_sysagent_ndpi.la
plg_sysagent_ndpi_la_SOURCES = %reldir%/plg_sysagent_ndpi.cpp
plg_sysagent_ndpi_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                ${GRPC_CFLAGS} \
                                -Isrc/proto \
                                -Isrc/services/sysagent 
plg_sysagent_ndpi_la_LDFLAGS = -version-info 1:0:0 \
                                  -shared \
                                  -module \
                                  -export-dynamic
plg_sysagent_ndpi_la_LIBADD = libjsonrpc.la \
                              ${PCAP_LIBS} \
                              ${NDPI_LIBS}

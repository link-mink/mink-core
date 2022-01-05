pkglib_LTLIBRARIES += plg_sysagent_openwrt.la
plg_sysagent_openwrt_la_SOURCES = src/services/sysagent/plugins/openwrt/plg_sysagent_openwrt.cpp
plg_sysagent_openwrt_la_CPPFLAGS = ${COMMON_INCLUDES} ${GRPC_CFLAGS} -Isrc/proto
plg_sysagent_openwrt_la_LDFLAGS = -version-info 1:0:0 -shared -module -export-dynamic
plg_sysagent_openwrt_la_LIBADD = ${UBUS_LIBS} ${UBOX_LIBS} ${BLOBMSG_JSON_LIBS} ${JSONC_LIBS} ${Z_LIBS}

pkglib_LTLIBRARIES += plg_sysagent_mqtt.la
plg_sysagent_mqtt_la_SOURCES = %reldir%/plg_sysagent_mqtt.cpp
plg_sysagent_mqtt_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                ${GRPC_CFLAGS} \
                                -Isrc/proto \
                                -Isrc/services/sysagent
plg_sysagent_mqtt_la_LDFLAGS = -version-info 1:0:0 \
                               -shared \
                               -module \
                               -export-dynamic
plg_sysagent_mqtt_la_LIBADD = libjsonrpc.la \
                              ${MQTT_LIBS}

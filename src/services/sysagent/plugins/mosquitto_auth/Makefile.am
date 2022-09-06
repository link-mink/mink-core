pkglib_LTLIBRARIES += plg_mosquitto_auth.la
plg_mosquitto_auth_la_SOURCES = %reldir%/plg_mosquitto_auth.cpp
plg_mosquitto_auth_la_CPPFLAGS = ${COMMON_INCLUDES}
plg_mosquitto_auth_la_LDFLAGS = -version-info 1:0:0 \
                                -shared \
                                -module \
                                -export-dynamic
plg_mosquitto_auth_la_LIBADD = libminkdb.la


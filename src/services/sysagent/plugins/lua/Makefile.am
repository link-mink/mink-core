pkglib_LTLIBRARIES += plg_sysagent_lua.la
plg_sysagent_lua_la_SOURCES = %reldir%/plg_sysagent_lua.cpp \
                              %reldir%/mink_lua.cpp
plg_sysagent_lua_la_CPPFLAGS = ${COMMON_INCLUDES} \
                               ${GRPC_CFLAGS} \
                               ${LUA_CFLAGS} \
                               -Isrc/proto \
                               -Isrc/services/sysagent
plg_sysagent_lua_la_LDFLAGS = -version-info 1:0:0 \
                              -shared \
                              -module \
                              -export-dynamic
plg_sysagent_lua_la_LIBADD = libjsonrpc.la \
                             ${LUA_LIBS}

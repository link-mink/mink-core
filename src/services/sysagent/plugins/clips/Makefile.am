pkglib_LTLIBRARIES += plg_sysagent_clips.la
plg_sysagent_clips_la_SOURCES = %reldir%/plg_sysagent_clips.cpp
plg_sysagent_clips_la_CPPFLAGS = ${COMMON_INCLUDES} \
                                 ${GRPC_CFLAGS} \
                                 -Isrc/proto \
                                 -Isrc/services/sysagent \
                                 -Ilib/libclips
plg_sysagent_clips_la_LDFLAGS = -version-info 1:0:0 \
                                -shared \
                                -module \
                                -export-dynamic
plg_sysagent_clips_la_LIBADD = libclips.la \
                               libjsonrpc.la

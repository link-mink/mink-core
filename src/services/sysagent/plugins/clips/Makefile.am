pkglib_LTLIBRARIES += plg_sysagent_clips.la
plg_sysagent_clips_la_SOURCES = src/services/sysagent/plugins/clips/plg_sysagent_clips.cpp
plg_sysagent_clips_la_CPPFLAGS = ${COMMON_INCLUDES} ${GRPC_CFLAGS} -Isrc/proto
plg_sysagent_clips_la_LDFLAGS = -version-info 1:0:0 -shared -module -export-dynamic
plg_sysagent_clips_la_LIBADD = -lclips

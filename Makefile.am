#            _       _
#  _ __ ___ (_)_ __ | | __
# | '_ ` _ \| | '_ \| |/ /
# | | | | | | | | | |   <
# |_| |_| |_|_|_| |_|_|\_\
#
# SPDX-License-Identifier: MIT
#

# aclocal m4 dir
ACLOCAL_AMFLAGS = -I m4
# subdirs
if ENABLE_CONFIGD
SUBDIRS = lib/libantlr3c-3.4
DIST_SUBDIRS = lib/libantlr3c-3.4
endif

# disable ncurses macros
CPPFLAGS += -DNCURSES_NOMACROS

# check for debug mode [--enable-debug]
if ENABLE_DEBUG
CXXFLAGS += -O${OLEVEL} -g
else
CXXFLAGS += -O${OLEVEL}
endif

# check for mdebug mode [--enable-mdebug]
if ENABLE_MDEBUG
CPPFLAGS += -DMDEBUG
endif

if ENABLE_CONFIGD
ANTLR_FLAGS = -Ilib/libantlr3c-3.4/include -Ilib/libantlr3c-3.4
ANTLR_LDLIBS = -lantlr3c -Llib/libantlr3c-3.4/.libs
endif

# compiler and linkerflags
COMMON_INCLUDES = -I. -Isrc/include

# MINK directories
confdir = $(sysconfdir)/mink

# MINK git generated files
BUILT_SOURCES = VERSION CHANGELOG AUTHORS
CLEANFILES = VERSION CHANGELOG AUTHORS
VERSION:
	./version.sh
	echo "Configured with: $(CONFIG_FLAGS)" >> VERSION

CHANGELOG:
	./changelog.sh

AUTHORS:
	./authors.sh

distclean-local: distclean-ax-prefix-mink-pkg-config-h
distclean-ax-prefix-mink-pkg-config-h:
	rm  -f mink_pkg_config.h



# MINK convenience libraries
noinst_LTLIBRARIES = libasn1.la \
                     libgdtdef.la \
                     libdaemon.la \
                     libgdtutils.la \
                     libstats.la \
                     libminkutils.la \
                     libminkdynamic.la \
                     libminkplugin.la \
                     libminkdb.la

if ENABLE_GRPC
noinst_LTLIBRARIES += libgdtgrpc.la
endif

lib_LTLIBRARIES = libgdt.la
pkglib_LTLIBRARIES =
bin_PROGRAMS = routingd

if ENABLE_GDTTRAPC
bin_PROGRAMS += gdttrapc
endif

if ENABLE_CONFIGD
bin_PROGRAMS += configd \
                cli_service
pkglib_LTLIBRARIES += plgcfg.la
noinst_LTLIBRARIES += libcli.la \
                      libcfg.la \
                      libantlrutils.la \
                      libcfgparser.la
endif

if ENABLE_GRPC
bin_PROGRAMS += grpcd
bin_PROGRAMS += grpcc
endif

if ENABLE_CODEGEN
bin_PROGRAMS += codegen
endif

if ENABLE_SYSAGENT
bin_PROGRAMS += sysagentd
endif

if ENABLE_JRPC
bin_PROGRAMS += jrpcd
noinst_LTLIBRARIES += libjsonrpc.la
endif

if ENABLE_CLIPS
noinst_LTLIBRARIES += libclips.la
endif

# code generator
if ENABLE_CODEGEN
codegen_SOURCES = src/codegen/codegen.cpp
codegen_CPPFLAGS = ${COMMON_INCLUDES} \
                   -Isrc/codegen
endif

# gdt grpc client
if ENABLE_GRPC
grpcc_SOURCES = src/gdt/gdt_grpc_client.cpp
grpcc_CPPFLAGS = ${COMMON_INCLUDES} \
                 -Isrc/proto \
                 ${GRPC_CFLAGS}
grpcc_LDADD = libgdtgrpc.la \
              ${PROTOBUF_LIBS} \
              ${GRPC_LIBS}
endif

# json rpc
if ENABLE_JRPC
jrpcd_SOURCES = src/services/json_rpc/events.cpp \
                src/services/json_rpc/jrpcd.cpp \
                src/services/json_rpc/ws_server.cpp \
                src/services/json_rpc/jrpc.cpp
jrpcd_CPPFLAGS = ${COMMON_INCLUDES} \
                 -Isrc/proto
jrpcd_LDADD = libdaemon.la \
              libstats.la \
              libgdt.la \
              libminkutils.la \
              libgdtutils.la \
              libasn1.la \
              libjsonrpc.la \
              libminkdb.la \
              ${NCURSES_LIBS} \
              -lcap
if ENABLE_OPENSSL
jrpcd_LDADD += $(CRYPTO_LIBS) \
               $(SSL_LIBS) \
               $(Z_LIBS)
endif
endif

# sysagentd
if ENABLE_SYSAGENT
sysagentd_SOURCES = src/services/sysagent/events.cpp \
                    src/services/sysagent/sysagent.cpp \
                    src/services/sysagent/sysagentd.cpp
sysagentd_CPPFLAGS = ${COMMON_INCLUDES} \
                     ${GRPC_CFLAGS} \
                     -Isrc/proto \
                     -Isrc/services/sysagent
sysagentd_LDFLAGS = -export-dynamic
sysagentd_LDADD = libdaemon.la \
                  libgdt.la \
                  libminkutils.la \
                  libgdtutils.la \
                  libasn1.la \
                  libminkplugin.la \
                  libminkdb.la \
                  ${NCURSES_LIBS} \
                  ${Z_LIBS} \
                  -lcap
endif

# grpcd
if ENABLE_GRPC
grpcd_SOURCES = src/services/grpc/grpc.cpp \
                src/services/grpc/events.cpp \
                src/services/grpc/gdtgrpc.cpp \
                src/services/grpc/grpcd.cpp
grpcd_CPPFLAGS = ${COMMON_INCLUDES} \
                 -Isrc/proto \
                 -Isrc/services/grpc \
                 ${GRPC_CFLAGS}
grpcd_LDADD = libdaemon.la \
              libminkutils.la \
              libgdt.la \
              libgdtutils.la \
              libasn1.la \
              libgdtgrpc.la \
              ${PROTOBUF_LIBS} \
              ${GRPC_LIBS} \
              ${NCURSES_LIBS} \
              -lcap
endif

# cli service
if ENABLE_CONFIGD
cli_service_SOURCES = src/services/cli/cli_service.cpp
cli_service_CPPFLAGS = ${COMMON_INCLUDES} \
                       $(ANTLR_FLAGS)
cli_service_LDFLAGS = -export-dynamic
cli_service_LDADD = libcli.la \
                    libgdt.la \
                    libasn1.la \
                    libminkutils.la \
                    libminkdynamic.la \
                    libantlrutils.la \
                    libcfg.la \
                    libcfgparser.la \
                    ${NCURSES_LIBS} \
                    ${ANTLR_LDLIBS} \
                    -lcap
endif

# gdt trapc client
if ENABLE_GDTTRAPC
gdttrapc_SOURCES = src/services/stats/gdttrapc.cpp
gdttrapc_CPPFLAGS = ${COMMON_INCLUDES}
gdttrapc_LDADD = libasn1.la \
                 libgdt.la \
                 libminkutils.la \
                 libcfg.la \
                 ${NCURSES_LIBS}
endif

# configd
if ENABLE_CONFIGD
configd_SOURCES = src/services/config/events.cpp \
                  src/services/config/configd.cpp
configd_CPPFLAGS = ${COMMON_INCLUDES} \
                   ${ANTLR_FLAGS} \
                   -Isrc/services/config
configd_LDADD = libasn1.la \
                libcfg.la \
                libdaemon.la \
                libgdt.la \
                libminkutils.la \
                libantlrutils.la \
                libcli.la \
                libminkdynamic.la \
                libcfgparser.la \
                ${NCURSES_LIBS} \
                ${ANTLR_LDLIBS} \
                -lcap
endif

# routingd
routingd_SOURCES = src/services/routing/cfg_events.cpp \
                   src/services/routing/routing.cpp \
                   src/services/routing/routingd_events.cpp \
                   src/services/routing/routingd.cpp
routingd_CPPFLAGS = ${COMMON_INCLUDES} \
                    ${NCURSES_CFLAGS} \
                    -Isrc/services/routing
routingd_LDADD = libgdt.la \
                 libdaemon.la \
                 libstats.la \
                 libgdt.la \
                 libasn1.la \
                 libcfg.la \
                 libminkutils.la \
                 ${NCURSES_LIBS} \
                 -lcap

# mink plugin
libminkplugin_la_SOURCES = src/utils/mink_plugin.cpp
libminkplugin_la_CPPFLAGS = ${COMMON_INCLUDES}
libminkplugin_la_LIBADD = -ldl

if ENABLE_GRPC
# grpc
libgdtgrpc_la_SOURCES = src/proto/gdt.grpc.pb.cc \
                        src/proto/gdt.pb.cc
libgdtgrpc_la_CPPFLAGS = ${COMMON_INCLUDES} \
                         ${GRPC_CFLAGS}
endif

# json rpc
libjsonrpc_la_SOURCES = src/utils/json_rpc.cpp
libjsonrpc_la_CPPFLAGS = ${COMMON_INCLUDES} \
                         -Isrc/proto

# dynamic (dlopen)
libminkdynamic_la_SOURCES = src/utils/mink_dynamic.cpp
libminkdynamic_la_CPPFLAGS = ${COMMON_INCLUDES}
libminkdynamic_la_LIBADD = -ldl

# utils
libminkutils_la_SOURCES = src/utils/mink_utils.cpp
libminkutils_la_CPPFLAGS = ${COMMON_INCLUDES}

# daemon
libdaemon_la_SOURCES = src/daemon/daemon.cpp
libdaemon_la_CPPFLAGS = $(COMMON_INCLUDES)

# asn1
libasn1_la_SOURCES = src/asn1/asn1.cpp
libasn1_la_CPPFLAGS = $(COMMON_INCLUDES)

# gdt def
libgdtdef_la_SOURCES = src/gdt/gdt_def.cpp
libgdtdef_la_CPPFLAGS = $(COMMON_INCLUDES)

# libcfg parser
libcfgparser_la_SOURCES = src/cfg/minkLexer.c \
                          src/cfg/minkParser.c
libcfgparser_la_CPPFLAGS = ${COMMON_INCLUDES} \
                           ${ANTLR_FLAGS}

# libcfg
libcfg_la_SOURCES = src/cfg/mink_config.cpp
libcfg_la_CPPFLAGS = ${COMMON_INCLUDES}

# libantlrutils
libantlrutils_la_SOURCES = src/cfg/antlr_utils.cpp
libantlrutils_la_CPPFLAGS = ${COMMON_INCLUDES} \
                            ${ANTLR_FLAGS}

# libcli
libcli_la_SOURCES = src/cli/cli.cpp
libcli_la_CPPFLAGS = ${COMMON_INCLUDES} \
                     ${ANTLR_FLAGS}

# gdt utils
libgdtutils_la_SOURCES = src/gdt/gdt_utils.cpp
if ENABLE_CONFIGD
libgdtutils_la_SOURCES += src/cfg/config_gdt.cpp
endif
libgdtutils_la_CPPFLAGS = ${COMMON_INCLUDES}

# stats
libstats_la_SOURCES = src/stats/gdt_stats.cpp
libstats_la_CPPFLAGS = ${COMMON_INCLUDES}

# MINK libraries
libgdt_la_SOURCES = src/gdt/gdt.cpp \
                    src/gdt/gdt_reg_events.cpp \
                    src/net/sctp.cpp \
                    src/net/chunk.cpp
libgdt_la_CPPFLAGS = $(COMMON_INCLUDES)
libgdt_la_LIBADD = libgdtdef.la \
                   libgdtutils.la \
                   ${SCTP_LIBS}
if ENABLE_CONFIGD
libgdt_la_LIBADD += libcfg.la
endif

libminkdb_la_SOURCES = src/utils/mink_sqlite.cpp
libminkdb_la_CPPFLAGS = $(COMMON_INCLUDES) \
                        -Isrc/proto
libminkdb_la_LIBADD = ${SQLITE_LIBS}

# clips
if ENABLE_CLIPS
libclips_la_SOURCES = lib/libclips/agenda.c \
                      lib/libclips/analysis.c \
                      lib/libclips/argacces.c \
                      lib/libclips/bload.c \
                      lib/libclips/bmathfun.c \
                      lib/libclips/bsave.c \
                      lib/libclips/classcom.c \
                      lib/libclips/classexm.c \
                      lib/libclips/classfun.c \
                      lib/libclips/classinf.c \
                      lib/libclips/classini.c \
                      lib/libclips/classpsr.c \
                      lib/libclips/clsltpsr.c \
                      lib/libclips/commline.c \
                      lib/libclips/conscomp.c \
                      lib/libclips/constrct.c \
                      lib/libclips/constrnt.c \
                      lib/libclips/crstrtgy.c \
                      lib/libclips/cstrcbin.c \
                      lib/libclips/cstrccom.c \
                      lib/libclips/cstrcpsr.c \
                      lib/libclips/cstrnbin.c \
                      lib/libclips/cstrnchk.c \
                      lib/libclips/cstrncmp.c \
                      lib/libclips/cstrnops.c \
                      lib/libclips/cstrnpsr.c \
                      lib/libclips/cstrnutl.c \
                      lib/libclips/default.c \
                      lib/libclips/defins.c \
                      lib/libclips/developr.c \
                      lib/libclips/dffctbin.c \
                      lib/libclips/dffctbsc.c \
                      lib/libclips/dffctcmp.c \
                      lib/libclips/dffctdef.c \
                      lib/libclips/dffctpsr.c \
                      lib/libclips/dffnxbin.c \
                      lib/libclips/dffnxcmp.c \
                      lib/libclips/dffnxexe.c \
                      lib/libclips/dffnxfun.c \
                      lib/libclips/dffnxpsr.c \
                      lib/libclips/dfinsbin.c \
                      lib/libclips/dfinscmp.c \
                      lib/libclips/drive.c \
                      lib/libclips/emathfun.c \
                      lib/libclips/engine.c \
                      lib/libclips/envrnbld.c \
                      lib/libclips/envrnmnt.c \
                      lib/libclips/evaluatn.c \
                      lib/libclips/expressn.c \
                      lib/libclips/exprnbin.c \
                      lib/libclips/exprnops.c \
                      lib/libclips/exprnpsr.c \
                      lib/libclips/extnfunc.c \
                      lib/libclips/factbin.c \
                      lib/libclips/factbld.c \
                      lib/libclips/factcmp.c \
                      lib/libclips/factcom.c \
                      lib/libclips/factfun.c \
                      lib/libclips/factgen.c \
                      lib/libclips/facthsh.c \
                      lib/libclips/factlhs.c \
                      lib/libclips/factmch.c \
                      lib/libclips/factmngr.c \
                      lib/libclips/factprt.c \
                      lib/libclips/factqpsr.c \
                      lib/libclips/factqury.c \
                      lib/libclips/factrete.c \
                      lib/libclips/factrhs.c \
                      lib/libclips/filecom.c \
                      lib/libclips/filertr.c \
                      lib/libclips/fileutil.c \
                      lib/libclips/generate.c \
                      lib/libclips/genrcbin.c \
                      lib/libclips/genrccmp.c \
                      lib/libclips/genrccom.c \
                      lib/libclips/genrcexe.c \
                      lib/libclips/genrcfun.c \
                      lib/libclips/genrcpsr.c \
                      lib/libclips/globlbin.c \
                      lib/libclips/globlbsc.c \
                      lib/libclips/globlcmp.c \
                      lib/libclips/globlcom.c \
                      lib/libclips/globldef.c \
                      lib/libclips/globlpsr.c \
                      lib/libclips/immthpsr.c \
                      lib/libclips/incrrset.c \
                      lib/libclips/inherpsr.c \
                      lib/libclips/inscom.c \
                      lib/libclips/insfile.c \
                      lib/libclips/insfun.c \
                      lib/libclips/insmngr.c \
                      lib/libclips/insmoddp.c \
                      lib/libclips/insmult.c \
                      lib/libclips/inspsr.c \
                      lib/libclips/insquery.c \
                      lib/libclips/insqypsr.c \
                      lib/libclips/iofun.c \
                      lib/libclips/lgcldpnd.c \
                      lib/libclips/main.c \
                      lib/libclips/memalloc.c \
                      lib/libclips/miscfun.c \
                      lib/libclips/modulbin.c \
                      lib/libclips/modulbsc.c \
                      lib/libclips/modulcmp.c \
                      lib/libclips/moduldef.c \
                      lib/libclips/modulpsr.c \
                      lib/libclips/modulutl.c \
                      lib/libclips/msgcom.c \
                      lib/libclips/msgfun.c \
                      lib/libclips/msgpass.c \
                      lib/libclips/msgpsr.c \
                      lib/libclips/multifld.c \
                      lib/libclips/multifun.c \
                      lib/libclips/objbin.c \
                      lib/libclips/objcmp.c \
                      lib/libclips/objrtbin.c \
                      lib/libclips/objrtbld.c \
                      lib/libclips/objrtcmp.c \
                      lib/libclips/objrtfnx.c \
                      lib/libclips/objrtgen.c \
                      lib/libclips/objrtmch.c \
                      lib/libclips/parsefun.c \
                      lib/libclips/pattern.c \
                      lib/libclips/pprint.c \
                      lib/libclips/prccode.c \
                      lib/libclips/prcdrfun.c \
                      lib/libclips/prcdrpsr.c \
                      lib/libclips/prdctfun.c \
                      lib/libclips/prntutil.c \
                      lib/libclips/proflfun.c \
                      lib/libclips/reorder.c \
                      lib/libclips/reteutil.c \
                      lib/libclips/retract.c \
                      lib/libclips/router.c \
                      lib/libclips/rulebin.c \
                      lib/libclips/rulebld.c \
                      lib/libclips/rulebsc.c \
                      lib/libclips/rulecmp.c \
                      lib/libclips/rulecom.c \
                      lib/libclips/rulecstr.c \
                      lib/libclips/ruledef.c \
                      lib/libclips/ruledlt.c \
                      lib/libclips/rulelhs.c \
                      lib/libclips/rulepsr.c \
                      lib/libclips/scanner.c \
                      lib/libclips/sortfun.c \
                      lib/libclips/strngfun.c \
                      lib/libclips/strngrtr.c \
                      lib/libclips/symblbin.c \
                      lib/libclips/symblcmp.c \
                      lib/libclips/symbol.c \
                      lib/libclips/sysdep.c \
                      lib/libclips/textpro.c \
                      lib/libclips/tmpltbin.c \
                      lib/libclips/tmpltbsc.c \
                      lib/libclips/tmpltcmp.c \
                      lib/libclips/tmpltdef.c \
                      lib/libclips/tmpltfun.c \
                      lib/libclips/tmpltlhs.c \
                      lib/libclips/tmpltpsr.c \
                      lib/libclips/tmpltrhs.c \
                      lib/libclips/tmpltutl.c \
                      lib/libclips/userdata.c \
                      lib/libclips/userfunctions.c \
                      lib/libclips/utility.c \
                      lib/libclips/watch.c
libclips_la_CPPFLAGS = -Ilib/libclips
endif

# MINK configd plugin
if ENABLE_CONFIGD
plgcfg_la_SOURCES = src/cfg/plgcfg_events.cpp \
                    src/cfg/config_gdt.cpp \
                    src/cfg/plgcfg.cpp
plgcfg_la_CPPFLAGS = ${COMMON_INCLUDES} \
                     ${ANTLR_FLAGS}
plgcfg_la_LIBADD = libdaemon.la \
                   -lcap
plgcfg_la_LDFLAGS = -version-info 1:0:0 \
                    -shared \
                    -module \
                    -export-dynamic
endif

# /********************/
# /* Sysagent plugins */
# /********************/
if ENABLE_SYSAGENT
# sysagent system plugin
include src/services/sysagent/plugins/system/Makefile.am
# sysagent openwrt plugin
if ENABLE_OPENWRT
include src/services/sysagent/plugins/openwrt/Makefile.am
endif
# sysagent system monitor plugin
if ENABLE_SYSMON
include src/services/sysagent/plugins/sysmon/Makefile.am
endif
# sysagent clips plugin
if ENABLE_CLIPS
include src/services/sysagent/plugins/clips/Makefile.am
endif
# syslog plugin
if ENABLE_SYSLOG
include src/services/sysagent/plugins/syslog/Makefile.am
endif
# cgroup2 plugin
if ENABLE_CGROUP2
include src/services/sysagent/plugins/cgroup2/Makefile.am
endif
# sysagent unix plugin
if ENABLE_UNIX
include src/services/sysagent/plugins/unix/Makefile.am
endif
# sysagent systemd plugin
if ENABLE_SYSTEMD
include src/services/sysagent/plugins/systemd/Makefile.am
endif
# sysagent cfgd plugin
if ENABLE_CONFIG_HANDLER
include src/services/sysagent/plugins/cfgd/Makefile.am
endif
# sysagent modbus plugin
if ENABLE_MODBUS
include src/services/sysagent/plugins/modbus/Makefile.am
endif
# sysagent ndpi plugin
if ENABLE_NDPI
include src/services/sysagent/plugins/ndpi/Makefile.am
endif
if ENABLE_LUA
# sysagent lua plugin
include src/services/sysagent/plugins/lua/Makefile.am
pkgdata_DATA = src/services/sysagent/plugins/lua/mink.lua
endif
# sysagent mqtt plugin
if ENABLE_MQTT
include src/services/sysagent/plugins/mqtt/Makefile.am
endif
endif
